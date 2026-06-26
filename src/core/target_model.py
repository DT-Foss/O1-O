#!/usr/bin/env python3
"""
Target Model — In-Memory Simulation of a Target for Offline Problem-Solving

When a tool fails on a real target, FORGE:
1. Builds a model of the target (services, defenses, observed behavior)
2. Simulates the failure scenario in-memory
3. Generates and tests alternative approaches AGAINST THE MODEL
4. Only deploys the solution that works in simulation

This is NOT brute force against the real target.
This is: "understand the problem → solve it offline → deploy the solution."
"""

import re
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class Service:
    """A discovered service on the target."""
    port: int
    proto: str
    status: str  # open, filtered, closed
    banner: str = ""
    version: str = ""
    auth_required: bool = True
    auth_methods: List[str] = field(default_factory=list)  # password, key, none
    known_vulns: List[str] = field(default_factory=list)


@dataclass
class Attempt:
    """A recorded attempt against the target."""
    tool: str
    intent: str
    service_port: int
    status: str  # success, failed, timeout, error
    failure_reason: str = ""
    failure_detail: str = ""  # Raw stderr/stdout excerpt
    duration_s: float = 0.0
    findings: Dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class TargetModel:
    """
    In-memory model of a target system.

    Built from recon data + observed tool behavior.
    Used to simulate attacks offline before deploying.
    """
    ip: str
    internal_ips: List[str] = field(default_factory=list)  # Internal IPs (from /etc/hosts)
    services: Dict[int, Service] = field(default_factory=dict)
    attempts: List[Attempt] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)  # {user, pass, source, service}
    access_level: str = "none"  # none → user → root
    files_found: List[str] = field(default_factory=list)
    defenses_detected: List[str] = field(default_factory=list)  # edr, firewall, ids, etc.
    os_guess: str = ""
    hostname: str = ""

    # === BUILD MODEL FROM RECON ===

    def add_service(self, port: int, proto: str, status: str = "open",
                    banner: str = "", version: str = ""):
        """Add a discovered service from recon."""
        svc = Service(port=port, proto=proto, status=status,
                      banner=banner, version=version)
        # Infer auth from banner
        if "openssh" in banner.lower():
            svc.auth_methods = ["password", "publickey"]
        elif "ftp" in proto.lower():
            svc.auth_methods = ["password", "anonymous"]
        elif "http" in proto.lower():
            svc.auth_required = False
        self.services[port] = svc

    def add_services_from_recon(self, recon_output: str):
        """Parse recon stdout and populate services."""
        # Nmap-style: 22/tcp open ssh OpenSSH_8.9
        for m in re.finditer(
            r'(\d+)/tcp\s+(open|filtered|closed)\s+(\S+)(?:\s+(.*))?',
            recon_output
        ):
            port, status, proto, banner = int(m.group(1)), m.group(2), m.group(3), m.group(4) or ""
            self.add_service(port, proto, status, banner)

        # FORGE-style: Port 22 (ssh): OPEN [banner: OpenSSH_8.9]
        for m in re.finditer(
            r'[Pp]ort\s+(\d+)\s*\((\w+)\):\s*(OPEN|CLOSED|FILTERED)(?:\s*\[banner:\s*([^\]]+)\])?',
            recon_output
        ):
            port, proto, status, banner = int(m.group(1)), m.group(2), m.group(3).lower(), m.group(4) or ""
            self.add_service(port, proto, status, banner)

        # OS detection
        if "linux" in recon_output.lower():
            self.os_guess = "linux"
        elif "windows" in recon_output.lower():
            self.os_guess = "windows"

    # === RECORD ATTEMPTS ===

    def record_attempt(self, tool: str, intent: str, port: int,
                       status: str, stdout: str = "", stderr: str = "",
                       exit_code: int = -1, duration: float = 0.0):
        """Record an attempt and extract intelligence from the result."""
        combined = f"{stdout}\n{stderr}".lower()

        # Classify failure reason
        reason = ""
        detail = ""
        if status == "failed":
            reason, detail = self._classify_failure(combined, exit_code)

        # Extract findings from success
        findings = {}
        if status == "success":
            findings = self._extract_findings(combined)

        attempt = Attempt(
            tool=tool, intent=intent, service_port=port,
            status=status, failure_reason=reason, failure_detail=detail,
            duration_s=duration, findings=findings,
        )
        self.attempts.append(attempt)

        # Update model from findings
        self._update_from_findings(findings)
        self._update_from_failure(reason, detail, port)

        return attempt

    def _classify_failure(self, output: str, exit_code: int) -> Tuple[str, str]:
        """Understand WHY something failed — not just that it failed."""
        patterns = [
            # Authentication
            (r"permission denied|authentication fail|invalid password|access denied",
             "auth_failure", "Target rejected credentials"),
            (r"no route to host|connection refused|econnrefused",
             "connection_refused", "Service not accepting connections"),
            (r"connection timed out|operation timed out|deadline exceeded",
             "timeout", "Service didn't respond in time"),
            # Defenses
            (r"connection reset by peer|broken pipe",
             "defense_reset", "Connection actively terminated (possible IDS/firewall)"),
            (r"ssl.*error|certificate.*verify|tls.*handshake",
             "ssl_mismatch", "SSL/TLS configuration mismatch"),
            (r"rate.?limit|too many|throttl|banned|blocked",
             "rate_limited", "Target is rate-limiting or blocking us"),
            # Software
            (r"modulenotfounderror|importerror|no module named",
             "missing_module", "Tool needs a Python module not available on target"),
            (r"command not found|no such file",
             "missing_tool", "Required binary not installed on target"),
            (r"syntax.?error|name.?error|type.?error",
             "code_error", "Generated code has a bug"),
            # Service-specific
            (r"no ftp|ftp.*refused|530",
             "service_absent", "Expected service is not running"),
            (r"protocol.*mismatch|unexpected.*response",
             "protocol_mismatch", "Service speaks a different protocol than expected"),
        ]
        for pattern, reason, detail in patterns:
            if re.search(pattern, output):
                return reason, detail

        if exit_code == 1:
            return "generic_error", "Tool exited with error (check output for details)"
        return "unknown", f"Unclassified failure (exit code {exit_code})"

    def _extract_findings(self, output: str) -> Dict:
        """Extract intelligence from successful tool output."""
        findings = {}

        # Try structured output first (FORGE V2 standardized format)
        try:
            from core.tool_output import parse_tool_output
            structured = parse_tool_output(output)
            if structured and structured.get("findings"):
                return structured["findings"]
        except ImportError:
            pass

        # Fallback: regex-based parsing for tools without structured output
        # Credentials
        creds = []
        for pattern in [
            r'(\w+):(\S+)@',
            r'(?:user|login)[:\s]+["\']?(\S+)["\']?\s+(?:pass|password)[:\s]+["\']?(\S+)',
            r'credentials?\s*(?:found|discovered)?[:\s]+(\S+)[/:\s]+(\S+)',
        ]:
            for m in re.finditer(pattern, output, re.IGNORECASE):
                creds.append({"user": m.group(1), "pass": m.group(2)})
        if creds:
            findings["credentials"] = creds

        # New ports
        new_ports = []
        for m in re.finditer(r'(?:open|discovered|found)[:\s]*port\s*(\d+)', output, re.IGNORECASE):
            new_ports.append(int(m.group(1)))
        if new_ports:
            findings["new_ports"] = new_ports

        # Vulnerabilities
        vulns = []
        for vuln_pattern, vuln_name in [
            (r'sql\s*injection|sqli', 'sqli'),
            (r'xss|cross.site.script', 'xss'),
            (r'lfi|local.file.inclusion', 'lfi'),
            (r'rce|remote.code.execution', 'rce'),
            (r'directory.traversal|path.traversal', 'directory_traversal'),
            (r'command.injection|os.injection', 'command_injection'),
            (r'ssrf|server.side.request', 'ssrf'),
            (r'file.upload|unrestricted.upload', 'file_upload'),
        ]:
            if re.search(vuln_pattern, output, re.IGNORECASE):
                vulns.append(vuln_name)
        if vulns:
            findings["vulnerabilities"] = vulns

        # Access level
        if re.search(r'uid=0|root@|# $|euid.*root', output):
            findings["access_level"] = "root"
        elif re.search(r'whoami|shell|session.*opened|\$\s*$', output):
            findings["access_level"] = "user"

        # Files
        files = re.findall(
            r'(?:found|readable|access)[:\s].*?((?:/[\w.]+)+)', output, re.IGNORECASE
        )
        if files:
            findings["files"] = files[:10]

        # SSH Keys (from credential harvester output — multiple formats)
        ssh_keys = []
        # Format 1: JSON {"path": "/...id_ed25519", "encrypted": false}
        for m in re.finditer(
            r'"path":\s*"([^"]*(?:id_rsa|id_ed25519|id_ecdsa)[^"]*)".*?"encrypted":\s*(true|false)',
            output, re.IGNORECASE | re.DOTALL
        ):
            ssh_keys.append({"path": m.group(1), "encrypted": m.group(2) == "true"})
        # Format 2: "encrypted: false" after path
        for m in re.finditer(r'((?:/[\w./]+)?(?:id_rsa|id_ed25519|id_ecdsa))\b.*?encrypt(?:ed)?[:\s]*(false|no|unencrypted)', output, re.IGNORECASE):
            if not any(k["path"] == m.group(1) for k in ssh_keys):
                ssh_keys.append({"path": m.group(1), "encrypted": False})
        # Format 3: "[+] private_key: /path/to/id_ed25519" (from [+] style output)
        for m in re.finditer(r'private.?key[:\s]+(\S*(?:id_rsa|id_ed25519|id_ecdsa)\S*)', output, re.IGNORECASE):
            path = m.group(1)
            if not any(k["path"] == path for k in ssh_keys):
                ssh_keys.append({"path": path, "encrypted": False})
        # Format 4: Any absolute path containing id_rsa/id_ed25519 (catch-all)
        for m in re.finditer(r'(/\S+/(?:id_rsa|id_ed25519|id_ecdsa))\b', output):
            path = m.group(1)
            if not any(k["path"] == path for k in ssh_keys):
                ssh_keys.append({"path": path, "encrypted": False})
        if ssh_keys:
            findings["ssh_keys"] = ssh_keys

        # Running services (from post-exploitation enum)
        services_found = []
        for m in re.finditer(r'(mysql|apache|nginx|postgres|redis|mongo|docker|sshd)\w*\s+\d+\s+[\d.]+', output, re.IGNORECASE):
            services_found.append(m.group(1).lower())
        if services_found:
            findings["running_services"] = list(set(services_found))

        # Lateral movement targets (IPs from known_hosts, arp, /etc/hosts, network enum)
        lateral_targets = []
        for m in re.finditer(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output):
            ip = m.group(1)
            if (ip != self.ip and not ip.startswith("127.")
                and not ip.startswith("0.") and not ip.startswith("255.")
                and ip not in lateral_targets):
                lateral_targets.append(ip)
        # Also parse /etc/hosts format: "10.10.10.102  web01" (including escaped versions)
        for m in re.finditer(r'(10\.\d+\.\d+\.\d+)[\s\\t]+(\w+)', output):
            ip = m.group(1)
            if ip != self.ip and ip not in lateral_targets:
                lateral_targets.append(ip)
        # Try subnet neighbors: if we found 10.10.10.102, also suggest 10.10.10.103, 104
        own_ips = re.findall(r'(10\.\d+\.\d+)\.\d+', output)
        if own_ips:
            subnet = own_ips[0]
            for last_octet in range(101, 110):
                candidate = f"{subnet}.{last_octet}"
                if candidate != self.ip and candidate not in lateral_targets:
                    # Only add first few neighbors, not the whole subnet
                    if len(lateral_targets) < 5:
                        lateral_targets.append(candidate)
        # Parse known_hosts entries (unhashed IPs)
        for m in re.finditer(r'^(\d+\.\d+\.\d+\.\d+)\s+ssh-', output, re.MULTILINE):
            ip = m.group(1)
            if ip not in lateral_targets and ip != self.ip:
                lateral_targets.append(ip)
        if lateral_targets:
            findings["lateral_targets"] = lateral_targets[:10]

        # Hostname (from post-exploit enum)
        hostname_match = re.search(r'"hostname":\s*"(\w+)"', output)
        if hostname_match:
            findings["hostname"] = hostname_match.group(1)
            # If hostname found, look for its IP in various formats
            hn = hostname_match.group(1)
            # Format: "10.10.10.102  web01" or "10.10.10.102 (web01)" or "10.10.10.102\tweb01"
            for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+)\s+[\(]?' + re.escape(hn), output):
                own_internal = m.group(1)
                if own_internal not in self.internal_ips:
                    self.internal_ips.append(own_internal)
                    findings.setdefault("own_internal_ips", []).append(own_internal)
            # Also: if hostname matches and we see "host": "web01" with nearby IP
            for m in re.finditer(r'"host":\s*"' + re.escape(hn) + r'"', output):
                # Look for IPs in the surrounding context
                ctx = output[max(0,m.start()-200):m.end()+200]
                for ip_m in re.finditer(r'(\d+\.\d+\.\d+\.\d+)', ctx):
                    ip = ip_m.group(1)
                    if not ip.startswith("127.") and ip not in self.internal_ips:
                        self.internal_ips.append(ip)
                        findings.setdefault("own_internal_ips", []).append(ip)

        # Database credentials (MySQL root:toor pattern)
        for m in re.finditer(r'mysql.*?(?:root|admin)[:/](\S+)', output, re.IGNORECASE):
            findings.setdefault("credentials", []).append({"user": "root", "pass": m.group(1), "service": "mysql"})

        return findings

    def _update_from_findings(self, findings: Dict):
        """Update target model from successful tool findings."""
        for cred in findings.get("credentials", []):
            if cred not in self.credentials:
                self.credentials.append(cred)

        for port in findings.get("new_ports", []):
            if port not in self.services:
                self.add_service(port, "unknown", "open")

        # Associate vulns with the service port from the attempt
        for vuln in findings.get("vulnerabilities", []):
            # Find which attempt this came from (last one)
            if self.attempts:
                last_port = self.attempts[-1].service_port
                if last_port in self.services:
                    if vuln not in self.services[last_port].known_vulns:
                        self.services[last_port].known_vulns.append(vuln)

        access = findings.get("access_level")
        if access:
            if access == "root" or (access == "user" and self.access_level == "none"):
                self.access_level = access

        self.files_found.extend(findings.get("files", []))

        # SSH keys — critical for lateral movement
        for key_info in findings.get("ssh_keys", []):
            if not key_info.get("encrypted", True):
                # Unencrypted key = usable for auth
                if key_info not in getattr(self, "ssh_keys_found", []):
                    if not hasattr(self, "ssh_keys_found"):
                        self.ssh_keys_found = []
                    self.ssh_keys_found.append(key_info)

        # Lateral movement targets
        for lt in findings.get("lateral_targets", []):
            if not hasattr(self, "lateral_targets_found"):
                self.lateral_targets_found = []
            if lt not in self.lateral_targets_found:
                self.lateral_targets_found.append(lt)

        # Running services (update model with discovered internal services)
        for svc_name in findings.get("running_services", []):
            svc_port_map = {"mysql": 3306, "postgres": 5432, "redis": 6379,
                           "mongo": 27017, "apache": 80, "nginx": 80}
            port = svc_port_map.get(svc_name, 0)
            if port and port not in self.services:
                self.add_service(port, svc_name, "open")

        # Hostname
        if findings.get("hostname"):
            self.hostname = findings["hostname"]

    def _update_from_failure(self, reason: str, detail: str, port: int):
        """Update target model from failure intelligence."""
        if reason == "defense_reset":
            if "ids" not in self.defenses_detected:
                self.defenses_detected.append("ids")
        if reason == "rate_limited":
            if "rate_limit" not in self.defenses_detected:
                self.defenses_detected.append("rate_limit")
        if reason == "service_absent" and port in self.services:
            self.services[port].status = "closed"

    # === QUERY MODEL ===

    def get_open_services(self) -> Dict[int, Service]:
        return {p: s for p, s in self.services.items() if s.status == "open"}

    def get_untried_services(self) -> Dict[int, Service]:
        tried_ports = {a.service_port for a in self.attempts}
        return {p: s for p, s in self.services.items()
                if s.status == "open" and p not in tried_ports}

    def get_failed_approaches(self) -> List[Attempt]:
        return [a for a in self.attempts if a.status == "failed"]

    def get_successful_approaches(self) -> List[Attempt]:
        return [a for a in self.attempts if a.status == "success"]

    def get_failure_reasons(self) -> Dict[str, int]:
        reasons = {}
        for a in self.attempts:
            if a.failure_reason:
                reasons[a.failure_reason] = reasons.get(a.failure_reason, 0) + 1
        return reasons

    def has_tried(self, tool: str, port: int = None) -> bool:
        for a in self.attempts:
            if a.tool == tool and (port is None or a.service_port == port):
                return True
        return False

    # === SIMULATE (for offline problem-solving) ===

    def would_fail(self, tool_type: str, port: int) -> Tuple[bool, str]:
        """
        Predict if an approach would fail based on what we know.
        This is the simulation — no real deployment needed.
        """
        svc = self.services.get(port)
        if not svc:
            return True, "no_service"
        if svc.status != "open":
            return True, f"service_{svc.status}"

        # Check if we already failed with this approach
        similar_failures = [
            a for a in self.attempts
            if a.service_port == port and a.status == "failed"
            and tool_type in a.tool.lower()
        ]
        if similar_failures:
            reason = similar_failures[-1].failure_reason
            # Can we do something different?
            if reason == "auth_failure" and not self.credentials:
                return True, "auth_failure_no_creds"
            if reason == "rate_limited":
                return True, "rate_limited"
            if reason == "defense_reset":
                return True, "defense_active"

        # Check defense compatibility
        if "brute" in tool_type and "rate_limit" in self.defenses_detected:
            return True, "rate_limit_defense"
        if "scan" in tool_type and "ids" in self.defenses_detected:
            # Scans might still work but need stealth
            pass

        return False, "ok"

    def suggest_approach(self, objective: str = "access") -> List[Dict]:
        """
        Based on everything we know about the target, suggest the best
        approaches — filtered through simulation.
        """
        suggestions = []

        open_svcs = self.get_open_services()
        failed_reasons = self.get_failure_reasons()

        for port, svc in open_svcs.items():
            approaches = self._approaches_for_service(svc, port)
            for approach in approaches:
                would_fail, reason = self.would_fail(approach["tool_type"], port)
                if not would_fail:
                    approach["port"] = port
                    approach["predicted_success"] = True
                    approach["reason"] = "untried and no known blockers"
                    suggestions.append(approach)
                else:
                    # Still record it but mark as likely-to-fail
                    approach["port"] = port
                    approach["predicted_success"] = False
                    approach["reason"] = reason

        # Sort: untried > tried-different-approach > known-to-fail
        suggestions.sort(key=lambda x: (
            x["predicted_success"],           # True first
            not self.has_tried(x["tool_type"], x.get("port")),  # Untried first
            x.get("priority", 0),             # Higher priority first
        ), reverse=True)

        return suggestions[:10]

    def _approaches_for_service(self, svc: Service, port: int) -> List[Dict]:
        """Generate possible approaches for a service."""
        approaches = []
        proto = svc.proto.lower()

        if proto in ("ssh", "openssh"):
            approaches.extend([
                {"tool_type": "ssh_brute_force", "intent": f"ssh brute force targeting {self.ip}:{port}", "priority": 3},
                {"tool_type": "ssh_key_auth", "intent": f"ssh key authentication test on {self.ip}:{port}", "priority": 2},
                {"tool_type": "ssh_enum", "intent": f"ssh user enumeration on {self.ip}:{port}", "priority": 4},
            ])
            # If we have creds, try them first
            if self.credentials:
                cred = self.credentials[0]
                approaches.insert(0, {
                    "tool_type": "ssh_login",
                    "intent": f"ssh login to {self.ip}:{port} with user {cred['user']}",
                    "priority": 5,
                })

        elif proto in ("http", "https", "nginx", "apache"):
            approaches.extend([
                {"tool_type": "web_scanner", "intent": f"web vulnerability scanner for {self.ip}:{port}", "priority": 4},
                {"tool_type": "dir_brute", "intent": f"directory brute force on {self.ip}:{port}", "priority": 3},
                {"tool_type": "sqli_scanner", "intent": f"sql injection scanner for {self.ip}:{port}", "priority": 3},
            ])
            # If vulns found, exploit them
            for vuln in svc.known_vulns:
                approaches.insert(0, {
                    "tool_type": f"{vuln}_exploit",
                    "intent": f"exploit {vuln} on {self.ip}:{port}",
                    "priority": 5,
                })

        elif proto in ("ftp", "vsftpd", "proftpd"):
            approaches.extend([
                {"tool_type": "ftp_brute", "intent": f"ftp brute force on {self.ip}:{port}", "priority": 3},
                {"tool_type": "ftp_anon", "intent": f"ftp anonymous login test on {self.ip}:{port}", "priority": 4},
            ])

        elif proto in ("mysql", "mariadb", "postgresql", "mssql"):
            approaches.extend([
                {"tool_type": "sql_brute", "intent": f"database brute force on {self.ip}:{port}", "priority": 3},
                {"tool_type": "sql_enum", "intent": f"database enumeration on {self.ip}:{port}", "priority": 4},
            ])

        elif proto in ("modbus", "scada"):
            approaches.extend([
                {"tool_type": "modbus_scan", "intent": f"modbus scanner for {self.ip}:{port}", "priority": 4},
                {"tool_type": "modbus_write", "intent": f"modbus register write tool for {self.ip}:{port}", "priority": 3},
            ])

        elif proto in ("mqtt"):
            approaches.extend([
                {"tool_type": "mqtt_sub", "intent": f"mqtt subscriber monitor on {self.ip}:{port}", "priority": 4},
                {"tool_type": "mqtt_inject", "intent": f"mqtt message injection on {self.ip}:{port}", "priority": 3},
            ])

        elif proto in ("smb", "samba", "netbios"):
            approaches.extend([
                {"tool_type": "smb_enum", "intent": f"smb enumeration on {self.ip}:{port}", "priority": 4},
                {"tool_type": "smb_relay", "intent": f"smb relay attack on {self.ip}:{port}", "priority": 3},
            ])

        else:
            # Generic
            approaches.append({
                "tool_type": f"{proto}_enum",
                "intent": f"{proto} enumeration on {self.ip}:{port}",
                "priority": 2,
            })

        return approaches

    # === DISPLAY ===

    def summary(self) -> str:
        """Human-readable target model summary."""
        lines = [
            f"Target: {self.ip}" + (f" ({self.hostname})" if self.hostname else ""),
            f"OS: {self.os_guess or 'unknown'}",
            f"Access: {self.access_level}",
            f"Services: {len(self.get_open_services())} open",
            f"Attempts: {len(self.attempts)} ({len(self.get_successful_approaches())} success, {len(self.get_failed_approaches())} failed)",
            f"Credentials: {len(self.credentials)}",
            f"Defenses: {', '.join(self.defenses_detected) or 'none detected'}",
        ]
        if self.services:
            lines.append("\nServices:")
            for port, svc in sorted(self.services.items()):
                vulns = f" VULNS: {svc.known_vulns}" if svc.known_vulns else ""
                lines.append(f"  {port}/tcp {svc.proto} [{svc.status}] {svc.banner}{vulns}")
        if self.attempts:
            lines.append("\nAttempts:")
            for a in self.attempts[-5:]:
                marker = "✓" if a.status == "success" else "✗"
                reason = f" ({a.failure_reason})" if a.failure_reason else ""
                lines.append(f"  {marker} {a.tool} on :{a.service_port} — {a.status}{reason}")
        return "\n".join(lines)


# === TEST ===
if __name__ == "__main__":
    # Simulate a real engagement scenario
    print("=== TARGET MODEL TEST ===\n")

    # Build model from recon
    target = TargetModel(ip="10.10.1.100")
    target.add_services_from_recon("""
        22/tcp open ssh OpenSSH_8.9p1
        80/tcp open http nginx/1.22
        3306/tcp filtered mysql
        1883/tcp open mqtt
    """)
    print(target.summary())

    # Attempt 1: SSH brute force fails
    print("\n--- Attempt 1: SSH brute force ---")
    target.record_attempt(
        tool="ssh_brute_force", intent="ssh brute force", port=22,
        status="failed", stderr="Permission denied (publickey,password)",
        exit_code=1, duration=45.0,
    )

    # What does the model suggest now?
    print("\n--- Model suggestions after SSH failure ---")
    suggestions = target.suggest_approach()
    for i, s in enumerate(suggestions[:5], 1):
        ok = "✓" if s["predicted_success"] else "✗"
        print(f"  {i}. [{ok}] {s['intent']} (reason: {s['reason']})")

    # Attempt 2: Web scanner succeeds, finds SQLi
    print("\n--- Attempt 2: Web scanner ---")
    target.record_attempt(
        tool="web_scanner", intent="web scanner", port=80,
        status="success",
        stdout="Found: SQL injection on /login.php\nParameter: username",
        exit_code=0, duration=12.0,
    )

    print("\n--- Model suggestions after web scanner success ---")
    suggestions = target.suggest_approach()
    for i, s in enumerate(suggestions[:5], 1):
        ok = "✓" if s["predicted_success"] else "✗"
        print(f"  {i}. [{ok}] {s['intent']} (reason: {s['reason']})")

    print("\n--- Final target model ---")
    print(target.summary())
