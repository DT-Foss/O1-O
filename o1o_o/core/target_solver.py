#!/usr/bin/env python3
"""
Target Solver — Simulate approaches against a target model until one works.

Flow:
  1. Tool fails on real target → failure reason captured
  2. Target Model updated with failure intelligence
  3. Solver generates next approach based on what we know
  4. Solver simulates approach against model (would_fail?)
  5. If model says it would work → return it (deploy this)
  6. If model says it would fail → learn why, generate next approach
  7. Repeat until solution found or approaches exhausted

No hardcoded limits on iterations.
Stops the moment it finds something that should work.
"""

import time
from typing import Optional, Dict, List, Tuple
from o1o_o.core.target_model import TargetModel, Service


class TargetSolver:
    """
    Solve an objective against a target model.

    The solver doesn't touch the real target. It works entirely
    against the TargetModel (in-memory simulation). Only the winning
    approach gets deployed for real.
    """

    # Service → ordered list of approach types (most promising first)
    APPROACH_TREE = {
        "ssh": [
            # If we have creds, use them
            ("ssh_login_creds", "ssh connect stdlib", lambda m, p: bool(m.credentials)),
            # Stdlib variants first (no dependencies)
            ("ssh_connect_stdlib", "ssh connect stdlib", None),
            ("ssh_brute_stdlib", "ssh brute force stdlib", None),
            # Then paramiko variants as fallback
            ("ssh_enum", "ssh user enumeration", None),
            ("ssh_key_auth", "ssh key authentication test", None),
            ("ssh_brute_force", "ssh brute force", None),
        ],
        "http": [
            # Stdlib first
            ("http_scanner_stdlib", "http scanner stdlib", None),
            ("web_scanner", "web vulnerability scanner", None),
            ("dir_brute", "directory discovery", None),
            ("sqli_scanner", "sql injection scanner", None),
            ("xss_scanner", "xss scanner", None),
            ("lfi_scanner", "local file inclusion scanner", None),
            ("web_login_brute", "web login brute force", None),
        ],
        "https": [
            ("web_scanner", "web vulnerability scanner", None),
            ("dir_brute", "directory discovery", None),
            ("sqli_scanner", "sql injection scanner", None),
        ],
        "ftp": [
            ("ftp_anon", "ftp anonymous login test", None),
            ("ftp_brute", "ftp brute force", None),
        ],
        "mysql": [
            ("sql_enum", "mysql enumeration", None),
            ("sql_brute", "mysql brute force", None),
            ("sqli_exploit", "sql injection exploit", lambda m, p: "sqli" in [v for s in m.services.values() for v in s.known_vulns]),
        ],
        "smb": [
            ("smb_enum", "smb enumeration", None),
            ("smb_null_session", "smb null session test", None),
            ("pass_the_hash", "pass the hash attack", lambda m, p: bool(m.credentials)),
        ],
        "modbus": [
            ("modbus_scan", "modbus device scanner", None),
            ("modbus_enum", "modbus register enumeration", None),
            ("modbus_write", "modbus register write", None),
        ],
        "mqtt": [
            ("mqtt_sub", "mqtt topic subscription monitor", None),
            ("mqtt_enum", "mqtt topic enumeration", None),
            ("mqtt_inject", "mqtt message injection", None),
        ],
        "rdp": [
            ("rdp_brute", "rdp brute force", None),
            ("rdp_enum", "rdp user enumeration", None),
        ],
        "snmp": [
            ("snmp_enum", "snmp community string enumeration", None),
            ("snmp_brute", "snmp brute force", None),
        ],
    }

    # When a vuln is found, these are the exploit approaches
    VULN_EXPLOITS = {
        "sqli": [
            ("sqli_exploit", "sql injection exploit"),
            ("sqli_dump", "database dump via sql injection"),
            ("sqli_shell", "os shell via sql injection"),
        ],
        "xss": [
            ("xss_steal_session", "session steal via xss"),
        ],
        "lfi": [
            ("lfi_read_files", "read sensitive files via lfi"),
            ("lfi_to_rce", "lfi to remote code execution"),
        ],
        "rce": [
            ("rce_exploit", "remote code execution exploit"),
            ("rce_shell", "reverse shell via rce"),
        ],
        "command_injection": [
            ("cmdi_exploit", "command injection exploit"),
            ("cmdi_shell", "reverse shell via command injection"),
        ],
        "file_upload": [
            ("upload_shell", "upload webshell"),
        ],
        "directory_traversal": [
            ("traversal_read", "read files via directory traversal"),
        ],
    }

    # Post-access approaches (after getting user/root)
    POST_ACCESS = {
        "user": [
            ("post_exploit_enum_stdlib", "post exploitation enumeration stdlib"),
            ("credential_harvester_stdlib", "credential harvester stdlib"),
            ("privesc_enum", "privilege escalation enumeration"),
            ("credential_harvest", "credential harvesting"),
            ("lateral_enum", "lateral movement enumeration"),
        ],
        "root": [
            ("credential_harvest_full", "full credential harvesting"),
            ("persistence_install", "persistence mechanism installation"),
            ("data_exfil", "data exfiltration"),
        ],
    }

    # Modules that indicate a tool needs specific dependencies
    DEPENDENCY_SIGNATURES = {
        "paramiko": ["ssh_enum", "ssh_brute_force", "ssh_key_auth", "ssh_brute_extended"],
        "requests": ["web_login_brute", "sqli_scanner", "xss_scanner"],
        "scapy": ["arp_scanner", "packet_sniffer"],
        "nmap": ["nmap_scan"],
    }

    def __init__(self, target: TargetModel, fragment_keys: set = None):
        self.target = target
        self.solve_log: List[Dict] = []
        self.blacklisted_tools: set = set()
        self.blacklisted_reasons: dict = {}
        # Optional: FORGE fragment keys for dynamic approach generation
        self.fragment_keys = fragment_keys or set()

    def _dynamic_approaches_for_service(self, proto: str) -> List:
        """Generate approaches dynamically from FORGE fragment keys.
        Used when a service type isn't in the static APPROACH_TREE."""
        if not self.fragment_keys:
            return []
        approaches = []
        proto_lower = proto.lower()
        for key in sorted(self.fragment_keys):
            key_lower = key.lower()
            # Match fragments that contain the protocol name
            if proto_lower in key_lower or key_lower.startswith(proto_lower):
                description = key.replace("_", " ")
                approaches.append((key, f"build {description}", None))
        return approaches[:10]  # Cap at 10 to avoid explosion

    def learn_from_failure(self, tool_type: str, reason: str, stderr: str = ""):
        """
        Analyze a failure and blacklist similar tools that would fail the same way.
        This is the key intelligence: don't repeat the same class of mistake.
        """
        combined = f"{reason} {stderr}".lower()

        # Missing module → blacklist ALL tools that need that module
        if "modulenotfounderror" in combined or "importerror" in combined or "missing_module" in combined:
            # Extract module name
            import re
            mod_match = re.search(r"no module named ['\"](\w+)", combined)
            if mod_match:
                missing_mod = mod_match.group(1)
                # Blacklist all tools that depend on this module
                if missing_mod in self.DEPENDENCY_SIGNATURES:
                    for blocked_tool in self.DEPENDENCY_SIGNATURES[missing_mod]:
                        if blocked_tool not in self.blacklisted_tools:
                            self.blacklisted_tools.add(blocked_tool)
                            self.blacklisted_reasons[blocked_tool] = f"needs {missing_mod} (not installed on target)"
                            self._log("blacklist", f"Blacklisted {blocked_tool}: needs {missing_mod}")

        # Connection refused on a port → blacklist that port's service
        if "connection refused" in combined:
            port_match = re.search(r"port (\d+)", combined)
            if port_match:
                port = int(port_match.group(1))
                self._log("blacklist", f"Port {port} connection refused — service likely not on this port")

        # Auth failure with specific method → blacklist that auth method
        if "auth_failure" in combined or "permission denied" in combined:
            if "password" in combined and "publickey" in combined:
                # Both methods failed → blacklist all password-based SSH
                for bt in ["ssh_brute_force", "ssh_brute_stdlib", "ssh_brute_extended"]:
                    if bt not in self.blacklisted_tools:
                        self.blacklisted_tools.add(bt)
                        self.blacklisted_reasons[bt] = "password auth rejected by target"
                        self._log("blacklist", f"Blacklisted {bt}: password auth rejected")

    def _is_blacklisted(self, tool_type: str) -> bool:
        """Check if a tool is blacklisted due to previous failure analysis."""
        # Exact match
        if tool_type in self.blacklisted_tools:
            return True
        # Partial match (e.g., "ssh_brute_force" matches blacklist for "ssh_brute")
        for bt in self.blacklisted_tools:
            if bt in tool_type or tool_type in bt:
                return True
        return False

    def solve(self, objective: str = "access") -> Optional[Dict]:
        """
        Find the next approach that should work against this target.

        Returns the first approach that passes simulation, or None if
        all known approaches are exhausted.

        Does NOT deploy anything. Returns the approach for the caller to deploy.
        """
        t0 = time.time()

        # Phase 0: Credential harvesting (always useful, run early)
        if not self.target.has_tried("credential_harvester_stdlib"):
            self._log("recon_first", "Credential harvesting before attack")
            solution = self._make_solution(
                "credential_harvester_stdlib", "credential harvester stdlib",
                0, "recon_first"
            )
            solution["solve_time_ms"] = (time.time() - t0) * 1000
            return solution

        # Phase 0b: Post-exploit enum (gather intelligence including internal network)
        if not self.target.has_tried("post_exploit_enum_stdlib"):
            self._log("recon_first", "Post-exploitation enumeration (network + lateral targets)")
            port = next((p for p, s in self.target.services.items()
                        if s.proto in ("ssh", "openssh") and s.status == "open"), 0)
            solution = self._make_solution(
                "post_exploit_enum_stdlib", "post exploitation enumeration stdlib",
                port, "recon_first"
            )
            # Override intent to be more specific so FORGE picks our stdlib fragment
            solution["intent"] = "create post exploitation enumeration stdlib"
            solution["solve_time_ms"] = (time.time() - t0) * 1000
            return solution

        # Phase 0c: Internal network recon (find lateral targets from /etc/hosts, known_hosts, arp)
        # Only run if we already have access and no lateral targets found yet
        lateral = getattr(self.target, "lateral_targets_found", [])
        if not lateral and not self.target.has_tried("internal_network_scan"):
            # The post_exploit_enum should have found internal IPs
            # If not, skip this phase (will be populated from post_exploit output)
            pass

        # Phase 0d: If we found SSH keys, try lateral movement
        # LIMIT: Only try top 3 lateral attempts per solve cycle
        # (prevents exhausting all IP×user combos before trying other vectors)
        ssh_keys = getattr(self.target, "ssh_keys_found", [])
        lateral_attempts = sum(1 for a in self.target.attempts if "lateral" in a.tool)
        if ssh_keys and lateral_attempts < 3:
            solution = self._try_lateral_with_keys()
            if solution:
                solution["solve_time_ms"] = (time.time() - t0) * 1000
                return solution

        # Phase 1: If we have vulns, exploit them first
        solution = self._try_vuln_exploits()
        if solution:
            solution["solve_time_ms"] = (time.time() - t0) * 1000
            return solution

        # Phase 2: If we have access, do post-exploitation
        if self.target.access_level != "none":
            solution = self._try_post_access()
            if solution:
                solution["solve_time_ms"] = (time.time() - t0) * 1000
                return solution

        # Phase 3: Try untried services in priority order
        solution = self._try_service_approaches()
        if solution:
            solution["solve_time_ms"] = (time.time() - t0) * 1000
            return solution

        # Phase 4: Cross-service strategies (use findings from one service on another)
        solution = self._try_cross_service()
        if solution:
            solution["solve_time_ms"] = (time.time() - t0) * 1000
            return solution

        # Nothing left to try
        self._log("exhausted", "All known approaches exhausted against this target model")
        return None

    def _try_vuln_exploits(self) -> Optional[Dict]:
        """If we know about vulnerabilities, try exploiting them."""
        for port, svc in self.target.services.items():
            for vuln in svc.known_vulns:
                exploits = self.VULN_EXPLOITS.get(vuln, [])
                for tool_type, description in exploits:
                    if not self.target.has_tried(tool_type, port):
                        would_fail, reason = self.target.would_fail(tool_type, port)
                        if not would_fail:
                            self._log("vuln_exploit", f"Exploit {vuln} on :{port} via {tool_type}")
                            return self._make_solution(tool_type, description, port, "vuln_exploit")
                        else:
                            self._log("vuln_skip", f"Would fail: {tool_type} on :{port} — {reason}")
        return None

    def _try_post_access(self) -> Optional[Dict]:
        """If we have access, do post-exploitation."""
        approaches = self.POST_ACCESS.get(self.target.access_level, [])
        for tool_type, description in approaches:
            if not self.target.has_tried(tool_type):
                self._log("post_access", f"Post-exploitation: {tool_type}")
                # Post-access tools target any open service (usually SSH)
                port = next((p for p, s in self.target.services.items()
                            if s.proto in ("ssh", "openssh") and s.status == "open"), 0)
                return self._make_solution(tool_type, description, port, "post_access")
        return None

    def _try_service_approaches(self) -> Optional[Dict]:
        """Try approaches for each open service, in priority order."""
        open_services = self.target.get_open_services()

        for port, svc in sorted(open_services.items()):
            proto = svc.proto.lower()

            # Skip SSH service if we already have SSH access (deploy access)
            if "ssh" in proto:
                already_has_ssh = any(
                    a.status == "success" and "ssh" in a.tool.lower()
                    for a in self.target.attempts
                )
                if already_has_ssh:
                    continue  # Don't brute force SSH when we already have it

            # Find matching approach tree
            tree = None
            for key in self.APPROACH_TREE:
                if key in proto:
                    tree = self.APPROACH_TREE[key]
                    break

            if not tree:
                # Try dynamic approaches from FORGE fragment keys
                tree = self._dynamic_approaches_for_service(proto)
                if not tree:
                    # Last resort: generic enumeration
                    tool_type = f"{proto}_enum"
                    if not self.target.has_tried(tool_type, port):
                        self._log("generic", f"Generic enum for {proto} on :{port}")
                        return self._make_solution(tool_type, f"{proto} enumeration", port, "generic")
                    continue

            for tool_type, description, condition in tree:
                # Check precondition (e.g., "only if we have creds")
                if condition and not condition(self.target, port):
                    continue

                if self.target.has_tried(tool_type, port):
                    continue

                # Check blacklist (learned from previous failures)
                if self._is_blacklisted(tool_type):
                    reason = self.blacklisted_reasons.get(tool_type, "blacklisted")
                    self._log("skip_bl", f"Skipping {tool_type}: {reason}")
                    continue

                # Simulate against model
                would_fail, reason = self.target.would_fail(tool_type, port)
                if not would_fail:
                    self._log("service", f"Try {tool_type} on :{port}")
                    return self._make_solution(tool_type, description, port, "service_approach")
                else:
                    self._log("skip", f"Would fail: {tool_type} on :{port} — {reason}")

        return None

    def _try_lateral_with_keys(self) -> Optional[Dict]:
        """If we found SSH keys, try using them on lateral targets or known hosts."""
        ssh_keys = getattr(self.target, "ssh_keys_found", [])
        if not ssh_keys:
            return None

        unencrypted_keys = [k for k in ssh_keys if not k.get("encrypted", True)]
        if not unencrypted_keys:
            return None

        key_path = unencrypted_keys[0]["path"]

        # Try lateral targets (skip self, try common users)
        lateral_targets = getattr(self.target, "lateral_targets_found", [])
        # Get own IPs to skip (external + internal from /etc/hosts)
        own_ips = {self.target.ip}
        own_ips.update(getattr(self.target, "internal_ips", []))
        # Try each untried IP with the most likely username
        # SMART: If ANY lateral attempt to an IP failed, skip that IP entirely
        # (the key either works or doesn't — trying more users wastes rounds)
        failed_lateral_ips = set()
        for a in self.target.attempts:
            if "lateral" in a.tool and a.status == "failed":
                for part in a.tool.split("_"):
                    if part.count(".") == 3:
                        failed_lateral_ips.add(part)

        lateral_users = ["devops", "deploy", "developer", "admin", "root"]
        for lt_ip in lateral_targets:
            if lt_ip in own_ips or lt_ip in failed_lateral_ips:
                continue
            # Try ONLY the first user — if key doesn't work for devops, it won't work for others
            for lt_user in lateral_users[:1]:  # Only first
                tool_type = f"ssh_key_lateral_{lt_ip}_{lt_user}"
                if not self.target.has_tried(tool_type):
                    self._log("lateral", f"Lateral movement to {lt_user}@{lt_ip} with stolen key {key_path}")
                    return {
                        "tool_type": tool_type,
                        "description": f"ssh connect stdlib with key {key_path}",
                        "intent": f"create ssh connect stdlib targeting {lt_ip}",
                        "config": {
                            "target": lt_ip,
                            "port": "22",
                            "username": lt_user,
                            "ssh_key": key_path,
                        },
                        "port": 22,
                        "strategy": "lateral_key",
                        "target_ip": lt_ip,
                        "model_state": {},
                    }

        # Try the key on the same host for privilege escalation (different user)
        tool_type = "ssh_key_privesc"
        if not self.target.has_tried(tool_type):
            self._log("lateral", f"SSH key privesc with {key_path}")
            return self._make_solution(
                tool_type,
                f"ssh connect stdlib with stolen key",
                next((p for p, s in self.target.services.items()
                     if "ssh" in s.proto.lower()), 22),
                "lateral_key"
            )

        return None

    def _try_cross_service(self) -> Optional[Dict]:
        """Use discoveries from one service to attack another."""
        # If we found credentials, try them on other services
        if self.target.credentials:
            for port, svc in self.target.get_open_services().items():
                if svc.auth_required:
                    cred = self.target.credentials[0]
                    tool_type = f"{svc.proto}_login_creds"
                    if not self.target.has_tried(tool_type, port):
                        self._log("cross_service",
                                  f"Try creds {cred['user']} on {svc.proto}:{port}")
                        return self._make_solution(
                            tool_type,
                            f"{svc.proto} login with discovered credentials",
                            port, "cross_service"
                        )
        return None

    def _make_solution(self, tool_type: str, description: str,
                       port: int, strategy: str) -> Dict:
        """Package a solution for deployment."""
        svc = self.target.services.get(port)
        intent = f"create {description} targeting {self.target.ip}"
        if port:
            intent += f" on port {port}"

        config = {
            "target": self.target.ip,
            "port": str(port),
        }

        # Add credentials if available and relevant
        if self.target.credentials and ("login" in tool_type or "cred" in tool_type):
            cred = self.target.credentials[0]
            config["username"] = cred.get("user", "")
            config["password"] = cred.get("pass", "")

        return {
            "tool_type": tool_type,
            "description": description,
            "intent": intent,
            "config": config,
            "port": port,
            "strategy": strategy,
            "target_ip": self.target.ip,
            "model_state": {
                "access_level": self.target.access_level,
                "services_open": len(self.target.get_open_services()),
                "attempts_total": len(self.target.attempts),
                "credentials_known": len(self.target.credentials),
                "defenses": self.target.defenses_detected,
            },
        }

    def _log(self, action: str, detail: str):
        self.solve_log.append({
            "action": action,
            "detail": detail,
            "timestamp": time.time(),
        })


# === FULL ENGAGEMENT SIMULATION ===

def simulate_engagement(target_ip: str, recon_output: str, max_rounds: int = 20):
    """
    Simulate a full engagement against a target model.

    This runs entirely in-memory — no real deployment.
    Shows what FORGE would do at each step.
    """
    print(f"\n{'='*60}")
    print(f"ENGAGEMENT SIMULATION: {target_ip}")
    print(f"{'='*60}")

    # Build target model from recon
    target = TargetModel(ip=target_ip)
    target.add_services_from_recon(recon_output)
    print(f"\nRecon: {len(target.get_open_services())} open services")
    for port, svc in sorted(target.services.items()):
        print(f"  {port}/tcp {svc.proto} [{svc.status}] {svc.banner}")

    solver = TargetSolver(target)
    round_num = 0

    while round_num < max_rounds:
        round_num += 1
        print(f"\n{'─'*50}")
        print(f"Round {round_num}: access={target.access_level}, creds={len(target.credentials)}")

        # Solve: find next approach
        solution = solver.solve()
        if not solution:
            print("  No more approaches available. Engagement complete.")
            break

        print(f"  → {solution['strategy']}: {solution['description']}")
        print(f"    Intent: {solution['intent']}")
        print(f"    Solve log: {len(solver.solve_log)} steps")

        # Simulate deployment result (for testing)
        # In real FORGE: this would be run_live_pipeline + deploy
        result = _simulate_deploy(solution, target, round_num)

        print(f"    Result: {result['status']}" +
              (f" ({result.get('reason', '')})" if result.get('reason') else ""))

        # Record in target model
        target.record_attempt(
            tool=solution["tool_type"],
            intent=solution["intent"],
            port=solution["port"],
            status=result["status"],
            stdout=result.get("stdout", ""),
            stderr=result.get("stderr", ""),
            exit_code=result.get("exit_code", -1),
            duration=result.get("duration", 0),
        )

        # Check if objective reached
        if target.access_level == "root":
            print(f"\n  ★ ROOT ACCESS ACHIEVED in round {round_num}")
            break
        elif target.access_level == "user" and round_num > 1:
            print(f"  ★ User access achieved, continuing to escalate...")

    # Summary
    print(f"\n{'='*60}")
    print(f"SIMULATION SUMMARY")
    print(f"{'='*60}")
    print(target.summary())
    print(f"\nSolver log ({len(solver.solve_log)} entries):")
    for entry in solver.solve_log:
        print(f"  [{entry['action']:15s}] {entry['detail']}")


def _simulate_deploy(solution: Dict, target: TargetModel, round_num: int) -> Dict:
    """
    Fake deployment results for testing the solver logic.
    In real FORGE, this would be actual tool generation + SSH deploy.
    """
    tool = solution["tool_type"]
    port = solution["port"]

    # Simulate realistic outcomes
    if "enum" in tool:
        # Enumerations usually succeed
        return {"status": "success", "stdout": f"Enumerated {port}: found 3 items", "exit_code": 0, "duration": 5.0}

    if "web_scanner" in tool:
        # Web scanner finds SQLi on round 2+
        return {"status": "success", "stdout": "Found: SQL injection on /login.php\nParameter: username\nType: blind boolean", "exit_code": 0, "duration": 12.0}

    if "sqli" in tool:
        # SQLi exploit gives us credentials
        return {"status": "success", "stdout": "Extracted credentials: admin:Sup3rS3cret! from users table\nDatabase: webapp_db\n3 tables dumped", "exit_code": 0, "duration": 8.0}

    if "brute" in tool and "ssh" in tool:
        # SSH brute fails (realistic)
        return {"status": "failed", "stderr": "Permission denied (publickey,password)", "exit_code": 1, "duration": 45.0, "reason": "auth_failure"}

    if "login_creds" in tool:
        # Login with discovered creds succeeds
        return {"status": "success", "stdout": "Connected as admin@target\nuid=1000(admin) gid=1000(admin)\n$ whoami\nadmin", "exit_code": 0, "duration": 2.0}

    if "privesc" in tool:
        # Privesc finds something
        return {"status": "success", "stdout": "Found SUID binary: /usr/bin/pkexec\nCVE-2021-4034 applicable\nuid=0(root)", "exit_code": 0, "duration": 15.0}

    if "credential_harvest" in tool:
        return {"status": "success", "stdout": "Found credentials: root:toor in /etc/shadow", "exit_code": 0, "duration": 10.0}

    # Default: success
    return {"status": "success", "stdout": f"{tool} completed", "exit_code": 0, "duration": 5.0}


if __name__ == "__main__":
    # Simulate a realistic engagement
    simulate_engagement(
        target_ip="10.10.1.100",
        recon_output="""
            22/tcp open ssh OpenSSH_8.9p1
            80/tcp open http nginx/1.22
            3306/tcp filtered mysql
            1883/tcp open mqtt
        """
    )
