"""Threat Model Generator — MITRE ATT&CK mapping + IOC identification.

Maps generated tools to ATT&CK techniques, identifies indicators of
compromise, and suggests detection methods + countermeasures.

Usage:
    from o1o_o.core.threat_model import ThreatModelGenerator
    tmg = ThreatModelGenerator()
    model = tmg.generate(intent_str, code, config)
"""
# Dependencies: re, json
# Depended by: forge_live.py pipeline (step 11)

import re
import json
from pathlib import Path


class ThreatModelGenerator:
    """
    Maps generated tools to MITRE ATT&CK framework, identifies IOCs,
    and suggests detection methods + countermeasures.
    """

    # MITRE ATT&CK technique mapping by tool intent keywords
    TECHNIQUE_MAP = {
        # Reconnaissance
        "scan": [("T1046", "Network Service Discovery"), ("T1595", "Active Scanning")],
        "recon": [("T1592", "Gather Victim Host Information"), ("T1590", "Gather Victim Network Information")],
        # Resource Development
        "phish": [("T1566", "Phishing"), ("T1598", "Phishing for Information")],
        "credential": [("T1589", "Gather Victim Identity Information")],
        # Initial Access
        "exploit": [("T1190", "Exploit Public-Facing Application"), ("T1203", "Exploitation for Client Execution")],
        "reverse shell": [("T1059", "Command and Scripting Interpreter"), ("T1071", "Application Layer Protocol")],
        "shell": [("T1059.006", "Python"), ("T1059", "Command and Scripting Interpreter")],
        # Execution
        "inject": [("T1055", "Process Injection"), ("T1055.001", "DLL Injection")],
        "dll": [("T1055.001", "DLL Injection"), ("T1574.001", "DLL Search Order Hijacking")],
        "hollowing": [("T1055.012", "Process Hollowing")],
        # Persistence
        "persist": [("T1547", "Boot or Logon Autostart Execution"), ("T1053", "Scheduled Task/Job")],
        "backdoor": [("T1547", "Boot or Logon Autostart Execution"), ("T1505", "Server Software Component")],
        "rootkit": [("T1014", "Rootkit"), ("T1547", "Boot or Logon Autostart Execution")],
        # Privilege Escalation
        "privesc": [("T1068", "Exploitation for Privilege Escalation"), ("T1548", "Abuse Elevation Control Mechanism")],
        "kerbero": [("T1558.003", "Kerberoasting"), ("T1558", "Steal or Forge Kerberos Tickets")],
        # Defense Evasion
        "evasion": [("T1027", "Obfuscated Files or Information"), ("T1562", "Impair Defenses")],
        "packer": [("T1027.002", "Software Packing")],
        "stego": [("T1027.003", "Steganography"), ("T1001.002", "Steganography")],
        # Credential Access
        "keylog": [("T1056.001", "Keylogging"), ("T1056", "Input Capture")],
        "harvest": [("T1555", "Credentials from Password Stores"), ("T1003", "OS Credential Dumping")],
        "brute": [("T1110", "Brute Force"), ("T1110.001", "Password Guessing")],
        "mimikatz": [("T1003.001", "LSASS Memory"), ("T1003", "OS Credential Dumping")],
        # Discovery
        "enum": [("T1087", "Account Discovery"), ("T1069", "Permission Groups Discovery")],
        # Lateral Movement
        "lateral": [("T1021", "Remote Services"), ("T1570", "Lateral Tool Transfer")],
        "psexec": [("T1021.002", "SMB/Windows Admin Shares"), ("T1569.002", "Service Execution")],
        "wmi": [("T1047", "Windows Management Instrumentation")],
        # Collection
        "exfil": [("T1041", "Exfiltration Over C2 Channel"), ("T1048", "Exfiltration Over Alternative Protocol")],
        "screen": [("T1113", "Screen Capture")],
        "clipboard": [("T1115", "Clipboard Data")],
        # Command & Control
        "c2": [("T1071", "Application Layer Protocol"), ("T1573", "Encrypted Channel")],
        "c&c": [("T1071", "Application Layer Protocol"), ("T1573", "Encrypted Channel")],
        "botnet": [("T1071", "Application Layer Protocol"), ("T1090", "Proxy")],
        "beacon": [("T1071.001", "Web Protocols"), ("T1573.001", "Symmetric Cryptography")],
        "dns tunnel": [("T1071.004", "DNS"), ("T1572", "Protocol Tunneling")],
        # Impact
        "ransomware": [("T1486", "Data Encrypted for Impact"), ("T1490", "Inhibit System Recovery")],
        "wiper": [("T1485", "Data Destruction"), ("T1561", "Disk Wipe")],
        "ddos": [("T1498", "Network Denial of Service"), ("T1499", "Endpoint Denial of Service")],
        "dos": [("T1498", "Network Denial of Service")],
        # Network
        "sniffer": [("T1040", "Network Sniffing")],
        "packet": [("T1040", "Network Sniffing")],
        "arp": [("T1557.002", "ARP Cache Poisoning"), ("T1557", "Adversary-in-the-Middle")],
        "mitm": [("T1557", "Adversary-in-the-Middle")],
        "wifi": [("T1557", "Adversary-in-the-Middle"), ("T1040", "Network Sniffing")],
    }

    # Detection methods by technique category
    DETECTION_MAP = {
        "T1046": ["Network IDS (port scan detection)", "Firewall rate limiting", "Honeypot canaries"],
        "T1055": ["EDR process monitoring", "ETW tracing", "Memory forensics (Volatility)"],
        "T1059": ["Script block logging", "AMSI scanning", "Process command-line monitoring"],
        "T1071": ["Network traffic analysis", "TLS inspection", "DNS monitoring", "JA3/JA3S fingerprinting"],
        "T1486": ["File system monitoring", "Canary files", "Backup verification", "Process behavior analysis"],
        "T1040": ["Promiscuous mode detection", "ARP monitoring", "802.1X port security"],
        "T1056": ["API hooking detection", "Keyboard driver monitoring", "Behavioral analysis"],
        "T1003": ["LSASS protection (PPL)", "Credential Guard", "Event log monitoring (4624/4625)"],
        "T1110": ["Account lockout policies", "Rate limiting", "Login anomaly detection"],
        "T1041": ["DLP solutions", "Egress filtering", "Data volume anomaly detection"],
        "T1498": ["Rate limiting", "CDN/DDoS protection", "BGP flowspec"],
        "T1557": ["ARP inspection", "802.1X", "DNSSEC", "Certificate pinning"],
        "T1547": ["Autoruns monitoring", "Registry monitoring", "Service creation events"],
    }

    def generate(self, intent_str, code, config=None):
        """Generate threat model for the tool."""
        il = intent_str.lower()
        config = config or {}

        # Find matching ATT&CK techniques
        techniques = []
        seen_ids = set()
        for keyword, techs in self.TECHNIQUE_MAP.items():
            if keyword in il:
                for tid, tname in techs:
                    if tid not in seen_ids:
                        techniques.append({"id": tid, "name": tname, "keyword": keyword})
                        seen_ids.add(tid)

        # Identify IOCs the tool produces
        iocs = self._identify_iocs(code, il)

        # Map detection methods
        detections = []
        seen_detect = set()
        for tech in techniques:
            base_id = tech["id"].split(".")[0]
            for method in self.DETECTION_MAP.get(base_id, []):
                if method not in seen_detect:
                    detections.append(method)
                    seen_detect.add(method)
        if not detections:
            detections = ["Network traffic analysis", "Endpoint detection and response (EDR)",
                          "Process monitoring", "Log correlation (SIEM)"]

        # Countermeasures
        countermeasures = self._suggest_countermeasures(techniques, il)

        # Tactical classification
        kill_chain_phase = self._classify_kill_chain(il)

        return {
            "mitre_techniques": techniques,
            "kill_chain_phase": kill_chain_phase,
            "iocs": iocs,
            "detection_methods": detections,
            "countermeasures": countermeasures,
        }

    def _identify_iocs(self, code, il):
        """Identify Indicators of Compromise the tool produces."""
        iocs = []

        # Network IOCs
        if re.search(r'socket\.|requests\.|http\.|urllib', code):
            iocs.append({"type": "network", "indicator": "Outbound connections on configured port",
                         "persistence": "network logs, PCAP"})
        if re.search(r'bind\s*\(', code):
            iocs.append({"type": "network", "indicator": "Listening port on target",
                         "persistence": "netstat, port scan"})
        if re.search(r'dns|nslookup|resolve', code, re.IGNORECASE):
            iocs.append({"type": "network", "indicator": "DNS queries to C2/exfil domain",
                         "persistence": "DNS logs, passive DNS"})

        # File IOCs
        file_writes = re.findall(r'open\s*\([^)]*["\']([^"\']+)["\'][^)]*["\']w', code)
        for path in file_writes:
            iocs.append({"type": "file", "indicator": f"File created: {path}",
                         "persistence": "disk forensics, MFT"})

        # Process IOCs
        if re.search(r'subprocess|os\.system|Popen', code):
            iocs.append({"type": "process", "indicator": "Child process spawned",
                         "persistence": "process tree, ETW, Sysmon"})
        if "inject" in il or "hollow" in il:
            iocs.append({"type": "process", "indicator": "Memory injected into remote process",
                         "persistence": "memory forensics, VAD analysis"})

        # Registry IOCs (Windows)
        if re.search(r'winreg|RegSetValue|HKEY_', code):
            iocs.append({"type": "registry", "indicator": "Registry modification",
                         "persistence": "registry forensics, RegRipper"})

        # Crypto IOCs
        if re.search(r'encrypt|cipher|AES|RSA|ChaCha', code, re.IGNORECASE):
            iocs.append({"type": "behavioral", "indicator": "Encryption activity (potential ransomware)",
                         "persistence": "entropy analysis, file monitoring"})

        if not iocs:
            iocs.append({"type": "generic", "indicator": "Python process execution",
                         "persistence": "process logs, bash history"})

        return iocs

    def _suggest_countermeasures(self, techniques, il):
        """Suggest countermeasures (what defenders should watch for)."""
        cms = []

        if any("T10" in t["id"][:3] for t in techniques):
            cms.append("Deploy EDR with behavior-based detection")
            cms.append("Enable detailed process logging (Sysmon, auditd)")

        if any("T1071" in t["id"] or "T1573" in t["id"] for t in techniques):
            cms.append("Implement TLS inspection at network boundary")
            cms.append("Monitor for anomalous outbound connections (frequency, volume, destination)")

        if any("T1486" in t["id"] for t in techniques):
            cms.append("Maintain offline backups with integrity verification")
            cms.append("Deploy canary files to detect encryption activity")

        if any("T1040" in t["id"] or "T1557" in t["id"] for t in techniques):
            cms.append("Implement 802.1X port security")
            cms.append("Enable dynamic ARP inspection (DAI)")

        if any("T1110" in t["id"] for t in techniques):
            cms.append("Enforce account lockout policies")
            cms.append("Implement MFA on all accounts")

        if not cms:
            cms.append("Monitor for anomalous process execution patterns")
            cms.append("Implement network segmentation")
            cms.append("Deploy host-based IDS/IPS")

        return cms

    def _classify_kill_chain(self, il):
        """Classify where this tool fits in the cyber kill chain."""
        if any(k in il for k in ("scan", "recon", "enum", "discover")):
            return "Reconnaissance"
        elif any(k in il for k in ("exploit", "vuln", "payload")):
            return "Weaponization / Delivery"
        elif any(k in il for k in ("shell", "beacon", "implant", "inject")):
            return "Installation / C2"
        elif any(k in il for k in ("c2", "c&c", "botnet", "command")):
            return "Command & Control"
        elif any(k in il for k in ("exfil", "harvest", "steal", "dump")):
            return "Actions on Objectives"
        elif any(k in il for k in ("persist", "backdoor", "rootkit")):
            return "Persistence"
        elif any(k in il for k in ("privesc", "escalat")):
            return "Privilege Escalation"
        elif any(k in il for k in ("lateral", "pivot", "spray")):
            return "Lateral Movement"
        elif any(k in il for k in ("ransomware", "wiper", "ddos", "dos")):
            return "Impact"
        elif any(k in il for k in ("keylog", "sniff", "mitm", "arp")):
            return "Collection"
        elif any(k in il for k in ("phish", "social")):
            return "Initial Access"
        return "General Offensive"

    def write_model(self, model, task_dir):
        """Write threat model to task directory."""
        task_dir = Path(task_dir)
        (task_dir / "threat_model.json").write_text(json.dumps(model, indent=2))

        # Human-readable version
        lines = [
            "FORGE THREAT MODEL",
            "=" * 60,
            "",
            f"Kill Chain Phase: {model['kill_chain_phase']}",
            "",
            "MITRE ATT&CK Techniques:",
        ]
        for t in model["mitre_techniques"]:
            lines.append(f"  * {t['id']} -- {t['name']}")

        lines.extend(["", "Indicators of Compromise (IOCs):"])
        for ioc in model["iocs"]:
            lines.append(f"  [{ioc['type'].upper()}] {ioc['indicator']}")
            lines.append(f"    Evidence: {ioc['persistence']}")

        lines.extend(["", "Detection Methods:"])
        for d in model["detection_methods"]:
            lines.append(f"  * {d}")

        lines.extend(["", "Countermeasures (Blue Team Awareness):"])
        for c in model["countermeasures"]:
            lines.append(f"  * {c}")

        (task_dir / "threat_model.txt").write_text("\n".join(lines))
