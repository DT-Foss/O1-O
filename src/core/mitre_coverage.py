"""MITRE ATT&CK Coverage Map for FORGE.

Maps fragment keys to ATT&CK technique IDs, computes coverage stats,
and generates ATT&CK Navigator layer JSON.

Usage:
    from core.mitre_coverage import MitreCoverage
    mc = MitreCoverage()
    stats = mc.get_stats()
    layer = mc.generate_navigator_layer()
"""
# Dependencies: json
# Depended by: forge_live.py REPL (/coverage command)

import json
from pathlib import Path
from collections import defaultdict


# ── ATT&CK Tactic IDs ──────────────────────────────────────────────────
TACTICS = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0013",
}

# ── Fragment → ATT&CK Technique Mapping ─────────────────────────────────
# Maps offensive fragment keys to MITRE ATT&CK technique IDs + tactic
FRAGMENT_TECHNIQUE_MAP = {
    # === Reconnaissance (TA0043) ===
    "port_scanner": [("T1046", "Network Service Discovery", "discovery")],
    "network_scanner": [("T1046", "Network Service Discovery", "discovery"), ("T1595.001", "Scanning IP Blocks", "reconnaissance")],
    "service_scanner": [("T1046", "Network Service Discovery", "discovery")],
    "os_detection": [("T1046", "Network Service Discovery", "discovery")],
    "smb_enum": [("T1046", "Network Service Discovery", "discovery"), ("T1135", "Network Share Discovery", "discovery")],
    "snmp_scanner": [("T1046", "Network Service Discovery", "discovery")],
    "dns_enum": [("T1046", "Network Service Discovery", "discovery"), ("T1596.001", "DNS/Passive DNS", "reconnaissance")],
    "subdomain_enum": [("T1596.001", "DNS/Passive DNS", "reconnaissance")],
    "web_scanner": [("T1595.002", "Vulnerability Scanning", "reconnaissance")],
    "directory_bruteforce": [("T1595.003", "Wordlist Scanning", "reconnaissance")],

    # === Initial Access (TA0001) ===
    "ssh_brute_force": [("T1110.001", "Brute Force: Password Guessing", "credential-access")],
    "ssh_credential_tester": [("T1110.001", "Brute Force: Password Guessing", "credential-access")],
    "credential_stuffing": [("T1110.004", "Credential Stuffing", "credential-access")],
    "password_brute_force": [("T1110.001", "Brute Force: Password Guessing", "credential-access")],
    "phishing_page": [("T1566.003", "Phishing: Spearphishing via Service", "initial-access")],
    "phishing_mailer": [("T1566.001", "Phishing: Spearphishing Attachment", "initial-access")],
    "exploit_buffer_overflow": [("T1190", "Exploit Public-Facing Application", "initial-access")],
    "exploit_dev": [("T1190", "Exploit Public-Facing Application", "initial-access"), ("T1203", "Exploitation for Client Execution", "execution")],
    "shellcode_loader": [("T1059.006", "Python", "execution")],

    # === Execution (TA0002) ===
    "reverse_shell": [("T1059.004", "Unix Shell", "execution"), ("T1071.001", "Web Protocols", "command-and-control")],
    "web_shell": [("T1505.003", "Web Shell", "persistence")],
    "command_injection": [("T1059", "Command and Scripting Interpreter", "execution")],
    "sql_injection": [("T1190", "Exploit Public-Facing Application", "initial-access")],
    "code_injection": [("T1059", "Command and Scripting Interpreter", "execution")],

    # === Persistence (TA0003) ===
    "persistence_mechanism": [("T1547.001", "Registry Run Keys", "persistence"), ("T1053.005", "Scheduled Task", "persistence")],
    "registry_persistence": [("T1547.001", "Registry Run Keys", "persistence")],
    "scheduled_task_persist": [("T1053.005", "Scheduled Task", "persistence")],
    "service_persistence": [("T1543.003", "Windows Service", "persistence")],
    "startup_persist": [("T1547.001", "Registry Run Keys", "persistence")],
    "rootkit": [("T1014", "Rootkit", "defense-evasion")],
    "backdoor": [("T1505", "Server Software Component", "persistence")],

    # === Privilege Escalation (TA0004) ===
    "privilege_escalation": [("T1068", "Exploitation for Privilege Escalation", "privilege-escalation")],
    "privesc_checker": [("T1068", "Exploitation for Privilege Escalation", "privilege-escalation")],
    "uac_bypass": [("T1548.002", "Bypass User Account Control", "privilege-escalation")],
    "token_manipulation": [("T1134", "Access Token Manipulation", "privilege-escalation")],

    # === Defense Evasion (TA0005) ===
    "process_hollowing": [("T1055.012", "Process Hollowing", "defense-evasion")],
    "dll_injection": [("T1055.001", "Dynamic-link Library Injection", "defense-evasion")],
    "dll_injector": [("T1055.001", "Dynamic-link Library Injection", "defense-evasion")],
    "anti_debugging": [("T1622", "Debugger Evasion", "defense-evasion")],
    "anti_vm": [("T1497", "Virtualization/Sandbox Evasion", "defense-evasion")],
    "etw_bypass": [("T1562.006", "Indicator Blocking", "defense-evasion")],
    "amsi_bypass": [("T1562.001", "Disable or Modify Tools", "defense-evasion")],
    "reflective_loader": [("T1620", "Reflective Code Loading", "defense-evasion")],
    "packer": [("T1027.002", "Software Packing", "defense-evasion")],
    "steganography": [("T1027.003", "Steganography", "defense-evasion")],
    "obfuscation": [("T1027", "Obfuscated Files or Information", "defense-evasion")],
    "timestomping": [("T1070.006", "Timestomp", "defense-evasion")],
    "log_tampering": [("T1070", "Indicator Removal", "defense-evasion")],

    # === Credential Access (TA0006) ===
    "credential_harvester": [("T1555", "Credentials from Password Stores", "credential-access")],
    "browser_cred_theft": [("T1555.003", "Credentials from Web Browsers", "credential-access")],
    "keylogger": [("T1056.001", "Keylogging", "credential-access")],
    "mimikatz_style": [("T1003.001", "LSASS Memory", "credential-access")],
    "pass_the_hash": [("T1550.002", "Pass the Hash", "lateral-movement")],
    "kerberoast": [("T1558.003", "Kerberoasting", "credential-access")],
    "lsass_dump": [("T1003.001", "LSASS Memory", "credential-access")],
    "ntlm_relay": [("T1557.001", "LLMNR/NBT-NS Poisoning", "credential-access")],
    "password_spray": [("T1110.003", "Password Spraying", "credential-access")],

    # === Discovery (TA0007) ===
    "ad_enum": [("T1087.002", "Domain Account", "discovery")],
    "ldap_enum": [("T1087.002", "Domain Account", "discovery")],
    "network_share_enum": [("T1135", "Network Share Discovery", "discovery")],

    # === Lateral Movement (TA0008) ===
    "lateral_movement": [("T1021", "Remote Services", "lateral-movement")],
    "psexec": [("T1021.002", "SMB/Windows Admin Shares", "lateral-movement")],
    "wmi_exec": [("T1047", "Windows Management Instrumentation", "execution")],
    "ssh_tunnel": [("T1572", "Protocol Tunneling", "command-and-control")],

    # === Collection (TA0009) ===
    "packet_sniffer": [("T1040", "Network Sniffing", "credential-access")],
    "network_sniffer": [("T1040", "Network Sniffing", "credential-access")],
    "screen_capture": [("T1113", "Screen Capture", "collection")],
    "clipboard_monitor": [("T1115", "Clipboard Data", "collection")],
    "webcam_capture": [("T1125", "Video Capture", "collection")],
    "data_exfiltration": [("T1041", "Exfiltration Over C2 Channel", "exfiltration")],

    # === Command and Control (TA0011) ===
    "c2_server": [("T1071.001", "Web Protocols", "command-and-control"), ("T1573.001", "Symmetric Cryptography", "command-and-control")],
    "c2_client": [("T1071.001", "Web Protocols", "command-and-control")],
    "botnet_controller": [("T1071.001", "Web Protocols", "command-and-control"), ("T1090", "Proxy", "command-and-control")],
    "botnet_c2": [("T1071.001", "Web Protocols", "command-and-control")],
    "dns_tunnel": [("T1071.004", "DNS", "command-and-control"), ("T1572", "Protocol Tunneling", "command-and-control")],
    "dns_exfil": [("T1048.001", "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "exfiltration")],
    "icmp_tunnel": [("T1095", "Non-Application Layer Protocol", "command-and-control")],
    "socks_proxy": [("T1090.001", "Internal Proxy", "command-and-control")],

    # === Exfiltration (TA0010) ===
    "data_exfil": [("T1041", "Exfiltration Over C2 Channel", "exfiltration")],

    # === Impact (TA0013) ===
    "ransomware": [("T1486", "Data Encrypted for Impact", "impact"), ("T1490", "Inhibit System Recovery", "impact")],
    "file_encryptor": [("T1486", "Data Encrypted for Impact", "impact")],
    "wiper": [("T1485", "Data Destruction", "impact"), ("T1561", "Disk Wipe", "impact")],
    "ddos": [("T1498", "Network Denial of Service", "impact")],

    # === Network Attacks ===
    "arp_spoof": [("T1557.002", "ARP Cache Poisoning", "credential-access")],
    "arp_spoof_reply": [("T1557.002", "ARP Cache Poisoning", "credential-access")],
    "wifi_deauth": [("T1557", "Adversary-in-the-Middle", "credential-access")],
    "mitm": [("T1557", "Adversary-in-the-Middle", "credential-access")],

    # === ICS/SCADA ===
    "modbus_scanner": [("T0846", "Remote System Discovery", "discovery")],
    "modbus_write": [("T0855", "Unauthorized Command Message", "impact")],
    "modbus_write_registers": [("T0855", "Unauthorized Command Message", "impact")],
    "mqtt_monitor": [("T1040", "Network Sniffing", "credential-access")],
    "ais_spoofer": [("T0830", "Adversary-in-the-Middle", "collection")],
    "nmea_ais_spoofer": [("T0830", "Adversary-in-the-Middle", "collection")],
    "hmi_probe": [("T0846", "Remote System Discovery", "discovery")],
    "ics_fuzzer": [("T0855", "Unauthorized Command Message", "impact")],

    # === Fragment Aliases (actual keys in fragments/*.json) ===
    "ad_enumerator": [("T1087.002", "Domain Account", "discovery")],
    "backdoor_reverse_tcp": [("T1505", "Server Software Component", "persistence")],
    "credential_harvester_wifi": [("T1555", "Credentials from Password Stores", "credential-access")],
    "credential_harvester_env": [("T1555", "Credentials from Password Stores", "credential-access")],
    "credential_harvester_browser": [("T1555.003", "Credentials from Web Browsers", "credential-access")],
    "data_exfiltration_tool": [("T1041", "Exfiltration Over C2 Channel", "exfiltration")],
    "ddos_syn_flood": [("T1498", "Network Denial of Service", "impact")],
    "dns_tunnel_server": [("T1071.004", "DNS", "command-and-control"), ("T1572", "Protocol Tunneling", "command-and-control")],
    "exfil_dns_tunnel": [("T1048.001", "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "exfiltration")],
    "kerberoasting_attack": [("T1558.003", "Kerberoasting", "credential-access")],
    "keylogger_evdev": [("T1056.001", "Keylogging", "credential-access")],
    "keylogger_hook": [("T1056.001", "Keylogging", "credential-access")],
    "c_keylogger": [("T1056.001", "Keylogging", "credential-access")],
    "ssh_lateral_movement": [("T1021", "Remote Services", "lateral-movement")],
    "lateral_movement_orchestrator": [("T1021", "Remote Services", "lateral-movement"), ("T1570", "Lateral Tool Transfer", "lateral-movement")],
    "lsass_dump_concept": [("T1003.001", "LSASS Memory", "credential-access")],
    "mitm_arp_dns": [("T1557", "Adversary-in-the-Middle", "credential-access")],
    "password_brute_forcer": [("T1110.001", "Brute Force: Password Guessing", "credential-access")],
    "port_scanner_socket": [("T1046", "Network Service Discovery", "discovery")],
    "port_scanner_syn": [("T1046", "Network Service Discovery", "discovery")],
    "c_port_scanner": [("T1046", "Network Service Discovery", "discovery")],
    "privilege_escalation_scanner": [("T1068", "Exploitation for Privilege Escalation", "privilege-escalation")],
    "ransomware_encrypt": [("T1486", "Data Encrypted for Impact", "impact"), ("T1490", "Inhibit System Recovery", "impact")],
    "ransomware_decrypt": [("T1486", "Data Encrypted for Impact", "impact")],
    "ransomware_rsa_aes": [("T1486", "Data Encrypted for Impact", "impact")],
    "reverse_shell_payloads": [("T1059.004", "Unix Shell", "execution"), ("T1071.001", "Web Protocols", "command-and-control")],
    "reverse_shell_listener": [("T1059.004", "Unix Shell", "execution")],
    "rootkit_basic": [("T1014", "Rootkit", "defense-evasion")],
    "rootkit_ld_preload": [("T1014", "Rootkit", "defense-evasion"), ("T1574.006", "Dynamic Linker Hijacking", "persistence")],
    "steganography_data_hiding": [("T1027.003", "Steganography", "defense-evasion")],
    "subdomain_enumerator": [("T1596.001", "DNS/Passive DNS", "reconnaissance")],
    "data_destruction_wiper": [("T1485", "Data Destruction", "impact"), ("T1561", "Disk Wipe", "impact")],
    "command_obfuscation": [("T1027", "Obfuscated Files or Information", "defense-evasion")],
    "sleep_obfuscation": [("T1027", "Obfuscated Files or Information", "defense-evasion")],
    "ssh_credential_tester": [("T1110.001", "Brute Force: Password Guessing", "credential-access")],
}


class MitreCoverage:
    """Compute and report MITRE ATT&CK coverage for FORGE."""

    def __init__(self, fragments_dir=None):
        self.fragments_dir = Path(fragments_dir or 'fragments')
        self._fragment_keys = None
        self._coverage = None

    def _load_fragment_keys(self):
        """Load all fragment keys from JSON files."""
        if self._fragment_keys is not None:
            return self._fragment_keys

        keys = set()
        for fpath in self.fragments_dir.glob('*.json'):
            try:
                with open(fpath) as f:
                    data = json.load(f)
                keys.update(data.keys())
            except Exception:
                pass
        self._fragment_keys = keys
        return keys

    def _compute_coverage(self):
        """Compute coverage: which ATT&CK techniques can FORGE generate?"""
        if self._coverage is not None:
            return self._coverage

        keys = self._load_fragment_keys()
        covered_techniques = {}  # technique_id → {name, tactic, fragments}
        tactic_coverage = defaultdict(lambda: {"covered": set(), "fragments": []})

        for frag_key, techniques in FRAGMENT_TECHNIQUE_MAP.items():
            if frag_key in keys:
                for tid, tname, tactic in techniques:
                    if tid not in covered_techniques:
                        covered_techniques[tid] = {
                            "id": tid,
                            "name": tname,
                            "tactic": tactic,
                            "fragments": [],
                        }
                    covered_techniques[tid]["fragments"].append(frag_key)
                    tactic_coverage[tactic]["covered"].add(tid)
                    tactic_coverage[tactic]["fragments"].append(frag_key)

        # Also check fragments via fuzzy key matching
        for frag_key in keys:
            if frag_key in FRAGMENT_TECHNIQUE_MAP:
                continue
            # Try to match by keyword
            fk = frag_key.lower()
            for map_key, techniques in FRAGMENT_TECHNIQUE_MAP.items():
                if map_key in fk or fk in map_key:
                    for tid, tname, tactic in techniques:
                        if tid not in covered_techniques:
                            covered_techniques[tid] = {
                                "id": tid,
                                "name": tname,
                                "tactic": tactic,
                                "fragments": [],
                            }
                        if frag_key not in covered_techniques[tid]["fragments"]:
                            covered_techniques[tid]["fragments"].append(frag_key)
                            tactic_coverage[tactic]["covered"].add(tid)

        self._coverage = {
            "techniques": covered_techniques,
            "tactic_coverage": {k: {"count": len(v["covered"]), "techniques": list(v["covered"])}
                                for k, v in tactic_coverage.items()},
        }
        return self._coverage

    def get_stats(self):
        """Get coverage statistics summary."""
        coverage = self._compute_coverage()
        techniques = coverage["techniques"]
        tactic_cov = coverage["tactic_coverage"]

        # Count unique techniques
        total_techniques = len(techniques)

        # Tactic breakdown
        tactic_stats = {}
        for tactic_name, tactic_id in sorted(TACTICS.items()):
            tc = tactic_cov.get(tactic_name, {"count": 0, "techniques": []})
            tactic_stats[tactic_name] = {
                "tactic_id": tactic_id,
                "covered": tc["count"],
                "techniques": tc["techniques"],
            }

        # Fragment coverage
        keys = self._load_fragment_keys()
        mapped_fragments = sum(1 for k in FRAGMENT_TECHNIQUE_MAP if k in keys)
        total_offensive = len(FRAGMENT_TECHNIQUE_MAP)

        return {
            "total_techniques": total_techniques,
            "total_fragments": len(keys),
            "mapped_fragments": mapped_fragments,
            "total_in_map": total_offensive,
            "tactic_breakdown": tactic_stats,
            "techniques": {tid: {"name": t["name"], "tactic": t["tactic"],
                                  "fragment_count": len(t["fragments"])}
                           for tid, t in techniques.items()},
        }

    def generate_navigator_layer(self):
        """Generate ATT&CK Navigator JSON layer (importable at navigator.mitre-attack.org)."""
        coverage = self._compute_coverage()

        techniques_layer = []
        for tid, tech in coverage["techniques"].items():
            techniques_layer.append({
                "techniqueID": tid,
                "tactic": tech["tactic"],
                "color": "#28a745",  # Green = covered
                "comment": f"FORGE fragments: {', '.join(tech['fragments'][:5])}",
                "enabled": True,
                "score": len(tech["fragments"]),
            })

        layer = {
            "name": "FORGE Code Generation Coverage",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": f"FORGE deterministic code generation — {len(techniques_layer)} ATT&CK techniques covered",
            "filters": {
                "platforms": ["Linux", "Windows", "macOS"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
            },
            "hideDisabled": False,
            "techniques": techniques_layer,
            "gradient": {
                "colors": ["#ff6666", "#ffe766", "#28a745"],
                "minValue": 0,
                "maxValue": 5,
            },
            "legendItems": [
                {"label": "FORGE can generate", "color": "#28a745"},
                {"label": "Not covered", "color": "#ffffff"},
            ],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#205b8f",
            "selectTechniquesAcrossTactics": False,
            "selectSubtechniquesWithParent": False,
        }

        return layer

    def save_layer(self, output_path=None):
        """Save Navigator layer JSON to file."""
        output_path = Path(output_path or 'forge_attack_navigator.json')
        layer = self.generate_navigator_layer()
        output_path.write_text(json.dumps(layer, indent=2))
        return output_path

    def format_summary(self):
        """Format coverage summary for terminal display."""
        stats = self.get_stats()
        lines = []
        lines.append(f"FORGE MITRE ATT&CK Coverage: {stats['total_techniques']} techniques")
        lines.append(f"Fragments mapped: {stats['mapped_fragments']}/{stats['total_in_map']}")
        lines.append("")

        for tactic, info in sorted(stats['tactic_breakdown'].items(),
                                    key=lambda x: x[1]['covered'], reverse=True):
            count = info['covered']
            bar = '#' * min(count, 20)
            lines.append(f"  {tactic:<25s} {count:>3d}  {bar}")

        return "\n".join(lines)
