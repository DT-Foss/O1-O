"""Detection Self-Test: Scan FORGE outputs against detection rules.

Ships with common AV/EDR detection patterns (YARA-style string matching,
behavioral patterns, signature heuristics). Scans payloads, identifies
detections, auto-mutates until clean, and learns evasion-detection
relationships as causal triplets.

Detection sources:
  1. Built-in signature patterns (strings, imports, API sequences)
  2. Behavioral heuristics (suspicious function combinations)
  3. Entropy analysis (packing/encryption detection)
  4. Import table analysis (dangerous API combinations)

Part of FORGE Phase O: Operational Evasion Intelligence.
"""
# Dependencies: mutation_engine
# Depended by: mission_package

import ast
import hashlib
import math
import os
import re
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple


# ─── Detection Signatures ───────────────────────────────────────────

# String-based signatures (YARA-like patterns)
STRING_SIGNATURES = {
    'socket_connect': {
        'patterns': [r'socket\.connect', r'\.connect\(\('],
        'severity': 'medium',
        'category': 'network',
        'desc': 'Direct socket connection',
    },
    'reverse_shell': {
        'patterns': [r'subprocess\.Popen.*shell=True', r'os\.dup2.*socket',
                     r'pty\.spawn', r'/bin/sh', r'/bin/bash', r'cmd\.exe'],
        'severity': 'critical',
        'category': 'execution',
        'desc': 'Reverse shell indicators',
    },
    'process_injection': {
        'patterns': [r'ctypes\.windll', r'WriteProcessMemory',
                     r'VirtualAllocEx', r'CreateRemoteThread',
                     r'NtCreateThreadEx', r'RtlCreateUserThread'],
        'severity': 'critical',
        'category': 'injection',
        'desc': 'Process injection API calls',
    },
    'credential_access': {
        'patterns': [r'mimikatz', r'lsass', r'sekurlsa', r'wdigest',
                     r'SAM.*database', r'hashdump', r'credential.*dump'],
        'severity': 'critical',
        'category': 'credential',
        'desc': 'Credential harvesting indicators',
    },
    'registry_persistence': {
        'patterns': [r'winreg\.OpenKey', r'HKEY_CURRENT_USER.*Run',
                     r'HKEY_LOCAL_MACHINE.*Run', r'RegSetValueEx',
                     r'CurrentVersion\\\\Run'],
        'severity': 'high',
        'category': 'persistence',
        'desc': 'Registry Run key persistence',
    },
    'file_encryption': {
        'patterns': [r'\.encrypt\(', r'AES\.new', r'Fernet\(',
                     r'ransom', r'\.locked', r'bitcoin.*wallet'],
        'severity': 'critical',
        'category': 'ransomware',
        'desc': 'File encryption / ransomware indicators',
    },
    'keylogger': {
        'patterns': [r'GetAsyncKeyState', r'SetWindowsHookEx',
                     r'WH_KEYBOARD', r'pynput.*keyboard',
                     r'keyboard\.on_press'],
        'severity': 'high',
        'category': 'spyware',
        'desc': 'Keylogger indicators',
    },
    'data_exfil': {
        'patterns': [r'requests\.post.*data=', r'urllib.*upload',
                     r'ftp.*STOR', r'base64.*encode.*send',
                     r'dns.*query.*encode'],
        'severity': 'high',
        'category': 'exfiltration',
        'desc': 'Data exfiltration patterns',
    },
    'amsi_bypass': {
        'patterns': [r'AmsiScanBuffer', r'amsi\.dll', r'AmsiUtils',
                     r'amsiInitFailed', r'SetProtection.*amsi'],
        'severity': 'critical',
        'category': 'evasion',
        'desc': 'AMSI bypass attempt',
    },
    'powershell_abuse': {
        'patterns': [r'powershell.*-enc', r'powershell.*-nop',
                     r'IEX.*\(New-Object', r'Invoke-Expression',
                     r'downloadstring', r'-ExecutionPolicy.*Bypass'],
        'severity': 'high',
        'category': 'execution',
        'desc': 'PowerShell abuse patterns',
    },
    'shellcode_loader': {
        'patterns': [r'\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}',
                     r'msfvenom', r'shellcode', r'VirtualAlloc.*PAGE_EXECUTE',
                     r'mmap.*PROT_EXEC'],
        'severity': 'critical',
        'category': 'shellcode',
        'desc': 'Shellcode loading patterns',
    },
    'c2_beacon': {
        'patterns': [r'sleep\(\d+\).*while\s+True', r'beacon',
                     r'heartbeat.*interval', r'check_in',
                     r'command.*server.*loop'],
        'severity': 'high',
        'category': 'c2',
        'desc': 'C2 beaconing patterns',
    },
    'privilege_escalation': {
        'patterns': [r'setuid', r'setgid', r'sudo\s',
                     r'AdjustTokenPrivileges', r'SeDebugPrivilege',
                     r'ImpersonateLoggedOnUser'],
        'severity': 'high',
        'category': 'privesc',
        'desc': 'Privilege escalation indicators',
    },
    'anti_debug': {
        'patterns': [r'IsDebuggerPresent', r'NtQueryInformationProcess',
                     r'CheckRemoteDebuggerPresent', r'ptrace.*PTRACE_TRACEME',
                     r'OutputDebugString'],
        'severity': 'medium',
        'category': 'evasion',
        'desc': 'Anti-debugging techniques',
    },
    'network_scan': {
        'patterns': [r'socket.*connect.*range', r'port.*scan',
                     r'nmap', r'masscan', r'syn.*scan'],
        'severity': 'medium',
        'category': 'recon',
        'desc': 'Network scanning activity',
    },
    # ── Real-world AV/EDR rules (CrowdStrike/SentinelOne/Defender patterns) ──
    'wmi_abuse': {
        'patterns': [r'wmi\.WMI\(\)', r'Win32_Process.*Create',
                     r'ActiveScriptEventConsumer', r'CommandLineEventConsumer',
                     r'__EventFilter.*__FilterToConsumer'],
        'severity': 'high',
        'category': 'execution',
        'desc': 'WMI-based execution or persistence',
    },
    'named_pipe_c2': {
        'patterns': [r'CreateNamedPipe', r'ConnectNamedPipe',
                     r'\\\\.\\pipe\\', r'win32pipe\.CreateNamedPipe'],
        'severity': 'high',
        'category': 'c2',
        'desc': 'Named pipe C2 channel',
    },
    'token_manipulation': {
        'patterns': [r'OpenProcessToken', r'DuplicateTokenEx',
                     r'CreateProcessWithToken', r'ImpersonateNamedPipeClient',
                     r'NtOpenProcessToken'],
        'severity': 'critical',
        'category': 'privesc',
        'desc': 'Access token manipulation',
    },
    'dll_injection': {
        'patterns': [r'ctypes.*LoadLibrary', r'GetProcAddress',
                     r'LdrLoadDll', r'RtlCreateUserThread.*LoadLibrary'],
        'severity': 'critical',
        'category': 'injection',
        'desc': 'DLL injection via LoadLibrary/GetProcAddress',
    },
    'scheduled_task_persist': {
        'patterns': [r'schtasks\s+/create', r'ITaskService',
                     r'TASK_TRIGGER_BOOT', r'TASK_TRIGGER_LOGON',
                     r'Register-ScheduledTask'],
        'severity': 'high',
        'category': 'persistence',
        'desc': 'Scheduled task persistence',
    },
    'service_persistence': {
        'patterns': [r'sc\s+create', r'CreateService[AW]?',
                     r'New-Service', r'ChangeServiceConfig',
                     r'SERVICE_AUTO_START'],
        'severity': 'high',
        'category': 'persistence',
        'desc': 'Windows service persistence',
    },
    'lateral_psexec': {
        'patterns': [r'psexec', r'smbexec', r'wmiexec',
                     r'atexec', r'dcomexec',
                     r'impacket\.smbconnection'],
        'severity': 'critical',
        'category': 'lateral',
        'desc': 'Remote execution tools (PsExec-like)',
    },
    'etw_bypass': {
        'patterns': [r'EtwEventWrite', r'NtTraceControl',
                     r'EtwNotificationRegister',
                     r'patch.*etw', r'etw.*patch'],
        'severity': 'critical',
        'category': 'evasion',
        'desc': 'ETW (Event Tracing for Windows) bypass',
    },
    'uac_bypass': {
        'patterns': [r'fodhelper', r'eventvwr.*mmc', r'CMSTPLUA',
                     r'CompMgmtLauncher', r'sdclt',
                     r'DelegateExecute'],
        'severity': 'critical',
        'category': 'privesc',
        'desc': 'UAC bypass technique',
    },
    'sandbox_detect': {
        'patterns': [r'wine_get_unix_file_name', r'SbieDll',
                     r'vmtoolsd', r'VBoxService',
                     r'HKEY.*VMware', r'HKEY.*VirtualBox'],
        'severity': 'medium',
        'category': 'evasion',
        'desc': 'Sandbox/VM detection',
    },
    'browser_cred_theft': {
        'patterns': [r'Login\s*Data.*Chrome', r'logins\.json.*Firefox',
                     r'CryptUnprotectData',
                     r'AppData.*Local.*Google.*Chrome.*User\s*Data'],
        'severity': 'critical',
        'category': 'credential',
        'desc': 'Browser credential theft',
    },
    'clipboard_monitor': {
        'patterns': [r'win32clipboard', r'pyperclip',
                     r'GetClipboardData', r'OpenClipboard',
                     r'CF_TEXT.*clipboard'],
        'severity': 'medium',
        'category': 'spyware',
        'desc': 'Clipboard monitoring/stealing',
    },
    'screenshot_capture': {
        'patterns': [r'ImageGrab\.grab', r'pyautogui\.screenshot',
                     r'GetDesktopWindow.*BitBlt',
                     r'mss\.mss\(\)'],
        'severity': 'medium',
        'category': 'spyware',
        'desc': 'Screenshot capture',
    },
    'cryptominer': {
        'patterns': [r'stratum\+tcp', r'xmrig', r'hashrate',
                     r'cpuminer', r'cryptonight',
                     r'monero.*pool'],
        'severity': 'high',
        'category': 'cryptomining',
        'desc': 'Cryptocurrency mining indicators',
    },
    'dns_tunnel': {
        'patterns': [r'dns\.resolver.*TXT', r'dnslib',
                     r'\.encode\(.*\).*subdomain',
                     r'base32.*\..*domain'],
        'severity': 'high',
        'category': 'exfiltration',
        'desc': 'DNS tunneling for data exfiltration',
    },
    'webcam_capture': {
        'patterns': [r'cv2\.VideoCapture\(0\)', r'picamera',
                     r'DirectShow.*Capture',
                     r'webcam.*capture', r'camera.*stream'],
        'severity': 'high',
        'category': 'spyware',
        'desc': 'Webcam/camera capture',
    },
    'reflective_load': {
        'patterns': [r'Assembly\.Load', r'ReflectiveLoader',
                     r'PELoader', r'RunPE',
                     r'NtAllocateVirtualMemory.*exec'],
        'severity': 'critical',
        'category': 'execution',
        'desc': 'Reflective PE/DLL loading',
    },
    'phishing_mailer': {
        'patterns': [r'smtplib.*SMTP.*sendmail.*(?:for|range|list)',
                     r'MIMEMultipart.*attach.*(?:loop|batch)',
                     r'mail.*merge.*recipient'],
        'severity': 'high',
        'category': 'social_engineering',
        'desc': 'Mass phishing email campaign',
    },
    'log_tampering': {
        'patterns': [r'wevtutil.*cl', r'Clear-EventLog',
                     r'ClearEventLog[AW]?', r'EventLog.*Clear',
                     r'Remove-Item.*\.evtx'],
        'severity': 'high',
        'category': 'defense_evasion',
        'desc': 'Event log clearing/tampering',
    },
    'timestomping': {
        'patterns': [r'SetFileTime', r'os\.utime.*modify',
                     r'NtSetInformationFile.*FileBasicInformation',
                     r'timestomp'],
        'severity': 'medium',
        'category': 'defense_evasion',
        'desc': 'File timestamp manipulation',
    },
    'com_hijack': {
        'patterns': [r'InprocServer32', r'CLSID.*hijack',
                     r'TreatAs.*CLSID',
                     r'ScriptletURL'],
        'severity': 'high',
        'category': 'persistence',
        'desc': 'COM object hijacking',
    },
    'kerberos_attack': {
        'patterns': [r'TGS_REP', r'kerberoast', r'AS_REP.*roast',
                     r'krb5.*ticket', r'golden.*ticket',
                     r'Rubeus'],
        'severity': 'critical',
        'category': 'credential',
        'desc': 'Kerberos attack (kerberoasting/golden ticket)',
    },
    'socks_proxy': {
        'patterns': [r'SOCKS[45]', r'socks\.socksocket',
                     r'PySocks', r'CONNECT.*tunnel',
                     r'ssh.*-D\s+\d+'],
        'severity': 'medium',
        'category': 'lateral',
        'desc': 'SOCKS proxy / network tunneling',
    },
    'lolbin_abuse': {
        'patterns': [r'certutil.*-urlcache', r'certutil.*-decode',
                     r'mshta.*javascript', r'regsvr32.*scrobj',
                     r'rundll32.*javascript', r'bitsadmin.*transfer'],
        'severity': 'high',
        'category': 'execution',
        'desc': 'Living-off-the-land binary abuse',
    },
    'process_hollowing': {
        'patterns': [r'NtUnmapViewOfSection', r'ZwUnmapViewOfSection',
                     r'NtWriteVirtualMemory', r'CREATE_SUSPENDED',
                     r'ResumeThread.*hollow'],
        'severity': 'critical',
        'category': 'injection',
        'desc': 'Process hollowing technique',
    },
    'arp_spoof': {
        'patterns': [r'ARP.*reply.*spoof', r'scapy.*ARP.*op=2',
                     r'arp.*poison', r'arping.*reply',
                     r'is-at.*poison', r'gratuitous.*arp'],
        'severity': 'high',
        'category': 'network',
        'desc': 'ARP spoofing/poisoning',
    },
    'ntlm_relay': {
        'patterns': [r'ntlmrelayx', r'responder', r'NTLM.*relay',
                     r'NTLMv[12].*capture', r'NetNTLM'],
        'severity': 'critical',
        'category': 'credential',
        'desc': 'NTLM relay/capture attack',
    },
    'password_spray': {
        'patterns': [r'password.*spray', r'spray.*password',
                     r'single.*password.*(?:many|all|users)',
                     r'lockout.*threshold.*spray'],
        'severity': 'high',
        'category': 'credential',
        'desc': 'Password spraying attack',
    },
    'rootkit_hooks': {
        'patterns': [r'syscall.*hook', r'IDT.*patch',
                     r'SSDT.*modify', r'inline.*hook.*nt',
                     r'dkom.*process.*hide'],
        'severity': 'critical',
        'category': 'rootkit',
        'desc': 'Kernel-level rootkit hooks',
    },
    'memory_scraping': {
        'patterns': [r'ReadProcessMemory.*track', r'memory.*scrape',
                     r'PANHunter', r'card.*number.*regex.*memory',
                     r'ccnum.*dump'],
        'severity': 'critical',
        'category': 'credential',
        'desc': 'Memory scraping (POS/credit card)',
    },
    'bootkit': {
        'patterns': [r'MBR.*overwrite', r'VBR.*patch',
                     r'bootmgr.*replace', r'UEFI.*implant',
                     r'EFI.*System.*Partition.*write'],
        'severity': 'critical',
        'category': 'persistence',
        'desc': 'Boot sector/UEFI persistence',
    },
}

# Import-based detection (suspicious module combinations)
IMPORT_SIGNATURES = {
    'offensive_combo': {
        'imports': {'socket', 'subprocess'},
        'severity': 'high',
        'desc': 'Socket + subprocess = potential reverse shell',
    },
    'injection_combo': {
        'imports': {'ctypes', 'struct'},
        'severity': 'medium',
        'desc': 'ctypes + struct = potential memory manipulation',
    },
    'crypto_combo': {
        'imports': {'cryptography', 'os'},
        'severity': 'medium',
        'desc': 'Crypto + file ops = potential ransomware',
    },
    'recon_combo': {
        'imports': {'socket', 'threading'},
        'severity': 'medium',
        'desc': 'Socket + threading = potential scanner',
    },
    'exfil_combo': {
        'imports': {'requests', 'base64'},
        'severity': 'medium',
        'desc': 'HTTP + encoding = potential exfiltration',
    },
    'keylog_combo': {
        'imports': {'pynput', 'threading'},
        'severity': 'high',
        'desc': 'Input hook + threading = potential keylogger',
    },
    # ── Extended import combos (real EDR heuristics) ──
    'lateral_combo': {
        'imports': {'impacket', 'socket'},
        'severity': 'critical',
        'desc': 'Impacket + socket = lateral movement tooling',
    },
    'process_manip_combo': {
        'imports': {'ctypes', 'subprocess'},
        'severity': 'high',
        'desc': 'ctypes + subprocess = process manipulation',
    },
    'screen_capture_combo': {
        'imports': {'PIL', 'socket'},
        'severity': 'medium',
        'desc': 'Screenshot + network = spyware exfiltration',
    },
    'scapy_attack_combo': {
        'imports': {'scapy', 'socket'},
        'severity': 'high',
        'desc': 'Scapy + socket = network attack tooling',
    },
    'dns_exfil_combo': {
        'imports': {'dns', 'base64'},
        'severity': 'high',
        'desc': 'DNS + encoding = DNS tunneling exfiltration',
    },
    'smtplib_phish_combo': {
        'imports': {'smtplib', 'email'},
        'severity': 'medium',
        'desc': 'SMTP + email = potential phishing campaign',
    },
    'winreg_persist_combo': {
        'imports': {'winreg', 'os'},
        'severity': 'high',
        'desc': 'Registry + OS = persistence setup',
    },
}

# Behavioral heuristics (AST-level patterns)
BEHAVIOR_SIGNATURES = {
    'exec_eval': {
        'check': lambda tree: any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id in ('exec', 'eval', 'compile')
            for n in ast.walk(tree)
        ),
        'severity': 'high',
        'category': 'execution',
        'desc': 'Dynamic code execution (exec/eval)',
    },
    'base64_decode': {
        'check': lambda tree: any(
            isinstance(n, ast.Attribute) and n.attr in ('b64decode', 'decodebytes')
            for n in ast.walk(tree)
        ),
        'severity': 'medium',
        'category': 'obfuscation',
        'desc': 'Base64 decoding (potential payload)',
    },
    'os_system': {
        'check': lambda tree: any(
            isinstance(n, ast.Attribute) and n.attr == 'system'
            and isinstance(n.value, ast.Name) and n.value.id == 'os'
            for n in ast.walk(tree)
        ),
        'severity': 'high',
        'category': 'execution',
        'desc': 'os.system() command execution',
    },
    'pickle_load': {
        'check': lambda tree: any(
            isinstance(n, ast.Attribute) and n.attr in ('loads', 'load')
            and isinstance(n.value, ast.Name) and n.value.id == 'pickle'
            for n in ast.walk(tree)
        ),
        'severity': 'high',
        'category': 'deserialization',
        'desc': 'Pickle deserialization (RCE risk)',
    },
    'infinite_loop_with_sleep': {
        'check': lambda tree: any(
            isinstance(n, ast.While) and (
                isinstance(n.test, ast.Constant) and n.test.value is True
            )
            for n in ast.walk(tree)
        ),
        'severity': 'low',
        'category': 'c2',
        'desc': 'Infinite loop (potential beacon)',
    },
    # ── Extended behavioral heuristics (real EDR checks) ──
    'dynamic_import': {
        'check': lambda tree: sum(
            1 for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == '__import__'
        ) >= 12,
        'severity': 'medium',
        'category': 'obfuscation',
        'desc': 'Excessive dynamic imports (12+) — heavy obfuscation',
    },
    'getattr_chain': {
        'check': lambda tree: sum(
            1 for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == 'getattr'
        ) >= 15,
        'severity': 'medium',
        'category': 'obfuscation',
        'desc': 'Excessive getattr calls (15+) — heavy API obfuscation',
    },
    'file_walk_exfil': {
        'check': lambda tree: any(
            isinstance(n, ast.Attribute) and n.attr == 'walk'
            and isinstance(n.value, ast.Name) and n.value.id == 'os'
            for n in ast.walk(tree)
        ) and any(
            isinstance(n, ast.Attribute) and n.attr in ('send', 'post', 'put')
            for n in ast.walk(tree)
        ),
        'severity': 'high',
        'category': 'exfiltration',
        'desc': 'File enumeration + network send = data exfiltration',
    },
    'subprocess_hidden': {
        'check': lambda tree: any(
            isinstance(n, ast.keyword) and n.arg == 'creationflags'
            for n in ast.walk(tree)
        ),
        'severity': 'high',
        'category': 'execution',
        'desc': 'Hidden subprocess execution (creationflags)',
    },
}


# ─── Entropy Analysis ───────────────────────────────────────────────

def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of text."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return round(entropy, 3)


# ─── Detection Engine ───────────────────────────────────────────────

class DetectionResult:
    """Result of scanning code against detection rules."""

    def __init__(self):
        self.detections: List[dict] = []
        self.clean = True
        self.score = 0
        self.entropy = 0.0

    def add(self, name: str, category: str, severity: str,
            desc: str, evidence: str = ''):
        self.detections.append({
            'rule': name,
            'category': category,
            'severity': severity,
            'desc': desc,
            'evidence': evidence,
        })
        self.clean = False
        self.score += {'critical': 10, 'high': 7, 'medium': 4, 'low': 2}.get(severity, 1)


class DetectionEngine:
    """Scan code against built-in detection rules.

    Simulates AV/EDR signature and behavioral detection.
    """

    def __init__(self):
        self.scans = 0
        self.detections_total = 0
        self.learned_triplets: List[dict] = []

    def scan(self, code: str) -> DetectionResult:
        """Scan code against all detection rules.

        Returns DetectionResult with all matches.
        """
        self.scans += 1
        result = DetectionResult()

        # 1. String signature scan
        for name, sig in STRING_SIGNATURES.items():
            for pattern in sig['patterns']:
                if re.search(pattern, code, re.IGNORECASE):
                    # Find the matching line for evidence
                    for line_num, line in enumerate(code.split('\n'), 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            evidence = f"Line {line_num}: {line.strip()[:60]}"
                            break
                    else:
                        evidence = f"Pattern: {pattern}"

                    result.add(name, sig['category'], sig['severity'],
                              sig['desc'], evidence)
                    break  # One match per signature is enough

        # 2. Import analysis
        try:
            tree = ast.parse(code)
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])

            for name, sig in IMPORT_SIGNATURES.items():
                if sig['imports'].issubset(imports):
                    result.add(name, 'import_analysis', sig['severity'],
                              sig['desc'], f"Imports: {', '.join(sig['imports'] & imports)}")

            # 3. Behavioral analysis
            for name, sig in BEHAVIOR_SIGNATURES.items():
                try:
                    if sig['check'](tree):
                        result.add(name, sig['category'], sig['severity'],
                                  sig['desc'], '')
                except Exception:
                    pass

        except SyntaxError:
            pass

        # 4. Entropy analysis
        result.entropy = _shannon_entropy(code)
        if result.entropy > 6.5:
            result.add('high_entropy', 'heuristic', 'medium',
                       f'High entropy ({result.entropy:.2f}) — possible encryption/packing',
                       f'Entropy: {result.entropy:.2f} bits/char')

        self.detections_total += len(result.detections)
        return result

    def scan_and_mutate(self, code: str, max_rounds: int = 5,
                        intensity: float = 0.8) -> dict:
        """Scan code, if detected → mutate → rescan until clean.

        Returns:
            {original_detections, rounds, final_code, final_clean,
             mutations_applied, learned_triplets}
        """
        from o1o_o.core.mutation_engine import MutationEngine

        result = {
            'original_code': code,
            'original_detections': [],
            'rounds': [],
            'final_code': code,
            'final_clean': False,
            'total_rounds': 0,
            'learned_triplets': [],
        }

        # Initial scan
        initial = self.scan(code)
        result['original_detections'] = initial.detections

        if initial.clean:
            result['final_clean'] = True
            return result

        current_code = code
        engine = MutationEngine()
        level = 3  # Start at medium intensity

        for round_num in range(1, max_rounds + 1):
            result['total_rounds'] = round_num

            # Generate variants using existing MutationEngine API
            variants = engine.generate_variants(current_code, count=3, level=level)

            round_info = {
                'round': round_num,
                'variants_tested': len(variants),
                'best_score': float('inf'),
                'best_variant': None,
                'detections_before': len(self.scan(current_code).detections),
            }

            # Find variant with fewest detections
            for i, v in enumerate(variants, 1):
                scan_result = self.scan(v['variant'])

                if scan_result.clean:
                    # Clean variant found
                    result['final_code'] = v['variant']
                    result['final_clean'] = True

                    # Learn what worked
                    for det in initial.detections:
                        triplet = {
                            'trigger': f"detected_by_{det['rule']}",
                            'mechanism': f"mutation_level_{level}",
                            'outcome': f"evaded_{det['rule']}",
                            'confidence': 0.8,
                        }
                        result['learned_triplets'].append(triplet)
                        self.learned_triplets.append(triplet)

                    round_info['best_score'] = 0
                    round_info['best_variant'] = i
                    result['rounds'].append(round_info)
                    return result

                if scan_result.score < round_info['best_score']:
                    round_info['best_score'] = scan_result.score
                    round_info['best_variant'] = i
                    current_code = v['variant']

            round_info['detections_after'] = len(self.scan(current_code).detections)
            result['rounds'].append(round_info)

            # Increase level each round (caps at 5)
            level = min(5, level + 1)

        result['final_code'] = current_code
        final_scan = self.scan(current_code)
        result['final_clean'] = final_scan.clean

        return result

    def format_scan(self, result: DetectionResult) -> str:
        """Format scan results."""
        if result.clean:
            return "  CLEAN — No detections"

        lines = [
            f"  DETECTED — {len(result.detections)} rules triggered (score: {result.score})",
            f"  Entropy: {result.entropy:.2f} bits/char",
            f"",
            f"  {'Rule':<25s} {'Severity':>10s} {'Category':<15s} Description",
            f"  {'-' * 75}",
        ]

        for d in sorted(result.detections, key=lambda x: -{'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x['severity'], 0)):
            lines.append(
                f"  {d['rule']:<25s} {d['severity']:>10s} {d['category']:<15s} {d['desc']}"
            )
            if d['evidence']:
                lines.append(f"    → {d['evidence'][:70]}")

        return '\n'.join(lines)

    def format_mutate_result(self, result: dict) -> str:
        """Format scan-and-mutate results."""
        lines = [
            f"  DETECTION SELF-TEST",
            f"  Original detections: {len(result['original_detections'])}",
            f"  Mutation rounds:     {result['total_rounds']}",
            f"  Final status:        {'CLEAN' if result['final_clean'] else 'STILL DETECTED'}",
        ]

        if result['rounds']:
            lines.append(f"")
            for r in result['rounds']:
                det_before = r.get('detections_before', '?')
                det_after = r.get('detections_after', r.get('best_score', '?'))
                lines.append(
                    f"    Round {r['round']}: {r['variants_tested']} variants, "
                    f"best score={r['best_score']}, variant #{r.get('best_variant', '?')}"
                )

        if result['learned_triplets']:
            lines.append(f"")
            lines.append(f"  LEARNED EVASION PATTERNS ({len(result['learned_triplets'])} triplets):")
            for t in result['learned_triplets'][:5]:
                lines.append(f"    {t['trigger']} → {t['mechanism']} → {t['outcome']}")

        return '\n'.join(lines)

    def stats(self) -> dict:
        return {
            'total_scans': self.scans,
            'total_detections': self.detections_total,
            'string_rules': len(STRING_SIGNATURES),
            'import_rules': len(IMPORT_SIGNATURES),
            'behavior_rules': len(BEHAVIOR_SIGNATURES),
            'total_rules': len(STRING_SIGNATURES) + len(IMPORT_SIGNATURES) + len(BEHAVIOR_SIGNATURES),
            'learned_triplets': len(self.learned_triplets),
        }
