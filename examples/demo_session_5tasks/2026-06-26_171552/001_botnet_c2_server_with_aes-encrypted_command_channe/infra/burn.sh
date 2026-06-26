#!/bin/bash
# FORGE OPSEC — Burn Infrastructure
# Destroys ALL operational infrastructure. Run when operation is complete.
set -euo pipefail

echo "╔══════════════════════════════════════════════════╗"
echo "║  FORGE BURN PROTOCOL — Destroying Infrastructure ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# 1. Stop all services
echo "[1/6] Stopping services..."
docker-compose down --volumes --remove-orphans 2>/dev/null || true
systemctl stop nginx tor 2>/dev/null || true

# 2. Kill all related processes
echo "[2/6] Terminating processes..."
pkill -f "botnet_c2_server_with_aes_encrypted_comm" 2>/dev/null || true
pkill -f "redirector" 2>/dev/null || true
pkill -f "tor" 2>/dev/null || true

# 3. Secure wipe all operational data
echo "[3/6] Secure wiping data..."
INFRA_DIR="$(dirname "$0")"
if command -v shred &>/dev/null; then
    find "$INFRA_DIR/.." -type f -exec shred -vfz -n 3 {} \;
else
    find "$INFRA_DIR/.." -type f -exec dd if=/dev/urandom of={} bs=4k count=1 2>/dev/null \;
fi

# 4. Remove Docker artifacts
echo "[4/6] Purging Docker artifacts..."
docker system prune -af --volumes 2>/dev/null || true
docker network prune -f 2>/dev/null || true

# 5. Clear logs and history
echo "[5/6] Sanitizing logs..."
: > /var/log/syslog 2>/dev/null || true
: > /var/log/auth.log 2>/dev/null || true
: > /var/log/nginx/access.log 2>/dev/null || true
: > /var/log/nginx/error.log 2>/dev/null || true
journalctl --rotate && journalctl --vacuum-time=1s 2>/dev/null || true
unset HISTFILE
history -c 2>/dev/null || true
: > ~/.bash_history 2>/dev/null || true

# 6. Remove all traces
echo "[6/6] Final cleanup..."
rm -rf "$INFRA_DIR/.."
rm -rf /tmp/.forge.* /tmp/forge_*

echo ""
echo "[+] BURN COMPLETE — all infrastructure destroyed."
echo "[+] If this is a VPS, run: shutdown -h now"
