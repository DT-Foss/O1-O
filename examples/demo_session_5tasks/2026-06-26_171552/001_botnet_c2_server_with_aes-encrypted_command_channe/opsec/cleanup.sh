#!/bin/bash
# FORGE OPSEC Cleanup — eliminate all operational traces
# Run this AFTER the operation is complete
set -euo pipefail

echo "[*] FORGE post-op cleanup starting..."

# 1. Stop and remove containers
echo "[*] Destroying containers..."
docker-compose down --volumes --remove-orphans 2>/dev/null || true
docker system prune -f --volumes 2>/dev/null || true

# 2. Secure wipe workspace (3-pass: random, zeros, random)
WORKSPACE="$(dirname "$0")/.."
echo "[*] Secure wiping workspace..."
if command -v shred &>/dev/null; then
    find "$WORKSPACE" -type f -not -name "cleanup.sh" -exec shred -vfz -n 3 {} \;
elif command -v gshred &>/dev/null; then
    find "$WORKSPACE" -type f -not -name "cleanup.sh" -exec gshred -vfz -n 3 {} \;
else
    # Fallback: overwrite full file with /dev/urandom then zeros
    find "$WORKSPACE" -type f -not -name "cleanup.sh" -exec sh -c 'dd if=/dev/urandom of="$1" bs=4k count=$(($(stat -f%z "$1" 2>/dev/null || stat -c%s "$1" 2>/dev/null || echo 4096)/4096+1)) 2>/dev/null' _ {} \;
    find "$WORKSPACE" -type f -not -name "cleanup.sh" -exec sh -c 'dd if=/dev/zero of="$1" bs=4k count=$(($(stat -f%z "$1" 2>/dev/null || stat -c%s "$1" 2>/dev/null || echo 4096)/4096+1)) 2>/dev/null' _ {} \;
fi

# 3. Remove workspace directory
rm -rf "$WORKSPACE"

# 4. Clear shell history
unset HISTFILE
history -c 2>/dev/null || true
: > ~/.bash_history 2>/dev/null || true
: > ~/.zsh_history 2>/dev/null || true

# 5. Clear recent file lists
rm -f ~/.local/share/recently-used.xbel 2>/dev/null || true

# 6. Docker cleanup — remove any FORGE images
docker images --format '{{.Repository}}:{{.Tag}}' | grep -i forge | xargs -r docker rmi -f 2>/dev/null || true

# 7. Self-destruct this script
shred -vfz -n 3 "$0" 2>/dev/null || rm -f "$0"

echo "[+] Cleanup complete. All traces eliminated."
