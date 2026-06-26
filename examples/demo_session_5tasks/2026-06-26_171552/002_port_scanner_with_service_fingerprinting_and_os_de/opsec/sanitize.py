#!/usr/bin/env python3
"""
FORGE OPSEC — Artifact Sanitizer
Strips all identifiable metadata from generated files.
Run this before deploying any generated tools.
"""
import os
import re
import sys
import random
import string
import struct
from pathlib import Path


def sanitize_python_source(filepath):
    """Remove FORGE markers, normalize code style, strip metadata."""
    code = Path(filepath).read_text()
    original = code

    # Remove FORGE attribution comments
    code = re.sub(r'#.*FORGE.*\n', '\n', code)
    code = re.sub(r'#.*forge.*generated.*\n', '\n', code, flags=re.IGNORECASE)

    # Remove docstring metadata (Intent:, Entities:, Confidence:)
    code = re.sub(
        r'"""\nFORGE-generated.*?"""\n',
        '', code, flags=re.DOTALL
    )
    code = re.sub(
        r"'''\nFORGE-generated.*?'''\n",
        '', code, flags=re.DOTALL
    )

    # Remove any hardcoded timestamps
    code = re.sub(r'# Generated: \d{4}-\d{2}-\d{2}.*\n', '\n', code)

    # Normalize shebang
    if not code.startswith('#!/'):
        code = '#!/usr/bin/env python3\n' + code

    if code != original:
        Path(filepath).write_text(code)
        return True
    return False


def sanitize_binary(filepath):
    """Strip identifiable strings from compiled binary."""
    data = Path(filepath).read_bytes()
    original = data

    # Replace FORGE-related strings
    for marker in [b'FORGE', b'forge_', b'forge-', b'ForgeSession',
                   b'FORGE-generated', b'forge_live']:
        if marker in data:
            replacement = bytes(random.choices(range(65, 91), k=len(marker)))
            data = data.replace(marker, replacement)

    # Replace build paths (PyInstaller embeds source paths)
    data = re.sub(
        rb'/Users/[^\x00]+\.py',
        lambda m: b'/tmp/' + bytes(random.choices(range(97, 123), k=8)) + b'.py',
        data
    )
    data = re.sub(
        rb'C:\\Users\\[^\x00]+\.py',
        lambda m: b'C:\\Windows\\Temp\\' + bytes(random.choices(range(97, 123), k=8)) + b'.py',
        data
    )

    if data != original:
        Path(filepath).write_bytes(data)
        return True
    return False


def randomize_pe_timestamp(filepath):
    """Randomize PE compilation timestamp (Windows executables)."""
    data = bytearray(Path(filepath).read_bytes())
    if data[:2] != b'MZ':
        return False
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        return False
    # TimeDateStamp is at PE offset + 8
    random_ts = random.randint(1577836800, 1735689600)  # 2020-2025
    struct.pack_into('<I', data, pe_offset + 8, random_ts)
    Path(filepath).write_bytes(bytes(data))
    return True


def main():
    target_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('.').parent
    print(f'[*] Sanitizing artifacts in {target_dir}')
    count = 0

    for f in target_dir.rglob('*'):
        if f.is_dir() or f.name == 'sanitize.py':
            continue
        if f.suffix == '.py':
            if sanitize_python_source(f):
                print(f'  [+] Sanitized source: {f.name}')
                count += 1
        elif f.suffix in ('.sh', '.yml', '.yaml', '.conf', '.txt', '.md', '.inf', '.bat', '.profile'):
            # Strip FORGE markers from config/script files
            text = Path(f).read_text()
            original = text
            text = re.sub(r'.*FORGE OPSEC.*\n', '\n', text)
            text = re.sub(r'.*FORGE.*Container.*\n', '\n', text)
            text = re.sub(r'.*FORGE.*generated.*\n', '\n', text, flags=re.IGNORECASE)
            text = re.sub(r'.*forge-\w+.*\n', '\n', text)
            text = re.sub(r'Generated:.*\d{4}-\d{2}-\d{2}.*\n', '\n', text)
            if text != original:
                Path(f).write_text(text)
                print(f'  [+] Sanitized config: {f.name}')
                count += 1
        elif f.suffix in ('.exe', '') and f.stat().st_size > 10000:
            if sanitize_binary(f):
                print(f'  [+] Sanitized binary: {f.name}')
                count += 1
            if f.suffix == '.exe':
                if randomize_pe_timestamp(f):
                    print(f'  [+] Randomized PE timestamp: {f.name}')

    print(f'[+] Sanitized {count} files')


if __name__ == '__main__':
    main()
