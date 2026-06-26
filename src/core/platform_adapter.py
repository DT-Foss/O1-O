"""Platform Adapter: Unified binary analysis across PE, ELF, and Mach-O.

Detects file type from magic bytes, routes to the correct parser,
and normalizes output into a unified format. Single entry point for
all binary analysis in FORGE.

Part of FORGE Phase L: Multi-Platform Support.
"""
# Dependencies: none
# Depended by: decompiler, hunt_loop, target_queue, xref_engine

import struct
import hashlib
import os
import json
from typing import Any, Dict, List, Optional, Tuple


# ─── File Type Detection ─────────────────────────────────────────────

class BinaryFormat:
    PE = 'pe'
    ELF = 'elf'
    MACHO = 'macho'
    MACHO_FAT = 'macho_fat'
    UNKNOWN = 'unknown'


# Magic bytes for detection
MAGIC_TABLE = {
    b'\x7fELF': BinaryFormat.ELF,
    b'MZ': BinaryFormat.PE,
}

MACHO_MAGICS = {
    0xFEEDFACF: BinaryFormat.MACHO,     # 64-bit
    0xFEEDFACE: BinaryFormat.MACHO,     # 32-bit
    0xCFFAEDFE: BinaryFormat.MACHO,     # 64-bit swapped
    0xCEFAEDFE: BinaryFormat.MACHO,     # 32-bit swapped
    0xCAFEBABE: BinaryFormat.MACHO_FAT, # Fat binary
    0xBEBAFECA: BinaryFormat.MACHO_FAT, # Fat binary swapped
}


def detect_format(filepath: str) -> str:
    """Detect binary format from magic bytes."""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(16)
    except (IOError, OSError):
        return BinaryFormat.UNKNOWN

    if len(header) < 4:
        return BinaryFormat.UNKNOWN

    # Check ELF first (4 bytes)
    if header[:4] == b'\x7fELF':
        return BinaryFormat.ELF

    # Check PE (MZ header)
    if header[:2] == b'MZ':
        return BinaryFormat.PE

    # Check Mach-O (4 bytes as uint32)
    magic32 = struct.unpack('<I', header[:4])[0]
    if magic32 in MACHO_MAGICS:
        return MACHO_MAGICS[magic32]

    # Also try big-endian
    magic32_be = struct.unpack('>I', header[:4])[0]
    if magic32_be in MACHO_MAGICS:
        return MACHO_MAGICS[magic32_be]

    return BinaryFormat.UNKNOWN


# ─── Normalized Binary Info ──────────────────────────────────────────

class BinaryInfo:
    """Normalized binary analysis result across all platforms."""

    def __init__(self):
        self.file = ''
        self.size = 0
        self.sha256 = ''
        self.format = BinaryFormat.UNKNOWN  # pe/elf/macho
        self.arch = ''           # x86, x86_64, arm64, etc.
        self.bitness = 0         # 32 or 64
        self.endian = 'little'
        self.file_type = ''      # EXEC, DYN, DLL, DYLIB, etc.
        self.entry_point = 0

        # Security features (normalized)
        self.nx = False          # DEP/NX/W^X
        self.aslr = False        # PIE/DYNAMIC_BASE
        self.stack_canary = False
        self.code_signing = False
        self.cfg = False         # CFG/CET/PAC
        self.relro = 'none'      # none/partial/full (ELF)
        self.fortify = False

        # Sections
        self.sections = []       # [{name, size, prot, ...}]
        self.rwx_sections = 0

        # Libraries/dependencies
        self.libraries = []      # Shared libs / DLL imports

        # Security findings
        self.findings = []       # [(severity, message)]

        # Platform-specific raw data
        self.raw = {}

    def to_dict(self) -> dict:
        return {
            'file': self.file,
            'size': self.size,
            'sha256': self.sha256,
            'format': self.format,
            'arch': self.arch,
            'bitness': self.bitness,
            'endian': self.endian,
            'file_type': self.file_type,
            'entry_point': self.entry_point,
            'security': {
                'nx': self.nx,
                'aslr': self.aslr,
                'stack_canary': self.stack_canary,
                'code_signing': self.code_signing,
                'cfg': self.cfg,
                'relro': self.relro,
                'fortify': self.fortify,
            },
            'sections': self.sections,
            'rwx_sections': self.rwx_sections,
            'libraries': self.libraries,
            'findings': self.findings,
        }

    def security_score(self) -> int:
        """0-100 security hardening score."""
        score = 0
        if self.nx: score += 20
        if self.aslr: score += 20
        if self.stack_canary: score += 15
        if self.code_signing: score += 15
        if self.cfg: score += 10
        if self.relro == 'full': score += 10
        elif self.relro == 'partial': score += 5
        if self.fortify: score += 10
        # Deductions
        if self.rwx_sections > 0:
            score = max(0, score - 20 * self.rwx_sections)
        return min(100, score)

    def risk_level(self) -> str:
        s = self.security_score()
        if s >= 80: return 'LOW'
        if s >= 50: return 'MEDIUM'
        if s >= 25: return 'HIGH'
        return 'CRITICAL'

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            f"Binary Analysis: {self.file}",
            f"  Format:  {self.format.upper()} ({self.arch}, {self.bitness}-bit)",
            f"  Type:    {self.file_type}",
            f"  Size:    {self.size:,} bytes",
            f"  SHA256:  {self.sha256[:16]}...",
            f"  Entry:   0x{self.entry_point:x}",
            f"",
            f"  Security Hardening: {self.security_score()}/100 ({self.risk_level()})",
        ]

        sec = []
        if self.nx: sec.append('NX')
        if self.aslr: sec.append('ASLR')
        if self.stack_canary: sec.append('Canary')
        if self.code_signing: sec.append('CodeSign')
        if self.cfg: sec.append('CFG')
        if self.relro != 'none': sec.append(f'RELRO({self.relro})')
        if self.fortify: sec.append('FORTIFY')
        lines.append(f"  Enabled: {', '.join(sec) if sec else 'NONE'}")

        missing = []
        if not self.nx: missing.append('NX')
        if not self.aslr: missing.append('ASLR')
        if not self.stack_canary: missing.append('Canary')
        if not self.cfg: missing.append('CFG')
        if missing:
            lines.append(f"  Missing: {', '.join(missing)}")

        if self.rwx_sections:
            lines.append(f"  WARNING: {self.rwx_sections} RWX section(s)!")

        if self.libraries:
            lines.append(f"  Libs:    {len(self.libraries)} dependencies")
            for lib in self.libraries[:8]:
                lines.append(f"           - {lib}")
            if len(self.libraries) > 8:
                lines.append(f"           ... +{len(self.libraries) - 8} more")

        if self.findings:
            lines.append(f"")
            lines.append(f"  Findings ({len(self.findings)}):")
            for sev, msg in self.findings[:10]:
                lines.append(f"    [{sev}] {msg}")
            if len(self.findings) > 10:
                lines.append(f"    ... +{len(self.findings) - 10} more")

        return '\n'.join(lines)


# ─── PE Parser (inline, from windows_pe_fragments) ──────────────────

def _parse_pe(filepath: str, data: bytes) -> BinaryInfo:
    """Parse PE binary into normalized BinaryInfo."""
    info = BinaryInfo()
    info.format = BinaryFormat.PE

    if len(data) < 64:
        info.findings.append(('ERROR', 'File too small for PE'))
        return info

    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if pe_offset + 24 > len(data):
        info.findings.append(('ERROR', 'Invalid PE offset'))
        return info

    pe_sig = struct.unpack_from('<I', data, pe_offset)[0]
    if pe_sig != 0x00004550:
        info.findings.append(('ERROR', 'Invalid PE signature'))
        return info

    # COFF header
    coff = pe_offset + 4
    machine = struct.unpack_from('<H', data, coff)[0]
    num_sections = struct.unpack_from('<H', data, coff + 2)[0]
    opt_size = struct.unpack_from('<H', data, coff + 16)[0]
    chars = struct.unpack_from('<H', data, coff + 18)[0]

    MACHINES = {0x14c: 'x86', 0x8664: 'x86_64', 0xaa64: 'arm64', 0x1c0: 'arm'}
    info.arch = MACHINES.get(machine, f'0x{machine:x}')
    info.file_type = 'DLL' if (chars & 0x2000) else 'EXE'

    # Optional header
    opt_off = coff + 20
    if opt_size < 2:
        return info

    opt_magic = struct.unpack_from('<H', data, opt_off)[0]
    is_64 = (opt_magic == 0x20b)
    info.bitness = 64 if is_64 else 32

    if is_64:
        info.entry_point = struct.unpack_from('<I', data, opt_off + 16)[0]
        dll_chars_off = opt_off + 70
        num_dd_off = opt_off + 108
        dd_off = opt_off + 112
    else:
        info.entry_point = struct.unpack_from('<I', data, opt_off + 16)[0]
        dll_chars_off = opt_off + 70
        num_dd_off = opt_off + 92
        dd_off = opt_off + 96

    # DLL characteristics → security features
    if dll_chars_off + 2 <= len(data):
        dll_chars = struct.unpack_from('<H', data, dll_chars_off)[0]
        if dll_chars & 0x0040:
            info.aslr = True
            info.findings.append(('GOOD', 'ASLR enabled (DYNAMIC_BASE)'))
        else:
            info.findings.append(('HIGH', 'ASLR disabled'))
        if dll_chars & 0x0100:
            info.nx = True
            info.findings.append(('GOOD', 'DEP/NX enabled'))
        else:
            info.findings.append(('HIGH', 'DEP disabled'))
        if dll_chars & 0x4000:
            info.cfg = True
            info.findings.append(('GOOD', 'CFG enabled'))
        else:
            info.findings.append(('MEDIUM', 'CFG disabled'))
        if dll_chars & 0x0020:
            info.findings.append(('GOOD', 'High entropy ASLR'))

    # Check security data directory (Authenticode)
    if num_dd_off + 4 <= len(data):
        num_dd = struct.unpack_from('<I', data, num_dd_off)[0]
        if num_dd > 4:  # SECURITY is index 4
            sec_dd_off = dd_off + 4 * 8
            if sec_dd_off + 8 <= len(data):
                sec_rva, sec_size = struct.unpack_from('<II', data, sec_dd_off)
                if sec_rva and sec_size:
                    info.code_signing = True
                    info.findings.append(('GOOD', 'Authenticode signature present'))

    # Sections
    sec_off = opt_off + opt_size
    for i in range(min(num_sections, 96)):
        s_off = sec_off + i * 40
        if s_off + 40 > len(data):
            break
        name = data[s_off:s_off + 8].split(b'\x00')[0].decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', data, s_off + 8)[0]
        s_chars = struct.unpack_from('<I', data, s_off + 36)[0]

        prot = ''
        if s_chars & 0x20000000: prot += 'x'
        if s_chars & 0x40000000: prot += 'r'
        if s_chars & 0x80000000: prot += 'w'

        info.sections.append({'name': name, 'size': vsize, 'prot': prot})
        if 'x' in prot and 'w' in prot:
            info.rwx_sections += 1
            info.findings.append(('CRITICAL', f'RWX section: {name}'))

    # Imports (DLL names only for speed)
    if num_dd_off + 4 <= len(data):
        num_dd = struct.unpack_from('<I', data, num_dd_off)[0]
        if num_dd > 1:
            imp_dd_off = dd_off + 1 * 8  # IMPORT is index 1
            if imp_dd_off + 8 <= len(data):
                imp_rva, imp_size = struct.unpack_from('<II', data, imp_dd_off)
                if imp_rva:
                    _parse_pe_imports(data, info, imp_rva, num_sections, sec_off)

    return info


def _parse_pe_imports(data, info, imp_rva, num_sections, sec_off):
    """Parse PE import directory for DLL names."""
    # RVA to file offset
    for i in range(min(num_sections, 96)):
        s_off = sec_off + i * 40
        if s_off + 40 > len(data):
            return
        s_rva = struct.unpack_from('<I', data, s_off + 12)[0]
        s_rawsz = struct.unpack_from('<I', data, s_off + 16)[0]
        s_rawoff = struct.unpack_from('<I', data, s_off + 20)[0]
        if s_rva <= imp_rva < s_rva + s_rawsz:
            file_off = imp_rva - s_rva + s_rawoff
            # Read import entries
            idx = 0
            while idx < 256:
                ent_off = file_off + idx * 20
                if ent_off + 20 > len(data):
                    break
                name_rva = struct.unpack_from('<I', data, ent_off + 12)[0]
                if name_rva == 0:
                    break
                # Convert name RVA to offset
                for j in range(min(num_sections, 96)):
                    sj_off = sec_off + j * 40
                    if sj_off + 40 > len(data):
                        break
                    sj_rva = struct.unpack_from('<I', data, sj_off + 12)[0]
                    sj_rawsz = struct.unpack_from('<I', data, sj_off + 16)[0]
                    sj_rawoff = struct.unpack_from('<I', data, sj_off + 20)[0]
                    if sj_rva <= name_rva < sj_rva + sj_rawsz:
                        name_off = name_rva - sj_rva + sj_rawoff
                        if name_off < len(data):
                            end = data.find(b'\x00', name_off, min(name_off + 256, len(data)))
                            if end > name_off:
                                dll = data[name_off:end].decode('ascii', errors='replace')
                                info.libraries.append(dll)
                        break
                idx += 1
            return


# ─── ELF Parser (inline, from linux_elf_fragments) ──────────────────

def _parse_elf(filepath: str, data: bytes) -> BinaryInfo:
    """Parse ELF binary into normalized BinaryInfo."""
    info = BinaryInfo()
    info.format = BinaryFormat.ELF

    if len(data) < 16:
        info.findings.append(('ERROR', 'File too small for ELF'))
        return info

    is_64 = (data[4] == 2)
    is_le = (data[5] == 1)
    fmt = '<' if is_le else '>'

    info.bitness = 64 if is_64 else 32
    info.endian = 'little' if is_le else 'big'

    EM = {3: 'x86', 8: 'mips', 20: 'ppc', 40: 'arm', 62: 'x86_64', 183: 'arm64', 243: 'riscv'}
    ET = {1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE'}

    if is_64:
        if len(data) < 64:
            info.findings.append(('ERROR', 'Truncated ELF64'))
            return info
        e_type, e_machine = struct.unpack_from(fmt + 'HH', data, 16)
        e_entry = struct.unpack_from(fmt + 'Q', data, 24)[0]
        e_phoff = struct.unpack_from(fmt + 'Q', data, 32)[0]
        e_shoff = struct.unpack_from(fmt + 'Q', data, 40)[0]
        e_phentsize = struct.unpack_from(fmt + 'H', data, 54)[0]
        e_phnum = struct.unpack_from(fmt + 'H', data, 56)[0]
        e_shentsize = struct.unpack_from(fmt + 'H', data, 58)[0]
        e_shnum = struct.unpack_from(fmt + 'H', data, 60)[0]
        e_shstrndx = struct.unpack_from(fmt + 'H', data, 62)[0]
    else:
        if len(data) < 52:
            info.findings.append(('ERROR', 'Truncated ELF32'))
            return info
        e_type, e_machine = struct.unpack_from(fmt + 'HH', data, 16)
        e_entry = struct.unpack_from(fmt + 'I', data, 24)[0]
        e_phoff = struct.unpack_from(fmt + 'I', data, 28)[0]
        e_shoff = struct.unpack_from(fmt + 'I', data, 32)[0]
        e_phentsize = struct.unpack_from(fmt + 'H', data, 42)[0]
        e_phnum = struct.unpack_from(fmt + 'H', data, 44)[0]
        e_shentsize = struct.unpack_from(fmt + 'H', data, 46)[0]
        e_shnum = struct.unpack_from(fmt + 'H', data, 48)[0]
        e_shstrndx = struct.unpack_from(fmt + 'H', data, 50)[0]

    info.arch = EM.get(e_machine, f'0x{e_machine:x}')
    info.file_type = ET.get(e_type, f'0x{e_type:x}')
    info.entry_point = e_entry

    # PIE check
    if e_type == 3:
        info.aslr = True

    # Parse program headers
    has_relro = False
    has_bind_now = False

    for i in range(min(e_phnum, 64)):
        ph_off = e_phoff + i * e_phentsize
        if ph_off + e_phentsize > len(data):
            break

        if is_64:
            p_type = struct.unpack_from(fmt + 'I', data, ph_off)[0]
            p_flags = struct.unpack_from(fmt + 'I', data, ph_off + 4)[0]
            p_offset = struct.unpack_from(fmt + 'Q', data, ph_off + 8)[0]
            p_filesz = struct.unpack_from(fmt + 'Q', data, ph_off + 32)[0]
        else:
            p_type = struct.unpack_from(fmt + 'I', data, ph_off)[0]
            p_offset = struct.unpack_from(fmt + 'I', data, ph_off + 4)[0]
            p_filesz = struct.unpack_from(fmt + 'I', data, ph_off + 16)[0]
            p_flags = struct.unpack_from(fmt + 'I', data, ph_off + 24)[0]

        # GNU_STACK
        if p_type == 0x6474E551:
            info.nx = not (p_flags & 1)
            if info.nx:
                info.findings.append(('GOOD', 'NX enabled (non-executable stack)'))
            else:
                info.findings.append(('CRITICAL', 'NX disabled — executable stack'))

        # GNU_RELRO
        if p_type == 0x6474E552:
            has_relro = True

        # RWX LOAD
        if p_type == 1 and (p_flags & 7) == 7:
            info.rwx_sections += 1
            info.findings.append(('CRITICAL', f'RWX LOAD segment at offset 0x{p_offset:x}'))

        # DYNAMIC — check for BIND_NOW
        if p_type == 2:
            entry_sz = 16 if is_64 else 8
            for j in range(min(p_filesz // entry_sz, 200)):
                ent_off = p_offset + j * entry_sz
                if ent_off + entry_sz > len(data):
                    break
                if is_64:
                    d_tag = struct.unpack_from(fmt + 'q', data, ent_off)[0]
                    d_val = struct.unpack_from(fmt + 'Q', data, ent_off + 8)[0]
                else:
                    d_tag = struct.unpack_from(fmt + 'i', data, ent_off)[0]
                    d_val = struct.unpack_from(fmt + 'I', data, ent_off + 4)[0]

                if d_tag == 0:
                    break
                if d_tag == 24:  # DT_BIND_NOW
                    has_bind_now = True
                if d_tag == 30:  # DT_FLAGS_1
                    if d_val & 1:
                        has_bind_now = True

        # INTERP
        if p_type == 3 and p_offset + p_filesz <= len(data):
            interp = data[p_offset:p_offset + p_filesz].rstrip(b'\x00')
            info.raw['interpreter'] = interp.decode('utf-8', errors='replace')

    # RELRO status
    if has_relro and has_bind_now:
        info.relro = 'full'
        info.findings.append(('GOOD', 'Full RELRO (RELRO + BIND_NOW)'))
    elif has_relro:
        info.relro = 'partial'
        info.findings.append(('MEDIUM', 'Partial RELRO (no BIND_NOW)'))
    else:
        info.findings.append(('HIGH', 'No RELRO — GOT writable'))

    if not info.aslr:
        info.findings.append(('HIGH', 'No PIE — fixed base address'))
    else:
        info.findings.append(('GOOD', 'PIE enabled'))

    # Stack canary / FORTIFY check via binary string search
    if b'__stack_chk_fail' in data:
        info.stack_canary = True
        info.findings.append(('GOOD', 'Stack canary found'))
    else:
        info.findings.append(('MEDIUM', 'No stack canary detected'))

    if b'_chk@' in data or b'__chk_fail' in data:
        info.fortify = True
        info.findings.append(('GOOD', 'FORTIFY_SOURCE detected'))

    # Section headers — get names via shstrtab
    shstrtab = b''
    if e_shstrndx < e_shnum and e_shoff > 0:
        sh_off = e_shoff + e_shstrndx * e_shentsize
        if is_64 and sh_off + 64 <= len(data):
            s_offset = struct.unpack_from(fmt + 'Q', data, sh_off + 24)[0]
            s_size = struct.unpack_from(fmt + 'Q', data, sh_off + 32)[0]
        elif not is_64 and sh_off + 40 <= len(data):
            s_offset = struct.unpack_from(fmt + 'I', data, sh_off + 16)[0]
            s_size = struct.unpack_from(fmt + 'I', data, sh_off + 20)[0]
        else:
            s_offset = s_size = 0
        if s_offset + s_size <= len(data):
            shstrtab = data[s_offset:s_offset + s_size]

    for i in range(min(e_shnum, 256)):
        sh_off = e_shoff + i * e_shentsize
        if sh_off + e_shentsize > len(data):
            break
        if is_64:
            sh_name_idx = struct.unpack_from(fmt + 'I', data, sh_off)[0]
            sh_flags = struct.unpack_from(fmt + 'Q', data, sh_off + 8)[0]
            sh_size = struct.unpack_from(fmt + 'Q', data, sh_off + 32)[0]
        else:
            sh_name_idx = struct.unpack_from(fmt + 'I', data, sh_off)[0]
            sh_flags = struct.unpack_from(fmt + 'I', data, sh_off + 8)[0]
            sh_size = struct.unpack_from(fmt + 'I', data, sh_off + 20)[0]

        name = ''
        if sh_name_idx < len(shstrtab):
            end = shstrtab.find(b'\x00', sh_name_idx)
            if end > sh_name_idx:
                name = shstrtab[sh_name_idx:end].decode('utf-8', errors='replace')

        prot = ''
        if sh_flags & 1: prot += 'w'
        if sh_flags & 2: prot += 'a'
        if sh_flags & 4: prot += 'x'
        info.sections.append({'name': name, 'size': sh_size, 'prot': prot})

    # Shared libraries from dynamic string table
    _parse_elf_needed(data, info, e_phoff, e_phentsize, e_phnum, fmt, is_64)

    return info


def _parse_elf_needed(data, info, e_phoff, e_phentsize, e_phnum, fmt, is_64):
    """Extract DT_NEEDED shared library names from ELF dynamic section."""
    # Find PT_DYNAMIC
    for i in range(min(e_phnum, 64)):
        ph_off = e_phoff + i * e_phentsize
        if ph_off + e_phentsize > len(data):
            return

        p_type = struct.unpack_from(fmt + 'I', data, ph_off)[0]
        if p_type != 2:  # PT_DYNAMIC
            continue

        if is_64:
            dyn_off = struct.unpack_from(fmt + 'Q', data, ph_off + 8)[0]
            dyn_sz = struct.unpack_from(fmt + 'Q', data, ph_off + 32)[0]
        else:
            dyn_off = struct.unpack_from(fmt + 'I', data, ph_off + 4)[0]
            dyn_sz = struct.unpack_from(fmt + 'I', data, ph_off + 16)[0]

        entry_sz = 16 if is_64 else 8
        needed_offsets = []
        strtab_addr = 0

        # First pass: collect DT_NEEDED offsets and DT_STRTAB address
        for j in range(min(dyn_sz // entry_sz, 500)):
            ent_off = dyn_off + j * entry_sz
            if ent_off + entry_sz > len(data):
                break
            if is_64:
                d_tag = struct.unpack_from(fmt + 'q', data, ent_off)[0]
                d_val = struct.unpack_from(fmt + 'Q', data, ent_off + 8)[0]
            else:
                d_tag = struct.unpack_from(fmt + 'i', data, ent_off)[0]
                d_val = struct.unpack_from(fmt + 'I', data, ent_off + 4)[0]

            if d_tag == 0:
                break
            elif d_tag == 1:  # DT_NEEDED
                needed_offsets.append(d_val)
            elif d_tag == 5:  # DT_STRTAB
                strtab_addr = d_val

        if not strtab_addr or not needed_offsets:
            return

        # Find .dynstr section by matching address
        for sec in info.sections:
            if sec.get('name') == '.dynstr':
                # Find the section's file offset
                sec_idx = info.sections.index(sec)
                sh_off_base = 0
                # We need to find the actual file offset from the section header
                # Use the strtab address to locate it in LOAD segments
                break

        # Locate strtab in file via LOAD segments
        strtab_file_off = None
        for k in range(min(e_phnum, 64)):
            pk_off = e_phoff + k * e_phentsize
            if pk_off + e_phentsize > len(data):
                break
            pk_type = struct.unpack_from(fmt + 'I', data, pk_off)[0]
            if pk_type != 1:  # PT_LOAD
                continue
            if is_64:
                pk_vaddr = struct.unpack_from(fmt + 'Q', data, pk_off + 16)[0]
                pk_offset = struct.unpack_from(fmt + 'Q', data, pk_off + 8)[0]
                pk_filesz = struct.unpack_from(fmt + 'Q', data, pk_off + 32)[0]
            else:
                pk_vaddr = struct.unpack_from(fmt + 'I', data, pk_off + 8)[0]
                pk_offset = struct.unpack_from(fmt + 'I', data, pk_off + 4)[0]
                pk_filesz = struct.unpack_from(fmt + 'I', data, pk_off + 16)[0]

            if pk_vaddr <= strtab_addr < pk_vaddr + pk_filesz:
                strtab_file_off = strtab_addr - pk_vaddr + pk_offset
                break

        if strtab_file_off is None:
            return

        # Resolve needed names
        for n_off in needed_offsets:
            str_off = strtab_file_off + n_off
            if str_off < len(data):
                end = data.find(b'\x00', str_off, min(str_off + 256, len(data)))
                if end > str_off:
                    info.libraries.append(data[str_off:end].decode('utf-8', errors='replace'))
        return


# ─── Mach-O Parser (inline, from ios_security_fragments) ────────────

MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC_32 = 0xFEEDFACE

CPU_MAP = {
    0x7: 'x86', 0x01000007: 'x86_64',
    0xC: 'arm', 0x100000C: 'arm64', 0x100000D: 'arm64e',
}

FTYPE_MAP = {
    1: 'OBJECT', 2: 'EXECUTE', 6: 'DYLIB', 7: 'DYLINKER',
    8: 'BUNDLE', 10: 'DSYM', 11: 'KEXT', 12: 'FILESET',
}

LC_SEGMENT_64 = 0x19
LC_SEGMENT = 0x1
LC_LOAD_DYLIB = 0xC
LC_CODE_SIGNATURE = 0x1D
LC_MAIN = 0x80000028
LC_RPATH = 0x8000001C
LC_ENCRYPTION_INFO_64 = 0x2C


def _parse_macho(filepath: str, data: bytes) -> BinaryInfo:
    """Parse Mach-O binary into normalized BinaryInfo."""
    info = BinaryInfo()
    info.format = BinaryFormat.MACHO

    magic = struct.unpack_from('<I', data, 0)[0]
    if magic == MH_MAGIC_64:
        is_64 = True
        fmt = '<'
    elif magic == MH_MAGIC_32:
        is_64 = False
        fmt = '<'
    elif struct.unpack_from('>I', data, 0)[0] in (MH_MAGIC_64, MH_MAGIC_32):
        is_64 = struct.unpack_from('>I', data, 0)[0] == MH_MAGIC_64
        fmt = '>'
    else:
        info.findings.append(('ERROR', 'Invalid Mach-O magic'))
        return info

    info.bitness = 64 if is_64 else 32
    info.endian = 'little' if fmt == '<' else 'big'
    hdr_size = 32 if is_64 else 28

    if len(data) < hdr_size:
        info.findings.append(('ERROR', 'Truncated Mach-O header'))
        return info

    cputype = struct.unpack_from(fmt + 'I', data, 4)[0]
    filetype = struct.unpack_from(fmt + 'I', data, 12)[0]
    ncmds = struct.unpack_from(fmt + 'I', data, 16)[0]

    info.arch = CPU_MAP.get(cputype, f'0x{cputype:x}')
    info.file_type = FTYPE_MAP.get(filetype, f'0x{filetype:x}')

    # Mach-O flags
    flags = struct.unpack_from(fmt + 'I', data, 24)[0]
    if flags & 0x00000080:  # MH_TWOLEVEL
        info.findings.append(('GOOD', 'Two-level namespaces'))
    if flags & 0x00200000:  # MH_PIE
        info.aslr = True
        info.findings.append(('GOOD', 'PIE enabled (ASLR)'))
    else:
        info.findings.append(('HIGH', 'No PIE — no ASLR'))
    if flags & 0x00000004:  # MH_DYLDLINK
        pass  # Normal for dynamically linked
    if flags & 0x00020000:  # MH_NO_HEAP_EXECUTION
        info.nx = True
        info.findings.append(('GOOD', 'No heap execution'))
    if flags & 0x00010000:  # MH_ALLOW_STACK_EXECUTION
        info.findings.append(('CRITICAL', 'Stack execution ALLOWED'))
    else:
        info.nx = True  # Default on modern macOS

    # Parse load commands
    offset = hdr_size
    for _ in range(min(ncmds, 256)):
        if offset + 8 > len(data):
            break
        cmd = struct.unpack_from(fmt + 'I', data, offset)[0]
        cmdsize = struct.unpack_from(fmt + 'I', data, offset + 4)[0]
        if cmdsize < 8:
            break

        if cmd == LC_SEGMENT_64 or cmd == LC_SEGMENT:
            _parse_macho_segment(data, info, offset, cmd == LC_SEGMENT_64, fmt)

        elif cmd == LC_LOAD_DYLIB:
            _parse_macho_dylib(data, info, offset, cmdsize, fmt)

        elif cmd == LC_CODE_SIGNATURE:
            info.code_signing = True
            info.findings.append(('GOOD', 'Code signature present'))

        elif cmd == LC_MAIN:
            if is_64 and offset + 16 <= len(data):
                info.entry_point = struct.unpack_from(fmt + 'Q', data, offset + 8)[0]
            elif offset + 12 <= len(data):
                info.entry_point = struct.unpack_from(fmt + 'I', data, offset + 8)[0]

        elif cmd == LC_ENCRYPTION_INFO_64 or cmd == 0x21:
            info.findings.append(('INFO', 'Encryption info present (FairPlay?)'))

        offset += cmdsize

    # Stack canary check
    if b'___stack_chk_fail' in data or b'___stack_chk_guard' in data:
        info.stack_canary = True
        info.findings.append(('GOOD', 'Stack canary (__stack_chk_fail)'))

    # ARM64e PAC
    if info.arch == 'arm64e':
        info.cfg = True
        info.findings.append(('GOOD', 'ARM64e PAC (pointer authentication)'))

    return info


def _parse_macho_segment(data, info, offset, is_64, fmt):
    """Parse Mach-O segment command."""
    if is_64:
        if offset + 72 > len(data):
            return
        segname = data[offset + 8:offset + 24].split(b'\x00')[0].decode('ascii', errors='replace')
        vmsize = struct.unpack_from(fmt + 'Q', data, offset + 32)[0]
        initprot = struct.unpack_from(fmt + 'I', data, offset + 56)[0]
        nsects = struct.unpack_from(fmt + 'I', data, offset + 64)[0]
    else:
        if offset + 56 > len(data):
            return
        segname = data[offset + 8:offset + 24].split(b'\x00')[0].decode('ascii', errors='replace')
        vmsize = struct.unpack_from(fmt + 'I', data, offset + 28)[0]
        initprot = struct.unpack_from(fmt + 'I', data, offset + 44)[0]
        nsects = struct.unpack_from(fmt + 'I', data, offset + 48)[0]

    prot = ''
    if initprot & 1: prot += 'r'
    if initprot & 2: prot += 'w'
    if initprot & 4: prot += 'x'

    info.sections.append({'name': segname, 'size': vmsize, 'prot': prot})
    if 'r' in prot and 'w' in prot and 'x' in prot:
        info.rwx_sections += 1
        info.findings.append(('CRITICAL', f'RWX segment: {segname}'))


def _parse_macho_dylib(data, info, offset, cmdsize, fmt):
    """Parse Mach-O LC_LOAD_DYLIB command."""
    if offset + 12 > len(data):
        return
    str_offset = struct.unpack_from(fmt + 'I', data, offset + 8)[0]
    abs_off = offset + str_offset
    if abs_off < len(data):
        end = data.find(b'\x00', abs_off, min(abs_off + 256, len(data)))
        if end > abs_off:
            lib = data[abs_off:end].decode('utf-8', errors='replace')
            # Shorten common paths
            if lib.startswith('/usr/lib/'):
                lib = lib.split('/')[-1]
            elif lib.startswith('/System/Library/'):
                lib = lib.split('/')[-1]
            info.libraries.append(lib)


# ─── Fat Binary Handler ─────────────────────────────────────────────

def _parse_fat(filepath: str, data: bytes) -> BinaryInfo:
    """Parse fat (universal) Mach-O — analyze first slice."""
    magic = struct.unpack('>I', data[:4])[0]
    nfat = struct.unpack('>I', data[4:8])[0]

    if nfat == 0 or nfat > 20:
        info = BinaryInfo()
        info.format = BinaryFormat.MACHO_FAT
        info.findings.append(('ERROR', f'Suspicious fat arch count: {nfat}'))
        return info

    # Prefer arm64 slice, fall back to first
    best_offset = None
    best_size = None
    first_offset = None
    first_size = None

    for i in range(nfat):
        fat_off = 8 + i * 20
        if fat_off + 20 > len(data):
            break
        cpu = struct.unpack('>I', data[fat_off:fat_off + 4])[0]
        offset = struct.unpack('>I', data[fat_off + 8:fat_off + 12])[0]
        size = struct.unpack('>I', data[fat_off + 12:fat_off + 16])[0]

        if first_offset is None:
            first_offset = offset
            first_size = size

        if cpu in (0x100000C, 0x100000D, 0x01000007):  # arm64, arm64e, x86_64
            best_offset = offset
            best_size = size

    use_offset = best_offset if best_offset is not None else first_offset
    use_size = best_size if best_size is not None else first_size

    if use_offset is None or use_offset + use_size > len(data):
        info = BinaryInfo()
        info.format = BinaryFormat.MACHO_FAT
        info.findings.append(('ERROR', 'Fat slice out of bounds'))
        return info

    slice_data = data[use_offset:use_offset + use_size]
    info = _parse_macho(filepath, slice_data)
    info.raw['fat_binary'] = True
    info.raw['fat_arch_count'] = nfat
    info.findings.insert(0, ('INFO', f'Fat binary with {nfat} architecture(s)'))
    return info


# ─── Main Entry Point ───────────────────────────────────────────────

class PlatformAdapter:
    """Unified binary analysis interface."""

    def analyze(self, filepath: str) -> BinaryInfo:
        """Analyze any binary file. Auto-detects format."""
        if not os.path.isfile(filepath):
            info = BinaryInfo()
            info.file = filepath
            info.findings.append(('ERROR', f'File not found: {filepath}'))
            return info

        with open(filepath, 'rb') as f:
            data = f.read()

        info = self._parse(filepath, data)
        info.file = filepath
        info.size = len(data)
        info.sha256 = hashlib.sha256(data).hexdigest()
        return info

    def _parse(self, filepath: str, data: bytes) -> BinaryInfo:
        """Route to correct parser based on magic bytes."""
        if len(data) < 4:
            info = BinaryInfo()
            info.findings.append(('ERROR', 'File too small'))
            return info

        fmt = detect_format(filepath)

        if fmt == BinaryFormat.PE:
            return _parse_pe(filepath, data)
        elif fmt == BinaryFormat.ELF:
            return _parse_elf(filepath, data)
        elif fmt == BinaryFormat.MACHO:
            return _parse_macho(filepath, data)
        elif fmt == BinaryFormat.MACHO_FAT:
            return _parse_fat(filepath, data)
        else:
            info = BinaryInfo()
            magic_hex = data[:4].hex()
            info.findings.append(('ERROR', f'Unknown binary format (magic: {magic_hex})'))
            return info

    def analyze_directory(self, dirpath: str, extensions: Optional[List[str]] = None) -> List[BinaryInfo]:
        """Analyze all binaries in a directory."""
        if extensions is None:
            extensions = ['.exe', '.dll', '.sys', '.so', '.dylib', '.o', '']

        results = []
        for root, dirs, files in os.walk(dirpath):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in extensions or '' in extensions:
                    full = os.path.join(root, f)
                    fmt = detect_format(full)
                    if fmt != BinaryFormat.UNKNOWN:
                        results.append(self.analyze(full))
        return results

    def compare(self, path_a: str, path_b: str) -> dict:
        """Compare two binaries side by side."""
        a = self.analyze(path_a)
        b = self.analyze(path_b)

        diff = {
            'files': [path_a, path_b],
            'same_format': a.format == b.format,
            'same_arch': a.arch == b.arch,
            'score_delta': a.security_score() - b.security_score(),
            'a': {'score': a.security_score(), 'risk': a.risk_level()},
            'b': {'score': b.security_score(), 'risk': b.risk_level()},
            'security_diff': {},
        }

        for feat in ['nx', 'aslr', 'stack_canary', 'code_signing', 'cfg', 'fortify']:
            va = getattr(a, feat)
            vb = getattr(b, feat)
            if va != vb:
                diff['security_diff'][feat] = {'a': va, 'b': vb}

        if a.relro != b.relro:
            diff['security_diff']['relro'] = {'a': a.relro, 'b': b.relro}

        return diff

    def to_triplets(self, info: BinaryInfo) -> List[dict]:
        """Convert binary analysis to causal triplets for FORGE knowledge base."""
        triplets = []

        # Format identification
        triplets.append({
            'trigger': f'{info.format}_binary_detected',
            'mechanism': f'magic_bytes_{info.format}',
            'outcome': f'binary_format_{info.format}_{info.arch}',
            'confidence': 1.0,
        })

        # Security feature triplets
        sec_map = {
            'nx': ('nx_enabled', 'dep_enforcement', 'code_execution_prevented'),
            'aslr': ('aslr_enabled', 'address_randomization', 'exploit_reliability_reduced'),
            'stack_canary': ('stack_canary_present', 'stack_overflow_detection', 'stack_smash_detected'),
            'code_signing': ('code_signing_present', 'signature_verification', 'tamper_detection'),
            'cfg': ('cfg_enabled', 'control_flow_integrity', 'rop_mitigated'),
        }

        for feat, (trigger, mech, outcome) in sec_map.items():
            if getattr(info, feat):
                triplets.append({
                    'trigger': trigger,
                    'mechanism': mech,
                    'outcome': outcome,
                    'confidence': 0.95,
                })

        # RWX sections
        if info.rwx_sections > 0:
            triplets.append({
                'trigger': 'rwx_section_found',
                'mechanism': 'writable_executable_memory',
                'outcome': 'code_injection_possible',
                'confidence': 0.9,
            })

        # Risk level
        triplets.append({
            'trigger': f'security_score_{info.security_score()}',
            'mechanism': f'hardening_assessment_{info.format}',
            'outcome': f'risk_level_{info.risk_level().lower()}',
            'confidence': 0.85,
        })

        return triplets


# ─── Module-level convenience functions ──────────────────────────────

_adapter = PlatformAdapter()

def analyze(filepath: str) -> BinaryInfo:
    """Quick analysis of any binary file."""
    return _adapter.analyze(filepath)

def analyze_dir(dirpath: str) -> List[BinaryInfo]:
    """Analyze all binaries in directory."""
    return _adapter.analyze_directory(dirpath)

def compare(a: str, b: str) -> dict:
    """Compare two binaries."""
    return _adapter.compare(a, b)
