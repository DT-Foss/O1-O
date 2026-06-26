"""Control Flow Graph Recovery Engine.

Extracts CFGs from Mach-O, PE, and ELF binaries using pure struct-based
parsing. No disassembler required — uses:
  - Symbol tables (nlist/symtab) for function boundaries
  - Branch pattern matching for ARM64 (B/BL/CBZ/CBNZ/TBZ/TBNZ/B.cond)
  - x86_64 basic branch detection (CALL/JMP/Jcc)
  - Relocation entries for indirect call targets

Part of FORGE Phase M: Static Analysis Infrastructure.
"""
# Dependencies: none
# Depended by: decompiler, xref_engine

import struct
import os
from typing import Any, Dict, List, Optional, Set, Tuple


# ─── ARM64 Instruction Patterns ──────────────────────────────────────

def _decode_arm64_branch(insn: int, addr: int) -> Optional[Dict]:
    """Decode ARM64 branch instruction → target address + type."""
    # B (unconditional): 000101xx xxxxxxxx xxxxxxxx xxxxxxxx
    if (insn >> 26) == 0b000101:
        imm26 = insn & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 -= 0x04000000
        target = addr + imm26 * 4
        return {'type': 'jump', 'target': target}

    # BL (call): 100101xx xxxxxxxx xxxxxxxx xxxxxxxx
    if (insn >> 26) == 0b100101:
        imm26 = insn & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 -= 0x04000000
        target = addr + imm26 * 4
        return {'type': 'call', 'target': target}

    # B.cond: 01010100 xxxxxxxx xxxxxxxx xxx0xxxx
    if (insn >> 24) == 0b01010100 and not (insn & 0x10):
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 -= 0x80000
        target = addr + imm19 * 4
        cond = insn & 0xF
        CONDS = {0: 'eq', 1: 'ne', 2: 'hs', 3: 'lo', 4: 'mi', 5: 'pl',
                 6: 'vs', 7: 'vc', 8: 'hi', 9: 'ls', 10: 'ge', 11: 'lt',
                 12: 'gt', 13: 'le', 14: 'al'}
        return {'type': 'branch', 'target': target, 'cond': CONDS.get(cond, f'c{cond}')}

    # CBZ/CBNZ: x011010x xxxxxxxx xxxxxxxx xxxxxxxx
    if (insn >> 25) & 0x3F == 0b011010:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 -= 0x80000
        target = addr + imm19 * 4
        op = 'cbnz' if (insn >> 24) & 1 else 'cbz'
        return {'type': 'branch', 'target': target, 'cond': op}

    # TBZ/TBNZ: x011011x xxxxxxxx xxxxxxxx xxxxxxxx
    if (insn >> 25) & 0x3F == 0b011011:
        imm14 = (insn >> 5) & 0x3FFF
        if imm14 & 0x2000:
            imm14 -= 0x4000
        target = addr + imm14 * 4
        op = 'tbnz' if (insn >> 24) & 1 else 'tbz'
        return {'type': 'branch', 'target': target, 'cond': op}

    # RET: 1101011001011111000000xxxxx00000
    if (insn & 0xFFFFFC1F) == 0xD65F0000:
        return {'type': 'return'}

    # BLR (indirect call): 1101011000111111000000xxxxx00000
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        reg = (insn >> 5) & 0x1F
        return {'type': 'indirect_call', 'reg': f'x{reg}'}

    # BR (indirect jump): 1101011000011111000000xxxxx00000
    if (insn & 0xFFFFFC1F) == 0xD61F0000:
        reg = (insn >> 5) & 0x1F
        return {'type': 'indirect_jump', 'reg': f'x{reg}'}

    return None


# ─── x86_64 Branch Detection (basic patterns) ───────────────────────

def _detect_x86_branches(data: bytes, base_addr: int) -> List[Dict]:
    """Detect x86_64 branch instructions (simplified pattern matching).

    This is a heuristic approach — scans for common branch opcodes.
    Not a full disassembler, but catches most direct calls/jumps.
    """
    branches = []
    i = 0
    while i < len(data):
        b = data[i]

        # CALL rel32 (E8 xx xx xx xx)
        if b == 0xE8 and i + 5 <= len(data):
            rel = struct.unpack_from('<i', data, i + 1)[0]
            target = base_addr + i + 5 + rel
            branches.append({
                'offset': i, 'addr': base_addr + i,
                'type': 'call', 'target': target,
            })
            i += 5
            continue

        # JMP rel32 (E9 xx xx xx xx)
        if b == 0xE9 and i + 5 <= len(data):
            rel = struct.unpack_from('<i', data, i + 1)[0]
            target = base_addr + i + 5 + rel
            branches.append({
                'offset': i, 'addr': base_addr + i,
                'type': 'jump', 'target': target,
            })
            i += 5
            continue

        # Jcc rel32 (0F 8x xx xx xx xx)
        if b == 0x0F and i + 6 <= len(data) and i + 1 < len(data):
            b2 = data[i + 1]
            if 0x80 <= b2 <= 0x8F:
                rel = struct.unpack_from('<i', data, i + 2)[0]
                target = base_addr + i + 6 + rel
                JCC = {0x80: 'jo', 0x81: 'jno', 0x82: 'jb', 0x83: 'jae',
                       0x84: 'je', 0x85: 'jne', 0x86: 'jbe', 0x87: 'ja',
                       0x88: 'js', 0x89: 'jns', 0x8A: 'jp', 0x8B: 'jnp',
                       0x8C: 'jl', 0x8D: 'jge', 0x8E: 'jle', 0x8F: 'jg'}
                branches.append({
                    'offset': i, 'addr': base_addr + i,
                    'type': 'branch', 'target': target,
                    'cond': JCC.get(b2, f'j{b2:02x}'),
                })
                i += 6
                continue

        # JMP rel8 (EB xx)
        if b == 0xEB and i + 2 <= len(data):
            rel = struct.unpack_from('<b', data, i + 1)[0]
            target = base_addr + i + 2 + rel
            branches.append({
                'offset': i, 'addr': base_addr + i,
                'type': 'jump', 'target': target,
            })
            i += 2
            continue

        # Jcc rel8 (7x xx)
        if 0x70 <= b <= 0x7F and i + 2 <= len(data):
            rel = struct.unpack_from('<b', data, i + 1)[0]
            target = base_addr + i + 2 + rel
            JCC8 = {0x70: 'jo', 0x71: 'jno', 0x72: 'jb', 0x73: 'jae',
                    0x74: 'je', 0x75: 'jne', 0x76: 'jbe', 0x77: 'ja',
                    0x78: 'js', 0x79: 'jns', 0x7A: 'jp', 0x7B: 'jnp',
                    0x7C: 'jl', 0x7D: 'jge', 0x7E: 'jle', 0x7F: 'jg'}
            branches.append({
                'offset': i, 'addr': base_addr + i,
                'type': 'branch', 'target': target,
                'cond': JCC8.get(b, f'j{b:02x}'),
            })
            i += 2
            continue

        # RET (C3)
        if b == 0xC3:
            branches.append({
                'offset': i, 'addr': base_addr + i,
                'type': 'return',
            })
            i += 1
            continue

        # FF /2 = CALL r/m, FF /4 = JMP r/m (indirect)
        if b == 0xFF and i + 2 <= len(data):
            modrm = data[i + 1]
            reg = (modrm >> 3) & 7
            if reg == 2:
                branches.append({
                    'offset': i, 'addr': base_addr + i,
                    'type': 'indirect_call',
                })
            elif reg == 4:
                branches.append({
                    'offset': i, 'addr': base_addr + i,
                    'type': 'indirect_jump',
                })

        i += 1

    return branches


# ─── CFG Node & Graph ────────────────────────────────────────────────

class BasicBlock:
    """A basic block in the control flow graph."""

    def __init__(self, start_addr: int, end_addr: int = 0):
        self.start = start_addr
        self.end = end_addr
        self.successors: List[int] = []     # addresses of successor blocks
        self.predecessors: List[int] = []   # addresses of predecessor blocks
        self.calls: List[int] = []          # call targets from this block
        self.is_entry = False
        self.is_exit = False
        self.branch_type = ''               # '', 'conditional', 'unconditional', 'return'

    def to_dict(self) -> dict:
        return {
            'start': self.start,
            'end': self.end,
            'size': self.end - self.start if self.end > self.start else 0,
            'successors': self.successors,
            'predecessors': self.predecessors,
            'calls': self.calls,
            'is_entry': self.is_entry,
            'is_exit': self.is_exit,
            'branch_type': self.branch_type,
        }


class FunctionCFG:
    """Control flow graph for a single function."""

    def __init__(self, name: str, addr: int, size: int = 0):
        self.name = name
        self.addr = addr
        self.size = size
        self.blocks: Dict[int, BasicBlock] = {}  # keyed by start address
        self.calls_to: Set[int] = set()          # functions this calls
        self.called_by: Set[int] = set()         # functions that call this
        self.num_branches = 0
        self.num_loops = 0

    def add_block(self, block: BasicBlock):
        self.blocks[block.start] = block

    def detect_loops(self):
        """Detect loops via back-edges (successor addr <= block addr)."""
        self.num_loops = 0
        for addr, block in self.blocks.items():
            for succ in block.successors:
                if succ <= addr:  # Back-edge = loop
                    self.num_loops += 1

    def complexity(self) -> int:
        """Cyclomatic complexity: E - N + 2."""
        n = len(self.blocks)
        e = sum(len(b.successors) for b in self.blocks.values())
        return max(1, e - n + 2)

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'addr': self.addr,
            'size': self.size,
            'num_blocks': len(self.blocks),
            'num_branches': self.num_branches,
            'num_loops': self.num_loops,
            'complexity': self.complexity(),
            'calls_to': sorted(self.calls_to),
            'called_by': sorted(self.called_by),
            'blocks': [b.to_dict() for b in sorted(self.blocks.values(), key=lambda x: x.start)],
        }


# ─── Mach-O Symbol Extraction ────────────────────────────────────────

def _extract_macho_functions(data: bytes) -> List[Dict]:
    """Extract function symbols from Mach-O (LC_SYMTAB + __TEXT segment)."""
    magic = struct.unpack_from('<I', data, 0)[0]

    # Handle fat binary
    if magic in (0xCAFEBABE, 0xBEBAFECA):
        nfat = struct.unpack('>I', data[4:8])[0]
        for i in range(min(nfat, 8)):
            fat_off = 8 + i * 20
            cpu = struct.unpack('>I', data[fat_off:fat_off + 4])[0]
            offset = struct.unpack('>I', data[fat_off + 8:fat_off + 12])[0]
            size = struct.unpack('>I', data[fat_off + 12:fat_off + 16])[0]
            if cpu in (0x100000C, 0x100000D, 0x01000007):  # arm64/x86_64
                return _extract_macho_functions(data[offset:offset + size])
        # Fallback to first slice
        offset = struct.unpack('>I', data[16:20])[0]
        size = struct.unpack('>I', data[20:24])[0]
        return _extract_macho_functions(data[offset:offset + size])

    # Determine format
    if magic in (0xFEEDFACF, 0xFEEDFACE):
        fmt = '<'
    elif magic in (0xCFFAEDFE, 0xCEFAEDFE):
        fmt = '>'
    else:
        return []

    is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    hdr_size = 32 if is_64 else 28
    ncmds = struct.unpack_from(fmt + 'I', data, 16)[0]

    # Parse load commands to find LC_SYMTAB and __TEXT segment
    symtab_off = symtab_nsyms = strtab_off = strtab_size = 0
    text_vmaddr = text_fileoff = text_size = 0

    offset = hdr_size
    for _ in range(min(ncmds, 256)):
        if offset + 8 > len(data):
            break
        cmd = struct.unpack_from(fmt + 'I', data, offset)[0]
        cmdsize = struct.unpack_from(fmt + 'I', data, offset + 4)[0]
        if cmdsize < 8:
            break

        # LC_SYMTAB = 0x2
        if cmd == 0x2 and offset + 24 <= len(data):
            symtab_off = struct.unpack_from(fmt + 'I', data, offset + 8)[0]
            symtab_nsyms = struct.unpack_from(fmt + 'I', data, offset + 12)[0]
            strtab_off = struct.unpack_from(fmt + 'I', data, offset + 16)[0]
            strtab_size = struct.unpack_from(fmt + 'I', data, offset + 20)[0]

        # LC_SEGMENT_64 / LC_SEGMENT
        if cmd in (0x19, 0x1):
            segname = data[offset + 8:offset + 24].split(b'\x00')[0].decode('ascii', errors='replace')
            if segname == '__TEXT':
                if cmd == 0x19:  # 64-bit
                    text_vmaddr = struct.unpack_from(fmt + 'Q', data, offset + 24)[0]
                    text_size = struct.unpack_from(fmt + 'Q', data, offset + 32)[0]
                    text_fileoff = struct.unpack_from(fmt + 'Q', data, offset + 40)[0]
                else:  # 32-bit
                    text_vmaddr = struct.unpack_from(fmt + 'I', data, offset + 24)[0]
                    text_size = struct.unpack_from(fmt + 'I', data, offset + 28)[0]
                    text_fileoff = struct.unpack_from(fmt + 'I', data, offset + 32)[0]

        offset += cmdsize

    if not symtab_off or not symtab_nsyms:
        return []

    # Parse symbol table
    functions = []
    nlist_size = 16 if is_64 else 12
    strtab = data[strtab_off:strtab_off + strtab_size] if strtab_off + strtab_size <= len(data) else b''

    for i in range(min(symtab_nsyms, 50000)):
        nlist_off = symtab_off + i * nlist_size
        if nlist_off + nlist_size > len(data):
            break

        n_strx = struct.unpack_from(fmt + 'I', data, nlist_off)[0]
        n_type = data[nlist_off + 4] if nlist_off + 4 < len(data) else 0
        n_sect = data[nlist_off + 5] if nlist_off + 5 < len(data) else 0

        if is_64:
            n_value = struct.unpack_from(fmt + 'Q', data, nlist_off + 8)[0]
        else:
            n_value = struct.unpack_from(fmt + 'I', data, nlist_off + 8)[0]

        # Filter: N_SECT (0x0E) type, in a section, in __TEXT
        if (n_type & 0x0E) != 0x0E:
            continue
        if n_value == 0:
            continue

        # Only functions in __TEXT range
        if text_vmaddr and not (text_vmaddr <= n_value < text_vmaddr + text_size):
            continue

        # Get name
        name = ''
        if n_strx < len(strtab):
            end = strtab.find(b'\x00', n_strx)
            if end > n_strx:
                name = strtab[n_strx:end].decode('utf-8', errors='replace')

        if name:
            functions.append({
                'name': name,
                'addr': n_value,
                'type': 'function',
            })

    # Sort by address and compute sizes
    functions.sort(key=lambda x: x['addr'])
    for i in range(len(functions) - 1):
        functions[i]['size'] = functions[i + 1]['addr'] - functions[i]['addr']
    if functions:
        functions[-1]['size'] = max(16, min(4096, text_size - (functions[-1]['addr'] - text_vmaddr)))

    return functions


# ─── ELF Symbol Extraction ──────────────────────────────────────────

def _extract_elf_functions(data: bytes) -> List[Dict]:
    """Extract function symbols from ELF .symtab or .dynsym."""
    if len(data) < 16 or data[:4] != b'\x7fELF':
        return []

    is_64 = data[4] == 2
    fmt = '<' if data[5] == 1 else '>'

    if is_64:
        e_shoff = struct.unpack_from(fmt + 'Q', data, 40)[0]
        e_shentsize = struct.unpack_from(fmt + 'H', data, 58)[0]
        e_shnum = struct.unpack_from(fmt + 'H', data, 60)[0]
        e_shstrndx = struct.unpack_from(fmt + 'H', data, 62)[0]
    else:
        e_shoff = struct.unpack_from(fmt + 'I', data, 32)[0]
        e_shentsize = struct.unpack_from(fmt + 'H', data, 46)[0]
        e_shnum = struct.unpack_from(fmt + 'H', data, 48)[0]
        e_shstrndx = struct.unpack_from(fmt + 'H', data, 50)[0]

    if e_shoff == 0 or e_shnum == 0:
        return []

    # Get section header string table
    shstrtab = b''
    if e_shstrndx < e_shnum:
        sh_off = e_shoff + e_shstrndx * e_shentsize
        if is_64 and sh_off + 64 <= len(data):
            s_offset = struct.unpack_from(fmt + 'Q', data, sh_off + 24)[0]
            s_size = struct.unpack_from(fmt + 'Q', data, sh_off + 32)[0]
        elif sh_off + 40 <= len(data):
            s_offset = struct.unpack_from(fmt + 'I', data, sh_off + 16)[0]
            s_size = struct.unpack_from(fmt + 'I', data, sh_off + 20)[0]
        else:
            s_offset = s_size = 0
        if s_offset + s_size <= len(data):
            shstrtab = data[s_offset:s_offset + s_size]

    # Find .symtab or .dynsym
    symtab_off = symtab_size = symtab_entsize = symtab_link = 0
    SHT_SYMTAB = 2
    SHT_DYNSYM = 11

    for i in range(min(e_shnum, 256)):
        sh_off = e_shoff + i * e_shentsize
        if sh_off + e_shentsize > len(data):
            break

        if is_64:
            sh_type = struct.unpack_from(fmt + 'I', data, sh_off + 4)[0]
            sh_offset = struct.unpack_from(fmt + 'Q', data, sh_off + 24)[0]
            sh_size = struct.unpack_from(fmt + 'Q', data, sh_off + 32)[0]
            sh_link = struct.unpack_from(fmt + 'I', data, sh_off + 40)[0]
            sh_entsize = struct.unpack_from(fmt + 'Q', data, sh_off + 56)[0]
        else:
            sh_type = struct.unpack_from(fmt + 'I', data, sh_off + 4)[0]
            sh_offset = struct.unpack_from(fmt + 'I', data, sh_off + 16)[0]
            sh_size = struct.unpack_from(fmt + 'I', data, sh_off + 20)[0]
            sh_link = struct.unpack_from(fmt + 'I', data, sh_off + 24)[0]
            sh_entsize = struct.unpack_from(fmt + 'I', data, sh_off + 36)[0]

        if sh_type in (SHT_SYMTAB, SHT_DYNSYM):
            if sh_type == SHT_SYMTAB or not symtab_off:
                symtab_off = sh_offset
                symtab_size = sh_size
                symtab_entsize = sh_entsize or (24 if is_64 else 16)
                symtab_link = sh_link

    if not symtab_off:
        return []

    # Get associated string table
    strtab = b''
    if symtab_link < e_shnum:
        sl_off = e_shoff + symtab_link * e_shentsize
        if is_64 and sl_off + 64 <= len(data):
            sl_offset = struct.unpack_from(fmt + 'Q', data, sl_off + 24)[0]
            sl_size = struct.unpack_from(fmt + 'Q', data, sl_off + 32)[0]
        elif sl_off + 40 <= len(data):
            sl_offset = struct.unpack_from(fmt + 'I', data, sl_off + 16)[0]
            sl_size = struct.unpack_from(fmt + 'I', data, sl_off + 20)[0]
        else:
            sl_offset = sl_size = 0
        if sl_offset + sl_size <= len(data):
            strtab = data[sl_offset:sl_offset + sl_size]

    # Parse symbols
    functions = []
    nsyms = symtab_size // symtab_entsize if symtab_entsize else 0

    for i in range(min(nsyms, 50000)):
        sym_off = symtab_off + i * symtab_entsize
        if sym_off + symtab_entsize > len(data):
            break

        if is_64:
            st_name = struct.unpack_from(fmt + 'I', data, sym_off)[0]
            st_info = data[sym_off + 4]
            st_shndx = struct.unpack_from(fmt + 'H', data, sym_off + 6)[0]
            st_value = struct.unpack_from(fmt + 'Q', data, sym_off + 8)[0]
            st_size = struct.unpack_from(fmt + 'Q', data, sym_off + 16)[0]
        else:
            st_name = struct.unpack_from(fmt + 'I', data, sym_off)[0]
            st_value = struct.unpack_from(fmt + 'I', data, sym_off + 4)[0]
            st_size = struct.unpack_from(fmt + 'I', data, sym_off + 8)[0]
            st_info = data[sym_off + 12]
            st_shndx = struct.unpack_from(fmt + 'H', data, sym_off + 14)[0]

        # Filter: STT_FUNC type (info & 0xF == 2)
        st_type = st_info & 0xF
        if st_type != 2:  # STT_FUNC
            continue
        if st_value == 0 or st_shndx == 0:
            continue

        name = ''
        if st_name < len(strtab):
            end = strtab.find(b'\x00', st_name)
            if end > st_name:
                name = strtab[st_name:end].decode('utf-8', errors='replace')

        if name:
            functions.append({
                'name': name,
                'addr': st_value,
                'size': st_size,
                'type': 'function',
            })

    functions.sort(key=lambda x: x['addr'])
    return functions


# ─── CFG Builder ─────────────────────────────────────────────────────

class CFGEngine:
    """Build control flow graphs from binary files."""

    def __init__(self):
        self.functions: Dict[int, FunctionCFG] = {}
        self.call_graph: Dict[int, Set[int]] = {}
        self.arch = ''

    def analyze(self, filepath: str) -> Dict[str, Any]:
        """Analyze a binary file and extract CFGs."""
        filepath = os.path.expanduser(filepath)
        if not os.path.isfile(filepath):
            return {'error': f'File not found: {filepath}'}

        with open(filepath, 'rb') as f:
            data = f.read()

        # Detect format and extract functions
        if len(data) < 4:
            return {'error': 'File too small'}

        magic = struct.unpack('<I', data[:4])[0]

        if magic in (0xFEEDFACF, 0xFEEDFACE, 0xCFFAEDFE, 0xCEFAEDFE,
                     0xCAFEBABE, 0xBEBAFECA):
            return self._analyze_macho(filepath, data)
        elif data[:4] == b'\x7fELF':
            return self._analyze_elf(filepath, data)
        elif data[:2] == b'MZ':
            return self._analyze_pe(filepath, data)
        else:
            return {'error': f'Unknown format (magic: {data[:4].hex()})'}

    def _analyze_macho(self, filepath: str, data: bytes) -> Dict:
        """Extract CFGs from Mach-O binary."""
        funcs = _extract_macho_functions(data)
        if not funcs:
            return {'file': filepath, 'format': 'macho', 'functions': 0,
                    'error': 'No function symbols found (stripped?)'}

        # Determine architecture
        magic = struct.unpack('<I', data[:4])[0]
        is_fat = magic in (0xCAFEBABE, 0xBEBAFECA)
        if is_fat:
            nfat = struct.unpack('>I', data[4:8])[0]
            cpu = struct.unpack('>I', data[8:12])[0]
        else:
            cpu = struct.unpack('<I', data[4:8])[0]
        self.arch = 'arm64' if cpu in (0x100000C, 0x100000D) else 'x86_64'

        # Get __TEXT data for branch analysis
        text_data, text_vmaddr = self._get_text_section(data)

        # Build CFGs
        self.functions.clear()
        for func in funcs:
            cfg = FunctionCFG(func['name'], func['addr'], func.get('size', 0))

            # Extract branches within function
            if text_data and func.get('size', 0) > 0:
                func_start = func['addr'] - text_vmaddr
                func_end = func_start + func['size']
                if 0 <= func_start < len(text_data) and func_end <= len(text_data):
                    func_data = text_data[func_start:func_end]
                    self._build_cfg(cfg, func_data, func['addr'])

            cfg.detect_loops()
            self.functions[func['addr']] = cfg

        # Build call graph
        self._build_call_graph()

        return self._summarize(filepath, 'macho')

    def _analyze_elf(self, filepath: str, data: bytes) -> Dict:
        """Extract CFGs from ELF binary."""
        funcs = _extract_elf_functions(data)
        if not funcs:
            return {'file': filepath, 'format': 'elf', 'functions': 0,
                    'error': 'No function symbols found (stripped?)'}

        # Determine arch
        e_machine = struct.unpack_from('<H' if data[5] == 1 else '>H', data, 18)[0]
        self.arch = 'arm64' if e_machine == 183 else ('x86_64' if e_machine == 62 else f'em_{e_machine}')

        # Get .text section data
        text_data, text_vmaddr = self._get_elf_text(data)

        self.functions.clear()
        for func in funcs:
            cfg = FunctionCFG(func['name'], func['addr'], func.get('size', 0))

            if text_data and func.get('size', 0) > 0:
                func_start = func['addr'] - text_vmaddr
                func_end = func_start + func['size']
                if 0 <= func_start < len(text_data) and func_end <= len(text_data):
                    func_data = text_data[func_start:func_end]
                    self._build_cfg(cfg, func_data, func['addr'])

            cfg.detect_loops()
            self.functions[func['addr']] = cfg

        self._build_call_graph()
        return self._summarize(filepath, 'elf')

    def _analyze_pe(self, filepath: str, data: bytes) -> Dict:
        """Extract CFGs from PE binary (limited — PE often lacks function symbols)."""
        self.arch = 'x86_64'
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_offset + 24 > len(data):
            return {'file': filepath, 'format': 'pe', 'error': 'Invalid PE'}

        machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
        if machine == 0xAA64:
            self.arch = 'arm64'

        # PE usually has no symbol table — try entry point only
        opt_off = pe_offset + 24
        opt_magic = struct.unpack_from('<H', data, opt_off)[0]
        is_64 = opt_magic == 0x20b

        entry = struct.unpack_from('<I', data, opt_off + 16)[0]
        if entry:
            opt_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
            sec_off = opt_off + opt_size
            num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]

            # Find .text section
            text_data = None
            text_rva = 0
            for i in range(min(num_sections, 96)):
                s_off = sec_off + i * 40
                if s_off + 40 > len(data):
                    break
                name = data[s_off:s_off + 8].split(b'\x00')[0]
                s_chars = struct.unpack_from('<I', data, s_off + 36)[0]
                if s_chars & 0x20000000:  # EXECUTE
                    text_rva = struct.unpack_from('<I', data, s_off + 12)[0]
                    raw_off = struct.unpack_from('<I', data, s_off + 20)[0]
                    raw_sz = struct.unpack_from('<I', data, s_off + 16)[0]
                    if raw_off + raw_sz <= len(data):
                        text_data = data[raw_off:raw_off + raw_sz]
                    break

            self.functions.clear()
            if text_data:
                cfg = FunctionCFG('_entry', entry, len(text_data))
                self._build_cfg(cfg, text_data, entry)
                cfg.detect_loops()
                self.functions[entry] = cfg

        self._build_call_graph()
        return self._summarize(filepath, 'pe')

    def _get_text_section(self, data: bytes) -> Tuple[Optional[bytes], int]:
        """Get __TEXT,__text section data from Mach-O."""
        magic = struct.unpack_from('<I', data, 0)[0]

        # Handle fat
        if magic in (0xCAFEBABE, 0xBEBAFECA):
            nfat = struct.unpack('>I', data[4:8])[0]
            for i in range(min(nfat, 8)):
                fat_off = 8 + i * 20
                cpu = struct.unpack('>I', data[fat_off:fat_off + 4])[0]
                offset = struct.unpack('>I', data[fat_off + 8:fat_off + 12])[0]
                size = struct.unpack('>I', data[fat_off + 12:fat_off + 16])[0]
                if cpu in (0x100000C, 0x100000D, 0x01000007):
                    return self._get_text_section(data[offset:offset + size])
            offset = struct.unpack('>I', data[16:20])[0]
            size = struct.unpack('>I', data[20:24])[0]
            return self._get_text_section(data[offset:offset + size])

        if magic in (0xFEEDFACF, 0xFEEDFACE):
            fmt = '<'
        elif magic in (0xCFFAEDFE, 0xCEFAEDFE):
            fmt = '>'
        else:
            return None, 0

        is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
        hdr_size = 32 if is_64 else 28
        ncmds = struct.unpack_from(fmt + 'I', data, 16)[0]

        offset = hdr_size
        for _ in range(min(ncmds, 256)):
            if offset + 8 > len(data):
                break
            cmd = struct.unpack_from(fmt + 'I', data, offset)[0]
            cmdsize = struct.unpack_from(fmt + 'I', data, offset + 4)[0]
            if cmdsize < 8:
                break

            if cmd in (0x19, 0x1):  # LC_SEGMENT_64, LC_SEGMENT
                segname = data[offset + 8:offset + 24].split(b'\x00')[0]
                if segname == b'__TEXT':
                    if is_64:
                        nsects = struct.unpack_from(fmt + 'I', data, offset + 64)[0]
                        sect_off = offset + 72
                        sect_size = 80
                    else:
                        nsects = struct.unpack_from(fmt + 'I', data, offset + 48)[0]
                        sect_off = offset + 56
                        sect_size = 68

                    for s in range(min(nsects, 64)):
                        s_off = sect_off + s * sect_size
                        if s_off + sect_size > len(data):
                            break
                        sectname = data[s_off:s_off + 16].split(b'\x00')[0]
                        if sectname == b'__text':
                            if is_64:
                                s_addr = struct.unpack_from(fmt + 'Q', data, s_off + 32)[0]
                                s_size = struct.unpack_from(fmt + 'Q', data, s_off + 40)[0]
                                s_offset = struct.unpack_from(fmt + 'I', data, s_off + 48)[0]
                            else:
                                s_addr = struct.unpack_from(fmt + 'I', data, s_off + 32)[0]
                                s_size = struct.unpack_from(fmt + 'I', data, s_off + 36)[0]
                                s_offset = struct.unpack_from(fmt + 'I', data, s_off + 40)[0]
                            if s_offset + s_size <= len(data):
                                return data[s_offset:s_offset + s_size], s_addr
            offset += cmdsize

        return None, 0

    def _get_elf_text(self, data: bytes) -> Tuple[Optional[bytes], int]:
        """Get .text section data from ELF."""
        is_64 = data[4] == 2
        fmt = '<' if data[5] == 1 else '>'

        if is_64:
            e_shoff = struct.unpack_from(fmt + 'Q', data, 40)[0]
            e_shentsize = struct.unpack_from(fmt + 'H', data, 58)[0]
            e_shnum = struct.unpack_from(fmt + 'H', data, 60)[0]
            e_shstrndx = struct.unpack_from(fmt + 'H', data, 62)[0]
        else:
            e_shoff = struct.unpack_from(fmt + 'I', data, 32)[0]
            e_shentsize = struct.unpack_from(fmt + 'H', data, 46)[0]
            e_shnum = struct.unpack_from(fmt + 'H', data, 48)[0]
            e_shstrndx = struct.unpack_from(fmt + 'H', data, 50)[0]

        # Get shstrtab
        shstrtab = b''
        if e_shstrndx < e_shnum:
            sh = e_shoff + e_shstrndx * e_shentsize
            if is_64 and sh + 64 <= len(data):
                so = struct.unpack_from(fmt + 'Q', data, sh + 24)[0]
                ss = struct.unpack_from(fmt + 'Q', data, sh + 32)[0]
            elif sh + 40 <= len(data):
                so = struct.unpack_from(fmt + 'I', data, sh + 16)[0]
                ss = struct.unpack_from(fmt + 'I', data, sh + 20)[0]
            else:
                so = ss = 0
            if so + ss <= len(data):
                shstrtab = data[so:so + ss]

        for i in range(min(e_shnum, 256)):
            sh = e_shoff + i * e_shentsize
            if sh + e_shentsize > len(data):
                break
            sh_name_idx = struct.unpack_from(fmt + 'I', data, sh)[0]
            name = ''
            if sh_name_idx < len(shstrtab):
                end = shstrtab.find(b'\x00', sh_name_idx)
                if end > sh_name_idx:
                    name = shstrtab[sh_name_idx:end].decode('utf-8', errors='replace')

            if name == '.text':
                if is_64:
                    s_addr = struct.unpack_from(fmt + 'Q', data, sh + 16)[0]
                    s_offset = struct.unpack_from(fmt + 'Q', data, sh + 24)[0]
                    s_size = struct.unpack_from(fmt + 'Q', data, sh + 32)[0]
                else:
                    s_addr = struct.unpack_from(fmt + 'I', data, sh + 12)[0]
                    s_offset = struct.unpack_from(fmt + 'I', data, sh + 16)[0]
                    s_size = struct.unpack_from(fmt + 'I', data, sh + 20)[0]
                if s_offset + s_size <= len(data):
                    return data[s_offset:s_offset + s_size], s_addr

        return None, 0

    def _build_cfg(self, cfg: FunctionCFG, func_data: bytes, base_addr: int):
        """Build basic blocks and edges for a function."""
        if len(func_data) < 4:
            block = BasicBlock(base_addr, base_addr + len(func_data))
            block.is_entry = True
            block.is_exit = True
            cfg.add_block(block)
            return

        # Collect all branch targets and branch instructions
        branches = []
        if self.arch == 'arm64':
            for i in range(0, len(func_data) - 3, 4):
                insn = struct.unpack_from('<I', func_data, i)[0]
                addr = base_addr + i
                decoded = _decode_arm64_branch(insn, addr)
                if decoded:
                    decoded['addr'] = addr
                    decoded['offset'] = i
                    branches.append(decoded)
        else:
            branches = _detect_x86_branches(func_data, base_addr)

        cfg.num_branches = len([b for b in branches if b['type'] in ('branch', 'jump')])

        # Identify block boundaries
        block_starts = {base_addr}  # Entry point
        for br in branches:
            # Branch target is a block start
            target = br.get('target')
            if target and base_addr <= target < base_addr + len(func_data):
                block_starts.add(target)
            # Instruction after branch is a block start
            if br['type'] in ('branch', 'jump', 'return'):
                next_addr = br['addr'] + (4 if self.arch == 'arm64' else
                                          (6 if br.get('cond') and not br['type'] == 'return' else
                                           (5 if br['type'] in ('call', 'jump') and br.get('target') else 1)))
                if base_addr <= next_addr < base_addr + len(func_data):
                    block_starts.add(next_addr)

        # Create blocks
        sorted_starts = sorted(block_starts)
        func_end = base_addr + len(func_data)

        for i, start in enumerate(sorted_starts):
            end = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else func_end
            block = BasicBlock(start, end)
            if start == base_addr:
                block.is_entry = True
            cfg.add_block(block)

        # Add edges
        for br in branches:
            block_addr = max(s for s in sorted_starts if s <= br['addr'])
            block = cfg.blocks.get(block_addr)
            if not block:
                continue

            if br['type'] == 'return':
                block.is_exit = True
                block.branch_type = 'return'

            elif br['type'] == 'jump':
                target = br.get('target')
                if target and target in cfg.blocks:
                    block.successors.append(target)
                    cfg.blocks[target].predecessors.append(block_addr)
                block.branch_type = 'unconditional'

            elif br['type'] == 'branch':
                target = br.get('target')
                if target and target in cfg.blocks:
                    block.successors.append(target)
                    cfg.blocks[target].predecessors.append(block_addr)
                # Fallthrough edge
                next_addr = br['addr'] + (4 if self.arch == 'arm64' else 6)
                if next_addr in cfg.blocks:
                    block.successors.append(next_addr)
                    cfg.blocks[next_addr].predecessors.append(block_addr)
                block.branch_type = 'conditional'

            elif br['type'] == 'call':
                target = br.get('target')
                if target:
                    block.calls.append(target)
                    cfg.calls_to.add(target)

        # Blocks without explicit successors: fallthrough to next block
        for i, start in enumerate(sorted_starts[:-1]):
            block = cfg.blocks[start]
            if not block.successors and not block.is_exit and block.branch_type == '':
                next_start = sorted_starts[i + 1]
                block.successors.append(next_start)
                cfg.blocks[next_start].predecessors.append(start)

    def _build_call_graph(self):
        """Build cross-function call graph."""
        self.call_graph.clear()
        for addr, cfg in self.functions.items():
            self.call_graph[addr] = cfg.calls_to
            for target in cfg.calls_to:
                if target in self.functions:
                    self.functions[target].called_by.add(addr)

    def _summarize(self, filepath: str, fmt: str) -> Dict:
        """Generate analysis summary."""
        total_blocks = sum(len(f.blocks) for f in self.functions.values())
        total_branches = sum(f.num_branches for f in self.functions.values())
        total_loops = sum(f.num_loops for f in self.functions.values())
        total_calls = sum(len(f.calls_to) for f in self.functions.values())

        complexities = [f.complexity() for f in self.functions.values()]
        avg_complexity = sum(complexities) / len(complexities) if complexities else 0
        max_complexity = max(complexities) if complexities else 0

        # Top complex functions
        sorted_funcs = sorted(self.functions.values(), key=lambda f: f.complexity(), reverse=True)
        top_complex = [{'name': f.name, 'complexity': f.complexity(), 'blocks': len(f.blocks),
                        'loops': f.num_loops, 'addr': f.addr}
                       for f in sorted_funcs[:10]]

        # Entry points (functions not called by any other)
        entries = [f for f in self.functions.values() if not f.called_by]
        # Leaf functions (call nothing)
        leaves = [f for f in self.functions.values() if not f.calls_to]

        return {
            'file': filepath,
            'format': fmt,
            'arch': self.arch,
            'functions': len(self.functions),
            'total_blocks': total_blocks,
            'total_branches': total_branches,
            'total_loops': total_loops,
            'total_calls': total_calls,
            'avg_complexity': round(avg_complexity, 1),
            'max_complexity': max_complexity,
            'entry_points': len(entries),
            'leaf_functions': len(leaves),
            'top_complex': top_complex,
        }

    def to_triplets(self) -> List[Dict]:
        """Convert CFG analysis to causal triplets."""
        triplets = []

        for addr, func in self.functions.items():
            # Function → calls → target
            for target in func.calls_to:
                target_func = self.functions.get(target)
                target_name = target_func.name if target_func else f'sub_{target:x}'
                triplets.append({
                    'trigger': func.name,
                    'mechanism': 'calls',
                    'outcome': target_name,
                    'confidence': 0.95,
                })

            # Loop detection
            if func.num_loops > 0:
                triplets.append({
                    'trigger': func.name,
                    'mechanism': 'contains_loop',
                    'outcome': f'loop_count_{func.num_loops}',
                    'confidence': 0.9,
                })

            # High complexity warning
            if func.complexity() > 15:
                triplets.append({
                    'trigger': func.name,
                    'mechanism': 'high_cyclomatic_complexity',
                    'outcome': f'complexity_{func.complexity()}',
                    'confidence': 0.85,
                })

        return triplets

    def format_summary(self, result: Dict) -> str:
        """Format analysis result as text."""
        if 'error' in result and 'arch' not in result:
            return f"CFG Analysis: {result.get('file', '?')}\n  Error: {result['error']}"

        lines = [
            f"CFG Analysis: {result['file']}",
            f"  Format:      {result['format'].upper()} ({result.get('arch', '?')})",
            f"  Functions:   {result['functions']}",
            f"  Basic blocks: {result['total_blocks']}",
            f"  Branches:    {result['total_branches']}",
            f"  Loops:       {result['total_loops']}",
            f"  Call edges:  {result['total_calls']}",
            f"  Avg complexity: {result['avg_complexity']}",
            f"  Max complexity: {result['max_complexity']}",
            f"  Entry points: {result['entry_points']}",
            f"  Leaf funcs:  {result['leaf_functions']}",
        ]

        if result.get('top_complex'):
            lines.append(f"")
            lines.append(f"  Top complex functions:")
            for f in result['top_complex'][:5]:
                lines.append(f"    {f['name'][:40]:40s} cx={f['complexity']:3d} "
                             f"blocks={f['blocks']:3d} loops={f['loops']}")

        return '\n'.join(lines)
