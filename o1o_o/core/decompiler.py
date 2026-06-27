"""Decompilation-to-Triplet Pipeline: Binary → Pseudocode → Vulnerability Knowledge.

Combines CFG, XRef, and platform analysis to produce structured vulnerability
knowledge as causal triplets. This is the intelligence layer that turns raw
binary analysis into actionable understanding.

Key capabilities:
  - Function-level vulnerability patterns (buffer overflow, format string, etc.)
  - Argument flow reconstruction (which arg reaches which sink)
  - Stack frame analysis (local variable sizes, canary presence)
  - Security posture assessment per-function
  - Composite vulnerability scoring (multiple weak patterns = higher risk)
  - Full triplet generation for FORGE knowledge base

Part of FORGE Phase M: Deep Binary Analysis.
"""
# Dependencies: cfg_engine, platform_adapter, xref_engine
# Depended by: none (leaf module)

import os
import struct
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict


# ─── Vulnerability Patterns ─────────────────────────────────────────

# Stack buffer overflow indicators
STACK_PATTERNS = {
    'sub_sp_large': {
        'desc': 'Large stack frame allocation (>1024 bytes)',
        'risk': 'stack_buffer_overflow',
        'confidence': 0.6,
    },
    'no_canary_with_buffer': {
        'desc': 'Stack buffer without canary protection',
        'risk': 'stack_smash',
        'confidence': 0.7,
    },
    'unbounded_copy_to_stack': {
        'desc': 'Unbounded copy into stack buffer (strcpy/gets/sprintf)',
        'risk': 'stack_buffer_overflow',
        'confidence': 0.9,
    },
}

# Dangerous function call patterns
DANGEROUS_PATTERNS = {
    # (callee, context_indicator) → vulnerability description
    'strcpy': {'vuln': 'buffer_overflow', 'desc': 'Unbounded string copy', 'severity': 'high'},
    'strcat': {'vuln': 'buffer_overflow', 'desc': 'Unbounded string concatenation', 'severity': 'high'},
    'gets':   {'vuln': 'buffer_overflow', 'desc': 'No length limit on stdin read', 'severity': 'critical'},
    'sprintf': {'vuln': 'buffer_overflow', 'desc': 'Formatted write without length limit', 'severity': 'high'},
    'vsprintf': {'vuln': 'buffer_overflow', 'desc': 'Variadic formatted write without limit', 'severity': 'high'},
    'scanf':  {'vuln': 'buffer_overflow', 'desc': 'Formatted input without field width', 'severity': 'medium'},
    'system': {'vuln': 'command_injection', 'desc': 'Shell command execution', 'severity': 'critical'},
    'popen':  {'vuln': 'command_injection', 'desc': 'Shell pipe execution', 'severity': 'critical'},
    'execve': {'vuln': 'command_injection', 'desc': 'Process execution', 'severity': 'high'},
    'printf': {'vuln': 'format_string', 'desc': 'Format string if user-controlled', 'severity': 'high'},
    'fprintf': {'vuln': 'format_string', 'desc': 'Format string to file', 'severity': 'high'},
    'syslog': {'vuln': 'format_string', 'desc': 'Format string to syslog', 'severity': 'high'},
    'dlopen': {'vuln': 'code_injection', 'desc': 'Dynamic library loading', 'severity': 'high'},
    'dlsym':  {'vuln': 'code_injection', 'desc': 'Dynamic symbol resolution', 'severity': 'medium'},
    'mmap':   {'vuln': 'memory_corruption', 'desc': 'Memory mapping (check PROT_EXEC)', 'severity': 'medium'},
    'alloca': {'vuln': 'stack_overflow', 'desc': 'Dynamic stack allocation', 'severity': 'medium'},
    'setuid': {'vuln': 'privilege_escalation', 'desc': 'UID manipulation', 'severity': 'high'},
    'setgid': {'vuln': 'privilege_escalation', 'desc': 'GID manipulation', 'severity': 'high'},
    'chmod':  {'vuln': 'permission_change', 'desc': 'Permission modification', 'severity': 'medium'},
    'chown':  {'vuln': 'ownership_change', 'desc': 'Ownership modification', 'severity': 'medium'},
    'mktemp': {'vuln': 'race_condition', 'desc': 'Predictable temp file (use mkstemp)', 'severity': 'medium'},
    'tmpnam': {'vuln': 'race_condition', 'desc': 'Predictable temp name (use tmpfile)', 'severity': 'medium'},
    'access': {'vuln': 'toctou', 'desc': 'Check-then-use race (TOCTOU)', 'severity': 'medium'},
    'rand':   {'vuln': 'weak_crypto', 'desc': 'Non-cryptographic PRNG', 'severity': 'low'},
    'srand':  {'vuln': 'weak_crypto', 'desc': 'Predictable PRNG seed', 'severity': 'low'},
}

# Severity scores for composite calculation
SEVERITY_SCORES = {
    'critical': 10,
    'high': 7,
    'medium': 4,
    'low': 2,
    'info': 1,
}

# Security feature impact on exploitability
MITIGATION_IMPACT = {
    'nx': 0.3,           # Makes code injection harder
    'aslr': 0.4,         # Makes ROP/JOP harder
    'stack_canary': 0.5,  # Makes stack smash harder
    'cfg': 0.6,          # Makes control flow hijack harder
    'code_signing': 0.2,  # Makes code modification harder
    'relro': 0.3,        # Makes GOT overwrite harder
    'fortify': 0.3,      # Replaces dangerous functions
}


# ─── Function Analysis ──────────────────────────────────────────────

class FunctionProfile:
    """Vulnerability profile for a single function."""

    def __init__(self, name: str, addr: int = 0):
        self.name = name
        self.addr = addr
        self.size = 0
        self.complexity = 1

        # Stack frame
        self.stack_size = 0
        self.has_canary = False
        self.local_buffers: List[Dict] = []  # {offset, size, type}

        # Calls
        self.dangerous_calls: List[Dict] = []  # {callee, vuln, desc, severity}
        self.safe_calls: List[str] = []
        self.total_calls = 0

        # Data flow
        self.takes_external_input = False
        self.input_sources: List[str] = []
        self.passes_to_sinks: List[str] = []

        # Cross-reference context
        self.callers: List[str] = []
        self.callees: List[str] = []
        self.reachable_from_sources: Set[str] = set()
        self.reaches_sinks: Set[str] = set()

        # Vulnerabilities found
        self.vulns: List[Dict] = []
        self.vuln_score = 0.0

    def add_dangerous_call(self, callee: str, pattern: dict):
        """Record a call to a dangerous function."""
        self.dangerous_calls.append({
            'callee': callee,
            'vuln': pattern['vuln'],
            'desc': pattern['desc'],
            'severity': pattern['severity'],
        })

    def compute_score(self, binary_mitigations: Dict[str, bool] = None) -> float:
        """Compute composite vulnerability score (0-100).

        Factors:
          - Number and severity of dangerous calls (40%)
          - Data flow (attacker input reaches sinks) (25%)
          - Stack frame risk (15%)
          - Complexity (10%)
          - Mitigation discount (10%)
        """
        score = 0.0

        # 1. Dangerous calls (40 points max)
        call_score = 0
        for dc in self.dangerous_calls:
            call_score += SEVERITY_SCORES.get(dc['severity'], 1)
        score += min(40, call_score * 4)

        # 2. Data flow (25 points max)
        if self.takes_external_input and self.passes_to_sinks:
            score += 25
        elif self.takes_external_input:
            score += 10
        elif self.reachable_from_sources and self.reaches_sinks:
            score += 20

        # 3. Stack frame risk (15 points max)
        if self.stack_size > 4096:
            score += 10
        elif self.stack_size > 1024:
            score += 5
        if not self.has_canary and self.stack_size > 256:
            score += 5

        # 4. Complexity (10 points max)
        if self.complexity > 50:
            score += 10
        elif self.complexity > 20:
            score += 7
        elif self.complexity > 10:
            score += 4

        # 5. Mitigation discount (reduce by up to 10 points)
        if binary_mitigations:
            discount = 0
            for mit, impact in MITIGATION_IMPACT.items():
                if binary_mitigations.get(mit, False):
                    discount += impact * 3
            score = max(0, score - min(10, discount))

        self.vuln_score = round(min(100, score), 1)
        return self.vuln_score

    def classify_vulns(self):
        """Classify vulnerabilities based on all collected evidence."""
        self.vulns = []

        # Check dangerous calls
        for dc in self.dangerous_calls:
            vuln = {
                'type': dc['vuln'],
                'severity': dc['severity'],
                'evidence': f"calls {dc['callee']}: {dc['desc']}",
                'confidence': 0.7,
                'function': self.name,
            }

            # Boost confidence if data flow confirms
            if self.takes_external_input:
                vuln['confidence'] = min(0.95, vuln['confidence'] + 0.15)
                vuln['evidence'] += ' (receives external input)'

            if self.reachable_from_sources:
                vuln['confidence'] = min(0.95, vuln['confidence'] + 0.1)

            self.vulns.append(vuln)

        # Stack-specific checks
        if self.stack_size > 1024 and not self.has_canary:
            has_copy = any(dc['vuln'] == 'buffer_overflow' for dc in self.dangerous_calls)
            self.vulns.append({
                'type': 'stack_buffer_overflow',
                'severity': 'high' if has_copy else 'medium',
                'evidence': f'Stack frame {self.stack_size} bytes, no canary'
                           + (', has unbounded copy' if has_copy else ''),
                'confidence': 0.8 if has_copy else 0.5,
                'function': self.name,
            })

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'addr': hex(self.addr),
            'size': self.size,
            'complexity': self.complexity,
            'stack_size': self.stack_size,
            'has_canary': self.has_canary,
            'dangerous_calls': self.dangerous_calls,
            'total_calls': self.total_calls,
            'input_sources': self.input_sources,
            'callers': self.callers,
            'callees': self.callees,
            'vuln_score': self.vuln_score,
            'vulns': self.vulns,
        }


# ─── ARM64 Stack Frame Analysis ─────────────────────────────────────

def _analyze_arm64_stack(func_data: bytes, func_addr: int) -> dict:
    """Analyze ARM64 function prologue/epilogue for stack info.

    Looks for:
      - SUB SP, SP, #imm (stack frame size)
      - STP x29, x30, [SP, ...] (frame pointer save)
      - Stack canary patterns (__stack_chk_guard load + __stack_chk_fail call)
    """
    result = {
        'stack_size': 0,
        'has_frame_pointer': False,
        'has_canary': False,
        'saves_lr': False,
    }

    if len(func_data) < 8:
        return result

    # Check first 20 instructions for prologue
    limit = min(len(func_data), 80)
    for off in range(0, limit, 4):
        if off + 4 > len(func_data):
            break
        insn = struct.unpack_from('<I', func_data, off)[0]

        # SUB SP, SP, #imm: 1101000100 imm12 11111 11111
        # 110100010 0 xxxxxxxxxxxx 11111 11111
        if (insn & 0xFF8003FF) == 0xD10003FF:
            imm12 = (insn >> 10) & 0xFFF
            shift = (insn >> 22) & 0x3
            stack_size = imm12 << (12 if shift else 0)
            if stack_size > result['stack_size']:
                result['stack_size'] = stack_size

        # STP x29, x30, [SP, #off]: xx101001 00 xxxxxxx 11110 11111 11101
        if (insn & 0x7FC003E0) == 0x29000000:
            rt = insn & 0x1F
            rt2 = (insn >> 10) & 0x1F
            rn = (insn >> 5) & 0x1F
            if rn == 31 and rt == 29 and rt2 == 30:
                result['has_frame_pointer'] = True
                result['saves_lr'] = True

        # BL to __stack_chk_fail (canary check)
        if (insn >> 26) == 0b100101:
            # We can't resolve the target here without the full binary,
            # but if we see BL in the last 5 instructions, it might be canary
            if off > limit - 24:
                result['has_canary'] = True  # Heuristic

    return result


def _analyze_x86_stack(func_data: bytes, func_addr: int) -> dict:
    """Analyze x86_64 function prologue for stack info.

    Looks for:
      - PUSH RBP; MOV RBP, RSP (frame setup)
      - SUB RSP, imm (stack allocation)
      - XOR with stack canary patterns
    """
    result = {
        'stack_size': 0,
        'has_frame_pointer': False,
        'has_canary': False,
        'saves_lr': False,
    }

    if len(func_data) < 4:
        return result

    # Check for push rbp; mov rbp, rsp
    if len(func_data) >= 4:
        if func_data[0] == 0x55:  # push rbp
            result['has_frame_pointer'] = True
            # Check for mov rbp, rsp (48 89 E5)
            if len(func_data) >= 4 and func_data[1:4] == b'\x48\x89\xe5':
                result['has_frame_pointer'] = True

    # Look for SUB RSP, imm in first 32 bytes
    for off in range(0, min(len(func_data), 32)):
        # SUB RSP, imm8: 48 83 EC xx
        if off + 4 <= len(func_data) and func_data[off:off + 3] == b'\x48\x83\xec':
            result['stack_size'] = func_data[off + 3]
            break
        # SUB RSP, imm32: 48 81 EC xx xx xx xx
        if off + 7 <= len(func_data) and func_data[off:off + 3] == b'\x48\x81\xec':
            result['stack_size'] = struct.unpack_from('<I', func_data, off + 3)[0]
            break

    # Look for fs:0x28 (stack canary on Linux x86_64)
    # MOV RAX, FS:0x28 = 64 48 8B 04 25 28 00 00 00
    canary_pat = b'\x64\x48\x8b\x04\x25\x28\x00\x00\x00'
    if canary_pat in func_data[:64]:
        result['has_canary'] = True

    return result


# ─── Decompilation Pipeline ─────────────────────────────────────────

class DecompPipeline:
    """Binary → pseudocode-level vulnerability analysis → triplets.

    Orchestrates CFGEngine, XRefEngine, and PlatformAdapter to produce
    structured vulnerability knowledge.
    """

    def __init__(self):
        self.profiles: Dict[str, FunctionProfile] = {}
        self.binary_info = None
        self.cfg_result = None
        self.xref_result = None
        self.mitigations = {}

    def analyze(self, filepath: str) -> dict:
        """Full decompilation analysis pipeline.

        Steps:
          1. Platform analysis (format, arch, security features)
          2. CFG recovery (function boundaries, call graph, complexity)
          3. Cross-reference analysis (sinks, sources, data flow)
          4. Stack frame analysis (per-function)
          5. Vulnerability classification (per-function)
          6. Composite scoring
          7. Triplet generation
        """
        filepath = os.path.expanduser(filepath)
        if not os.path.isfile(filepath):
            return {'error': f'File not found: {filepath}'}

        result = {
            'file': filepath,
            'name': os.path.basename(filepath),
        }

        # Step 1: Platform analysis
        try:
            from o1o_o.core.platform_adapter import PlatformAdapter
            pa = PlatformAdapter()
            self.binary_info = pa.analyze(filepath)
            self.mitigations = {
                'nx': self.binary_info.nx,
                'aslr': self.binary_info.aslr,
                'stack_canary': self.binary_info.stack_canary,
                'cfg': self.binary_info.cfg,
                'code_signing': self.binary_info.code_signing,
                'relro': getattr(self.binary_info, 'relro', False),
                'fortify': getattr(self.binary_info, 'fortify', False),
            }
            result['binary'] = {
                'format': self.binary_info.format,
                'arch': self.binary_info.arch,
                'security_score': self.binary_info.security_score(),
                'risk_level': self.binary_info.risk_level(),
                'mitigations': self.mitigations,
            }
        except Exception as e:
            result['binary'] = {'error': str(e)}
            self.mitigations = {}

        # Step 2: CFG recovery
        try:
            from o1o_o.core.cfg_engine import CFGEngine
            cfg = CFGEngine()
            self.cfg_result = cfg.analyze(filepath)
            result['cfg'] = {
                'functions': self.cfg_result.get('functions', 0),
                'total_blocks': self.cfg_result.get('total_blocks', 0),
                'total_branches': self.cfg_result.get('total_branches', 0),
                'avg_complexity': self.cfg_result.get('avg_complexity', 0),
                'max_complexity': self.cfg_result.get('max_complexity', 0),
            }

            # Build function profiles from CFGEngine's internal function objects
            for addr, func_cfg in cfg.functions.items():
                name = func_cfg.name
                prof = FunctionProfile(name, func_cfg.addr)
                prof.size = func_cfg.size
                prof.complexity = func_cfg.complexity()
                prof.total_calls = len(func_cfg.calls_to)
                prof.callees = [
                    cfg.functions[a].name for a in func_cfg.calls_to
                    if a in cfg.functions
                ]
                prof.callers = [
                    cfg.functions[a].name for a in func_cfg.called_by
                    if a in cfg.functions
                ]
                self.profiles[name] = prof

        except Exception as e:
            result['cfg'] = {'error': str(e)}

        # Step 3: Cross-reference analysis
        try:
            from o1o_o.core.xref_engine import XRefEngine
            xref = XRefEngine()
            self.xref_result = xref.analyze(filepath)

            result['xref'] = {
                'sinks': self.xref_result.get('sinks', {}).get('total', 0),
                'sources': self.xref_result.get('sources', {}).get('total', 0),
                'source_sink_paths': self.xref_result.get('source_sink_paths', 0),
                'dangerous_callers': len(self.xref_result.get('dangerous_callers', [])),
            }

            # Enrich function profiles with xref data
            for dc in self.xref_result.get('dangerous_callers', []):
                fname = dc['function']
                if fname in self.profiles:
                    prof = self.profiles[fname]
                    prof.reaches_sinks = set(dc.get('reachable_sinks', []))

            # Mark functions that receive external input
            for src_cat, src_funcs in self.xref_result.get('sources', {}).get('by_category', {}).items():
                for fname in src_funcs:
                    if fname in self.profiles:
                        self.profiles[fname].takes_external_input = True
                        self.profiles[fname].input_sources.append(src_cat)

            # Propagate source reachability from paths
            for path in self.xref_result.get('paths', []):
                for hop in path.get('path', []):
                    if hop in self.profiles:
                        self.profiles[hop].reachable_from_sources.add(path['source'])

        except Exception as e:
            result['xref'] = {'error': str(e)}

        # Step 4: Stack frame analysis + dangerous call detection
        self._analyze_functions(filepath)

        # Step 5: Vulnerability classification
        for prof in self.profiles.values():
            prof.classify_vulns()
            prof.compute_score(self.mitigations)

        # Step 6: Aggregate results
        all_vulns = []
        scored_funcs = []
        for prof in self.profiles.values():
            if prof.vuln_score > 0:
                scored_funcs.append(prof)
            all_vulns.extend(prof.vulns)

        scored_funcs.sort(key=lambda p: -p.vuln_score)

        result['functions_analyzed'] = len(self.profiles)
        result['functions_with_issues'] = len(scored_funcs)
        result['vulnerabilities'] = {
            'total': len(all_vulns),
            'by_type': dict(self._count_by(all_vulns, 'type')),
            'by_severity': dict(self._count_by(all_vulns, 'severity')),
            'top': all_vulns[:20],
        }
        result['hotspots'] = [
            {
                'function': p.name,
                'addr': hex(p.addr),
                'score': p.vuln_score,
                'vulns': len(p.vulns),
                'dangerous_calls': len(p.dangerous_calls),
                'stack_size': p.stack_size,
                'complexity': p.complexity,
                'has_canary': p.has_canary,
                'input_sources': p.input_sources,
            }
            for p in scored_funcs[:20]
        ]

        # Step 7: Triplet generation
        triplets = self.to_triplets()
        result['triplets'] = len(triplets)

        return result

    def _analyze_functions(self, filepath: str):
        """Per-function stack analysis and dangerous call detection."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except Exception:
            return

        arch = ''
        if self.binary_info:
            arch = self.binary_info.arch

        # Get __TEXT section data for Mach-O / .text for ELF
        text_data, text_vmaddr = self._get_text(data)
        if not text_data:
            # Still do dangerous call detection without stack analysis
            self._detect_dangerous_calls_from_xref()
            return

        for name, prof in self.profiles.items():
            if prof.size <= 0:
                continue

            # Extract function bytes
            func_offset = prof.addr - text_vmaddr
            if func_offset < 0 or func_offset + prof.size > len(text_data):
                continue
            func_bytes = text_data[func_offset:func_offset + prof.size]

            # Stack frame analysis
            if 'arm64' in arch or 'aarch64' in arch:
                stack_info = _analyze_arm64_stack(func_bytes, prof.addr)
            elif 'x86' in arch or 'amd64' in arch:
                stack_info = _analyze_x86_stack(func_bytes, prof.addr)
            else:
                stack_info = _analyze_arm64_stack(func_bytes, prof.addr)  # Default ARM64

            prof.stack_size = stack_info['stack_size']
            prof.has_canary = stack_info['has_canary']

        # Detect dangerous calls
        self._detect_dangerous_calls_from_xref()

    def _detect_dangerous_calls_from_xref(self):
        """Use XRef data to identify dangerous function calls per function."""
        if not self.xref_result:
            return

        # From xref dangerous_callers
        for dc in self.xref_result.get('dangerous_callers', []):
            fname = dc['function']
            if fname not in self.profiles:
                continue
            prof = self.profiles[fname]

            for sink_name in dc.get('reachable_sinks', []):
                # Strip leading underscore (macOS name mangling)
                clean = sink_name.lstrip('_')
                if clean in DANGEROUS_PATTERNS:
                    prof.add_dangerous_call(clean, DANGEROUS_PATTERNS[clean])
                elif sink_name in DANGEROUS_PATTERNS:
                    prof.add_dangerous_call(sink_name, DANGEROUS_PATTERNS[sink_name])

        # Also check callees directly
        for name, prof in self.profiles.items():
            for callee in prof.callees:
                clean = callee.lstrip('_')
                if clean in DANGEROUS_PATTERNS and clean not in [d['callee'] for d in prof.dangerous_calls]:
                    prof.add_dangerous_call(clean, DANGEROUS_PATTERNS[clean])

    def _get_text(self, data: bytes) -> Tuple[Optional[bytes], int]:
        """Extract executable text section from binary."""
        if len(data) < 4:
            return None, 0

        magic = struct.unpack('<I', data[:4])[0]

        # Handle fat Mach-O
        if magic in (0xCAFEBABE, 0xBEBAFECA):
            nfat = struct.unpack('>I', data[4:8])[0]
            for i in range(min(nfat, 8)):
                fat_off = 8 + i * 20
                cpu = struct.unpack('>I', data[fat_off:fat_off + 4])[0]
                offset = struct.unpack('>I', data[fat_off + 8:fat_off + 12])[0]
                size = struct.unpack('>I', data[fat_off + 12:fat_off + 16])[0]
                if cpu in (0x100000C, 0x100000D, 0x01000007):
                    return self._get_text(data[offset:offset + size])
            if nfat > 0:
                offset = struct.unpack('>I', data[16:20])[0]
                size = struct.unpack('>I', data[20:24])[0]
                return self._get_text(data[offset:offset + size])
            return None, 0

        # Mach-O
        if magic in (0xFEEDFACF, 0xFEEDFACE, 0xCFFAEDFE, 0xCEFAEDFE):
            return self._get_macho_text(data)

        # ELF
        if data[:4] == b'\x7fELF':
            return self._get_elf_text(data)

        # PE
        if data[:2] == b'MZ':
            return self._get_pe_text(data)

        return None, 0

    def _get_macho_text(self, data: bytes) -> Tuple[Optional[bytes], int]:
        """Get __TEXT,__text section from Mach-O."""
        magic = struct.unpack('<I', data[:4])[0]
        is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
        fmt = '<' if magic in (0xFEEDFACF, 0xFEEDFACE) else '>'
        hdr_size = 32 if is_64 else 28
        ncmds = struct.unpack_from(fmt + 'I', data, 16)[0]

        off = hdr_size
        for _ in range(ncmds):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(fmt + 'II', data, off)

            # LC_SEGMENT_64 = 0x19, LC_SEGMENT = 0x01
            if cmd in (0x19, 0x01):
                segname = data[off + 8:off + 24].split(b'\0')[0].decode('ascii', errors='ignore')
                if segname == '__TEXT':
                    # Parse sections within segment
                    if cmd == 0x19:
                        nsects = struct.unpack_from(fmt + 'I', data, off + 64)[0]
                        sect_off = off + 72
                        sect_size = 80
                    else:
                        nsects = struct.unpack_from(fmt + 'I', data, off + 48)[0]
                        sect_off = off + 56
                        sect_size = 68

                    for si in range(nsects):
                        if sect_off + sect_size > len(data):
                            break
                        sectname = data[sect_off:sect_off + 16].split(b'\0')[0].decode('ascii', errors='ignore')
                        if sectname == '__text':
                            if cmd == 0x19:
                                s_addr = struct.unpack_from(fmt + 'Q', data, sect_off + 32)[0]
                                s_size = struct.unpack_from(fmt + 'Q', data, sect_off + 40)[0]
                                s_offset = struct.unpack_from(fmt + 'I', data, sect_off + 48)[0]
                            else:
                                s_addr = struct.unpack_from(fmt + 'I', data, sect_off + 32)[0]
                                s_size = struct.unpack_from(fmt + 'I', data, sect_off + 36)[0]
                                s_offset = struct.unpack_from(fmt + 'I', data, sect_off + 40)[0]
                            return data[s_offset:s_offset + s_size], s_addr
                        sect_off += sect_size

            off += cmdsize
        return None, 0

    def _get_elf_text(self, data: bytes) -> Tuple[Optional[bytes], int]:
        """Get .text section from ELF."""
        ei_class = data[4]
        is_64 = ei_class == 2
        ei_data = data[5]
        fmt = '<' if ei_data == 1 else '>'

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
            return None, 0

        # Get section name string table
        shstr_off = e_shoff + e_shstrndx * e_shentsize
        if is_64:
            str_offset = struct.unpack_from(fmt + 'Q', data, shstr_off + 24)[0]
            str_size = struct.unpack_from(fmt + 'Q', data, shstr_off + 32)[0]
        else:
            str_offset = struct.unpack_from(fmt + 'I', data, shstr_off + 16)[0]
            str_size = struct.unpack_from(fmt + 'I', data, shstr_off + 20)[0]

        strtab = data[str_offset:str_offset + str_size]

        # Find .text section
        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            sh_name = struct.unpack_from(fmt + 'I', data, sh_off)[0]

            # Get section name
            name_end = strtab.find(b'\0', sh_name)
            name = strtab[sh_name:name_end].decode('ascii', errors='ignore') if name_end > sh_name else ''

            if name == '.text':
                if is_64:
                    sh_addr = struct.unpack_from(fmt + 'Q', data, sh_off + 16)[0]
                    sh_offset = struct.unpack_from(fmt + 'Q', data, sh_off + 24)[0]
                    sh_size = struct.unpack_from(fmt + 'Q', data, sh_off + 32)[0]
                else:
                    sh_addr = struct.unpack_from(fmt + 'I', data, sh_off + 12)[0]
                    sh_offset = struct.unpack_from(fmt + 'I', data, sh_off + 16)[0]
                    sh_size = struct.unpack_from(fmt + 'I', data, sh_off + 20)[0]

                return data[sh_offset:sh_offset + sh_size], sh_addr

        return None, 0

    def _get_pe_text(self, data: bytes) -> Tuple[Optional[bytes], int]:
        """Get .text section from PE."""
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b'PE\0\0':
            return None, 0

        num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
        opt_hdr_size = struct.unpack_from('<H', data, pe_off + 20)[0]
        sections_off = pe_off + 24 + opt_hdr_size

        # Get ImageBase
        magic = struct.unpack_from('<H', data, pe_off + 24)[0]
        if magic == 0x20b:  # PE32+
            image_base = struct.unpack_from('<Q', data, pe_off + 24 + 24)[0]
        else:
            image_base = struct.unpack_from('<I', data, pe_off + 24 + 28)[0]

        for i in range(num_sections):
            sh_off = sections_off + i * 40
            name = data[sh_off:sh_off + 8].split(b'\0')[0].decode('ascii', errors='ignore')
            if name == '.text':
                virt_size = struct.unpack_from('<I', data, sh_off + 8)[0]
                virt_addr = struct.unpack_from('<I', data, sh_off + 12)[0]
                raw_size = struct.unpack_from('<I', data, sh_off + 16)[0]
                raw_off = struct.unpack_from('<I', data, sh_off + 20)[0]
                return data[raw_off:raw_off + raw_size], image_base + virt_addr

        return None, 0

    # ─── Triplet Generation ──────────────────────────────────────

    def to_triplets(self) -> List[dict]:
        """Convert decompilation analysis to causal triplets."""
        triplets = []

        for name, prof in self.profiles.items():
            if not prof.vulns and prof.vuln_score == 0:
                continue

            # Function vulnerability triplets
            for vuln in prof.vulns:
                triplets.append({
                    'trigger': f'function_{name}_analyzed',
                    'mechanism': vuln['evidence'],
                    'outcome': f'{vuln["type"]}_in_{name}',
                    'confidence': vuln['confidence'],
                    'metadata': {
                        'severity': vuln['severity'],
                        'function': name,
                        'addr': hex(prof.addr),
                    },
                })

            # Stack risk triplets
            if prof.stack_size > 1024:
                triplets.append({
                    'trigger': f'{name}_large_stack_{prof.stack_size}',
                    'mechanism': f'stack_frame_{"no_canary" if not prof.has_canary else "with_canary"}',
                    'outcome': f'stack_overflow_risk_{"high" if not prof.has_canary else "mitigated"}',
                    'confidence': 0.7 if not prof.has_canary else 0.4,
                })

            # Data flow triplets
            if prof.reachable_from_sources and prof.reaches_sinks:
                triplets.append({
                    'trigger': f'external_input_reaches_{name}',
                    'mechanism': f'flows_to_{len(prof.reaches_sinks)}_sinks',
                    'outcome': f'attack_surface_confirmed_{name}',
                    'confidence': 0.85,
                })

            # Composite risk triplets
            if prof.vuln_score >= 50:
                triplets.append({
                    'trigger': f'{name}_vuln_score_{prof.vuln_score}',
                    'mechanism': f'{len(prof.dangerous_calls)}_dangerous_calls_complexity_{prof.complexity}',
                    'outcome': f'high_priority_target_{name}',
                    'confidence': 0.8,
                })

        # Binary-level triplets
        if self.binary_info:
            score = self.binary_info.security_score()
            active_mitigations = [k for k, v in self.mitigations.items() if v]
            missing_mitigations = [k for k, v in self.mitigations.items() if not v]

            if missing_mitigations:
                triplets.append({
                    'trigger': f'binary_missing_mitigations',
                    'mechanism': f'absent_{",".join(missing_mitigations[:3])}',
                    'outcome': f'exploitation_easier_score_{score}',
                    'confidence': 0.9,
                })

        return triplets

    # ─── Formatting ──────────────────────────────────────────────

    def format_report(self, result: dict) -> str:
        """Format decompilation analysis as text report."""
        lines = []

        lines.append(f"DECOMPILATION ANALYSIS: {result.get('name', '?')}")
        lines.append(f"{'=' * 60}")

        # Binary info
        bi = result.get('binary', {})
        if 'error' not in bi:
            lines.append(f"  Format:     {bi.get('format', '?')} {bi.get('arch', '?')}")
            lines.append(f"  Security:   {bi.get('security_score', '?')}/100 ({bi.get('risk_level', '?')})")
            mits = [k for k, v in bi.get('mitigations', {}).items() if v]
            missing = [k for k, v in bi.get('mitigations', {}).items() if not v]
            if mits:
                lines.append(f"  Enabled:    {', '.join(mits)}")
            if missing:
                lines.append(f"  Missing:    {', '.join(missing)}")

        # CFG summary
        cfg = result.get('cfg', {})
        if 'error' not in cfg:
            lines.append(f"")
            lines.append(f"  Functions:  {cfg.get('functions', 0)}")
            lines.append(f"  Blocks:     {cfg.get('total_blocks', 0)}")
            lines.append(f"  Complexity: avg={cfg.get('avg_complexity', 0):.1f} max={cfg.get('max_complexity', 0)}")

        # XRef summary
        xr = result.get('xref', {})
        if 'error' not in xr:
            lines.append(f"")
            lines.append(f"  Sinks:      {xr.get('sinks', 0)}")
            lines.append(f"  Sources:    {xr.get('sources', 0)}")
            lines.append(f"  Src→Sink:   {xr.get('source_sink_paths', 0)} paths")

        # Vulnerabilities
        vulns = result.get('vulnerabilities', {})
        if vulns.get('total', 0) > 0:
            lines.append(f"")
            lines.append(f"  VULNERABILITIES: {vulns['total']}")
            for sev in ['critical', 'high', 'medium', 'low']:
                count = vulns.get('by_severity', {}).get(sev, 0)
                if count > 0:
                    lines.append(f"    {sev:12s} {count}")

            lines.append(f"")
            lines.append(f"  By type:")
            for vtype, count in sorted(vulns.get('by_type', {}).items(), key=lambda x: -x[1]):
                lines.append(f"    {vtype:30s} {count}")

        # Hotspots
        hotspots = result.get('hotspots', [])
        if hotspots:
            lines.append(f"")
            lines.append(f"  TOP VULNERABILITY HOTSPOTS:")
            lines.append(f"  {'Function':<30s} {'Score':>6s} {'Vulns':>6s} {'DCall':>6s} {'Stack':>8s} {'Cx':>4s}")
            lines.append(f"  {'-' * 64}")
            for h in hotspots[:15]:
                name = h['function'][:30]
                lines.append(
                    f"  {name:<30s} {h['score']:>6.1f} {h['vulns']:>6d} "
                    f"{h['dangerous_calls']:>6d} {h['stack_size']:>8d} {h['complexity']:>4d}"
                )

        lines.append(f"")
        lines.append(f"  {result.get('triplets', 0)} causal triplets generated")

        return '\n'.join(lines)

    @staticmethod
    def _count_by(items: List[dict], key: str) -> Dict[str, int]:
        """Count items by a key."""
        counts = defaultdict(int)
        for item in items:
            counts[item.get(key, 'unknown')] += 1
        return counts


# ─── Module-level convenience ────────────────────────────────────────

def analyze(filepath: str) -> dict:
    """Quick decompilation analysis."""
    pipeline = DecompPipeline()
    return pipeline.analyze(filepath)


def analyze_and_format(filepath: str) -> str:
    """Analyze and return formatted report."""
    pipeline = DecompPipeline()
    result = pipeline.analyze(filepath)
    return pipeline.format_report(result)
