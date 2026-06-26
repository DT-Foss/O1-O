"""Crash Analyzer: Parse crash logs and classify exploit primitives.

Parses macOS .ips crash reports (JSON format) and classifies the
crash into exploit primitive categories:
  - DoS: Denial of Service only (NULL deref, abort, assert)
  - InfoLeak: Read primitive (OOB read, uninitialized memory)
  - Write: Write primitive (heap overflow, UAF write, OOB write)
  - Execute: Code execution potential (controlled PC, ROP possible)

Part of FORGE Phase I: Exploit Primitive Classification.
"""
# Dependencies: none
# Depended by: hunt_loop

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from core.crash_triage import CrashTriager


# ─── Crash Signal → Base Classification ────────────────────────────────

SIGNAL_CLASS = {
    'SIGSEGV': 'memory_access',
    'SIGBUS': 'memory_alignment',
    'SIGABRT': 'abort',
    'SIGFPE': 'arithmetic',
    'SIGILL': 'illegal_instruction',
    'SIGTRAP': 'trap',
    'SIGKILL': 'killed',
}

EXCEPTION_CLASS = {
    'EXC_BAD_ACCESS': 'memory_access',
    'EXC_BAD_INSTRUCTION': 'illegal_instruction',
    'EXC_ARITHMETIC': 'arithmetic',
    'EXC_CRASH': 'abort',
    'EXC_BREAKPOINT': 'breakpoint',
    'EXC_GUARD': 'guard_violation',
    'EXC_RESOURCE': 'resource_limit',
}

# ─── Exploit Primitive Types ───────────────────────────────────────────

class ExploitPrimitive:
    """Classification of a crash into exploit primitive type."""

    # Primitive types ordered by severity
    DOS = 'dos'
    INFO_LEAK = 'info_leak'
    WRITE = 'write'
    EXECUTE = 'execute'

    SEVERITY_ORDER = {DOS: 1, INFO_LEAK: 2, WRITE: 3, EXECUTE: 4}

    def __init__(self, primitive_type: str, confidence: float,
                 reasoning: List[str], controllability: str = 'none',
                 exploitation_difficulty: str = 'unknown'):
        self.type = primitive_type
        self.confidence = confidence  # 0.0 - 1.0
        self.reasoning = reasoning
        self.controllability = controllability  # none, partial, full
        self.exploitation_difficulty = exploitation_difficulty  # trivial, moderate, hard, impractical

    @property
    def severity(self) -> int:
        return self.SEVERITY_ORDER.get(self.type, 0)

    def __repr__(self):
        return (f"ExploitPrimitive({self.type}, confidence={self.confidence:.0%}, "
                f"controllability={self.controllability})")


# ─── Crash Report Parser ──────────────────────────────────────────────

class CrashReport:
    """Parsed crash report from .ips file."""

    def __init__(self):
        self.app_name: str = ''
        self.pid: int = 0
        self.cpu_type: str = ''
        self.signal: str = ''
        self.exception_type: str = ''
        self.exception_subtype: str = ''
        self.exception_codes: List[int] = []
        self.faulting_address: int = 0
        self.faulting_thread: int = 0
        self.pc: int = 0
        self.lr: int = 0
        self.sp: int = 0
        self.fp: int = 0
        self.registers: Dict[str, int] = {}
        self.stack_frames: List[Dict] = []
        self.crashing_function: str = ''
        self.crashing_symbol: str = ''
        self.crashing_offset: int = 0
        self.binary_images: List[Dict] = []
        self.os_version: str = ''
        self.sip_enabled: bool = True
        self.esr: int = 0
        self.esr_description: str = ''
        self.vm_region_info: str = ''
        self.raw: Dict = {}

    def __repr__(self):
        return (f"CrashReport({self.app_name}, {self.signal}, "
                f"addr=0x{self.faulting_address:x}, "
                f"func={self.crashing_function})")


class CrashAnalyzer:
    """Parse .ips crash logs and classify exploit primitives."""

    def __init__(self):
        self.triager = CrashTriager()

    def parse_ips(self, filepath: str) -> CrashReport:
        """Parse a macOS .ips crash report file.

        .ips files have a JSON header line followed by a JSON body.
        """
        report = CrashReport()

        with open(filepath) as f:
            content = f.read()

        # Split header and body
        lines = content.split('\n', 1)
        if len(lines) < 2:
            return report

        try:
            header = json.loads(lines[0])
            body = json.loads(lines[1])
        except json.JSONDecodeError:
            # Try parsing entire file as JSON
            try:
                body = json.loads(content)
                header = {}
            except json.JSONDecodeError:
                return report

        report.raw = body
        report.app_name = header.get('app_name', body.get('procName', ''))

        # Process info
        report.pid = body.get('pid', 0)
        report.cpu_type = body.get('cpuType', '')
        report.sip_enabled = body.get('sip', '') == 'enabled'

        # OS version
        os_info = body.get('osVersion', {})
        report.os_version = os_info.get('train', '') + ' ' + os_info.get('build', '')

        # Exception info
        exc = body.get('exception', {})
        report.exception_type = exc.get('type', '')
        report.signal = exc.get('signal', '')
        report.exception_subtype = exc.get('subtype', '')
        report.exception_codes = exc.get('rawCodes', [])

        # Parse faulting address from subtype
        addr_match = re.search(r'at 0x([0-9a-fA-F]+)', report.exception_subtype)
        if addr_match:
            report.faulting_address = int(addr_match.group(1), 16)

        # VM region info
        report.vm_region_info = body.get('vmRegionInfo', body.get('vmregioninfo', ''))

        # Faulting thread
        report.faulting_thread = body.get('faultingThread', 0)

        # Parse threads
        threads = body.get('threads', [])
        for thread in threads:
            if thread.get('triggered', False):
                # This is the crashing thread
                self._parse_crashing_thread(thread, report)
                break

        # Binary images
        for img in body.get('usedImages', []):
            report.binary_images.append({
                'name': img.get('name', ''),
                'path': img.get('path', ''),
                'base': img.get('base', 0),
                'size': img.get('size', 0),
                'uuid': img.get('uuid', ''),
                'arch': img.get('arch', ''),
            })

        return report

    def _parse_crashing_thread(self, thread: Dict, report: CrashReport):
        """Parse the crashing thread's state and frames."""
        # Thread state (registers)
        state = thread.get('threadState', {})

        # ARM64 registers
        x_regs = state.get('x', [])
        for i, reg in enumerate(x_regs):
            if isinstance(reg, dict):
                report.registers[f'x{i}'] = reg.get('value', 0)
            else:
                report.registers[f'x{i}'] = reg

        # Special registers
        pc_info = state.get('pc', {})
        lr_info = state.get('lr', {})
        sp_info = state.get('sp', {})
        fp_info = state.get('fp', {})

        report.pc = pc_info.get('value', 0) if isinstance(pc_info, dict) else pc_info
        report.lr = lr_info.get('value', 0) if isinstance(lr_info, dict) else lr_info
        report.sp = sp_info.get('value', 0) if isinstance(sp_info, dict) else sp_info
        report.fp = fp_info.get('value', 0) if isinstance(fp_info, dict) else fp_info

        # ESR (Exception Syndrome Register)
        esr_info = state.get('esr', {})
        if isinstance(esr_info, dict):
            report.esr = esr_info.get('value', 0)
            report.esr_description = esr_info.get('description', '')

        # Stack frames
        frames = thread.get('frames', [])
        for frame in frames:
            report.stack_frames.append({
                'symbol': frame.get('symbol', ''),
                'offset': frame.get('imageOffset', 0),
                'symbol_offset': frame.get('symbolLocation', 0),
                'image_index': frame.get('imageIndex', 0),
            })

        # Crashing function = first frame
        if report.stack_frames:
            top = report.stack_frames[0]
            report.crashing_function = top['symbol']
            report.crashing_offset = top['offset']
            report.crashing_symbol = top['symbol']

    def classify_primitive(self, report: CrashReport) -> ExploitPrimitive:
        """Classify a crash report into exploit primitive type.

        Classification logic:
        1. Parse exception type and faulting address
        2. Analyze ESR (Exception Syndrome Register) for access type
        3. Check register controllability
        4. Analyze stack trace for vulnerability class
        5. Determine primitive type and confidence
        """
        reasoning = []
        primitive_type = ExploitPrimitive.DOS
        confidence = 0.5
        controllability = 'none'
        difficulty = 'impractical'

        # 1. Exception type analysis
        exc_class = EXCEPTION_CLASS.get(report.exception_type, 'unknown')
        sig_class = SIGNAL_CLASS.get(report.signal, 'unknown')

        reasoning.append(f"Exception: {report.exception_type} ({report.signal})")
        reasoning.append(f"Faulting address: 0x{report.faulting_address:x}")

        # 2. Faulting address analysis
        fault_addr = report.faulting_address

        if fault_addr == 0:
            # NULL pointer dereference
            reasoning.append("NULL pointer dereference — DoS only on arm64e+PAC")
            primitive_type = ExploitPrimitive.DOS
            confidence = 0.9
            controllability = 'none'
            difficulty = 'impractical'

        elif fault_addr < 0x1000:
            # Near-NULL dereference (small offset from NULL)
            reasoning.append(f"Near-NULL dereference (offset {fault_addr}) — "
                           f"DoS, possible struct member access via NULL ptr")
            primitive_type = ExploitPrimitive.DOS
            confidence = 0.85
            controllability = 'none'
            difficulty = 'hard'

        elif fault_addr > 0xFFFF000000000000:
            # Kernel address space
            reasoning.append("Kernel address access — potential kernel vuln")
            primitive_type = ExploitPrimitive.WRITE
            confidence = 0.6
            controllability = 'partial'
            difficulty = 'hard'

        elif self._is_pattern_address(fault_addr):
            # Classic pattern fill — controlled input reached pointer
            reasoning.append(f"Pattern-filled address (0x{fault_addr:x}) — CONTROLLED pointer!")
            primitive_type = ExploitPrimitive.EXECUTE
            confidence = 0.95
            controllability = 'full'
            difficulty = 'moderate'

        else:
            # Unmapped address — heap corruption, UAF, or OOB
            reasoning.append(f"Unmapped address 0x{fault_addr:x}")

        # 3. ESR analysis (ARM64 Exception Syndrome Register)
        # Only upgrade from DOS if the faulting address is NOT null/near-null
        # (NULL deref reads are just DOS, not info leaks)
        is_null_deref = fault_addr < 0x1000
        if report.esr:
            esr_desc = report.esr_description.lower()
            if 'write' in esr_desc:
                reasoning.append(f"ESR indicates WRITE access — write primitive possible")
                if primitive_type == ExploitPrimitive.DOS and not is_null_deref:
                    primitive_type = ExploitPrimitive.WRITE
                    confidence = 0.75
                    controllability = 'partial'
                    difficulty = 'hard'
            elif 'read' in esr_desc:
                reasoning.append(f"ESR indicates READ access")
                if primitive_type == ExploitPrimitive.DOS and not is_null_deref:
                    primitive_type = ExploitPrimitive.INFO_LEAK
                    confidence = 0.7
                    controllability = 'partial'
                    difficulty = 'moderate'
            elif 'translation fault' in esr_desc:
                reasoning.append(f"Translation fault — page not mapped")
            elif 'instruction abort' in esr_desc:
                reasoning.append(f"Instruction abort — potential code execution")
                primitive_type = ExploitPrimitive.EXECUTE
                confidence = 0.8
                controllability = 'partial'
                difficulty = 'hard'

        # 4. Stack trace analysis
        vuln_indicators = self._analyze_stack_trace(report)
        for indicator in vuln_indicators:
            reasoning.append(indicator['description'])
            if indicator['severity'] > ExploitPrimitive.SEVERITY_ORDER.get(primitive_type, 0):
                primitive_type = indicator['type']
                confidence = max(confidence, indicator['confidence'])
                if indicator.get('controllability'):
                    controllability = indicator['controllability']

        # 5. Register controllability analysis
        reg_analysis = self._analyze_registers(report)
        if reg_analysis:
            reasoning.extend(reg_analysis['reasoning'])
            if reg_analysis['controllability'] == 'full':
                controllability = 'full'
                if primitive_type in (ExploitPrimitive.DOS, ExploitPrimitive.INFO_LEAK):
                    primitive_type = ExploitPrimitive.WRITE
                    confidence = max(confidence, 0.7)

        # 6. VM region analysis
        if 'not in any region' in report.vm_region_info:
            reasoning.append("Faulting address not in any mapped region")
        if 'MALLOC' in report.vm_region_info:
            reasoning.append("Crash in MALLOC region — heap corruption likely")
            if primitive_type == ExploitPrimitive.DOS:
                primitive_type = ExploitPrimitive.WRITE
                confidence = max(confidence, 0.65)
                difficulty = 'hard'

        # Compute exploitation difficulty
        if report.cpu_type == 'ARM-64' and report.sip_enabled:
            reasoning.append("arm64e + SIP enabled — PAC/MTE mitigations active")
            if difficulty not in ('impractical',):
                difficulty = 'hard'

        return ExploitPrimitive(
            primitive_type, confidence, reasoning,
            controllability, difficulty)

    def _analyze_stack_trace(self, report: CrashReport) -> List[Dict]:
        """Analyze stack trace for vulnerability indicators."""
        indicators = []

        # Check for known vulnerable patterns in stack
        vuln_patterns = {
            'malloc': {'type': ExploitPrimitive.WRITE, 'desc': 'Crash in allocator — heap corruption', 'conf': 0.75, 'sev': 3},
            'free': {'type': ExploitPrimitive.WRITE, 'desc': 'Crash in free — double free or UAF', 'conf': 0.8, 'sev': 3},
            'realloc': {'type': ExploitPrimitive.WRITE, 'desc': 'Crash in realloc — heap corruption', 'conf': 0.75, 'sev': 3},
            'memcpy': {'type': ExploitPrimitive.WRITE, 'desc': 'Crash in memcpy — buffer overflow', 'conf': 0.8, 'sev': 3},
            'memmove': {'type': ExploitPrimitive.WRITE, 'desc': 'Crash in memmove — buffer overflow', 'conf': 0.75, 'sev': 3},
            'strcpy': {'type': ExploitPrimitive.WRITE, 'desc': 'Crash in strcpy — stack/heap overflow', 'conf': 0.85, 'sev': 3},
            'strcat': {'type': ExploitPrimitive.WRITE, 'desc': 'Crash in strcat — buffer overflow', 'conf': 0.8, 'sev': 3},
            'sprintf': {'type': ExploitPrimitive.WRITE, 'desc': 'Crash in sprintf — format string or overflow', 'conf': 0.8, 'sev': 3},
            'objc_msgSend': {'type': ExploitPrimitive.EXECUTE, 'desc': 'Crash in objc_msgSend — UAF on ObjC object', 'conf': 0.7, 'sev': 4},
            'objc_release': {'type': ExploitPrimitive.WRITE, 'desc': 'Crash in objc_release — UAF', 'conf': 0.75, 'sev': 3},
            'CFRelease': {'type': ExploitPrimitive.WRITE, 'desc': 'Crash in CFRelease — CF object UAF', 'conf': 0.7, 'sev': 3},
            '_xzm_': {'type': ExploitPrimitive.WRITE, 'desc': 'Crash in xzone malloc — heap metadata corruption', 'conf': 0.8, 'sev': 3},
            'IOKit': {'type': ExploitPrimitive.EXECUTE, 'desc': 'Crash in IOKit — kernel surface', 'conf': 0.6, 'sev': 4},
        }

        for frame in report.stack_frames[:10]:
            symbol = frame.get('symbol', '')
            for pattern, info in vuln_patterns.items():
                if pattern in symbol:
                    indicators.append({
                        'description': f"{info['desc']} (in {symbol})",
                        'type': info['type'],
                        'confidence': info['conf'],
                        'severity': info['sev'],
                        'controllability': 'partial',
                    })
                    break

        return indicators

    def _analyze_registers(self, report: CrashReport) -> Optional[Dict]:
        """Analyze register state for controllability indicators."""
        reasoning = []
        controllability = 'none'

        # Check for pattern-filled registers (signs of controlled input)
        pattern_regs = []
        for name, value in report.registers.items():
            if isinstance(value, int):
                # Check for repeating byte patterns
                hex_val = f'{value:016x}'
                if len(set(hex_val)) <= 2 and value != 0:
                    pattern_regs.append(f'{name}=0x{value:x}')

        if pattern_regs:
            reasoning.append(f"Pattern-filled registers: {', '.join(pattern_regs[:5])}")
            controllability = 'partial'

        # Check if PC/LR appear corrupted
        if report.pc and report.pc < 0x100000:
            reasoning.append(f"PC at low address 0x{report.pc:x} — possibly controlled")
            controllability = 'full'

        if not reasoning:
            return None

        return {'reasoning': reasoning, 'controllability': controllability}

    @staticmethod
    def _is_pattern_address(addr: int) -> bool:
        """Check if address looks like a repeating byte pattern (e.g. 0x41414141).

        Pattern-filled addresses indicate controlled input reached a pointer,
        which is a strong indicator of exploitability.
        """
        if addr == 0:
            return False
        hex_str = f'{addr:016x}'
        # Check 4-byte repeating pattern: AABBCCDD AABBCCDD
        if len(hex_str) >= 8:
            half = len(hex_str) // 2
            if hex_str[:half] == hex_str[half:]:
                return True
        # Check 2-byte repeating pattern: AABB AABB AABB AABB
        if len(hex_str) >= 4:
            chunk = hex_str[:4]
            if all(hex_str[i:i+4] == chunk for i in range(0, len(hex_str), 4)):
                return True
        # Check single-byte repeating: AA AA AA AA AA AA AA AA
        if len(hex_str) >= 2:
            chunk = hex_str[:2]
            if all(hex_str[i:i+2] == chunk for i in range(0, len(hex_str), 2)):
                return True
        return False

    def analyze_file(self, filepath: str) -> Dict:
        """Full analysis pipeline: parse + classify."""
        report = self.parse_ips(filepath)
        primitive = self.classify_primitive(report)

        return {
            'file': filepath,
            'app': report.app_name,
            'signal': report.signal,
            'exception': report.exception_type,
            'faulting_address': f'0x{report.faulting_address:x}',
            'crashing_function': report.crashing_function,
            'stack_depth': len(report.stack_frames),
            'primitive': {
                'type': primitive.type,
                'confidence': primitive.confidence,
                'controllability': primitive.controllability,
                'difficulty': primitive.exploitation_difficulty,
                'reasoning': primitive.reasoning,
            },
            'cpu': report.cpu_type,
            'os': report.os_version,
            'sip': report.sip_enabled,
        }

    def format_analysis(self, analysis: Dict) -> str:
        """Format analysis result as readable string."""
        lines = []
        p = analysis['primitive']

        severity_icon = {
            'dos': 'DoS',
            'info_leak': 'INFO LEAK',
            'write': 'WRITE PRIMITIVE',
            'execute': 'CODE EXECUTION',
        }

        lines.append(f"{'═' * 60}")
        lines.append(f"CRASH ANALYSIS: {analysis['app']}")
        lines.append(f"{'═' * 60}")
        lines.append(f"Signal: {analysis['signal']} ({analysis['exception']})")
        lines.append(f"Faulting address: {analysis['faulting_address']}")
        lines.append(f"Crashing function: {analysis['crashing_function']}")
        lines.append(f"Stack depth: {analysis['stack_depth']} frames")
        lines.append(f"Platform: {analysis['cpu']}, SIP={'ON' if analysis['sip'] else 'OFF'}")
        lines.append(f"")
        lines.append(f"EXPLOIT PRIMITIVE: {severity_icon.get(p['type'], p['type'])}")
        lines.append(f"  Confidence: {p['confidence']:.0%}")
        lines.append(f"  Controllability: {p['controllability']}")
        lines.append(f"  Exploitation difficulty: {p['difficulty']}")
        lines.append(f"")
        lines.append(f"Reasoning:")
        for r in p['reasoning']:
            lines.append(f"  - {r}")

        return '\n'.join(lines)

    # ─── Linux Core Dump / GDB Backtrace Parser ────────────────────

    def parse_gdb_backtrace(self, filepath: str) -> CrashReport:
        """Parse a GDB backtrace or Linux crash dump.

        Handles:
        - GDB 'bt' output (text format)
        - Linux /var/log/kern.log crash entries
        - AddressSanitizer (ASan) reports
        """
        report = CrashReport()

        with open(filepath) as f:
            content = f.read()

        # Detect format
        if 'AddressSanitizer' in content:
            return self._parse_asan_report(content)
        elif 'Thread' in content and '#0' in content:
            return self._parse_gdb_output(content)
        elif 'BUG:' in content or 'Oops:' in content:
            return self._parse_kernel_oops(content)
        else:
            # Try GDB format as default
            return self._parse_gdb_output(content)

    def _parse_asan_report(self, content: str) -> CrashReport:
        """Parse AddressSanitizer crash report."""
        report = CrashReport()
        report.app_name = 'asan_report'
        report.cpu_type = 'x86-64'

        # Error type: heap-buffer-overflow, use-after-free, etc
        error_match = re.search(r'ERROR: AddressSanitizer: (\S+)', content)
        if error_match:
            report.exception_type = error_match.group(1)

            asan_to_signal = {
                'heap-buffer-overflow': 'SIGSEGV',
                'stack-buffer-overflow': 'SIGSEGV',
                'heap-use-after-free': 'SIGSEGV',
                'use-after-poison': 'SIGSEGV',
                'double-free': 'SIGABRT',
                'alloc-dealloc-mismatch': 'SIGABRT',
                'SEGV': 'SIGSEGV',
            }
            report.signal = asan_to_signal.get(report.exception_type, 'SIGSEGV')

        # Faulting address
        addr_match = re.search(r'on (?:address|unknown address) 0x([0-9a-fA-F]+)', content)
        if addr_match:
            report.faulting_address = int(addr_match.group(1), 16)

        # Access type (read/write)
        if 'READ' in content:
            report.esr_description = 'read'
        elif 'WRITE' in content:
            report.esr_description = 'write'
            report.esr = 1  # Non-zero to trigger ESR analysis

        # Stack frames
        frame_pattern = re.compile(
            r'#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(\S+)')
        for m in frame_pattern.finditer(content):
            report.stack_frames.append({
                'symbol': m.group(2),
                'offset': 0,
                'symbol_offset': 0,
                'image_index': 0,
                'source': m.group(3),
            })

        if report.stack_frames:
            report.crashing_function = report.stack_frames[0]['symbol']

        return report

    def _parse_gdb_output(self, content: str) -> CrashReport:
        """Parse GDB backtrace output."""
        report = CrashReport()
        report.app_name = 'gdb_backtrace'
        report.cpu_type = 'x86-64'

        # Signal
        sig_match = re.search(r'Program received signal (\w+)', content)
        if sig_match:
            report.signal = sig_match.group(1)
            report.exception_type = report.signal

        # Stack frames: #0  0x00... in func_name (args) at file:line
        frame_pattern = re.compile(
            r'#(\d+)\s+(?:0x([0-9a-fA-F]+)\s+in\s+)?(\S+)\s*\(([^)]*)\)')
        for m in frame_pattern.finditer(content):
            addr = int(m.group(2), 16) if m.group(2) else 0
            report.stack_frames.append({
                'symbol': m.group(3),
                'offset': addr,
                'symbol_offset': 0,
                'image_index': 0,
            })

        if report.stack_frames:
            report.crashing_function = report.stack_frames[0]['symbol']

        # Faulting address from signal info
        addr_match = re.search(r'si_addr\s*=\s*0x([0-9a-fA-F]+)', content)
        if addr_match:
            report.faulting_address = int(addr_match.group(1), 16)

        return report

    def _parse_kernel_oops(self, content: str) -> CrashReport:
        """Parse Linux kernel Oops / BUG log."""
        report = CrashReport()
        report.app_name = 'kernel'
        report.cpu_type = 'x86-64'
        report.signal = 'SIGSEGV'
        report.exception_type = 'kernel_oops'

        # RIP (instruction pointer)
        rip_match = re.search(r'RIP:\s+\w+:(\S+)\+0x([0-9a-fA-F]+)', content)
        if rip_match:
            report.crashing_function = rip_match.group(1)
            report.crashing_offset = int(rip_match.group(2), 16)

        # Faulting address
        addr_match = re.search(r'(?:BUG|Oops).*at\s+(?:virtual address\s+)?0?x?([0-9a-fA-F]+)', content)
        if addr_match:
            report.faulting_address = int(addr_match.group(1), 16)

        # Call trace
        trace_pattern = re.compile(r'\[\s*\d+\.\d+\]\s+(\w+)\+0x([0-9a-fA-F]+)')
        for m in trace_pattern.finditer(content):
            report.stack_frames.append({
                'symbol': m.group(1),
                'offset': int(m.group(2), 16),
                'symbol_offset': 0,
                'image_index': 0,
            })

        return report

    def analyze_any(self, filepath: str) -> Dict:
        """Auto-detect file format and analyze.

        Supports: .ips (macOS), .txt/.log (GDB/ASan/kernel), .crash (macOS legacy)
        """
        ext = os.path.splitext(filepath)[1].lower()
        if ext == '.ips':
            report = self.parse_ips(filepath)
        else:
            # Try .ips JSON first, fall back to text format
            try:
                with open(filepath) as f:
                    first_line = f.readline()
                if first_line.strip().startswith('{'):
                    report = self.parse_ips(filepath)
                else:
                    report = self.parse_gdb_backtrace(filepath)
            except Exception:
                report = self.parse_gdb_backtrace(filepath)

        primitive = self.classify_primitive(report)

        # Enrich with CrashTriager exploitability assessment
        triage = {}
        try:
            with open(filepath) as f:
                raw_text = f.read()
            triage_report = self.triager.triage(raw_text)
            triage = {
                'exploitability': triage_report.exploitability,
                'crash_type': triage_report.crash_type,
                'score': triage_report.exploitability_score,
                'hypothesis': triage_report.hypothesis,
            }
        except Exception:
            pass

        return {
            'file': filepath,
            'app': report.app_name,
            'signal': report.signal,
            'exception': report.exception_type,
            'faulting_address': f'0x{report.faulting_address:x}',
            'crashing_function': report.crashing_function,
            'stack_depth': len(report.stack_frames),
            'primitive': {
                'type': primitive.type,
                'confidence': primitive.confidence,
                'controllability': primitive.controllability,
                'difficulty': primitive.exploitation_difficulty,
                'reasoning': primitive.reasoning,
            },
            'triage': triage,
            'cpu': report.cpu_type,
            'os': report.os_version,
            'sip': report.sip_enabled,
        }

    def batch_analyze(self, directory: str) -> List[Dict]:
        """Analyze all crash files in a directory."""
        import glob
        results = []
        patterns = ['*.ips', '*.crash', '*.txt', '*.log']
        for pattern in patterns:
            for filepath in glob.glob(os.path.join(directory, pattern)):
                try:
                    result = self.analyze_any(filepath)
                    results.append(result)
                except Exception as e:
                    results.append({
                        'file': filepath,
                        'error': str(e),
                    })
        return results


if __name__ == '__main__':
    import sys
    import glob

    analyzer = CrashAnalyzer()

    # Find .ips files
    ips_files = glob.glob('output_sota_audit/zday_07_opendirectoryd_crash/*.ips')
    if not ips_files:
        ips_paths = [
            os.path.expanduser('~/Desktop/apple_security_submission/'
                             'report_1_opendirectoryd_segv/'
                             'opendirectoryd-2026-02-16-065423.ips'),
        ]
        ips_files = [p for p in ips_paths if os.path.exists(p)]

    if not ips_files:
        print("No .ips files found. Provide path as argument.")
        if len(sys.argv) > 1:
            ips_files = [sys.argv[1]]

    for path in ips_files:
        print(f"\nAnalyzing: {path}")
        analysis = analyzer.analyze_file(path)
        print(analyzer.format_analysis(analysis))
