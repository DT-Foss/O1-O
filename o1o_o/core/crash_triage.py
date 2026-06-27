"""
Crash Triage & Exploitability Assessment

Parses crash logs (.ips, stderr output, core dumps) and classifies:
1. Signal type (SEGV, SIGABRT, SIGBUS, SIGFPE, etc.)
2. Register state analysis for memory corruption indicators
3. Exploitability scoring (EXPLOITABLE, PROBABLY_EXPLOITABLE, UNKNOWN, NOT_EXPLOITABLE)
4. Crash classification (heap corruption, stack overflow, null deref, etc.)
5. Root cause hypothesis based on crash context

Designed for macOS .ips crash reports and generic stderr crash output.
"""
# Dependencies: none
# Depended by: crash_analyzer


import re
import json
from typing import Dict, List, Any, Optional


# Signal classifications
SIGNAL_INFO = {
    'SIGSEGV': {
        'name': 'Segmentation Fault',
        'description': 'Invalid memory access',
        'base_score': 7,
    },
    'SIGBUS': {
        'name': 'Bus Error',
        'description': 'Misaligned memory access or non-existent physical address',
        'base_score': 7,
    },
    'SIGABRT': {
        'name': 'Abort',
        'description': 'Process called abort() — usually assertion failure or heap corruption',
        'base_score': 5,
    },
    'SIGFPE': {
        'name': 'Floating Point Exception',
        'description': 'Division by zero or arithmetic overflow',
        'base_score': 3,
    },
    'SIGILL': {
        'name': 'Illegal Instruction',
        'description': 'Attempted to execute invalid instruction — possible code corruption',
        'base_score': 8,
    },
    'SIGTRAP': {
        'name': 'Trace Trap',
        'description': 'Breakpoint or debugger trap',
        'base_score': 2,
    },
    'SIGKILL': {
        'name': 'Killed',
        'description': 'Forcefully terminated (OOM, watchdog, etc.)',
        'base_score': 1,
    },
    'EXC_BAD_ACCESS': {
        'name': 'Bad Access (macOS)',
        'description': 'Invalid memory access — macOS Mach exception',
        'base_score': 7,
    },
    'EXC_BAD_INSTRUCTION': {
        'name': 'Bad Instruction (macOS)',
        'description': 'Invalid instruction — macOS Mach exception',
        'base_score': 8,
    },
    'EXC_CRASH': {
        'name': 'Crash (macOS)',
        'description': 'Unhandled exception — macOS Mach exception',
        'base_score': 5,
    },
    'EXC_BREAKPOINT': {
        'name': 'Breakpoint (macOS)',
        'description': 'Software breakpoint — often assertion or __builtin_trap',
        'base_score': 3,
    },
    'EXC_GUARD': {
        'name': 'Guard Exception (macOS)',
        'description': 'Guarded resource violation — fd, port, or VM guard',
        'base_score': 4,
    },
}

# Exploitability levels
EXPLOITABLE = 'EXPLOITABLE'
PROBABLY_EXPLOITABLE = 'PROBABLY_EXPLOITABLE'
PROBABLY_NOT = 'PROBABLY_NOT_EXPLOITABLE'
NOT_EXPLOITABLE = 'NOT_EXPLOITABLE'
UNKNOWN = 'UNKNOWN'

# Crash classifications
CRASH_TYPES = {
    'null_deref': {
        'description': 'NULL pointer dereference',
        'exploitability': PROBABLY_NOT,
        'base_score': 3,
    },
    'heap_corruption': {
        'description': 'Heap metadata corruption',
        'exploitability': EXPLOITABLE,
        'base_score': 9,
    },
    'heap_overflow': {
        'description': 'Heap buffer overflow',
        'exploitability': EXPLOITABLE,
        'base_score': 9,
    },
    'stack_overflow': {
        'description': 'Stack buffer overflow',
        'exploitability': EXPLOITABLE,
        'base_score': 9,
    },
    'stack_exhaustion': {
        'description': 'Stack exhaustion (deep recursion)',
        'exploitability': PROBABLY_NOT,
        'base_score': 3,
    },
    'use_after_free': {
        'description': 'Use-after-free',
        'exploitability': EXPLOITABLE,
        'base_score': 9,
    },
    'double_free': {
        'description': 'Double free',
        'exploitability': EXPLOITABLE,
        'base_score': 8,
    },
    'integer_overflow': {
        'description': 'Integer overflow leading to memory corruption',
        'exploitability': PROBABLY_EXPLOITABLE,
        'base_score': 7,
    },
    'format_string': {
        'description': 'Format string vulnerability',
        'exploitability': EXPLOITABLE,
        'base_score': 9,
    },
    'oob_read': {
        'description': 'Out-of-bounds read',
        'exploitability': PROBABLY_NOT,
        'base_score': 4,
    },
    'oob_write': {
        'description': 'Out-of-bounds write',
        'exploitability': EXPLOITABLE,
        'base_score': 9,
    },
    'type_confusion': {
        'description': 'Type confusion',
        'exploitability': PROBABLY_EXPLOITABLE,
        'base_score': 7,
    },
    'uninitialized': {
        'description': 'Use of uninitialized memory',
        'exploitability': PROBABLY_EXPLOITABLE,
        'base_score': 6,
    },
    'assertion_failure': {
        'description': 'Assertion failure',
        'exploitability': NOT_EXPLOITABLE,
        'base_score': 2,
    },
    'unknown': {
        'description': 'Unclassified crash',
        'exploitability': UNKNOWN,
        'base_score': 5,
    },
}


class CrashReport:
    """Parsed and analyzed crash report."""

    def __init__(self):
        self.process_name = ''
        self.pid = 0
        self.signal = ''
        self.exception_type = ''
        self.exception_subtype = ''
        self.faulting_address = 0
        self.crash_type = 'unknown'
        self.exploitability = UNKNOWN
        self.score = 0.0
        self.thread_id = 0
        self.crashed_thread_frames = []  # [(frame_num, module, function, offset)]
        self.registers = {}  # register → value
        self.raw_text = ''
        self.hypothesis = ''
        self.mitigations_bypassed = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            'process': self.process_name,
            'pid': self.pid,
            'signal': self.signal,
            'exception': self.exception_type,
            'faulting_address': hex(self.faulting_address) if self.faulting_address else '0x0',
            'crash_type': self.crash_type,
            'crash_description': CRASH_TYPES.get(self.crash_type, {}).get('description', ''),
            'exploitability': self.exploitability,
            'score': round(self.score, 1),
            'hypothesis': self.hypothesis,
            'crashed_thread_frames': self.crashed_thread_frames[:10],
            'registers': {k: hex(v) if isinstance(v, int) else v for k, v in self.registers.items()},
            'mitigations_bypassed': self.mitigations_bypassed,
        }

    def __repr__(self):
        return (f'CrashReport({self.process_name} PID={self.pid} '
                f'{self.signal} @ {hex(self.faulting_address)} '
                f'[{self.crash_type}] [{self.exploitability}] score={self.score:.1f})')


class CrashTriager:
    """Parse and triage crash reports."""

    def triage(self, crash_text: str) -> CrashReport:
        """Parse a crash log and produce a triage report.

        Supports macOS .ips format and generic crash output.
        """
        report = CrashReport()
        report.raw_text = crash_text

        # Try JSON .ips format first
        if crash_text.strip().startswith('{'):
            try:
                return self._parse_ips_json(crash_text, report)
            except (json.JSONDecodeError, KeyError):
                pass

        # Parse text-based crash logs
        self._parse_text_crash(crash_text, report)

        # Classify and score
        self._classify_crash(report)
        self._assess_exploitability(report)
        self._generate_hypothesis(report)

        return report

    def triage_batch(self, crash_texts: List[str]) -> List[CrashReport]:
        """Triage multiple crash reports."""
        return [self.triage(text) for text in crash_texts]

    def _parse_ips_json(self, text: str, report: CrashReport) -> CrashReport:
        """Parse macOS .ips JSON crash report.

        macOS .ips format: line 1 = JSON header (app_name, timestamp, bug_type),
        lines 2+ = actual crash data JSON with exception, threads, termination.
        """
        lines = text.strip().split('\n')

        # .ips files have a header JSON line, then the real crash JSON
        # Try to parse line 2+ first (the actual crash data)
        data = None
        if len(lines) > 1:
            try:
                data = json.loads('\n'.join(lines[1:]))
            except json.JSONDecodeError:
                pass

        if data is None:
            # Fallback: find first { that starts a large JSON block
            for i, line in enumerate(lines):
                if line.strip().startswith('{'):
                    try:
                        data = json.loads('\n'.join(lines[i:]))
                        break
                    except json.JSONDecodeError:
                        continue

        if data is None:
            data = json.loads(text)  # Last resort — will raise if invalid

        report.process_name = data.get('procName', data.get('name', ''))
        report.pid = data.get('pid', 0)

        # Exception info
        exc = data.get('exception', {})
        report.exception_type = exc.get('type', '')
        report.signal = exc.get('signal', report.exception_type)
        report.exception_subtype = exc.get('subtype', '')

        # Faulting address from exception codes
        codes = exc.get('codes', '')
        if isinstance(codes, str):
            # codes like "0x0000000000000001, 0x000000018ca221dc"
            addrs = re.findall(r'0x([0-9a-fA-F]+)', codes)
            if len(addrs) >= 2:
                # Second code is usually the faulting address
                report.faulting_address = int(addrs[1], 16)
            elif addrs:
                report.faulting_address = int(addrs[0], 16)
        # rawCodes fallback
        raw_codes = exc.get('rawCodes', [])
        if not report.faulting_address and len(raw_codes) >= 2:
            report.faulting_address = raw_codes[1]

        # Termination info (fallback for signal)
        term = data.get('termination', {})
        if not report.signal and term:
            indicator = term.get('indicator', '')
            namespace = term.get('namespace', '')
            if 'SIGNAL' in namespace:
                # Extract signal from indicator like "Trace/BPT trap: 5"
                for sig in SIGNAL_INFO:
                    if sig.replace('SIG', '') in indicator.upper():
                        report.signal = sig
                        break
            if not report.signal and 'Abort' in indicator:
                report.signal = 'SIGABRT'

        # ASI (Application Specific Information) — root cause clues
        asi = data.get('asi', {})
        if asi:
            asi_text = ' '.join(str(v) for v in asi.values())
            report.exception_subtype = report.exception_subtype or asi_text[:200]

        # Crashed thread — use faultingThread index if available
        faulting_idx = data.get('faultingThread', None)
        threads = data.get('threads', [])
        for i, thread in enumerate(threads):
            if thread.get('triggered', False) or i == faulting_idx:
                report.thread_id = thread.get('id', i)
                frames = thread.get('frames', [])
                for frame in frames[:20]:
                    report.crashed_thread_frames.append((
                        frame.get('imageIndex', 0),
                        frame.get('imageOffset', 0),
                        frame.get('symbol', ''),
                        frame.get('symbolLocation', 0),
                    ))
                break

        # Classify and score
        self._classify_crash(report)
        self._assess_exploitability(report)
        self._generate_hypothesis(report)

        return report

    def _parse_text_crash(self, text: str, report: CrashReport):
        """Parse text-based crash output (stderr, console, gdb, lldb)."""
        lines = text.split('\n')

        for line in lines:
            # Process name
            m = re.search(r'Process:\s+(.+?)(?:\s+\[|$)', line)
            if m:
                report.process_name = m.group(1).strip()

            # PID
            m = re.search(r'\[(\d+)\]', line)
            if m and not report.pid:
                report.pid = int(m.group(1))

            # Signal
            for sig in SIGNAL_INFO:
                if sig in line:
                    report.signal = sig
                    break

            # Exception type (macOS)
            m = re.search(r'Exception Type:\s+(.+)', line)
            if m:
                report.exception_type = m.group(1).strip()
                for sig in SIGNAL_INFO:
                    if sig in report.exception_type:
                        report.signal = sig

            # Exception subtype / codes
            m = re.search(r'Exception (?:Subtype|Codes):\s+(.+)', line)
            if m:
                report.exception_subtype = m.group(1).strip()

            # Faulting address
            m = re.search(r'(?:fault|address|addr|at)\s*(?:=|:|\s)\s*0x([0-9a-fA-F]+)', line, re.IGNORECASE)
            if m:
                report.faulting_address = int(m.group(1), 16)

            # Segfault address from kernel
            m = re.search(r'KERN_\w+\s+at\s+0x([0-9a-fA-F]+)', line)
            if m:
                report.faulting_address = int(m.group(1), 16)

            # Stack frames: module`function + offset
            m = re.search(r'^\s*(\d+)\s+(\S+)\s+0x[0-9a-f]+\s+(.+?)(?:\s+\+\s+(\d+))?$', line)
            if m:
                report.crashed_thread_frames.append((
                    int(m.group(1)),
                    m.group(2),
                    m.group(3),
                    int(m.group(4)) if m.group(4) else 0,
                ))

            # Register values
            m = re.findall(r'((?:r|x|e)\w+)\s*(?:=|:)\s*0x([0-9a-fA-F]+)', line)
            for reg, val in m:
                report.registers[reg] = int(val, 16)

    def _classify_crash(self, report: CrashReport):
        """Classify the crash type based on signal, address, and context."""
        addr = report.faulting_address

        # EXC_GUARD → guarded resource violation (fd/port/vm guard)
        if report.signal == 'EXC_GUARD' or report.exception_type == 'EXC_GUARD':
            report.crash_type = 'assertion_failure'
            return

        # SIGABRT / EXC_CRASH / SIGTRAP+EXC_BREAKPOINT → assertion, heap, or bug trap
        if report.signal in ('SIGABRT', 'EXC_CRASH', 'SIGTRAP', 'EXC_BREAKPOINT'):
            subtype = report.exception_subtype.lower()
            stack_text = ' '.join(str(f) for f in report.crashed_thread_frames).lower()
            combined = subtype + ' ' + stack_text
            if 'heap' in combined or 'malloc_error' in combined:
                report.crash_type = 'heap_corruption'
            elif 'double' in combined and 'free' in combined:
                report.crash_type = 'double_free'
            elif 'use_after_free' in combined or ('free' in combined and 'use' in combined):
                report.crash_type = 'use_after_free'
            elif 'semaphore' in combined or 'dispatch' in combined or 'bug in client' in combined:
                report.crash_type = 'use_after_free'  # Semaphore dealloc while in use
            elif 'assert' in combined or 'abort' in combined or 'trap' in combined:
                report.crash_type = 'assertion_failure'
            elif 'malloc' in combined or 'free' in combined:
                report.crash_type = 'heap_corruption'
            else:
                report.crash_type = 'assertion_failure'
            return

        # NULL dereference (address near 0, but not addr=0 with no signal)
        if addr is not None and 0 < addr < 0x10000:
            report.crash_type = 'null_deref'
            return

        # Controlled address patterns (0x41414141 = AAAA, 0x42424242 = BBBB, etc.)
        if addr:
            addr_hex = f'{addr:016x}'
            # Repeated byte patterns indicate attacker-controlled value
            if len(set(addr_hex[::2])) == 1 and len(set(addr_hex[1::2])) == 1:
                report.crash_type = 'oob_write'
                return

        # SIGILL → possible code corruption / ROP
        if report.signal == 'SIGILL' or report.signal == 'EXC_BAD_INSTRUCTION':
            report.crash_type = 'oob_write'  # Code page corrupted
            return

        # Stack exhaustion (very high stack address, actual stack range)
        if addr and 0x7FF000000000 < addr < 0x800000000000:
            report.crash_type = 'stack_exhaustion'
            return

        # Stack overflow check (PC in stack region, or stack-related frames)
        stack_text = ' '.join(str(f) for f in report.crashed_thread_frames).lower()
        if 'stack_overflow' in stack_text or 'stack_chk_fail' in stack_text:
            report.crash_type = 'stack_overflow'
            return

        # Heap indicators
        if 'heap' in stack_text or 'malloc' in stack_text or 'free' in stack_text:
            if 'free' in stack_text and ('double' in stack_text or report.exception_subtype.lower().count('free') > 1):
                report.crash_type = 'double_free'
            else:
                report.crash_type = 'heap_overflow'
            return

        # SEGV with writable address → likely OOB write
        if report.signal in ('SIGSEGV', 'EXC_BAD_ACCESS'):
            subtype = report.exception_subtype.lower()
            if 'write' in subtype or 'store' in subtype:
                report.crash_type = 'oob_write'
            elif 'read' in subtype or 'load' in subtype:
                report.crash_type = 'oob_read'
            else:
                report.crash_type = 'oob_read'  # Default for SEGV
            return

        report.crash_type = 'unknown'

    def _assess_exploitability(self, report: CrashReport):
        """Score exploitability (0-10) based on crash classification and context."""
        crash_info = CRASH_TYPES.get(report.crash_type, CRASH_TYPES['unknown'])
        base = crash_info['base_score']
        report.exploitability = crash_info['exploitability']

        score = float(base)

        # Signal modifiers
        sig_info = SIGNAL_INFO.get(report.signal, {})
        sig_base = sig_info.get('base_score', 5)
        score = (score + sig_base) / 2.0  # Average of crash type and signal

        # Control of PC/IP → highly exploitable
        pc_regs = {'rip', 'pc', 'eip', 'x30', 'lr'}
        for reg in pc_regs:
            if reg in report.registers:
                val = report.registers[reg]
                # If PC is in a non-standard range, might be controlled
                if val < 0x1000 or (val > 0x41414141 and val < 0x42424242):
                    score = min(10.0, score + 2.0)
                    report.exploitability = EXPLOITABLE
                    report.mitigations_bypassed.append('control of instruction pointer')
                    break

        # Heap corruption is worse if ASLR indicators present
        if report.crash_type in ('heap_corruption', 'heap_overflow', 'use_after_free'):
            score = min(10.0, score + 1.0)

        # Write-based crashes are more exploitable than reads
        if report.crash_type == 'oob_write':
            score = min(10.0, score + 1.5)
        elif report.crash_type == 'oob_read':
            score = max(0, score - 1.0)

        # NULL deref is generally not exploitable (unless kernel)
        if report.crash_type == 'null_deref':
            score = min(score, 4.0)

        report.score = round(score, 1)

    def _generate_hypothesis(self, report: CrashReport):
        """Generate a root cause hypothesis based on crash analysis."""
        crash_info = CRASH_TYPES.get(report.crash_type, {})
        parts = [crash_info.get('description', 'Unknown crash')]

        addr = report.faulting_address
        if addr:
            if addr < 0x1000:
                parts.append(f'at near-NULL address {hex(addr)} (likely NULL pointer + small offset)')
            elif addr > 0x7FF000000000:
                parts.append(f'at stack address {hex(addr)} (stack region)')
            else:
                parts.append(f'at address {hex(addr)}')

        if report.signal:
            sig_info = SIGNAL_INFO.get(report.signal, {})
            parts.append(f'signal: {sig_info.get("name", report.signal)}')

        if report.crashed_thread_frames:
            top_frame = report.crashed_thread_frames[0]
            parts.append(f'in: {top_frame[2] if len(top_frame) > 2 else top_frame[1]}')

        report.hypothesis = ' — '.join(parts)

    def format_report(self, report: CrashReport) -> str:
        """Format a crash report as human-readable text."""
        lines = [
            f'=== CRASH TRIAGE: {report.process_name} (PID {report.pid}) ===',
            f'Signal: {report.signal}',
            f'Exception: {report.exception_type}',
            f'Address: {hex(report.faulting_address)}',
            '',
            f'Classification: {report.crash_type}',
            f'Description: {CRASH_TYPES.get(report.crash_type, {}).get("description", "?")}',
            f'Exploitability: {report.exploitability}',
            f'Score: {report.score:.1f}/10.0',
            '',
            f'Hypothesis: {report.hypothesis}',
        ]

        if report.mitigations_bypassed:
            lines.append(f'Mitigations bypassed: {", ".join(report.mitigations_bypassed)}')

        if report.crashed_thread_frames:
            lines.append('')
            lines.append('Crashed thread backtrace:')
            for frame in report.crashed_thread_frames[:10]:
                lines.append(f'  {frame}')

        if report.registers:
            lines.append('')
            lines.append('Registers:')
            for reg, val in sorted(report.registers.items()):
                lines.append(f'  {reg} = {hex(val) if isinstance(val, int) else val}')

        return '\n'.join(lines)

    def summary(self, reports: List[CrashReport]) -> Dict[str, Any]:
        """Summarize multiple crash reports."""
        by_type = {}
        by_exploit = {}
        scores = []

        for r in reports:
            by_type[r.crash_type] = by_type.get(r.crash_type, 0) + 1
            by_exploit[r.exploitability] = by_exploit.get(r.exploitability, 0) + 1
            scores.append(r.score)

        return {
            'total_crashes': len(reports),
            'by_type': by_type,
            'by_exploitability': by_exploit,
            'max_score': max(scores) if scores else 0,
            'avg_score': round(sum(scores) / len(scores), 1) if scores else 0,
            'exploitable_count': by_exploit.get(EXPLOITABLE, 0) + by_exploit.get(PROBABLY_EXPLOITABLE, 0),
        }
