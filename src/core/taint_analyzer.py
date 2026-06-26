"""
Taint Analyzer — Static data-flow analysis for generated code

Uses dataflow triplets to detect vulnerability patterns in FORGE output:
1. Identifies taint sources (user_input, socket_recv, file_read, etc.)
2. Traces flows through operations to dangerous sinks
3. Checks for sanitization on each flow path
4. Reports findings with severity and remediation
"""
# Dependencies: none
# Depended by: security_analyzer


import re
from typing import List, Dict, Any, Optional


# Maps Python code patterns to dataflow entity names
SOURCE_PATTERNS = {
    'user_input': [
        r'\binput\s*\(',
        r'\brequest\.(form|args|json|data|values|get_json)',
        r'\bflask\.request\b',
        r'\bsys\.argv\b',
        r'\bargparse\b',
    ],
    'file_read': [
        r'\bopen\s*\([^)]*["\']r',
        r'\bopen\s*\([^)]*\)\s*\.\s*read\b',
        r'\.read\(\)',
        r'\.readlines?\(\)',
        r'\bPath\([^)]*\)\.read_text\b',
    ],
    'http_response': [
        r'\brequests\.(get|post|put|delete|patch|head)\b',
        r'\burllib\.request\.urlopen\b',
        r'\bhttpx\.\w+\b',
        r'\baiohttp\.\w+\b',
    ],
    'socket_recv': [
        r'\.recv\(',
        r'\.recvfrom\(',
        r'\.recv_into\(',
        r'\bsocket\.socket\b',
    ],
    'environment_variable': [
        r'\bos\.environ\b',
        r'\bos\.getenv\b',
    ],
    'database_result': [
        r'\.fetchone\b',
        r'\.fetchall\b',
        r'\.fetchmany\b',
        r'\bcursor\.execute\b',
    ],
    'command_line_args': [
        r'\bsys\.argv\b',
        r'\bargparse\b',
        r'\bclick\.\w+\b',
    ],
    'mach_msg': [
        r'\bmach_msg\b',
        r'\bMachPort\b',
    ],
    'xpc_message': [
        r'\bxpc_\w+\b',
        r'\bNSXPCConnection\b',
    ],
}

# Maps Python code patterns to dangerous sink entity names
SINK_PATTERNS = {
    'eval': [r'\beval\s*\('],
    'exec': [r'\bexec\s*\('],
    'subprocess_run': [
        r'\bsubprocess\.(run|call|Popen|check_output|check_call)\b',
        r'\bos\.popen\b',
    ],
    'os_system': [r'\bos\.system\s*\('],
    'sql_query': [
        r'\.execute\s*\(\s*["\']',
        r'\.execute\s*\(\s*f["\']',
        r'\.execute\s*\([^,]*%',
        r'\.execute\s*\([^,]*\.format\b',
    ],
    'pickle_loads': [
        r'\bpickle\.loads?\b',
        r'\bcPickle\.loads?\b',
        r'\bjoblib\.load\b',
    ],
    'yaml_load': [
        r'\byaml\.load\s*\(',
        r'\byaml\.unsafe_load\b',
    ],
    'html_template': [
        r'\brender_template_string\b',
        r'\bMarkup\s*\(',
        r'\bJinja2\b.*\brender\b',
        r'%>.*<%',
    ],
    'open': [
        r'\bopen\s*\([^)]*["\']w',
        r'\bopen\s*\(\s*[a-z_]+\s*[,)]',
    ],
    'struct_unpack': [r'\bstruct\.unpack\b'],
    'nscoding_decode': [r'\bNSKeyedUnarchiver\b'],
}

# Maps Python code patterns to sanitization entity names
SANITIZER_PATTERNS = {
    'parameterized_query': [
        r'\.execute\s*\([^,]*,\s*[\[\(]',
        r'\.execute\s*\(\s*["\'][^"\']*\?\s*["\']',
        r'\.execute\s*\(\s*["\'][^"\']*%s',
    ],
    'shlex_quote': [r'\bshlex\.quote\b'],
    'html_escape': [
        r'\bhtml\.escape\b',
        r'\bmarkupsafe\.escape\b',
        r'\bescape\s*\(',
        r'\bbleach\.clean\b',
    ],
    'input_validation': [
        r'\bisinstance\s*\(',
        r'\bint\s*\(\s*\w+\s*\)',
        r'\bfloat\s*\(\s*\w+\s*\)',
        r'\bre\.(match|fullmatch|search)\b.*\binput\b',
    ],
    'os_path_basename': [
        r'\bos\.path\.basename\b',
        r'\bos\.path\.realpath\b',
        r'\bos\.path\.abspath\b',
        r'\bPurePath\b',
    ],
}


class TaintFinding:
    """A single taint analysis finding"""

    SEVERITY_MAP = {
        'code_injection': 'CRITICAL',
        'command_injection': 'CRITICAL',
        'deserialization': 'CRITICAL',
        'injection_risk': 'HIGH',
        'xss': 'HIGH',
        'stored_xss': 'HIGH',
        'path_traversal': 'MEDIUM',
        'privilege_escalation': 'CRITICAL',
        'kernel_overflow': 'CRITICAL',
        'heap_overflow': 'CRITICAL',
        'integer_overflow': 'HIGH',
        'buffer_overflow': 'HIGH',
        'ipc_injection': 'HIGH',
        'plist_injection': 'MEDIUM',
        'sandbox_escape': 'HIGH',
        'data_propagation': 'INFO',
    }

    def __init__(self, source: str, sink: str, flow_type: str,
                 line_source: int = 0, line_sink: int = 0,
                 sanitized: bool = False, sanitizer: str = ''):
        self.source = source
        self.sink = sink
        self.flow_type = flow_type
        self.severity = self.SEVERITY_MAP.get(flow_type, 'MEDIUM')
        self.line_source = line_source
        self.line_sink = line_sink
        self.sanitized = sanitized
        self.sanitizer = sanitizer

    def to_dict(self) -> Dict[str, Any]:
        return {
            'source': self.source,
            'sink': self.sink,
            'flow_type': self.flow_type,
            'severity': self.severity,
            'line_source': self.line_source,
            'line_sink': self.line_sink,
            'sanitized': self.sanitized,
            'sanitizer': self.sanitizer,
        }

    def __repr__(self):
        status = 'SANITIZED' if self.sanitized else 'VULNERABLE'
        return (f"[{self.severity}] {self.source}:{self.line_source} → "
                f"{self.sink}:{self.line_sink} ({self.flow_type}) [{status}]")


class TaintAnalyzer:
    """Static taint analysis using dataflow triplets"""

    def __init__(self, knowledge_engine=None):
        self.knowledge = knowledge_engine

    def analyze(self, code: str) -> List[TaintFinding]:
        """Analyze generated code for taint flow vulnerabilities.
        Returns list of TaintFinding objects."""
        findings = []
        lines = code.split('\n')

        # Phase 1: Detect sources and their line numbers
        detected_sources = []  # [(entity_name, line_num, line_text)]
        for i, line in enumerate(lines, 1):
            for source_entity, patterns in SOURCE_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, line):
                        detected_sources.append((source_entity, i, line.strip()))
                        break

        if not detected_sources:
            return findings

        # Phase 2: Detect sinks and their line numbers
        detected_sinks = []  # [(entity_name, line_num, line_text)]
        for i, line in enumerate(lines, 1):
            for sink_entity, patterns in SINK_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, line):
                        detected_sinks.append((sink_entity, i, line.strip()))
                        break

        if not detected_sinks:
            return findings

        # Phase 3: Detect sanitizers
        detected_sanitizers = set()  # entity names
        for i, line in enumerate(lines, 1):
            for san_entity, patterns in SANITIZER_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, line):
                        detected_sanitizers.add(san_entity)
                        break

        # Phase 4: Check each source→sink pair against knowledge graph
        for source_entity, src_line, _ in detected_sources:
            for sink_entity, sink_line, _ in detected_sinks:
                # Source must appear before sink
                if src_line >= sink_line:
                    continue

                # Query knowledge engine for this flow path
                if self.knowledge:
                    trace = self.knowledge.trace_taint_path(source_entity, sink_entity)
                    if not trace['reachable']:
                        continue
                    flow_type = trace['flow_type'] or 'unknown'

                    # Check if any sanitizer in code matches known sanitizers for this source
                    is_sanitized = False
                    sanitizer_used = ''
                    for san in trace['sanitizers']:
                        if san in detected_sanitizers:
                            is_sanitized = True
                            sanitizer_used = san
                            break
                    # Also check safe_paths (sanitizer → sink direct)
                    if not is_sanitized:
                        for safe in trace['safe_paths']:
                            if safe in detected_sanitizers:
                                is_sanitized = True
                                sanitizer_used = safe
                                break
                else:
                    # No knowledge engine — use hardcoded flow type inference
                    flow_type = self._infer_flow_type(source_entity, sink_entity)
                    if not flow_type:
                        continue
                    is_sanitized = bool(detected_sanitizers)
                    sanitizer_used = ', '.join(detected_sanitizers) if is_sanitized else ''

                findings.append(TaintFinding(
                    source=source_entity,
                    sink=sink_entity,
                    flow_type=flow_type,
                    line_source=src_line,
                    line_sink=sink_line,
                    sanitized=is_sanitized,
                    sanitizer=sanitizer_used,
                ))

        return findings

    def _infer_flow_type(self, source: str, sink: str) -> Optional[str]:
        """Fallback flow type inference without knowledge engine"""
        dangerous_combos = {
            # User input → dangerous sinks
            ('user_input', 'eval'): 'code_injection',
            ('user_input', 'exec'): 'code_injection',
            ('user_input', 'subprocess_run'): 'command_injection',
            ('user_input', 'os_system'): 'command_injection',
            ('user_input', 'sql_query'): 'injection_risk',
            ('user_input', 'pickle_loads'): 'deserialization',
            ('user_input', 'yaml_load'): 'deserialization',
            ('user_input', 'html_template'): 'xss',
            ('user_input', 'open'): 'path_traversal',
            ('user_input', 'struct_unpack'): 'buffer_overflow',
            # Socket/network → sinks
            ('socket_recv', 'eval'): 'code_injection',
            ('socket_recv', 'exec'): 'code_injection',
            ('socket_recv', 'subprocess_run'): 'command_injection',
            ('socket_recv', 'os_system'): 'command_injection',
            ('socket_recv', 'pickle_loads'): 'deserialization',
            ('socket_recv', 'yaml_load'): 'deserialization',
            ('socket_recv', 'open'): 'path_traversal',
            ('socket_recv', 'struct_unpack'): 'buffer_overflow',
            ('socket_recv', 'sql_query'): 'injection_risk',
            # File read → sinks
            ('file_read', 'eval'): 'code_injection',
            ('file_read', 'exec'): 'code_injection',
            ('file_read', 'pickle_loads'): 'deserialization',
            ('file_read', 'yaml_load'): 'deserialization',
            ('file_read', 'open'): 'data_propagation',
            ('file_read', 'subprocess_run'): 'command_injection',
            ('file_read', 'struct_unpack'): 'buffer_overflow',
            # HTTP response → sinks
            ('http_response', 'eval'): 'code_injection',
            ('http_response', 'exec'): 'code_injection',
            ('http_response', 'pickle_loads'): 'deserialization',
            ('http_response', 'open'): 'path_traversal',
            ('http_response', 'subprocess_run'): 'command_injection',
            ('http_response', 'struct_unpack'): 'buffer_overflow',
            # Database → sinks
            ('database_result', 'eval'): 'code_injection',
            ('database_result', 'html_template'): 'stored_xss',
            ('database_result', 'open'): 'path_traversal',
            # Environment → sinks
            ('environment_variable', 'eval'): 'code_injection',
            ('environment_variable', 'subprocess_run'): 'command_injection',
            ('environment_variable', 'open'): 'path_traversal',
            # Command line → sinks
            ('command_line_args', 'eval'): 'code_injection',
            ('command_line_args', 'exec'): 'code_injection',
            ('command_line_args', 'subprocess_run'): 'command_injection',
            ('command_line_args', 'os_system'): 'command_injection',
            ('command_line_args', 'open'): 'path_traversal',
            ('command_line_args', 'sql_query'): 'injection_risk',
            # IPC → sinks
            ('mach_msg', 'eval'): 'ipc_injection',
            ('mach_msg', 'exec'): 'ipc_injection',
            ('mach_msg', 'struct_unpack'): 'buffer_overflow',
            ('xpc_message', 'eval'): 'ipc_injection',
            ('xpc_message', 'exec'): 'ipc_injection',
            ('xpc_message', 'open'): 'path_traversal',
        }
        return dangerous_combos.get((source, sink))

    def get_summary(self, findings: List[TaintFinding]) -> Dict[str, Any]:
        """Summarize analysis findings"""
        if not findings:
            return {'total': 0, 'vulnerable': 0, 'sanitized': 0, 'by_severity': {}}

        vulnerable = [f for f in findings if not f.sanitized]
        sanitized = [f for f in findings if f.sanitized]

        by_severity = {}
        for f in vulnerable:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        return {
            'total': len(findings),
            'vulnerable': len(vulnerable),
            'sanitized': len(sanitized),
            'by_severity': by_severity,
            'findings': [f.to_dict() for f in findings],
        }

    def format_report(self, findings: List[TaintFinding]) -> str:
        """Format findings as a human-readable report"""
        if not findings:
            return "No taint flow issues detected."

        lines = ["=== TAINT ANALYSIS REPORT ===", ""]
        vulnerable = [f for f in findings if not f.sanitized]
        sanitized = [f for f in findings if f.sanitized]

        if vulnerable:
            lines.append(f"VULNERABLE FLOWS: {len(vulnerable)}")
            for f in sorted(vulnerable, key=lambda x: x.severity):
                lines.append(f"  {f}")
            lines.append("")

        if sanitized:
            lines.append(f"SANITIZED FLOWS: {len(sanitized)}")
            for f in sanitized:
                lines.append(f"  {f}")
            lines.append("")

        summary = self.get_summary(findings)
        lines.append(f"Total: {summary['total']} | "
                      f"Vulnerable: {summary['vulnerable']} | "
                      f"Sanitized: {summary['sanitized']}")

        return '\n'.join(lines)
