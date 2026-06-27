"""
Self-Diagnostics — Phase 1 of FORGE Self-Repair

Structured error classification and diagnostic triplet generation.
FORGE doesn't just say "Task 23 failed" — it says WHY.

Error taxonomy: ~50 error classes organized into 6 categories.
Each error class has:
  - Pattern matchers (regex on stderr/error)
  - Diagnosable-by function
  - Suggested fix strategies (for Phase 2)
  - Severity (how hard to fix: trivial/moderate/hard/structural)

Diagnostic triplets: (task_id, failed_because, structured_diagnosis)
"""
# Dependencies: none
# Depended by: autonomous_loop, self_repair


import re
import ast
import traceback
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class Diagnosis:
    """Structured diagnosis for a single failure."""
    task_id: int
    task_intent: str
    error_class: str
    error_category: str
    severity: str                      # trivial, moderate, hard, structural
    root_cause: str                    # human-readable explanation
    failing_line: Optional[int] = None
    failing_function: Optional[str] = None
    failing_code: Optional[str] = None
    fix_strategies: List[str] = field(default_factory=list)
    fragment_keys: List[str] = field(default_factory=list)
    compound: bool = False             # multiple root causes?
    sub_diagnoses: List['Diagnosis'] = field(default_factory=list)

    def to_triplet(self) -> Dict[str, Any]:
        """Convert to a causal triplet."""
        return {
            'trigger': f'task_{self.task_id}',
            'mechanism': 'failed_because',
            'outcome': self.error_class,
            'confidence': 1.0,
            '_diagnostic': {
                'category': self.error_category,
                'severity': self.severity,
                'root_cause': self.root_cause,
                'fix_strategies': self.fix_strategies,
                'fragment_keys': self.fragment_keys,
                'failing_line': self.failing_line,
            }
        }

    def __str__(self) -> str:
        frags = ', '.join(self.fragment_keys) if self.fragment_keys else 'unknown'
        line = f" (line {self.failing_line})" if self.failing_line else ""
        fixes = ' | Fixes: ' + ', '.join(self.fix_strategies) if self.fix_strategies else ''
        return (
            f"[{self.severity:9s}] {self.error_class}: {self.root_cause}{line}"
            f" [fragments: {frags}]{fixes}"
        )


# ── Error Taxonomy ────────────────────────────────────────────────

ERROR_TAXONOMY = {
    # Category: IMPORT — missing or unavailable modules
    'import_error': {
        'category': 'import',
        'severity': 'trivial',
        'patterns': [r'ModuleNotFoundError', r'ImportError'],
        'fix_strategies': ['add_try_except_import', 'remove_unused_import', 'use_stdlib_alternative'],
    },
    'import_circular': {
        'category': 'import',
        'severity': 'moderate',
        'patterns': [r'circular import', r'cannot import name.*from partially initialized'],
        'fix_strategies': ['defer_import', 'restructure_imports'],
    },

    # Category: SYNTAX — code that won't parse
    'syntax_error': {
        'category': 'syntax',
        'severity': 'moderate',
        'patterns': [r'SyntaxError'],
        'fix_strategies': ['fix_syntax_ast', 'regenerate_fragment'],
    },
    'indentation_error': {
        'category': 'syntax',
        'severity': 'trivial',
        'patterns': [r'IndentationError'],
        'fix_strategies': ['fix_indentation'],
    },

    # Category: TYPE — wrong types, missing attributes, bad args
    'type_error_args': {
        'category': 'type',
        'severity': 'moderate',
        'patterns': [r'TypeError.*argument', r'TypeError.*positional', r'TypeError.*keyword'],
        'fix_strategies': ['fix_function_args', 'add_default_args'],
    },
    'type_error_general': {
        'category': 'type',
        'severity': 'moderate',
        'patterns': [r'TypeError'],
        'fix_strategies': ['add_type_cast', 'fix_type_mismatch'],
    },
    'attribute_error': {
        'category': 'type',
        'severity': 'moderate',
        'patterns': [r'AttributeError'],
        'fix_strategies': ['fix_attribute_name', 'add_hasattr_guard'],
    },
    'key_error': {
        'category': 'type',
        'severity': 'trivial',
        'patterns': [r'KeyError'],
        'fix_strategies': ['use_dict_get', 'add_key_check'],
    },
    'index_error': {
        'category': 'type',
        'severity': 'trivial',
        'patterns': [r'IndexError'],
        'fix_strategies': ['add_bounds_check', 'use_safe_index'],
    },
    'value_error': {
        'category': 'type',
        'severity': 'moderate',
        'patterns': [r'ValueError'],
        'fix_strategies': ['add_value_validation', 'use_try_except'],
    },

    # Category: RUNTIME — execution environment issues
    'file_not_found': {
        'category': 'runtime',
        'severity': 'moderate',
        'patterns': [r'FileNotFoundError', r'No such file or directory'],
        'fix_strategies': ['create_test_file', 'add_file_exists_check', 'use_tempfile'],
    },
    'permission_error': {
        'category': 'runtime',
        'severity': 'hard',
        'patterns': [r'PermissionError'],
        'fix_strategies': ['use_tempdir', 'add_permission_check'],
    },
    'connection_error': {
        'category': 'runtime',
        'severity': 'hard',
        'patterns': [r'ConnectionError', r'ConnectionRefused', r'URLError', r'socket\.error'],
        'fix_strategies': ['mock_network', 'add_offline_fallback'],
    },
    'system_exit': {
        'category': 'runtime',
        'severity': 'moderate',
        'patterns': [r'SystemExit'],
        'fix_strategies': ['add_argv_fallback', 'remove_sys_exit', 'wrap_main'],
    },
    'timeout': {
        'category': 'runtime',
        'severity': 'hard',
        'patterns': [r'timed out', r'TimeoutError', r'timeout'],
        'fix_strategies': ['add_iteration_limit', 'break_infinite_loop', 'reduce_data_size'],
    },
    'recursion_error': {
        'category': 'runtime',
        'severity': 'moderate',
        'patterns': [r'RecursionError', r'maximum recursion depth'],
        'fix_strategies': ['convert_to_iterative', 'add_recursion_limit'],
    },
    'memory_error': {
        'category': 'runtime',
        'severity': 'hard',
        'patterns': [r'MemoryError', r'MemoryError\b'],
        'fix_strategies': ['reduce_data_size', 'use_generator'],
    },
    'os_error': {
        'category': 'runtime',
        'severity': 'moderate',
        'patterns': [r'OSError', r'IOError'],
        'fix_strategies': ['add_os_check', 'use_tempdir'],
    },
    'name_error': {
        'category': 'runtime',
        'severity': 'moderate',
        'patterns': [r'NameError'],
        'fix_strategies': ['define_missing_variable', 'fix_variable_scope'],
    },
    'zero_division': {
        'category': 'runtime',
        'severity': 'trivial',
        'patterns': [r'ZeroDivisionError'],
        'fix_strategies': ['add_zero_check'],
    },
    'unicode_error': {
        'category': 'runtime',
        'severity': 'trivial',
        'patterns': [r'UnicodeError', r'UnicodeDecodeError', r'UnicodeEncodeError'],
        'fix_strategies': ['add_encoding_param', 'use_errors_replace'],
    },
    'overflow_error': {
        'category': 'runtime',
        'severity': 'moderate',
        'patterns': [r'OverflowError'],
        'fix_strategies': ['add_bounds_clamp', 'use_decimal'],
    },
    'assertion_error': {
        'category': 'runtime',
        'severity': 'moderate',
        'patterns': [r'AssertionError'],
        'fix_strategies': ['fix_assertion_condition', 'remove_assertion'],
    },

    # Category: SANDBOX — specific to FORGE's sandbox environment
    'missing_cli_args': {
        'category': 'sandbox',
        'severity': 'moderate',
        'patterns': [
            r'error: the following arguments are required',
            r'expected one argument',
            r'too few arguments',
            r'unrecognized arguments',
        ],
        'fix_strategies': ['add_argv_fallback', 'use_defaults_instead_of_argparse'],
    },
    'missing_test_data': {
        'category': 'sandbox',
        'severity': 'moderate',
        'patterns': [
            r'No such file.*\.csv',
            r'No such file.*\.json',
            r'No such file.*\.txt',
            r'No such file.*\.db',
        ],
        'fix_strategies': ['create_inline_test_data', 'use_io_stringio'],
    },
    'network_in_sandbox': {
        'category': 'sandbox',
        'severity': 'hard',
        'patterns': [
            r'urlopen',
            r'requests\.get',
            r'urllib',
            r'socket\.connect',
        ],
        'fix_strategies': ['mock_network_response', 'use_offline_data'],
    },
    'server_never_stops': {
        'category': 'sandbox',
        'severity': 'hard',
        'patterns': [r'Script timed out.*server', r'Script timed out.*daemon'],
        'fix_strategies': ['add_server_timeout', 'run_in_thread_with_timeout'],
    },
    'interactive_input': {
        'category': 'sandbox',
        'severity': 'moderate',
        'patterns': [r'EOFError', r'input\(\)', r'raw_input'],
        'fix_strategies': ['replace_input_with_default', 'remove_interactive'],
    },

    # Category: FORGE — FORGE-specific assembly/generation issues
    'empty_functions': {
        'category': 'forge',
        'severity': 'moderate',
        'patterns': [r'empty_functions', r'Empty functions'],
        'fix_strategies': ['fill_function_bodies', 'use_different_fragment'],
    },
    'no_code_generated': {
        'category': 'forge',
        'severity': 'structural',
        'patterns': [r'No code generated', r'no_code'],
        'fix_strategies': ['add_fragment', 'add_bridge_triplet'],
    },
    'unresolved_template': {
        'category': 'forge',
        'severity': 'trivial',
        'patterns': [r'\{[a-z_]+\}', r'unsubstituted'],
        'fix_strategies': ['hardcode_template_default', 'add_to_resolve_variables'],
    },
    'wrong_fragment': {
        'category': 'forge',
        'severity': 'structural',
        'patterns': [r'No implementation available'],
        'fix_strategies': ['add_bridge_triplet', 'add_fragment'],
    },
    'composition_bloat': {
        'category': 'forge',
        'severity': 'moderate',
        'patterns': [r'Script timed out.*not.*server'],
        'fix_strategies': ['limit_fragments', 'add_dedicated_fragment'],
    },

    # Category: DATA — data format/content issues
    'column_mismatch': {
        'category': 'data',
        'severity': 'moderate',
        'patterns': [
            r'table.*has.*columns.*but.*values',
            r'column.*not found',
            r'OperationalError.*column',
        ],
        'fix_strategies': ['use_explicit_columns', 'match_schema'],
    },
    'json_decode_error': {
        'category': 'data',
        'severity': 'moderate',
        'patterns': [r'JSONDecodeError', r'json\.decoder'],
        'fix_strategies': ['validate_json_input', 'use_try_except_json'],
    },
    'csv_format_error': {
        'category': 'data',
        'severity': 'moderate',
        'patterns': [r'csv\.Error', r'field larger than field limit'],
        'fix_strategies': ['increase_csv_limit', 'add_csv_error_handling'],
    },
    'sqlite_error': {
        'category': 'data',
        'severity': 'moderate',
        'patterns': [r'OperationalError', r'IntegrityError', r'sqlite3'],
        'fix_strategies': ['fix_sql_schema', 'use_explicit_columns'],
    },
}


class SelfDiagnostics:
    """Diagnose FORGE failures with structured error classification."""

    def __init__(self):
        self.taxonomy = ERROR_TAXONOMY
        # Compile patterns for faster matching
        self._compiled = {}
        for cls_name, cls_info in self.taxonomy.items():
            self._compiled[cls_name] = [
                re.compile(p, re.IGNORECASE) for p in cls_info['patterns']
            ]
        # Accumulated diagnoses for the current run
        self.diagnoses: List[Diagnosis] = []

    def diagnose(self, task_id: int, task_intent: str, error_str: str,
                 code: str = None, fragment_keys: List[str] = None) -> Diagnosis:
        """Produce a structured diagnosis for a task failure.

        Args:
            task_id: Benchmark task ID
            task_intent: The task description
            error_str: Error message / stderr
            code: The generated code (for line-level analysis)
            fragment_keys: Which fragments were used

        Returns:
            Diagnosis dataclass with full analysis
        """
        if not error_str:
            return Diagnosis(
                task_id=task_id, task_intent=task_intent,
                error_class='unknown', error_category='unknown',
                severity='hard', root_cause='No error information available',
                fragment_keys=fragment_keys or [],
            )

        # Match against taxonomy
        matched_class = None
        matched_info = None

        for cls_name, compiled_patterns in self._compiled.items():
            for pattern in compiled_patterns:
                if pattern.search(error_str):
                    matched_class = cls_name
                    matched_info = self.taxonomy[cls_name]
                    break
            if matched_class:
                break

        if not matched_class:
            matched_class = 'unknown'
            matched_info = {
                'category': 'unknown',
                'severity': 'hard',
                'fix_strategies': [],
            }

        # Extract traceback details
        failing_line, failing_func, failing_code = self._parse_traceback(error_str)

        # Determine root cause
        root_cause = self._determine_root_cause(
            matched_class, error_str, code, failing_line
        )

        # Check for compound failures
        all_matches = self._find_all_matches(error_str)
        compound = len(all_matches) > 1

        diag = Diagnosis(
            task_id=task_id,
            task_intent=task_intent,
            error_class=matched_class,
            error_category=matched_info['category'],
            severity=matched_info['severity'],
            root_cause=root_cause,
            failing_line=failing_line,
            failing_function=failing_func,
            failing_code=failing_code,
            fix_strategies=matched_info.get('fix_strategies', []),
            fragment_keys=fragment_keys or [],
            compound=compound,
        )

        self.diagnoses.append(diag)
        return diag

    def diagnose_batch(self, results: List[Dict[str, Any]],
                       fragment_map: Dict[int, List[str]] = None) -> List[Diagnosis]:
        """Diagnose all failures in a benchmark result set.

        Args:
            results: List of benchmark result dicts (id, intent, success, error, ...)
            fragment_map: Optional mapping of task_id → fragment_keys

        Returns:
            List of Diagnosis objects for all failures
        """
        diagnoses = []
        for r in results:
            if not r.get('success', True):
                frags = (fragment_map or {}).get(r['id'], [])
                diag = self.diagnose(
                    task_id=r['id'],
                    task_intent=r.get('intent', ''),
                    error_str=r.get('error', ''),
                    fragment_keys=frags,
                )
                diagnoses.append(diag)
        return diagnoses

    def _parse_traceback(self, error_str: str) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """Extract failing line number, function name, and code from a traceback."""
        # Match: File "...", line N, in func_name
        tb_matches = re.findall(
            r'File "([^"]+)", line (\d+), in (\w+)',
            error_str
        )
        if tb_matches:
            # Take the last (most specific) traceback entry
            _, line_str, func_name = tb_matches[-1]
            line_num = int(line_str)

            # Try to extract the failing code line
            code_match = re.search(
                rf'line {line_str}.*?\n\s*(.+?)(?:\n|$)',
                error_str
            )
            code_line = code_match.group(1).strip() if code_match else None

            return line_num, func_name, code_line

        return None, None, None

    def _determine_root_cause(self, error_class: str, error_str: str,
                              code: str = None, failing_line: int = None) -> str:
        """Generate a human-readable root cause explanation."""

        # Extract the actual error message (last line of traceback)
        lines = error_str.strip().split('\n')
        last_line = lines[-1].strip() if lines else error_str

        # Class-specific root cause descriptions
        if error_class == 'missing_cli_args':
            # Extract which args are missing
            match = re.search(r'required: (.+)', error_str)
            args = match.group(1) if match else 'unknown arguments'
            return f"Script requires CLI arguments ({args}) but sandbox provides none"

        if error_class == 'import_error':
            match = re.search(r"No module named '([^']+)'", error_str)
            module = match.group(1) if match else 'unknown'
            return f"Module '{module}' not available in sandbox"

        if error_class == 'file_not_found' or error_class == 'missing_test_data':
            match = re.search(r"No such file.*?'([^']+)'", error_str)
            path = match.group(1) if match else 'unknown file'
            return f"Expected file '{path}' does not exist in sandbox"

        if error_class == 'column_mismatch':
            return f"SQL column count mismatch: {last_line}"

        if error_class == 'timeout' or error_class == 'server_never_stops':
            return "Script did not complete within timeout (infinite loop or server)"

        if error_class == 'system_exit':
            return "Script called sys.exit() — likely argparse failure"

        if error_class == 'empty_functions':
            match = re.search(r"Empty functions: \[(.+?)\]", error_str)
            funcs = match.group(1) if match else 'unknown'
            return f"Generated code has stub functions: {funcs}"

        if error_class == 'no_code_generated':
            return "No fragment matched the task intent"

        if error_class == 'composition_bloat':
            return "Too many fragments assembled — resulting code too large/slow"

        if error_class == 'unresolved_template':
            match = re.search(r'\{(\w+)\}', error_str)
            var = match.group(1) if match else 'unknown'
            return f"Template variable '{{{var}}}' was not resolved"

        # Generic: use the last line of the traceback
        return last_line[:200]

    def _find_all_matches(self, error_str: str) -> List[str]:
        """Find all matching error classes (for compound diagnosis)."""
        matches = []
        for cls_name, compiled_patterns in self._compiled.items():
            for pattern in compiled_patterns:
                if pattern.search(error_str):
                    matches.append(cls_name)
                    break
        return matches

    # ── Reporting ──

    def category_summary(self) -> Dict[str, int]:
        """Count diagnoses by category."""
        counts = {}
        for d in self.diagnoses:
            counts[d.error_category] = counts.get(d.error_category, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: -x[1]))

    def severity_summary(self) -> Dict[str, int]:
        """Count diagnoses by severity."""
        counts = {}
        for d in self.diagnoses:
            counts[d.severity] = counts.get(d.severity, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: -x[1]))

    def fixable_count(self) -> Tuple[int, int]:
        """Return (fixable, total) — how many have at least one fix strategy."""
        fixable = sum(1 for d in self.diagnoses if d.fix_strategies)
        return fixable, len(self.diagnoses)

    def format_report(self) -> str:
        """Generate a diagnostic report for all accumulated diagnoses."""
        if not self.diagnoses:
            return "No failures diagnosed."

        lines = [
            f"=== FORGE Self-Diagnostics Report ===",
            f"Total failures: {len(self.diagnoses)}",
            f"",
        ]

        # Category breakdown
        cats = self.category_summary()
        if cats:
            lines.append("By category:")
            for cat, cnt in cats.items():
                lines.append(f"  {cat}: {cnt}")
            lines.append("")

        # Severity breakdown
        sevs = self.severity_summary()
        if sevs:
            lines.append("By severity:")
            for sev, cnt in sevs.items():
                lines.append(f"  {sev}: {cnt}")
            lines.append("")

        # Fixability
        fixable, total = self.fixable_count()
        lines.append(f"Auto-fixable: {fixable}/{total} ({fixable/total*100:.0f}%)")
        lines.append("")

        # Individual diagnoses
        lines.append("Diagnoses:")
        for d in self.diagnoses:
            lines.append(f"  Task #{d.task_id}: {d}")

        return '\n'.join(lines)

    def to_triplets(self) -> List[Dict[str, Any]]:
        """Convert all diagnoses to causal triplets."""
        return [d.to_triplet() for d in self.diagnoses]
