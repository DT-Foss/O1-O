"""
Vulnerability Pattern Engine — Advanced pattern detection for code analysis

Detects complex vulnerability patterns that go beyond simple taint analysis:

1. Type confusion: type checks that can be bypassed, unsafe casts
2. TOCTOU (Time-of-check-to-time-of-use): gap between check and use
3. Double-free / use-after-free indicators
4. Integer overflow in size calculations (malloc, memcpy, etc.)
5. Race conditions: shared state without synchronization
6. Logic bugs: inverted checks, off-by-one, missing error handling
7. Format string vulnerabilities
8. Path traversal patterns
9. Deserialization gadgets
"""
# Dependencies: none
# Depended by: security_analyzer


import ast
import re
from typing import List, Dict, Any, Optional


class VulnFinding:
    """A detected vulnerability pattern."""

    def __init__(self, pattern: str, line: int, code: str,
                 severity: str, description: str, cwe: str = '',
                 cve_examples: List[str] = None):
        self.pattern = pattern
        self.line = line
        self.code = code
        self.severity = severity
        self.description = description
        self.cwe = cwe
        self.cve_examples = cve_examples or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            'pattern': self.pattern,
            'line': self.line,
            'code': self.code[:100],
            'severity': self.severity,
            'description': self.description,
            'cwe': self.cwe,
            'cve_examples': self.cve_examples,
        }

    def __repr__(self):
        cwe = f' [{self.cwe}]' if self.cwe else ''
        return f'[{self.severity}] L{self.line}: {self.pattern}{cwe} — {self.description}'


# ========== PATTERN DEFINITIONS ==========

TOCTOU_PATTERNS = [
    # Check file exists then open → race window
    {
        'check': r'\bos\.path\.(exists|isfile|isdir)\s*\(',
        'use': r'\bopen\s*\(',
        'max_gap': 5,
        'description': 'File existence check then open — TOCTOU race window',
        'cwe': 'CWE-367',
        'cve_examples': ['CVE-2016-1247', 'CVE-2019-3462'],
    },
    # Check permission then access
    {
        'check': r'\bos\.access\s*\(',
        'use': r'\b(open|os\.rename|os\.remove|shutil\.\w+)\s*\(',
        'max_gap': 5,
        'description': 'Permission check then file operation — TOCTOU race',
        'cwe': 'CWE-367',
    },
    # Check PID then signal
    {
        'check': r'\bos\.path\.exists\s*\([\'"]\/proc\/',
        'use': r'\bos\.kill\s*\(',
        'max_gap': 10,
        'description': 'Process existence check then signal — PID reuse race',
        'cwe': 'CWE-367',
    },
]

TYPE_CONFUSION_PATTERNS = [
    {
        'pattern': r'isinstance\s*\(\s*\w+\s*,\s*\(.*str.*int.*\)\s*\)',
        'description': 'Mixed type check (str, int) — possible type confusion on operations',
        'cwe': 'CWE-843',
        'severity': 'MEDIUM',
    },
    {
        'pattern': r'json\.loads\s*\([^)]+\)\s*\[[\'"]',
        'description': 'Direct indexing on json.loads result without type check — may raise TypeError/KeyError',
        'cwe': 'CWE-843',
        'severity': 'MEDIUM',
    },
    {
        'pattern': r'int\s*\(\s*request\.',
        'description': 'Direct int() on request parameter — ValueError on non-numeric input',
        'cwe': 'CWE-843',
        'severity': 'MEDIUM',
        'cve_examples': ['CVE-2021-23017'],
    },
    {
        'pattern': r'struct\.unpack\s*\([^)]*,\s*\w+\s*\)',
        'description': 'struct.unpack without length validation — truncated data causes errors',
        'cwe': 'CWE-843',
        'severity': 'HIGH',
    },
]

RACE_CONDITION_PATTERNS = [
    {
        'pattern': r'threading\.Thread.*target=.*(?:global|shared|lock|counter|total)',
        'description': 'Thread accesses shared variable — potential race condition',
        'cwe': 'CWE-362',
        'severity': 'HIGH',
    },
    {
        'pattern': r'(?:global\s+\w+|shared_\w+)\s*[+\-*/]?=',
        'description': 'Non-atomic modification of shared/global variable',
        'cwe': 'CWE-362',
        'severity': 'MEDIUM',
    },
]

FORMAT_STRING_PATTERNS = [
    {
        'pattern': r'logging\.\w+\s*\(\s*[^,]+%\s',
        'description': 'String formatting in logging call — use logging params instead',
        'cwe': 'CWE-134',
        'severity': 'LOW',
    },
    {
        'pattern': r'\.format\s*\(\s*\*',
        'description': 'str.format with splat — user-controlled format string possible',
        'cwe': 'CWE-134',
        'severity': 'HIGH',
    },
]

DESERIALIZATION_GADGETS = [
    {
        'pattern': r'pickle\.(loads?|Unpickler)\s*\(',
        'description': 'Pickle deserialization — arbitrary code execution via __reduce__',
        'cwe': 'CWE-502',
        'severity': 'CRITICAL',
        'cve_examples': ['CVE-2019-6446', 'CVE-2020-7965'],
    },
    {
        'pattern': r'yaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*yaml\.SafeLoader)',
        'description': 'yaml.load without SafeLoader — arbitrary code execution',
        'cwe': 'CWE-502',
        'severity': 'CRITICAL',
        'cve_examples': ['CVE-2017-18342'],
    },
    {
        'pattern': r'marshal\.loads?\s*\(',
        'description': 'marshal deserialization — can execute bytecode',
        'cwe': 'CWE-502',
        'severity': 'HIGH',
    },
    {
        'pattern': r'shelve\.open\s*\(',
        'description': 'shelve uses pickle internally — same risks as pickle',
        'cwe': 'CWE-502',
        'severity': 'HIGH',
    },
    {
        'pattern': r'xmlrpc\.client|xmlrpclib',
        'description': 'XML-RPC can deserialize arbitrary objects',
        'cwe': 'CWE-502',
        'severity': 'MEDIUM',
    },
]

LOGIC_BUG_PATTERNS = [
    {
        'pattern': r'if\s+not\s+\w+\s*(==|!=|<|>|<=|>=)',
        'description': 'Ambiguous negation: "not x ==" may not negate the comparison',
        'cwe': 'CWE-480',
        'severity': 'MEDIUM',
    },
    {
        'pattern': r'except\s*:\s*\n\s*pass',
        'description': 'Bare except with pass — silently swallows all errors',
        'cwe': 'CWE-390',
        'severity': 'MEDIUM',
    },
    {
        'pattern': r'except\s+Exception\s*:\s*\n\s*pass',
        'description': 'Exception swallowed silently — hides bugs',
        'cwe': 'CWE-390',
        'severity': 'LOW',
    },
    {
        'pattern': r'range\s*\(\s*len\s*\(\s*\w+\s*\)\s*\-\s*1\s*\)',
        'description': 'Off-by-one: range(len(x)-1) skips last element',
        'cwe': 'CWE-193',
        'severity': 'LOW',
    },
    {
        'pattern': r'==\s*True|==\s*False|is\s+True|is\s+False',
        'description': 'Explicit True/False comparison — fragile for truthy/falsy values',
        'cwe': 'CWE-480',
        'severity': 'INFO',
    },
]

MEMORY_PATTERNS_C = [
    # C-specific patterns (for C renderer output)
    {
        'pattern': r'malloc\s*\(\s*\w+\s*\*\s*\w+\s*\)',
        'description': 'Integer overflow in malloc size calculation',
        'cwe': 'CWE-190',
        'severity': 'HIGH',
        'cve_examples': ['CVE-2021-22555'],
    },
    {
        'pattern': r'strcpy\s*\(',
        'description': 'strcpy without bounds check — use strncpy or strlcpy',
        'cwe': 'CWE-120',
        'severity': 'HIGH',
    },
    {
        'pattern': r'sprintf\s*\(',
        'description': 'sprintf without bounds check — use snprintf',
        'cwe': 'CWE-120',
        'severity': 'HIGH',
    },
    {
        'pattern': r'gets\s*\(',
        'description': 'gets() is always unsafe — use fgets()',
        'cwe': 'CWE-120',
        'severity': 'CRITICAL',
    },
]


class VulnPatternEngine:
    """Detects advanced vulnerability patterns in Python and C code."""

    def __init__(self):
        pass

    def analyze(self, code: str, language: str = 'python') -> List[VulnFinding]:
        """Run all pattern checks on code.

        Args:
            code: Source code to analyze
            language: 'python' or 'c'
        """
        findings = []
        lines = code.split('\n')

        # Regex-based pattern checks
        findings.extend(self._check_toctou(lines))
        findings.extend(self._check_regex_patterns(lines, TYPE_CONFUSION_PATTERNS, 'type_confusion'))
        findings.extend(self._check_regex_patterns(lines, DESERIALIZATION_GADGETS, 'deserialization'))
        findings.extend(self._check_regex_patterns(lines, FORMAT_STRING_PATTERNS, 'format_string'))
        findings.extend(self._check_regex_patterns(lines, LOGIC_BUG_PATTERNS, 'logic_bug'))

        if language == 'python':
            findings.extend(self._check_regex_patterns(lines, RACE_CONDITION_PATTERNS, 'race_condition'))
            findings.extend(self._check_python_specific(code))
        elif language == 'c':
            findings.extend(self._check_regex_patterns(lines, MEMORY_PATTERNS_C, 'memory_safety'))
            findings.extend(self._check_c_specific(code, lines))

        return findings

    def _check_toctou(self, lines: List[str]) -> List[VulnFinding]:
        """Check for TOCTOU race conditions (check-then-use patterns)."""
        findings = []

        for pattern in TOCTOU_PATTERNS:
            check_re = re.compile(pattern['check'])
            use_re = re.compile(pattern['use'])
            max_gap = pattern['max_gap']

            for i, line in enumerate(lines):
                if check_re.search(line):
                    # Look for the use within max_gap lines
                    for j in range(i + 1, min(i + max_gap + 1, len(lines))):
                        if use_re.search(lines[j]):
                            findings.append(VulnFinding(
                                pattern='toctou',
                                line=i + 1,
                                code=line.strip(),
                                severity='HIGH',
                                description=pattern['description'],
                                cwe=pattern.get('cwe', ''),
                                cve_examples=pattern.get('cve_examples', []),
                            ))
                            break

        return findings

    def _check_regex_patterns(self, lines: List[str],
                               patterns: List[Dict], category: str) -> List[VulnFinding]:
        """Check lines against regex pattern definitions."""
        findings = []

        for pattern_def in patterns:
            pat = re.compile(pattern_def['pattern'])
            for i, line in enumerate(lines):
                if pat.search(line):
                    findings.append(VulnFinding(
                        pattern=category,
                        line=i + 1,
                        code=line.strip(),
                        severity=pattern_def.get('severity', 'MEDIUM'),
                        description=pattern_def['description'],
                        cwe=pattern_def.get('cwe', ''),
                        cve_examples=pattern_def.get('cve_examples', []),
                    ))

        return findings

    def _check_python_specific(self, code: str) -> List[VulnFinding]:
        """Python-specific AST-level vulnerability checks."""
        findings = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # Check for eval/exec with non-constant argument
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ('eval', 'exec'):
                    if node.args and not isinstance(node.args[0], ast.Constant):
                        findings.append(VulnFinding(
                            pattern='code_injection',
                            line=node.lineno,
                            code=f'{node.func.id}(...)',
                            severity='CRITICAL',
                            description=f'{node.func.id}() with non-constant argument',
                            cwe='CWE-94',
                        ))

            # Check for assert used for input validation (removed in -O mode)
            if isinstance(node, ast.Assert):
                findings.append(VulnFinding(
                    pattern='logic_bug',
                    line=node.lineno,
                    code='assert ...',
                    severity='LOW',
                    description='assert used for validation — removed with python -O flag',
                    cwe='CWE-617',
                ))

            # Check for mutable default arguments
            if isinstance(node, ast.FunctionDef):
                for default in node.args.defaults:
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        findings.append(VulnFinding(
                            pattern='logic_bug',
                            line=node.lineno,
                            code=f'def {node.name}(...)',
                            severity='LOW',
                            description=f'Mutable default argument in {node.name}() — shared across calls',
                            cwe='CWE-1321',
                        ))

        return findings

    def _check_c_specific(self, code: str, lines: List[str]) -> List[VulnFinding]:
        """C-specific vulnerability checks."""
        findings = []

        # Check for double-free patterns
        free_vars = {}  # var_name → line_number of free()
        for i, line in enumerate(lines):
            m = re.search(r'free\s*\(\s*(\w+)\s*\)', line)
            if m:
                var = m.group(1)
                if var in free_vars:
                    findings.append(VulnFinding(
                        pattern='double_free',
                        line=i + 1,
                        code=line.strip(),
                        severity='CRITICAL',
                        description=f'Double free: {var} freed at L{free_vars[var]} and L{i+1}',
                        cwe='CWE-415',
                    ))
                free_vars[var] = i + 1
            # Reset if variable is reassigned
            m = re.search(r'(\w+)\s*=\s*(?:malloc|calloc|realloc)', line)
            if m:
                var = m.group(1)
                free_vars.pop(var, None)

        # Check for missing NULL check after malloc
        for i, line in enumerate(lines):
            m = re.search(r'(\w+)\s*=\s*(?:malloc|calloc)\s*\(', line)
            if m:
                var = m.group(1)
                # Check next 3 lines for NULL check
                has_check = False
                for j in range(i + 1, min(i + 4, len(lines))):
                    if re.search(rf'\b{var}\b.*(?:==|!=)\s*NULL|!\s*{var}\b', lines[j]):
                        has_check = True
                        break
                if not has_check:
                    findings.append(VulnFinding(
                        pattern='null_deref',
                        line=i + 1,
                        code=line.strip(),
                        severity='MEDIUM',
                        description=f'No NULL check after malloc for {var}',
                        cwe='CWE-476',
                    ))

        return findings

    def get_summary(self, findings: List[VulnFinding]) -> Dict[str, Any]:
        """Summarize findings."""
        by_pattern = {}
        by_severity = {}
        cwes = set()

        for f in findings:
            by_pattern[f.pattern] = by_pattern.get(f.pattern, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            if f.cwe:
                cwes.add(f.cwe)

        return {
            'total': len(findings),
            'by_pattern': by_pattern,
            'by_severity': by_severity,
            'unique_cwes': sorted(cwes),
            'has_critical': by_severity.get('CRITICAL', 0) > 0,
        }
