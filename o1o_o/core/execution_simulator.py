"""Execution Simulator: Predict failures before running code.

Formal constraint propagation specific to FORGE's sandbox.
Not a generic simulator — focused on "will this code run in THIS sandbox?"

Converts sandbox constraints + code analysis into binary predictions:
  PASS: code will execute successfully
  FAIL: code will fail (with specific reason and fix suggestion)
  UNKNOWN: cannot determine (code uses dynamic features)

Part of FORGE Phase 4: Predictive Failure Avoidance.
"""
# Dependencies: sandbox_model
# Depended by: autonomous_loop, fix_evaluator, fragment_generator

import ast
import re
from typing import Dict, List, Optional, Set, Tuple

from o1o_o.core.sandbox_model import SANDBOX_CONSTRAINTS, SANDBOX_FILES


# ─── Known third-party modules (not in stdlib) ─────────────────────────

THIRD_PARTY_MODULES = {
    # Data science
    'numpy', 'pandas', 'scipy', 'sklearn', 'matplotlib', 'seaborn',
    'tensorflow', 'torch', 'keras', 'xgboost', 'lightgbm',
    # Web / HTTP
    'requests', 'flask', 'django', 'fastapi', 'aiohttp', 'httpx',
    'bottle', 'tornado', 'starlette', 'uvicorn',
    # Database
    'psycopg2', 'pymongo', 'sqlalchemy', 'redis', 'pymysql',
    # Security
    'cryptography', 'pycryptodome', 'paramiko', 'scapy', 'pwntools',
    'nmap', 'impacket', 'ldap3',
    # Image / PDF
    'PIL', 'pillow', 'cv2', 'fitz', 'pymupdf', 'reportlab',
    # Other
    'yaml', 'pyyaml', 'toml', 'beautifulsoup4', 'bs4', 'lxml',
    'celery', 'boto3', 'docker', 'kubernetes',
    'pytest', 'colorama', 'tqdm', 'rich', 'click', 'typer',
    'websocket', 'pika', 'kafka', 'grpc',
}

# Modules that are stdlib despite sounding third-party
STDLIB_MODULES = {
    'os', 'sys', 'json', 'csv', 're', 'math', 'random', 'collections',
    'itertools', 'functools', 'operator', 'string', 'textwrap',
    'datetime', 'time', 'calendar', 'hashlib', 'hmac', 'secrets',
    'base64', 'binascii', 'struct', 'codecs',
    'pathlib', 'glob', 'shutil', 'tempfile', 'io', 'gzip', 'zipfile',
    'tarfile', 'bz2', 'lzma',
    'socket', 'http', 'urllib', 'email', 'smtplib', 'ftplib',
    'sqlite3', 'dbm', 'shelve',
    'threading', 'multiprocessing', 'concurrent', 'queue', 'sched',
    'subprocess', 'signal', 'atexit',
    'logging', 'warnings', 'traceback', 'pdb', 'unittest',
    'argparse', 'configparser', 'getopt',
    'xml', 'html', 'plistlib',
    'pickle', 'copyreg', 'copy', 'pprint',
    'typing', 'abc', 'dataclasses', 'enum', 'contextlib',
    'statistics', 'decimal', 'fractions',
    'ast', 'dis', 'inspect', 'types',
    'ctypes', 'array', 'mmap',
    'uuid', 'platform', 'locale',
}


class SimulationResult:
    """Result of simulating code execution."""

    def __init__(self, prediction: str, confidence: float,
                 failures: List[Dict], fixes: List[str]):
        self.prediction = prediction  # PASS, FAIL, UNKNOWN
        self.confidence = confidence  # 0.0 - 1.0
        self.failures = failures      # [{check, message, line, severity}]
        self.fixes = fixes            # suggested fix strategy names

    @property
    def will_fail(self) -> bool:
        return self.prediction == 'FAIL'

    @property
    def is_certain(self) -> bool:
        return self.confidence >= 0.9

    def __repr__(self):
        return (f"SimulationResult({self.prediction}, "
                f"confidence={self.confidence:.0%}, "
                f"failures={len(self.failures)})")


class ExecutionSimulator:
    """Predicts whether code will execute in the FORGE sandbox."""

    def __init__(self):
        self.available_files = set(SANDBOX_FILES.keys())
        self.checks = [
            self._check_imports,
            self._check_argparse,
            self._check_network,
            self._check_gui,
            self._check_input,
            self._check_file_access,
            self._check_syntax,
            self._check_pip_install,
            self._check_system_paths,
            self._check_infinite_loops,
            self._check_missing_functions,
        ]

    def simulate(self, code: str) -> SimulationResult:
        """Run all constraint checks on code and predict outcome."""
        all_failures = []
        all_fixes = []

        for check in self.checks:
            failures, fixes = check(code)
            all_failures.extend(failures)
            all_fixes.extend(fixes)

        # Determine prediction
        hard_failures = [f for f in all_failures if f['severity'] == 'hard']
        moderate_failures = [f for f in all_failures if f['severity'] == 'moderate']

        if hard_failures:
            # Hard failures = certain to fail
            confidence = min(0.95, 0.7 + 0.05 * len(hard_failures))
            return SimulationResult('FAIL', confidence, all_failures, all_fixes)
        elif moderate_failures:
            # Moderate = likely to fail
            confidence = min(0.85, 0.5 + 0.1 * len(moderate_failures))
            return SimulationResult('FAIL', confidence, all_failures, all_fixes)
        elif all_failures:
            # Only soft/warning failures
            return SimulationResult('UNKNOWN', 0.5, all_failures, all_fixes)
        else:
            return SimulationResult('PASS', 0.85, [], [])

    def _check_imports(self, code: str) -> Tuple[List[Dict], List[str]]:
        """Check for third-party imports that won't be available."""
        failures = []
        fixes = []

        # AST-based import extraction
        imports = set()
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])
        except SyntaxError:
            # Fallback: regex
            for m in re.finditer(r'^(?:from|import)\s+([\w.]+)', code, re.MULTILINE):
                imports.add(m.group(1).split('.')[0])

        for module in imports:
            if module in THIRD_PARTY_MODULES:
                failures.append({
                    'check': 'import',
                    'message': f"Third-party module '{module}' not available in sandbox",
                    'severity': 'hard',
                    'module': module,
                })
                fixes.append('fix_stdlib_alternative')
            elif module not in STDLIB_MODULES and module not in ('__future__',):
                # Unknown module — might be third-party
                failures.append({
                    'check': 'import',
                    'message': f"Unknown module '{module}' — may not be available",
                    'severity': 'moderate',
                    'module': module,
                })

        return failures, fixes

    def _check_argparse(self, code: str) -> Tuple[List[Dict], List[str]]:
        """Check for argparse/sys.argv usage."""
        failures = []
        fixes = []

        if 'argparse' in code or 'parse_args' in code:
            failures.append({
                'check': 'argparse',
                'message': "argparse will fail — sandbox provides no CLI arguments",
                'severity': 'hard',
            })
            fixes.append('fix_argparse_to_defaults')

        if 'sys.argv[' in code and 'sys.argv[0]' not in code:
            failures.append({
                'check': 'sys_argv',
                'message': "sys.argv access will fail — only sys.argv[0] exists",
                'severity': 'hard',
            })
            fixes.append('fix_argparse_to_defaults')

        return failures, fixes

    def _check_network(self, code: str) -> Tuple[List[Dict], List[str]]:
        """Check for network access attempts."""
        failures = []
        fixes = []

        network_patterns = [
            (r'requests\.(get|post|put|delete|patch|head)\(', 'requests HTTP call'),
            (r'urllib\.request\.urlopen\(', 'urllib HTTP call'),
            (r'socket\.socket\(.*\).*\.connect\(', 'socket connection'),
            (r'http\.client\.HTTPConnection', 'HTTP connection'),
            (r'smtplib\.SMTP\(', 'SMTP connection'),
            (r'ftplib\.FTP\(', 'FTP connection'),
        ]

        for pattern, desc in network_patterns:
            if re.search(pattern, code, re.DOTALL):
                failures.append({
                    'check': 'network',
                    'message': f"Network access ({desc}) will fail in sandbox",
                    'severity': 'hard',
                })
                fixes.append('fix_mock_network')
                break

        return failures, fixes

    def _check_gui(self, code: str) -> Tuple[List[Dict], List[str]]:
        """Check for GUI/display operations."""
        failures = []
        fixes = []

        gui_patterns = [
            'tkinter', 'pygame', 'PyQt', 'PySide', 'wx.',
            'plt.show()', 'matplotlib.pyplot.show',
        ]

        for pattern in gui_patterns:
            if pattern in code:
                failures.append({
                    'check': 'gui',
                    'message': f"GUI operation '{pattern}' will fail in headless sandbox",
                    'severity': 'hard',
                })
                break

        return failures, fixes

    def _check_input(self, code: str) -> Tuple[List[Dict], List[str]]:
        """Check for interactive input."""
        failures = []
        fixes = []

        if re.search(r'\binput\s*\(', code):
            failures.append({
                'check': 'input',
                'message': "input() will block forever — sandbox has no stdin",
                'severity': 'hard',
            })
            fixes.append('fix_hardcode_input')

        return failures, fixes

    def _check_file_access(self, code: str) -> Tuple[List[Dict], List[str]]:
        """Check for file accesses that reference non-existent files."""
        failures = []
        fixes = []

        # Find file open patterns
        file_patterns = [
            r"open\(['\"]([^'\"]+)['\"]",
            r"Path\(['\"]([^'\"]+)['\"]",
            r"os\.path\.exists\(['\"]([^'\"]+)['\"]",
        ]

        for pattern in file_patterns:
            for m in re.finditer(pattern, code):
                filepath = m.group(1)
                # Skip template vars
                if '{' in filepath:
                    continue
                # Skip absolute paths
                if filepath.startswith('/') or filepath.startswith('C:'):
                    continue
                # Skip dynamic paths
                if filepath.startswith('f"') or filepath.startswith("f'"):
                    continue
                # Check if file exists in sandbox
                if filepath not in self.available_files:
                    # Check if code creates the file first
                    if f"open('{filepath}', 'w')" in code or f'open("{filepath}", "w")' in code:
                        continue
                    failures.append({
                        'check': 'file_access',
                        'message': f"File '{filepath}' not in sandbox fixtures",
                        'severity': 'moderate',
                        'filepath': filepath,
                    })
                    fixes.append('fix_create_inline_data')

        return failures, fixes

    def _check_syntax(self, code: str) -> Tuple[List[Dict], List[str]]:
        """Check for syntax errors."""
        failures = []
        fixes = []

        try:
            ast.parse(code)
        except SyntaxError as e:
            failures.append({
                'check': 'syntax',
                'message': f"SyntaxError: {e.msg} (line {e.lineno})",
                'severity': 'hard',
                'line': e.lineno,
            })

        return failures, fixes

    def _check_pip_install(self, code: str) -> Tuple[List[Dict], List[str]]:
        """Check for pip install commands in code."""
        failures = []
        fixes = []

        if 'pip install' in code or 'pip3 install' in code:
            failures.append({
                'check': 'pip_install',
                'message': "pip install will fail in sandbox (no internet, no pip)",
                'severity': 'hard',
            })

        return failures, fixes

    def _check_system_paths(self, code: str) -> Tuple[List[Dict], List[str]]:
        """Check for hardcoded system paths."""
        failures = []
        fixes = []

        system_paths = [
            '/etc/', '/var/', '/opt/', '/root/',
            'C:\\Windows', 'C:\\Program Files',
        ]
        for path in system_paths:
            # Skip shebangs and comment lines
            if path in code and 'platform' not in code and not re.search(rf'^#.*{re.escape(path)}', code, re.MULTILINE):
                failures.append({
                    'check': 'system_path',
                    'message': f"Hardcoded system path '{path}' may not exist",
                    'severity': 'moderate',
                })
                break

        return failures, fixes

    def _check_infinite_loops(self, code: str) -> Tuple[List[Dict], List[str]]:
        """Check for potential infinite loops (will hit timeout)."""
        failures = []
        fixes = []

        # while True without break
        if 'while True:' in code:
            # Check if there's a break in the same block
            has_break = 'break' in code
            has_timeout = 'timeout' in code or 'time.sleep' in code
            if not has_break and not has_timeout:
                failures.append({
                    'check': 'infinite_loop',
                    'message': "'while True:' without break — will hit 10s timeout",
                    'severity': 'moderate',
                })

        return failures, fixes

    def _check_missing_functions(self, code: str) -> Tuple[List[Dict], List[str]]:
        """Check for function calls to undefined functions."""
        failures = []
        fixes = []

        try:
            tree = ast.parse(code)
        except SyntaxError:
            return failures, fixes

        # Collect defined names
        defined = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined.add(node.name)
            elif isinstance(node, ast.ClassDef):
                defined.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                defined.add(node.id)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    defined.add(alias.asname or alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    defined.add(alias.asname or alias.name)

        # Built-in names
        import builtins
        defined.update(dir(builtins))

        # Check calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id not in defined:
                    failures.append({
                        'check': 'undefined_function',
                        'message': f"Function '{node.func.id}' called but not defined",
                        'severity': 'moderate',
                    })
                    fixes.append('fix_fill_stubs')

        return failures, fixes

    def format_result(self, result: SimulationResult) -> str:
        """Format simulation result as readable string."""
        lines = []
        icon = {'PASS': '+', 'FAIL': 'X', 'UNKNOWN': '?'}[result.prediction]
        lines.append(f"[{icon}] Prediction: {result.prediction} "
                     f"(confidence: {result.confidence:.0%})")

        if result.failures:
            lines.append(f"  Failures ({len(result.failures)}):")
            for f in result.failures:
                lines.append(f"    [{f['severity']}] {f['check']}: {f['message']}")

        if result.fixes:
            unique_fixes = list(dict.fromkeys(result.fixes))
            lines.append(f"  Suggested fixes: {', '.join(unique_fixes)}")

        return '\n'.join(lines)


if __name__ == '__main__':
    # Test with sample codes
    sim = ExecutionSimulator()

    # Code that should pass
    code_pass = '''
import json
data = {"name": "test", "value": 42}
print(json.dumps(data, indent=2))
'''
    r = sim.simulate(code_pass)
    print(sim.format_result(r))
    print()

    # Code that should fail
    code_fail = '''
import requests
import numpy as np
data = requests.get("http://api.example.com/data").json()
arr = np.array(data)
print(arr.mean())
'''
    r = sim.simulate(code_fail)
    print(sim.format_result(r))
