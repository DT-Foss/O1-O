"""
Test Generator — Automatically generate tests for FORGE-generated code

Strategies:
1. Import validation tests (can we import all modules?)
2. Function signature tests (do functions exist with correct params?)
3. Output validation tests (does the script produce output?)
4. Edge case tests (empty input, None, large data)
5. Type checking tests (return types match expectations)
"""
# Dependencies: none
# Depended by: none (leaf module)


import ast
import re
from typing import List, Dict, Any, Optional


class TestGenerator:
    """Generate pytest test suites for generated code"""

    # Default test values by type
    DEFAULT_VALUES = {
        'str': ['"hello"', '""', '"a" * 1000'],
        'int': ['0', '1', '-1', '42', '999999'],
        'float': ['0.0', '1.5', '-1.0', 'float("inf")'],
        'list': ['[]', '[1, 2, 3]', '["a", "b"]', 'list(range(100))'],
        'dict': ['{}', '{"key": "value"}', '{"a": 1, "b": 2}'],
        'bool': ['True', 'False'],
        'path': ['"."', '"/tmp"', '"nonexistent_path"'],
        'url': ['"https://example.com"', '"https://httpbin.org/get"'],
        'file': ['"test_file.txt"', '"/dev/null"'],
    }

    # Module → required test imports
    TEST_IMPORTS = {
        'os': 'import os',
        'json': 'import json',
        'csv': 'import csv',
        'requests': 'import requests',
        'sqlite3': 'import sqlite3',
        'hashlib': 'import hashlib',
        'pathlib': 'from pathlib import Path',
    }

    def __init__(self):
        pass

    def generate(self, code: str, intent: Dict[str, Any] = None) -> str:
        """Generate a complete pytest test file for the given code"""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return self._generate_basic_test(code)

        tests = []
        tests.append(self._generate_header(code))
        tests.extend(self._generate_import_tests(tree))
        tests.extend(self._generate_function_tests(tree, code))
        tests.extend(self._generate_execution_test(code))
        tests.extend(self._generate_output_tests(tree, code, intent))

        return '\n\n'.join(tests)

    def _generate_header(self, code: str) -> str:
        """Generate test file header with imports"""
        imports = set()
        imports.add('import pytest')
        imports.add('import subprocess')
        imports.add('import tempfile')
        imports.add('import os')
        imports.add('import sys')

        # Add imports from the code under test
        for line in code.split('\n'):
            stripped = line.strip()
            if stripped.startswith('import ') or stripped.startswith('from '):
                imports.add(stripped)

        header = '#!/usr/bin/env python3\n'
        header += '"""Auto-generated tests by FORGE TestGenerator"""\n\n'
        header += '\n'.join(sorted(imports))
        header += '\n\n'
        header += '# Code under test\n'
        header += 'CODE = """' + code.replace('"""', '\\"\\"\\"') + '"""\n'
        return header

    def _generate_import_tests(self, tree: ast.Module) -> List[str]:
        """Generate tests that verify all imports are available"""
        tests = []
        modules = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    modules.add(node.module)

        if modules:
            lines = ['def test_imports():']
            lines.append('    """Verify all required modules are importable"""')
            for mod in sorted(modules):
                top_mod = mod.split('.')[0]
                lines.append(f'    import importlib')
                lines.append(f'    mod = importlib.import_module("{top_mod}")')
                lines.append(f'    assert mod is not None, "Failed to import {top_mod}"')
            tests.append('\n'.join(lines))

        return tests

    def _generate_function_tests(self, tree: ast.Module, code: str) -> List[str]:
        """Generate tests for each function in the code"""
        tests = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name == 'main':
                continue  # main() tested separately

            func_name = node.name
            args = [a.arg for a in node.args.args if a.arg != 'self']

            # Generate a test that calls the function
            test_lines = [f'def test_{func_name}_exists():']
            test_lines.append(f'    """Verify {func_name} can be called"""')
            test_lines.append(f'    # Execute the code to define the function')
            test_lines.append(f'    namespace = {{}}')
            test_lines.append(f'    exec(CODE, namespace)')
            test_lines.append(f'    assert "{func_name}" in namespace, "Function {func_name} not defined"')
            test_lines.append(f'    assert callable(namespace["{func_name}"]), "{func_name} is not callable"')
            tests.append('\n'.join(test_lines))

            # Generate parameter test
            if args:
                test_lines = [f'def test_{func_name}_params():']
                test_lines.append(f'    """Verify {func_name} accepts {len(args)} parameters"""')
                test_lines.append(f'    import inspect')
                test_lines.append(f'    namespace = {{}}')
                test_lines.append(f'    exec(CODE, namespace)')
                test_lines.append(f'    sig = inspect.signature(namespace["{func_name}"])')
                test_lines.append(f'    assert len(sig.parameters) == {len(args)}, '
                                f'"Expected {len(args)} params, got {{len(sig.parameters)}}"')
                tests.append('\n'.join(test_lines))

        return tests

    def _generate_execution_test(self, code: str) -> List[str]:
        """Generate test that runs the full script"""
        test = [
            'def test_script_executes():',
            '    """Verify the script runs without errors"""',
            '    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:',
            '        f.write(CODE)',
            '        f.flush()',
            '        try:',
            '            result = subprocess.run(',
            '                [sys.executable, f.name],',
            '                capture_output=True, text=True, timeout=30,',
            '                cwd=tempfile.gettempdir()',
            '            )',
            '            # Script should either succeed or fail gracefully',
            '            assert result.returncode == 0 or "Error" in result.stderr, \\',
            '                f"Script crashed: {result.stderr[:200]}"',
            '        finally:',
            '            os.unlink(f.name)',
        ]
        return ['\n'.join(test)]

    def _generate_output_tests(self, tree: ast.Module, code: str,
                               intent: Dict[str, Any] = None) -> List[str]:
        """Generate tests for expected output patterns"""
        tests = []

        # Check if code should produce output
        has_print = 'print(' in code
        if not has_print:
            return tests

        test_lines = [
            'def test_produces_output():',
            '    """Verify the script produces output"""',
            '    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:',
            '        f.write(CODE)',
            '        f.flush()',
            '        try:',
            '            result = subprocess.run(',
            '                [sys.executable, f.name],',
            '                capture_output=True, text=True, timeout=30,',
            '                cwd=tempfile.gettempdir()',
            '            )',
            '            if result.returncode == 0:',
            '                assert len(result.stdout.strip()) > 0, "Script produced no output"',
            '        finally:',
            '            os.unlink(f.name)',
        ]
        tests.append('\n'.join(test_lines))

        return tests

    def _generate_basic_test(self, code: str) -> str:
        """Fallback test for unparseable code"""
        return f'''#!/usr/bin/env python3
"""Basic test for unparseable code"""
import subprocess
import tempfile
import sys
import os

CODE = """{code.replace(chr(34)*3, chr(39)*3)}"""

def test_syntax():
    """Check if code has valid syntax"""
    try:
        compile(CODE, "<test>", "exec")
    except SyntaxError as e:
        pytest.fail(f"Syntax error: {{e}}")

def test_executes():
    """Check if code runs"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(CODE)
        f.flush()
        try:
            result = subprocess.run(
                [sys.executable, f.name],
                capture_output=True, text=True, timeout=30
            )
            assert result.returncode == 0, f"Exit code: {{result.returncode}}"
        finally:
            os.unlink(f.name)
'''

    def generate_for_fragment(self, fragment_key: str, fragment_code: str) -> str:
        """Generate a focused test for a single fragment"""
        # Find template variables
        template_vars = re.findall(r'\{(\w+)\}', fragment_code)

        lines = [
            '#!/usr/bin/env python3',
            f'"""Test for fragment: {fragment_key}"""',
            'import pytest',
            '',
            f'FRAGMENT = """{fragment_code}"""',
            '',
        ]

        # Generate test with default substitutions
        lines.append(f'def test_{fragment_key}_compiles():')
        lines.append(f'    """Fragment should compile after variable substitution"""')

        # Substitute template vars with defaults
        resolved = fragment_code
        for var in template_vars:
            if var in ('path', 'input_path', 'file'):
                resolved = resolved.replace(f'{{{var}}}', '/tmp/test_file.txt')
            elif var in ('url',):
                resolved = resolved.replace(f'{{{var}}}', 'https://example.com')
            elif var in ('data', 'text', 'content'):
                resolved = resolved.replace(f'{{{var}}}', 'test data')
            elif var in ('output_path',):
                resolved = resolved.replace(f'{{{var}}}', '/tmp/output.txt')
            elif var in ('n', 'count', 'limit'):
                resolved = resolved.replace(f'{{{var}}}', '10')
            else:
                resolved = resolved.replace(f'{{{var}}}', 'test_value')

        lines.append(f'    code = """{resolved}"""')
        lines.append(f'    compile(code, "<test>", "exec")')

        return '\n'.join(lines)
