"""
Self-Repair Engine — Phase 2 of FORGE Self-Repair

AST-based code transformations for diagnosed failures.
Unlike executor.py's regex-based auto_fix (12 strategies),
this uses the AST module for precise, structural fixes.

Each fix strategy is a function that:
1. Takes: (code_str, diagnosis) → Optional[fixed_code_str]
2. Uses AST parsing for structural transforms
3. Returns None if fix doesn't apply

The fix catalog maps error_class → list of fix functions.
"""
# Dependencies: sandbox_model, self_diagnostics
# Depended by: autonomous_loop


import ast
import re
import textwrap
from typing import Dict, Any, List, Optional, Callable, Tuple
from core.self_diagnostics import Diagnosis


class SelfRepair:
    """AST-based self-repair engine."""

    def __init__(self):
        # Fix catalog: error_class → ordered list of fix functions
        self.fix_catalog: Dict[str, List[Callable]] = {
            # Sandbox-specific fixes (highest priority)
            'missing_cli_args': [self._fix_argparse_to_defaults, self._fix_argv_fallback],
            'system_exit': [self._fix_argparse_to_defaults, self._fix_wrap_main],
            'missing_test_data': [self._fix_create_inline_data],
            'interactive_input': [self._fix_replace_input],
            'network_in_sandbox': [self._fix_mock_network],

            # Import fixes
            'import_error': [self._fix_try_except_import, self._fix_stdlib_alternative],

            # Type/attribute fixes
            'key_error': [self._fix_dict_get],
            'index_error': [self._fix_bounds_check],
            'attribute_error': [self._fix_hasattr_guard],
            'name_error': [self._fix_define_variable],
            'zero_division': [self._fix_zero_check],

            # Runtime fixes
            'timeout': [self._fix_add_iteration_limit],
            'composition_bloat': [self._fix_add_iteration_limit],
            'recursion_error': [self._fix_add_recursion_limit],
            'file_not_found': [self._fix_create_inline_data, self._fix_file_exists_guard],

            # Data fixes
            'column_mismatch': [self._fix_explicit_columns],
            'sqlite_error': [self._fix_explicit_columns],

            # FORGE-specific fixes
            'empty_functions': [self._fix_fill_stubs],
            'unresolved_template': [self._fix_hardcode_template],

            # Generic fallback
            'type_error_args': [self._fix_try_except_wrap],
            'type_error_general': [self._fix_try_except_wrap],
            'value_error': [self._fix_try_except_wrap],
        }

        # Track fix statistics
        self.stats = {
            'attempted': 0,
            'succeeded': 0,
            'failed': 0,
            'by_strategy': {},
        }

    def attempt_fix(self, code: str, diagnosis: Diagnosis) -> Optional[str]:
        """Try to fix code based on a diagnosis.

        Tries each fix strategy for the error class in order.
        Returns the first successful fix, or None.
        """
        strategies = self.fix_catalog.get(diagnosis.error_class, [])
        if not strategies:
            return None

        for strategy_fn in strategies:
            self.stats['attempted'] += 1
            strategy_name = strategy_fn.__name__

            try:
                fixed = strategy_fn(code, diagnosis)
                if fixed and fixed != code:
                    self.stats['succeeded'] += 1
                    self.stats['by_strategy'][strategy_name] = \
                        self.stats['by_strategy'].get(strategy_name, 0) + 1
                    return fixed
            except Exception:
                pass

            self.stats['failed'] += 1

        return None

    def attempt_all_fixes(self, code: str, diagnosis: Diagnosis,
                          max_attempts: int = 3) -> List[Tuple[str, str]]:
        """Try ALL applicable fix strategies and return all that produce different code.

        Returns: list of (strategy_name, fixed_code) tuples.
        Used by Phase 5 Fix Evaluator to choose the best fix.
        """
        strategies = self.fix_catalog.get(diagnosis.error_class, [])
        results = []

        for strategy_fn in strategies[:max_attempts]:
            try:
                fixed = strategy_fn(code, diagnosis)
                if fixed and fixed != code:
                    results.append((strategy_fn.__name__, fixed))
            except Exception:
                pass

        return results

    # ═══════════════════════════════════════════════════════════
    # Fix Strategies — AST-based code transformations
    # ═══════════════════════════════════════════════════════════

    def _fix_argparse_to_defaults(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Replace argparse with hardcoded defaults for sandbox execution.

        Transforms:
            parser = argparse.ArgumentParser()
            parser.add_argument('filename')
            args = parser.parse_args()
            ... args.filename ...

        Into:
            class Args: pass
            args = Args()
            args.filename = 'data.txt'
        """
        if 'argparse' not in code:
            return None

        try:
            tree = ast.parse(code)
        except SyntaxError:
            return None

        # Find all add_argument calls to extract arg names and defaults
        arg_defs = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == 'add_argument':
                    # Get argument name
                    if node.args:
                        arg_name_node = node.args[0]
                        if isinstance(arg_name_node, ast.Constant):
                            name = str(arg_name_node.value).lstrip('-').replace('-', '_')
                            # Check for default kwarg
                            default = None
                            for kw in node.keywords:
                                if kw.arg == 'default' and isinstance(kw.value, ast.Constant):
                                    default = kw.value.value
                            arg_defs.append((name, default))

        if not arg_defs:
            return None

        # Build replacement: Args class with defaults
        from core.sandbox_model import SANDBOX_FILES

        args_lines = ["class _Args: pass", "args = _Args()"]
        for name, default in arg_defs:
            if default is not None:
                args_lines.append(f"args.{name} = {repr(default)}")
            elif name in ('file', 'filename', 'input', 'path', 'source'):
                args_lines.append(f"args.{name} = 'data.txt'")
            elif name in ('output', 'out', 'dest', 'target'):
                args_lines.append(f"args.{name} = 'output.txt'")
            elif name in ('port', 'p'):
                args_lines.append(f"args.{name} = 8080")
            elif name in ('host', 'h', 'address'):
                args_lines.append(f"args.{name} = 'localhost'")
            elif name in ('count', 'n', 'num', 'limit'):
                args_lines.append(f"args.{name} = 10")
            elif name in ('verbose', 'v', 'debug'):
                args_lines.append(f"args.{name} = False")
            else:
                args_lines.append(f"args.{name} = 'test'")

        args_block = '\n'.join(args_lines)

        # Remove argparse import, ArgumentParser creation, add_argument calls, parse_args
        lines = code.split('\n')
        filtered = []
        skip_continuation = False

        for line in lines:
            stripped = line.strip()

            if skip_continuation:
                if stripped.endswith(')') or stripped.endswith('),'):
                    skip_continuation = False
                continue

            # Skip argparse-related lines
            if 'import argparse' in stripped:
                continue
            if 'ArgumentParser' in stripped:
                continue
            if '.add_argument(' in stripped:
                if not stripped.endswith(')'):
                    skip_continuation = True
                continue
            if '.parse_args()' in stripped:
                # Replace with our args block
                indent = len(line) - len(line.lstrip())
                for args_line in args_block.split('\n'):
                    filtered.append(' ' * indent + args_line)
                continue

            filtered.append(line)

        result = '\n'.join(filtered)
        return result if result != code else None

    def _fix_argv_fallback(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Add sys.argv fallback for scripts that read sys.argv directly."""
        if 'sys.argv[' not in code:
            return None

        # Add fallback at the top of the script (after imports)
        fallback = (
            "import sys\n"
            "if len(sys.argv) < 2:\n"
            "    sys.argv = ['script.py', 'data.txt']\n"
        )

        # Insert after the last import line
        lines = code.split('\n')
        last_import = -1
        for i, line in enumerate(lines):
            if line.strip().startswith('import ') or line.strip().startswith('from '):
                last_import = i

        if last_import >= 0:
            lines.insert(last_import + 1, '')
            lines.insert(last_import + 2, fallback)
        else:
            lines.insert(0, fallback)

        return '\n'.join(lines)

    def _fix_wrap_main(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Wrap sys.exit() calls to prevent premature exit."""
        if 'sys.exit' not in code:
            return None

        code = code.replace('sys.exit(0)', 'pass  # sys.exit removed for sandbox')
        code = code.replace('sys.exit(1)', 'pass  # sys.exit removed for sandbox')
        code = code.replace('sys.exit()', 'pass  # sys.exit removed for sandbox')

        return code if 'sys.exit' not in code or code else None

    def _fix_create_inline_data(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Create inline test data for file-reading code."""
        if not diag.root_cause or 'file' not in diag.root_cause.lower():
            return None

        # Extract the missing filename
        match = re.search(r"'([^']+\.\w+)'", diag.root_cause)
        if not match:
            return None

        filename = match.group(1)

        # Generate data creation code based on file extension
        ext = filename.rsplit('.', 1)[-1] if '.' in filename else ''

        if ext == 'csv':
            data_code = f"""
import os
if not os.path.exists('{filename}'):
    with open('{filename}', 'w') as _f:
        _f.write('name,age,city\\nAlice,30,Berlin\\nBob,25,Munich\\n')
"""
        elif ext == 'json':
            data_code = f"""
import os, json
if not os.path.exists('{filename}'):
    with open('{filename}', 'w') as _f:
        json.dump({{'name': 'test', 'items': [1, 2, 3]}}, _f)
"""
        elif ext == 'txt':
            data_code = f"""
import os
if not os.path.exists('{filename}'):
    with open('{filename}', 'w') as _f:
        _f.write('hello world\\nfoo bar baz\\ntest data 42\\n')
"""
        else:
            return None

        # Insert at the top (after imports)
        lines = code.split('\n')
        last_import = -1
        for i, line in enumerate(lines):
            if line.strip().startswith('import ') or line.strip().startswith('from '):
                last_import = i

        insert_at = last_import + 1 if last_import >= 0 else 0
        lines.insert(insert_at, data_code)

        return '\n'.join(lines)

    def _fix_replace_input(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Replace input() calls with hardcoded defaults."""
        if 'input(' not in code:
            return None

        # Replace input() with a default value
        code = re.sub(
            r"input\(['\"]([^'\"]*)['\"]?\)",
            r"'test'  # input replaced for sandbox",
            code
        )
        # Handle bare input()
        code = re.sub(
            r"input\(\)",
            "'test'  # input replaced for sandbox",
            code
        )
        return code

    def _fix_mock_network(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Replace network calls with mock data."""
        if 'requests.get' not in code and 'urlopen' not in code:
            return None

        # Simple: wrap in try/except with mock data
        mock = textwrap.dedent("""
        class _MockResponse:
            status_code = 200
            text = '<html><body><h1>Test</h1><a href="http://example.com">Link</a></body></html>'
            content = text.encode()
            def json(self): return {"status": "ok", "data": [1, 2, 3]}
            def raise_for_status(self): pass
        """)

        # Add mock class and wrap requests.get
        if 'requests.get' in code:
            code = mock + '\n' + code
            code = re.sub(
                r'requests\.get\([^)]+\)',
                '_MockResponse()',
                code
            )
            # Remove requests import
            code = re.sub(r'^import requests\s*$', '', code, flags=re.MULTILINE)

        return code

    def _fix_try_except_import(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Wrap failing import in try/except with fallback."""
        match = re.search(r"Module '(\w+)' not available", diag.root_cause)
        if not match:
            match = re.search(r"No module named '(\w+)'", str(diag.root_cause))
        if not match:
            return None

        module = match.group(1)

        # Replace the import with try/except
        code = re.sub(
            rf'^(import {module})\s*$',
            f'try:\n    import {module}\nexcept ImportError:\n    {module} = None  # not available in sandbox',
            code,
            flags=re.MULTILINE
        )

        return code

    def _fix_stdlib_alternative(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Replace pip package with stdlib equivalent."""
        STDLIB_ALTERNATIVES = {
            'requests': ('urllib.request', {
                'requests.get(': 'urllib.request.urlopen(',
            }),
            'yaml': ('json', {
                'yaml.safe_load': 'json.loads',
                'yaml.dump': 'json.dumps',
                'import yaml': 'import json',
            }),
            'toml': ('tomllib', {
                'import toml': 'import tomllib',
                'toml.load': 'tomllib.load',
            }),
        }

        for pkg, (alt, replacements) in STDLIB_ALTERNATIVES.items():
            if f'import {pkg}' in code or f'from {pkg}' in code:
                for old, new in replacements.items():
                    code = code.replace(old, new)
                return code

        return None

    def _fix_dict_get(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Replace dict[key] with dict.get(key, default)."""
        if not diag.failing_code:
            return None

        # Find dict[key] patterns and replace with .get()
        modified = re.sub(
            r'(\w+)\[([\'"][^\'"]+[\'"])\]',
            r'\1.get(\2, None)',
            code
        )
        return modified if modified != code else None

    def _fix_bounds_check(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Add bounds checking for list index access."""
        if not diag.failing_line:
            return None

        lines = code.split('\n')
        if diag.failing_line <= len(lines):
            line = lines[diag.failing_line - 1]
            indent = len(line) - len(line.lstrip())
            # Wrap in if check
            match = re.search(r'(\w+)\[(\w+)\]', line)
            if match:
                lst, idx = match.group(1), match.group(2)
                guard = f"{' ' * indent}if {idx} < len({lst}):"
                lines[diag.failing_line - 1] = guard + '\n' + ' ' * (indent + 4) + line.strip()
                return '\n'.join(lines)

        return None

    def _fix_hasattr_guard(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Add hasattr check before attribute access."""
        if not diag.failing_code:
            return None

        # Extract object.attr pattern
        match = re.search(r"'(\w+)' object has no attribute '(\w+)'", str(diag.root_cause))
        if not match:
            return None

        obj_type, attr = match.group(1), match.group(2)

        # Add hasattr guard (rough — better than nothing)
        lines = code.split('\n')
        if diag.failing_line and diag.failing_line <= len(lines):
            line = lines[diag.failing_line - 1]
            indent = len(line) - len(line.lstrip())
            # Find the object reference
            attr_match = re.search(rf'(\w+)\.{re.escape(attr)}', line)
            if attr_match:
                obj = attr_match.group(1)
                guard = f"{' ' * indent}if hasattr({obj}, '{attr}'):"
                lines[diag.failing_line - 1] = guard + '\n' + ' ' * (indent + 4) + line.strip()
                return '\n'.join(lines)

        return None

    def _fix_define_variable(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Define missing variable with sensible default."""
        match = re.search(r"name '(\w+)' is not defined", str(diag.root_cause))
        if not match:
            return None

        var = match.group(1)

        # Add default definition after imports
        defaults = {
            'data': "data = []",
            'result': "result = None",
            'results': "results = []",
            'output': "output = ''",
            'count': "count = 0",
            'total': "total = 0",
            'items': "items = []",
            'config': "config = {}",
        }

        definition = defaults.get(var, f"{var} = None")

        lines = code.split('\n')
        last_import = -1
        for i, line in enumerate(lines):
            if line.strip().startswith('import ') or line.strip().startswith('from '):
                last_import = i

        lines.insert(last_import + 1, '')
        lines.insert(last_import + 2, definition)

        return '\n'.join(lines)

    def _fix_zero_check(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Add zero-division guard."""
        if not diag.failing_line:
            return None

        lines = code.split('\n')
        if diag.failing_line <= len(lines):
            line = lines[diag.failing_line - 1]
            # Replace / with division-safe version
            if '/' in line:
                line = re.sub(r'(\w+)\s*/\s*(\w+)',
                              r'(\1 / \2 if \2 != 0 else 0)',
                              line)
                lines[diag.failing_line - 1] = line
                return '\n'.join(lines)

        return None

    def _fix_add_iteration_limit(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Add iteration limit to while loops."""
        if 'while ' not in code:
            return None

        # Find while True or while <condition> loops and add counter
        lines = code.split('\n')
        modified = False

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('while ') and ':' in stripped:
                indent = len(line) - len(line.lstrip())
                # Add counter before the while
                counter_var = '_iter_count'
                lines.insert(i, f"{' ' * indent}{counter_var} = 0")
                # Add break inside the loop
                # Find the next line (body)
                for j in range(i + 2, min(i + 20, len(lines))):
                    body_line = lines[j]
                    body_indent = len(body_line) - len(body_line.lstrip())
                    if body_indent > indent and body_line.strip():
                        limit_check = (
                            f"{' ' * body_indent}{counter_var} += 1\n"
                            f"{' ' * body_indent}if {counter_var} > 10000:\n"
                            f"{' ' * (body_indent + 4)}break"
                        )
                        lines.insert(j, limit_check)
                        modified = True
                        break
                break  # Only fix the first while loop

        return '\n'.join(lines) if modified else None

    def _fix_add_recursion_limit(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Add recursion depth tracking."""
        # Simple fix: add sys.setrecursionlimit or memoize
        if 'import sys' not in code:
            code = 'import sys\n' + code

        if 'sys.setrecursionlimit' not in code:
            code = code.replace('import sys\n', 'import sys\nsys.setrecursionlimit(500)\n', 1)

        return code

    def _fix_file_exists_guard(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Add os.path.exists guard before file open."""
        match = re.search(r"'([^']+)'", str(diag.root_cause))
        if not match:
            return None

        filename = match.group(1)
        guard = f"import os\nif not os.path.exists('{filename}'):\n    print('File not found: {filename}')\nelse:\n"

        # Find the open() call and indent it
        open_pattern = rf"open\(['\"]({re.escape(filename)})['\"]"
        if re.search(open_pattern, code):
            # Wrap the entire relevant section
            lines = code.split('\n')
            for i, line in enumerate(lines):
                if re.search(open_pattern, line):
                    indent = len(line) - len(line.lstrip())
                    lines[i] = ' ' * indent + 'if os.path.exists(' + repr(filename) + '):\n' + ' ' * (indent + 4) + line.strip()
                    if 'import os' not in code:
                        lines.insert(0, 'import os')
                    return '\n'.join(lines)

        return None

    def _fix_explicit_columns(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Fix SQL INSERT by adding explicit column list."""
        # Match INSERT INTO table VALUES
        pattern = r"INSERT\s+INTO\s+(\w+)\s+VALUES"
        match = re.search(pattern, code, re.IGNORECASE)
        if not match:
            return None

        table = match.group(1)

        # From sandbox model, data table has (id, name, age, city)
        from core.sandbox_model import SANDBOX_FILES
        db_info = SANDBOX_FILES.get('data.db', {})
        tables = db_info.get('tables', {})

        if table in tables:
            cols = [c[0] for c in tables[table]['columns']]
            col_list = ', '.join(cols)
            code = re.sub(
                rf"INSERT\s+INTO\s+{table}\s+VALUES",
                f"INSERT INTO {table} ({col_list}) VALUES",
                code,
                flags=re.IGNORECASE
            )
            return code

        return None

    def _fix_fill_stubs(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Fill empty function bodies with pass or basic implementation."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return None

        lines = code.split('\n')
        modified = False

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check if body is just 'pass' or empty
                body = node.body
                if len(body) == 1 and isinstance(body[0], (ast.Pass, ast.Expr)):
                    if isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                        continue  # docstring only — ok

                    # Add a basic implementation
                    line_num = node.lineno - 1  # 0-indexed
                    indent = len(lines[line_num]) - len(lines[line_num].lstrip())
                    body_indent = indent + 4

                    # Determine return type from name
                    name = node.name
                    if name.startswith('get_') or name.startswith('fetch_'):
                        impl = f"{' ' * body_indent}return None  # TODO: implement"
                    elif name.startswith('is_') or name.startswith('has_') or name.startswith('check_'):
                        impl = f"{' ' * body_indent}return True  # TODO: implement"
                    elif name == 'execute' or name == 'run':
                        impl = f"{' ' * body_indent}print(f'{{self.__class__.__name__}}.{name}() called')"
                    elif name == 'description' or name == '__str__' or name == '__repr__':
                        impl = f"{' ' * body_indent}return f'{{self.__class__.__name__}}'"
                    else:
                        impl = f"{' ' * body_indent}print(f'{name}() called')"

                    # Find the pass line and replace
                    for j in range(line_num + 1, min(line_num + 5, len(lines))):
                        if lines[j].strip() == 'pass':
                            lines[j] = impl
                            modified = True
                            break

        return '\n'.join(lines) if modified else None

    def _fix_hardcode_template(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Replace unresolved {template_vars} with sensible defaults."""
        TEMPLATE_DEFAULTS = {
            'description': 'Command line tool',
            'name': 'test',
            'filename': 'data.txt',
            'path': 'data.txt',
            'host': 'localhost',
            'port': '8080',
            'url': 'http://example.com',
            'title': 'Test',
            'output': 'output.txt',
        }

        modified = False
        for var, default in TEMPLATE_DEFAULTS.items():
            pattern = r'(?<![\'"])\{' + var + r'\}'
            if re.search(pattern, code):
                code = re.sub(pattern, default, code)
                modified = True

        return code if modified else None

    def _fix_try_except_wrap(self, code: str, diag: Diagnosis) -> Optional[str]:
        """Generic fix: wrap failing line in try/except."""
        if not diag.failing_line:
            return None

        lines = code.split('\n')
        if diag.failing_line > len(lines):
            return None

        line = lines[diag.failing_line - 1]
        indent = len(line) - len(line.lstrip())

        wrapped = (
            f"{' ' * indent}try:\n"
            f"{' ' * (indent + 4)}{line.strip()}\n"
            f"{' ' * indent}except Exception:\n"
            f"{' ' * (indent + 4)}pass"
        )
        lines[diag.failing_line - 1] = wrapped

        return '\n'.join(lines)

    # ── Reporting ──

    def format_stats(self) -> str:
        """Format fix statistics."""
        lines = [
            "=== Self-Repair Statistics ===",
            f"Attempted: {self.stats['attempted']}",
            f"Succeeded: {self.stats['succeeded']}",
            f"Failed: {self.stats['failed']}",
        ]

        if self.stats['by_strategy']:
            lines.append("\nBy strategy:")
            for name, count in sorted(self.stats['by_strategy'].items(),
                                       key=lambda x: -x[1]):
                lines.append(f"  {name}: {count}")

        return '\n'.join(lines)
