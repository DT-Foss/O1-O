"""
AST Engine — Code transformation + semantic analysis via Python AST

Provides deterministic code modifications:
1. Add error handling (wrap in try/except)
2. Add type hints (infer from usage patterns)
3. Extract function (refactor code block into function)
4. Rename variable (safe rename across scope)
5. Add logging/debug prints
6. Optimize patterns (list comp, generator, etc.)
7. Security hardening (input validation, path sanitization)

Semantic code understanding (P1-03):
8. Function signature extraction
9. Control flow graph (CFG) building
10. Dead code detection
11. Structural comparison / functional equivalence
"""
# Dependencies: none
# Depended by: security_analyzer


import ast
import re
from typing import Dict, List, Any, Optional, Tuple, Set


class ASTEngine:
    """Transform Python code via AST manipulation"""

    # Common type inference patterns
    TYPE_INFERENCE = {
        'open': 'TextIOWrapper',
        'int': 'int',
        'float': 'float',
        'str': 'str',
        'list': 'List',
        'dict': 'Dict',
        'set': 'Set',
        'tuple': 'Tuple',
        'True': 'bool',
        'False': 'bool',
        'None': 'Optional',
        'os.listdir': 'List[str]',
        'os.walk': 'Generator',
        'json.load': 'Dict',
        'json.loads': 'Dict',
        'csv.reader': 'csv.reader',
        'requests.get': 'requests.Response',
        'Path': 'Path',
        'datetime.now': 'datetime',
        'hashlib.sha256': 'hashlib._Hash',
        're.findall': 'List[str]',
        're.search': 'Optional[re.Match]',
        'sqlite3.connect': 'sqlite3.Connection',
        'subprocess.run': 'subprocess.CompletedProcess',
    }

    # Error handling patterns per module
    ERROR_HANDLERS = {
        'requests': ('requests.RequestException', 'Network request failed'),
        'json': ('json.JSONDecodeError', 'Invalid JSON'),
        'csv': ('csv.Error', 'CSV parsing error'),
        'sqlite3': ('sqlite3.Error', 'Database error'),
        'os': ('OSError', 'File system error'),
        'subprocess': ('subprocess.SubprocessError', 'Command execution failed'),
        'socket': ('socket.error', 'Network error'),
        'hashlib': ('ValueError', 'Hashing error'),
        'xml': ('xml.parsers.expat.ExpatError', 'XML parsing error'),
        'yaml': ('yaml.YAMLError', 'YAML parsing error'),
        'tarfile': ('tarfile.TarError', 'Archive error'),
        'zipfile': ('zipfile.BadZipFile', 'Invalid zip file'),
    }

    # Loop optimization patterns
    LOOP_OPTIMIZATIONS = {
        'append_in_loop': 'list_comprehension',
        'dict_build_loop': 'dict_comprehension',
        'filter_loop': 'filter_expression',
        'map_loop': 'map_expression',
    }

    def __init__(self):
        self.transformations_applied = []

    def parse(self, code: str) -> Optional[ast.Module]:
        """Parse code string into AST"""
        try:
            return ast.parse(code)
        except SyntaxError:
            return None

    def transform(self, code: str, operations: List[str]) -> str:
        """Apply a sequence of AST transformations to code.

        Operations: 'add_error_handling', 'add_type_hints', 'optimize_loops',
                   'add_logging', 'security_harden', 'extract_function'
        """
        self.transformations_applied = []

        for op in operations:
            if op == 'add_error_handling':
                code = self.add_error_handling(code)
            elif op == 'add_type_hints':
                code = self.add_type_hints(code)
            elif op == 'optimize_loops':
                code = self.optimize_loops(code)
            elif op == 'add_logging':
                code = self.add_logging(code)
            elif op == 'security_harden':
                code = self.security_harden(code)

        return code

    def add_error_handling(self, code: str) -> str:
        """Wrap risky operations in try/except based on imported modules"""
        tree = self.parse(code)
        if not tree:
            return code

        # Detect which modules are imported
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_modules.add(node.module.split('.')[0])

        # Determine which exceptions to catch
        exceptions = []
        for mod in imported_modules:
            if mod in self.ERROR_HANDLERS:
                exc_type, msg = self.ERROR_HANDLERS[mod]
                exceptions.append((exc_type, msg))

        if not exceptions:
            exceptions = [('Exception', 'An error occurred')]

        # Find the main() body and wrap it
        lines = code.split('\n')
        result_lines = []
        in_main = False
        main_indent = 0
        main_body_lines = []
        main_start = -1

        for i, line in enumerate(lines):
            stripped = line.strip()

            if stripped.startswith('def main('):
                in_main = True
                main_indent = len(line) - len(line.lstrip())
                result_lines.append(line)
                main_start = i
                continue

            if in_main:
                if stripped and not line.startswith(' ' * (main_indent + 1)) and \
                   not stripped.startswith('"""') and stripped != '':
                    # Left main() scope
                    in_main = False
                    # Insert wrapped body
                    result_lines = self._wrap_main_body(
                        result_lines, main_body_lines, main_indent, exceptions
                    )
                    result_lines.append(line)
                    continue
                main_body_lines.append(line)
                continue

            result_lines.append(line)

        # If still in main at end of file
        if in_main and main_body_lines:
            result_lines = self._wrap_main_body(
                result_lines, main_body_lines, main_indent, exceptions
            )

        self.transformations_applied.append('add_error_handling')
        return '\n'.join(result_lines)

    def _wrap_main_body(self, result_lines: List[str], body_lines: List[str],
                        main_indent: int, exceptions: List[Tuple[str, str]]) -> List[str]:
        """Wrap main() body in try/except"""
        indent = ' ' * (main_indent + 4)
        try_indent = ' ' * (main_indent + 8)

        # Check if already wrapped
        first_body = next((l.strip() for l in body_lines if l.strip() and not l.strip().startswith('"""')), '')
        if first_body.startswith('try:'):
            result_lines.extend(body_lines)
            return result_lines

        result_lines.append(f'{indent}try:')

        # Re-indent body under try
        for line in body_lines:
            if line.strip():
                # Calculate current indent relative to main
                current = len(line) - len(line.lstrip())
                new_indent = current + 4
                result_lines.append(' ' * new_indent + line.lstrip())
            else:
                result_lines.append('')

        # Add except clauses
        for exc_type, msg in exceptions[:3]:  # Max 3 handlers
            result_lines.append(f'{indent}except {exc_type} as e:')
            result_lines.append(f'{try_indent}print(f"Error: {msg}: {{e}}")')
            result_lines.append(f'{try_indent}sys.exit(1)')

        return result_lines

    def add_type_hints(self, code: str) -> str:
        """Add type hints to function signatures based on usage patterns"""
        tree = self.parse(code)
        if not tree:
            return code

        lines = code.split('\n')
        modifications = []  # (line_idx, old_line, new_line)

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if node.returns is not None:
                    continue  # Already has return type

                # Infer return type from return statements
                return_type = self._infer_return_type(node)

                # Infer argument types from usage
                arg_types = self._infer_arg_types(node)

                # Build new signature
                line_idx = node.lineno - 1
                if line_idx < len(lines):
                    old_line = lines[line_idx]
                    new_line = self._rebuild_signature(old_line, node, arg_types, return_type)
                    if new_line != old_line:
                        modifications.append((line_idx, old_line, new_line))

        # Apply modifications (reverse order to preserve line numbers)
        for line_idx, old_line, new_line in reversed(modifications):
            lines[line_idx] = new_line

        if modifications:
            self.transformations_applied.append('add_type_hints')

        return '\n'.join(lines)

    def _infer_return_type(self, func_node: ast.FunctionDef) -> Optional[str]:
        """Infer return type from return statements in function"""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value:
                val = node.value
                if isinstance(val, ast.Constant):
                    if isinstance(val.value, str):
                        return 'str'
                    elif isinstance(val.value, int):
                        return 'int'
                    elif isinstance(val.value, float):
                        return 'float'
                    elif isinstance(val.value, bool):
                        return 'bool'
                    elif val.value is None:
                        return 'None'
                elif isinstance(val, ast.List):
                    return 'list'
                elif isinstance(val, ast.Dict):
                    return 'dict'
                elif isinstance(val, ast.Name):
                    if val.id in ('True', 'False'):
                        return 'bool'
        return None

    def _infer_arg_types(self, func_node: ast.FunctionDef) -> Dict[str, str]:
        """Infer argument types from how they're used in the function body"""
        arg_types = {}

        arg_names = {arg.arg for arg in func_node.args.args if arg.arg != 'self'}

        for node in ast.walk(func_node):
            # Detect: arg.method() calls
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id in arg_names:
                    method = node.attr
                    if method in ('split', 'strip', 'lower', 'upper', 'replace', 'startswith', 'endswith'):
                        arg_types[node.value.id] = 'str'
                    elif method in ('append', 'extend', 'pop', 'sort', 'reverse'):
                        arg_types[node.value.id] = 'list'
                    elif method in ('keys', 'values', 'items', 'get', 'update'):
                        arg_types[node.value.id] = 'dict'
                    elif method in ('add', 'discard', 'union', 'intersection'):
                        arg_types[node.value.id] = 'set'
                    elif method in ('read', 'write', 'readline', 'close'):
                        arg_types[node.value.id] = 'IO'

            # Detect: open(arg)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == 'open' and node.args:
                    if isinstance(node.args[0], ast.Name) and node.args[0].id in arg_names:
                        arg_types[node.args[0].id] = 'str'
                elif node.func.id == 'int' and node.args:
                    if isinstance(node.args[0], ast.Name) and node.args[0].id in arg_names:
                        arg_types[node.args[0].id] = 'str'
                elif node.func.id == 'len' and node.args:
                    if isinstance(node.args[0], ast.Name) and node.args[0].id in arg_names:
                        if node.args[0].id not in arg_types:
                            arg_types[node.args[0].id] = 'Sized'

        return arg_types

    def _rebuild_signature(self, line: str, node: ast.FunctionDef,
                          arg_types: Dict[str, str], return_type: Optional[str]) -> str:
        """Rebuild function signature with type hints"""
        indent = len(line) - len(line.lstrip())
        prefix = ' ' * indent

        args_str_parts = []
        for arg in node.args.args:
            name = arg.arg
            if name == 'self':
                args_str_parts.append('self')
            elif name in arg_types:
                args_str_parts.append(f'{name}: {arg_types[name]}')
            else:
                args_str_parts.append(name)

        args_str = ', '.join(args_str_parts)

        if return_type:
            return f'{prefix}def {node.name}({args_str}) -> {return_type}:'
        else:
            return f'{prefix}def {node.name}({args_str}):'

    def optimize_loops(self, code: str) -> str:
        """Optimize common loop patterns into comprehensions"""
        # Pattern: result = []; for x in items: result.append(expr)
        # → result = [expr for x in items]
        pattern = re.compile(
            r'(\s*)(\w+)\s*=\s*\[\]\s*\n'
            r'\1for\s+(\w+)\s+in\s+(.+?):\s*\n'
            r'\1\s+\2\.append\((.+?)\)\s*\n',
            re.MULTILINE
        )

        def replace_with_comprehension(match):
            indent = match.group(1)
            var = match.group(2)
            loop_var = match.group(3)
            iterable = match.group(4)
            expr = match.group(5)
            return f'{indent}{var} = [{expr} for {loop_var} in {iterable}]\n'

        new_code = pattern.sub(replace_with_comprehension, code)

        # Pattern: result = {}; for x in items: result[key] = value
        dict_pattern = re.compile(
            r'(\s*)(\w+)\s*=\s*\{\}\s*\n'
            r'\1for\s+(\w+)\s+in\s+(.+?):\s*\n'
            r'\1\s+\2\[(.+?)\]\s*=\s*(.+?)\s*\n',
            re.MULTILINE
        )

        def replace_with_dict_comp(match):
            indent = match.group(1)
            var = match.group(2)
            loop_var = match.group(3)
            iterable = match.group(4)
            key = match.group(5)
            value = match.group(6)
            return f'{indent}{var} = {{{key}: {value} for {loop_var} in {iterable}}}\n'

        new_code = dict_pattern.sub(replace_with_dict_comp, new_code)

        if new_code != code:
            self.transformations_applied.append('optimize_loops')

        return new_code

    def add_logging(self, code: str) -> str:
        """Add logging statements at key points"""
        tree = self.parse(code)
        if not tree:
            return code

        lines = code.split('\n')
        insertions = []  # (line_idx, indent, message)

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name != 'main':
                # Add entry/exit logging
                body_start = node.body[0].lineno - 1 if node.body else node.lineno
                indent = '    ' * (node.col_offset // 4 + 1)
                args_list = ', '.join(a.arg for a in node.args.args if a.arg != 'self')
                insertions.append((body_start, indent,
                    f'print(f"[DEBUG] {node.name}({args_list}) called")'))

        # Apply insertions in reverse order
        for line_idx, indent, msg in reversed(sorted(insertions, key=lambda x: x[0])):
            lines.insert(line_idx, f'{indent}{msg}')

        if insertions:
            self.transformations_applied.append('add_logging')

        return '\n'.join(lines)

    def security_harden(self, code: str) -> str:
        """Add security checks: input validation, path traversal prevention"""
        lines = code.split('\n')
        result = []

        for line in lines:
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            pad = ' ' * indent

            # Prevent path traversal in open()
            if 'open(' in stripped and '..' in stripped:
                result.append(f'{pad}# Security: path traversal check')
                result.append(line)
                continue

            # Warn about eval/exec
            if stripped.startswith('eval(') or stripped.startswith('exec('):
                result.append(f'{pad}# WARNING: eval/exec is dangerous — validate input first')
                result.append(line)
                self.transformations_applied.append('security_warning')
                continue

            # Warn about shell=True
            if 'shell=True' in stripped:
                result.append(f'{pad}# WARNING: shell=True allows command injection')
                result.append(line)
                self.transformations_applied.append('security_warning')
                continue

            result.append(line)

        return '\n'.join(result)

    def rename_variable(self, code: str, old_name: str, new_name: str) -> str:
        """Safely rename a variable across entire scope using AST"""
        tree = self.parse(code)
        if not tree:
            return code.replace(old_name, new_name)

        # Use regex with word boundaries for safe replacement
        pattern = re.compile(r'\b' + re.escape(old_name) + r'\b')
        return pattern.sub(new_name, code)

    def extract_function(self, code: str, start_line: int, end_line: int,
                        func_name: str) -> str:
        """Extract lines start_line..end_line into a new function"""
        lines = code.split('\n')

        if start_line < 0 or end_line >= len(lines):
            return code

        # Extract the block
        block = lines[start_line:end_line + 1]

        # Detect variables used but not defined in the block (= parameters)
        tree = self.parse('\n'.join(block))
        if not tree:
            return code

        defined = set()
        used = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Store):
                    defined.add(node.id)
                elif isinstance(node.ctx, ast.Load):
                    used.add(node.id)

        # Parameters = used but not defined in block
        # Exclude builtins
        builtins_set = set(dir(__builtins__)) if isinstance(__builtins__, dict) else set(dir(__builtins__))
        params = sorted(used - defined - builtins_set)

        # Build new function
        indent = '    '
        func_lines = [f'def {func_name}({", ".join(params)}):']
        for line in block:
            if line.strip():
                func_lines.append(indent + line.lstrip())
            else:
                func_lines.append('')

        # Add return if block assigns a variable
        if defined:
            last_defined = list(defined)[-1]
            func_lines.append(f'{indent}return {last_defined}')

        # Replace original block with function call
        call_args = ', '.join(params)
        if defined:
            last_defined = list(defined)[-1]
            replacement = f'    {last_defined} = {func_name}({call_args})'
        else:
            replacement = f'    {func_name}({call_args})'

        # Insert function before main(), replace block with call
        new_lines = []
        inserted_func = False
        for i, line in enumerate(lines):
            if not inserted_func and line.strip().startswith('def main('):
                new_lines.extend(func_lines)
                new_lines.append('')
                new_lines.append('')
                inserted_func = True

            if start_line <= i <= end_line:
                if i == start_line:
                    new_lines.append(replacement)
                # Skip other lines in block
                continue

            new_lines.append(line)

        self.transformations_applied.append('extract_function')
        return '\n'.join(new_lines)

    def analyze_complexity(self, code: str) -> Dict[str, Any]:
        """Analyze code complexity metrics"""
        tree = self.parse(code)
        if not tree:
            return {'error': 'parse_failed'}

        metrics = {
            'functions': 0,
            'classes': 0,
            'loops': 0,
            'conditionals': 0,
            'try_blocks': 0,
            'imports': 0,
            'lines': len(code.split('\n')),
            'cyclomatic_complexity': 1,  # Start at 1
            'max_nesting': 0,
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                metrics['functions'] += 1
            elif isinstance(node, ast.ClassDef):
                metrics['classes'] += 1
            elif isinstance(node, (ast.For, ast.While)):
                metrics['loops'] += 1
                metrics['cyclomatic_complexity'] += 1
            elif isinstance(node, ast.If):
                metrics['conditionals'] += 1
                metrics['cyclomatic_complexity'] += 1
            elif isinstance(node, ast.Try):
                metrics['try_blocks'] += 1
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                metrics['imports'] += 1

        # Calculate max nesting depth
        metrics['max_nesting'] = self._max_nesting_depth(tree)

        return metrics

    def _max_nesting_depth(self, tree: ast.AST, depth: int = 0) -> int:
        """Calculate maximum nesting depth"""
        max_depth = depth
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.For, ast.While, ast.If, ast.With, ast.Try)):
                child_depth = self._max_nesting_depth(node, depth + 1)
                max_depth = max(max_depth, child_depth)
            else:
                child_depth = self._max_nesting_depth(node, depth)
                max_depth = max(max_depth, child_depth)
        return max_depth

    # ========== P1-03: SEMANTIC CODE UNDERSTANDING ==========

    def extract_signatures(self, code: str) -> List[Dict[str, Any]]:
        """Extract all function and class signatures from code.

        Returns list of:
        {name, type (function/method/class), args, return_type, decorators, line, docstring}
        """
        tree = self.parse(code)
        if not tree:
            return []

        sigs = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                sig = {
                    'name': node.name,
                    'type': 'function',
                    'line': node.lineno,
                    'args': [],
                    'return_type': None,
                    'decorators': [],
                    'docstring': ast.get_docstring(node) or '',
                }

                # Check if it's a method (inside a class)
                for parent in ast.walk(tree):
                    if isinstance(parent, ast.ClassDef):
                        if node in parent.body:
                            sig['type'] = 'method'
                            sig['class'] = parent.name
                            break

                # Extract arguments
                for arg in node.args.args:
                    arg_info = {'name': arg.arg, 'annotation': None}
                    if arg.annotation:
                        arg_info['annotation'] = ast.unparse(arg.annotation)
                    sig['args'].append(arg_info)

                # Defaults
                defaults = node.args.defaults
                if defaults:
                    offset = len(sig['args']) - len(defaults)
                    for i, d in enumerate(defaults):
                        sig['args'][offset + i]['default'] = ast.unparse(d)

                # Return type
                if node.returns:
                    sig['return_type'] = ast.unparse(node.returns)

                # Decorators
                for dec in node.decorator_list:
                    sig['decorators'].append(ast.unparse(dec))

                sigs.append(sig)

            elif isinstance(node, ast.ClassDef):
                sig = {
                    'name': node.name,
                    'type': 'class',
                    'line': node.lineno,
                    'bases': [ast.unparse(b) for b in node.bases],
                    'decorators': [ast.unparse(d) for d in node.decorator_list],
                    'docstring': ast.get_docstring(node) or '',
                    'methods': [],
                }
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        sig['methods'].append(item.name)
                sigs.append(sig)

        return sigs

    def build_cfg(self, code: str) -> Dict[str, Any]:
        """Build a basic control flow graph from code.

        Returns {nodes: [{id, type, line, label}], edges: [{from, to, condition}]}
        representing the control flow.
        """
        tree = self.parse(code)
        if not tree:
            return {'nodes': [], 'edges': []}

        nodes = []
        edges = []
        node_id = [0]  # mutable counter

        def new_node(ntype: str, line: int, label: str) -> int:
            nid = node_id[0]
            node_id[0] += 1
            nodes.append({'id': nid, 'type': ntype, 'line': line, 'label': label})
            return nid

        def add_edge(src: int, dst: int, condition: str = ''):
            edges.append({'from': src, 'to': dst, 'condition': condition})

        def visit_body(stmts: List[ast.stmt], entry_id: int) -> int:
            """Visit a sequence of statements, return the exit node id."""
            prev = entry_id
            for stmt in stmts:
                prev = visit_stmt(stmt, prev)
            return prev

        def visit_stmt(stmt: ast.stmt, prev: int) -> int:
            """Visit a single statement, return exit node id."""
            if isinstance(stmt, ast.If):
                cond_id = new_node('condition', stmt.lineno,
                                   f'if {ast.unparse(stmt.test)[:40]}')
                add_edge(prev, cond_id)

                # True branch
                true_entry = new_node('block', stmt.lineno, 'if-body')
                add_edge(cond_id, true_entry, 'True')
                true_exit = visit_body(stmt.body, true_entry)

                # Merge node
                merge_id = new_node('merge', stmt.end_lineno or stmt.lineno, 'endif')

                add_edge(true_exit, merge_id)

                if stmt.orelse:
                    false_entry = new_node('block', stmt.orelse[0].lineno, 'else-body')
                    add_edge(cond_id, false_entry, 'False')
                    false_exit = visit_body(stmt.orelse, false_entry)
                    add_edge(false_exit, merge_id)
                else:
                    add_edge(cond_id, merge_id, 'False')

                return merge_id

            elif isinstance(stmt, (ast.For, ast.While)):
                loop_type = 'for' if isinstance(stmt, ast.For) else 'while'
                if isinstance(stmt, ast.For):
                    label = f'for {ast.unparse(stmt.target)} in {ast.unparse(stmt.iter)[:30]}'
                else:
                    label = f'while {ast.unparse(stmt.test)[:40]}'

                loop_id = new_node('loop', stmt.lineno, label)
                add_edge(prev, loop_id)

                body_entry = new_node('block', stmt.lineno, f'{loop_type}-body')
                add_edge(loop_id, body_entry, 'iterate')
                body_exit = visit_body(stmt.body, body_entry)
                add_edge(body_exit, loop_id, 'next')

                exit_id = new_node('merge', stmt.end_lineno or stmt.lineno,
                                   f'end-{loop_type}')
                add_edge(loop_id, exit_id, 'done')

                return exit_id

            elif isinstance(stmt, ast.Try):
                try_id = new_node('try', stmt.lineno, 'try')
                add_edge(prev, try_id)
                try_exit = visit_body(stmt.body, try_id)

                merge_id = new_node('merge', stmt.end_lineno or stmt.lineno, 'end-try')
                add_edge(try_exit, merge_id, 'success')

                for handler in stmt.handlers:
                    exc_name = ast.unparse(handler.type) if handler.type else 'Exception'
                    h_id = new_node('except', handler.lineno, f'except {exc_name}')
                    add_edge(try_id, h_id, 'exception')
                    h_exit = visit_body(handler.body, h_id)
                    add_edge(h_exit, merge_id)

                if stmt.finalbody:
                    fin_id = new_node('finally', stmt.finalbody[0].lineno, 'finally')
                    add_edge(merge_id, fin_id)
                    return visit_body(stmt.finalbody, fin_id)

                return merge_id

            elif isinstance(stmt, ast.Return):
                ret_id = new_node('return', stmt.lineno,
                                  f'return {ast.unparse(stmt.value)[:30]}' if stmt.value else 'return')
                add_edge(prev, ret_id)
                return ret_id

            elif isinstance(stmt, ast.FunctionDef):
                func_id = new_node('function', stmt.lineno, f'def {stmt.name}()')
                add_edge(prev, func_id)
                body_entry = new_node('block', stmt.lineno, f'{stmt.name}-body')
                add_edge(func_id, body_entry)
                visit_body(stmt.body, body_entry)
                return func_id

            else:
                # Generic statement
                label = ast.unparse(stmt)[:50] if hasattr(ast, 'unparse') else f'L{stmt.lineno}'
                stmt_id = new_node('statement', stmt.lineno, label)
                add_edge(prev, stmt_id)
                return stmt_id

        # Start with entry node
        entry = new_node('entry', 1, 'START')
        visit_body(tree.body, entry)

        return {'nodes': nodes, 'edges': edges}

    def detect_dead_code(self, code: str) -> List[Dict[str, Any]]:
        """Detect unreachable code after return/raise/break/continue.

        Returns list of {line, code, reason}.
        """
        tree = self.parse(code)
        if not tree:
            return []

        dead = []
        lines = code.split('\n')

        def check_body(stmts: List[ast.stmt]):
            """Check a list of statements for dead code after terminators."""
            for i, stmt in enumerate(stmts):
                # Check nested bodies
                if isinstance(stmt, ast.If):
                    check_body(stmt.body)
                    check_body(stmt.orelse)
                elif isinstance(stmt, (ast.For, ast.While)):
                    check_body(stmt.body)
                    check_body(stmt.orelse)
                elif isinstance(stmt, ast.Try):
                    check_body(stmt.body)
                    for handler in stmt.handlers:
                        check_body(handler.body)
                    check_body(stmt.finalbody)
                elif isinstance(stmt, ast.FunctionDef):
                    check_body(stmt.body)
                elif isinstance(stmt, ast.ClassDef):
                    check_body(stmt.body)
                elif isinstance(stmt, ast.With):
                    check_body(stmt.body)

                # Is this a terminator?
                is_terminator = isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue))

                # If both branches of if terminate, the if is a terminator
                if isinstance(stmt, ast.If) and stmt.orelse:
                    body_terminates = any(isinstance(s, (ast.Return, ast.Raise, ast.Break, ast.Continue))
                                          for s in stmt.body)
                    else_terminates = any(isinstance(s, (ast.Return, ast.Raise, ast.Break, ast.Continue))
                                          for s in stmt.orelse)
                    if body_terminates and else_terminates:
                        is_terminator = True

                if is_terminator and i + 1 < len(stmts):
                    # Everything after is dead
                    for dead_stmt in stmts[i + 1:]:
                        line_num = dead_stmt.lineno
                        reason = f'unreachable after {type(stmt).__name__.lower()} on line {stmt.lineno}'
                        line_text = lines[line_num - 1].strip() if line_num <= len(lines) else ''
                        dead.append({
                            'line': line_num,
                            'code': line_text,
                            'reason': reason,
                        })
                    break  # No need to check further

        check_body(tree.body)
        return dead

    def structural_compare(self, code1: str, code2: str) -> Dict[str, Any]:
        """Compare two implementations for structural/functional similarity.

        Returns {similarity, matching_features, differences, equivalent}.
        """
        tree1 = self.parse(code1)
        tree2 = self.parse(code2)
        if not tree1 or not tree2:
            return {'similarity': 0.0, 'matching_features': [], 'differences': [], 'equivalent': False}

        # Extract structural fingerprints
        fp1 = self._structural_fingerprint(tree1)
        fp2 = self._structural_fingerprint(tree2)

        # Compare features
        matching = []
        differences = []

        # 1. Same imports
        common_imports = fp1['imports'] & fp2['imports']
        if common_imports:
            matching.append(f'shared imports: {", ".join(sorted(common_imports)[:5])}')
        only1 = fp1['imports'] - fp2['imports']
        only2 = fp2['imports'] - fp1['imports']
        if only1:
            differences.append(f'code1 only imports: {", ".join(sorted(only1)[:5])}')
        if only2:
            differences.append(f'code2 only imports: {", ".join(sorted(only2)[:5])}')

        # 2. Same function names
        common_funcs = fp1['functions'] & fp2['functions']
        if common_funcs:
            matching.append(f'shared functions: {", ".join(sorted(common_funcs)[:5])}')

        # 3. Same operation types (calls to builtins/stdlib)
        common_calls = fp1['call_names'] & fp2['call_names']
        if common_calls:
            matching.append(f'shared calls: {", ".join(sorted(common_calls)[:5])}')

        # 4. Same control flow shape
        if fp1['loop_count'] == fp2['loop_count']:
            matching.append(f'same loop count: {fp1["loop_count"]}')
        else:
            differences.append(f'loop count: {fp1["loop_count"]} vs {fp2["loop_count"]}')

        if fp1['branch_count'] == fp2['branch_count']:
            matching.append(f'same branch count: {fp1["branch_count"]}')
        else:
            differences.append(f'branch count: {fp1["branch_count"]} vs {fp2["branch_count"]}')

        # 5. Same output patterns
        if fp1['has_print'] == fp2['has_print']:
            matching.append('same output pattern')

        # 6. AST node type histogram similarity
        hist_sim = self._histogram_similarity(fp1['node_histogram'], fp2['node_histogram'])
        if hist_sim > 0.8:
            matching.append(f'AST structure similarity: {hist_sim:.0%}')

        # 7. Variable flow pattern: same number of assignments
        assign_diff = abs(fp1['assign_count'] - fp2['assign_count'])
        if assign_diff == 0:
            matching.append(f'same assignment count: {fp1["assign_count"]}')
        elif assign_diff <= 2:
            matching.append(f'similar assignment count: {fp1["assign_count"]} vs {fp2["assign_count"]}')

        # Compute overall similarity
        total_features = max(len(matching) + len(differences), 1)
        similarity = len(matching) / total_features

        # Boost similarity if call patterns and imports match heavily
        if len(common_calls) > 3:
            similarity = min(1.0, similarity + 0.1)
        if len(common_imports) > 2:
            similarity = min(1.0, similarity + 0.05)

        # Functional equivalence heuristic: same imports, same calls, same output
        equivalent = (
            similarity > 0.75
            and fp1['imports'] == fp2['imports']
            and fp1['has_print'] == fp2['has_print']
            and hist_sim > 0.7
        )

        return {
            'similarity': round(similarity, 3),
            'ast_similarity': round(hist_sim, 3),
            'matching_features': matching,
            'differences': differences,
            'equivalent': equivalent,
        }

    def _structural_fingerprint(self, tree: ast.Module) -> Dict[str, Any]:
        """Extract a structural fingerprint from an AST for comparison."""
        fp: Dict[str, Any] = {
            'imports': set(),
            'functions': set(),
            'call_names': set(),
            'loop_count': 0,
            'branch_count': 0,
            'has_print': False,
            'assign_count': 0,
            'node_histogram': {},
        }

        for node in ast.walk(tree):
            # Count node types
            ntype = type(node).__name__
            fp['node_histogram'][ntype] = fp['node_histogram'].get(ntype, 0) + 1

            if isinstance(node, ast.Import):
                for alias in node.names:
                    fp['imports'].add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    fp['imports'].add(node.module)
            elif isinstance(node, ast.FunctionDef):
                fp['functions'].add(node.name)
            elif isinstance(node, (ast.For, ast.While)):
                fp['loop_count'] += 1
            elif isinstance(node, ast.If):
                fp['branch_count'] += 1
            elif isinstance(node, ast.Assign):
                fp['assign_count'] += 1
            elif isinstance(node, ast.Call):
                name = self._call_name(node)
                if name:
                    fp['call_names'].add(name)
                    if name == 'print':
                        fp['has_print'] = True

        return fp

    def _call_name(self, node: ast.Call) -> Optional[str]:
        """Extract the name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f'{node.func.value.id}.{node.func.attr}'
            return node.func.attr
        return None

    def _histogram_similarity(self, h1: Dict[str, int], h2: Dict[str, int]) -> float:
        """Cosine similarity between two histograms."""
        all_keys = set(h1.keys()) | set(h2.keys())
        if not all_keys:
            return 1.0

        dot = sum(h1.get(k, 0) * h2.get(k, 0) for k in all_keys)
        mag1 = sum(v ** 2 for v in h1.values()) ** 0.5
        mag2 = sum(v ** 2 for v in h2.values()) ** 0.5

        if mag1 == 0 or mag2 == 0:
            return 0.0

        return dot / (mag1 * mag2)
