"""Payload Mutation Engine.

Takes working Python code and generates N functional variants that look
structurally different to static analysis. All variants preserve behavior.

Mutation operators:
1. Variable renaming (random identifiers)
2. Dead code injection (NOPs that don't affect execution)
3. String obfuscation (chr() construction, base64, split)
4. Control flow transformation (if-True wrapping, dispatch tables)
5. Function splitting (extract blocks into helper functions)
6. Comment/whitespace variation

Part of FORGE Phase O: Evasion Intelligence.
"""
# Dependencies: none
# Depended by: detection_test, mission_package

import ast
import random
import string
import hashlib
import copy
import re
import textwrap
from typing import Any, Dict, List, Optional, Set, Tuple


# ─── Random Name Generator ──────────────────────────────────────────

def _random_name(prefix: str = '', length: int = 8) -> str:
    """Generate a random variable name."""
    chars = string.ascii_lowercase
    name = ''.join(random.choice(chars) for _ in range(length))
    return f'{prefix}{name}' if prefix else name


def _random_names(count: int, prefix: str = '') -> List[str]:
    """Generate unique random names."""
    names = set()
    while len(names) < count:
        names.add(_random_name(prefix))
    return list(names)


# ─── Mutation Operators ──────────────────────────────────────────────

class VariableRenamer:
    """Rename all user-defined variables to random identifiers."""

    # Names we must never rename
    PROTECTED = {
        # Language keywords
        'self', 'cls', 'True', 'False', 'None',
        'import', 'from', 'as', 'if', 'else', 'elif', 'for', 'while',
        'return', 'yield', 'break', 'continue', 'pass', 'raise', 'try',
        'except', 'finally', 'with', 'class', 'def', 'lambda', 'and',
        'or', 'not', 'in', 'is', 'del', 'global', 'nonlocal', 'assert',
        'async', 'await',
        # Builtins — types
        'int', 'str', 'float', 'bool', 'list', 'dict', 'set', 'tuple',
        'bytes', 'bytearray', 'memoryview', 'complex', 'frozenset',
        'object', 'type', 'property', 'staticmethod', 'classmethod', 'super',
        # Builtins — functions
        'print', 'len', 'range', 'open', 'input', 'repr', 'id',
        'isinstance', 'issubclass', 'hasattr', 'getattr', 'setattr', 'delattr',
        'chr', 'ord', 'hex', 'bin', 'oct', 'abs', 'round', 'pow', 'divmod',
        'max', 'min', 'sum', 'any', 'all', 'sorted', 'reversed',
        'map', 'filter', 'zip', 'enumerate', 'iter', 'next', 'callable',
        'hash', 'dir', 'vars', 'globals', 'locals', 'exec', 'eval', 'compile',
        'format', 'ascii', 'breakpoint',
        # Builtins — exceptions
        'Exception', 'BaseException', 'ValueError', 'TypeError', 'KeyError',
        'IndexError', 'AttributeError', 'NameError', 'FileNotFoundError',
        'OSError', 'IOError', 'RuntimeError', 'ImportError', 'ModuleNotFoundError',
        'StopIteration', 'GeneratorExit', 'SystemExit', 'KeyboardInterrupt',
        'PermissionError', 'TimeoutError', 'ConnectionError', 'BrokenPipeError',
        'NotImplementedError', 'ArithmeticError', 'OverflowError', 'ZeroDivisionError',
        # Standard library modules
        'os', 'sys', 'json', 'struct', 'socket', 'subprocess', 'signal',
        'ctypes', 'hashlib', 'base64', 'time', 'threading', 're', 'math',
        'random', 'string', 'io', 'tempfile', 'shutil', 'pathlib', 'logging',
        'urllib', 'http', 'ssl', 'email', 'html', 'xml', 'csv', 'sqlite3',
        'collections', 'itertools', 'functools', 'operator', 'contextlib',
        'abc', 'copy', 'pprint', 'textwrap', 'codecs', 'binascii',
        'argparse', 'configparser', 'platform', 'traceback', 'warnings',
        'multiprocessing', 'concurrent', 'asyncio', 'select', 'selectors',
        'queue', 'heapq', 'bisect', 'array', 'weakref', 'gc',
        'inspect', 'dis', 'ast', 'token', 'tokenize',
        'unittest', 'doctest', 'pytest',
        'requests', 'paramiko', 'scapy', 'cryptography', 'pycryptodome',
        # Dunder names
        '__name__', '__main__', '__init__', '__file__', '__doc__',
        '__all__', '__dict__', '__class__', '__module__', '__slots__',
        '__enter__', '__exit__', '__iter__', '__next__', '__call__',
        '__getitem__', '__setitem__', '__delitem__', '__len__', '__repr__',
        '__str__', '__eq__', '__hash__', '__lt__', '__gt__', '__le__', '__ge__',
        # Common methods (attribute access, not renamable anyway)
        'encode', 'decode', 'append', 'extend', 'join', 'split',
        'replace', 'strip', 'lstrip', 'rstrip', 'lower', 'upper',
        'startswith', 'endswith', 'find', 'rfind', 'index', 'count',
        'items', 'keys', 'values', 'get', 'update', 'pop', 'clear',
        'remove', 'insert', 'sort', 'reverse', 'copy', 'read', 'write',
        'close', 'flush', 'seek', 'tell', 'readline', 'readlines',
    }

    def __init__(self):
        self.mapping: Dict[str, str] = {}

    def mutate(self, code: str) -> str:
        """Rename variables in code."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return code

        # Collect DEFINED names only (not all references)
        defined_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                defined_names.add(node.name)
                for arg in node.args.args:
                    defined_names.add(arg.arg)
                for arg in node.args.posonlyargs:
                    defined_names.add(arg.arg)
                for arg in node.args.kwonlyargs:
                    defined_names.add(arg.arg)
                if node.args.vararg:
                    defined_names.add(node.args.vararg.arg)
                if node.args.kwarg:
                    defined_names.add(node.args.kwarg.arg)
            elif isinstance(node, ast.ClassDef):
                defined_names.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                defined_names.add(node.id)
            elif isinstance(node, ast.withitem) and isinstance(node.optional_vars, ast.Name):
                defined_names.add(node.optional_vars.id)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                defined_names.add(node.name)

        # Filter to renamable names (only names we DEFINE, minus protected)
        renamable = defined_names - self.PROTECTED
        # Don't rename module-level imports (including dotted components)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    actual = alias.asname or alias.name
                    renamable.discard(actual)
                    renamable.discard(alias.name)
                    for part in alias.name.split('.'):
                        renamable.discard(part)
                if isinstance(node, ast.ImportFrom) and node.module:
                    for part in node.module.split('.'):
                        renamable.discard(part)

        # Generate mapping
        for name in sorted(renamable):
            if name not in self.mapping and not name.startswith('__'):
                self.mapping[name] = _random_name()

        # Protect string literals from renaming (INCLUDING f/r/b/u prefixes)
        strings = []
        def _save_str(m):
            strings.append(m.group(0))
            return f'__FORGE_SR_{len(strings) - 1}__'

        result = code
        # Save triple-quoted strings first (with optional prefix), then single/double
        _STR_PREFIX = r'(?:[fFrRbBuU]{1,2})?'
        result = re.sub(_STR_PREFIX + r'"""[\s\S]*?"""|' + _STR_PREFIX + r"'''[\s\S]*?'''",
                        _save_str, result)
        result = re.sub(_STR_PREFIX + r'"[^"\\]*(?:\\.[^"\\]*)*"|' + _STR_PREFIX + r"'[^'\\]*(?:\\.[^'\\]*)*'",
                        _save_str, result)

        # Apply mapping via regex (word-boundary aware)
        for old, new in sorted(self.mapping.items(), key=lambda x: -len(x[0])):
            result = re.sub(r'\b' + re.escape(old) + r'\b', new, result)

        # Restore string literals
        for i, s in enumerate(strings):
            result = result.replace(f'__FORGE_SR_{i}__', s)

        # Post-fixup: rename variable references inside f-string {expr} blocks.
        # The save/restore cycle protected ALL string content from renaming,
        # but f-strings contain {var} expressions that must match renamed variables.
        for i, s in enumerate(strings):
            if not s or s[0] not in ('f', 'F'):
                # Also check rf/fr prefixes
                if len(s) < 2 or s[:2].lower() not in ('rf', 'fr'):
                    continue
            fixed = s
            for old, new in sorted(self.mapping.items(), key=lambda x: -len(x[0])):
                # Rename inside {...} interpolation blocks only
                def _fix_interp(m):
                    inner = m.group(1)
                    inner = re.sub(r'\b' + re.escape(old) + r'\b', new, inner)
                    return '{' + inner + '}'
                fixed = re.sub(r'\{([^}]+)\}', _fix_interp, fixed)
            if fixed != s:
                result = result.replace(s, fixed, 1)

        return result


class DeadCodeInjector:
    """Insert dead code that doesn't affect execution."""

    DEAD_STATEMENTS = [
        '_ = 0',
        '__ = None',
        '_noop = type(None)',
        '_temp = [] if False else []',
        'pass',
        '_x = 0; _x += 0',
        '_d = {}; _d.clear()',
    ]

    DEAD_FUNCTIONS = [
        'def _noop_{n}(): pass',
        'def _check_{n}(): return True',
    ]

    def mutate(self, code: str, density: float = 0.15) -> str:
        """Inject dead code into source."""
        lines = code.split('\n')
        result = []
        n = 0
        bracket_depth = 0
        in_triple_quote = False

        for line in lines:
            result.append(line)
            stripped = line.strip()

            # Track triple-quoted strings
            tq_count = stripped.count('"""') + stripped.count("'''")
            if tq_count % 2 == 1:
                in_triple_quote = not in_triple_quote
            if in_triple_quote or tq_count > 0:
                continue

            # Track bracket depth
            was_in_brackets = bracket_depth > 0
            for ch in stripped:
                if ch in '([{':
                    bracket_depth += 1
                elif ch in ')]}':
                    bracket_depth = max(0, bracket_depth - 1)

            # Skip empty lines, comments, decorators
            if not stripped or stripped.startswith('#') or stripped.startswith('@'):
                continue
            if stripped.startswith(('import ', 'from ')):
                continue
            # Skip if inside multi-line expression
            if bracket_depth > 0 or was_in_brackets:
                continue
            # Skip lines ending with continuation markers
            if stripped.endswith((',', '\\', ':', '(', '[', '{')):
                continue

            if random.random() < density:
                # Match indentation
                indent = len(line) - len(line.lstrip())
                indent_str = line[:indent] if indent > 0 else ''

                if random.random() < 0.7:
                    dead = random.choice(self.DEAD_STATEMENTS)
                    result.append(f'{indent_str}{dead}')
                else:
                    tmpl = random.choice(self.DEAD_FUNCTIONS)
                    dead = tmpl.format(n=_random_name(length=4))
                    result.append(f'{indent_str}{dead}')
                n += 1

        return '\n'.join(result)


class StringObfuscator:
    """Obfuscate string literals."""

    def mutate(self, code: str, probability: float = 0.6) -> str:
        """Replace string literals with obfuscated equivalents."""
        # Find string literals via regex (simple: single and double quoted)
        def _obfuscate(match):
            if random.random() > probability:
                return match.group(0)

            quote = match.group(0)[0]
            content = match.group(0)[1:-1]

            if len(content) < 2 or len(content) > 100:
                return match.group(0)

            # Don't obfuscate format strings, raw strings, byte strings
            # NOTE: read from _protected (post-triple-quote-save), not code,
            # because match positions are relative to the protected string
            prefix = ''
            if match.start() > 0:
                prefix = _protected[max(0, match.start()-1):match.start()]
            if prefix in ('f', 'r', 'b', 'F', 'R', 'B'):
                return match.group(0)

            method = random.randint(0, 2)
            if method == 0:
                # chr() construction
                chars = [f'chr({ord(c)})' for c in content]
                return f"''.join([{', '.join(chars)}])"
            elif method == 1:
                # Split and join
                mid = len(content) // 2
                return f"({quote}{content[:mid]}{quote}+{quote}{content[mid:]}{quote})"
            else:
                # Reverse
                return f"{quote}{content[::-1]}{quote}[::-1]"

        # First, protect triple-quoted strings from mutation
        # Replace them with placeholders, obfuscate other strings, then restore
        triple_quotes = []
        def _save_triple(m):
            triple_quotes.append(m.group(0))
            return f'__FORGE_TQ_{len(triple_quotes) - 1}__'

        _protected = re.sub(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'', _save_triple, code)

        # Match single and double quoted strings (triple-quotes already removed)
        result = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\"",
                        _obfuscate, _protected)

        # Restore triple-quoted strings
        for i, tq in enumerate(triple_quotes):
            result = result.replace(f'__FORGE_TQ_{i}__', tq)
        return result


class ControlFlowTransformer:
    """Transform control flow without changing behavior."""

    def mutate(self, code: str, density: float = 0.1) -> str:
        """Apply control flow transformations."""
        lines = code.split('\n')
        result = []
        bracket_depth = 0
        in_triple_quote = False

        for line in lines:
            stripped = line.strip()

            # Track triple-quoted strings
            tq_count = stripped.count('"""') + stripped.count("'''")
            if tq_count % 2 == 1:
                in_triple_quote = not in_triple_quote
            if in_triple_quote or tq_count > 0:
                result.append(line)
                continue

            # Track bracket depth
            was_in_brackets = bracket_depth > 0
            for ch in stripped:
                if ch in '([{':
                    bracket_depth += 1
                elif ch in ')]}':
                    bracket_depth = max(0, bracket_depth - 1)

            # Skip structural lines and block headers
            if not stripped or stripped.startswith(('#', 'import', 'from', 'def ', 'class ', '@')):
                result.append(line)
                continue
            if stripped.endswith(':'):
                result.append(line)
                continue
            # Skip lines inside or closing multi-line expressions
            if bracket_depth > 0 or was_in_brackets:
                result.append(line)
                continue
            # Skip continuation lines
            if stripped.endswith((',', '\\', '(', '[', '{')):
                result.append(line)
                continue

            if random.random() < density:
                indent = len(line) - len(line.lstrip())
                indent_str = line[:indent] if indent > 0 else ''

                method = random.randint(0, 2)
                if method == 0:
                    # if True: wrapper
                    result.append(f'{indent_str}if True:')
                    result.append(f'{indent_str}    {stripped}')
                elif method == 1:
                    # for _ in [0]: wrapper (executes once)
                    result.append(f'{indent_str}for _ in [0]:')
                    result.append(f'{indent_str}    {stripped}')
                else:
                    # (lambda: expr)() wrapper — only for pure expressions
                    _stmt_kw = ('return', 'pass', 'break', 'continue', 'raise',
                                'del', 'yield', 'assert', 'global', 'nonlocal')
                    if ('=' not in stripped
                            and not any(stripped.startswith(kw) for kw in _stmt_kw)
                            and stripped != 'pass'):
                        result.append(f'{indent_str}(lambda: {stripped})()')
                    else:
                        result.append(line)
            else:
                result.append(line)

        return '\n'.join(result)


class CommentMutator:
    """Mutate comments and whitespace."""

    FAKE_COMMENTS = [
        '# Initialize configuration',
        '# Process data buffer',
        '# Validate input parameters',
        '# Check boundary conditions',
        '# Handle edge cases',
        '# Perform cleanup',
        '# Update state',
        '# Apply transformation',
        '# Verify integrity',
        '# Synchronize state',
    ]

    def mutate(self, code: str) -> str:
        """Remove existing comments and optionally add fake ones."""
        lines = code.split('\n')
        result = []

        for line in lines:
            # Remove existing inline comments (but keep shebang and encoding)
            if line.strip().startswith('#!') or line.strip().startswith('# -*-'):
                result.append(line)
                continue

            if '#' in line:
                # Find # that's not inside a string
                in_str = False
                str_char = None
                comment_pos = -1
                for i, c in enumerate(line):
                    if c in ('"', "'") and not in_str:
                        in_str = True
                        str_char = c
                    elif c == str_char and in_str:
                        in_str = False
                    elif c == '#' and not in_str:
                        comment_pos = i
                        break
                if comment_pos > 0:
                    line = line[:comment_pos].rstrip()
                elif comment_pos == 0:
                    # Pure comment line — replace with random
                    indent = len(line) - len(line.lstrip())
                    indent_str = ' ' * indent
                    line = f'{indent_str}{random.choice(self.FAKE_COMMENTS)}'

            result.append(line)

            # Random blank line insertion
            if random.random() < 0.05 and line.strip():
                result.append('')

        return '\n'.join(result)


# ─── Mutation Engine ──────────────────────────────────────────────────

class MutationEngine:
    """Generate functional variants of Python payloads."""

    def __init__(self):
        self.renamer = VariableRenamer()
        self.dead_code = DeadCodeInjector()
        self.string_obf = StringObfuscator()
        self.cfg_transform = ControlFlowTransformer()
        self.comment_mut = CommentMutator()

    def mutate(self, code: str, level: int = 3) -> str:
        """Generate a single mutated variant.

        Args:
            code: Original Python source code
            level: Mutation intensity 1-5
                1 = comments only
                2 = comments + variable rename
                3 = + dead code + string obfuscation
                4 = + control flow transforms
                5 = all operators, high density

        Returns:
            Mutated code (functionally equivalent)
        """
        result = code

        # Level 1: Comments
        if level >= 1:
            result = self.comment_mut.mutate(result)

        # Level 2: Variable renaming
        if level >= 2:
            self.renamer = VariableRenamer()  # Fresh mapping per mutation
            result = self.renamer.mutate(result)

        # Level 3: Dead code + strings
        if level >= 3:
            density = 0.1 + (level - 3) * 0.05
            result = self.dead_code.mutate(result, density)
            result = self.string_obf.mutate(result, 0.4 + (level - 3) * 0.15)

        # Level 4: Control flow
        if level >= 4:
            density = 0.05 + (level - 4) * 0.05
            result = self.cfg_transform.mutate(result, density)

        return result

    def generate_variants(self, code: str, count: int = 5,
                          level: int = 3, validate: bool = True) -> List[dict]:
        """Generate N unique variants with optional validation.

        Args:
            code: Original source code
            count: Number of variants to generate
            level: Mutation intensity (1-5)
            validate: If True, verify each variant compiles

        Returns:
            List of {variant, hash, compiles, mutations}
        """
        variants = []
        seen_hashes = set()
        attempts = 0
        max_attempts = count * 3

        while len(variants) < count and attempts < max_attempts:
            attempts += 1
            mutated = self.mutate(code, level)

            # Check uniqueness
            h = hashlib.sha256(mutated.encode()).hexdigest()[:16]
            if h in seen_hashes:
                continue
            seen_hashes.add(h)

            # Validate compilation
            compiles = True
            if validate:
                try:
                    compile(mutated, '<variant>', 'exec')
                except SyntaxError:
                    compiles = False

            if not validate or compiles:
                variants.append({
                    'variant': mutated,
                    'hash': h,
                    'compiles': compiles,
                    'size': len(mutated),
                    'lines': mutated.count('\n') + 1,
                    'size_ratio': len(mutated) / max(len(code), 1),
                })

        return variants

    def diff_stats(self, original: str, variant: str) -> dict:
        """Compare original and variant."""
        orig_lines = set(original.strip().split('\n'))
        var_lines = set(variant.strip().split('\n'))

        shared = orig_lines & var_lines
        added = var_lines - orig_lines
        removed = orig_lines - var_lines

        return {
            'original_lines': len(orig_lines),
            'variant_lines': len(var_lines),
            'shared_lines': len(shared),
            'added_lines': len(added),
            'removed_lines': len(removed),
            'similarity': len(shared) / max(len(orig_lines), 1),
            'original_size': len(original),
            'variant_size': len(variant),
            'size_ratio': len(variant) / max(len(original), 1),
        }

    def format_report(self, original: str, variants: List[dict]) -> str:
        """Format mutation report."""
        lines = [
            f"MUTATION ENGINE REPORT",
            f"=" * 60,
            f"  Original: {len(original)} bytes, {original.count(chr(10))+1} lines",
            f"  Variants: {len(variants)} generated",
            f"",
        ]

        for i, v in enumerate(variants, 1):
            stats = self.diff_stats(original, v['variant'])
            lines.append(
                f"  Variant {i}: {v['size']} bytes ({v['size_ratio']:.1f}x), "
                f"hash={v['hash']}, "
                f"sim={stats['similarity']:.0%}, "
                f"{'OK' if v['compiles'] else 'FAIL'}"
            )

        # Average stats
        if variants:
            avg_ratio = sum(v['size_ratio'] for v in variants) / len(variants)
            all_compile = all(v['compiles'] for v in variants)
            unique = len(set(v['hash'] for v in variants))
            lines.append(f"")
            lines.append(f"  Avg size ratio: {avg_ratio:.1f}x")
            lines.append(f"  All compile: {all_compile}")
            lines.append(f"  Unique hashes: {unique}/{len(variants)}")

        return '\n'.join(lines)
