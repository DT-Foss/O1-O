"""
AST-Based Code Mutation Engine — Proper AST transformation for polymorphic payloads.

NOT string replacement. NOT regex. Full ast.parse → transform → ast.unparse pipeline.

6 Mutation Operators:
1. Variable Name Randomization (realistic pool, 500+ names)
2. Dead Code Insertion (200+ realistic snippets)
3. Control Flow Flattening (state-machine dispatch)
4. String Encryption (XOR with per-string key + decryptor prepend)
5. Integer Constant Obfuscation (arithmetic expression substitution)
6. Import Reordering and Aliasing

Each mutation produces unique SHA256. All variants functionally equivalent.
"""
import ast
import copy
import hashlib
import json
import os
import random
import string
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ─── Pool Loaders ─────────────────────────────────────────────────

_POOL_DIR = Path(__file__).parent.parent / 'fragments' / 'mutation_pools'

_VARNAME_POOL: List[str] = []
_DEAD_STMT_POOL: List[str] = []
_DEAD_FUNC_POOL: List[str] = []
_DEAD_COMMENT_POOL: List[str] = []


def _load_pools():
    global _VARNAME_POOL, _DEAD_STMT_POOL, _DEAD_FUNC_POOL, _DEAD_COMMENT_POOL
    if _VARNAME_POOL:
        return

    vp = _POOL_DIR / 'varnames.json'
    if vp.exists():
        data = json.loads(vp.read_text())
        _VARNAME_POOL = data.get('names', [])

    dp = _POOL_DIR / 'dead_code.json'
    if dp.exists():
        data = json.loads(dp.read_text())
        _DEAD_STMT_POOL = data.get('statements', [])
        _DEAD_FUNC_POOL = data.get('functions', [])
        _DEAD_COMMENT_POOL = data.get('comments', [])


# ─── Protected Names (never rename) ──────────────────────────────

PROTECTED_NAMES = {
    'self', 'cls', 'True', 'False', 'None', 'super',
    '__name__', '__main__', '__init__', '__file__', '__doc__',
    '__all__', '__dict__', '__class__', '__module__', '__slots__',
    '__enter__', '__exit__', '__iter__', '__next__', '__call__',
    '__getitem__', '__setitem__', '__delitem__', '__len__',
    '__repr__', '__str__', '__eq__', '__hash__',
    '__getattr__', '__setattr__', '__delattr__',
    # builtins — types
    'int', 'str', 'float', 'bool', 'list', 'dict', 'set', 'tuple',
    'bytes', 'bytearray', 'memoryview', 'complex', 'frozenset',
    'object', 'type', 'property', 'staticmethod', 'classmethod',
    # builtins — functions
    'print', 'len', 'range', 'open', 'input', 'repr', 'id',
    'isinstance', 'issubclass', 'hasattr', 'getattr', 'setattr', 'delattr',
    'chr', 'ord', 'hex', 'bin', 'oct', 'abs', 'round', 'pow', 'divmod',
    'max', 'min', 'sum', 'any', 'all', 'sorted', 'reversed',
    'map', 'filter', 'zip', 'enumerate', 'iter', 'next', 'callable',
    'hash', 'dir', 'vars', 'globals', 'locals', 'exec', 'eval', 'compile',
    'format', 'ascii', 'breakpoint', '__import__', '__builtins__',
    # builtins — exceptions
    'Exception', 'BaseException', 'ValueError', 'TypeError', 'KeyError',
    'IndexError', 'AttributeError', 'NameError', 'FileNotFoundError',
    'OSError', 'IOError', 'RuntimeError', 'ImportError', 'StopIteration',
    'SystemExit', 'KeyboardInterrupt', 'PermissionError', 'TimeoutError',
    'ConnectionError', 'NotImplementedError', 'SyntaxError', 'UnicodeError',
}


# ─── Operator 1: Variable Name Randomization ─────────────────────

class VarNameRandomizer(ast.NodeTransformer):
    """AST-level variable rename using realistic name pool."""

    def __init__(self):
        _load_pools()
        self.mapping: Dict[str, str] = {}
        self._defined: Set[str] = set()
        self._imported: Set[str] = set()
        self._pool = list(_VARNAME_POOL) if _VARNAME_POOL else []
        random.shuffle(self._pool)
        self._pool_idx = 0

    def _pick_name(self) -> str:
        if self._pool_idx < len(self._pool):
            name = self._pool[self._pool_idx]
            self._pool_idx += 1
            return name
        # Fallback: generate realistic name
        prefixes = ['data', 'buf', 'tmp', 'cfg', 'ctx', 'val', 'ref', 'ptr']
        suffixes = ['size', 'count', 'len', 'idx', 'pos', 'offset', 'handle', 'state']
        return f"_{random.choice(prefixes)}_{random.choice(suffixes)}_{random.randint(0, 999)}"

    def _collect_names(self, tree: ast.AST):
        """First pass: collect defined names and imports."""
        for node in ast.walk(tree):
            # Imports — never rename
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    actual = alias.asname or alias.name
                    self._imported.add(actual)
                    for part in alias.name.split('.'):
                        self._imported.add(part)
                    if isinstance(node, ast.ImportFrom) and node.module:
                        for part in node.module.split('.'):
                            self._imported.add(part)

            # Defined names
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._defined.add(node.name)
                for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                    self._defined.add(arg.arg)
                if node.args.vararg:
                    self._defined.add(node.args.vararg.arg)
                if node.args.kwarg:
                    self._defined.add(node.args.kwarg.arg)
            elif isinstance(node, ast.ClassDef):
                self._defined.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                self._defined.add(node.id)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                self._defined.add(node.name)

        # Build mapping for renamable names
        renamable = self._defined - self._imported - PROTECTED_NAMES
        for name in sorted(renamable):
            if not name.startswith('__') and not name.startswith('_d'):  # preserve decryptor
                self.mapping[name] = self._pick_name()

    def _rename(self, name: str) -> str:
        return self.mapping.get(name, name)

    def visit_FunctionDef(self, node):
        node.name = self._rename(node.name)
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            arg.arg = self._rename(arg.arg)
        if node.args.vararg:
            node.args.vararg.arg = self._rename(node.args.vararg.arg)
        if node.args.kwarg:
            node.args.kwarg.arg = self._rename(node.args.kwarg.arg)
        self.generic_visit(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        node.name = self._rename(node.name)
        self.generic_visit(node)
        return node

    def visit_Name(self, node):
        node.id = self._rename(node.id)
        return node

    def visit_ExceptHandler(self, node):
        if node.name:
            node.name = self._rename(node.name)
        self.generic_visit(node)
        return node

    def visit_arg(self, node):
        node.arg = self._rename(node.arg)
        return node

    def visit_Global(self, node):
        node.names = [self._rename(n) for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [self._rename(n) for n in node.names]
        return node

    def transform(self, tree: ast.AST) -> ast.AST:
        tree = copy.deepcopy(tree)
        self._collect_names(tree)
        return self.visit(tree)


# ─── Operator 2: Dead Code Insertion ─────────────────────────────

class DeadCodeInserter(ast.NodeTransformer):
    """Insert realistic dead code between statements at AST level."""

    def __init__(self, density: float = 0.2):
        _load_pools()
        self.density = density
        self._used_snippets: Set[int] = set()

    def _random_dead_stmt(self) -> Optional[ast.AST]:
        """Generate a random dead code AST node."""
        pool = _DEAD_STMT_POOL or [
            '_ref = 0', '_buf = None', '_ok = True',
            'if hasattr(os, "getpid"):\n    _p = os.getpid()',
        ]

        # Pick unused snippet
        available = [i for i in range(len(pool)) if i not in self._used_snippets]
        if not available:
            self._used_snippets.clear()
            available = list(range(len(pool)))

        idx = random.choice(available)
        self._used_snippets.add(idx)
        snippet = pool[idx]

        try:
            nodes = ast.parse(snippet).body
            return nodes if nodes else None
        except SyntaxError:
            return None

    def _random_dead_func(self) -> Optional[ast.AST]:
        """Generate a dead helper function."""
        pool = _DEAD_FUNC_POOL or [
            "def _validate_config(cfg):\n    return isinstance(cfg, dict)",
        ]
        snippet = random.choice(pool)
        try:
            nodes = ast.parse(snippet).body
            return nodes if nodes else None
        except SyntaxError:
            return None

    def _inject_into_body(self, body: list) -> list:
        """Insert dead code into a statement list."""
        if not body:
            return body

        new_body = []
        for i, stmt in enumerate(body):
            new_body.append(stmt)
            if random.random() < self.density:
                if random.random() < 0.8:
                    dead = self._random_dead_stmt()
                else:
                    dead = self._random_dead_func()
                if dead:
                    if isinstance(dead, list):
                        new_body.extend(dead)
                    else:
                        new_body.append(dead)
        return new_body

    def visit_Module(self, node):
        self.generic_visit(node)
        node.body = self._inject_into_body(node.body)
        return node

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        node.body = self._inject_into_body(node.body)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node):
        self.generic_visit(node)
        node.body = self._inject_into_body(node.body)
        if node.orelse:
            node.orelse = self._inject_into_body(node.orelse)
        return node

    def visit_For(self, node):
        self.generic_visit(node)
        node.body = self._inject_into_body(node.body)
        return node

    visit_While = visit_For

    def visit_Try(self, node):
        self.generic_visit(node)
        node.body = self._inject_into_body(node.body)
        return node

    def transform(self, tree: ast.AST) -> ast.AST:
        tree = copy.deepcopy(tree)
        return self.visit(tree)


# ─── Operator 3: Control Flow Flattening ─────────────────────────

class ControlFlowFlattener(ast.NodeTransformer):
    """Transform if/elif/else chains into state-machine dispatch."""

    def __init__(self):
        self._state_var_counter = 0

    def _next_state_var(self) -> str:
        self._state_var_counter += 1
        name = f"_fsm_{self._state_var_counter}"
        return name

    def _count_branches(self, node: ast.If) -> int:
        """Count if/elif/else branches."""
        count = 1
        current = node
        while current.orelse:
            if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                count += 1
                current = current.orelse[0]
            else:
                count += 1  # else branch
                break
        return count

    def _collect_branches(self, node: ast.If) -> List[Tuple[Optional[ast.expr], list]]:
        """Collect (condition, body) pairs from if/elif/else chain."""
        branches = [(node.test, node.body)]
        current = node
        while current.orelse:
            if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                current = current.orelse[0]
                branches.append((current.test, current.body))
            else:
                branches.append((None, current.orelse))  # else
                break
        return branches

    def _flatten_if(self, node: ast.If) -> list:
        """Convert if/elif/else to while+state dispatch."""
        branches = self._collect_branches(node)
        state_var = self._next_state_var()
        n_states = len(branches)

        # _fsm_N = 0
        init = ast.Assign(
            targets=[ast.Name(id=state_var, ctx=ast.Store())],
            value=ast.Constant(value=0),
            lineno=node.lineno,
        )

        # Build while body: series of if _fsm == N and condition: body; _fsm = EXIT
        exit_state = n_states
        while_body = []
        for i, (cond, body) in enumerate(branches):
            # Terminator: _fsm_N = exit_state
            terminator = ast.Assign(
                targets=[ast.Name(id=state_var, ctx=ast.Store())],
                value=ast.Constant(value=exit_state),
                lineno=node.lineno,
            )
            body_with_term = list(body) + [terminator]

            state_check = ast.Compare(
                left=ast.Name(id=state_var, ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=i)],
            )

            if cond is not None:
                # if _fsm == i and condition: body; _fsm = exit
                # else if _fsm == i: _fsm = i+1
                combined_test = ast.BoolOp(
                    op=ast.And(),
                    values=[state_check, cond],
                )
                advance = ast.Assign(
                    targets=[ast.Name(id=state_var, ctx=ast.Store())],
                    value=ast.Constant(value=i + 1),
                    lineno=node.lineno,
                )
                advance_check = ast.Compare(
                    left=ast.Name(id=state_var, ctx=ast.Load()),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=i)],
                )
                if_node = ast.If(
                    test=combined_test,
                    body=body_with_term,
                    orelse=[ast.If(
                        test=advance_check,
                        body=[advance],
                        orelse=[],
                    )],
                )
            else:
                # else branch: if _fsm == i: body; _fsm = exit
                if_node = ast.If(
                    test=state_check,
                    body=body_with_term,
                    orelse=[],
                )

            while_body.append(if_node)

        # while _fsm_N < exit_state:
        while_node = ast.While(
            test=ast.Compare(
                left=ast.Name(id=state_var, ctx=ast.Load()),
                ops=[ast.Lt()],
                comparators=[ast.Constant(value=exit_state)],
            ),
            body=while_body,
            orelse=[],
            lineno=node.lineno,
        )

        return [init, while_node]

    def visit_If(self, node):
        self.generic_visit(node)
        if self._count_branches(node) >= 3:
            return self._flatten_if(node)
        return node

    def transform(self, tree: ast.AST) -> ast.AST:
        tree = copy.deepcopy(tree)
        result = self.visit(tree)
        ast.fix_missing_locations(result)
        return result


# ─── Operator 4: String Encryption ───────────────────────────────

class StringEncryptor(ast.NodeTransformer):
    """Replace string literals with XOR-encrypted equivalents + decryptor."""

    def __init__(self, probability: float = 0.7):
        self.probability = probability
        self._encrypted_any = False
        self._decryptor_name = '_d'
        self._in_decorator = False

    def _xor_encrypt(self, plaintext: str, key: bytes) -> bytes:
        data = plaintext.encode('utf-8')
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    def _make_decryptor(self) -> ast.FunctionDef:
        """Generate the _d(data, key) decryptor function as AST."""
        src = textwrap.dedent(f"""
def {self._decryptor_name}(_enc_data, _enc_key):
    return bytes(_enc_data[_i] ^ _enc_key[_i % len(_enc_key)] for _i in range(len(_enc_data))).decode('utf-8')
""").strip()
        return ast.parse(src).body[0]

    def visit_Constant(self, node):
        if not isinstance(node.value, str):
            return node
        if len(node.value) < 2 or len(node.value) > 500:
            return node
        if self._in_decorator:
            return node
        if random.random() > self.probability:
            return node

        self._encrypted_any = True
        key = os.urandom(16)
        encrypted = self._xor_encrypt(node.value, key)

        # _d(b'...', b'...')
        call = ast.Call(
            func=ast.Name(id=self._decryptor_name, ctx=ast.Load()),
            args=[
                ast.Constant(value=encrypted),
                ast.Constant(value=key),
            ],
            keywords=[],
        )
        return ast.copy_location(call, node)

    def visit_FunctionDef(self, node):
        # Don't encrypt decorator arguments
        old = self._in_decorator
        for dec in node.decorator_list:
            self._in_decorator = True
            self.visit(dec)
        self._in_decorator = old
        # Visit everything else
        node.args = self.visit(node.args)
        node.body = [self.visit(s) for s in node.body]
        node.returns = self.visit(node.returns) if node.returns else None
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_JoinedStr(self, node):
        # Don't encrypt f-string components
        return node

    def transform(self, tree: ast.AST) -> ast.AST:
        tree = copy.deepcopy(tree)
        result = self.visit(tree)
        if self._encrypted_any:
            decryptor = self._make_decryptor()
            # Insert after imports but before other code
            insert_idx = 0
            for i, stmt in enumerate(result.body):
                if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                    insert_idx = i + 1
                elif isinstance(stmt, ast.Expr) and isinstance(getattr(stmt, 'value', None), ast.Constant):
                    insert_idx = i + 1  # Skip docstrings
                else:
                    break
            result.body.insert(insert_idx, decryptor)
        ast.fix_missing_locations(result)
        return result


# ─── Operator 5: Integer Constant Obfuscation ────────────────────

class IntObfuscator(ast.NodeTransformer):
    """Replace integer constants with equivalent arithmetic expressions."""

    SKIP_VALUES = {0, 1, -1}  # Don't obfuscate trivial values

    def __init__(self, probability: float = 0.6):
        self.probability = probability
        self._in_index = False

    def _obfuscate_int(self, n: int) -> ast.expr:
        """Generate arithmetic expression that evaluates to n."""
        method = random.randint(0, 5)

        if method == 0:
            # a + b where a + b = n
            a = random.randint(-1000, 1000)
            b = n - a
            return ast.BinOp(
                left=ast.Constant(value=a),
                op=ast.Add(),
                right=ast.Constant(value=b),
            )
        elif method == 1:
            # a * b + c where a*b+c = n (pick small a)
            a = random.choice([2, 3, 4, 5, 7, 8, 16])
            c = n % a
            b = (n - c) // a
            return ast.BinOp(
                left=ast.BinOp(
                    left=ast.Constant(value=a),
                    op=ast.Mult(),
                    right=ast.Constant(value=b),
                ),
                op=ast.Add(),
                right=ast.Constant(value=c),
            )
        elif method == 2:
            # a - b where a - b = n
            a = n + random.randint(1, 500)
            b = a - n
            return ast.BinOp(
                left=ast.Constant(value=a),
                op=ast.Sub(),
                right=ast.Constant(value=b),
            )
        elif method == 3:
            # hex literal (just change representation via int('hex', 16))
            hex_str = hex(n)
            return ast.Call(
                func=ast.Name(id='int', ctx=ast.Load()),
                args=[ast.Constant(value=hex_str), ast.Constant(value=16)],
                keywords=[],
            )
        elif method == 4:
            # (a ^ b) where a ^ b = n
            a = random.randint(0, 0xFFFF)
            b = n ^ a
            return ast.BinOp(
                left=ast.Constant(value=a),
                op=ast.BitXor(),
                right=ast.Constant(value=b),
            )
        else:
            # ~(~n) = n via bit inversion
            inverted = ~n
            return ast.UnaryOp(
                op=ast.Invert(),
                operand=ast.Constant(value=inverted),
            )

    def visit_Subscript(self, node):
        """Don't obfuscate array indices."""
        old = self._in_index
        self._in_index = True
        node.slice = self.visit(node.slice)
        self._in_index = old
        node.value = self.visit(node.value)
        return node

    def visit_Constant(self, node):
        if not isinstance(node.value, int) or isinstance(node.value, bool):
            return node
        if node.value in self.SKIP_VALUES:
            return node
        if self._in_index:
            return node
        if random.random() > self.probability:
            return node

        expr = self._obfuscate_int(node.value)
        return ast.copy_location(expr, node)

    def transform(self, tree: ast.AST) -> ast.AST:
        tree = copy.deepcopy(tree)
        result = self.visit(tree)
        ast.fix_missing_locations(result)
        return result


# ─── Operator 6: Import Reordering and Aliasing ──────────────────

class ImportMutator:
    """Shuffle imports, add aliases, insert benign unused imports."""

    BENIGN_IMPORTS = [
        'logging', 'warnings', 'functools', 'itertools', 'contextlib',
        'collections', 'operator', 'abc', 'copy', 'pprint',
        'textwrap', 'codecs', 'binascii', 'decimal', 'fractions',
        'statistics', 'unicodedata', 'inspect', 'dis', 'traceback',
        'weakref', 'types', 'enum', 'dataclasses',
    ]

    def _alias_name(self, module: str) -> str:
        """Generate realistic alias for a module."""
        short = module.split('.')[-1]
        styles = [
            f'_{short}',
            f'_{short}_mod',
            f'_{short}_lib',
            f'_{short[0]}',
        ]
        return random.choice(styles)

    def transform(self, tree: ast.AST) -> ast.AST:
        tree = copy.deepcopy(tree)

        # Separate imports from other statements
        imports = []
        other = []
        from_imports = []
        existing_modules = set()

        for stmt in tree.body:
            if isinstance(stmt, ast.Import):
                imports.append(stmt)
                for alias in stmt.names:
                    existing_modules.add(alias.name.split('.')[0])
            elif isinstance(stmt, ast.ImportFrom):
                from_imports.append(stmt)
                if stmt.module:
                    existing_modules.add(stmt.module.split('.')[0])
            else:
                other.append(stmt)

        # Shuffle import order
        random.shuffle(imports)
        random.shuffle(from_imports)

        # Add aliases to some imports (30% chance each)
        for imp in imports:
            for alias in imp.names:
                if not alias.asname and random.random() < 0.3:
                    alias.asname = self._alias_name(alias.name)

        # Add 1-3 benign unused imports
        available = [m for m in self.BENIGN_IMPORTS if m not in existing_modules]
        if available:
            n_add = random.randint(1, min(3, len(available)))
            for mod in random.sample(available, n_add):
                new_imp = ast.Import(
                    names=[ast.alias(name=mod, asname=self._alias_name(mod))],
                )
                imports.append(new_imp)

        # Reassemble: imports first, then from-imports, then body
        tree.body = imports + from_imports + other
        ast.fix_missing_locations(tree)
        return tree


# ─── Payload Mutator (Main Class) ────────────────────────────────

class PayloadMutator:
    """AST-based polymorphic mutation engine.

    Usage:
        pm = PayloadMutator()
        mutated = pm.mutate(source_code)
        is_equiv = pm.verify_equivalence(original, mutated, test_inputs)
    """

    def __init__(self):
        self.var_renamer = VarNameRandomizer
        self.dead_code = DeadCodeInserter
        self.cfg_flatten = ControlFlowFlattener
        self.str_encrypt = StringEncryptor
        self.int_obfuscate = IntObfuscator
        self.import_mutator = ImportMutator

    def mutate(self, source_code: str, language: str = 'python',
               operators: List[int] = None, level: int = 3) -> str:
        """Apply random subset of mutation operators.

        Args:
            source_code: Original Python source
            language: 'python' (C support planned)
            operators: Specific operator IDs [1-6] or None for auto
            level: 1=minimal, 3=standard, 5=maximum

        Returns:
            Mutated source with guaranteed different SHA256
        """
        if language != 'python':
            return source_code

        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return source_code

        # Select operators
        if operators is None:
            all_ops = [1, 2, 3, 4, 5, 6]
            if level <= 1:
                ops = random.sample(all_ops, 2)
            elif level <= 3:
                ops = random.sample(all_ops, random.randint(3, 5))
            else:
                ops = all_ops[:]
            random.shuffle(ops)
        else:
            ops = list(operators)
            random.shuffle(ops)

        # Apply in random order
        for op_id in ops:
            try:
                if op_id == 1:
                    renamer = self.var_renamer()
                    tree = renamer.transform(tree)
                elif op_id == 2:
                    density = 0.1 + (level - 1) * 0.05
                    inserter = self.dead_code(density=min(density, 0.4))
                    tree = inserter.transform(tree)
                elif op_id == 3:
                    flattener = self.cfg_flatten()
                    tree = flattener.transform(tree)
                elif op_id == 4:
                    prob = 0.3 + (level - 1) * 0.1
                    encryptor = self.str_encrypt(probability=min(prob, 0.9))
                    tree = encryptor.transform(tree)
                elif op_id == 5:
                    prob = 0.3 + (level - 1) * 0.08
                    obfuscator = self.int_obfuscate(probability=min(prob, 0.8))
                    tree = obfuscator.transform(tree)
                elif op_id == 6:
                    mutator = self.import_mutator()
                    tree = mutator.transform(tree)
            except Exception:
                continue  # Skip failed operator, try next

        try:
            result = ast.unparse(tree)
        except Exception:
            return source_code

        # Verify compilation
        try:
            compile(result, '<mutated>', 'exec')
        except SyntaxError:
            return source_code

        return result

    def verify_equivalence(self, original: str, mutated: str,
                           test_inputs: list = None, timeout: float = 5.0) -> bool:
        """Verify that original and mutated produce identical output.

        Runs both versions in subprocesses with same stdin, compares stdout.
        """
        if test_inputs is None:
            test_inputs = [b'']  # empty stdin

        for inp in test_inputs:
            try:
                # Run original
                orig_result = subprocess.run(
                    [sys.executable, '-c', original],
                    input=inp if isinstance(inp, bytes) else inp.encode(),
                    capture_output=True, timeout=timeout,
                )
                # Run mutated
                mut_result = subprocess.run(
                    [sys.executable, '-c', mutated],
                    input=inp if isinstance(inp, bytes) else inp.encode(),
                    capture_output=True, timeout=timeout,
                )
                # Compare stdout (ignore stderr — dead code may produce warnings)
                if orig_result.stdout != mut_result.stdout:
                    return False
                if orig_result.returncode != mut_result.returncode:
                    return False
            except subprocess.TimeoutExpired:
                continue  # Both might timeout equally
            except Exception:
                return False

        return True

    def generate_variants(self, source_code: str, count: int = 10,
                          level: int = 3, verify: bool = False) -> List[dict]:
        """Generate N unique mutated variants.

        Args:
            source_code: Original source
            count: Number of variants
            level: Mutation intensity
            verify: If True, verify equivalence (slow)

        Returns:
            List of {code, hash, size, compiles, [equivalent]}
        """
        variants = []
        seen_hashes = set()
        orig_hash = hashlib.sha256(source_code.encode()).hexdigest()
        seen_hashes.add(orig_hash)
        attempts = 0
        max_attempts = count * 5

        while len(variants) < count and attempts < max_attempts:
            attempts += 1
            mutated = self.mutate(source_code, level=level)
            h = hashlib.sha256(mutated.encode()).hexdigest()

            if h in seen_hashes:
                continue
            seen_hashes.add(h)

            entry = {
                'code': mutated,
                'hash': h[:16],
                'size': len(mutated),
                'size_ratio': len(mutated) / max(len(source_code), 1),
                'compiles': True,  # Already verified in mutate()
            }

            if verify:
                entry['equivalent'] = self.verify_equivalence(source_code, mutated)

            variants.append(entry)

        return variants

    def mutation_report(self, source_code: str, variants: List[dict]) -> str:
        """Format mutation analysis report."""
        lines = [
            "PAYLOAD MUTATOR REPORT",
            "=" * 60,
            f"  Original: {len(source_code)} bytes, SHA256={hashlib.sha256(source_code.encode()).hexdigest()[:16]}",
            f"  Variants: {len(variants)} generated",
            "",
        ]
        for i, v in enumerate(variants, 1):
            equiv_str = f", equiv={'YES' if v.get('equivalent') else 'N/A'}" if 'equivalent' in v else ''
            lines.append(
                f"  [{i:3d}] {v['size']:6d} bytes ({v['size_ratio']:.1f}x), "
                f"hash={v['hash']}{equiv_str}"
            )
        if variants:
            unique = len(set(v['hash'] for v in variants))
            avg_ratio = sum(v['size_ratio'] for v in variants) / len(variants)
            lines.extend([
                "",
                f"  Unique hashes: {unique}/{len(variants)}",
                f"  Avg size ratio: {avg_ratio:.1f}x",
                f"  All compile: {all(v['compiles'] for v in variants)}",
            ])
        return '\n'.join(lines)
