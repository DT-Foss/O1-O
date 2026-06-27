"""
Property-Based Verification — Generate and check algebraic properties

Extends formal verification with property-based testing:
1. Commutativity: f(a, b) == f(b, a)
2. Associativity: f(f(a, b), c) == f(a, f(b, c))
3. Idempotence: f(f(x)) == f(x)
4. Monotonicity: a <= b → f(a) <= f(b)
5. Identity element: f(x, e) == x
6. Involution: f(f(x)) == x
7. Determinism: f(x) always returns same result
8. Boundary: f handles edge cases (0, empty, None)

Works by extracting callable functions from generated code,
generating random test inputs, and checking properties hold.
"""
# Dependencies: none
# Depended by: forge.py (/verify CLI command)


import ast
import random
import string
import sys
import io
from typing import Dict, List, Any, Optional, Callable, Tuple


# Property definitions
PROPERTIES = {
    'commutativity': {
        'description': 'f(a, b) == f(b, a)',
        'min_args': 2,
    },
    'associativity': {
        'description': 'f(f(a, b), c) == f(a, f(b, c))',
        'min_args': 2,
    },
    'idempotence': {
        'description': 'f(f(x)) == f(x)',
        'min_args': 1,
    },
    'monotonicity': {
        'description': 'a <= b → f(a) <= f(b)',
        'min_args': 1,
    },
    'identity': {
        'description': 'f(x, e) == x for some identity element e',
        'min_args': 2,
    },
    'involution': {
        'description': 'f(f(x)) == x',
        'min_args': 1,
    },
    'determinism': {
        'description': 'f(x) returns same result every time',
        'min_args': 1,
    },
    'boundary': {
        'description': 'f handles edge cases without crashing',
        'min_args': 1,
    },
}


class PropertyResult:
    """Result of a property check."""

    def __init__(self, property_name: str, function_name: str,
                 holds: bool, counterexample: Any = None,
                 tests_run: int = 0, tests_passed: int = 0):
        self.property_name = property_name
        self.function_name = function_name
        self.holds = holds
        self.counterexample = counterexample
        self.tests_run = tests_run
        self.tests_passed = tests_passed

    def to_dict(self) -> Dict[str, Any]:
        return {
            'property': self.property_name,
            'function': self.function_name,
            'holds': self.holds,
            'counterexample': str(self.counterexample) if self.counterexample else None,
            'tests_run': self.tests_run,
            'tests_passed': self.tests_passed,
        }

    def __repr__(self):
        status = 'HOLDS' if self.holds else 'FAILS'
        ce = f' (counterexample: {self.counterexample})' if self.counterexample else ''
        return f'{self.property_name}({self.function_name}): {status} [{self.tests_passed}/{self.tests_run}]{ce}'


class PropertyVerifier:
    """Generate test cases from algebraic properties and verify them."""

    def __init__(self, num_tests: int = 50, timeout_per_call: float = 0.1):
        self.num_tests = num_tests
        self.timeout = timeout_per_call

    def verify(self, code: str, properties: List[str] = None) -> List[PropertyResult]:
        """Verify properties of functions in generated code.

        Args:
            code: Python source code containing function definitions
            properties: List of property names to check (None = auto-detect)

        Returns:
            List of PropertyResult for each (function, property) pair
        """
        results = []

        # Extract function signatures
        functions = self._extract_functions(code)
        if not functions:
            return results

        # Compile code in isolated namespace
        namespace = self._safe_exec(code)
        if namespace is None:
            return results

        # For each function, check applicable properties
        for func_info in functions:
            name = func_info['name']
            n_args = func_info['n_args']
            arg_types = func_info['arg_types']

            if name not in namespace or not callable(namespace[name]):
                continue

            func = namespace[name]

            # Determine which properties to check
            check_props = properties or self._auto_detect_properties(func_info)

            for prop in check_props:
                prop_def = PROPERTIES.get(prop)
                if not prop_def:
                    continue
                if n_args < prop_def['min_args']:
                    continue

                result = self._check_property(func, name, prop, n_args, arg_types)
                results.append(result)

        return results

    def generate_test_cases(self, code: str) -> List[Dict[str, Any]]:
        """Generate test cases from detected properties.

        Returns test cases as {function, input, expected_output, property} dicts.
        """
        test_cases = []
        functions = self._extract_functions(code)
        namespace = self._safe_exec(code)
        if not namespace:
            return test_cases

        for func_info in functions:
            name = func_info['name']
            n_args = func_info['n_args']
            arg_types = func_info['arg_types']

            if name not in namespace or not callable(namespace[name]):
                continue

            func = namespace[name]

            # Generate input-output pairs
            for _ in range(min(self.num_tests, 10)):
                args = self._generate_args(n_args, arg_types)
                try:
                    result = func(*args)
                    test_cases.append({
                        'function': name,
                        'input': args,
                        'expected_output': result,
                        'property': 'determinism',
                    })
                except Exception:
                    pass

        return test_cases

    def _extract_functions(self, code: str) -> List[Dict[str, Any]]:
        """Extract function signatures from code."""
        functions = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return functions

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Skip private/dunder functions
                if node.name.startswith('_'):
                    continue

                n_args = len(node.args.args)
                # Skip 'self' parameter for methods
                if n_args > 0 and node.args.args[0].arg == 'self':
                    n_args -= 1

                # Try to infer argument types from annotations and defaults
                arg_types = self._infer_arg_types(node)

                functions.append({
                    'name': node.name,
                    'n_args': n_args,
                    'arg_types': arg_types,
                    'has_return': self._has_return(node),
                    'decorators': [self._decorator_name(d) for d in node.decorator_list],
                })

        return functions

    def _infer_arg_types(self, func_node: ast.FunctionDef) -> List[str]:
        """Infer argument types from annotations, defaults, and naming."""
        types = []
        for arg in func_node.args.args:
            if arg.arg == 'self':
                continue
            if arg.annotation:
                ann = ast.dump(arg.annotation)
                if 'int' in ann:
                    types.append('int')
                elif 'float' in ann:
                    types.append('float')
                elif 'str' in ann:
                    types.append('str')
                elif 'list' in ann or 'List' in ann:
                    types.append('list')
                elif 'bool' in ann:
                    types.append('bool')
                else:
                    types.append('any')
            else:
                # Guess from name
                name = arg.arg.lower()
                if name in ('n', 'count', 'size', 'num', 'x', 'y', 'a', 'b', 'c', 'i', 'j'):
                    types.append('int')
                elif name in ('text', 'string', 's', 'name', 'msg', 'message', 'word', 'key', 'value'):
                    types.append('str')
                elif name in ('items', 'lst', 'arr', 'data', 'values', 'numbers', 'elements'):
                    types.append('list')
                elif name in ('flag', 'enabled', 'verbose'):
                    types.append('bool')
                else:
                    types.append('any')
        return types

    def _has_return(self, func_node: ast.FunctionDef) -> bool:
        """Check if function has a return statement with a value."""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value is not None:
                return True
        return False

    def _decorator_name(self, dec) -> str:
        if isinstance(dec, ast.Name):
            return dec.id
        elif isinstance(dec, ast.Attribute):
            return dec.attr
        return ''

    def _safe_exec(self, code: str) -> Optional[Dict]:
        """Execute code in isolated namespace, return namespace or None."""
        namespace = {}
        # Add safe builtins
        safe_builtins = {
            'range': range, 'len': len, 'int': int, 'float': float,
            'str': str, 'list': list, 'dict': dict, 'set': set,
            'tuple': tuple, 'bool': bool, 'abs': abs, 'max': max,
            'min': min, 'sum': sum, 'sorted': sorted, 'reversed': reversed,
            'enumerate': enumerate, 'zip': zip, 'map': map, 'filter': filter,
            'print': lambda *a, **k: None,  # Suppress output
            'isinstance': isinstance, 'type': type, 'hasattr': hasattr,
            'getattr': getattr, 'round': round, 'pow': pow, 'divmod': divmod,
            'chr': chr, 'ord': ord, 'hex': hex, 'bin': bin, 'oct': oct,
            'any': any, 'all': all, 'input': lambda *a: 'test',
            '__import__': __import__,
        }
        namespace['__builtins__'] = safe_builtins

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            exec(code, namespace)
            return namespace
        except Exception:
            return None
        finally:
            sys.stdout = old_stdout

    def _auto_detect_properties(self, func_info: Dict) -> List[str]:
        """Auto-detect which properties to check for a function."""
        props = ['determinism', 'boundary']

        n = func_info['n_args']
        name = func_info['name'].lower()
        types = func_info['arg_types']

        # Functions with 2+ args might be commutative/associative
        if n >= 2:
            # Math-like operations
            if any(k in name for k in ('add', 'sum', 'mul', 'multiply', 'max', 'min',
                                        'gcd', 'lcm', 'merge', 'combine', 'union')):
                props.extend(['commutativity', 'associativity'])
            elif any(k in name for k in ('concat', 'append', 'join')):
                props.append('associativity')
            else:
                # Try commutativity if both args are same type
                if len(types) >= 2 and types[0] == types[1]:
                    props.append('commutativity')

        # Single-arg functions
        if n >= 1:
            # Idempotence candidates
            if any(k in name for k in ('sort', 'unique', 'normalize', 'clean',
                                        'strip', 'lower', 'upper', 'abs', 'flatten')):
                props.append('idempotence')

            # Monotonicity candidates (numeric functions)
            if all(t in ('int', 'float') for t in types[:1]):
                if any(k in name for k in ('square', 'cube', 'double', 'abs',
                                            'factorial', 'fibonacci', 'length')):
                    props.append('monotonicity')

            # Involution candidates
            if any(k in name for k in ('reverse', 'invert', 'negate', 'flip', 'toggle', 'not')):
                props.append('involution')

        # Identity element candidates
        if n >= 2:
            if any(k in name for k in ('add', 'sum', 'concat', 'mul', 'multiply')):
                props.append('identity')

        return list(dict.fromkeys(props))  # Deduplicate preserving order

    def _generate_args(self, n_args: int, arg_types: List[str]) -> tuple:
        """Generate random arguments based on inferred types."""
        args = []
        for i in range(n_args):
            t = arg_types[i] if i < len(arg_types) else 'any'
            args.append(self._generate_value(t))
        return tuple(args)

    def _generate_value(self, typ: str) -> Any:
        """Generate a random value of the given type."""
        if typ == 'int':
            return random.randint(-100, 100)
        elif typ == 'float':
            return round(random.uniform(-100, 100), 2)
        elif typ == 'str':
            length = random.randint(1, 10)
            return ''.join(random.choices(string.ascii_lowercase, k=length))
        elif typ == 'list':
            length = random.randint(0, 10)
            return [random.randint(-50, 50) for _ in range(length)]
        elif typ == 'bool':
            return random.choice([True, False])
        else:
            # 'any' — pick a random type
            return self._generate_value(random.choice(['int', 'str', 'list']))

    def _generate_boundary_values(self, typ: str) -> List[Any]:
        """Generate edge case values for boundary testing."""
        if typ == 'int':
            return [0, -1, 1, -2**31, 2**31 - 1, 2**63 - 1]
        elif typ == 'float':
            return [0.0, -0.0, 1.0, -1.0, float('inf'), float('-inf')]
        elif typ == 'str':
            return ['', ' ', 'a', 'a' * 1000, '\n', '\t', '\x00']
        elif typ == 'list':
            return [[], [0], [1, 2, 3], list(range(100))]
        elif typ == 'bool':
            return [True, False]
        else:
            return [0, '', [], None, False, True]

    def _check_property(self, func: Callable, func_name: str,
                        prop: str, n_args: int, arg_types: List[str]) -> PropertyResult:
        """Check a specific property for a function."""
        checker = {
            'commutativity': self._check_commutativity,
            'associativity': self._check_associativity,
            'idempotence': self._check_idempotence,
            'monotonicity': self._check_monotonicity,
            'identity': self._check_identity,
            'involution': self._check_involution,
            'determinism': self._check_determinism,
            'boundary': self._check_boundary,
        }.get(prop)

        if not checker:
            return PropertyResult(prop, func_name, False, 'Unknown property')

        return checker(func, func_name, n_args, arg_types)

    def _check_commutativity(self, func, name, n_args, arg_types) -> PropertyResult:
        """f(a, b) == f(b, a)"""
        passed = 0
        total = 0
        for _ in range(self.num_tests):
            t = arg_types[0] if arg_types else 'int'
            a = self._generate_value(t)
            b = self._generate_value(t)
            try:
                r1 = func(a, b)
                r2 = func(b, a)
                total += 1
                if r1 == r2:
                    passed += 1
                else:
                    return PropertyResult('commutativity', name, False,
                                          {'a': a, 'b': b, 'f(a,b)': r1, 'f(b,a)': r2},
                                          total, passed)
            except Exception:
                pass  # Skip invalid inputs

        holds = total > 0 and passed == total
        return PropertyResult('commutativity', name, holds, None, total, passed)

    def _check_associativity(self, func, name, n_args, arg_types) -> PropertyResult:
        """f(f(a, b), c) == f(a, f(b, c))"""
        passed = 0
        total = 0
        t = arg_types[0] if arg_types else 'int'
        for _ in range(self.num_tests):
            a = self._generate_value(t)
            b = self._generate_value(t)
            c = self._generate_value(t)
            try:
                left = func(func(a, b), c)
                right = func(a, func(b, c))
                total += 1
                if left == right:
                    passed += 1
                else:
                    return PropertyResult('associativity', name, False,
                                          {'a': a, 'b': b, 'c': c,
                                           'f(f(a,b),c)': left, 'f(a,f(b,c))': right},
                                          total, passed)
            except Exception:
                pass

        holds = total > 0 and passed == total
        return PropertyResult('associativity', name, holds, None, total, passed)

    def _check_idempotence(self, func, name, n_args, arg_types) -> PropertyResult:
        """f(f(x)) == f(x)"""
        passed = 0
        total = 0
        t = arg_types[0] if arg_types else 'any'
        for _ in range(self.num_tests):
            x = self._generate_value(t)
            try:
                r1 = func(x)
                r2 = func(r1)
                total += 1
                if r1 == r2:
                    passed += 1
                else:
                    return PropertyResult('idempotence', name, False,
                                          {'x': x, 'f(x)': r1, 'f(f(x))': r2},
                                          total, passed)
            except Exception:
                pass

        holds = total > 0 and passed == total
        return PropertyResult('idempotence', name, holds, None, total, passed)

    def _check_monotonicity(self, func, name, n_args, arg_types) -> PropertyResult:
        """a <= b → f(a) <= f(b)"""
        passed = 0
        total = 0
        for _ in range(self.num_tests):
            a = random.randint(0, 100)  # Use non-negative for simpler monotonicity
            b = random.randint(a, 200)
            try:
                fa = func(a)
                fb = func(b)
                if not isinstance(fa, (int, float)) or not isinstance(fb, (int, float)):
                    continue
                total += 1
                if fa <= fb:
                    passed += 1
                else:
                    return PropertyResult('monotonicity', name, False,
                                          {'a': a, 'b': b, 'f(a)': fa, 'f(b)': fb,
                                           'note': f'a<=b but f(a)>f(b)'},
                                          total, passed)
            except Exception:
                pass

        holds = total > 0 and passed == total
        return PropertyResult('monotonicity', name, holds, None, total, passed)

    def _check_identity(self, func, name, n_args, arg_types) -> PropertyResult:
        """f(x, e) == x for some identity element e."""
        t = arg_types[0] if arg_types else 'int'
        # Try common identity elements
        candidates = {
            'int': [0, 1],
            'float': [0.0, 1.0],
            'str': [''],
            'list': [[]],
            'any': [0, 1, '', [], False, True],
        }
        identity_candidates = candidates.get(t, [0, 1, ''])

        for e in identity_candidates:
            all_pass = True
            passed = 0
            total = 0
            for _ in range(self.num_tests):
                x = self._generate_value(t)
                try:
                    result = func(x, e)
                    total += 1
                    if result == x:
                        passed += 1
                    else:
                        all_pass = False
                        break
                except Exception:
                    all_pass = False
                    break

            if all_pass and total > 0:
                return PropertyResult('identity', name, True,
                                      {'identity_element': e},
                                      total, passed)

        return PropertyResult('identity', name, False, 'no identity element found',
                              self.num_tests, 0)

    def _check_involution(self, func, name, n_args, arg_types) -> PropertyResult:
        """f(f(x)) == x"""
        passed = 0
        total = 0
        t = arg_types[0] if arg_types else 'any'
        for _ in range(self.num_tests):
            x = self._generate_value(t)
            try:
                r1 = func(x)
                r2 = func(r1)
                total += 1
                if r2 == x:
                    passed += 1
                else:
                    return PropertyResult('involution', name, False,
                                          {'x': x, 'f(x)': r1, 'f(f(x))': r2},
                                          total, passed)
            except Exception:
                pass

        holds = total > 0 and passed == total
        return PropertyResult('involution', name, holds, None, total, passed)

    def _check_determinism(self, func, name, n_args, arg_types) -> PropertyResult:
        """f(x) returns same result every time."""
        passed = 0
        total = 0
        for _ in range(self.num_tests):
            args = self._generate_args(n_args, arg_types)
            try:
                r1 = func(*args)
                r2 = func(*args)
                total += 1
                if r1 == r2:
                    passed += 1
                else:
                    return PropertyResult('determinism', name, False,
                                          {'args': args, 'call_1': r1, 'call_2': r2},
                                          total, passed)
            except Exception:
                pass

        holds = total > 0 and passed == total
        return PropertyResult('determinism', name, holds, None, total, passed)

    def _check_boundary(self, func, name, n_args, arg_types) -> PropertyResult:
        """f handles edge cases without crashing."""
        passed = 0
        total = 0
        failures = []

        for i in range(n_args):
            t = arg_types[i] if i < len(arg_types) else 'any'
            boundary_vals = self._generate_boundary_values(t)

            for bv in boundary_vals:
                # Build args with boundary value at position i, normal elsewhere
                args = list(self._generate_args(n_args, arg_types))
                args[i] = bv
                try:
                    func(*tuple(args))
                    total += 1
                    passed += 1
                except (TypeError, ValueError):
                    # Type/value errors on boundary inputs are acceptable
                    total += 1
                    passed += 1
                except Exception as e:
                    total += 1
                    failures.append({'args': args, 'error': str(e)[:100]})

        holds = total > 0 and passed == total
        ce = failures[0] if failures else None
        return PropertyResult('boundary', name, holds, ce, total, passed)

    def summary(self, results: List[PropertyResult]) -> Dict[str, Any]:
        """Summarize property verification results."""
        by_prop = {}
        by_func = {}
        for r in results:
            by_prop.setdefault(r.property_name, {'holds': 0, 'fails': 0})
            by_func.setdefault(r.function_name, {'holds': 0, 'fails': 0})
            key = 'holds' if r.holds else 'fails'
            by_prop[r.property_name][key] += 1
            by_func[r.function_name][key] += 1

        return {
            'total_checks': len(results),
            'holds': sum(1 for r in results if r.holds),
            'fails': sum(1 for r in results if not r.holds),
            'by_property': by_prop,
            'by_function': by_func,
            'counterexamples': [r.to_dict() for r in results if not r.holds and r.counterexample],
        }
