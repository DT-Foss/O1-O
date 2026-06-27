"""
Symbolic Executor — Lightweight constraint-based analysis for FORGE output

NOT a full Z3-based symbolic engine. Instead, a targeted analyzer for
common FORGE code patterns:

1. Variable constraint tracking: what values can a variable hold at each point
2. Path exploration: enumerate branches and their constraints
3. Unreachable branch detection: find branches that can never execute
4. Overflow condition finding: detect integer operations that may overflow
5. Division-by-zero detection: find divisions with possibly-zero denominators
6. Loop bound analysis: detect potentially infinite loops
"""
# Dependencies: none
# Depended by: forge.py (build pipeline + /symbolic CLI)


import ast
import re
import math
from typing import List, Dict, Any, Optional, Set, Tuple, Union


class SymbolicValue:
    """Represents a symbolic variable with constraints."""

    def __init__(self, name: str, vtype: str = 'unknown',
                 min_val: Optional[float] = None, max_val: Optional[float] = None,
                 possible_values: Optional[Set] = None, is_const: bool = False):
        self.name = name
        self.vtype = vtype  # int, float, str, list, bool, unknown
        self.min_val = min_val
        self.max_val = max_val
        self.possible_values = possible_values  # finite set of known values
        self.is_const = is_const

    def can_be_zero(self) -> bool:
        if self.possible_values is not None:
            return 0 in self.possible_values
        if self.min_val is not None and self.max_val is not None:
            return self.min_val <= 0 <= self.max_val
        return True  # Unknown = assume possible

    def can_overflow_32(self) -> bool:
        if self.vtype not in ('int', 'float'):
            return False
        if self.max_val is not None and self.max_val > 2**31 - 1:
            return True
        if self.min_val is not None and self.min_val < -(2**31):
            return True
        return False

    def can_overflow_64(self) -> bool:
        if self.vtype not in ('int', 'float'):
            return False
        if self.max_val is not None and self.max_val > 2**63 - 1:
            return True
        if self.min_val is not None and self.min_val < -(2**63):
            return True
        return False

    def narrow(self, op: str, rhs: 'SymbolicValue') -> 'SymbolicValue':
        """Narrow constraints based on a comparison."""
        result = SymbolicValue(self.name, self.vtype, self.min_val, self.max_val,
                               self.possible_values, self.is_const)

        if rhs.is_const and rhs.possible_values and len(rhs.possible_values) == 1:
            val = next(iter(rhs.possible_values))
            if isinstance(val, (int, float)):
                if op in ('>', 'Gt'):
                    result.min_val = val + 1 if result.min_val is None else max(result.min_val, val + 1)
                elif op in ('>=', 'GtE'):
                    result.min_val = val if result.min_val is None else max(result.min_val, val)
                elif op in ('<', 'Lt'):
                    result.max_val = val - 1 if result.max_val is None else min(result.max_val, val - 1)
                elif op in ('<=', 'LtE'):
                    result.max_val = val if result.max_val is None else min(result.max_val, val)
                elif op in ('==', 'Eq'):
                    result.possible_values = {val}
                    result.min_val = val
                    result.max_val = val
                elif op in ('!=', 'NotEq'):
                    if result.possible_values:
                        result.possible_values.discard(val)

        return result

    def __repr__(self):
        parts = [f'{self.name}: {self.vtype}']
        if self.min_val is not None or self.max_val is not None:
            lo = str(self.min_val) if self.min_val is not None else '-inf'
            hi = str(self.max_val) if self.max_val is not None else 'inf'
            parts.append(f'[{lo}, {hi}]')
        if self.possible_values:
            parts.append(f'in {self.possible_values}')
        return ' '.join(parts)


class PathConstraint:
    """A single path through the code with its constraints."""

    def __init__(self, conditions: List[str] = None, reachable: bool = True):
        self.conditions = conditions or []
        self.reachable = reachable

    def add_condition(self, cond: str, negated: bool = False):
        prefix = 'NOT ' if negated else ''
        self.conditions.append(f'{prefix}{cond}')

    def __repr__(self):
        status = 'reachable' if self.reachable else 'DEAD'
        return f'Path({" AND ".join(self.conditions)}) [{status}]'


class SymbolicFinding:
    """A finding from symbolic execution."""

    def __init__(self, ftype: str, line: int, message: str, severity: str = 'MEDIUM'):
        self.type = ftype
        self.line = line
        self.message = message
        self.severity = severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.type,
            'line': self.line,
            'message': self.message,
            'severity': self.severity,
        }

    def __repr__(self):
        return f'[{self.severity}] L{self.line}: {self.type} — {self.message}'


class SymbolicExecutor:
    """Lightweight symbolic execution for FORGE-generated Python."""

    def __init__(self):
        self.variables: Dict[str, SymbolicValue] = {}
        self.findings: List[SymbolicFinding] = []
        self.paths: List[PathConstraint] = []

    def analyze(self, code: str) -> Dict[str, Any]:
        """Run full symbolic analysis on code.

        Returns {findings, paths, variables, summary}.
        """
        self.variables.clear()
        self.findings.clear()
        self.paths.clear()

        try:
            tree = ast.parse(code)
        except SyntaxError:
            return {'findings': [], 'paths': [], 'variables': {}, 'summary': {}}

        # Phase 1: Variable discovery and constraint collection
        self._discover_variables(tree)

        # Phase 2: Path exploration
        self._explore_paths(tree)

        # Phase 3: Check for issues at each point
        self._check_divisions(tree)
        self._check_overflows(tree)
        self._check_loop_bounds(tree)
        self._check_index_bounds(tree)
        self._check_type_errors(tree)

        return {
            'findings': [f.to_dict() for f in self.findings],
            'paths': [str(p) for p in self.paths],
            'variables': {k: str(v) for k, v in self.variables.items()},
            'summary': self._summarize(),
        }

    def _discover_variables(self, tree: ast.Module):
        """Phase 1: Find all variable assignments and infer types/ranges."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        sv = self._value_from_node(target.id, node.value)
                        if sv:
                            self.variables[target.id] = sv

            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name):
                    name = node.target.id
                    if name in self.variables:
                        existing = self.variables[name]
                        rhs = self._value_from_node('_rhs', node.value)
                        if rhs and isinstance(node.op, ast.Add):
                            if existing.max_val is not None and rhs.max_val is not None:
                                existing.max_val = None  # Potentially unbounded after augment

            elif isinstance(node, ast.For):
                if isinstance(node.target, ast.Name):
                    iter_sv = self._range_from_iter(node.target.id, node.iter)
                    if iter_sv:
                        self.variables[node.target.id] = iter_sv

    def _value_from_node(self, name: str, node: ast.expr) -> Optional[SymbolicValue]:
        """Infer a SymbolicValue from an AST expression node."""
        if isinstance(node, ast.Constant):
            val = node.value
            if isinstance(val, int):
                return SymbolicValue(name, 'int', val, val, {val}, is_const=True)
            elif isinstance(val, float):
                return SymbolicValue(name, 'float', val, val, {val}, is_const=True)
            elif isinstance(val, str):
                return SymbolicValue(name, 'str', is_const=True)
            elif isinstance(val, bool):
                return SymbolicValue(name, 'bool', possible_values={val}, is_const=True)

        elif isinstance(node, ast.List):
            return SymbolicValue(name, 'list', 0, len(node.elts))

        elif isinstance(node, ast.Call):
            func_name = ''
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name == 'int':
                return SymbolicValue(name, 'int')
            elif func_name == 'float':
                return SymbolicValue(name, 'float')
            elif func_name == 'input':
                return SymbolicValue(name, 'str')  # user input = string
            elif func_name == 'range':
                return self._range_from_call(name, node)
            elif func_name == 'len':
                return SymbolicValue(name, 'int', 0, None)
            elif func_name in ('abs', 'max', 'min', 'sum'):
                return SymbolicValue(name, 'int')

        elif isinstance(node, ast.BinOp):
            left = self._value_from_node('_left', node.left)
            right = self._value_from_node('_right', node.right)
            return self._binop_result(name, node.op, left, right)

        elif isinstance(node, ast.UnaryOp):
            operand = self._value_from_node('_op', node.operand)
            if operand and isinstance(node.op, ast.USub):
                return SymbolicValue(
                    name, operand.vtype,
                    -operand.max_val if operand.max_val is not None else None,
                    -operand.min_val if operand.min_val is not None else None,
                )

        return SymbolicValue(name, 'unknown')

    def _range_from_iter(self, name: str, iter_node: ast.expr) -> Optional[SymbolicValue]:
        """Extract range constraints from a for-loop iterator."""
        if isinstance(iter_node, ast.Call) and isinstance(iter_node.func, ast.Name):
            if iter_node.func.id == 'range':
                return self._range_from_call(name, iter_node)
        return SymbolicValue(name, 'unknown')

    def _range_from_call(self, name: str, call: ast.Call) -> Optional[SymbolicValue]:
        """Extract range constraints from range() call."""
        args = call.args
        if len(args) == 1:
            stop = self._const_value(args[0])
            if stop is not None:
                return SymbolicValue(name, 'int', 0, stop - 1 if stop > 0 else 0)
        elif len(args) >= 2:
            start = self._const_value(args[0])
            stop = self._const_value(args[1])
            if start is not None and stop is not None:
                return SymbolicValue(name, 'int', start, stop - 1 if stop > start else start)
        return SymbolicValue(name, 'int', 0, None)

    def _const_value(self, node: ast.expr) -> Optional[Union[int, float]]:
        """Extract constant numeric value from AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            inner = self._const_value(node.operand)
            return -inner if inner is not None else None
        return None

    def _binop_result(self, name: str, op: ast.operator,
                      left: Optional[SymbolicValue],
                      right: Optional[SymbolicValue]) -> SymbolicValue:
        """Compute the result of a binary operation on symbolic values."""
        if not left or not right:
            return SymbolicValue(name, 'unknown')

        if left.vtype in ('int', 'float') and right.vtype in ('int', 'float'):
            rtype = 'float' if 'float' in (left.vtype, right.vtype) else 'int'

            if isinstance(op, ast.Add):
                lo = (left.min_val + right.min_val) if left.min_val is not None and right.min_val is not None else None
                hi = (left.max_val + right.max_val) if left.max_val is not None and right.max_val is not None else None
                return SymbolicValue(name, rtype, lo, hi)
            elif isinstance(op, ast.Sub):
                lo = (left.min_val - right.max_val) if left.min_val is not None and right.max_val is not None else None
                hi = (left.max_val - right.min_val) if left.max_val is not None and right.min_val is not None else None
                return SymbolicValue(name, rtype, lo, hi)
            elif isinstance(op, ast.Mult):
                if left.min_val is not None and left.max_val is not None and \
                   right.min_val is not None and right.max_val is not None:
                    products = [left.min_val * right.min_val, left.min_val * right.max_val,
                                left.max_val * right.min_val, left.max_val * right.max_val]
                    return SymbolicValue(name, rtype, min(products), max(products))
            elif isinstance(op, ast.Pow):
                if left.max_val is not None and right.max_val is not None:
                    try:
                        hi = left.max_val ** right.max_val
                        return SymbolicValue(name, rtype, 0, hi)
                    except (OverflowError, ValueError):
                        return SymbolicValue(name, rtype, 0, float('inf'))

        return SymbolicValue(name, 'unknown')

    def _explore_paths(self, tree: ast.Module):
        """Phase 2: Enumerate execution paths through if/elif/else."""
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                cond_str = ast.unparse(node.test)[:60]

                # True branch
                true_path = PathConstraint([cond_str])
                self.paths.append(true_path)

                # False branch
                false_path = PathConstraint()
                false_path.add_condition(cond_str, negated=True)

                # Check if any branch is trivially dead
                const = self._eval_const_condition(node.test)
                if const is True:
                    false_path.reachable = False
                    self.findings.append(SymbolicFinding(
                        'dead_branch', node.lineno,
                        f'else-branch is dead: condition "{cond_str}" is always True',
                        'LOW'
                    ))
                elif const is False:
                    true_path.reachable = False
                    self.findings.append(SymbolicFinding(
                        'dead_branch', node.lineno,
                        f'if-branch is dead: condition "{cond_str}" is always False',
                        'LOW'
                    ))

                if node.orelse:
                    self.paths.append(false_path)

                # Narrow variables in true branch
                self._narrow_from_condition(node.test, negated=False)

    def _eval_const_condition(self, test: ast.expr) -> Optional[bool]:
        """Try to evaluate a condition as constant True/False."""
        # Simple cases: True, False, 0, 1
        if isinstance(test, ast.Constant):
            return bool(test.value)

        # x > 0 where x is known positive
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            left = test.left
            right = test.comparators[0]
            op = type(test.ops[0]).__name__

            if isinstance(left, ast.Name) and left.id in self.variables:
                sv = self.variables[left.id]
                rhs_val = self._const_value(right)

                if rhs_val is not None:
                    if op == 'Gt' and sv.min_val is not None and sv.min_val > rhs_val:
                        return True
                    if op == 'Lt' and sv.max_val is not None and sv.max_val < rhs_val:
                        return True
                    if op == 'Gt' and sv.max_val is not None and sv.max_val <= rhs_val:
                        return False
                    if op == 'Lt' and sv.min_val is not None and sv.min_val >= rhs_val:
                        return False
                    if op == 'Eq' and sv.possible_values and rhs_val not in sv.possible_values:
                        return False

        return None

    def _narrow_from_condition(self, test: ast.expr, negated: bool):
        """Narrow variable constraints based on a branch condition."""
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            left = test.left
            right = test.comparators[0]
            op = type(test.ops[0]).__name__

            if isinstance(left, ast.Name) and left.id in self.variables:
                rhs_sv = self._value_from_node('_rhs', right)
                if rhs_sv:
                    if negated:
                        # Invert the operator
                        invert = {'Gt': 'LtE', 'Lt': 'GtE', 'GtE': 'Lt', 'LtE': 'Gt',
                                   'Eq': 'NotEq', 'NotEq': 'Eq'}
                        op = invert.get(op, op)
                    self.variables[left.id] = self.variables[left.id].narrow(op, rhs_sv)

    def _check_divisions(self, tree: ast.Module):
        """Check for potential division by zero."""
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                # Check if divisor can be zero
                if isinstance(node.right, ast.Name):
                    sv = self.variables.get(node.right.id)
                    if sv and sv.can_be_zero():
                        self.findings.append(SymbolicFinding(
                            'division_by_zero', node.lineno,
                            f'Possible division by zero: {node.right.id} can be 0',
                            'HIGH'
                        ))
                elif isinstance(node.right, ast.Constant):
                    if node.right.value == 0:
                        self.findings.append(SymbolicFinding(
                            'division_by_zero', node.lineno,
                            'Division by literal zero',
                            'CRITICAL'
                        ))

    def _check_overflows(self, tree: ast.Module):
        """Check for potential integer overflows."""
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp):
                if isinstance(node.op, (ast.Mult, ast.Pow, ast.LShift)):
                    result = self._value_from_node('_result', node)
                    if result and result.can_overflow_32():
                        self.findings.append(SymbolicFinding(
                            'integer_overflow', node.lineno,
                            f'Result may exceed 32-bit integer range',
                            'MEDIUM'
                        ))
                    if result and result.can_overflow_64():
                        self.findings.append(SymbolicFinding(
                            'integer_overflow', node.lineno,
                            f'Result may exceed 64-bit integer range',
                            'HIGH'
                        ))

            # Check for struct.pack with values that may overflow
            if isinstance(node, ast.Call):
                name = ''
                if isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    name = node.func.id

                if name == 'pack' and node.args:
                    fmt_node = node.args[0]
                    if isinstance(fmt_node, ast.Constant) and isinstance(fmt_node.value, str):
                        fmt = fmt_node.value
                        if 'H' in fmt or 'h' in fmt:  # 16-bit
                            for arg in node.args[1:]:
                                sv = self._value_from_node('_arg', arg)
                                if sv and sv.max_val is not None and sv.max_val > 65535:
                                    self.findings.append(SymbolicFinding(
                                        'pack_overflow', node.lineno,
                                        f'Value may exceed uint16 range in struct.pack',
                                        'HIGH'
                                    ))

    def _check_loop_bounds(self, tree: ast.Module):
        """Check for potentially unbounded or infinite loops."""
        for node in ast.walk(tree):
            if isinstance(node, ast.While):
                # while True without break
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    has_break = any(isinstance(n, ast.Break) for n in ast.walk(node))
                    if not has_break:
                        self.findings.append(SymbolicFinding(
                            'infinite_loop', node.lineno,
                            'while True loop without break statement',
                            'MEDIUM'
                        ))

                # while condition that never changes
                if isinstance(node.test, ast.Compare):
                    test_vars = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
                    # Check if any test variable is modified in the loop body
                    modified = set()
                    for child in ast.walk(node):
                        if isinstance(child, ast.Assign):
                            for t in child.targets:
                                if isinstance(t, ast.Name):
                                    modified.add(t.id)
                        elif isinstance(child, ast.AugAssign):
                            if isinstance(child.target, ast.Name):
                                modified.add(child.target.id)

                    if test_vars and not (test_vars & modified):
                        self.findings.append(SymbolicFinding(
                            'infinite_loop', node.lineno,
                            f'Loop condition vars {test_vars} never modified in body',
                            'HIGH'
                        ))

    def _check_index_bounds(self, tree: ast.Module):
        """Check for potential index-out-of-bounds access."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int):
                    idx = node.slice.value
                    if isinstance(node.value, ast.Name):
                        sv = self.variables.get(node.value.id)
                        if sv and sv.vtype == 'list':
                            if sv.max_val is not None and idx >= sv.max_val:
                                self.findings.append(SymbolicFinding(
                                    'index_out_of_bounds', node.lineno,
                                    f'Index {idx} may exceed list size ({sv.max_val})',
                                    'HIGH'
                                ))
                            if idx < 0 and sv.min_val is not None and abs(idx) > sv.max_val:
                                self.findings.append(SymbolicFinding(
                                    'index_out_of_bounds', node.lineno,
                                    f'Negative index {idx} may underflow list size ({sv.max_val})',
                                    'HIGH'
                                ))

    def _check_type_errors(self, tree: ast.Module):
        """Check for obvious type mismatches."""
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp):
                left_sv = self._value_from_node('_l', node.left) if isinstance(node.left, ast.Name) else None
                right_sv = self._value_from_node('_r', node.right) if isinstance(node.right, ast.Name) else None

                if isinstance(node.left, ast.Name):
                    left_sv = self.variables.get(node.left.id)
                if isinstance(node.right, ast.Name):
                    right_sv = self.variables.get(node.right.id)

                if left_sv and right_sv:
                    if isinstance(node.op, (ast.Add, ast.Sub)):
                        if left_sv.vtype == 'str' and right_sv.vtype in ('int', 'float'):
                            self.findings.append(SymbolicFinding(
                                'type_error', node.lineno,
                                f'Cannot {type(node.op).__name__.lower()} str and {right_sv.vtype}',
                                'HIGH'
                            ))

    def _summarize(self) -> Dict[str, Any]:
        """Summarize analysis results."""
        by_type = {}
        by_severity = {}
        for f in self.findings:
            by_type[f.type] = by_type.get(f.type, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        dead_paths = sum(1 for p in self.paths if not p.reachable)

        return {
            'total_findings': len(self.findings),
            'by_type': by_type,
            'by_severity': by_severity,
            'variables_tracked': len(self.variables),
            'paths_explored': len(self.paths),
            'dead_paths': dead_paths,
        }
