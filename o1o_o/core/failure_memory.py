"""
Failure Memory — FORGE learns from its mistakes

When scripts fail, stores (error_signature → context).
When a fix works, stores (error_signature → fix_strategy).
After N similar errors, extracts a reusable auto-fix pattern.

Unlike the hardcoded 12 strategies in executor.py, failure memory
grows organically from actual errors encountered during self-improvement.

Storage: knowledge/failure_patterns.json
"""
# Dependencies: none
# Depended by: executor, self_improve


import re
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from collections import defaultdict


class FailureMemory:
    """Learn from script failures and build a fix knowledge base.

    v2: Inverse Inference Engine
    - Build reverse index: error_signature → code_patterns_that_cause_it
    - Generate hypotheses: "What code produces this error?"
    - Useful for finding root causes (backward search through error space)
    """

    # Minimum occurrences before a pattern is promoted to a fix strategy
    PROMOTION_THRESHOLD = 3

    def __init__(self, storage_path: str = None):
        """
        Args:
            storage_path: Path to failure_patterns.json. If None, uses
                          default location relative to forge root.
        """
        if storage_path is None:
            base = Path(__file__).parent.parent / 'knowledge'
            storage_path = str(base / 'failure_patterns.json')

        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

        # Load existing patterns
        self.patterns = self._load()

        # In-memory index: error_signature → list of fix strategies
        self.fix_index = self._build_fix_index()

        # Stats
        self.stats = {
            'failures_recorded': 0,
            'fixes_recorded': 0,
            'patterns_promoted': 0,
            'fix_hits': 0,
        }

    def _load(self) -> Dict[str, Any]:
        """Load failure patterns from disk."""
        if self.storage_path.exists():
            try:
                with open(self.storage_path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {
            'errors': {},      # signature → {count, contexts, fixes}
            'fix_strategies': {},  # signature → {fix_type, fix_data, success_count}
            'version': 1,
        }

    def save(self):
        """Persist failure patterns to disk."""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(self.patterns, f, indent=2, default=str)
        except IOError:
            pass

    def _build_fix_index(self) -> Dict[str, List[Dict]]:
        """Build in-memory index of known fixes."""
        index = defaultdict(list)
        for sig, strategy in self.patterns.get('fix_strategies', {}).items():
            index[sig].append(strategy)
        return dict(index)

    # ── Recording ────────────────────────────────────────────────────

    def record_failure(self, error_type: str, stderr: str,
                       intent_raw: str, script: str, fragment_key: str = ''):
        """Record a script failure for pattern analysis.

        Args:
            error_type: Parsed error type (e.g., 'FileNotFoundError')
            stderr: Full stderr output
            intent_raw: Original task text
            script: The script that failed
            fragment_key: Which fragment was used (optional)
        """
        signature = self._compute_signature(error_type, stderr)

        errors = self.patterns.setdefault('errors', {})
        if signature not in errors:
            errors[signature] = {
                'error_type': error_type,
                'message_pattern': self._extract_message_pattern(stderr),
                'count': 0,
                'contexts': [],
                'fixes': [],
            }

        entry = errors[signature]
        entry['count'] += 1

        # Store context (limited to prevent unbounded growth)
        if len(entry['contexts']) < 10:
            entry['contexts'].append({
                'intent': intent_raw[:200],
                'fragment': fragment_key,
                'stderr_head': stderr[:300],
            })

        self.stats['failures_recorded'] += 1

    def record_fix(self, error_type: str, stderr: str,
                   original_script: str, fixed_script: str,
                   fix_description: str = ''):
        """Record a successful fix for an error pattern.

        Args:
            error_type: Error type that was fixed
            stderr: The stderr that triggered the fix
            original_script: Script before fix
            fixed_script: Script after fix (working)
            fix_description: Human-readable fix description
        """
        signature = self._compute_signature(error_type, stderr)

        # Compute the diff (what changed)
        diff = self._compute_fix_diff(original_script, fixed_script)
        if not diff:
            return

        # Record in errors entry
        errors = self.patterns.setdefault('errors', {})
        if signature in errors:
            fixes = errors[signature].setdefault('fixes', [])
            if len(fixes) < 20:
                fixes.append({
                    'diff': diff,
                    'description': fix_description,
                })

        # Check if we should promote to fix strategy
        if signature in errors and len(errors[signature].get('fixes', [])) >= self.PROMOTION_THRESHOLD:
            self._promote_to_strategy(signature, errors[signature])

        self.stats['fixes_recorded'] += 1

    # ── Lookup ───────────────────────────────────────────────────────

    def lookup_fix(self, error_type: str, stderr: str,
                   script: str) -> Optional[str]:
        """Look up a known fix for this error pattern.

        Args:
            error_type: Error type string
            stderr: Full stderr
            script: The failing script

        Returns:
            Fixed script, or None if no fix known
        """
        signature = self._compute_signature(error_type, stderr)

        # Check promoted fix strategies first
        if signature in self.fix_index:
            for strategy in self.fix_index[signature]:
                fixed = self._apply_strategy(strategy, script, stderr)
                if fixed and fixed != script:
                    self.stats['fix_hits'] += 1
                    return fixed

        # Check raw fix diffs from error records
        errors = self.patterns.get('errors', {})
        if signature in errors:
            for fix_record in errors[signature].get('fixes', []):
                fixed = self._apply_diff(fix_record['diff'], script)
                if fixed and fixed != script:
                    self.stats['fix_hits'] += 1
                    return fixed

        # Try fuzzy match (same error_type, similar message)
        for sig, entry in errors.items():
            if entry.get('error_type') == error_type and sig != signature:
                for fix_record in entry.get('fixes', []):
                    fixed = self._apply_diff(fix_record['diff'], script)
                    if fixed and fixed != script:
                        self.stats['fix_hits'] += 1
                        return fixed

        return None

    def get_stats(self) -> Dict[str, Any]:
        """Return failure memory statistics."""
        errors = self.patterns.get('errors', {})
        strategies = self.patterns.get('fix_strategies', {})

        return {
            **self.stats,
            'total_error_patterns': len(errors),
            'total_fix_strategies': len(strategies),
            'top_errors': sorted(
                [(sig, e['count'], e['error_type'])
                 for sig, e in errors.items()],
                key=lambda x: -x[1]
            )[:10],
        }

    # ── INVERSE INFERENCE: Error → Code Hypothesis ───────────────

    def generate_hypotheses(self, error_type: str, stderr: str) -> List[Dict[str, Any]]:
        """Generate code hypotheses that would produce this error.

        INVERSE INFERENCE: backward search through error space.
        Returns ranked hypotheses of "what code causes this error?"

        Returns:
            [
                {'hypothesis': str, 'confidence': 0.0-1.0, 'fix_if_wrong': str},
                ...
            ]
        """
        hypotheses = []

        # Pattern 1: NameError → undefined variable
        if 'NameError' in error_type:
            match = re.search(r"name '(\w+)' is not defined", stderr)
            if match:
                var_name = match.group(1)
                hypotheses.append({
                    'hypothesis': f'Variable "{var_name}" is not defined — initialize it before use',
                    'confidence': 0.9,
                    'fix_if_wrong': f'{var_name} = None  # or other default',
                    'fix_type': 'init_variable',
                })

        # Pattern 2: TypeError: int + str → type mismatch
        if 'TypeError' in error_type:
            if 'int' in stderr and 'str' in stderr:
                hypotheses.append({
                    'hypothesis': 'Type mismatch: mixing int and str — coerce one of them',
                    'confidence': 0.85,
                    'fix_if_wrong': 'use str(var) or int(var) to coerce types',
                    'fix_type': 'type_coercion',
                })

        # Pattern 3: FileNotFoundError → file doesn't exist
        if 'FileNotFoundError' in error_type:
            match = re.search(r"No such file or directory: '(.+?)'", stderr)
            if match:
                filepath = match.group(1)
                hypotheses.append({
                    'hypothesis': f'File "{filepath}" doesn\'t exist — create directory or check path',
                    'confidence': 0.9,
                    'fix_if_wrong': f'os.makedirs(os.path.dirname("{filepath}"), exist_ok=True)',
                    'fix_type': 'create_directory',
                })

        # Pattern 4: ModuleNotFoundError → missing import
        if 'ModuleNotFoundError' in error_type:
            match = re.search(r"No module named '(.+?)'", stderr)
            if match:
                module = match.group(1)
                hypotheses.append({
                    'hypothesis': f'Module "{module}" is not installed',
                    'confidence': 0.95,
                    'fix_if_wrong': f'pip install {module}',
                    'fix_type': 'add_import',
                })

        # Pattern 5: KeyError → dict key missing
        if 'KeyError' in error_type:
            match = re.search(r"KeyError: '(.+?)'", stderr)
            if match:
                key = match.group(1)
                hypotheses.append({
                    'hypothesis': f'Dictionary key "{key}" doesn\'t exist — use dict.get() instead of dict[]',
                    'confidence': 0.85,
                    'fix_if_wrong': f'data.get("{key}", default_value)',
                    'fix_type': 'dict_get_default',
                })

        # Pattern 6: AttributeError → missing attribute
        if 'AttributeError' in error_type:
            match = re.search(r"has no attribute '(.+?)'", stderr)
            if match:
                attr = match.group(1)
                hypotheses.append({
                    'hypothesis': f'Object doesn\'t have attribute "{attr}" — check object type or spelling',
                    'confidence': 0.8,
                    'fix_if_wrong': 'verify object construction or use hasattr() for optional attrs',
                    'fix_type': 'null_check',
                })

        # Pattern 7: Encoding issues → use encoding parameter
        if 'UnicodeDecodeError' in error_type or 'UnicodeEncodeError' in error_type:
            hypotheses.append({
                'hypothesis': 'Character encoding mismatch — specify encoding=\'utf-8\'',
                'confidence': 0.85,
                'fix_if_wrong': 'open(file, encoding="utf-8")',
                'fix_type': 'add_encoding',
            })

        # Pattern 8: ZeroDivisionError → division by zero
        if 'ZeroDivisionError' in error_type:
            hypotheses.append({
                'hypothesis': 'Division by zero — add zero check before division',
                'confidence': 0.95,
                'fix_if_wrong': 'if divisor != 0: result = numerator / divisor',
                'fix_type': 'add_try_except',
            })

        # Pattern 9: IndexError → array index out of bounds
        if 'IndexError' in error_type:
            hypotheses.append({
                'hypothesis': 'Index out of bounds — check array length before accessing',
                'confidence': 0.9,
                'fix_if_wrong': 'if index < len(array): value = array[index]',
                'fix_type': 'null_check',
            })

        # Pattern 10: IndentationError → syntax (not runtime), but still useful
        if 'IndentationError' in error_type:
            hypotheses.append({
                'hypothesis': 'Indentation error — check that all blocks have consistent 4-space indentation',
                'confidence': 0.95,
                'fix_if_wrong': 'Verify all if/for/while/def blocks are indented with 4 spaces',
                'fix_type': 'general',
            })

        # Sort by confidence
        hypotheses.sort(key=lambda h: -h['confidence'])
        return hypotheses

    def generate_hypotheses_from_context(self, error_type: str, stderr: str,
                                        failed_code: str) -> List[Dict[str, Any]]:
        """Generate more specific hypotheses using code context.

        Analyzes the failed code to suggest concrete fixes.
        """
        hypotheses = self.generate_hypotheses(error_type, stderr)

        # Add code-specific analysis
        if not hypotheses:
            # Generic fallback based on error type
            error_class = error_type.split(':')[0]
            hypotheses.append({
                'hypothesis': f'Error "{error_class}" occurred — examine the stack trace for clues',
                'confidence': 0.5,
                'fix_if_wrong': 'Add try/except for detailed error handling',
                'fix_type': 'add_try_except',
            })

        return hypotheses

    # ── Private: Signature computation ───────────────────────────────

    def _compute_signature(self, error_type: str, stderr: str) -> str:
        """Compute a stable signature for an error pattern.

        Normalizes line numbers, paths, and variable names to group
        similar errors together.
        """
        # Extract the key error message (last line of traceback)
        msg = self._extract_message_pattern(stderr)

        # Combine error type + normalized message
        key = f"{error_type}::{msg}"
        return hashlib.md5(key.encode()).hexdigest()[:12]

    def _extract_message_pattern(self, stderr: str) -> str:
        """Extract and normalize the error message from stderr.

        Strips line numbers, file paths, and specific values to get
        a generalizable pattern.
        """
        if not stderr:
            return ''

        # Get the last meaningful line (usually the actual error)
        lines = stderr.strip().split('\n')
        msg_line = ''
        for line in reversed(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith('File '):
                msg_line = stripped
                break

        if not msg_line:
            msg_line = lines[-1].strip() if lines else ''

        # Normalize: remove specific values
        normalized = msg_line

        # Remove file paths
        normalized = re.sub(r'/[\w/._-]+', '<PATH>', normalized)

        # Remove specific quoted strings
        normalized = re.sub(r"'[^']{1,50}'", "'<VAL>'", normalized)
        normalized = re.sub(r'"[^"]{1,50}"', '"<VAL>"', normalized)

        # Remove specific line numbers
        normalized = re.sub(r'line \d+', 'line <N>', normalized)

        # Remove specific numbers
        normalized = re.sub(r'\b\d{2,}\b', '<N>', normalized)

        return normalized

    # ── Private: Diff computation ────────────────────────────────────

    def _compute_fix_diff(self, original: str, fixed: str) -> Optional[Dict]:
        """Compute a structured diff between original and fixed scripts.

        Returns a dict describing the transformation, not a raw text diff.
        """
        orig_lines = original.split('\n')
        fixed_lines = fixed.split('\n')

        # Find added lines
        added = []
        removed = []

        orig_set = set(l.strip() for l in orig_lines if l.strip())
        fixed_set = set(l.strip() for l in fixed_lines if l.strip())

        for line in fixed_set - orig_set:
            added.append(line)
        for line in orig_set - fixed_set:
            removed.append(line)

        if not added and not removed:
            return None

        # Classify the fix type
        fix_type = self._classify_fix(added, removed)

        return {
            'type': fix_type,
            'added': added[:10],  # Cap at 10 lines
            'removed': removed[:10],
        }

    def _classify_fix(self, added: List[str], removed: List[str]) -> str:
        """Classify what kind of fix was applied."""
        added_text = ' '.join(added)

        if any('import ' in a for a in added):
            return 'add_import'
        if any('pip install' in a for a in added):
            return 'install_package'
        if any('os.makedirs' in a or 'mkdir' in a for a in added):
            return 'create_directory'
        if any('try:' in a or 'except' in a for a in added):
            return 'add_try_except'
        if any('.get(' in a for a in added) and any('[' in r and ']' in r for r in removed):
            return 'dict_get_default'
        if any('encoding=' in a for a in added):
            return 'add_encoding'
        if any('= None' in a or '= ""' in a or '= []' in a for a in added):
            return 'init_variable'
        if any('if ' in a and 'is not None' in a for a in added):
            return 'null_check'
        if any('open(' in a and 'w' in a for a in added):
            return 'create_file'
        if 'str(' in added_text:
            return 'type_coercion'

        return 'general'

    # ── Private: Fix application ─────────────────────────────────────

    def _promote_to_strategy(self, signature: str, error_entry: Dict):
        """Promote a frequently-fixed error pattern to a fix strategy."""
        fixes = error_entry.get('fixes', [])
        if not fixes:
            return

        # Find the most common fix type
        fix_types = defaultdict(int)
        for fix in fixes:
            diff = fix.get('diff', {})
            fix_types[diff.get('type', 'unknown')] += 1

        best_type = max(fix_types, key=fix_types.get)

        # Find a representative fix of that type
        representative = None
        for fix in fixes:
            if fix.get('diff', {}).get('type') == best_type:
                representative = fix
                break

        if not representative:
            return

        strategies = self.patterns.setdefault('fix_strategies', {})
        if signature not in strategies:
            strategies[signature] = {
                'error_type': error_entry['error_type'],
                'message_pattern': error_entry.get('message_pattern', ''),
                'fix_type': best_type,
                'fix_data': representative['diff'],
                'success_count': len(fixes),
                'promoted_from_count': error_entry['count'],
            }
            self.stats['patterns_promoted'] += 1

            # Rebuild index
            self.fix_index = self._build_fix_index()

    def _apply_strategy(self, strategy: Dict, script: str, stderr: str) -> Optional[str]:
        """Apply a promoted fix strategy to a script."""
        fix_type = strategy.get('fix_type', '')
        fix_data = strategy.get('fix_data', {})

        return self._apply_fix_by_type(fix_type, fix_data, script, stderr)

    def _apply_diff(self, diff: Dict, script: str) -> Optional[str]:
        """Apply a raw fix diff to a script."""
        if not diff:
            return None

        fix_type = diff.get('type', 'general')
        return self._apply_fix_by_type(fix_type, diff, script, '')

    def _apply_fix_by_type(self, fix_type: str, fix_data: Dict,
                           script: str, stderr: str) -> Optional[str]:
        """Apply a fix based on its classified type."""
        added = fix_data.get('added', [])

        if fix_type == 'add_import':
            # Add missing import lines after existing imports
            lines = script.split('\n')
            last_import = 0
            for i, line in enumerate(lines):
                if line.startswith('import ') or line.startswith('from '):
                    last_import = i
            for imp_line in added:
                if imp_line.startswith(('import ', 'from ')):
                    if imp_line.strip() not in script:
                        last_import += 1
                        lines.insert(last_import, imp_line)
            result = '\n'.join(lines)
            return result if result != script else None

        elif fix_type == 'create_directory':
            # Add os.makedirs before file operations
            if 'os.makedirs' not in script:
                lines = script.split('\n')
                last_import = 0
                has_os = False
                for i, line in enumerate(lines):
                    if line.startswith('import ') or line.startswith('from '):
                        last_import = i
                        if 'import os' in line:
                            has_os = True
                if not has_os:
                    lines.insert(last_import + 1, 'import os')
                # Add makedirs for each directory reference
                for add_line in added:
                    if 'makedirs' in add_line and add_line.strip() not in script:
                        lines.insert(last_import + 2, add_line)
                return '\n'.join(lines)

        elif fix_type == 'init_variable':
            # Add variable initialization
            lines = script.split('\n')
            last_import = 0
            for i, line in enumerate(lines):
                if line.startswith('import ') or line.startswith('from '):
                    last_import = i
            for init_line in added:
                if '=' in init_line and init_line.strip() not in script:
                    lines.insert(last_import + 1, init_line)
            result = '\n'.join(lines)
            return result if result != script else None

        elif fix_type == 'add_try_except':
            # Wrap error-prone lines in try/except
            # This is harder to generalize — just add the lines
            for add_line in added:
                if add_line.strip() not in script:
                    script += '\n' + add_line
            return script

        elif fix_type == 'add_encoding':
            # Add encoding parameter to open() calls
            if 'encoding=' not in script:
                script = re.sub(
                    r"open\(([^)]+)\)",
                    lambda m: m.group(0) if 'encoding' in m.group(0) else
                    f"open({m.group(1)}, encoding='utf-8')",
                    script
                )
                return script

        # General: try to apply added lines
        if added:
            lines = script.split('\n')
            last_import = 0
            for i, line in enumerate(lines):
                if line.startswith('import ') or line.startswith('from '):
                    last_import = i
            for add_line in added:
                if add_line.strip() and add_line.strip() not in script:
                    lines.insert(last_import + 1, add_line)
            result = '\n'.join(lines)
            if result != script:
                return result

        return None
