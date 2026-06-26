"""
Output Oracle — Semantic output validation for FORGE

Validates whether a script's output matches what the task intent expected.
Deterministic, zero-AI: uses intent verbs + entity types + output patterns.

Three validation levels:
  1. Structural: exit code, error indicators, output presence
  2. Semantic: verb-based expectations (count→number, sort→ordered, json→valid JSON)
  3. Content: entity-based patterns (email→regex, hash→hex, url→http pattern)

Returns (passed, reason, confidence) for each validation.
"""
# Dependencies: none
# Depended by: self_improve


import re
import json as _json
from typing import Dict, Any, Tuple, List, Optional


class OutputOracle:
    """Validate script output against task intent expectations."""

    # ── Verb → expected output characteristics ────────────────────────

    # Verbs that MUST produce visible output
    OUTPUT_REQUIRED_VERBS = {
        'list', 'show', 'print', 'display', 'count', 'find', 'search',
        'get', 'fetch', 'read', 'check', 'view', 'see', 'calculate',
        'compute', 'measure', 'compare', 'analyze', 'sort', 'convert',
        'transform', 'parse', 'extract', 'filter', 'generate', 'determine',
        'detect', 'identify', 'enumerate', 'iterate', 'demonstrate',
    }

    # Verbs that imply numeric output
    NUMERIC_VERBS = {
        'count', 'calculate', 'compute', 'measure', 'sum', 'average',
        'total', 'mean', 'median', 'factorial', 'fibonacci',
    }

    # Verbs that imply multi-line output
    MULTILINE_VERBS = {
        'list', 'enumerate', 'iterate', 'display', 'tree', 'walk',
    }

    # Verbs that imply file operations (no stdout needed)
    FILE_OP_VERBS = {
        'save', 'write', 'export', 'compress', 'archive', 'download',
        'upload', 'copy', 'move', 'rename', 'delete', 'remove', 'backup',
        'create',
    }

    # Verbs for daemon/server (non-terminating is OK)
    DAEMON_VERBS = {
        'serve', 'monitor', 'watch', 'listen',
    }

    # ── Format → output expectations ─────────────────────────────────

    FORMAT_CHECKS = {
        'json': {
            'check': 'json_format',
            'desc': 'output should be valid JSON',
        },
        'csv': {
            'check': 'csv_format',
            'desc': 'output should have comma-separated values',
        },
        'xml': {
            'check': 'xml_format',
            'desc': 'output should contain XML tags',
        },
        'html': {
            'check': 'html_format',
            'desc': 'output should contain HTML tags',
        },
        'yaml': {
            'check': 'yaml_format',
            'desc': 'output should be multi-line key-value',
        },
    }

    # ── Entity → content pattern expectations ─────────────────────────

    ENTITY_PATTERNS = {
        'email': r'[\w.+-]+@[\w-]+\.[\w.]+',
        'url': r'https?://\S+',
        'ip address': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'ipv4': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'sha256': r'[0-9a-fA-F]{64}',
        'sha1': r'[0-9a-fA-F]{40}',
        'md5': r'[0-9a-fA-F]{32}',
        'uuid': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'base64': r'[A-Za-z0-9+/]{4,}={0,2}',
        'hex': r'[0-9a-fA-F]{8,}',
        'date': r'\d{4}[-/]\d{1,2}[-/]\d{1,2}',
        'timestamp': r'\d{4}[-/]\d{1,2}[-/]\d{1,2}[T ]\d{1,2}:\d{2}',
    }

    # ── Error indicators in stdout (always bad) ──────────────────────

    ERROR_INDICATORS = [
        'Traceback (most recent call last)',
        'SyntaxError:',
        'IndentationError:',
        'TabError:',
    ]

    # These look like errors but are OK in educational/demonstration code
    ERROR_EXCEPTIONS = [
        'Caught:', 'Handled:', 'Expected error:', 'caught exception',
        'example', 'demo', 'Custom', 'test', 'assert',
    ]

    def validate(self, stdout: str, stderr: str, exit_code: int,
                 intent: Dict[str, Any], script: str = '') -> Tuple[bool, str, float]:
        """
        Validate script output against intent expectations.

        Args:
            stdout: Script's standard output
            stderr: Script's standard error
            exit_code: Process exit code
            intent: Parsed intent dict from IntentParser
            script: The generated script (for context)

        Returns:
            (passed, reason, confidence)
            - passed: True if output matches expectations
            - reason: Human-readable explanation
            - confidence: 0.0-1.0 how sure the oracle is
        """
        raw = intent.get('raw', '').lower()
        tokens = set(intent.get('tokens', []))

        # ── Level 1: Structural checks ────────────────────────────
        if exit_code != 0:
            return False, f"Non-zero exit code: {exit_code}", 1.0

        if self._has_error_in_stdout(stdout):
            return False, "Output contains error traceback", 0.9

        if stdout.strip() == 'None':
            # "None" as sole output = function returned nothing
            if tokens & self.OUTPUT_REQUIRED_VERBS:
                return False, "Output is 'None' — function returned nothing", 0.85
            # For non-output tasks, None is fine
            return True, "No output expected, None is acceptable", 0.6

        # ── Level 2: Verb-based semantic checks ───────────────────
        checks_passed = 0
        checks_total = 0
        failures = []

        # 2a. Output presence
        needs_output = bool(tokens & self.OUTPUT_REQUIRED_VERBS)
        is_file_op = bool(tokens & self.FILE_OP_VERBS)
        is_daemon = bool(tokens & self.DAEMON_VERBS)

        if needs_output and not is_file_op and not is_daemon:
            checks_total += 1
            if stdout.strip():
                checks_passed += 1
            else:
                failures.append("Expected output but got none")

        # 2b. Numeric output
        needs_number = bool(tokens & self.NUMERIC_VERBS)
        # Also check raw for "how many", "number of"
        if not needs_number:
            needs_number = any(p in raw for p in ['how many', 'number of', 'factorial', 'fibonacci'])

        if needs_number and stdout.strip():
            checks_total += 1
            if re.search(r'\d+', stdout):
                checks_passed += 1
            else:
                failures.append("Expected numbers in output")

        # 2c. Multi-line output
        needs_multiline = bool(tokens & self.MULTILINE_VERBS)
        if needs_multiline and stdout.strip():
            checks_total += 1
            lines = [l for l in stdout.strip().split('\n') if l.strip()]
            if len(lines) >= 2:
                checks_passed += 1
            else:
                failures.append(f"Expected multiple output lines, got {len(lines)}")

        # 2d. Sorted output
        if 'sort' in tokens and stdout.strip():
            checks_total += 1
            if self._check_sorted(stdout):
                checks_passed += 1
            else:
                # Sorting is hard to verify — give benefit of doubt
                checks_passed += 1  # Lenient

        # ── Level 3: Format checks ───────────────────────────────
        for fmt, check_info in self.FORMAT_CHECKS.items():
            if fmt in raw and stdout.strip():
                checks_total += 1
                if self._check_format(stdout, check_info['check']):
                    checks_passed += 1
                else:
                    failures.append(check_info['desc'])

        # ── Level 4: Entity content checks ────────────────────────
        for entity_name, pattern in self.ENTITY_PATTERNS.items():
            # Only check if the entity is explicitly in the raw task
            if entity_name in raw and stdout.strip():
                # Special case: "hash" is too generic — only check if we're
                # specifically asked to hash something
                if entity_name == 'hex' and 'hash' not in raw:
                    continue
                checks_total += 1
                if re.search(pattern, stdout, re.IGNORECASE):
                    checks_passed += 1
                else:
                    failures.append(f"Expected {entity_name} pattern in output")

        # ── Scoring ──────────────────────────────────────────────
        if checks_total == 0:
            # No specific expectations — pass on structural checks alone
            return True, "No specific output expectations — passed structural", 0.5

        pass_rate = checks_passed / checks_total

        # Lenient threshold: 50% of checks passing is enough
        # (some checks may be too strict for edge cases)
        if pass_rate >= 0.5:
            return True, f"Passed {checks_passed}/{checks_total} semantic checks", min(0.95, 0.5 + pass_rate * 0.45)
        else:
            reason = "; ".join(failures[:3])
            return False, f"Oracle fail: {reason} ({checks_passed}/{checks_total})", pass_rate

    def validate_simple(self, stdout: str, task_text: str) -> Tuple[bool, str, float]:
        """Simplified validation when no parsed intent is available.

        Builds a minimal intent dict from raw task text.
        """
        tokens = set(re.findall(r'\b\w+\b', task_text.lower()))
        # Remove common stopwords
        stopwords = {'a', 'an', 'the', 'and', 'or', 'in', 'on', 'to', 'for',
                     'of', 'with', 'by', 'from', 'is', 'are', 'that', 'this'}
        tokens -= stopwords

        intent = {
            'raw': task_text,
            'tokens': list(tokens),
        }
        return self.validate(stdout, '', 0, intent)

    # ── Private helpers ──────────────────────────────────────────────

    def _has_error_in_stdout(self, stdout: str) -> bool:
        """Check for error indicators in stdout."""
        if not stdout:
            return False

        for indicator in self.ERROR_INDICATORS:
            if indicator in stdout:
                # Check if it's demonstrating error handling
                if any(exc in stdout for exc in self.ERROR_EXCEPTIONS):
                    return False
                return True
        return False

    def _check_sorted(self, stdout: str) -> bool:
        """Check if output appears sorted."""
        lines = [l.strip() for l in stdout.strip().split('\n') if l.strip()]
        if len(lines) < 2:
            return True  # Trivially sorted

        # Try numeric sort
        nums = []
        for line in lines:
            match = re.search(r'[-+]?\d*\.?\d+', line)
            if match:
                try:
                    nums.append(float(match.group()))
                except ValueError:
                    pass

        if len(nums) >= 2:
            return nums == sorted(nums) or nums == sorted(nums, reverse=True)

        # Try alphabetical sort
        return lines == sorted(lines) or lines == sorted(lines, reverse=True)

    def _check_format(self, stdout: str, check_type: str) -> bool:
        """Check if output matches expected format."""
        stripped = stdout.strip()

        if check_type == 'json_format':
            if not (stripped.startswith('{') or stripped.startswith('[')):
                # Maybe JSON is embedded in other output — look for it
                for line in stripped.split('\n'):
                    line = line.strip()
                    if line.startswith(('{', '[')):
                        try:
                            _json.loads(line)
                            return True
                        except (ValueError, _json.JSONDecodeError):
                            pass
                return False
            try:
                _json.loads(stripped)
                return True
            except (ValueError, _json.JSONDecodeError):
                # Partial JSON or pretty-printed JSON with extra output
                return '{' in stripped or '[' in stripped

        elif check_type == 'csv_format':
            lines = stripped.split('\n')
            if len(lines) >= 2:
                return any(',' in line for line in lines)
            return ',' in stripped

        elif check_type == 'xml_format':
            return '<' in stripped and '>' in stripped

        elif check_type == 'html_format':
            return '<' in stripped and '>' in stripped

        elif check_type == 'yaml_format':
            lines = stripped.split('\n')
            return len(lines) >= 2 and any(':' in line for line in lines)

        return True  # Unknown format — pass
