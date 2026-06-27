"""Proactive Bug Detector: Find likely bugs in fragments before they fail.

Analyzes FORGE's own fragments for missing patterns that peer fragments have.
"73% of similar fragments handle exceptions here — this one doesn't. Probable bug."

Uses fragment clusters from FragmentAnalyzer to propagate findings.
Part of FORGE Phase 3: Cross-Fragment Generalization.
"""
# Dependencies: fragment_analyzer
# Depended by: autonomous_loop

import ast
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from o1o_o.core.fragment_analyzer import FragmentAnalyzer


# ─── Bug Pattern Checkers ──────────────────────────────────────────────────

class BugPattern:
    """A pattern that detects a specific class of likely bug."""

    def __init__(self, name: str, description: str,
                 check_fn=None, severity: str = 'moderate'):
        self.name = name
        self.description = description
        self.check_fn = check_fn
        self.severity = severity  # trivial, moderate, hard

    def check(self, code: str, key: str) -> Optional[str]:
        """Returns warning message if bug pattern detected, None if OK."""
        if self.check_fn:
            return self.check_fn(code, key)
        return None


def _check_open_no_with(code: str, key: str) -> Optional[str]:
    """open() without 'with' statement = resource leak."""
    if 'open(' not in code:
        return None
    # Check for open() used as assignment without with
    lines = code.split('\n')
    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.search(r'\w+\s*=\s*open\(', stripped) and 'with' not in stripped:
            # Check if closed later
            var_match = re.match(r'(\w+)\s*=\s*open\(', stripped)
            if var_match:
                var = var_match.group(1)
                rest = '\n'.join(lines[i+1:])
                if f'{var}.close()' not in rest:
                    return f"open() on line {i+1} without 'with' or .close() — resource leak"
    return None


def _check_bare_except(code: str, key: str) -> Optional[str]:
    """Bare except: or except Exception without logging."""
    if 'except:' in code:
        return "Bare 'except:' catches SystemExit/KeyboardInterrupt — use 'except Exception:'"
    return None


def _check_sql_injection(code: str, key: str) -> Optional[str]:
    """String formatting in SQL queries."""
    sql_patterns = [
        r'execute\(.*["\'].*%s',
        r'execute\(.*\.format\(',
        r'execute\(.*f["\']',
    ]
    for pat in sql_patterns:
        if re.search(pat, code):
            return "Possible SQL injection: use parameterized queries (?)"
    return None


def _check_hardcoded_creds(code: str, key: str) -> Optional[str]:
    """Hardcoded passwords/keys (not template vars)."""
    patterns = [
        (r"password\s*=\s*['\"][^{'][^'\"]{3,}['\"]", "hardcoded password"),
        (r"api_key\s*=\s*['\"][A-Za-z0-9]{10,}['\"]", "hardcoded API key"),
        (r"secret\s*=\s*['\"][A-Za-z0-9]{10,}['\"]", "hardcoded secret"),
    ]
    for pat, desc in patterns:
        if re.search(pat, code, re.IGNORECASE):
            return f"Likely {desc} — should be parameterized"
    return None


def _check_no_timeout(code: str, key: str) -> Optional[str]:
    """Network calls without timeout."""
    if 'requests.' in code and 'timeout' not in code:
        if any(call in code for call in ['requests.get', 'requests.post', 'requests.put', 'requests.delete']):
            return "Network request without timeout — may hang indefinitely"
    if 'socket.socket' in code and 'settimeout' not in code and 'timeout' not in code:
        return "Socket without timeout — may hang indefinitely"
    return None


def _check_missing_imports(code: str, key: str) -> Optional[str]:
    """Detect usage of modules without importing them."""
    # Known module → usage patterns
    module_usage = {
        'json': [r'\bjson\.\w+'],
        'os': [r'\bos\.\w+'],
        're': [r'\bre\.\w+'],
        'sys': [r'\bsys\.\w+'],
        'csv': [r'\bcsv\.\w+'],
        'hashlib': [r'\bhashlib\.\w+'],
        'base64': [r'\bbase64\.\w+'],
        'socket': [r'\bsocket\.socket'],
        'sqlite3': [r'\bsqlite3\.connect'],
        'datetime': [r'\bdatetime\.\w+', r'\btimedelta\b'],
        'pathlib': [r'\bPath\('],
        'subprocess': [r'\bsubprocess\.\w+'],
        'logging': [r'\blogging\.\w+'],
        'struct': [r'\bstruct\.\w+'],
        'shutil': [r'\bshutil\.\w+'],
    }

    missing = []
    for module, patterns in module_usage.items():
        used = any(re.search(p, code) for p in patterns)
        if used:
            imported = (
                re.search(rf'\bimport\s+{module}\b', code) or
                re.search(rf'\bfrom\s+{module}\b', code) or
                re.search(rf'\bimport\s+\w+.*,\s*{module}\b', code)
            )
            if not imported:
                missing.append(module)

    if missing:
        return f"Used without import: {', '.join(missing)}"
    return None


def _check_division_by_zero(code: str, key: str) -> Optional[str]:
    """Division without zero check."""
    if re.search(r'/ \w+\b', code) and 'ZeroDivision' not in code:
        # Check if there's a denominator variable being divided
        divs = re.findall(r'/ (\w+)\b', code)
        for d in divs:
            if d in ('2', '10', '100', '1000', '255', '256', 'len'):
                continue  # constants are safe
            if f'if {d}' not in code and f'if not {d}' not in code:
                return f"Division by '{d}' without zero check"
    return None


def _check_unhandled_exceptions(code: str, key: str) -> Optional[str]:
    """Risky operations without try/except."""
    risky_ops = {
        'int(': 'ValueError from int()',
        'float(': 'ValueError from float()',
        'json.loads': 'JSONDecodeError from json.loads()',
        '.connect(': 'ConnectionError',
    }
    if 'try' in code or 'except' in code:
        return None  # has some error handling

    for op, risk in risky_ops.items():
        if op in code:
            return f"No exception handling for potential {risk}"
    return None


# ─── Registered Bug Patterns ──────────────────────────────────────────────

BUG_PATTERNS = [
    BugPattern('open_no_with', 'File opened without context manager', _check_open_no_with, 'moderate'),
    BugPattern('bare_except', 'Bare except clause catches too broadly', _check_bare_except, 'trivial'),
    BugPattern('sql_injection', 'SQL injection via string formatting', _check_sql_injection, 'hard'),
    BugPattern('hardcoded_creds', 'Hardcoded credentials', _check_hardcoded_creds, 'moderate'),
    BugPattern('no_timeout', 'Network call without timeout', _check_no_timeout, 'moderate'),
    BugPattern('missing_imports', 'Module used without import', _check_missing_imports, 'hard'),
    BugPattern('division_zero', 'Division without zero check', _check_division_by_zero, 'trivial'),
    BugPattern('unhandled_exception', 'Risky operation without error handling', _check_unhandled_exceptions, 'trivial'),
]


# ─── Anomaly Detector (cluster-based) ─────────────────────────────────────

class AnomalyDetector:
    """Detect anomalies by comparing fragment against its cluster peers."""

    def __init__(self, analyzer: FragmentAnalyzer):
        self.analyzer = analyzer
        self._cluster_stats: Dict[str, Dict[str, float]] = {}

    def _build_cluster_stats(self):
        """Pre-compute pattern frequencies per cluster (O(n) not O(n^2))."""
        if not self.analyzer.clusters:
            self.analyzer.build_clusters()

        for cluster_name, members in self.analyzer.clusters.items():
            if len(members) < 3:
                continue
            pattern_counts: Dict[str, int] = defaultdict(int)
            for member in members:
                for p in self.analyzer.fragment_patterns.get(member, set()):
                    pattern_counts[p] += 1
            self._cluster_stats[cluster_name] = {
                p: count / len(members) for p, count in pattern_counts.items()
            }

    def detect_missing_patterns(self, fragment_key: str,
                                 min_peer_ratio: float = 0.6) -> List[str]:
        """Find patterns common in fragment's clusters but missing from this fragment.

        Uses pre-computed cluster statistics instead of pairwise comparisons.
        """
        if not self._cluster_stats:
            self._build_cluster_stats()

        this_patterns = self.analyzer.fragment_patterns.get(fragment_key, set())
        if not this_patterns:
            return []

        # Check each cluster this fragment belongs to
        anomalies = []
        seen_patterns = set()
        for cluster_name in this_patterns:
            stats = self._cluster_stats.get(cluster_name, {})
            for pattern, ratio in stats.items():
                if ratio >= min_peer_ratio and pattern not in this_patterns and pattern not in seen_patterns:
                    cluster_size = len(self.analyzer.clusters.get(cluster_name, []))
                    anomalies.append(
                        f"{pattern} present in {ratio:.0%} of {cluster_name} cluster ({cluster_size} members) but missing"
                    )
                    seen_patterns.add(pattern)

        return anomalies


# ─── Main Detection Engine ─────────────────────────────────────────────────

class ProactiveDetector:
    """Run all bug detection checks on fragments."""

    def __init__(self, fragments_dir: str = 'fragments'):
        self.analyzer = FragmentAnalyzer(fragments_dir)
        self.anomaly_detector = None
        self.findings: Dict[str, List[Dict]] = defaultdict(list)

    def scan_all(self, patterns_only: bool = False) -> Dict[str, List[Dict]]:
        """Scan all fragments for potential bugs.

        Returns: {fragment_key: [{pattern, severity, message}]}
        """
        self.analyzer.load_all_fragments()
        self.analyzer.analyze_patterns()
        self.anomaly_detector = AnomalyDetector(self.analyzer)

        for frag_key, code in self.analyzer.fragments.items():
            # Run bug pattern checks
            for bp in BUG_PATTERNS:
                warning = bp.check(code, frag_key)
                if warning:
                    self.findings[frag_key].append({
                        'pattern': bp.name,
                        'severity': bp.severity,
                        'message': warning,
                        'type': 'bug_pattern',
                    })

            # Run anomaly detection (cluster-based) — only for fragments with patterns
            if not patterns_only and self.analyzer.fragment_patterns.get(frag_key):
                anomalies = self.anomaly_detector.detect_missing_patterns(frag_key)
                for anomaly in anomalies[:3]:  # cap per fragment
                    self.findings[frag_key].append({
                        'pattern': 'cluster_anomaly',
                        'severity': 'trivial',
                        'message': anomaly,
                        'type': 'anomaly',
                    })

        return dict(self.findings)

    def get_high_severity(self) -> Dict[str, List[Dict]]:
        """Return only moderate+ severity findings."""
        return {k: [f for f in findings if f['severity'] in ('moderate', 'hard')]
                for k, findings in self.findings.items()
                if any(f['severity'] in ('moderate', 'hard') for f in findings)}

    def propagate_fix(self, fixed_key: str, fix_pattern: str) -> Set[str]:
        """Given a fix applied to one fragment, find all others that need it too.

        Uses fragment clustering to propagate fixes proactively.
        """
        if not self.analyzer.clusters:
            self.analyzer.build_clusters()

        # Get the bug propagation set
        related = self.analyzer.get_bug_propagation_set(fixed_key, threshold=0.4)

        # Filter to those with the same bug pattern
        needs_fix = set()
        for key in related:
            for finding in self.findings.get(key, []):
                if finding['pattern'] == fix_pattern:
                    needs_fix.add(key)
                    break

        return needs_fix

    def format_report(self, max_findings: int = 50) -> str:
        """Generate human-readable detection report."""
        lines = []
        lines.append("Proactive Bug Detection Report")
        lines.append("=" * 50)
        lines.append(f"Fragments scanned: {len(self.analyzer.fragments)}")
        lines.append(f"Fragments with findings: {len(self.findings)}")

        # Count by severity
        sev_counts = defaultdict(int)
        type_counts = defaultdict(int)
        for findings in self.findings.values():
            for f in findings:
                sev_counts[f['severity']] += 1
                type_counts[f['pattern']] += 1

        lines.append(f"\nBy severity:")
        for sev in ['hard', 'moderate', 'trivial']:
            if sev in sev_counts:
                lines.append(f"  {sev}: {sev_counts[sev]}")

        lines.append(f"\nBy pattern:")
        for pat, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {pat}: {count}")

        # Show top findings
        lines.append(f"\nTop findings (severity >= moderate):")
        count = 0
        for frag_key, findings in sorted(self.findings.items()):
            for f in findings:
                if f['severity'] in ('moderate', 'hard'):
                    lines.append(f"  [{f['severity']}] {frag_key}: {f['message']}")
                    count += 1
                    if count >= max_findings:
                        break
            if count >= max_findings:
                break

        return '\n'.join(lines)


def run_scan(fragments_dir: str = 'fragments') -> ProactiveDetector:
    """Run full proactive scan and print report."""
    detector = ProactiveDetector(fragments_dir)
    detector.scan_all()
    print(detector.format_report())
    return detector


if __name__ == '__main__':
    run_scan()
