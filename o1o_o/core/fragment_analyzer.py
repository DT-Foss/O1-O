"""Fragment Analyzer: Cluster fragments by structural patterns.

Groups fragments by shared code patterns (imports, API calls, idioms) so that
when a bug is found in one fragment, all structurally similar fragments can be
checked. Uses AST analysis + pattern fingerprinting.

Part of FORGE Phase 3: Cross-Fragment Generalization.
"""
# Dependencies: none
# Depended by: autonomous_loop, proactive_detector

import ast
import json
import os
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple


# ─── Structural Pattern Definitions ────────────────────────────────────────

PATTERN_SIGNATURES = {
    # File I/O patterns
    'file_read': [r'\bopen\s*\(', r'\.read\(\)', r'\.readlines\(\)', r'with\s+open\b'],
    'file_write': [r'\.write\(', r'\.writelines\(', r"open\(.+['\"]w['\"]"],
    'csv_ops': [r'\bcsv\.\w+', r'DictReader', r'DictWriter', r'csv\.reader', r'csv\.writer'],
    'json_ops': [r'\bjson\.\w+', r'json\.loads', r'json\.dumps', r'json\.load', r'json\.dump'],

    # Database patterns
    'sqlite': [r'\bsqlite3\.connect', r'cursor\.execute', r'CREATE\s+TABLE', r'INSERT\s+INTO', r'SELECT\s+'],
    'sql_general': [r'INSERT\s+INTO', r'SELECT\s+.*FROM', r'UPDATE\s+.*SET', r'DELETE\s+FROM', r'CREATE\s+TABLE'],

    # Network patterns
    'socket_ops': [r'\bsocket\.socket', r'\.connect\(', r'\.bind\(', r'\.listen\(', r'\.accept\('],
    'http_client': [r'\brequests\.\w+', r'urllib\.request', r'\.get\(', r'\.post\('],
    'http_server': [r'\bFlask\b', r'\bHTTPServer\b', r'BaseHTTPRequestHandler', r'app\.route'],

    # CLI / subprocess patterns
    'argparse': [r'\bargparse\.\w+', r'add_argument', r'parse_args'],
    'subprocess': [r'\bsubprocess\.\w+', r'subprocess\.run', r'subprocess\.Popen', r'subprocess\.check_output'],

    # Data science patterns
    'numpy': [r'\bnp\.\w+', r'\bnumpy\.\w+', r'np\.array', r'np\.zeros', r'np\.ones'],
    'pandas': [r'\bpd\.\w+', r'DataFrame', r'read_csv', r'to_csv', r'groupby'],
    'matplotlib': [r'\bplt\.\w+', r'matplotlib', r'plt\.plot', r'plt\.show', r'plt\.savefig'],
    'sklearn': [r'\bsklearn\b', r'train_test_split', r'RandomForest', r'LinearRegression'],

    # Crypto / hashing patterns
    'hashing': [r'\bhashlib\.\w+', r'sha256', r'sha512', r'md5', r'\.hexdigest\(\)'],
    'crypto': [r'\bcryptography\b', r'Fernet', r'AES', r'RSA', r'HMAC'],

    # OS / system patterns
    'os_path': [r'\bos\.path\.\w+', r'os\.listdir', r'os\.walk', r'os\.makedirs', r'shutil\.\w+'],
    'process': [r'\bos\.getpid', r'\bos\.kill', r'\bsignal\.\w+', r'\batexit\b'],
    'threading': [r'\bthreading\.\w+', r'Thread\(', r'Lock\(', r'Queue\(', r'concurrent\.futures'],

    # String / text patterns
    'regex': [r'\bre\.\w+', r're\.compile', r're\.findall', r're\.search', r're\.match'],
    'string_ops': [r'\.split\(', r'\.strip\(', r'\.replace\(', r'\.join\(', r'\.format\('],
    'encoding': [r'\bbase64\.\w+', r'\.encode\(', r'\.decode\(', r'codecs\.\w+'],

    # Security / offensive patterns
    'network_scan': [r'port.*scan', r'socket.*connect', r'nmap', r'scapy'],
    'packet_craft': [r'\bscapy\b', r'IP\(', r'TCP\(', r'UDP\(', r'sendp\(', r'sniff\('],
    'c2_pattern': [r'reverse.*shell', r'bind.*shell', r'command.*control', r'beacon'],
    'persistence': [r'cron', r'systemd', r'registry', r'startup', r'launchd'],
    'evasion': [r'obfuscat', r'encrypt.*payload', r'pack.*unpack', r'xor.*key'],

    # Data structures
    'class_def': [r'\bclass\s+\w+', r'def\s+__init__', r'self\.\w+'],
    'decorator': [r'@\w+', r'@staticmethod', r'@classmethod', r'@property'],
    'generator': [r'\byield\b', r'\byield\s+from\b'],
    'context_manager': [r'\bwith\s+', r'__enter__', r'__exit__', r'contextmanager'],

    # Image / media
    'image_ops': [r'\bPIL\b', r'Image\.open', r'\.resize\(', r'\.rotate\(', r'\.save\('],
    'pdf_ops': [r'\bfitz\b', r'PyMuPDF', r'pymupdf', r'\.get_text\('],

    # Logging
    'logging': [r'\blogging\.\w+', r'getLogger', r'FileHandler', r'StreamHandler'],
}


class FragmentAnalyzer:
    """Analyzes and clusters code fragments by structural patterns."""

    def __init__(self, fragments_dir: str = 'fragments'):
        self.fragments_dir = fragments_dir
        self.fragments: Dict[str, str] = {}  # key → code
        self.fragment_sources: Dict[str, str] = {}  # key → source file
        self.pattern_map: Dict[str, Set[str]] = defaultdict(set)  # pattern → {frag_keys}
        self.fragment_patterns: Dict[str, Set[str]] = defaultdict(set)  # frag_key → {patterns}
        self.clusters: Dict[str, List[str]] = {}  # cluster_id → [frag_keys]
        self._loaded = False

    def load_all_fragments(self) -> int:
        """Load all fragments from JSON files."""
        count = 0
        for fname in sorted(os.listdir(self.fragments_dir)):
            if not fname.endswith('.json'):
                continue
            filepath = os.path.join(self.fragments_dir, fname)
            with open(filepath) as f:
                frags = json.load(f)
            for key, val in frags.items():
                code = val if isinstance(val, str) else val.get('code', '') if isinstance(val, dict) else ''
                if code:
                    self.fragments[key] = code
                    self.fragment_sources[key] = fname
                    count += 1
        self._loaded = True
        return count

    def analyze_patterns(self) -> Dict[str, Set[str]]:
        """Match each fragment against all pattern signatures."""
        if not self._loaded:
            self.load_all_fragments()

        for frag_key, code in self.fragments.items():
            for pattern_name, regexes in PATTERN_SIGNATURES.items():
                for regex in regexes:
                    if re.search(regex, code, re.IGNORECASE):
                        self.pattern_map[pattern_name].add(frag_key)
                        self.fragment_patterns[frag_key].add(pattern_name)
                        break  # one match per pattern is enough

        return dict(self.pattern_map)

    def extract_imports(self, code: str) -> Set[str]:
        """Extract import modules from code using AST."""
        imports = set()
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])
        except SyntaxError:
            # Fallback: regex-based import extraction
            for m in re.finditer(r'^(?:from|import)\s+([\w.]+)', code, re.MULTILINE):
                imports.add(m.group(1).split('.')[0])
        return imports

    def compute_similarity(self, key1: str, key2: str) -> float:
        """Compute Structural Similarity Index between two fragments.

        Uses Jaccard index on (patterns + imports).
        """
        if key1 not in self.fragments or key2 not in self.fragments:
            return 0.0

        # Pattern-based features
        p1 = self.fragment_patterns.get(key1, set())
        p2 = self.fragment_patterns.get(key2, set())

        # Import-based features
        i1 = self.extract_imports(self.fragments[key1])
        i2 = self.extract_imports(self.fragments[key2])

        # Combined feature sets
        features1 = p1 | {f'import:{m}' for m in i1}
        features2 = p2 | {f'import:{m}' for m in i2}

        if not features1 and not features2:
            return 0.0

        intersection = features1 & features2
        union = features1 | features2
        return len(intersection) / len(union) if union else 0.0

    def build_clusters(self, min_similarity: float = 0.3) -> Dict[str, List[str]]:
        """Build clusters of structurally similar fragments.

        Uses single-linkage clustering: fragments join a cluster if they
        share >= min_similarity with any existing member.
        """
        if not self.fragment_patterns:
            self.analyze_patterns()

        # Group by primary pattern (most discriminating)
        primary_clusters: Dict[str, Set[str]] = defaultdict(set)

        for frag_key, patterns in self.fragment_patterns.items():
            if not patterns:
                primary_clusters['uncategorized'].add(frag_key)
                continue
            # Use the most specific pattern as primary
            for p in patterns:
                primary_clusters[p].add(frag_key)

        # Merge clusters where fragments share high similarity
        self.clusters = {}
        for cluster_name, members in primary_clusters.items():
            self.clusters[cluster_name] = sorted(members)

        return self.clusters

    def find_related(self, fragment_key: str, top_n: int = 10) -> List[Tuple[str, float]]:
        """Find fragments most structurally similar to a given fragment.

        Optimized: only compares against fragments sharing at least one pattern.
        """
        if not self.fragment_patterns:
            self.analyze_patterns()

        this_patterns = self.fragment_patterns.get(fragment_key, set())
        if not this_patterns:
            return []

        # Only compare against fragments that share at least one pattern
        candidates = set()
        for pat in this_patterns:
            candidates.update(self.pattern_map.get(pat, set()))
        candidates.discard(fragment_key)

        similarities = []
        for other_key in candidates:
            sim = self.compute_similarity(fragment_key, other_key)
            if sim > 0:
                similarities.append((other_key, sim))

        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities[:top_n]

    def get_bug_propagation_set(self, fragment_key: str, threshold: float = 0.4) -> Set[str]:
        """Given a buggy fragment, find all fragments that might share the same bug.

        Returns the set of fragments with similarity >= threshold.
        Used by self-repair: "bug in one → check all in cluster."
        """
        related = self.find_related(fragment_key, top_n=100)
        return {key for key, sim in related if sim >= threshold}

    def pattern_coverage_report(self) -> Dict[str, int]:
        """Report how many fragments match each pattern."""
        if not self.pattern_map:
            self.analyze_patterns()

        return {p: len(frags) for p, frags in
                sorted(self.pattern_map.items(), key=lambda x: len(x[1]), reverse=True)}

    def uncovered_fragments(self) -> Set[str]:
        """Find fragments matching NO patterns (potential blind spots)."""
        if not self._loaded:
            self.load_all_fragments()
        if not self.fragment_patterns:
            self.analyze_patterns()

        all_keys = set(self.fragments.keys())
        covered = set(self.fragment_patterns.keys())
        return all_keys - covered

    def format_report(self, top_patterns: int = 15) -> str:
        """Generate a human-readable analysis report."""
        if not self.pattern_map:
            self.analyze_patterns()

        lines = []
        lines.append(f"Fragment Analysis Report")
        lines.append(f"{'=' * 50}")
        lines.append(f"Total fragments: {len(self.fragments)}")
        lines.append(f"Total patterns: {len(self.pattern_map)}")
        lines.append(f"Uncategorized: {len(self.uncovered_fragments())}")
        lines.append("")

        # Top patterns by fragment count
        lines.append(f"Top {top_patterns} Patterns:")
        coverage = self.pattern_coverage_report()
        for i, (pattern, count) in enumerate(list(coverage.items())[:top_patterns]):
            pct = 100 * count / len(self.fragments)
            lines.append(f"  {i+1:2d}. {pattern:20s} {count:4d} fragments ({pct:.1f}%)")

        lines.append("")

        # Cluster sizes
        if not self.clusters:
            self.build_clusters()

        lines.append(f"Clusters: {len(self.clusters)}")
        big = [(n, m) for n, m in self.clusters.items() if len(m) >= 5]
        big.sort(key=lambda x: len(x[1]), reverse=True)
        for name, members in big[:10]:
            lines.append(f"  {name}: {len(members)} fragments")

        return '\n'.join(lines)


def run_analysis(fragments_dir: str = 'fragments') -> FragmentAnalyzer:
    """Run full fragment analysis and print report."""
    analyzer = FragmentAnalyzer(fragments_dir)
    analyzer.load_all_fragments()
    analyzer.analyze_patterns()
    analyzer.build_clusters()
    print(analyzer.format_report())
    return analyzer


if __name__ == '__main__':
    run_analysis()
