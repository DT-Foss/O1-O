"""
Auto-Bridge Generator — Eliminate orphaned fragments

Analyzes each code fragment to infer what natural language queries should
map to it, then generates bridge triplets automatically. This ensures every
fragment in the system is reachable.

Strategies:
1. Module + function name → "use {module} {function}" phrases
2. Code content analysis → descriptive verb phrases
3. Docstring/comment extraction → direct intent phrases
4. Reverse engineering from variable names and operations
"""
# Dependencies: none
# Depended by: self_improve


import re
import json
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple


# Module → human-readable verb phrases
MODULE_VERBS = {
    'os': ['file', 'directory', 'path', 'system', 'environment'],
    'os.path': ['file path', 'directory path', 'check path'],
    'shutil': ['copy', 'move', 'delete', 'remove', 'directory'],
    'glob': ['find files', 'pattern', 'wildcard', 'match files'],
    'pathlib': ['path', 'file', 'directory'],
    'csv': ['csv', 'comma separated', 'spreadsheet', 'tabular'],
    'json': ['json', 'parse json', 'save json', 'serialize'],
    'yaml': ['yaml', 'yml', 'config'],
    'xml': ['xml', 'parse xml'],
    'html': ['html', 'parse html', 'webpage'],
    'requests': ['http', 'download', 'webpage', 'api', 'fetch', 'url'],
    'urllib': ['url', 'download', 'fetch'],
    'http': ['http server', 'web server'],
    'socket': ['socket', 'tcp', 'udp', 'port', 'network', 'connect'],
    'sqlite3': ['sqlite', 'database', 'sql', 'query', 'table'],
    'hashlib': ['hash', 'sha256', 'md5', 'checksum', 'digest'],
    're': ['regex', 'pattern', 'match', 'find', 'extract', 'replace'],
    'subprocess': ['run command', 'shell', 'execute', 'process'],
    'sys': ['system', 'argv', 'arguments', 'stdin', 'stdout'],
    'datetime': ['date', 'time', 'timestamp', 'format date'],
    'time': ['sleep', 'timer', 'delay', 'measure time', 'benchmark'],
    'random': ['random', 'shuffle', 'choice', 'generate random'],
    'math': ['math', 'calculate', 'square root', 'trigonometry'],
    'statistics': ['statistics', 'mean', 'median', 'standard deviation'],
    'collections': ['counter', 'frequency', 'default dict', 'ordered dict'],
    'itertools': ['permutation', 'combination', 'product', 'chain'],
    'functools': ['cache', 'reduce', 'partial', 'decorator'],
    'string': ['string', 'template', 'ascii', 'punctuation'],
    'textwrap': ['wrap text', 'indent', 'dedent'],
    'difflib': ['diff', 'compare', 'difference', 'similar'],
    'logging': ['log', 'logging', 'logger', 'debug log'],
    'argparse': ['argument', 'cli', 'command line', 'parser'],
    'configparser': ['config', 'ini file', 'configuration'],
    'zipfile': ['zip', 'compress', 'archive', 'extract zip'],
    'tarfile': ['tar', 'tar.gz', 'compress', 'archive', 'extract tar'],
    'gzip': ['gzip', 'compress', 'decompress'],
    'base64': ['base64', 'encode', 'decode'],
    'struct': ['binary', 'pack', 'unpack', 'struct'],
    'io': ['stream', 'buffer', 'string io', 'bytes io'],
    'tempfile': ['temporary file', 'temp dir', 'temp file'],
    'platform': ['platform', 'system info', 'os info', 'architecture'],
    'psutil': ['cpu', 'memory', 'process', 'disk', 'system monitor'],
    'threading': ['thread', 'parallel', 'concurrent', 'lock'],
    'multiprocessing': ['process', 'parallel', 'pool', 'spawn'],
    'asyncio': ['async', 'await', 'coroutine', 'event loop'],
    'email': ['email', 'mime', 'send email', 'smtp'],
    'smtplib': ['smtp', 'send email', 'mail server'],
    'ftplib': ['ftp', 'upload', 'download', 'file transfer'],
    'paramiko': ['ssh', 'sftp', 'remote', 'secure shell'],
    'cryptography': ['encrypt', 'decrypt', 'cipher', 'key'],
    'jwt': ['jwt', 'token', 'json web token', 'authenticate'],
    'flask': ['flask', 'web app', 'api', 'route', 'server'],
    'fastapi': ['fastapi', 'api', 'endpoint', 'rest'],
    'pandas': ['dataframe', 'pandas', 'data analysis', 'csv analysis'],
    'numpy': ['numpy', 'array', 'matrix', 'numerical'],
    'matplotlib': ['plot', 'chart', 'graph', 'visualize', 'figure'],
    'PIL': ['image', 'photo', 'resize image', 'crop'],
    'Pillow': ['image', 'photo', 'resize image', 'crop'],
    'bs4': ['beautifulsoup', 'scrape', 'parse html', 'web scraping'],
    'BeautifulSoup': ['scrape', 'parse html', 'web scraping'],
    'selenium': ['browser', 'automate browser', 'web automation'],
    'scrapy': ['scrape', 'crawl', 'spider', 'web crawler'],
    'pyyaml': ['yaml', 'parse yaml', 'config'],
    'toml': ['toml', 'parse toml', 'config'],
    'xml.etree': ['xml', 'parse xml', 'element tree'],
    'lxml': ['xml', 'html', 'xpath', 'parse'],
    'scapy': ['packet', 'network', 'sniff', 'craft packet'],
    'nmap': ['nmap', 'port scan', 'network scan', 'service detection'],
    'shodan': ['shodan', 'internet scan', 'device search'],
}

# Operation patterns in code → verb phrases
OPERATION_PATTERNS = [
    (r'\.read\(\)', 'read'),
    (r'\.write\(', 'write'),
    (r'\.readlines\(\)', 'read lines'),
    (r'open\(.+["\']r["\']', 'read file'),
    (r'open\(.+["\']w["\']', 'write file'),
    (r'open\(.+["\']a["\']', 'append to file'),
    (r'open\(.+["\']rb["\']', 'read binary file'),
    (r'open\(.+["\']wb["\']', 'write binary file'),
    (r'\.get\(', 'get'),
    (r'\.post\(', 'post'),
    (r'\.put\(', 'put'),
    (r'\.delete\(', 'delete'),
    (r'\.send\(', 'send'),
    (r'\.recv\(', 'receive'),
    (r'\.connect\(', 'connect'),
    (r'\.listen\(', 'listen'),
    (r'\.bind\(', 'bind'),
    (r'\.accept\(', 'accept connection'),
    (r'\.execute\(', 'execute query'),
    (r'\.fetchall\(\)', 'fetch results'),
    (r'\.fetchone\(\)', 'fetch one result'),
    (r'\.commit\(\)', 'commit'),
    (r'\.find\(', 'find'),
    (r'\.findall\(', 'find all'),
    (r'\.search\(', 'search'),
    (r'\.match\(', 'match'),
    (r'\.replace\(', 'replace'),
    (r'\.split\(', 'split'),
    (r'\.join\(', 'join'),
    (r'\.strip\(', 'strip'),
    (r'\.sort\(', 'sort'),
    (r'sorted\(', 'sort'),
    (r'\.encode\(', 'encode'),
    (r'\.decode\(', 'decode'),
    (r'\.hexdigest\(\)', 'hash'),
    (r'\.encrypt\(', 'encrypt'),
    (r'\.decrypt\(', 'decrypt'),
    (r'\.dump\(', 'dump'),
    (r'\.dumps\(', 'serialize'),
    (r'\.load\(', 'load'),
    (r'\.loads\(', 'deserialize'),
    (r'os\.listdir\(', 'list files'),
    (r'os\.walk\(', 'walk directory'),
    (r'os\.makedirs?\(', 'create directory'),
    (r'os\.remove\(', 'delete file'),
    (r'os\.rename\(', 'rename file'),
    (r'shutil\.copy', 'copy file'),
    (r'shutil\.move', 'move file'),
    (r'shutil\.rmtree', 'delete directory'),
    (r'glob\.glob\(', 'find files'),
    (r'\.to_csv\(', 'save csv'),
    (r'\.to_json\(', 'save json'),
    (r'\.plot\(', 'plot'),
    (r'plt\.show\(', 'show plot'),
    (r'plt\.savefig\(', 'save plot'),
]


class AutoBridgeGenerator:
    """Generate bridge triplets for orphaned fragments"""

    def __init__(self, fragments: Dict[str, str], existing_bridges: List[Dict]):
        self.fragments = fragments
        self.existing_bridges = existing_bridges
        self.bridged_keys = self._collect_bridged_keys()

    def _collect_bridged_keys(self) -> Set[str]:
        """Collect all fragment keys that already have bridges"""
        keys = set()
        for t in self.existing_bridges:
            outcome = t.get('outcome', '')
            keys.add(outcome)
            if '+' in outcome:
                for part in outcome.split('+'):
                    keys.add(part.strip())
        return keys

    def find_orphans(self) -> List[str]:
        """Find fragment keys with no bridge pointing to them"""
        return [k for k in self.fragments if k not in self.bridged_keys]

    def generate_bridges(self) -> List[Dict]:
        """Generate bridge triplets for all orphan fragments"""
        orphans = self.find_orphans()
        bridges = []

        for frag_key in orphans:
            code = self.fragments[frag_key]
            new_bridges = self._generate_for_fragment(frag_key, code)
            bridges.extend(new_bridges)

        return bridges

    def _generate_for_fragment(self, key: str, code: str) -> List[Dict]:
        """Generate bridge triplets for a single fragment"""
        bridges = []
        phrases = set()

        # Strategy 1: Module + key decomposition
        module = self._extract_module(code)
        key_words = key.replace('_', ' ').lower()

        # Key name itself as a phrase
        if len(key_words) >= 3:
            phrases.add(key_words)

        # Module context phrases
        if module:
            module_words = MODULE_VERBS.get(module, [])
            # Combine module words with key words
            for mw in module_words:
                phrases.add(f"{mw} {key_words}")
                phrases.add(f"{key_words} {mw}")
            # Just module words for very specific fragments
            if len(key_words.split()) >= 2:
                phrases.add(key_words)

        # Strategy 2: Code content analysis
        operations = self._extract_operations(code)
        for op in operations:
            phrases.add(f"{op} {key_words}")
            if module:
                phrases.add(f"{op} with {module}")

        # Strategy 3: Comment/docstring extraction
        doc_phrases = self._extract_doc_phrases(code)
        phrases.update(doc_phrases)

        # Strategy 4: Reverse from variable names
        var_phrases = self._extract_var_phrases(code)
        phrases.update(var_phrases)

        # Deduplicate and filter
        phrases = {p.strip() for p in phrases if len(p.strip()) >= 5}

        # Create bridge triplets (top 3 most specific phrases per fragment)
        ranked = sorted(phrases, key=lambda p: len(p), reverse=True)
        for phrase in ranked[:3]:
            bridges.append({
                'trigger': phrase,
                'mechanism': 'uses',
                'outcome': key,
                'confidence': 0.85,
                '_auto_bridge': True,
            })

        return bridges

    def _extract_module(self, code: str) -> Optional[str]:
        """Extract primary module from code"""
        for line in code.split('\n'):
            stripped = line.strip()
            if stripped.startswith('import '):
                parts = stripped.split()
                if len(parts) >= 2:
                    return parts[1].split('.')[0]
            elif stripped.startswith('from '):
                parts = stripped.split()
                if len(parts) >= 2:
                    return parts[1].split('.')[0]
        return None

    def _extract_operations(self, code: str) -> List[str]:
        """Extract operations from code using pattern matching"""
        ops = []
        for pattern, verb in OPERATION_PATTERNS:
            if re.search(pattern, code):
                ops.append(verb)
        return list(set(ops))

    def _extract_doc_phrases(self, code: str) -> Set[str]:
        """Extract phrases from comments and docstrings"""
        phrases = set()
        for line in code.split('\n'):
            stripped = line.strip()
            if stripped.startswith('#'):
                comment = stripped.lstrip('#').strip()
                if 5 <= len(comment) <= 60:
                    phrases.add(comment.lower())
        return phrases

    def _extract_var_phrases(self, code: str) -> Set[str]:
        """Extract descriptive phrases from variable names"""
        phrases = set()
        for line in code.split('\n'):
            match = re.match(r'^(\w+)\s*=\s*', line.strip())
            if match:
                var = match.group(1)
                # Convert snake_case to phrase
                words = var.replace('_', ' ')
                if len(words) >= 5 and var not in ('result', 'data', 'output', 'f'):
                    phrases.add(words)
        return phrases


def run_auto_bridge(forge_dir: Path = None) -> int:
    """Run auto-bridge generation and merge into bridge_triplets.json"""
    if forge_dir is None:
        forge_dir = Path(__file__).parent.parent

    fragments_dir = forge_dir / 'fragments'
    bridge_path = forge_dir / 'bridge_triplets.json'

    # Load all fragments
    all_fragments = {}
    for frag_file in fragments_dir.glob('*.json'):
        with open(frag_file) as f:
            all_fragments.update(json.load(f))

    # Load existing bridges
    with open(bridge_path) as f:
        existing = json.load(f)

    # Generate new bridges
    generator = AutoBridgeGenerator(all_fragments, existing)
    orphans = generator.find_orphans()
    new_bridges = generator.generate_bridges()

    if not new_bridges:
        print(f"No orphan fragments found — all {len(all_fragments)} fragments are bridged!")
        return 0

    # Deduplicate against existing
    existing_triggers = {t['trigger'].lower() for t in existing}
    truly_new = [b for b in new_bridges if b['trigger'].lower() not in existing_triggers]

    # Merge
    existing.extend(truly_new)
    with open(bridge_path, 'w') as f:
        json.dump(existing, f, indent=2)

    print(f"Auto-Bridge: {len(orphans)} orphan fragments found")
    print(f"Auto-Bridge: {len(truly_new)} new bridge triplets generated")
    print(f"Auto-Bridge: Total bridges now: {len(existing)}")

    return len(truly_new)


if __name__ == '__main__':
    run_auto_bridge()
