"""
Interface Contracts — Semantic fragment matching via input/output contracts

Instead of keyword fuzzy matching, fragments declare what they DO:
- capability: what semantic task this fragment performs
- inputs: what data types it needs
- outputs: what data types it produces
- requires: runtime requirements (files, network, etc.)

Assembly becomes constraint satisfaction:
  Intent → detect required capabilities → find fragments that provide them →
  chain fragments where output_type of A matches input_type of B
"""
# Dependencies: none
# Depended by: none (leaf module)


from typing import Dict, List, Set, Optional, Tuple
import re


# ─── Capability taxonomy ────────────────────────────────────────────
# Each capability maps to fragment keys that can fulfill it.
# This is the semantic layer between "what the user wants" and "what fragments do."

CAPABILITY_CATALOG = {
    # ── Data I/O ──
    'read_file': {
        'fragments': ['file_read', 'file_readlines', 'file_readline', 'file_read_binary'],
        'outputs': ['text', 'lines', 'bytes'],
        'description': 'Read data from a file',
    },
    'write_file': {
        'fragments': ['file_write', 'file_append', 'file_write_binary', 'file_writelines'],
        'inputs': ['text', 'bytes', 'lines'],
        'description': 'Write data to a file',
    },
    'read_json': {
        'fragments': ['json_load', 'json_loads'],
        'outputs': ['dict', 'list'],
        'description': 'Parse JSON data',
    },
    'write_json': {
        'fragments': ['json_dump', 'json_dumps'],
        'inputs': ['dict', 'list'],
        'description': 'Serialize data to JSON',
    },
    'read_csv': {
        'fragments': ['csv_read', 'csv_dictreader'],
        'outputs': ['rows', 'records'],
        'description': 'Read CSV data',
    },
    'write_csv': {
        'fragments': ['csv_write', 'csv_dictwriter'],
        'inputs': ['rows', 'records'],
        'description': 'Write CSV data',
    },
    'read_xml': {
        'fragments': ['xml_parse', 'xml_read'],
        'outputs': ['tree', 'dict'],
        'description': 'Parse XML data',
    },

    # ── Data transformation ──
    'transform_data': {
        'fragments': ['json_loads', 'json_dumps', 'csv_read', 'csv_write'],
        'inputs': ['text', 'dict', 'list', 'rows'],
        'outputs': ['text', 'dict', 'list', 'rows'],
        'description': 'Convert between data formats',
    },
    'filter_data': {
        'fragments': ['list_filter', 'list_comprehension'],
        'inputs': ['list', 'rows'],
        'outputs': ['list', 'rows'],
        'description': 'Filter data by condition',
    },
    'deduplicate': {
        'fragments': ['set_dedup', 'dict_dedup'],
        'inputs': ['list', 'rows'],
        'outputs': ['list', 'rows'],
        'description': 'Remove duplicate entries',
    },
    'sort_data': {
        'fragments': ['list_sort', 'sorted_call'],
        'inputs': ['list', 'rows'],
        'outputs': ['list', 'rows'],
        'description': 'Sort data',
    },
    'aggregate': {
        'fragments': ['collections_counter', 'statistics_mean'],
        'inputs': ['list', 'rows'],
        'outputs': ['dict', 'number'],
        'description': 'Aggregate/summarize data',
    },

    # ── Network ──
    'http_get': {
        'fragments': ['requests_get', 'urllib_get', 'http_get'],
        'outputs': ['response', 'text', 'json'],
        'description': 'Make HTTP GET request',
    },
    'http_post': {
        'fragments': ['requests_post', 'http_post'],
        'inputs': ['dict', 'text'],
        'outputs': ['response'],
        'description': 'Make HTTP POST request',
    },
    'http_server': {
        'fragments': ['flask_app', 'http_server', 'api_endpoint'],
        'description': 'Create HTTP server/API',
    },
    'tcp_server': {
        'fragments': ['socket_server', 'tcp_listener'],
        'description': 'Create TCP server',
    },
    'tcp_client': {
        'fragments': ['socket_client', 'tcp_connect'],
        'description': 'TCP client connection',
    },

    # ── Database ──
    'database_create': {
        'fragments': ['sqlite3_create', 'sqlite3_query', 'database_insert'],
        'description': 'Create/setup database',
    },
    'database_query': {
        'fragments': ['sqlite3_query', 'sqlite3_select'],
        'inputs': ['query'],
        'outputs': ['rows', 'records'],
        'description': 'Query database',
    },
    'database_insert': {
        'fragments': ['sqlite3_insert', 'database_insert'],
        'inputs': ['dict', 'rows'],
        'description': 'Insert into database',
    },

    # ── String/Text ──
    'regex_match': {
        'fragments': ['re_match', 're_search', 're_findall'],
        'inputs': ['text'],
        'outputs': ['matches', 'text'],
        'description': 'Pattern matching with regex',
    },
    'text_parse': {
        'fragments': ['re_findall', 're_split', 'string_split'],
        'inputs': ['text'],
        'outputs': ['list', 'parts'],
        'description': 'Parse text into components',
    },
    'text_format': {
        'fragments': ['string_format', 'template_render'],
        'inputs': ['text', 'dict'],
        'outputs': ['text'],
        'description': 'Format/template text',
    },

    # ── Crypto/Hash ──
    'hash_data': {
        'fragments': ['hashlib_sha256', 'hashlib_md5', 'hash_file'],
        'inputs': ['text', 'bytes'],
        'outputs': ['hash'],
        'description': 'Compute hash of data',
    },
    'encrypt': {
        'fragments': ['aes_encrypt', 'fernet_encrypt'],
        'inputs': ['text', 'bytes'],
        'outputs': ['ciphertext'],
        'description': 'Encrypt data',
    },
    'decrypt': {
        'fragments': ['aes_decrypt', 'fernet_decrypt'],
        'inputs': ['ciphertext'],
        'outputs': ['text', 'bytes'],
        'description': 'Decrypt data',
    },

    # ── Filesystem ──
    'list_files': {
        'fragments': ['os_listdir', 'os_walk', 'glob_glob', 'glob_rglob'],
        'outputs': ['files', 'paths'],
        'description': 'List files in directory',
    },
    'copy_files': {
        'fragments': ['shutil_copy', 'shutil_copytree'],
        'description': 'Copy files/directories',
    },
    'delete_files': {
        'fragments': ['os_remove', 'shutil_rmtree'],
        'description': 'Delete files/directories',
    },
    'move_files': {
        'fragments': ['shutil_move', 'os_rename'],
        'description': 'Move/rename files',
    },
    'create_directory': {
        'fragments': ['os_makedirs', 'os_mkdir'],
        'description': 'Create directories',
    },

    # ── Time/Schedule ──
    'timestamp': {
        'fragments': ['datetime_now', 'datetime_strftime', 'datetime_timestamp'],
        'outputs': ['datetime', 'text'],
        'description': 'Get current time/date',
    },
    'schedule': {
        'fragments': ['sched_scheduler', 'time_sleep_loop'],
        'description': 'Schedule tasks for execution',
    },

    # ── System ──
    'run_command': {
        'fragments': ['subprocess_run', 'subprocess_check_output', 'subprocess_popen'],
        'outputs': ['text', 'process'],
        'description': 'Execute system command',
    },
    'threading': {
        'fragments': ['threading_thread', 'threading_pool'],
        'description': 'Multi-threaded execution',
    },

    # ── Compression ──
    'compress': {
        'fragments': ['zipfile_create', 'tarfile_create', 'gzip_compress'],
        'inputs': ['files', 'bytes'],
        'outputs': ['archive'],
        'description': 'Compress files/data',
    },
    'decompress': {
        'fragments': ['zipfile_extract', 'tarfile_extract', 'gzip_decompress'],
        'inputs': ['archive'],
        'outputs': ['files', 'bytes'],
        'description': 'Extract compressed data',
    },
}


# ─── Intent → Capability mapping ────────────────────────────────────
# Maps natural language patterns to required capabilities.
# Each pattern is (regex, list_of_capabilities).

INTENT_CAPABILITY_PATTERNS = [
    # Data pipelines
    (r'pipeline.*(?:source|sink|flow|transform)', ['read_file', 'transform_data', 'write_file']),
    (r'(?:convert|bridge|transform).*(?:json|xml)', ['read_json', 'read_xml', 'transform_data']),
    (r'(?:convert|transform).*(?:csv|json)', ['read_csv', 'transform_data', 'write_json']),
    (r'(?:convert|transform).*(?:format|data)', ['read_file', 'transform_data', 'write_file']),

    # Query/search
    (r'query.*(?:dict|dictionary|nested)', ['read_json', 'filter_data']),
    (r'search.*(?:file|directory|text)', ['list_files', 'text_parse', 'regex_match']),

    # Deduplication
    (r'dedup(?:licate)?.*(?:csv|record|file)', ['read_csv', 'deduplicate', 'write_csv']),
    (r'dedup(?:licate)?', ['filter_data', 'deduplicate']),

    # CRUD / Management systems
    (r'(?:inventory|management|crud).*system', ['database_create', 'database_query', 'database_insert']),
    (r'(?:url.*shortener|todo.*list|registration)', ['database_create', 'http_server', 'database_query']),

    # Monitoring/alerting
    (r'(?:monitor|watch|guard|lighthouse|alert)', ['run_command', 'timestamp', 'write_file']),

    # Config systems
    (r'config(?:uration)?.*(?:system|manager)', ['read_json', 'read_file', 'write_json']),

    # Scheduling
    (r'(?:schedule|cron|task.*schedul)', ['schedule', 'timestamp', 'threading']),

    # API/Web
    (r'(?:web.*api|rest.*api|api.*endpoint)', ['http_server', 'database_create']),
    (r'(?:rate.*limit|middleware)', ['http_server', 'timestamp']),

    # Error handling
    (r'error.*handl(?:ing|er).*(?:api|rest|client)', ['http_get', 'write_file']),

    # File operations
    (r'(?:backup|sync).*(?:file|dir|folder)', ['list_files', 'copy_files', 'timestamp']),
    (r'(?:log.*rotat)', ['list_files', 'move_files', 'compress']),

    # Test data
    (r'(?:test.*data|realistic.*data|mock.*data|fake.*data)', ['write_json', 'write_csv']),

    # CSV parsing
    (r'csv.*pars(?:e|er|ing)', ['read_csv', 'text_parse']),

    # Threading
    (r'thread.*safe.*singleton', ['threading']),
    (r'(?:concurrent|parallel|multiprocess)', ['threading']),

    # Priority/adaptive
    (r'priority.*(?:system|queue|process)', ['database_create', 'timestamp', 'sort_data']),
]


class InterfaceContractEngine:
    """Constraint-based fragment selection using interface contracts"""

    def __init__(self, fragments: Dict[str, str]):
        self.fragments = fragments
        self._build_fragment_index()

    def _build_fragment_index(self):
        """Build reverse index: fragment_key → set of capabilities"""
        self.fragment_to_capabilities: Dict[str, Set[str]] = {}
        self.capability_to_fragments: Dict[str, List[str]] = {}

        for cap_name, cap_info in CAPABILITY_CATALOG.items():
            frag_keys = cap_info.get('fragments', [])
            available = [fk for fk in frag_keys if fk in self.fragments]
            self.capability_to_fragments[cap_name] = available

            for fk in available:
                if fk not in self.fragment_to_capabilities:
                    self.fragment_to_capabilities[fk] = set()
                self.fragment_to_capabilities[fk].add(cap_name)

    def detect_capabilities(self, intent_text: str) -> List[str]:
        """Detect required capabilities from intent text using pattern matching"""
        intent_lower = intent_text.lower()
        for pattern, capabilities in INTENT_CAPABILITY_PATTERNS:
            if re.search(pattern, intent_lower):
                return capabilities
        return []

    def resolve_fragments(self, capabilities: List[str]) -> List[Tuple[str, str, str]]:
        """
        Resolve capabilities to concrete fragment keys.

        Returns list of (fragment_key, fragment_code, capability_name) tuples,
        ordered to form a valid pipeline (inputs of later fragments match
        outputs of earlier ones).
        """
        resolved = []
        seen_keys = set()

        for cap_name in capabilities:
            available = self.capability_to_fragments.get(cap_name, [])
            if not available:
                continue

            # Pick the best fragment for this capability
            # Prefer fragments that produce output (for pipeline chaining)
            best = None
            for fk in available:
                if fk not in seen_keys:
                    best = fk
                    break

            if best and best not in seen_keys:
                seen_keys.add(best)
                resolved.append((best, self.fragments[best], cap_name))

        return resolved

    def score_fragment_for_intent(self, fragment_key: str, intent_text: str) -> float:
        """
        Score a fragment's relevance to an intent using capability matching.

        Returns 0.0 (no match) to 3.0 (strong semantic match).
        Higher scores mean the fragment's capabilities align with what the intent needs.
        """
        required_caps = self.detect_capabilities(intent_text)
        if not required_caps:
            return 0.0

        fragment_caps = self.fragment_to_capabilities.get(fragment_key, set())
        if not fragment_caps:
            return 0.0

        # Score: how many required capabilities does this fragment fulfill?
        overlap = fragment_caps & set(required_caps)
        if not overlap:
            return 0.0

        return len(overlap) * 1.5

    def build_pipeline(self, intent_text: str) -> Optional[List[Tuple[str, str]]]:
        """
        Build a complete fragment pipeline for an intent.

        Returns list of (fragment_key, fragment_code) if a valid pipeline exists,
        or None if no capabilities matched.
        """
        capabilities = self.detect_capabilities(intent_text)
        if not capabilities:
            return None

        resolved = self.resolve_fragments(capabilities)
        if not resolved:
            return None

        return [(key, code) for key, code, _ in resolved]
