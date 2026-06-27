"""
Reverse FORGE — Analyze Python code and extract causal triplets

Converts existing code into knowledge:
1. Import analysis → library triplets
2. Function call analysis → API usage triplets
3. Pattern detection → idiom triplets
4. Data flow analysis → dependency triplets
5. Error handling analysis → error pattern triplets

Usage:
    rf = ReverseForge(knowledge_engine)
    triplets = rf.analyze_file("script.py")
    triplets = rf.analyze_code(code_string)
"""
# Dependencies: none
# Depended by: auto_harvester


import ast
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple


class ReverseForge:
    """Extract causal triplets from Python source code"""

    # Known library → category mapping
    LIBRARY_CATEGORIES = {
        'os': 'filesystem', 'sys': 'runtime', 'pathlib': 'filesystem',
        'json': 'serialization', 'csv': 'data_format', 'yaml': 'data_format',
        'xml': 'data_format', 'toml': 'data_format',
        'requests': 'networking', 'urllib': 'networking', 'http': 'networking',
        'socket': 'networking', 'aiohttp': 'networking',
        'sqlite3': 'database', 'sqlalchemy': 'database', 'psycopg2': 'database',
        'redis': 'database', 'pymongo': 'database',
        'pandas': 'data_science', 'numpy': 'data_science', 'scipy': 'data_science',
        'matplotlib': 'visualization', 'seaborn': 'visualization',
        'sklearn': 'machine_learning', 'torch': 'machine_learning',
        'tensorflow': 'machine_learning',
        'flask': 'web_framework', 'django': 'web_framework', 'fastapi': 'web_framework',
        'pytest': 'testing', 'unittest': 'testing',
        'hashlib': 'cryptography', 'hmac': 'cryptography', 'secrets': 'cryptography',
        'cryptography': 'cryptography',
        're': 'text_processing', 'string': 'text_processing',
        'subprocess': 'system', 'shutil': 'filesystem', 'glob': 'filesystem',
        'threading': 'concurrency', 'multiprocessing': 'concurrency',
        'asyncio': 'concurrency',
        'logging': 'observability', 'argparse': 'cli',
        'datetime': 'time', 'time': 'time',
        'collections': 'data_structures', 'itertools': 'data_structures',
        'functools': 'functional',
        'tarfile': 'compression', 'zipfile': 'compression', 'gzip': 'compression',
        'struct': 'binary', 'ctypes': 'binary',
        'scapy': 'network_security', 'nmap': 'network_security',
        'paramiko': 'ssh', 'fabric': 'ssh',
        'pwntools': 'exploitation', 'angr': 'binary_analysis',
    }

    # Method → action verb mapping
    METHOD_VERBS = {
        'read': 'reads', 'write': 'writes', 'open': 'opens',
        'close': 'closes', 'connect': 'connects_to', 'send': 'sends',
        'recv': 'receives', 'get': 'fetches', 'post': 'sends',
        'put': 'updates', 'delete': 'deletes', 'patch': 'patches',
        'parse': 'parses', 'dump': 'serializes', 'load': 'deserializes',
        'encode': 'encodes', 'decode': 'decodes', 'hash': 'hashes',
        'encrypt': 'encrypts', 'decrypt': 'decrypts',
        'compress': 'compresses', 'decompress': 'decompresses',
        'search': 'searches', 'find': 'finds', 'match': 'matches',
        'replace': 'replaces', 'split': 'splits', 'join': 'joins',
        'sort': 'sorts', 'filter': 'filters', 'map': 'transforms',
        'append': 'adds_to', 'extend': 'extends', 'insert': 'inserts_into',
        'remove': 'removes_from', 'pop': 'extracts_from',
        'execute': 'executes', 'query': 'queries', 'commit': 'commits',
        'rollback': 'rolls_back', 'fetchall': 'fetches_all',
        'listen': 'listens_on', 'bind': 'binds_to', 'accept': 'accepts',
        'walk': 'traverses', 'listdir': 'lists', 'mkdir': 'creates',
        'rename': 'renames', 'unlink': 'deletes',
        'run': 'executes', 'call': 'calls', 'check_output': 'captures_output',
    }

    def __init__(self, knowledge_engine=None):
        self.knowledge = knowledge_engine

    def analyze_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Analyze a Python file and extract triplets"""
        path = Path(filepath)
        if not path.exists() or not path.suffix == '.py':
            return []

        code = path.read_text(encoding='utf-8', errors='replace')
        return self.analyze_code(code, source=path.name)

    def analyze_code(self, code: str, source: str = 'unknown') -> List[Dict[str, Any]]:
        """Analyze Python code string and extract triplets"""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

        triplets = []
        triplets.extend(self._extract_import_triplets(tree, source))
        triplets.extend(self._extract_call_triplets(tree, source))
        triplets.extend(self._extract_pattern_triplets(tree, code, source))
        triplets.extend(self._extract_dataflow_triplets(tree, source))
        triplets.extend(self._extract_error_triplets(tree, source))

        # Deduplicate
        seen = set()
        unique = []
        for t in triplets:
            key = (t['trigger'], t['mechanism'], t['outcome'])
            if key not in seen:
                seen.add(key)
                unique.append(t)

        return unique

    def _extract_import_triplets(self, tree: ast.Module, source: str) -> List[Dict]:
        """Extract triplets from import statements"""
        triplets = []
        imported = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split('.')[0]
                    imported.add(mod)
                    category = self.LIBRARY_CATEGORIES.get(mod, 'general')
                    triplets.append({
                        'trigger': source,
                        'mechanism': 'uses',
                        'outcome': mod,
                        'confidence': 0.95,
                        'source': 'reverse_forge_import',
                    })
                    triplets.append({
                        'trigger': mod,
                        'mechanism': 'type_of',
                        'outcome': category,
                        'confidence': 0.90,
                        'source': 'reverse_forge_category',
                    })

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod = node.module.split('.')[0]
                    imported.add(mod)
                    for alias in node.names:
                        triplets.append({
                            'trigger': mod,
                            'mechanism': 'provides',
                            'outcome': alias.name,
                            'confidence': 0.90,
                            'source': 'reverse_forge_import',
                        })

        # Cross-library relationships
        imported_list = sorted(imported)
        for i in range(len(imported_list)):
            for j in range(i + 1, len(imported_list)):
                triplets.append({
                    'trigger': imported_list[i],
                    'mechanism': 'often_paired_with',
                    'outcome': imported_list[j],
                    'confidence': 0.70,
                    'source': 'reverse_forge_pairing',
                })

        return triplets

    def _extract_call_triplets(self, tree: ast.Module, source: str) -> List[Dict]:
        """Extract triplets from function/method calls"""
        triplets = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # module.method() calls
            if isinstance(node.func, ast.Attribute):
                method = node.func.attr
                if isinstance(node.func.value, ast.Name):
                    obj = node.func.value.id

                    verb = self.METHOD_VERBS.get(method, 'uses')
                    triplets.append({
                        'trigger': obj,
                        'mechanism': verb,
                        'outcome': f'{obj}.{method}',
                        'confidence': 0.85,
                        'source': 'reverse_forge_call',
                    })

                    # Extract arguments as related entities
                    for arg in node.args[:2]:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if len(arg.value) < 100:
                                triplets.append({
                                    'trigger': f'{obj}.{method}',
                                    'mechanism': 'takes_input',
                                    'outcome': arg.value,
                                    'confidence': 0.70,
                                    'source': 'reverse_forge_arg',
                                })

            # Direct function calls: func()
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id
                if func_name not in ('print', 'len', 'str', 'int', 'float', 'bool',
                                     'list', 'dict', 'set', 'tuple', 'range', 'type',
                                     'isinstance', 'hasattr', 'getattr', 'super'):
                    triplets.append({
                        'trigger': source,
                        'mechanism': 'calls',
                        'outcome': func_name,
                        'confidence': 0.80,
                        'source': 'reverse_forge_call',
                    })

        return triplets

    def _extract_pattern_triplets(self, tree: ast.Module, code: str,
                                   source: str) -> List[Dict]:
        """Extract triplets from code patterns (idioms)"""
        triplets = []

        for node in ast.walk(tree):
            # Context managers (with statements)
            if isinstance(node, ast.With):
                for item in node.items:
                    if isinstance(item.context_expr, ast.Call):
                        if isinstance(item.context_expr.func, ast.Name):
                            triplets.append({
                                'trigger': item.context_expr.func.id,
                                'mechanism': 'idiom',
                                'outcome': 'context_manager',
                                'confidence': 0.85,
                                'source': 'reverse_forge_pattern',
                            })

            # List comprehensions
            if isinstance(node, ast.ListComp):
                triplets.append({
                    'trigger': source,
                    'mechanism': 'idiom',
                    'outcome': 'list_comprehension',
                    'confidence': 0.80,
                    'source': 'reverse_forge_pattern',
                })

            # Dict comprehensions
            if isinstance(node, ast.DictComp):
                triplets.append({
                    'trigger': source,
                    'mechanism': 'idiom',
                    'outcome': 'dict_comprehension',
                    'confidence': 0.80,
                    'source': 'reverse_forge_pattern',
                })

            # Generator expressions
            if isinstance(node, ast.GeneratorExp):
                triplets.append({
                    'trigger': source,
                    'mechanism': 'idiom',
                    'outcome': 'generator_expression',
                    'confidence': 0.80,
                    'source': 'reverse_forge_pattern',
                })

            # Decorators
            if isinstance(node, ast.FunctionDef) and node.decorator_list:
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Name):
                        triplets.append({
                            'trigger': dec.id,
                            'mechanism': 'decorates',
                            'outcome': node.name,
                            'confidence': 0.85,
                            'source': 'reverse_forge_pattern',
                        })

            # Class inheritance
            if isinstance(node, ast.ClassDef):
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        triplets.append({
                            'trigger': node.name,
                            'mechanism': 'inherits_from',
                            'outcome': base.id,
                            'confidence': 0.95,
                            'source': 'reverse_forge_pattern',
                        })

        return triplets

    def _extract_dataflow_triplets(self, tree: ast.Module, source: str) -> List[Dict]:
        """Extract data flow: what produces data, what consumes it"""
        triplets = []

        # Track assignments: var = expr
        assignments = {}  # var_name → producer expression description

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var = target.id
                        producer = self._describe_expr(node.value)
                        if producer:
                            assignments[var] = producer

            # Track usages: calls that use tracked variables
            if isinstance(node, ast.Call):
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id in assignments:
                        consumer = self._describe_expr(node.func)
                        if consumer:
                            triplets.append({
                                'trigger': assignments[arg.id],
                                'mechanism': 'feeds_into',
                                'outcome': consumer,
                                'confidence': 0.75,
                                'source': 'reverse_forge_dataflow',
                            })

        return triplets

    def _extract_error_triplets(self, tree: ast.Module, source: str) -> List[Dict]:
        """Extract error handling patterns"""
        triplets = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    if handler.type:
                        exc_name = self._describe_expr(handler.type)
                        if exc_name:
                            # What's in the try block?
                            for try_node in node.body:
                                for inner in ast.walk(try_node):
                                    if isinstance(inner, ast.Call):
                                        call_desc = self._describe_expr(inner.func)
                                        if call_desc:
                                            triplets.append({
                                                'trigger': call_desc,
                                                'mechanism': 'raises',
                                                'outcome': exc_name,
                                                'confidence': 0.85,
                                                'source': 'reverse_forge_error',
                                            })

        return triplets

    def _describe_expr(self, node: ast.AST) -> Optional[str]:
        """Convert an AST expression node to a readable string"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._describe_expr(node.value)
            return f'{val}.{node.attr}' if val else node.attr
        elif isinstance(node, ast.Call):
            return self._describe_expr(node.func)
        elif isinstance(node, ast.Constant):
            return str(node.value)[:50]
        return None

    def analyze_directory(self, directory: str, max_files: int = 100) -> List[Dict]:
        """Analyze all Python files in a directory"""
        path = Path(directory)
        all_triplets = []
        files_processed = 0

        for py_file in sorted(path.rglob('*.py'))[:max_files]:
            triplets = self.analyze_file(str(py_file))
            all_triplets.extend(triplets)
            files_processed += 1

        # Deduplicate
        seen = set()
        unique = []
        for t in all_triplets:
            key = (t['trigger'], t['mechanism'], t['outcome'])
            if key not in seen:
                seen.add(key)
                unique.append(t)

        return unique

    def ingest_into_knowledge(self, triplets: List[Dict]) -> int:
        """Load extracted triplets into the knowledge engine"""
        if not self.knowledge:
            return 0

        count = 0
        for t in triplets:
            # Check for duplicates
            existing = self.knowledge.get_triplet(t['trigger'], t['outcome'])
            if not existing:
                t['_source_graph'] = 'reverse_forge'
                self.knowledge.all_triplets.append(t)
                count += 1

        if count > 0:
            self.knowledge._build_indexes()
            self.knowledge._inference_done = False

        return count
