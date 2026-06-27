"""
Fragment Registry — Metadata extraction for variable wiring

Parses all code fragments at load time to extract:
- produces: variable names assigned by the fragment
- consumes: template variables ({path}, {data}, {url}) the fragment needs
- imports: modules required
- has_output: whether fragment prints output
- role: SOURCE (produces only), SINK (consumes only), TRANSFORM (both)
"""
# Dependencies: none
# Depended by: code_assembler, self_improve


import re
import json
from pathlib import Path
from typing import Dict, List, Set, Optional


# Maps common produced variables to compatible consumer template vars
VARIABLE_COMPATIBILITY = {
    # === HTTP/Network responses ===
    'response': ['data', 'text', 'html', 'content', 'page', 'body'],
    'response.text': ['data', 'text', 'html', 'content', 'string', 'body', 'page'],
    'response.json()': ['data', 'json_data', 'result', 'payload'],
    'response.content': ['data', 'content', 'binary_data', 'raw_data'],
    'html': ['data', 'text', 'content', 'page', 'body', 'string'],
    'page': ['data', 'text', 'html', 'content'],
    'body': ['data', 'text', 'html', 'content', 'string'],

    # === File I/O ===
    'text': ['data', 'content', 'string', 'html', 'body', 'input_text'],
    'content': ['data', 'text', 'string', 'body', 'input_text'],
    'data': ['text', 'content', 'string', 'input_data', 'payload'],
    'lines': ['data', 'items', 'text', 'rows', 'records'],
    'file_content': ['data', 'text', 'content', 'string'],

    # === List/Collection outputs ===
    'files': ['items', 'data', 'paths', 'file_list'],
    'rows': ['data', 'items', 'records', 'entries', 'lines'],
    'items': ['data', 'files', 'results', 'entries', 'elements'],
    'results': ['data', 'items', 'output', 'entries', 'records'],
    'records': ['data', 'items', 'rows', 'entries'],
    'entries': ['data', 'items', 'rows', 'records'],
    'elements': ['data', 'items', 'nodes'],
    'matches': ['data', 'items', 'results', 'found'],
    'urls': ['data', 'items', 'links'],
    'emails': ['data', 'items', 'results', 'addresses'],
    'links': ['data', 'items', 'urls'],

    # === Path/File outputs ===
    'filepath': ['path', 'file', 'input_path', 'filename'],
    'filename': ['path', 'file', 'filepath'],
    'output_path': ['path', 'file', 'filepath'],
    'directory': ['path', 'dir', 'folder'],
    'dir_path': ['path', 'directory', 'folder'],

    # === Database ===
    'conn': ['connection', 'db', 'database'],
    'connection': ['conn', 'db', 'database'],
    'cursor': ['cur', 'db_cursor'],
    'cur': ['cursor', 'db_cursor'],
    'query_results': ['data', 'rows', 'items', 'results', 'records'],
    'db': ['connection', 'conn', 'database'],

    # === Hash/Crypto ===
    'hash_value': ['data', 'result', 'string', 'digest', 'hash_str'],
    'digest': ['data', 'result', 'hash_value', 'string'],
    'encrypted': ['data', 'content', 'ciphertext'],
    'ciphertext': ['data', 'encrypted', 'content'],
    'key': ['secret', 'password', 'token'],

    # === Socket/Network ===
    'open_ports': ['data', 'items', 'results', 'ports'],
    'ports': ['data', 'items', 'open_ports', 'results'],
    'sock': ['socket', 'connection', 'conn'],
    'socket': ['sock', 'connection', 'conn'],
    'host': ['target', 'server', 'address', 'ip'],
    'target': ['host', 'server', 'address', 'ip', 'url'],
    'ip': ['host', 'target', 'address'],

    # === Process/System ===
    'output': ['data', 'text', 'result', 'stdout', 'string'],
    'stdout': ['data', 'text', 'output', 'result', 'string'],
    'process': ['proc', 'result'],
    'result': ['data', 'value', 'output', 'text'],

    # === JSON/Dict ===
    'json_data': ['data', 'result', 'payload', 'content'],
    'parsed': ['data', 'result', 'json_data', 'content'],
    'config': ['data', 'settings', 'options'],
    'payload': ['data', 'json_data', 'body', 'content'],

    # === String ===
    'string': ['data', 'text', 'content', 'input_text'],
    'formatted': ['data', 'text', 'string', 'output'],
    'cleaned': ['data', 'text', 'string', 'content'],
}


class FragmentRegistry:
    """Extract and store metadata about code fragments for variable wiring"""

    def __init__(self):
        self.registry: Dict[str, Dict] = {}

    def analyze_fragment(self, key: str, code: str) -> Dict:
        """Extract metadata from a single fragment"""
        produces = self._extract_produces(code)
        consumes = self._extract_consumes(code)
        imports = self._extract_imports(code)
        has_output = 'print(' in code or 'pprint(' in code

        # Classify role
        has_produces = len(produces) > 0
        has_consumes = len(consumes) > 0

        if has_produces and has_consumes:
            role = 'TRANSFORM'
        elif has_produces:
            role = 'SOURCE'
        elif has_consumes:
            role = 'SINK'
        else:
            role = 'STANDALONE'

        meta = {
            'key': key,
            'produces': produces,
            'consumes': consumes,
            'imports': imports,
            'has_output': has_output,
            'role': role,
        }
        self.registry[key] = meta
        return meta

    def analyze_all(self, fragments: Dict[str, str]):
        """Analyze all fragments in a dict"""
        for key, code in fragments.items():
            # Handle both string and dict fragment formats
            if isinstance(code, dict):
                code = code.get('code', '')
            self.analyze_fragment(key, code)

    def _extract_produces(self, code: str) -> List[str]:
        """Extract variable names that are assigned in the fragment"""
        produces = []
        for line in code.split('\n'):
            stripped = line.strip()
            # Skip function defs, for loops, with blocks, comments
            if stripped.startswith(('def ', 'for ', 'with ', 'if ', 'elif ',
                                   'else:', 'try:', 'except', 'class ', '#',
                                   'import ', 'from ')):
                continue
            # Match simple variable assignment: var = ...
            match = re.match(r'^(\w+)\s*=\s*.+', stripped)
            if match:
                var_name = match.group(1)
                # Skip common non-data assignments
                if var_name not in ('_', 'self', 'cls'):
                    produces.append(var_name)
        return produces

    def _extract_consumes(self, code: str) -> List[str]:
        """Extract template variables ({var}) from fragment"""
        return re.findall(r'\{(\w+)\}', code)

    def _extract_imports(self, code: str) -> List[str]:
        """Extract import statements"""
        imports = []
        for line in code.split('\n'):
            stripped = line.strip()
            if stripped.startswith('import ') or stripped.startswith('from '):
                imports.append(stripped)
        return imports

    def get_wiring(self, source_key: str, sink_key: str) -> Optional[Dict[str, str]]:
        """
        Determine how to wire source fragment output into sink fragment input.

        Returns dict mapping sink template vars to source variable expressions,
        or None if no wiring possible.
        """
        source = self.registry.get(source_key)
        sink = self.registry.get(sink_key)

        if not source or not sink:
            return None

        wiring = {}
        source_produces = source['produces']
        sink_consumes = sink['consumes']

        for consume_var in sink_consumes:
            # Direct match: source produces exactly what sink needs
            if consume_var in source_produces:
                wiring[consume_var] = consume_var
                continue

            # Compatibility match: source produces something compatible
            for produced in source_produces:
                compatible_vars = VARIABLE_COMPATIBILITY.get(produced, [])
                if consume_var in compatible_vars:
                    wiring[consume_var] = produced
                    break

                # Reverse check: consume_var is compatible with produced
                consume_compatible = VARIABLE_COMPATIBILITY.get(consume_var, [])
                if produced in consume_compatible:
                    wiring[consume_var] = produced
                    break

        return wiring if wiring else None

    def get_meta(self, key: str) -> Optional[Dict]:
        """Get metadata for a fragment key"""
        return self.registry.get(key)

    def get_sources(self) -> List[str]:
        """Get all SOURCE fragments"""
        return [k for k, v in self.registry.items() if v['role'] == 'SOURCE']

    def get_sinks(self) -> List[str]:
        """Get all SINK fragments"""
        return [k for k, v in self.registry.items() if v['role'] == 'SINK']

    def get_transforms(self) -> List[str]:
        """Get all TRANSFORM fragments"""
        return [k for k, v in self.registry.items() if v['role'] == 'TRANSFORM']
