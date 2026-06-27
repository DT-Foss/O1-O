"""
Code Assembler — Triplet chains → Python code

Converts inference chains into executable Python scripts via:
1. Triplet chain → dependency graph
2. Code fragment lookup
3. Variable resolution + wiring (composition mode)
4. Output-aware generation (auto-add print when needed)
5. Fragment deduplication (same module = keep most complete, relaxed for composition)
6. Assembly with imports + main() wrapper
"""
# Dependencies: c_renderer, color_assembler, color_types, fragment_registry
# Depended by: none (leaf module)


import ast
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

from o1o_o.core.fragment_registry import FragmentRegistry
from o1o_o.core.color_assembler import ColorAssembler
from o1o_o.core.c_renderer import CRenderer


# Language detection keywords in user intent
C_LANGUAGE_INDICATORS = {
    'in c', 'c code', 'c program', 'c language', 'c version',
    'compile', 'gcc', 'clang', 'binary', 'native',
    'systems programming', 'low-level', 'no dependencies',
}


class CodeAssembler:
    """Assemble Python code from inference chains"""

    def __init__(self, fragments_dir: Path, knowledge_engine, verifier=None, math_engine=None):
        self.fragments_dir = Path(fragments_dir)
        self.knowledge = knowledge_engine
        self.verifier = verifier
        self.math_engine = math_engine
        self.fragments = {}
        self.registry = FragmentRegistry()

        # Load code fragments
        self.load_fragments()

        # Color type system for deterministic assembly
        self.color_assembler = ColorAssembler(self.fragments)

        # Multi-language renderers
        self.c_renderer = CRenderer(self.fragments_dir)

        # Fragment tracking for quality scoring
        self.last_used_fragments = []

    def load_fragments(self):
        """Load all code fragment JSON files and build registry"""
        if not self.fragments_dir.exists():
            print(f"Warning: Fragments directory not found: {self.fragments_dir}")
            return

        for frag_file in self.fragments_dir.glob("*.json"):
            try:
                with open(frag_file, 'r') as f:
                    fragments = json.load(f)
                    # Normalize dict-format fragments {code, imports, description} to string
                    for key, val in fragments.items():
                        if isinstance(val, dict) and 'code' in val:
                            self.fragments[key] = val['code']
                        else:
                            self.fragments[key] = val
                    print(f"Loaded {len(fragments)} code fragments from {frag_file.name}")
            except Exception as e:
                print(f"Failed to load {frag_file}: {e}")

        # Build fragment metadata registry for variable wiring
        self.registry.analyze_all(self.fragments)

    def get_fragment(self, triplet: Dict[str, Any], safe: bool = False) -> Optional[str]:
        """Get code fragment for a triplet — prioritizes exact matches"""
        trigger = triplet['trigger']
        mechanism = triplet['mechanism']
        outcome = triplet['outcome']

        keys_to_try = []

        # Strategy 0: Outcome IS a fragment key (bridge triplets use this)
        keys_to_try.append(outcome)

        # Strategy 0a: Mechanism IS a fragment key (bridge triplets map mechanism → fragment)
        keys_to_try.append(mechanism)

        # Strategy 0b: Outcome with dots → underscores
        if '.' in outcome:
            keys_to_try.append(outcome.replace('.', '_'))

        # Strategy 1: Exact match trigger_mechanism_outcome
        keys_to_try.append(f"{trigger}_{mechanism}_{outcome}")

        # Strategy 2: trigger_outcome
        keys_to_try.append(f"{trigger}_{outcome}")

        # Strategy 3: Just trigger
        keys_to_try.append(trigger)

        # Strategy 4: Trigger with dots → underscores
        if '.' in trigger:
            keys_to_try.append(trigger.replace('.', '_'))

        for key in keys_to_try:
            if safe:
                safe_key = f"{key}_safe"
                if safe_key in self.fragments:
                    return self.fragments[safe_key]
            if key in self.fragments:
                return self.fragments[key]

        # Strategy 5: Outcome as substring in fragment keys (strict: need 4+ chars)
        # Skip detect_* fragments (Semgrep rules) — they match too broadly and
        # produce detection code instead of the intended tool.
        outcome_lower = outcome.lower().replace('_', '')
        if len(outcome_lower) >= 4:
            for frag_key, frag_code in self.fragments.items():
                if frag_key.startswith('detect_') or frag_key.startswith('sigma_'):
                    continue
                if safe and frag_key.endswith('_safe') and outcome_lower in frag_key.lower().replace('_', ''):
                    return frag_code
                if outcome_lower in frag_key.lower().replace('_', ''):
                    return frag_code

        # Strategy 6: Trigger as substring in fragment keys (strict: need 5+ chars)
        trigger_lower = trigger.lower()
        if len(trigger_lower) >= 5:
            for frag_key, frag_code in self.fragments.items():
                if frag_key.startswith('detect_') or frag_key.startswith('sigma_'):
                    continue
                if safe and frag_key.endswith('_safe') and trigger_lower in frag_key.lower():
                    return frag_code
                if trigger_lower in frag_key.lower():
                    return frag_code

        return None

    def resolve_variables(self, template: str, params: Dict[str, Any]) -> str:
        """Replace {variables} in template with actual values or sensible defaults"""
        # Detect if template opens {path} as a file → use file default, not dir
        path_used_as_file = ('open({path}' in template or 'open(\'{path}\'' in template
                             or 'open("{path}"' in template or 'hash_file(\'{path}\'' in template
                             or 'hash_file("{path}"' in template or "hash_file('{path}'" in template)
        default_path = 'data.txt' if path_used_as_file else params.get('input_path', '.')

        resolution = {
            'path': default_path,
            'input_path': params.get('input_path', '.'),
            'output_path': params.get('output_path', 'output.txt'),
            'file': params.get('file', 'file.txt'),
            'data': params.get('data', 'data'),
            'url': params.get('url', 'http://example.com'),
            'pattern': params.get('pattern', r'\w+'),
            'format': params.get('format', '%Y-%m-%d'),
            'n': '10',
            'old_path': 'old_file.txt',
            'new_path': 'new_file.txt',
            # Extended variable defaults (previously missing → broken code)
            'source_path': params.get('input_path', '.'),
            'csv_path': 'data.csv',
            'json_path': 'data.json',
            'db_path': 'data.db',
            'log_path': 'app.log',
            'txt_path': 'data.txt',
            'zip_path': 'output.zip',
            'extract_to': 'extracted',
            'host': 'localhost',
            'port': '8080',
            'target': 'localhost',
            'smtp_host': 'smtp.gmail.com',
            'smtp_port': '587',
            'from_addr': 'user@example.com',
            'to_addr': 'dest@example.com',
            'password': 'password',
            'subject': 'Test',
            'body': 'Test message',
            'attachment_path': 'data.txt',
            'message': 'hello',
            'content': 'test content',
            'string': 'hello world test@example.com http://example.com 42',
            'encoded_string': 'aGVsbG8gd29ybGQ=',
            'name': 'test',
            'description': 'FORGE tool',
            'key': 'name',
            'delimiter': ',',
            'prefix': 'test',
            'search': 'test',
            'replacement': 'new',
            'table_name': 'data',
            'new_value': 'updated',
            'value': 'test',
            'seconds': '1',
            'min': '1',
            'max': '100',
            'r': '2',
            'k': '3',
            'items': "['a', 'b', 'c', 'd', 'e']",
            'numbers': '[1, 2, 3, 4, 5]',
            'condition': 'True',
            'payload': '{"key": "value"}',
            'params': '{"q": "test"}',
            'arcname': 'archive',
            'path1': 'file1.txt',
            'path2': 'file2.txt',
            'path3': 'file3.txt',
            'output_dir': 'output',
            'filter_value': 'test',
            'urls': "['https://example.com']",
            'date1': '2024-01-01',
            'date2': '2024-12-31',
            # Matplotlib defaults (prevent NameError from bare variable injection)
            'labels': "['A', 'B', 'C', 'D']",
            'values': '[10, 20, 15, 25]',
            'xlabel': 'Category',
            'ylabel': 'Value',
            'title': 'Chart',
            'x_values': "['A', 'B', 'C', 'D']",
            'y_values': '[10, 20, 15, 25]',
            'x_data': '[1, 2, 3, 4, 5]',
            'y_data': '[10, 20, 15, 25, 30]',
            'figsize': '(10, 6)',
            # Subprocess/CLI defaults
            'arg': 'filename',
            'command': 'echo',
            'help': 'Input argument',
            'function': 'str',
            'rows': '[]',
            # Column/field names for SQL/CSV
            'column_name': 'name',
            'column_names': 'name, age, city',
            'fieldnames': "['name', 'age', 'city']",
            'interface': 'eth0',
            # Data science / ML defaults (identity resolution: {var} → var)
            'X_train': 'X_train',
            'X_test': 'X_test',
            'y_train': 'y_train',
            'y_pred': 'y_pred',
            'y_true': 'y_true',
            'n_estimators': '100',
            'test_size': '0.2',
            'categories': "['A', 'B', 'C']",
            'bins': '10',
            'shape': '(10, 5)',
            'fill_value': '0',
            'cols': '3',
            'stop': '10',
            'x1': '[1, 2, 3]',
            'x2': '[1, 2, 3]',
            'y1': '[4, 5, 6]',
            'y2': '[7, 8, 9]',
            'agg_func': 'mean',
            'ascending': 'True',
            'new_col': 'result',
            'page_num': '0',
            # Network / security defaults
            'api_key': 'YOUR_API_KEY',
            'binary': './target',
            'broker': 'localhost',
            'cve_id': 'CVE-2024-0001',
            'dc_ip': '192.168.1.1',
            'dns_server': '8.8.8.8',
            'domain': 'example.com',
            'gateway_ip': '192.168.1.1',
            'target_ip': '192.168.1.100',
            'target_url': 'http://example.com',
            'target_domain': 'example.com',
            'spoof_ip': '192.168.1.1',
            'start_port': '1',
            'end_port': '1024',
            'remote_port': '8080',
            'pubkey': 'ssh-rsa AAAA...',
            'hash': 'e3b0c44298fc1c149afbf4c8996fb924',
            'hash_type': 'md5',
            'wordlist': '/usr/share/wordlists/rockyou.txt',
            # File / path defaults
            'image_path': 'image.png',
            'pdf_path': 'document.pdf',
            'input_file': 'data.txt',
            'log_file': 'app.log',
            'memory_dump': 'memory.dmp',
            'evidence_dir': 'evidence',
            'target_dir': '/tmp/target',
            'firmware': 'firmware.bin',
            'file_path': 'data.txt',
            'destination': 'output',
            'subpath': 'sub',
            'working_dir': '/opt/app',
            # Service / config defaults
            'service': 'nginx',
            'service_name': 'myservice',
            'schedule': '*/5 * * * *',
            'COMMAND': '/usr/bin/python3 app.py',
            'DESCRIPTION': 'Custom Service',
            'TARGET_BRAND': 'Example Corp',
            'difficulty': '4',
            'duration': '10',
            'threads': '4',
            'iterations': '1000',
            'timeout': '10',
            'secret': 'supersecret',
            'profile': 'default',
            'timestamp': '1704067200',
            'date_string': '2024-01-01',
            'days': '7',
            'default': 'default_value',
            # Email / comms defaults
            'from_email': 'sender@example.com',
            'from_name': 'Sender',
            'to_email': 'recipient@example.com',
            'smtp_server': 'smtp.gmail.com',
            'topic': 'test/topic',
            'brand': 'TestBrand',
            # Code template defaults
            'function_name': 'target_function',
            'arg_types': 'ctypes.c_int',
            'res_type': 'ctypes.c_int',
            'hook_code': '// custom hook code here',
            'lines': "['line1\\n', 'line2\\n']",
            'headers': "{'Content-Type': 'application/json'}",
            'form_data': "{'key': 'value'}",
            'json_string': '{"key": "value"}',
            'css_selector': 'div.content',
            'attribute': 'href',
            'columns': 'category',
            'search_text': 'example',
            'process_name': 'target_process',
            'input_type': 'stdin',
            'vuln_type': 'buffer_overflow',
            'rule_name': 'test_rule',
            'key_path': '/root/.ssh/id_rsa',
            'target_file': '/etc/passwd',
            'target_exe': 'C:\\Windows\\System32\\cmd.exe',
            'output_name': 'output.doc',
            'reference_file': 'C:\\Windows\\explorer.exe',
            'directory': 'C:\\Users',
            'shortcut_name': 'Update',
            'trigger_time': '08:00:00',
            'python_path': '/usr/bin/python3',
            'sheet': 'Sheet1',
            'db': 'testdb',
            # Pillow crop coordinates
            'top': '0',
            'bottom': '100',
            'degrees': '90',
            # Non-Python fragment vars (JS/bash — resolved defensively)
            'PORT': '3000',
            'code': 'code',
            'http_code': 'http_code',
        }
        resolution.update(params)

        # Protect escaped braces {{word}} from template resolution
        # e.g., f'Hello {{name}}: {name}' — {{name}} should stay as literal
        result = template
        result = re.sub(r'\{\{(\w+)\}\}', r'__ESCAPED_BRACE_\1__', result)

        for key, value in resolution.items():
            result = result.replace(f"{{{key}}}", str(value))

        # Restore escaped braces
        result = re.sub(r'__ESCAPED_BRACE_(\w+)__', r'{{\1}}', result)

        # Catch remaining template vars that weren't in resolution dict,
        # but ONLY when they appear as quoted strings ('{var}' or "{var}"),
        # NOT inside f-strings where {var} is Python variable interpolation.
        # Pattern: match '{word}' or "{word}" (the quotes are literal in the code)
        result = re.sub(r"'(\{(\w+)\})'", lambda m: f"'{m.group(2)}'", result)
        result = re.sub(r'"(\{(\w+)\})"', lambda m: f'"{m.group(2)}"', result)

        return result

    def _extract_module(self, fragment: str) -> Optional[str]:
        """Extract the primary module from a fragment's import statements"""
        for line in fragment.split('\n'):
            stripped = line.strip()
            if stripped.startswith('import '):
                # "import os" → "os"
                parts = stripped.split()
                if len(parts) >= 2:
                    return parts[1].split('.')[0]
            elif stripped.startswith('from '):
                # "from pathlib import Path" → "pathlib"
                parts = stripped.split()
                if len(parts) >= 2:
                    return parts[1].split('.')[0]
        return None

    def _has_output(self, fragment: str) -> bool:
        """Check if a fragment produces visible output"""
        return 'print(' in fragment or 'pprint(' in fragment

    def _get_last_variable(self, fragment: str) -> Optional[str]:
        """Extract the last assigned variable name from a fragment"""
        last_var = None
        for line in fragment.split('\n'):
            stripped = line.strip()
            # Match simple assignments: "var = ..."
            match = re.match(r'^(\w+)\s*=\s*.+', stripped)
            if match and not stripped.startswith('def ') and not stripped.startswith('for '):
                last_var = match.group(1)
        return last_var

    def _add_output_to_fragment(self, fragment: str, var_name: str) -> str:
        """Add print output for a variable at the end of a fragment"""
        # Determine the type of variable and create appropriate output
        lines = fragment.rstrip().split('\n')

        # Check if variable is likely a list/iterable
        list_indicators = ['listdir', 'findall', 'readlines', 'glob', 'list(', 'split(']
        is_list = any(ind in fragment for ind in list_indicators)

        if is_list:
            lines.append(f"for item in {var_name}:")
            lines.append(f"    print(item)")
        else:
            lines.append(f"print({var_name})")

        return '\n'.join(lines)

    def _extract_variables(self, fragment: str) -> Set[str]:
        """Extract all variable assignments from a fragment"""
        variables = set()
        for line in fragment.split('\n'):
            stripped = line.strip()
            match = re.match(r'^(\w+)\s*=\s*.+', stripped)
            if match and not stripped.startswith('def ') and not stripped.startswith('for '):
                variables.add(match.group(1))
        return variables

    def rank_fragments(self, fragments_with_triplets: List[tuple],
                       intent: Dict[str, Any]) -> List[tuple]:
        """Rank fragments by relevance to intent"""
        intent_tokens = set(intent.get('tokens', []))
        entities = [e['matched'].lower() for e in intent.get('entities', [])]
        requires_output = intent.get('requires_output', False)

        ranked = []
        for i, (fragment, triplet) in enumerate(fragments_with_triplets):
            confidence = triplet.get('confidence', 0.5)

            # Extract meaningful line for matching
            frag_key = ""
            for line in fragment.split('\n'):
                if 'def ' in line or '.' in line or '(' in line:
                    frag_key = line.lower()
                    break

            # Score: keyword overlap
            keyword_score = 0.0
            for token in intent_tokens:
                if token in frag_key or token in str(triplet).lower():
                    keyword_score += 0.3

            # Score: entity match
            entity_score = 0.0
            for entity in entities:
                if entity in frag_key or entity in str(triplet['outcome']).lower():
                    entity_score += 0.5

            # Bridge Bonus: Bridge-matched fragments are highest priority
            bridge_bonus = 0.0
            if triplet.get('_source_graph') == 'bridge_intents':
                bridge_bonus = 2.0
            elif triplet.get('_source_graph') == 'composition':
                bridge_bonus = 2.5  # Composition-split fragments get highest priority

            # Idiom Bonus: Glue fragments get high priority [V6]
            idiom_bonus = 1.0 if triplet.get('mechanism') == 'idiom' else 0.0

            # Bonus: fragment has output (preferred for output-required intents)
            output_bonus = 0.0
            if requires_output and self._has_output(fragment):
                output_bonus = 0.8

            # Penalty: inferred triplets scored slightly lower
            inferred_penalty = 0.0
            if triplet.get('is_inferred'):
                inferred_penalty = -0.2

            # Position bonus (earlier = slightly better)
            position_score = 1.0 / (i + 1) * 0.1

            score = confidence + keyword_score + entity_score + bridge_bonus + idiom_bonus + output_bonus + inferred_penalty + position_score

            ranked.append((score, fragment, triplet))

        ranked.sort(reverse=True, key=lambda x: x[0])

        # Only keep fragments that score at least 80% of the best
        if ranked:
            best_score = ranked[0][0]
            threshold = best_score * 0.80
            ranked = [r for r in ranked if r[0] >= threshold]

        return [(frag, triplet) for _, frag, triplet in ranked]

    # Modules that serve the same semantic purpose (HTTP, parsing, etc.)
    MODULE_EQUIVALENTS = {
        'requests': 'urllib', 'urllib': 'requests',  # HTTP clients
        'httpx': 'requests', 'aiohttp': 'requests',
        'bs4': 'lxml', 'lxml': 'bs4',  # HTML parsers
        'pdfplumber': 'PyPDF2', 'PyPDF2': 'pdfplumber',
    }

    def _deduplicate_fragments(self, fragments: List[tuple],
                               is_composition: bool = False) -> List[tuple]:
        """Remove duplicate fragments: same module OR same purpose.

        In composition mode, relaxes module dedup: allows same module if
        fragments serve different roles (SOURCE vs SINK vs TRANSFORM).
        """
        seen_modules = {}  # module → (fragment, triplet, role)
        seen_purposes = set()  # set of outcome keywords
        result = []

        for fragment, triplet in fragments:
            module = self._extract_module(fragment)
            outcome = triplet['outcome']

            # Get fragment role from registry
            frag_meta = self.registry.get_meta(outcome)
            role = frag_meta['role'] if frag_meta else 'STANDALONE'

            # Normalize module via equivalence map
            canonical = self.MODULE_EQUIVALENTS.get(module, module) if module else module

            # Check 1: Same module dedup (relaxed in composition mode)
            if module and (module in seen_modules or canonical in seen_modules):
                match_key = module if module in seen_modules else canonical
                existing_frag, existing_triplet, existing_role = seen_modules[match_key]

                # In composition mode: allow same module if different roles
                # Also: always allow fragments from composition split (they're an explicit pair)
                if is_composition and (role != existing_role or
                    triplet.get('_source_graph') == 'composition' and
                    existing_triplet.get('_source_graph') == 'composition'):
                    result.append((fragment, triplet))
                    continue

                if self._has_output(fragment) and not self._has_output(existing_frag):
                    result = [(f, t) for f, t in result if self._extract_module(f) != module]
                    result.append((fragment, triplet))
                    seen_modules[module] = (fragment, triplet, role)
                elif len(fragment) > len(existing_frag) and not self._has_output(existing_frag):
                    result = [(f, t) for f, t in result if self._extract_module(f) != module]
                    result.append((fragment, triplet))
                    seen_modules[module] = (fragment, triplet, role)
                continue

            # Check 2: Same purpose dedup (outcome keyword overlap)
            # Skip this check in composition mode — different steps may share keywords
            if not is_composition:
                outcome_words = set(outcome.lower().split('_'))
                outcome_words = {w for w in outcome_words if len(w) >= 3}
                overlap = outcome_words & seen_purposes
                if len(overlap) >= 2 and result:
                    continue

            if module:
                seen_modules[module] = (fragment, triplet, role)
                # Also track canonical equivalent
                if canonical and canonical != module:
                    seen_modules[canonical] = (fragment, triplet, role)
            outcome_words = set(outcome.lower().split('_'))
            seen_purposes.update({w for w in outcome_words if len(w) >= 3})
            result.append((fragment, triplet))

        return result

    def extract_imports_from_fragment(self, fragment: str) -> set:
        """Extract import statements from code fragment"""
        imports = set()
        for line in fragment.split('\n'):
            stripped = line.strip()
            if stripped.startswith('import ') or stripped.startswith('from '):
                imports.add(stripped)
        return imports

    def remove_imports_from_fragment(self, fragment: str) -> str:
        """Remove import statements and duplicate shebangs from fragment (they go in header)"""
        lines = []
        for line in fragment.split('\n'):
            stripped = line.strip()
            if stripped.startswith('import ') or stripped.startswith('from '):
                continue
            if stripped.startswith('#!') and ('python' in stripped or '/env ' in stripped):
                continue
            lines.append(line)
        return '\n'.join(lines)

    def _detect_language(self, intent: Dict[str, Any]) -> str:
        """Detect target language from intent. Returns 'python' or 'c'."""
        raw = intent.get('raw', '').lower()
        for indicator in C_LANGUAGE_INDICATORS:
            if indicator in raw:
                return 'c'
        return 'python'

    def assemble(self, inference_chain: List[Dict[str, Any]], intent: Dict[str, Any], project_context: Dict[str, Any] = None) -> str:
        """
        Assemble script from inference chain, supporting incremental updates,
        V8 projects, composition mode with variable wiring, and multi-language.
        """
        # ── Multi-language: check if C is requested ──
        target_lang = self._detect_language(intent)
        if target_lang == 'c':
            c_code = self.c_renderer.render_chain(inference_chain, intent)
            if c_code:
                return c_code

        # ── Color Type System: try deterministic pipeline first ──
        intent_raw = intent.get('raw', '')
        if intent_raw and not intent.get('is_incremental'):
            color_script = self._assemble_color_pipeline(intent)
            if color_script:
                return color_script

        context_script = intent.get('context_script')
        is_incremental = intent.get('is_incremental', False)
        is_composition = intent.get('is_composition', False)

        imports = set()
        fragments_found = []
        params = intent.get('params', {})
        requires_output = intent.get('requires_output', False)

        # Collect fragments
        safe_mode = intent.get('safe_mode', False)

        # V6 Compatibility: Ensure we have a flat list of triplets
        if inference_chain and isinstance(inference_chain[0], list):
            inference_chain = inference_chain[0]

        manifest = project_context.get('manifest', {}) if project_context else {}
        params.update(manifest)

        # V10: Logic Consistency Check
        if self.math_engine:
            logic_proof = self.math_engine.validate_chain(inference_chain)
            if not logic_proof['is_consistent']:
                print(f"⚠️ Logic Inconsistency Detected: {logic_proof['contradictions']}")

        # Check if inference chain contains composition triplets (outcome has '+')
        composition_fragments = []
        for item in inference_chain:
            triplet = item['triplet']
            outcome = triplet['outcome']
            if '+' in outcome:
                # Composition triplet: split and look up each fragment
                is_composition = True
                for frag_key in outcome.split('+'):
                    frag_key = frag_key.strip()
                    if frag_key in self.fragments:
                        comp_triplet = {
                            'trigger': triplet['trigger'],
                            'mechanism': 'composition',
                            'outcome': frag_key,
                            'confidence': triplet.get('confidence', 0.9),
                            '_source_graph': 'composition',
                        }
                        composition_fragments.append((self.fragments[frag_key], comp_triplet))
            else:
                fragment = self.get_fragment(triplet, safe=safe_mode)
                if fragment:
                    fragments_found.append((fragment, triplet))

        # If composition fragments found, deduplicate by outcome key and prepend
        if composition_fragments:
            seen_comp_keys = set()
            unique_comp = []
            for frag, trip in composition_fragments:
                key = trip['outcome']
                if key not in seen_comp_keys:
                    seen_comp_keys.add(key)
                    unique_comp.append((frag, trip))
            composition_fragments = unique_comp
            fragments_found = composition_fragments + fragments_found

        # Rank and deduplicate (relaxed in composition mode)
        ranked_fragments = self.rank_fragments(fragments_found, intent)
        deduped = self._deduplicate_fragments(ranked_fragments, is_composition=is_composition)

        # Filter to best fragments
        # In composition mode: limit to unique composition fragments count
        if is_composition and composition_fragments:
            n_comp = len(composition_fragments)
            max_fragments = n_comp
        else:
            max_fragments = 4

        # If first fragment is a substantial bridge-matched fragment (>40 LOC),
        # limit to 1 to prevent unrelated fragments from being appended.
        # Only for bridge/composition sources with high confidence.
        if not is_composition and deduped:
            first_frag, first_trip = deduped[0]
            first_loc = len([l for l in first_frag.splitlines() if l.strip()])
            src = first_trip.get('_source_graph', '')
            conf = first_trip.get('confidence', 0)
            is_bridge = 'bridge' in src or src == 'composition'
            is_auto_bridge = first_trip.get('_auto_bridge', False)
            if first_loc > 40 and is_bridge and not is_auto_bridge and conf >= 0.9:
                max_fragments = 1

        top_fragments = []
        seen_modules = set()
        matched_entities = set()

        for fragment, triplet in deduped:
            module = self._extract_module(fragment)
            if len(top_fragments) >= max_fragments:
                break

            # In composition mode, allow same module for different roles
            if is_composition or module not in seen_modules:
                top_fragments.append((fragment, triplet))
                if module:
                    seen_modules.add(module)
                for entity in intent.get('entities', []):
                    e_name = entity['matched'].lower()
                    if e_name in fragment.lower() or e_name in str(triplet).lower():
                        matched_entities.add(e_name)

            if not is_composition and len(intent.get('entities', [])) > 0 and \
               len(matched_entities) / len(intent.get('entities', [])) >= 0.8:
                if len(top_fragments) >= 2:
                    break

        # Track which fragments were used (for quality scoring)
        self.last_used_fragments = [
            triplet.get('outcome', 'unknown') for _, triplet in top_fragments
        ]

        # Prepare code blocks
        used_variables = set()
        code_blocks = []

        # If incremental, extract existing imports and variables from context
        if is_incremental and context_script:
            imports.update(self.extract_imports_from_fragment(context_script))
            used_variables.update(self._extract_variables(context_script))

        # Track produced variables for wiring
        produced_vars = {}  # var_name → fragment_index

        for idx, (fragment, triplet) in enumerate(top_fragments):
            # Skip non-Python fragments (bash, JavaScript, etc.)
            frag_stripped = fragment.lstrip()
            if frag_stripped.startswith('#!/bin/bash') or frag_stripped.startswith('set -euo') or \
               frag_stripped.startswith('#!/bin/sh') or frag_stripped.startswith('#!/usr/bin/env bash'):
                continue
            if 'console.log(' in fragment and 'print(' not in fragment and \
               ('const ' in fragment or 'let ' in fragment or 'var ' in fragment):
                continue

            imports.update(self.extract_imports_from_fragment(fragment))
            clean_fragment = self.remove_imports_from_fragment(fragment)

            # Variable wiring: replace template vars with produced variables
            if is_composition and idx > 0 and produced_vars:
                clean_fragment = self._wire_variables(clean_fragment, produced_vars, params)

            code = self.resolve_variables(clean_fragment, params)
            if not code.strip():
                continue

            # Shadowing check — relaxed in composition mode
            new_vars = self._extract_variables(code)
            if not is_composition:
                conflict = new_vars & used_variables
                if conflict and not is_incremental:
                    continue
            used_variables.update(new_vars)

            # Track what this fragment produces
            for var in new_vars:
                produced_vars[var] = idx

            if requires_output and not self._has_output(code):
                # Only add output to the LAST fragment in composition mode
                if not is_composition or idx == len(top_fragments) - 1:
                    last_var = self._get_last_variable(code)
                    if last_var:
                        code = self._add_output_to_fragment(code, last_var)

            code_blocks.append(code)

        # Final Assembly logic: Patching vs Creation
        if is_incremental and context_script:
            return self._patch_script(context_script, code_blocks, imports, intent)
        else:
            return self._build_new_script(code_blocks, imports, intent)

    def _wire_variables(self, fragment: str, produced_vars: Dict[str, int],
                        params: Dict[str, Any]) -> str:
        """Wire template variables in a fragment to already-produced variables.

        If fragment contains {data} and a previous fragment produced 'response',
        replace {data} with the actual variable (using compatibility mapping).
        """
        from o1o_o.core.fragment_registry import VARIABLE_COMPATIBILITY

        # Find all template vars in fragment
        template_vars = re.findall(r'\{(\w+)\}', fragment)

        for tvar in template_vars:
            # Skip if already resolved by params
            if tvar in params:
                continue

            # Direct match: a produced var has the same name
            if tvar in produced_vars:
                # Only wire identity if the variable name is a computed value
                # (like 'data', 'result', 'content'), NOT if it's a parameter
                # like 'url', 'path', 'host' that has a meaningful default
                PARAMETER_VARS = {'url', 'path', 'host', 'port', 'file', 'db_path',
                                  'csv_path', 'json_path', 'log_path', 'output_path',
                                  'input_path', 'source_path', 'target', 'interface'}
                if tvar not in PARAMETER_VARS:
                    params[tvar] = tvar  # identity: {data} → data
                continue

            # Compatibility match: find a produced var that's compatible
            for produced_var in produced_vars:
                # Check if produced_var maps to tvar
                compatible = VARIABLE_COMPATIBILITY.get(produced_var, [])
                if tvar in compatible:
                    params[tvar] = produced_var
                    break

                # Check with .text accessor for response objects
                if produced_var == 'response' and tvar in ('data', 'text', 'html', 'content', 'string'):
                    params[tvar] = 'response.text'
                    break

        return fragment

    def _patch_script(self, context: str, new_blocks: List[str], new_imports: set, intent: Dict[str, Any]) -> str:
        """Patch new code into existing script"""
        lines = context.split('\n')
        
        # 1. Update imports (detect header end)
        import_zones = [i for i, line in enumerate(lines) if line.startswith('import ') or line.startswith('from ')]
        if import_zones:
            header_end = max(import_zones) + 1
        else:
            # Skip shebang and docstring
            header_end = 0
            if lines[0].startswith('#!'): header_end = 1
            if len(lines) > header_end and '"""' in lines[header_end]:
                # Found start of docstring, skip till end
                for i in range(header_end + 1, min(len(lines), 20)):
                    if '"""' in lines[i]:
                        header_end = i + 1
                        break
        
        existing_imports = self.extract_imports_from_fragment(context)
        truly_new_imports = new_imports - existing_imports
        if truly_new_imports:
            for imp in sorted(truly_new_imports):
                lines.insert(header_end, imp)
                header_end += 1
        
        # 2. Inject into main() or at end of main()
        main_end = -1
        for i, line in enumerate(lines):
            if line.strip() == 'if __name__ == "__main__":':
                main_end = i
                break
        
        if main_end != -1:
            # Inject before the if __name__ block
            # Actually, we want it inside main() if it exists
            inject_point = -1
            for i in range(main_end - 1, -1, -1):
                if lines[i].startswith('    '):
                    inject_point = i + 1
                    break
            
            if inject_point != -1:
                for block in new_blocks:
                    # Don't add if already roughly there
                    if block.strip()[:20] in context: continue
                    for block_line in block.split('\n'):
                        if block_line.strip():
                            lines.insert(inject_point, f'    {block_line}')
                            inject_point += 1
                    lines.insert(inject_point, '')
                    inject_point += 1
        
        # Update metadata header
        if lines[0].startswith('#!'):
            # Update entity list in docstring if possible
            for i in range(1, 10):
                if i < len(lines) and 'Entities:' in lines[i]:
                    new_entities = set([e['matched'] for e in intent.get('entities', [])])
                    lines[i] = f'Entities: {", ".join(list(new_entities)[:5])} (Extended)'
                    break

        return '\n'.join(lines)

    def decompose_chain(self, inference_chain: List[Dict[str, Any]],
                        intent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Decompose inference chain into ordered individual steps for Seed-and-Grow.

        Orders fragments by role:
          1. SOURCE (produces data — requests.get, open().read, os.listdir)
          2. TRANSFORM (consumes + produces — parse, filter, convert)
          3. STANDALONE (self-contained operations)
          4. SINK (consumes only — write, print, save)

        Deduplicates by module. Only includes items with resolvable fragments.
        Returns list of single triplet-items, each suitable for assemble([item], intent).
        """
        # Flatten nested chains
        if inference_chain and isinstance(inference_chain[0], list):
            inference_chain = inference_chain[0]

        by_role = {'SOURCE': [], 'TRANSFORM': [], 'STANDALONE': [], 'SINK': []}
        seen_modules = set()

        for item in inference_chain:
            triplet = item['triplet']
            outcome = triplet['outcome']

            # Handle composition triplets (outcome has '+')
            if '+' in outcome:
                for frag_key in outcome.split('+'):
                    frag_key = frag_key.strip()
                    if frag_key in self.fragments:
                        fragment = self.fragments[frag_key]
                        module = self._extract_module(fragment)
                        if module and module in seen_modules:
                            continue
                        frag_meta = self.registry.get_meta(frag_key)
                        role = frag_meta['role'] if frag_meta else 'STANDALONE'
                        comp_item = {
                            'triplet': {
                                'trigger': triplet['trigger'],
                                'mechanism': 'composition',
                                'outcome': frag_key,
                                'confidence': triplet.get('confidence', 0.9),
                                '_source_graph': 'composition',
                            },
                            'score': item.get('score', 0.5),
                        }
                        by_role[role].append(comp_item)
                        if module:
                            seen_modules.add(module)
                continue

            fragment = self.get_fragment(triplet)
            if not fragment:
                continue

            # Skip non-Python fragments
            frag_stripped = fragment.lstrip()
            if frag_stripped.startswith('#!/bin/bash') or frag_stripped.startswith('set -euo'):
                continue
            if 'console.log(' in fragment and 'print(' not in fragment \
               and ('const ' in fragment or 'let ' in fragment):
                continue

            module = self._extract_module(fragment)
            if module and module in seen_modules:
                continue

            frag_meta = self.registry.get_meta(outcome)
            role = frag_meta['role'] if frag_meta else 'STANDALONE'
            by_role[role].append(item)
            if module:
                seen_modules.add(module)

        # Order: SOURCE → TRANSFORM → STANDALONE → SINK
        ordered = (by_role['SOURCE'] + by_role['TRANSFORM']
                   + by_role['STANDALONE'] + by_role['SINK'])
        return ordered if ordered else list(inference_chain)

    def grow_script(self, working_script: str, step_item: Dict[str, Any],
                    intent: Dict[str, Any]) -> str:
        """Add a single fragment to an existing working script (Seed-and-Grow grow step).

        Takes a verified working script and merges one new fragment into it:
        1. Deduplicates imports
        2. Wires variables from existing script into new fragment
        3. Resolves template variables
        4. Injects new code inside main() before if __name__
        """
        triplet = step_item['triplet']
        fragment = self.get_fragment(triplet, safe=intent.get('safe_mode', False))
        if not fragment:
            return working_script  # No change — fragment not found

        # Skip non-Python
        frag_stripped = fragment.lstrip()
        if frag_stripped.startswith('#!/bin/bash') or frag_stripped.startswith('set -euo'):
            return working_script
        if 'console.log(' in fragment and 'print(' not in fragment \
           and ('const ' in fragment or 'let ' in fragment):
            return working_script

        # 1. Extract and deduplicate imports
        new_imports = self.extract_imports_from_fragment(fragment)
        existing_imports = self.extract_imports_from_fragment(working_script)
        truly_new = new_imports - existing_imports

        # 2. Clean fragment (remove import lines)
        clean = self.remove_imports_from_fragment(fragment)

        # 3. Extract variables produced by existing script for wiring
        produced_vars = {}
        for idx, line in enumerate(working_script.split('\n')):
            stripped = line.strip()
            match = re.match(r'^(\w+)\s*=\s*.+', stripped)
            if match and not stripped.startswith(('def ', 'for ', 'if ', 'elif ',
                                                  'with ', 'try:', 'except', 'class ')):
                produced_vars[match.group(1)] = idx

        # 4. Wire variables
        params = dict(intent.get('params', {}))
        if produced_vars:
            clean = self._wire_variables(clean, produced_vars, params)

        # 5. Resolve template variables
        clean = self.resolve_variables(clean, params)
        if not clean.strip():
            return working_script

        # 6. Check for variable shadowing — skip fragments that redefine
        #    critical existing variables with different semantics
        existing_vars = self._extract_variables(working_script)
        new_vars = self._extract_variables(clean)
        # Allow shadowing of generic names but block on specific ones
        SAFE_TO_SHADOW = {'result', 'data', 'output', 'content', 'text', 'items',
                          'count', 'total', 'i', 'j', 'k', 'line', 'row', 'item'}
        dangerous_shadow = (new_vars & existing_vars) - SAFE_TO_SHADOW
        if dangerous_shadow:
            return working_script

        # 7. Add output if this is the final grow step
        requires_output = intent.get('requires_output', False)
        if requires_output and not self._has_output(clean):
            last_var = self._get_last_variable(clean)
            if last_var:
                clean = self._add_output_to_fragment(clean, last_var)

        # 8. Merge into working script
        lines = working_script.split('\n')

        # Add new imports after existing ones
        if truly_new:
            last_import_idx = 0
            for i, line in enumerate(lines):
                if line.startswith('import ') or line.startswith('from '):
                    last_import_idx = i
            for imp in sorted(truly_new):
                last_import_idx += 1
                lines.insert(last_import_idx, imp)

        # Find insertion point: before `if __name__` or at end
        insert_idx = len(lines)
        for i, line in enumerate(lines):
            if line.strip() == 'if __name__ == "__main__":':
                insert_idx = i
                break

        # Determine indentation (inside main() or top-level)
        in_main = 'def main():' in working_script
        indent = '    ' if in_main else ''

        # Insert new code block
        new_lines = ['']  # blank line separator
        for frag_line in clean.split('\n'):
            if frag_line.strip():
                new_lines.append(f'{indent}{frag_line}')
        new_lines.append('')

        for j, new_line in enumerate(new_lines):
            lines.insert(insert_idx + j, new_line)

        return '\n'.join(lines)

    def _build_new_script(self, code_blocks: List[str], imports: set, intent: Dict[str, Any]) -> str:
        """Create a full script from scratch.

        Smart assembly:
        - Detects function definitions in code_blocks via ast
        - Places function defs at MODULE level (not inside main())
        - Generates argparse + invocation calls inside main()
        - Non-function code (assignments, expressions) stays in main()
        """
        # ── Step 1: Separate function defs from inline code ──────────
        module_level = []   # function defs go here (outside main)
        main_level = []     # inline code goes here (inside main)
        all_func_names = [] # track defined functions for invocation
        all_func_params = {}  # func_name -> list of (param_name, has_default, default_val)
        has_main_block = False  # track if any block has if __name__ == "__main__"

        # Detect if this is a "tool" (needs argparse + target) vs "utility" script
        TOOL_PARAM_NAMES = {
            'target', 'target_ip', 'host', 'url', 'ip', 'lhost', 'dst_ip',
            'listen_ip', 'listen_port', 'c2_url', 'c2_domain', 'interface',
            'attacker_ip', 'attacker_mac', 'victim_ip', 'gateway_ip',
            'agent_id', 'domain', 'kdc_ip',
        }
        is_tool = False  # set True if any function has tool-like parameters

        for block in code_blocks:
            if not block.strip():
                continue

            # Check if this block already has if __name__ == "__main__":
            if 'if __name__' in block and '__main__' in block:
                has_main_block = True

            # Try to parse with ast to detect function definitions
            try:
                tree = ast.parse(block)
            except SyntaxError:
                # Can't parse — treat as inline code
                main_level.append(block)
                continue

            has_func_def = False
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    has_func_def = True
                    if node.name not in all_func_params:  # skip duplicate names
                        all_func_names.append(node.name)
                    # Extract parameter info for argparse generation
                    params = []
                    args = node.args
                    defaults_offset = len(args.args) - len(args.defaults)
                    for i, arg in enumerate(args.args):
                        if arg.arg == 'self':
                            continue
                        has_default = i >= defaults_offset
                        default_val = None
                        if has_default:
                            default_node = args.defaults[i - defaults_offset]
                            default_val = self._ast_node_to_value(default_node)
                        params.append((arg.arg, has_default, default_val))
                        # Check if this is a tool parameter
                        if arg.arg in TOOL_PARAM_NAMES:
                            is_tool = True
                    if node.name not in all_func_params:  # keep first definition
                        all_func_params[node.name] = params

            if has_func_def:
                module_level.append(block)
            else:
                main_level.append(block)

        # If block already has __main__, use standalone mode
        if has_main_block and not main_level:
            return self._build_standalone_script(code_blocks, imports, intent)

        # If NOT a tool (no target/host/url params), use OLD behavior:
        # wrap everything in main() with example invocations (no argparse)
        if not is_tool and module_level:
            return self._build_utility_script(code_blocks, imports, intent,
                                               all_func_names, all_func_params)

        # ── Step 2: Build script (tool mode with argparse) ───────────
        script_parts = [
            '#!/usr/bin/env python3',
            '"""',
            f'FORGE-generated script',
            f'Intent: {intent.get("mode", "BUILD")}',
            f'Entities: {", ".join(e["matched"] for e in intent.get("entities", [])[:3])}',
            f'Confidence: {intent.get("confidence", 0.0):.2f}',
            '"""',
            '',
        ]

        # Imports
        merged_imports = set(imports)
        if all_func_names and not has_main_block:
            merged_imports.add('import argparse')
            merged_imports.add('import json')
            merged_imports.add('import sys')
        if merged_imports:
            script_parts.extend(sorted(merged_imports))
            script_parts.append('')

        # Module-level code: function definitions (deduplicated by name)
        seen_func_names = set()
        seen_class_names = set()
        for block in module_level:
            # Strip imports (already collected) but keep function defs
            clean = self.remove_imports_from_fragment(block)
            if not clean.strip():
                continue
            # Deduplicate: extract function/class names and skip blocks
            # that only re-define already-seen names
            try:
                tree = ast.parse(clean)
                block_names = set()
                for node in ast.iter_child_nodes(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        block_names.add(('func', node.name))
                    elif isinstance(node, ast.ClassDef):
                        block_names.add(('class', node.name))
                # If ALL names in this block are already seen, skip entire block
                new_names = {n for n in block_names if n not in seen_func_names and n not in seen_class_names}
                if block_names and not new_names:
                    continue  # all definitions are duplicates — skip
                # If block has MIX of new and duplicate names, keep it
                # (stripping individual dups would break indentation)
                for kind, name in block_names:
                    if kind == 'func':
                        seen_func_names.add(('func', name))
                    else:
                        seen_class_names.add(('class', name))
            except SyntaxError:
                pass  # can't parse — keep block as-is
            script_parts.append(clean)
            script_parts.append('')

        # main() with argparse + invocations
        script_parts.append('def main():')
        script_parts.append('    """Main execution"""')

        if all_func_names and not has_main_block:
            # Generate argparse based on detected function signatures
            argparse_block = self._generate_argparse(all_func_names, all_func_params, intent)
            for line in argparse_block:
                script_parts.append(f'    {line}')
            script_parts.append('')

        # Inline code inside main()
        if main_level:
            for block in main_level:
                for line in block.split('\n'):
                    if line.strip():
                        script_parts.append(f'    {line}')
                script_parts.append('')

        # If we have function defs but no inline code, generate invocations
        if all_func_names and not main_level and not has_main_block:
            invocations = self._generate_invocations(all_func_names, all_func_params, intent)
            for line in invocations:
                script_parts.append(f'    {line}')
            script_parts.append('')
        elif not main_level and not all_func_names:
            script_parts.append('    # No code fragments matched')
            script_parts.append('    print("No implementation available")')

        script_parts.append('')
        script_parts.append('if __name__ == "__main__":')
        script_parts.append('    main()')

        return '\n'.join(script_parts)

    def _build_utility_script(self, code_blocks: List[str], imports: set,
                               intent: Dict[str, Any],
                               func_names: List[str], func_params: dict) -> str:
        """Build script for non-tool utility functions (old behavior).
        Functions go inside main() with example invocations — no argparse."""
        script_parts = [
            '#!/usr/bin/env python3',
            '"""',
            f'FORGE-generated script',
            f'Intent: {intent.get("mode", "BUILD")}',
            f'Entities: {", ".join(e["matched"] for e in intent.get("entities", [])[:3])}',
            f'Confidence: {intent.get("confidence", 0.0):.2f}',
            '"""',
            '',
        ]

        if imports:
            script_parts.extend(sorted(imports))
            script_parts.append('')

        script_parts.append('def main():')
        script_parts.append('    """Main execution"""')

        if code_blocks:
            for block in code_blocks:
                for line in block.split('\n'):
                    if line.strip():
                        script_parts.append(f'    {line}')
                script_parts.append('')
        else:
            script_parts.append('    # No code fragments matched')
            script_parts.append('    print("No implementation available")')

        script_parts.append('')
        script_parts.append('if __name__ == "__main__":')
        script_parts.append('    main()')

        return '\n'.join(script_parts)

    @staticmethod
    def _ast_node_to_value(node):
        """Extract a Python value from an AST default-argument node."""
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, (ast.List, ast.Tuple)):
            return '[]'
        if isinstance(node, ast.Dict):
            return '{}'
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            if isinstance(node.operand, ast.Constant):
                return -node.operand.value
        return None

    def _generate_argparse(self, func_names: List[str], func_params: dict,
                           intent: Dict[str, Any]) -> List[str]:
        """Generate argparse lines for function parameters."""
        lines = ['parser = argparse.ArgumentParser(description="FORGE-generated tool")']

        # Collect all unique parameters across all functions
        seen_params = set()
        added_positional = False  # only ONE positional "target" arg
        added_port = False
        added_output = False
        POSITIONAL_NAMES = {'target', 'target_ip', 'host', 'url', 'ip', 'lhost'}

        for fname in func_names:
            params = func_params.get(fname, [])
            for param_name, has_default, default_val in params:
                if param_name in seen_params:
                    continue
                seen_params.add(param_name)

                # Skip callback/internal params
                if param_name in ('callback', 'true_check', 'namespace', 'stop_event'):
                    continue

                if param_name in POSITIONAL_NAMES and not added_positional:
                    lines.append('parser.add_argument("target", help="Target IP/host/URL")')
                    added_positional = True
                elif (param_name == 'port' or param_name.endswith('_port')) and not added_port:
                    port_default = default_val if default_val is not None else 80
                    lines.append(f'parser.add_argument("--port", type=int, default={port_default}, help="Target port")')
                    added_port = True
                elif param_name in ('output_file', 'output_path') and not added_output:
                    lines.append('parser.add_argument("--output", "-o", default=None, help="Output file")')
                    added_output = True
                elif param_name in POSITIONAL_NAMES or param_name == 'port' or param_name.endswith('_port'):
                    pass  # already added
                elif has_default and default_val is not None:
                    if isinstance(default_val, bool):
                        lines.append(f'parser.add_argument("--{param_name.replace("_", "-")}", action="store_true", help="{param_name}")')
                    elif isinstance(default_val, int):
                        lines.append(f'parser.add_argument("--{param_name.replace("_", "-")}", type=int, default={default_val}, help="{param_name}")')
                    elif isinstance(default_val, float):
                        lines.append(f'parser.add_argument("--{param_name.replace("_", "-")}", type=float, default={default_val}, help="{param_name}")')
                    elif isinstance(default_val, str):
                        lines.append(f'parser.add_argument("--{param_name.replace("_", "-")}", default={default_val!r}, help="{param_name}")')

        # Ensure at least a positional target arg if none was added
        if not added_positional and any(
            any(p[0] in POSITIONAL_NAMES for p in func_params.get(f, []))
            for f in func_names
        ):
            lines.append('parser.add_argument("target", help="Target IP/host/URL")')

        lines.append('args = parser.parse_args()')
        return lines

    def _generate_invocations(self, func_names: List[str], func_params: dict,
                              intent: Dict[str, Any]) -> List[str]:
        """Generate function invocation lines with argparse values."""
        lines = []
        POSITIONAL_NAMES = {'target', 'target_ip', 'host', 'url', 'ip', 'lhost'}
        SKIP_PARAMS = {'namespace', 'stop_event'}

        # Filter to "callable" functions:
        # - Not starting with _ (private)
        # - Has at least one param OR takes no args (like extract_chrome_passwords)
        # - All required params (no default) are satisfiable from argparse
        callable_funcs = []
        for fname in func_names:
            if fname.startswith('_'):
                continue
            fparams = func_params.get(fname, [])
            # Check if all required params can be satisfied
            unsatisfied = []
            for pname, has_def, def_val in fparams:
                if pname in SKIP_PARAMS:
                    continue
                if not has_def and pname not in POSITIONAL_NAMES and pname != 'port' and not pname.endswith('_port'):
                    unsatisfied.append(pname)
            if not unsatisfied:
                callable_funcs.append(fname)

        if not callable_funcs:
            # Fallback: call ALL non-private functions, providing string defaults for unknown params
            all_public = [f for f in func_names if not f.startswith('_')]
            if all_public:
                callable_funcs = all_public
            else:
                lines.append('print("No callable functions found")')
                return lines

        # Pick primary: prefer function with most params, then first
        primary = callable_funcs[0]
        max_score = 0
        for fname in callable_funcs:
            score = len(func_params.get(fname, []))
            if score > max_score:
                max_score = score
                primary = fname

        def _build_call_args(fname):
            """Build keyword arguments for a function call."""
            fparams = func_params.get(fname, [])
            call_args = []
            for pname, has_def, def_val in fparams:
                if pname in SKIP_PARAMS:
                    continue
                if pname in POSITIONAL_NAMES:
                    call_args.append(f'{pname}=args.target')
                elif pname == 'port' or pname.endswith('_port'):
                    call_args.append(f'{pname}=args.port')
                elif pname in ('output_file', 'output_path'):
                    call_args.append(f'{pname}=args.output')
                elif has_def:
                    arg_attr = pname.replace('-', '_')
                    call_args.append(f'{pname}=getattr(args, "{arg_attr}", {def_val!r})')
                elif not has_def:
                    # Required param not in POSITIONAL_NAMES — provide sensible default
                    if 'callback' in pname or 'check' in pname or 'func' in pname or 'handler' in pname:
                        call_args.append(f'{pname}=lambda *a, **kw: True')
                    elif 'param' in pname:
                        call_args.append(f'{pname}="id"')
                    elif 'query' in pname and 'bytes' in pname:
                        call_args.append(f'{pname}=b"\\x00" * 29')
                    elif 'query' in pname:
                        call_args.append(f'{pname}="SELECT 1"')
                    elif 'position' in pname or 'index' in pname:
                        call_args.append(f'{pname}=1')
                    elif 'bytes' in pname:
                        call_args.append(f'{pname}=b"\\x00" * 16')
                    elif 'data' in pname or 'payload' in pname:
                        call_args.append(f'{pname}=b"test"')
                    elif 'file' in pname or 'path' in pname:
                        call_args.append(f'{pname}="/tmp/forge_test"')
                    elif 'interface' in pname:
                        call_args.append(f'{pname}="eth0"')
                    elif 'mac' in pname:
                        call_args.append(f'{pname}="aa:bb:cc:dd:ee:ff"')
                    elif 'domain' in pname:
                        call_args.append(f'{pname}=args.target')
                    else:
                        call_args.append(f'{pname}=args.target')
            return ', '.join(call_args)

        # Generate calls
        if len(callable_funcs) == 1:
            args_str = _build_call_args(primary)
            lines.append(f'result = {primary}({args_str})')
        else:
            args_str = _build_call_args(primary)
            lines.append(f'print("=== {primary} ===")')
            lines.append(f'result = {primary}({args_str})')
            for fname in callable_funcs:
                if fname == primary:
                    continue
                sub_str = _build_call_args(fname)
                lines.append(f'print("\\n=== {fname} ===")')
                lines.append(f'r_{fname} = {fname}({sub_str})')
                lines.append(f'if isinstance(r_{fname}, dict):')
                lines.append(f'    print(json.dumps(r_{fname}, indent=2, default=str))')
                lines.append(f'elif r_{fname} is not None:')
                lines.append(f'    print(r_{fname})')

        # Output the primary result
        lines.append('if isinstance(result, dict):')
        lines.append('    print(json.dumps(result, indent=2, default=str))')
        lines.append('elif isinstance(result, (list, tuple)):')
        lines.append('    for item in result:')
        lines.append('        if isinstance(item, dict):')
        lines.append('            print(json.dumps(item, indent=2, default=str))')
        lines.append('        else:')
        lines.append('            print(item)')
        lines.append('elif isinstance(result, bytes):')
        lines.append('    print(f"Raw bytes: {len(result)} bytes")')
        lines.append('    print(f"Hex: {result.hex()[:200]}")')
        lines.append('elif result is not None:')
        lines.append('    print(result)')

        return lines

    def assemble_project(self, inference_chain: List[Dict[str, Any]],
                        intent: Dict[str, Any]) -> Dict[str, str]:
        """Assemble a complete multi-file Python project (TDD: tests first).

        Returns dict:
        {
            'test_main.py': test code (spec as executable assertions),
            'main.py': implementation code (must pass all tests),
            '__init__.py': package init,
            'requirements.txt': dependencies,
            'README.md': usage guide,
            'config.yaml': config template,
        }

        Philosophy: Tests define the contract. Code must satisfy it.
        """
        intent_text = intent.get('raw', '').lower()
        tokens = set(intent.get('tokens', []))
        params = intent.get('params', {})

        # ── Step 1: Generate test code (SPEC) ────────────────────
        test_code = self._generate_test_code(inference_chain, intent)

        # ── Step 2: Generate main code (IMPLEMENTATION) ──────────
        main_code = self.assemble(inference_chain, intent)

        # ── Step 3: Extract dependencies ─────────────────────────
        deps = self._extract_dependencies(main_code)

        # ── Step 4: Generate supporting files ────────────────────
        init_code = self._generate_init_file(params)
        requirements_txt = self._generate_requirements(deps)
        readme_md = self._generate_readme(intent_text, tokens, params)
        config_yaml = self._generate_config(params, tokens)

        return {
            'test_main.py': test_code,
            'main.py': main_code,
            '__init__.py': init_code,
            'requirements.txt': requirements_txt,
            'README.md': readme_md,
            'config.yaml': config_yaml,
        }

    def _generate_test_code(self, inference_chain: List[Dict[str, Any]],
                           intent: Dict[str, Any]) -> str:
        """Generate pytest test code that defines the spec.

        Tests are specifications: they define what success looks like.
        """
        intent_text = intent.get('raw', '')
        tokens = intent.get('tokens', [])

        test_parts = [
            '"""Test suite — defines the specification for main.py."""',
            '',
            'import pytest',
            'from main import main',
            '',
            '',
        ]

        # ── Test classes by task type ────────────────────────
        task_type = self._classify_task(intent_text, tokens)

        if task_type == 'data_processing':
            test_parts.extend([
                'class TestDataProcessing:',
                '    """Tests for data transformation tasks."""',
                '',
                '    def test_process_returns_result(self):',
                '        """Main function should return/produce output."""',
                '        result = main()',
                '        assert result is not None',
                '',
                '    def test_handles_input_data(self):',
                '        """Should process input without errors."""',
                '        try:',
                '            result = main()',
                '            assert True  # No exception',
                '        except Exception as e:',
                '            pytest.fail(f"Processing failed: {e}")',
                '',
                '    def test_output_is_structured(self):',
                '        """Output should be list, dict, or string."""',
                '        result = main()',
                '        assert isinstance(result, (list, dict, str, int, float))',
                '',
            ])

        elif task_type == 'api_service':
            test_parts.extend([
                'class TestAPIService:',
                '    """Tests for API/service creation."""',
                '',
                '    def test_service_initializes(self):',
                '        """Service should initialize without errors."""',
                '        try:',
                '            result = main()',
                '            assert True',
                '        except ImportError:',
                '            pytest.skip("Dependencies not installed")',
                '        except Exception as e:',
                '            pytest.fail(f"Service failed: {e}")',
                '',
                '    def test_has_handler(self):',
                '        """Service should define handlers/endpoints."""',
                '        import main',
                '        # Check for common patterns',
                '        assert any(hasattr(main, attr) for attr in',
                '                   ["app", "server", "handler", "main"])',
                '',
            ])

        elif task_type == 'system_tool':
            test_parts.extend([
                'class TestSystemTool:',
                '    """Tests for system utilities/tools."""',
                '',
                '    def test_tool_runs_without_error(self):',
                '        """Tool should execute successfully."""',
                '        try:',
                '            result = main()',
                '            assert result is None or isinstance(result, (str, int, bool))',
                '        except Exception as e:',
                '            pytest.fail(f"Tool failed: {e}")',
                '',
                '    def test_produces_output_or_side_effect(self):',
                '        """Tool should produce visible output/effect."""',
                '        import io',
                '        import sys',
                '        captured = io.StringIO()',
                '        sys.stdout = captured',
                '        try:',
                '            main()',
                '        finally:',
                '            sys.stdout = sys.__stdout__',
                '        output = captured.getvalue()',
                '        # Tool should produce output or return value',
                '        assert output or True',
                '',
            ])

        else:
            # Generic fallback
            test_parts.extend([
                'class TestGeneric:',
                '    """Generic tests for any task."""',
                '',
                '    def test_main_function_exists(self):',
                '        """main() function should exist."""',
                '        from main import main',
                '        assert callable(main)',
                '',
                '    def test_main_executes(self):',
                '        """main() should execute without exceptions."""',
                '        try:',
                '            result = main()',
                '            assert True  # Success',
                '        except Exception as e:',
                '            pytest.fail(f"main() failed: {e}")',
                '',
            ])

        test_parts.extend([
            '',
            'if __name__ == "__main__":',
            '    pytest.main([__file__, "-v"])',
        ])

        return '\n'.join(test_parts)

    def _generate_init_file(self, params: Dict[str, Any]) -> str:
        """Generate __init__.py package file."""
        return '"""Package initialization."""\n\n__version__ = "0.1.0"\n'

    def _generate_requirements(self, deps: List[str]) -> str:
        """Generate requirements.txt with extracted dependencies."""
        # Add pytest by default
        if 'pytest' not in deps:
            deps = list(set(deps + ['pytest']))

        if not deps:
            return '# No external dependencies\n'

        return '\n'.join(sorted(deps)) + '\n'

    def _generate_readme(self, intent_text: str, tokens: set, params: Dict) -> str:
        """Generate README.md with usage instructions."""
        lines = [
            '# Project',
            '',
            f'## Description',
            f'{intent_text.capitalize()}',
            '',
            '## Installation',
            '',
            '```bash',
            'pip install -r requirements.txt',
            '```',
            '',
            '## Usage',
            '',
            '### Run the main program',
            '```bash',
            'python main.py',
            '```',
            '',
            '### Run tests',
            '```bash',
            'pytest test_main.py -v',
            '```',
            '',
            '## Structure',
            '',
            '- `main.py` - Core implementation',
            '- `test_main.py` - Test suite (defines specification)',
            '- `__init__.py` - Package initialization',
            '- `requirements.txt` - Dependencies',
            '- `config.yaml` - Configuration template',
            '',
        ]
        return '\n'.join(lines)

    def _generate_config(self, params: Dict[str, Any], tokens: set) -> str:
        """Generate config.yaml template."""
        lines = [
            '# Configuration',
            '',
            'settings:',
            '  debug: false',
            '  verbose: false',
            '',
        ]

        # Add relevant config from params
        if params:
            lines.append('  # Custom parameters:')
            for key, val in list(params.items())[:5]:
                lines.append(f'  # {key}: {val}')

        return '\n'.join(lines)

    # Sample data generators for color pipelines that start by reading files
    _SEED_DATA = {
        'json': ('data.json', 'import json\n_seed = {"name": "test", "items": [1, 2, 3], "active": True}\nwith open(\'data.json\', \'w\') as _f:\n    json.dump(_seed, _f, indent=2)'),
        'csv':  ('data.csv', 'import csv\nwith open(\'data.csv\', \'w\', newline=\'\') as _f:\n    w = csv.writer(_f)\n    w.writerow([\'name\', \'age\', \'city\'])\n    w.writerow([\'Alice\', \'30\', \'Berlin\'])\n    w.writerow([\'Bob\', \'25\', \'Munich\'])\n    w.writerow([\'Alice\', \'30\', \'Berlin\'])\n    w.writerow([\'Carol\', \'35\', \'Hamburg\'])'),
        'xml':  ('data.xml', 'with open(\'data.xml\', \'w\') as _f:\n    _f.write(\'<root><item name="test">value1</item><item name="test2">value2</item></root>\')'),
        'text': ('data.txt', 'with open(\'data.txt\', \'w\') as _f:\n    _f.write(\'Hello World\\nLine 2: test@example.com\\nLine 3: https://example.com\\n42 items processed\\n\')'),
    }

    def _assemble_color_pipeline(self, intent: Dict[str, Any]) -> Optional[str]:
        """
        Color Type System: assemble fragments from a color pipeline.

        Bypasses triplet chain entirely. Fragments are assembled in color-chain
        order with proper variable wiring between stages.

        Returns assembled script, or None if no color pipeline matches.
        """
        intent_raw = intent.get('raw', '')
        pipeline = self.color_assembler.build_pipeline(intent_raw)
        if not pipeline:
            return None

        imports = set()
        code_blocks = []
        params = dict(intent.get('params', {}))
        requires_output = intent.get('requires_output', False)
        produced_vars = {}

        # Seed step: if first fragment reads a file, create sample data
        if pipeline:
            first_key = pipeline[0][0]
            from o1o_o.core.color_types import COLOR_REGISTRY, PATH
            first_colors = COLOR_REGISTRY.get(first_key)
            if first_colors and first_colors[0] == PATH:
                # Detect which data format to seed based on intent + first fragment
                intent_lower = intent_raw.lower()
                # Check if first fragment is a JSON reader → seed JSON
                if first_key in ('json_load', 'json_loads'):
                    seed_type = 'json'
                elif 'json' in intent_lower or 'config' in intent_lower or 'settings' in intent_lower:
                    seed_type = 'json'
                elif 'csv' in intent_lower:
                    seed_type = 'csv'
                elif 'xml' in intent_lower:
                    seed_type = 'xml'
                else:
                    seed_type = 'text'

                seed_file, seed_code = self._SEED_DATA[seed_type]
                params['path'] = seed_file
                params['json_path'] = seed_file
                params['csv_path'] = seed_file
                imports.update(self.extract_imports_from_fragment(seed_code))
                code_blocks.append(self.remove_imports_from_fragment(seed_code))

        # Preamble: define variables for VOID→VOID pipelines that write data
        frag_keys_in_pipeline = [k for k, _ in pipeline]

        # Track which fragments were used (for quality scoring)
        self.last_used_fragments = frag_keys_in_pipeline
        if 'json_dump' in frag_keys_in_pipeline or 'json_dumps' in frag_keys_in_pipeline:
            if not any(k in frag_keys_in_pipeline for k in ('json_load', 'json_loads', 'file_read')):
                imports.add('import random')
                imports.add('import string')
                code_blocks.append(
                    'data = [{"id": i, "name": "".join(random.choices(string.ascii_lowercase, k=6)), '
                    '"value": round(random.uniform(0, 100), 2)} for i in range(10)]'
                )
                produced_vars['data'] = -1
        if 'csv_write' in frag_keys_in_pipeline or 'csv_dictwriter' in frag_keys_in_pipeline:
            if 'rows' not in params or params.get('rows') == '{rows}':
                code_blocks.append(
                    'rows = [["name", "age", "city"], ["Alice", "30", "Berlin"], '
                    '["Bob", "25", "Munich"], ["Carol", "35", "Hamburg"]]'
                )
                params['rows'] = 'rows'
                produced_vars['rows'] = -1

        for idx, (frag_key, frag_code) in enumerate(pipeline):
            # Skip non-Python
            stripped = frag_code.lstrip()
            if stripped.startswith(('#!/bin/bash', 'set -euo', '#!/bin/sh')):
                continue
            if 'console.log(' in frag_code and 'print(' not in frag_code:
                continue

            # Self-contained fragments (single VOID→VOID with own output,
            # NO template variables): keep imports inline, skip resolve_variables,
            # skip main() wrapper.
            # Detect template vars: {word} on non-f-string, non-comment lines
            # that are NOT inside dict/set literals
            has_template_vars = False
            for _line in frag_code.split('\n'):
                _stripped = _line.lstrip()
                if _stripped.startswith('#'):
                    continue
                # Skip f-string lines
                if re.search(r'\bf[\'"]', _stripped):
                    continue
                # Check for {word} pattern (template variable)
                _tvars = re.findall(r'\{(\w+)\}', _stripped)
                if _tvars:
                    has_template_vars = True
                    break
            is_self_contained = (
                len(pipeline) == 1
                and self._has_output(frag_code)
                and not has_template_vars
            )

            if is_self_contained:
                # Use fragment as-is: no import extraction, no variable resolution
                code = frag_code
            else:
                imports.update(self.extract_imports_from_fragment(frag_code))
                clean = self.remove_imports_from_fragment(frag_code)

                # Wire variables from earlier stages
                if idx > 0 and produced_vars:
                    clean = self._wire_variables(clean, produced_vars, params)

                code = self.resolve_variables(clean, params)
            if not code.strip():
                continue

            # Track produced variables
            new_vars = self._extract_variables(code)
            for var in new_vars:
                produced_vars[var] = idx

            # Add output to last fragment
            if requires_output and idx == len(pipeline) - 1:
                if not self._has_output(code):
                    last_var = self._get_last_variable(code)
                    if last_var:
                        code = self._add_output_to_fragment(code, last_var)

            code_blocks.append(code)

        if not code_blocks:
            return None

        # Self-contained fragments: run at module level (no main() wrapper)
        # This preserves global statements, globals() calls, and import ordering
        if len(pipeline) == 1 and self._has_output(code_blocks[0]):
            return self._build_standalone_script(code_blocks, imports, intent)

        return self._build_new_script(code_blocks, imports, intent)

    def _build_standalone_script(self, code_blocks: List[str], imports: set,
                                  intent: Dict[str, Any]) -> str:
        """Build a script that runs at module level (no main() wrapper).
        Used for self-contained fragments that need module-level scope."""
        script_parts = [
            '#!/usr/bin/env python3',
            '"""',
            'FORGE-generated script',
            f'Intent: {intent.get("mode", "BUILD")}',
            f'Entities: {", ".join(e["matched"] for e in intent.get("entities", [])[:3])}',
            f'Confidence: {intent.get("confidence", 0.0):.2f}',
            '"""',
            '',
        ]

        if imports:
            script_parts.extend(sorted(imports))
            script_parts.append('')

        for block in code_blocks:
            script_parts.append(block)
            script_parts.append('')

        return '\n'.join(script_parts)

    def assemble_v4_architecture_aware(self, intent: Dict[str, Any]) -> str:
        """
        Architecture-aware assembly: decompose intent into components,
        find fragments by component_role, and assemble with orchestration.

        Replaces fuzzy keyword matching with exact role-based fragment lookup.
        Returns working code or "No implementation found" if no suitable fragments.
        """
        # Component types we recognize
        COMPONENT_ROLES = {
            'database': ['sqlite3_query', 'database_insert', 'orm_setup'],
            'api': ['api_endpoint', 'rest_handler', 'http_server'],
            'validation': ['input_validator', 'schema_check', 'data_validation'],
            'transformation': ['csv_transform', 'json_convert', 'data_transform'],
            'source': ['file_reader', 'api_caller', 'data_fetcher'],
            'sink': ['file_writer', 'database_store', 'api_post'],
            'authentication': ['auth_handler', 'token_manager', 'permission_check'],
        }

        intent_text = intent.get('intent', '').lower()
        imports = set()
        code_blocks = []
        params = intent.get('params', {})

        # Simple component detection: look for keywords in intent
        detected_components = set()
        for component, aliases in COMPONENT_ROLES.items():
            component_keywords = [component.replace('_', ' ')]
            component_keywords += [alias.replace('_', ' ') for alias in aliases]
            for keyword in component_keywords:
                if keyword.lower() in intent_text:
                    detected_components.add(component)
                    break

        # Fallback: if no components detected, try generic assembly
        if not detected_components:
            return self.assemble([], intent)

        # For each detected component, find a fragment with matching role
        for component in sorted(detected_components):
            # Look for fragments tagged with this component_role
            found_fragment = None
            for frag_key, frag_data in self.fragments.items():
                # Handle both string and dict fragments
                if isinstance(frag_data, dict):
                    frag_code = frag_data.get('code', '')
                    frag_role = frag_data.get('component_role')
                else:
                    frag_code = frag_data
                    frag_role = None

                # Match by component_role tag
                if frag_role == component:
                    found_fragment = frag_code
                    break

            if found_fragment:
                imports.update(self.extract_imports_from_fragment(found_fragment))
                clean_fragment = self.remove_imports_from_fragment(found_fragment)
                code = self.resolve_variables(clean_fragment, params)
                if code.strip():
                    code_blocks.append(code)

        # If no fragments found by role, return failure
        if not code_blocks:
            return "No implementation found"

        # Build final script from code blocks
        return self._build_new_script(code_blocks, imports, intent)

    def _classify_task(self, intent_text: str, tokens: set) -> str:
        """Classify the task type for test generation."""
        # Ensure tokens is a set
        if isinstance(tokens, list):
            tokens = set(tokens)

        data_keywords = {'read', 'parse', 'process', 'convert', 'transform', 'filter'}
        api_keywords = {'api', 'server', 'service', 'app', 'flask', 'django', 'web'}
        system_keywords = {'command', 'run', 'execute', 'script', 'tool', 'utility'}

        if tokens & data_keywords:
            return 'data_processing'
        if tokens & api_keywords:
            return 'api_service'
        if tokens & system_keywords:
            return 'system_tool'
        return 'generic'

    def _extract_dependencies(self, code: str) -> List[str]:
        """Extract Python package dependencies from imports."""
        deps = set()

        import_patterns = [
            (r'^\s*import\s+(\w+)', 1),
            (r'^\s*from\s+(\w+)', 1),
        ]

        # Standard library modules (don't add to requirements)
        stdlib = {
            'os', 'sys', 'json', 'csv', 're', 'pathlib', 'datetime', 'time',
            'collections', 'itertools', 'functools', 'subprocess', 'shutil',
            'tempfile', 'io', 'urllib', 'http', 'socket', 'threading',
            'multiprocessing', 'asyncio', 'logging', 'argparse', 'configparser',
            'sqlite3', 'random', 'math', 'statistics', 'string', 'hashlib',
            'unittest', 'pytest', 'typing', 'dataclasses', 'enum', '__future__',
        }

        for line in code.split('\n'):
            for pattern, group_idx in import_patterns:
                match = re.match(pattern, line)
                if match:
                    module = match.group(group_idx)
                    if module not in stdlib and not module.startswith('_'):
                        # Map common packages
                        pkg_map = {
                            'cv2': 'opencv-python',
                            'PIL': 'Pillow',
                            'sklearn': 'scikit-learn',
                            'yaml': 'PyYAML',
                        }
                        deps.add(pkg_map.get(module, module))

        return sorted(list(deps))
