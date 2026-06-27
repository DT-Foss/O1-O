"""Auto Fragment Generator: Deterministic synthesis from triplet knowledge.

When no existing fragment solves a task and no fix works, FORGE generates a
NEW fragment from its knowledge graph. Uses triplet patterns to assemble
code templates, validates in sandbox before storage.

GUARDRAIL: Every auto-fragment must pass 3x sandbox validation.

Part of FORGE Phase 6: Self-Optimization.
"""
# Dependencies: execution_simulator
# Depended by: autonomous_loop

import json
import os
import re
import textwrap
from typing import Dict, List, Optional, Set, Tuple

from o1o_o.core.execution_simulator import ExecutionSimulator


# ─── Code Templates ────────────────────────────────────────────────────

# Minimal code templates for common patterns that can be composed
CODE_TEMPLATES = {
    'file_reader': textwrap.dedent('''
        def read_file(path):
            """Read and return file contents."""
            with open(path) as f:
                return f.read()
    ''').strip(),

    'csv_reader': textwrap.dedent('''
        import csv
        def read_csv(path):
            """Read CSV file and return list of dicts."""
            with open(path) as f:
                return list(csv.DictReader(f))
    ''').strip(),

    'json_reader': textwrap.dedent('''
        import json
        def read_json(path):
            """Read JSON file and return parsed data."""
            with open(path) as f:
                return json.load(f)
    ''').strip(),

    'json_writer': textwrap.dedent('''
        import json
        def write_json(data, path):
            """Write data to JSON file."""
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
    ''').strip(),

    'csv_writer': textwrap.dedent('''
        import csv
        def write_csv(data, path, fieldnames=None):
            """Write list of dicts to CSV file."""
            if not data:
                return
            if fieldnames is None:
                fieldnames = list(data[0].keys())
            with open(path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
    ''').strip(),

    'sqlite_ops': textwrap.dedent('''
        import sqlite3
        def db_operation(db_path, query, params=None):
            """Execute a database query and return results."""
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(query, params or ())
            if query.strip().upper().startswith('SELECT'):
                results = cursor.fetchall()
            else:
                conn.commit()
                results = cursor.rowcount
            conn.close()
            return results
    ''').strip(),

    'hash_compute': textwrap.dedent('''
        import hashlib
        def compute_hash(data, algorithm='sha256'):
            """Compute hash of string data."""
            h = hashlib.new(algorithm)
            h.update(data.encode() if isinstance(data, str) else data)
            return h.hexdigest()
    ''').strip(),

    'list_transform': textwrap.dedent('''
        def transform_list(items, operation='sort'):
            """Transform a list using the specified operation."""
            if operation == 'sort':
                return sorted(items)
            elif operation == 'reverse':
                return list(reversed(items))
            elif operation == 'unique':
                return list(dict.fromkeys(items))
            elif operation == 'flatten':
                flat = []
                for item in items:
                    if isinstance(item, list):
                        flat.extend(item)
                    else:
                        flat.append(item)
                return flat
            return items
    ''').strip(),

    'string_processor': textwrap.dedent('''
        import re
        def process_string(text, operation='clean'):
            """Process string with common operations."""
            if operation == 'clean':
                return ' '.join(text.split())
            elif operation == 'words':
                return text.split()
            elif operation == 'sentences':
                return re.split(r'[.!?]+', text)
            elif operation == 'lines':
                return text.splitlines()
            return text
    ''').strip(),

    'datetime_ops': textwrap.dedent('''
        from datetime import datetime, timedelta
        def datetime_operation(operation='now', **kwargs):
            """Common datetime operations."""
            now = datetime.now()
            if operation == 'now':
                return now.strftime('%Y-%m-%d %H:%M:%S')
            elif operation == 'format':
                fmt = kwargs.get('format', '%Y-%m-%d')
                return now.strftime(fmt)
            elif operation == 'delta':
                days = kwargs.get('days', 0)
                return (now + timedelta(days=days)).strftime('%Y-%m-%d')
            return str(now)
    ''').strip(),

    'main_scaffold': textwrap.dedent('''
        def main():
            """Main entry point."""
            {body}
            print("Done.")

        if __name__ == '__main__':
            main()
    ''').strip(),
}

# ─── Triplet → Template mapping ────────────────────────────────────────

TRIPLET_TEMPLATE_MAP = {
    # (trigger_keyword, mechanism) → template_name
    ('file', 'read'): 'file_reader',
    ('csv', 'read'): 'csv_reader',
    ('csv', 'parse'): 'csv_reader',
    ('json', 'read'): 'json_reader',
    ('json', 'parse'): 'json_reader',
    ('json', 'write'): 'json_writer',
    ('json', 'dump'): 'json_writer',
    ('csv', 'write'): 'csv_writer',
    ('csv', 'export'): 'csv_writer',
    ('sqlite', 'query'): 'sqlite_ops',
    ('database', 'query'): 'sqlite_ops',
    ('hash', 'compute'): 'hash_compute',
    ('list', 'transform'): 'list_transform',
    ('list', 'sort'): 'list_transform',
    ('string', 'process'): 'string_processor',
    ('text', 'process'): 'string_processor',
    ('datetime', 'format'): 'datetime_ops',
    ('time', 'format'): 'datetime_ops',
}


class FragmentGenerator:
    """Generates new code fragments from triplet knowledge."""

    def __init__(self, fragments_dir: str = 'fragments'):
        self.fragments_dir = fragments_dir
        self.simulator = ExecutionSimulator()
        self.generated_count = 0

    def generate_from_intent(self, intent: str) -> Optional[str]:
        """Generate a code fragment from an intent string.

        Returns generated code if valid, None otherwise.
        """
        # Extract keywords from intent
        keywords = set(re.findall(r'\b\w+\b', intent.lower()))

        # Find matching templates
        templates = self._match_templates(keywords)
        if not templates:
            return None

        # Compose templates into a single script
        code = self._compose_templates(templates, intent)
        if not code:
            return None

        # Validate: must pass simulation
        sim = self.simulator.simulate(code)
        if sim.will_fail and sim.is_certain:
            return None

        return code

    def generate_and_validate(self, intent: str,
                               validation_rounds: int = 3) -> Optional[str]:
        """Generate a fragment and validate it N times in sandbox.

        GUARDRAIL: Must pass all validation rounds.
        """
        code = self.generate_from_intent(intent)
        if code is None:
            return None

        # Triple validation
        from tests.forge_validator import ForgeValidator
        validator = ForgeValidator()

        for round_num in range(validation_rounds):
            task = {'intent': intent, 'id': 0}
            result = validator.validate(code, task, timeout=10)
            if not result.get('success'):
                return None  # failed validation — reject

        self.generated_count += 1
        return code

    def store_fragment(self, key: str, code: str,
                       target_file: str = 'auto_generated_fragments.json') -> bool:
        """Store a validated fragment in the fragments directory.

        Only stores if it doesn't already exist and passes validation.
        """
        filepath = os.path.join(self.fragments_dir, target_file)

        # Load existing
        if os.path.exists(filepath):
            with open(filepath) as f:
                fragments = json.load(f)
        else:
            fragments = {}

        # Don't overwrite
        if key in fragments:
            return False

        # Store
        fragments[key] = code
        with open(filepath, 'w') as f:
            json.dump(fragments, f, indent=2)

        return True

    def _match_templates(self, keywords: Set[str]) -> List[str]:
        """Find code templates matching intent keywords."""
        matched = []

        for (trigger, mechanism), template_name in TRIPLET_TEMPLATE_MAP.items():
            if trigger in keywords or mechanism in keywords:
                if template_name not in matched:
                    matched.append(template_name)

        return matched

    def _compose_templates(self, templates: List[str],
                            intent: str) -> Optional[str]:
        """Compose multiple templates into a single script."""
        parts = []
        imports_seen = set()

        for template_name in templates:
            template = CODE_TEMPLATES.get(template_name)
            if template is None:
                continue

            # Extract imports
            for line in template.split('\n'):
                if line.startswith('import ') or line.startswith('from '):
                    if line not in imports_seen:
                        imports_seen.add(line)

            parts.append(template)

        if not parts:
            return None

        # Build final script
        lines = [f'"""Auto-generated: {intent[:80]}"""', '']

        # Imports first
        for imp in sorted(imports_seen):
            lines.append(imp)
        if imports_seen:
            lines.append('')

        # Template functions
        for part in parts:
            # Skip import lines (already added above)
            func_lines = [l for l in part.split('\n')
                          if not l.startswith('import ') and not l.startswith('from ')]
            lines.extend(func_lines)
            lines.append('')

        # Add demo/test section
        lines.append('')
        lines.append('# Demo')
        lines.append('if __name__ == "__main__":')

        # Generate demo calls based on templates
        for template_name in templates[:3]:
            demo = self._generate_demo(template_name)
            if demo:
                for dl in demo:
                    lines.append(f'    {dl}')

        lines.append('    print("Done.")')

        return '\n'.join(lines)

    def _generate_demo(self, template_name: str) -> List[str]:
        """Generate demo code for a template."""
        demos = {
            'file_reader': [
                'content = read_file("data.txt")',
                'print(f"Read {len(content)} chars")',
            ],
            'csv_reader': [
                'rows = read_csv("data.csv")',
                'print(f"Read {len(rows)} rows")',
            ],
            'json_reader': [
                'data = read_json("data.json")',
                'print(f"Read: {data}")',
            ],
            'json_writer': [
                'write_json({"key": "value"}, "output.json")',
                'print("Wrote output.json")',
            ],
            'csv_writer': [
                'write_csv([{"name": "Alice", "age": 30}], "output.csv")',
                'print("Wrote output.csv")',
            ],
            'sqlite_ops': [
                'db_operation("data.db", "SELECT * FROM users LIMIT 5")',
                'print("Queried database")',
            ],
            'hash_compute': [
                'h = compute_hash("hello world")',
                'print(f"SHA-256: {h}")',
            ],
            'list_transform': [
                'result = transform_list([3, 1, 4, 1, 5, 9])',
                'print(f"Sorted: {result}")',
            ],
            'string_processor': [
                'words = process_string("hello world test", "words")',
                'print(f"Words: {words}")',
            ],
            'datetime_ops': [
                'now = datetime_operation("now")',
                'print(f"Current: {now}")',
            ],
        }
        return demos.get(template_name, [])


if __name__ == '__main__':
    gen = FragmentGenerator()

    # Test generation
    test_intents = [
        "read a CSV file and sort the data",
        "compute hash of file contents",
        "parse json and write to database",
    ]

    for intent in test_intents:
        code = gen.generate_from_intent(intent)
        if code:
            print(f"=== {intent} ===")
            print(code[:300])
            print("...")
            print()
        else:
            print(f"Could not generate for: {intent}")
