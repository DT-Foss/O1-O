"""
Sandbox Model — Phase 1 of FORGE Self-Repair

Describes the ForgeValidator sandbox environment as structured data.
Used by:
  - Phase 1: Self-Diagnostics (explain WHY a failure happened)
  - Phase 4: Execution Simulator (predict IF code will fail)
  - Phase 2: Auto-Fix (choose appropriate fix strategy)

The sandbox is a tempdir with fixture files, no CLI args,
no network, Python 3.x stdlib only, 10s timeout.
"""
# Dependencies: none
# Depended by: execution_simulator, self_repair


from typing import Dict, Any, List


# ── Sandbox Constraints ──────────────────────────────────────────

SANDBOX_CONSTRAINTS = {
    # Execution environment
    'python_version': '3.x',
    'timeout_seconds': 10,
    'no_cli_args': True,         # sys.argv == ['script.py']
    'no_network': True,          # no outbound connections
    'no_gui': True,              # no tkinter, pygame, etc.
    'no_interactive': True,      # no input(), no stdin
    'cwd_is_sandbox': True,      # os.getcwd() == sandbox tempdir
    'subprocess_allowed': True,  # subprocess.run works (within sandbox)
    'threading_allowed': True,   # threads work but timeout kills all
    'max_output_bytes': 100000,  # stdout/stderr truncated beyond this

    # Available modules (stdlib only — no pip packages)
    'stdlib_available': True,
    'pip_packages': False,       # no pandas, numpy, requests, etc.

    # Writable paths
    'writable_cwd': True,        # can create files in sandbox dir
    'writable_tmp': True,        # /tmp accessible
}

# ── Fixture Files ────────────────────────────────────────────────

SANDBOX_FILES = {
    'data.txt': {
        'type': 'text',
        'content': "hello world\nfoo bar baz\ntest data 42\nalice bob charlie\n",
        'lines': 4,
        'encoding': 'utf-8',
    },
    'data.csv': {
        'type': 'csv',
        'columns': ['name', 'age', 'city'],
        'rows': [
            ['Alice', '30', 'Berlin'],
            ['Bob', '25', 'Munich'],
            ['Charlie', '35', 'Hamburg'],
            ['Diana', '28', 'Frankfurt'],
        ],
        'row_count': 4,
        'has_header': True,
    },
    'data.json': {
        'type': 'json',
        'structure': {'name': 'str', 'items': 'list[int]', 'nested': 'dict'},
        'content': {'name': 'test', 'items': [1, 2, 3], 'nested': {'key': 'value'}},
    },
    'data.db': {
        'type': 'sqlite',
        'tables': {
            'data': {
                'columns': [
                    ('id', 'INTEGER', 'PRIMARY KEY'),
                    ('name', 'TEXT', ''),
                    ('age', 'INTEGER', ''),
                    ('city', 'TEXT', ''),
                ],
                'rows': [
                    (1, 'Alice', 30, 'Berlin'),
                    (2, 'Bob', 25, 'Munich'),
                ],
                'row_count': 2,
            }
        }
    },
    'app.log': {
        'type': 'text',
        'content': (
            "2024-01-01 10:00:00 INFO Server started\n"
            "2024-01-01 10:01:00 WARNING High memory usage\n"
            "2024-01-01 10:02:00 ERROR Connection failed\n"
            "2024-01-01 10:03:00 INFO Retry successful\n"
        ),
        'lines': 4,
        'format': 'timestamp level message',
    },
    'file.txt': {
        'type': 'text',
        'content': "line 1\nline 2\nline 3\n",
        'lines': 3,
    },
    'file1.txt': {
        'type': 'text',
        'content': "line 1\nline 2\nline 3\nline 4\n",
        'lines': 4,
    },
    'file2.txt': {
        'type': 'text',
        'content': "line 1\nline 2 modified\nline 3\nline 5\n",
        'lines': 4,
    },
    'old_file.txt': {
        'type': 'text',
        'content': "original content\nline two\nline three\n",
        'lines': 3,
    },
    'new_file.txt': {
        'type': 'text',
        'content': "original content\nline two modified\nline three\nnew line\n",
        'lines': 4,
    },
    'output.txt': {
        'type': 'text',
        'content': '',
        'lines': 0,
        'writable': True,
    },
    'config.yaml': {
        'type': 'yaml',
        'content': "database:\n  host: localhost\n  port: 5432\n  name: testdb\nlogging:\n  level: INFO\n",
    },
}

SANDBOX_DIRS = ['output/']

# ── Constraint Triplets ──────────────────────────────────────────

def get_constraint_triplets() -> List[Dict[str, Any]]:
    """Generate sandbox constraint triplets for the knowledge engine.

    These triplets encode what the sandbox CAN and CANNOT do.
    Used by the Execution Simulator (Phase 4) to predict failures.
    """
    triplets = []

    # Environment constraints
    for key, val in SANDBOX_CONSTRAINTS.items():
        triplets.append({
            'trigger': 'sandbox',
            'mechanism': 'has_constraint',
            'outcome': f'{key}={val}',
            'confidence': 1.0,
            '_source_graph': 'sandbox_model',
        })

    # Available files
    for filename, info in SANDBOX_FILES.items():
        triplets.append({
            'trigger': 'sandbox',
            'mechanism': 'has_file',
            'outcome': filename,
            'confidence': 1.0,
            '_source_graph': 'sandbox_model',
            '_file_info': info,
        })

    # Available directories
    for dirname in SANDBOX_DIRS:
        triplets.append({
            'trigger': 'sandbox',
            'mechanism': 'has_directory',
            'outcome': dirname,
            'confidence': 1.0,
            '_source_graph': 'sandbox_model',
        })

    # DB schema
    db_info = SANDBOX_FILES['data.db']
    for table_name, table_info in db_info['tables'].items():
        cols = ', '.join(c[0] for c in table_info['columns'])
        triplets.append({
            'trigger': 'sandbox',
            'mechanism': 'has_table',
            'outcome': f'{table_name}({cols})',
            'confidence': 1.0,
            '_source_graph': 'sandbox_model',
        })

    # CSV schema
    csv_info = SANDBOX_FILES['data.csv']
    cols = ', '.join(csv_info['columns'])
    triplets.append({
        'trigger': 'sandbox',
        'mechanism': 'has_csv_schema',
        'outcome': f'data.csv({cols})',
        'confidence': 1.0,
        '_source_graph': 'sandbox_model',
    })

    # Prohibited operations
    prohibited = [
        ('cli_arguments', 'sys.argv has no user arguments'),
        ('network_access', 'no outbound connections allowed'),
        ('pip_packages', 'only stdlib modules available'),
        ('gui_display', 'no display server available'),
        ('user_input', 'no stdin / input() available'),
    ]
    for op, reason in prohibited:
        triplets.append({
            'trigger': 'sandbox',
            'mechanism': 'prohibits',
            'outcome': f'{op}: {reason}',
            'confidence': 1.0,
            '_source_graph': 'sandbox_model',
        })

    return triplets


def check_code_against_sandbox(code: str) -> List[Dict[str, str]]:
    """Quick static check: does this code use things the sandbox doesn't have?

    Returns list of potential violations:
    [{'type': 'missing_cli_args', 'evidence': 'argparse...', 'severity': 'moderate'}, ...]
    """
    violations = []

    # Check for CLI argument parsing
    if 'argparse' in code or 'sys.argv[1' in code or 'sys.argv[2' in code:
        if 'sys.argv[1:]' in code or "if len(sys.argv)" in code:
            pass  # has a guard
        else:
            violations.append({
                'type': 'missing_cli_args',
                'evidence': 'Uses argparse/sys.argv without fallback',
                'severity': 'moderate',
            })

    # Check for network access
    network_imports = ['requests', 'urllib.request', 'http.client', 'socket.connect']
    for ni in network_imports:
        if ni in code:
            violations.append({
                'type': 'network_in_sandbox',
                'evidence': f'Uses {ni}',
                'severity': 'hard',
            })
            break

    # Check for pip packages
    pip_packages = [
        'pandas', 'numpy', 'scipy', 'sklearn', 'tensorflow',
        'torch', 'flask', 'django', 'fastapi', 'beautifulsoup4',
        'bs4', 'selenium', 'matplotlib', 'plotly', 'pillow',
        'PIL', 'cv2', 'openai', 'anthropic', 'pydantic',
    ]
    for pkg in pip_packages:
        if f'import {pkg}' in code or f'from {pkg}' in code:
            violations.append({
                'type': 'pip_package',
                'evidence': f'Imports {pkg} (not in stdlib)',
                'severity': 'moderate',
            })
            break

    # Check for user input
    if 'input(' in code and 'mock' not in code.lower():
        violations.append({
            'type': 'interactive_input',
            'evidence': 'Uses input() without mock',
            'severity': 'moderate',
        })

    # Check for GUI
    gui_modules = ['tkinter', 'pygame', 'wx', 'PyQt', 'PySide']
    for gm in gui_modules:
        if f'import {gm}' in code or f'from {gm}' in code:
            violations.append({
                'type': 'gui_import',
                'evidence': f'Imports {gm} (no display)',
                'severity': 'hard',
            })
            break

    # Check for files that don't exist in sandbox
    import re
    file_opens = re.findall(r"open\(['\"]([^'\"]+)['\"]", code)
    for filepath in file_opens:
        basename = filepath.split('/')[-1]
        if basename not in SANDBOX_FILES and not filepath.startswith('/tmp'):
            # Check if it's a file being created (mode 'w')
            pattern = rf"open\(['\"]({re.escape(filepath)})['\"].*?['\"]w"
            if not re.search(pattern, code):
                violations.append({
                    'type': 'missing_file',
                    'evidence': f'Opens {filepath} for reading but file not in sandbox',
                    'severity': 'moderate',
                })

    return violations
