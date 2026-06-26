"""
Intent Verifier — Structural verification that generated code matches intent

NOT "formal verification" in the mathematical sense. This module does
pragmatic structural checks:
1. Import verification: does code import modules needed for the intent?
2. Operation verification: does code perform the operations requested?
3. Safety check: no dangerous calls in safe_mode
4. Completeness: code has actual logic, not just boilerplate
5. Output alignment: if intent requires output, code has print/return
"""
# Dependencies: none
# Depended by: none (leaf module)


import ast
import re
from typing import List, Dict, Any, Set


class FormalVerifier:
    """Structural intent verification for generated code"""

    # Intent keywords → expected modules
    INTENT_MODULE_MAP = {
        'csv': {'csv'},
        'json': {'json'},
        'database': {'sqlite3', 'sqlalchemy'},
        'sqlite': {'sqlite3'},
        'sql': {'sqlite3', 'sqlalchemy'},
        'download': {'requests', 'urllib'},
        'http': {'requests', 'urllib', 'http'},
        'webpage': {'requests', 'urllib'},
        'api': {'requests', 'flask', 'fastapi'},
        'hash': {'hashlib'},
        'sha256': {'hashlib'},
        'md5': {'hashlib'},
        'regex': {'re'},
        'pattern': {'re'},
        'email': {'re', 'smtplib', 'email'},
        'zip': {'zipfile'},
        'tar': {'tarfile'},
        'compress': {'zipfile', 'tarfile', 'gzip', 'zlib'},
        'socket': {'socket'},
        'port': {'socket'},
        'tcp': {'socket'},
        'udp': {'socket'},
        'random': {'random'},
        'plot': {'matplotlib'},
        'chart': {'matplotlib'},
        'graph': {'matplotlib', 'networkx'},
        'image': {'PIL', 'Pillow', 'cv2'},
        'numpy': {'numpy'},
        'pandas': {'pandas'},
        'dataframe': {'pandas'},
        'subprocess': {'subprocess'},
        'command': {'subprocess', 'os', 'socket', 'threading', 'json'},  # Network-based also valid
        'thread': {'threading'},
        'async': {'asyncio'},
        'encrypt': {'cryptography', 'Crypto'},
        'decrypt': {'cryptography', 'Crypto'},
        'yaml': {'yaml', 'pyyaml'},
        'xml': {'xml', 'lxml'},
        'html': {'html', 'bs4', 'lxml'},
        'scrape': {'requests', 'bs4', 'scrapy'},
        'ssh': {'paramiko'},
        'ftp': {'ftplib'},
        'smtp': {'smtplib'},
        # Network server patterns (agent, c2, bot, botnet, server)
        'agent': {'socket', 'threading', 'json', 'requests'},
        'c2': {'socket', 'threading', 'json'},
        'bot': {'socket', 'threading', 'json', 'requests'},
        'botnet': {'socket', 'threading', 'json', 'requests'},
        'server': {'socket', 'threading', 'http', 'json'},
        'listen': {'socket', 'threading'},
        'client': {'socket', 'threading', 'requests'},
        'network': {'socket', 'threading', 'json'},
        'protocol': {'socket', 'threading', 'json'},
        # Resilience / Fallback
        'resilient': {'socket', 'json', 'hashlib'},
        'fallback': {'socket', 'json', 'hashlib'},
        'watchdog': {'os', 'sys', 'signal'},
        'respawn': {'os', 'sys'},
        'persistence': {'os', 'sys'},
        'adaptive': {'socket', 'json', 'hashlib'},
        'beacon': {'socket', 'json'},
    }

    def __init__(self, knowledge_engine):
        self.ke = knowledge_engine

    def verify(self, script: str, intent: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify that generated code structurally matches the intent.

        Returns:
            {
                'is_proven': bool,       # All checks pass
                'violations': List[str], # What failed
                'checks_passed': int,    # How many checks passed
                'checks_total': int,     # Total checks run
                'cert': str or None,     # Verification certificate
            }
        """
        results = {
            'is_proven': False,
            'violations': [],
            'checks_passed': 0,
            'checks_total': 0,
            'cert': None,
        }

        try:
            tree = ast.parse(script)
        except SyntaxError as e:
            results['violations'].append(f'SyntaxError: {e}')
            results['checks_total'] = 1
            return results

        # Extract code info
        imports = self._extract_imports(script)
        has_output = 'print(' in script or 'return ' in script
        has_logic = self._has_real_logic(tree)
        func_count = sum(1 for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))

        # Run checks
        checks = []

        # Check 1: Code parses as valid Python
        checks.append(('valid_python', True))

        # Check 2: Code has actual logic (not just boilerplate)
        checks.append(('has_logic', has_logic))
        if not has_logic:
            results['violations'].append('Code has no real logic (empty functions or only print)')

        # Check 3: Safety check in safe_mode
        if intent.get('safe_mode'):
            safe = self._check_safety(tree)
            checks.append(('safe_mode', safe))
            if not safe:
                results['violations'].append('Dangerous calls detected in safe_mode')

        # Check 4: Import alignment — does code import modules matching the intent?
        intent_modules = self._get_expected_modules(intent)
        if intent_modules:
            import_ok = bool(imports & intent_modules)
            checks.append(('import_alignment', import_ok))
            if not import_ok:
                results['violations'].append(
                    f'Expected one of {intent_modules} but found {imports}'
                )

        # Check 5: Output alignment — if intent requires output, check for print
        if intent.get('requires_output'):
            checks.append(('has_output', has_output))
            if not has_output:
                results['violations'].append('Intent requires output but code has no print/return')

        # Check 6: Code is not just "No implementation available"
        not_empty = 'No implementation available' not in script
        checks.append(('not_empty', not_empty))
        if not not_empty:
            results['violations'].append('Code contains "No implementation available"')

        # Tally results
        results['checks_total'] = len(checks)
        results['checks_passed'] = sum(1 for _, ok in checks if ok)

        # Proven if ALL checks pass
        if all(ok for _, ok in checks):
            results['is_proven'] = True
            results['cert'] = self._generate_cert(intent, results['checks_passed'])

        return results

    def _extract_imports(self, script: str) -> Set[str]:
        """Extract imported module names from script"""
        modules = set()
        for line in script.split('\n'):
            stripped = line.strip()
            if stripped.startswith('import '):
                parts = stripped.split()
                if len(parts) >= 2:
                    modules.add(parts[1].split('.')[0])
            elif stripped.startswith('from '):
                parts = stripped.split()
                if len(parts) >= 2:
                    modules.add(parts[1].split('.')[0])
        return modules

    def _has_real_logic(self, tree: ast.AST) -> bool:
        """Check if the code has actual logic beyond boilerplate"""
        # Count meaningful nodes
        meaningful = 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.Call, ast.For, ast.While, ast.If, ast.With,
                                 ast.Assign, ast.AugAssign, ast.Try)):
                meaningful += 1
        return meaningful >= 2

    def _check_safety(self, tree: ast.AST) -> bool:
        """Check for dangerous calls in safe_mode"""
        dangerous = {'system', 'popen', 'eval', 'exec', '__import__'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ''
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                if func_name in dangerous:
                    return False
        return True

    def _get_expected_modules(self, intent: Dict[str, Any]) -> Set[str]:
        """Get expected modules based on intent tokens and entities"""
        expected = set()
        tokens = set(intent.get('tokens', []))
        entities = {e['matched'].lower() for e in intent.get('entities', [])}
        all_words = tokens | entities

        for keyword, modules in self.INTENT_MODULE_MAP.items():
            if keyword in all_words:
                expected.update(modules)

        return expected

    def _generate_cert(self, intent: Dict[str, Any], checks_passed: int) -> str:
        """Generate a verification certificate"""
        import hashlib
        sig = f"{intent.get('raw', '')}:{checks_passed}".encode()
        h = hashlib.sha256(sig).hexdigest()[:8].upper()
        return f"FORGE-V-{h}-{checks_passed}CK"
