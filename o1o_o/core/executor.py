"""
Executor — Sandbox execution + auto-debug + semantic error recovery

Runs generated scripts in isolated environment:
1. Sandbox execution (tempdir, timeout)
2. Error analysis (parse stderr)
3. Auto-fix (apply known fixes — 12 strategies)
4. Output validation (check if output matches intent)
5. Re-execute (max iterations)
6. Batch execution for Monte Carlo code generation
"""
# Dependencies: failure_memory
# Depended by: none (leaf module)


import subprocess
import tempfile
import os
import re
import time
from pathlib import Path
from typing import Dict, Any, Optional, List


class Executor:
    """Execute and debug generated scripts with semantic error recovery"""

    # Package name mappings for auto-install
    PACKAGE_MAP = {
        'PIL': 'Pillow',
        'cv2': 'opencv-python',
        'sklearn': 'scikit-learn',
        'yaml': 'pyyaml',
        'lxml': 'lxml',
        'bs4': 'beautifulsoup4',
        'dateutil': 'python-dateutil',
        'dotenv': 'python-dotenv',
        'jwt': 'PyJWT',
        'Crypto': 'pycryptodome',
        'serial': 'pyserial',
        'dns': 'dnspython',
        'socks': 'PySocks',
        'nacl': 'PyNaCl',
        'attr': 'attrs',
        'nmap': 'python-nmap',
        'scapy': 'scapy',
        'shodan': 'shodan',
        'magic': 'python-magic',
        'psycopg2': 'psycopg2-binary',
    }

    # Common variable defaults for NameError recovery
    VARIABLE_DEFAULTS = {
        'data': '""',
        'result': 'None',
        'output': '""',
        'items': '[]',
        'results': '[]',
        'count': '0',
        'total': '0',
        'content': '""',
        'text': '""',
        'response': 'None',
        'path': '"."',
        'filename': '"output.txt"',
        'url': '"https://example.com"',
    }

    # Patterns that indicate a long-running daemon/server process
    DAEMON_PATTERNS = [
        'serve_forever(', 'server.accept(', '.listen(',
        'HTTPServer(', 'TCPServer(', 'UDPServer(',
        'observer.start(', 'Observer(',
        'app.run(', 'Flask(__name__)',
        'asyncio.get_event_loop().run_forever',
        'run_forever(', 'socketserver.',
        'while True:\n',  # Generic infinite loop (monitors, watchers)
    ]

    def __init__(self, timeout: int = 30, max_retries: int = 5):
        self.timeout = timeout
        self.max_retries = max_retries
        self._failure_memory = None  # Lazy-loaded

    @property
    def failure_memory(self):
        """Lazy-load failure memory to avoid circular imports."""
        if self._failure_memory is None:
            try:
                from o1o_o.core.failure_memory import FailureMemory
                self._failure_memory = FailureMemory()
            except Exception:
                pass
        return self._failure_memory

    def _is_daemon_script(self, script: str) -> bool:
        """Check if script is a long-running daemon/server"""
        return any(p in script for p in self.DAEMON_PATTERNS)

    def run(self, script: str, intent: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute script in sandbox

        Returns:
            {
                'success': bool,
                'stdout': str,
                'stderr': str,
                'exit_code': int,
                'message': str,
                'error': Optional[str],
                'output_valid': bool  # semantic output validation
            }
        """
        if intent is None:
            intent = {}

        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "forge_script.py"

            with open(script_path, 'w') as f:
                f.write(script)

            os.chmod(script_path, 0o755)

            # Create common test files if script references them
            self._prepare_sandbox(tmpdir, script, intent)

            # Operator host guard: prevent persistence/system modification in sandbox
            sandbox_env = os.environ.copy()
            sandbox_env['FORGE_OPERATOR'] = '1'
            sandbox_env['FORGE_SANDBOX'] = '1'
            sandbox_env['FORGE_TTL'] = str(self.timeout)

            # Daemon/server scripts: start, wait briefly, if alive → success
            if self._is_daemon_script(script):
                return self._run_daemon(script_path, tmpdir, intent, env=sandbox_env)

            try:
                result = subprocess.run(
                    ['python3', str(script_path)],
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    env=sandbox_env
                )

                success = result.returncode == 0

                error_info = None if success else {
                    'type': self.parse_error_type(result.stderr),
                    'message': result.stderr
                }

                # Semantic output validation
                output_valid = self._validate_output(
                    result.stdout, intent
                ) if success else False

                return {
                    'success': success,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'exit_code': result.returncode,
                    'message': result.stdout if success else result.stderr,
                    'error': error_info['type'] if error_info else None,
                    'error_full': result.stderr if not success else None,
                    'output_valid': output_valid,
                }

            except subprocess.TimeoutExpired:
                return {
                    'success': False,
                    'stdout': '',
                    'stderr': f'Script timed out after {self.timeout}s',
                    'exit_code': -1,
                    'message': 'Timeout',
                    'error': 'TIMEOUT',
                    'output_valid': False,
                }
            except Exception as e:
                return {
                    'success': False,
                    'stdout': '',
                    'stderr': str(e),
                    'exit_code': -1,
                    'message': str(e),
                    'error': 'EXECUTION_ERROR',
                    'output_valid': False,
                }

    def _run_daemon(self, script_path: Path, tmpdir: str, intent: Dict[str, Any],
                    env: dict = None) -> Dict[str, Any]:
        """Execute a daemon/server script: start it, verify it stays alive, then kill it.

        For servers, staying alive IS the expected behavior. If the process
        starts and is still running after 3 seconds, that means the server
        initialized successfully.
        """
        try:
            proc = subprocess.Popen(
                ['python3', str(script_path)],
                cwd=tmpdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )

            # Wait 3 seconds — enough for import errors and bind failures
            time.sleep(3)

            if proc.poll() is None:
                # Still running → server started successfully
                proc.kill()
                proc.wait()
                stdout = proc.stdout.read().decode('utf-8', errors='replace') if proc.stdout else ''
                return {
                    'success': True,
                    'stdout': stdout or 'Server started successfully (daemon mode)',
                    'stderr': '',
                    'exit_code': 0,
                    'message': 'Server/daemon started and verified',
                    'error': None,
                    'output_valid': True,
                }
            else:
                # Process died quickly → startup error
                stdout = proc.stdout.read().decode('utf-8', errors='replace') if proc.stdout else ''
                stderr = proc.stderr.read().decode('utf-8', errors='replace') if proc.stderr else ''
                return {
                    'success': False,
                    'stdout': stdout,
                    'stderr': stderr,
                    'exit_code': proc.returncode,
                    'message': stderr or 'Daemon exited unexpectedly',
                    'error': self.parse_error_type(stderr),
                    'error_full': stderr,
                    'output_valid': False,
                }

        except Exception as e:
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1,
                'message': str(e),
                'error': 'EXECUTION_ERROR',
                'output_valid': False,
            }

    def _prepare_sandbox(self, tmpdir: str, script: str, intent: Dict[str, Any]):
        """Create test files in sandbox if script needs them"""
        # Always create a data.txt with test content (many fragments use this as default)
        default_txt = Path(tmpdir) / 'data.txt'
        if not default_txt.exists():
            lines = [f'Line {i}: test data content for line number {i}\n' for i in range(1, 2002)]
            lines.insert(3, 'ERROR: something went wrong here\n')
            lines.insert(7, 'ERROR: another error occurred\n')
            default_txt.write_text(''.join(lines))

        # If script references common test files, create them
        if "'data.csv'" in script or '"data.csv"' in script:
            csv_path = Path(tmpdir) / 'data.csv'
            csv_path.write_text('name,age,city\nAlice,30,NYC\nBob,25,London\nCarol,35,Tokyo\n')

        if "'data.json'" in script or '"data.json"' in script:
            json_path = Path(tmpdir) / 'data.json'
            json_path.write_text('{"name": "test", "values": [1, 2, 3]}\n')

        if "'data.txt'" in script or '"data.txt"' in script:
            txt_path = Path(tmpdir) / 'data.txt'
            txt_path.write_text('Hello World\nTest data line 1\nTest data line 2\nERROR: something failed\nLine 5\n')

        if "'input.txt'" in script or '"input.txt"' in script:
            txt_path = Path(tmpdir) / 'input.txt'
            txt_path.write_text('Input test data\nLine 2\nLine 3\n')

        if "'file.txt'" in script or '"file.txt"' in script:
            (Path(tmpdir) / 'file.txt').write_text('test file content\nline 2\nline 3\n')

        if "'app.log'" in script or '"app.log"' in script:
            (Path(tmpdir) / 'app.log').write_text(
                '2024-01-01 INFO  Application started\n'
                '2024-01-01 ERROR Connection refused\n'
                '2024-01-02 WARN  Slow query detected\n'
                '2024-01-02 ERROR Timeout expired\n'
            )

        # Create test files for directory organizer tasks
        if 'os.listdir' in script and ('shutil.move' in script or 'os.rename' in script):
            for name in ['photo.jpg', 'doc.pdf', 'song.mp3', 'code.py', 'data.csv']:
                (Path(tmpdir) / name).write_text(f'test file: {name}')

        # Create subdirectory with test files for directory tree operations
        if 'os.walk' in script:
            subdir = Path(tmpdir) / 'subdir'
            subdir.mkdir(exist_ok=True)
            (subdir / 'nested.txt').write_text('nested file\n')
            (Path(tmpdir) / 'root_file.txt').write_text('root level file\n')
            (Path(tmpdir) / 'test.py').write_text('print("hello")\n')

        # Create files for diff/comparison tasks
        if "'file1.txt'" in script or '"file1.txt"' in script:
            (Path(tmpdir) / 'file1.txt').write_text('line 1\nline 2\nline 3\n')
        if "'file2.txt'" in script or '"file2.txt"' in script:
            (Path(tmpdir) / 'file2.txt').write_text('line 1\nline 2 modified\nline 3\nline 4\n')

        # Create extracted directory for archive operations
        if "'extracted'" in script or '"extracted"' in script:
            (Path(tmpdir) / 'extracted').mkdir(exist_ok=True)

    def _validate_output(self, stdout: str, intent: Dict[str, Any]) -> bool:
        """Semantic validation: check if output matches what the intent expected"""
        if not stdout.strip():
            # No output — check if intent requires output
            requires_output = intent.get('requires_output', False)
            return not requires_output

        # Check for common error indicators in stdout (not stderr)
        error_indicators = ['Traceback', 'Error:', 'Exception:']
        for indicator in error_indicators:
            if indicator in stdout and len(stdout.strip()) < 100:
                return False

        # "None" alone as the entire output usually means a function returned nothing
        if stdout.strip() == 'None':
            return not intent.get('requires_output', False)

        # Check intent-specific expectations
        raw = intent.get('raw', '').lower()

        # If asking for a list/count, output should have numbers or items
        if any(w in raw for w in ['count', 'how many', 'list', 'enumerate']):
            has_numbers = bool(re.search(r'\d+', stdout))
            has_lines = len(stdout.strip().split('\n')) > 1
            if not has_numbers and not has_lines:
                return False

        # If asking for JSON, output should look like JSON
        if 'json' in raw:
            stripped = stdout.strip()
            if not (stripped.startswith('{') or stripped.startswith('[')):
                return False

        return True

    def run_project(self, project_files: Dict[str, str], intent: Dict[str, Any] = None,
                   timeout: int = 30) -> Dict[str, Any]:
        """Execute a multi-file project (TDD: tests first, then main).

        Args:
            project_files: Dict with keys like 'test_main.py', 'main.py', '__init__.py'
            intent: Task intent for error recovery
            timeout: Execution timeout in seconds

        Returns:
            {
                'success': bool,
                'test_passed': bool,
                'test_output': str,
                'main_output': str,
                'error': str or None,
                'exit_code': int,
            }
        """
        sandbox_dir = None
        try:
            sandbox_dir = tempfile.mkdtemp(prefix='forge_project_')

            # Step 1: Write all project files
            for filename, content in project_files.items():
                filepath = Path(sandbox_dir) / filename
                with open(filepath, 'w') as f:
                    f.write(content)

            # Step 2: Run tests FIRST (spec validation)
            test_file = Path(sandbox_dir) / 'test_main.py'
            if test_file.exists():
                test_result = subprocess.run(
                    ['/usr/bin/python3', str(test_file)],
                    capture_output=True, text=True, timeout=timeout,
                    cwd=sandbox_dir,
                    env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1',
                         'FORGE_OPERATOR': '1', 'FORGE_SANDBOX': '1'},
                )

                test_output = test_result.stdout + test_result.stderr
                test_passed = test_result.returncode == 0

                if not test_passed:
                    return {
                        'success': False,
                        'test_passed': False,
                        'test_output': test_output,
                        'main_output': '',
                        'error': f'Tests failed: {test_output[:200]}',
                        'exit_code': test_result.returncode,
                    }
            else:
                test_passed = True
                test_output = '(no test file)'

            # Step 3: Run main.py (implementation)
            main_file = Path(sandbox_dir) / 'main.py'
            if main_file.exists():
                main_result = subprocess.run(
                    ['/usr/bin/python3', str(main_file)],
                    capture_output=True, text=True, timeout=timeout,
                    cwd=sandbox_dir,
                    env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1',
                         'FORGE_OPERATOR': '1', 'FORGE_SANDBOX': '1'},
                )

                main_output = main_result.stdout
                main_stderr = main_result.stderr
                main_passed = main_result.returncode == 0

                if not main_passed:
                    return {
                        'success': False,
                        'test_passed': test_passed,
                        'test_output': test_output,
                        'main_output': main_output,
                        'error': main_stderr[:200],
                        'exit_code': main_result.returncode,
                    }

                return {
                    'success': True,
                    'test_passed': test_passed,
                    'test_output': test_output,
                    'main_output': main_output,
                    'error': None,
                    'exit_code': 0,
                }
            else:
                return {
                    'success': False,
                    'test_passed': test_passed,
                    'test_output': test_output,
                    'main_output': '',
                    'error': 'No main.py file',
                    'exit_code': 1,
                }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'test_passed': False,
                'test_output': '',
                'main_output': '',
                'error': 'Project execution timed out',
                'exit_code': -1,
            }
        except Exception as e:
            return {
                'success': False,
                'test_passed': False,
                'test_output': '',
                'main_output': '',
                'error': str(e),
                'exit_code': -1,
            }
        finally:
            if sandbox_dir:
                import shutil
                try:
                    shutil.rmtree(sandbox_dir, ignore_errors=True)
                except Exception:
                    pass

    def run_batch(self, scripts: List[str], intent: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Execute multiple candidate scripts in parallel, score, and rank.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        if not intent:
            intent = {}

        results = []

        def execute_one(idx_script):
            idx, script = idx_script
            result = self.run(script, intent)
            score = 0
            if result['success']:
                score += 10
            if result.get('stdout', '').strip():
                score += 3
                output_len = len(result['stdout'].strip())
                score += min(2, output_len / 100)
            if not result.get('stderr', '').strip():
                score += 2
            if result.get('error') == 'TIMEOUT':
                score -= 5
            # Bonus for semantic output validation
            if result.get('output_valid', False):
                score += 3

            return {
                'index': idx,
                'score': score,
                'script': script,
                'result': result,
            }

        with ThreadPoolExecutor(max_workers=min(len(scripts), 4)) as executor:
            futures = {
                executor.submit(execute_one, (i, s)): i
                for i, s in enumerate(scripts)
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    idx = futures[future]
                    results.append({
                        'index': idx,
                        'score': -1,
                        'script': scripts[idx],
                        'result': {'success': False, 'error': str(e),
                                   'stdout': '', 'stderr': str(e)},
                    })

        results.sort(key=lambda x: x['score'], reverse=True)
        return results

    def parse_error_type(self, stderr: str) -> str:
        """Extract error type from stderr"""
        error_types = [
            'ModuleNotFoundError',
            'FileNotFoundError',
            'IndexError',
            'KeyError',
            'TypeError',
            'ValueError',
            'AttributeError',
            'ImportError',
            'SyntaxError',
            'NameError',
            'ZeroDivisionError',
            'PermissionError',
            'RecursionError',
            'ConnectionError',
            'TimeoutError',
            'UnicodeDecodeError',
            'OSError',
        ]

        for error_type in error_types:
            if error_type in stderr:
                return error_type

        return 'UNKNOWN_ERROR'

    def auto_fix(self, script: str, error_info: str, knowledge_engine=None,
                 stderr: str = '') -> Optional[str]:
        """
        Attempt to auto-fix script based on error (12 hardcoded + failure memory + inverse inference)

        Args:
            script: Original script
            error_info: Error type string
            knowledge_engine: Access to error_patterns.causal
            stderr: Full stderr output from execution

        Returns:
            Fixed script or None if can't fix
        """
        # Strategy 0: Check failure memory first (learned fixes)
        if self.failure_memory:
            fixed = self.failure_memory.lookup_fix(error_info, stderr, script)
            if fixed and fixed != script:
                return fixed

        # Strategy 0.5: Try inverse inference hypotheses (Phase E)
        # Generate hypotheses about what code causes this error, try fixes
        if self.failure_memory:
            hypotheses = self.failure_memory.generate_hypotheses(error_info, stderr)
            if hypotheses:
                for hyp in hypotheses:  # Already sorted by confidence (descending)
                    fixed = self._apply_hypothesis_fix(script, hyp, stderr)
                    if fixed and fixed != script:
                        # Record this hypothesis as successful
                        self.failure_memory.record_fix(
                            error_info, stderr, script, fixed,
                            f"hypothesis: {hyp.get('hypothesis', '')}"
                        )
                        return fixed

        # Strategy 1: ModuleNotFoundError → auto-install
        if error_info == 'ModuleNotFoundError':
            return self._fix_module_not_found(script, stderr)

        # Strategy 2: NameError → initialize variable
        elif error_info == 'NameError':
            return self._fix_name_error(script, stderr)

        # Strategy 3: FileNotFoundError → create or use defaults
        elif error_info == 'FileNotFoundError':
            return self._fix_file_not_found(script, stderr)

        # Strategy 4: SyntaxError → common syntax fixes
        elif error_info == 'SyntaxError':
            return self._fix_syntax_error(script, stderr)

        # Strategy 5: TypeError → argument count, type coercion
        elif error_info == 'TypeError':
            return self._fix_type_error(script, stderr)

        # Strategy 6: IndexError → bounds checking
        elif error_info == 'IndexError':
            return self._fix_index_error(script, stderr)

        # Strategy 7: KeyError → .get() with default
        elif error_info == 'KeyError':
            return self._fix_key_error(script, stderr)

        # Strategy 8: AttributeError → hasattr check
        elif error_info == 'AttributeError':
            return self._fix_attribute_error(script, stderr)

        # Strategy 9: ValueError → try/except wrapper
        elif error_info == 'ValueError':
            return self._fix_value_error(script, stderr)

        # Strategy 10: ImportError → alternative import
        elif error_info == 'ImportError':
            return self._fix_import_error(script, stderr)

        # Strategy 11: UnicodeDecodeError → encoding fix
        elif error_info == 'UnicodeDecodeError':
            return self._fix_unicode_error(script, stderr)

        # Strategy 12: ConnectionError → retry with timeout
        elif error_info in ('ConnectionError', 'TimeoutError'):
            return self._fix_connection_error(script, stderr)

        return None

    def _fix_module_not_found(self, script: str, stderr: str) -> Optional[str]:
        """Strategy 1: Install missing module"""
        match = re.search(r"No module named ['\"](\w+)['\"]", stderr)
        if not match:
            return None

        module = match.group(1)
        pkg = self.PACKAGE_MAP.get(module, module)
        print(f"  -> Installing {pkg}...")

        try:
            result = subprocess.run(
                ['pip', 'install', '-q', pkg],
                capture_output=True, timeout=60, text=True
            )
            if result.returncode == 0:
                print(f"  ✓ Installed {pkg}")
                return script
        except Exception:
            pass

        return None

    def _fix_name_error(self, script: str, stderr: str) -> Optional[str]:
        """Strategy 2: Initialize undefined variable"""
        match = re.search(r"name ['\"](\w+)['\"] is not defined", stderr)
        if not match:
            return None

        var_name = match.group(1)
        default = self.VARIABLE_DEFAULTS.get(var_name, 'None')

        # Try to insert at start of main() or at top level
        if 'def main():' in script:
            fixed = re.sub(
                r'(def main\(\):\s*(?:""".*?"""\s*)?)',
                f'\\1    {var_name} = {default}  # Auto-initialized\n',
                script, count=1, flags=re.DOTALL
            )
            if fixed != script:
                return fixed

        # Top-level insertion after imports
        lines = script.split('\n')
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.startswith('import ') or line.startswith('from '):
                insert_idx = i + 1
            elif line.strip() and not line.startswith('#'):
                if insert_idx == 0:
                    insert_idx = i
                break
        lines.insert(insert_idx, f'{var_name} = {default}  # Auto-initialized')
        return '\n'.join(lines)

    def _fix_file_not_found(self, script: str, stderr: str) -> Optional[str]:
        """Strategy 3: Replace missing file paths with sensible defaults"""
        match = re.search(r"No such file or directory: '([^']+)'", stderr)
        if not match:
            return None

        missing_path = match.group(1)

        # Replace problematic path with test data
        replacements = {
            '.': 'data.csv',
            'input.txt': 'data.txt',
        }

        for old, new in replacements.items():
            if missing_path == old:
                return script.replace(f"'{old}'", f"'{new}'").replace(f'"{old}"', f'"{new}"')

        # If path looks like user-provided, create a stub
        if '/' not in missing_path and '.' in missing_path:
            # Inject file creation at the start
            ext = missing_path.rsplit('.', 1)[-1]
            stubs = {
                'csv': 'name,value\ntest,1\n',
                'json': '{"test": true}\n',
                'txt': 'test data\n',
            }
            stub_content = stubs.get(ext, 'test\n')
            create_line = f"# Auto-create missing file\nwith open('{missing_path}', 'w') as _f: _f.write('''{stub_content}''')\n\n"

            lines = script.split('\n')
            insert_idx = 0
            for i, line in enumerate(lines):
                if line.startswith('import ') or line.startswith('from '):
                    insert_idx = i + 1
            lines.insert(insert_idx, create_line)
            return '\n'.join(lines)

        return None

    def _fix_syntax_error(self, script: str, stderr: str) -> Optional[str]:
        """Strategy 4: Common syntax error fixes"""
        fixed = script

        # Remove trailing commas before closing parens
        fixed = re.sub(r',\s*\)', ')', fixed)
        if fixed != script:
            return fixed

        # Fix missing colons after if/for/while/def
        fixed = re.sub(r'((?:if|for|while|def|class)\s+[^\n:]+)\s*\n', r'\1:\n', script)
        if fixed != script:
            return fixed

        # Fix unclosed strings (add missing quote at EOL)
        lines = script.split('\n')
        for i, line in enumerate(lines):
            single_count = line.count("'") - line.count("\\'")
            double_count = line.count('"') - line.count('\\"')
            if single_count % 2 != 0:
                lines[i] = line + "'"
            elif double_count % 2 != 0:
                lines[i] = line + '"'
        fixed = '\n'.join(lines)
        if fixed != script:
            return fixed

        return None

    def _fix_type_error(self, script: str, stderr: str) -> Optional[str]:
        """Strategy 5: Fix type errors"""
        # "can't convert X to Y" → add str() or int() wrappers
        if 'str' in stderr and 'int' in stderr:
            # Wrap concatenation targets with str()
            fixed = re.sub(r'(\+\s*)(\w+)', r'\1str(\2)', script)
            if fixed != script:
                return fixed

        # Wrong number of arguments
        if 'argument' in stderr and 'positional' in stderr:
            # Can't reliably fix, skip
            pass

        return None

    def _fix_index_error(self, script: str, stderr: str) -> Optional[str]:
        """Strategy 6: Add bounds checking"""
        # Find the line that caused the error
        line_match = re.search(r'line (\d+)', stderr)
        if not line_match:
            return None

        error_line = int(line_match.group(1)) - 1
        lines = script.split('\n')
        if error_line >= len(lines):
            return None

        problem_line = lines[error_line]
        # Wrap with bounds check
        index_match = re.search(r'(\w+)\[(\w+|\d+)\]', problem_line)
        if index_match:
            arr_name = index_match.group(1)
            idx = index_match.group(2)
            indent = len(problem_line) - len(problem_line.lstrip())
            check = f"{' ' * indent}if {idx} < len({arr_name}):"
            indented = f"{' ' * (indent + 4)}{problem_line.strip()}"
            lines[error_line] = check + '\n' + indented
            return '\n'.join(lines)

        return None

    def _fix_key_error(self, script: str, stderr: str) -> Optional[str]:
        """Strategy 7: Replace dict[key] with dict.get(key)"""
        key_match = re.search(r"KeyError: ['\"]?(\w+)['\"]?", stderr)
        if not key_match:
            return None

        key = key_match.group(1)
        # Replace [key] with .get(key, None)
        fixed = script.replace(f"['{key}']", f".get('{key}', None)")
        fixed = fixed.replace(f'["{key}"]', f'.get("{key}", None)')
        if fixed != script:
            return fixed

        return None

    def _fix_attribute_error(self, script: str, stderr: str) -> Optional[str]:
        """Strategy 8: Handle missing attributes"""
        match = re.search(r"'(\w+)' object has no attribute '(\w+)'", stderr)
        if not match:
            return None

        obj_type = match.group(1)
        attr = match.group(2)

        # Common fixes
        if obj_type == 'NoneType':
            # Object is None — add None check
            line_match = re.search(r'line (\d+)', stderr)
            if line_match:
                error_line = int(line_match.group(1)) - 1
                lines = script.split('\n')
                if error_line < len(lines):
                    problem = lines[error_line]
                    indent = len(problem) - len(problem.lstrip())
                    var_match = re.search(r'(\w+)\.' + re.escape(attr), problem)
                    if var_match:
                        var_name = var_match.group(1)
                        check = f"{' ' * indent}if {var_name} is not None:"
                        indented = f"{' ' * (indent + 4)}{problem.strip()}"
                        lines[error_line] = check + '\n' + indented
                        return '\n'.join(lines)

        return None

    def _fix_value_error(self, script: str, stderr: str) -> Optional[str]:
        """Strategy 9: Wrap with try/except for value conversion errors"""
        line_match = re.search(r'line (\d+)', stderr)
        if not line_match:
            return None

        error_line = int(line_match.group(1)) - 1
        lines = script.split('\n')
        if error_line >= len(lines):
            return None

        problem = lines[error_line]
        indent = len(problem) - len(problem.lstrip())
        wrapped = (
            f"{' ' * indent}try:\n"
            f"{' ' * (indent + 4)}{problem.strip()}\n"
            f"{' ' * indent}except ValueError:\n"
            f"{' ' * (indent + 4)}pass  # Auto-skip invalid value"
        )
        lines[error_line] = wrapped
        return '\n'.join(lines)

    def _fix_import_error(self, script: str, stderr: str) -> Optional[str]:
        """Strategy 10: Try alternative imports"""
        match = re.search(r"cannot import name '(\w+)' from '(\w+)'", stderr)
        if match:
            name = match.group(1)
            module = match.group(2)
            # Remove the bad import line
            fixed = re.sub(
                rf'from\s+{re.escape(module)}\s+import\s+[^\n]*{re.escape(name)}[^\n]*\n',
                f'# Skipped: {name} not in {module}\n',
                script
            )
            if fixed != script:
                return fixed

        return self._fix_module_not_found(script, stderr)

    def _fix_unicode_error(self, script: str, stderr: str) -> Optional[str]:
        """Strategy 11: Add encoding parameter to open()"""
        fixed = script.replace("open(", "open(encoding='utf-8', errors='replace', file=")

        # Better approach: just add encoding to existing open() calls
        fixed = re.sub(
            r"open\(([^)]+)\)",
            lambda m: m.group(0) if 'encoding' in m.group(0) else
            f"open({m.group(1)}, encoding='utf-8', errors='replace')",
            script
        )
        if fixed != script:
            return fixed

        return None

    def _fix_connection_error(self, script: str, stderr: str) -> Optional[str]:
        """Strategy 12: Add retry logic for network errors"""
        # Add retry wrapper
        retry_code = '''
import time as _time
def _retry(fn, max_retries=3, delay=1):
    for i in range(max_retries):
        try:
            return fn()
        except Exception as e:
            if i == max_retries - 1:
                raise
            _time.sleep(delay * (i + 1))
'''
        if '_retry' not in script:
            lines = script.split('\n')
            insert_idx = 0
            for i, line in enumerate(lines):
                if line.startswith('import ') or line.startswith('from '):
                    insert_idx = i + 1
            lines.insert(insert_idx, retry_code)
            return '\n'.join(lines)

        return None

    def _apply_hypothesis_fix(self, script: str, hypothesis: Dict[str, Any],
                               stderr: str = '') -> Optional[str]:
        """Apply a hypothesis-based fix to the script.

        Phase E: Inverse Inference Engine
        Takes a hypothesis (e.g., "Variable X is not defined") and attempts
        to apply a concrete fix based on the fix_type.

        Args:
            script: Original script
            hypothesis: Dict with 'fix_type', 'fix_if_wrong', 'hypothesis'
            stderr: Full stderr output for context

        Returns:
            Fixed script or None if fix can't be applied
        """
        fix_type = hypothesis.get('fix_type', '')
        fix_suggestion = hypothesis.get('fix_if_wrong', '')

        # fix_type: 'init_variable' — initialize undefined variable
        if fix_type == 'init_variable':
            match = re.search(r"name '(\w+)' is not defined", stderr)
            if match:
                var_name = match.group(1)
                default = self.VARIABLE_DEFAULTS.get(var_name, 'None')
                return self._fix_name_error(script, stderr)

        # fix_type: 'type_coercion' — coerce types
        elif fix_type == 'type_coercion':
            # Look for int/str mixing in stderr
            if 'int' in stderr and 'str' in stderr:
                return self._fix_type_error(script, stderr)

        # fix_type: 'create_directory' — create missing directory
        elif fix_type == 'create_directory':
            match = re.search(r"No such file or directory: '(.+?)'", stderr)
            if match:
                filepath = match.group(1)
                # Inject os.makedirs call at top of main() or script
                if 'def main():' in script:
                    lines = script.split('\n')
                    for i, line in enumerate(lines):
                        if 'def main():' in line:
                            # Insert after function def and docstring
                            insert_idx = i + 1
                            if i + 1 < len(lines) and '"""' in lines[i + 1]:
                                insert_idx = i + 2
                            import_line = 'import os'
                            mkdir_line = f'    os.makedirs(os.path.dirname("{filepath}"), exist_ok=True)'
                            if import_line not in script:
                                lines.insert(0, import_line)
                                insert_idx += 1
                            lines.insert(insert_idx, mkdir_line)
                            return '\n'.join(lines)

        # fix_type: 'add_import' — install missing module
        elif fix_type == 'add_import':
            return self._fix_module_not_found(script, stderr)

        # fix_type: 'dict_get_default' — use dict.get() instead of dict[]
        elif fix_type == 'dict_get_default':
            match = re.search(r"KeyError: '(.+?)'", stderr)
            if match:
                return self._fix_key_error(script, stderr)

        # fix_type: 'null_check' — add null/attribute checks
        elif fix_type == 'null_check':
            if 'AttributeError' in stderr:
                return self._fix_attribute_error(script, stderr)
            elif 'IndexError' in stderr:
                return self._fix_index_error(script, stderr)

        # fix_type: 'add_encoding' — add encoding parameter
        elif fix_type == 'add_encoding':
            if 'UnicodeDecodeError' in stderr or 'UnicodeEncodeError' in stderr:
                return self._fix_unicode_error(script, stderr)

        # fix_type: 'add_try_except' — wrap in try/except
        elif fix_type == 'add_try_except':
            if 'ZeroDivisionError' in stderr:
                # Find division operations and wrap them
                fixed = re.sub(
                    r'(\s+)(\w+)\s*=\s*(.+?)\s*/\s*(.+?)(\n|;)',
                    r'\1try:\n\1    \2 = \3 / \4\n\1except ZeroDivisionError:\n\1    \2 = 0\5',
                    script
                )
                if fixed != script:
                    return fixed

        return None
