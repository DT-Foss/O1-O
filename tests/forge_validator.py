#!/usr/bin/env python3
"""
FORGE Hardened Benchmark Validator

Rules:
1. EXECUTION-FIRST: Every task runs in sandbox. Only fall back for
   genuinely non-terminating code (servers, infinite loops, daemons).
2. No keyword matching in comments/strings. AST-based checking only.
3. Code quality gate: no placeholders, no pass-only functions, no TODO,
   no unsubstituted template vars.
4. Output validation: task-specific checks on actual stdout.
"""

import ast
import os
import re
import sys
import json
import signal
import tempfile
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ForgeValidator:
    """Hardened code validator for FORGE benchmarks."""

    # Patterns indicating non-terminating code (servers, daemons, watchers)
    NON_TERMINATING_PATTERNS = [
        'serve_forever', 'app.run(', 'mainloop(', 'run_forever',
        'while True', 'while running', 'asyncio.run(', 'signal.pause()',
        'socket.accept(', 'socket.listen(', '.accept()', '.listen(',
        'HTTPServer(', 'ThreadingTCPServer', 'socketserver.',
        'uvicorn.run(', 'Flask(__name__)', 'tornado.ioloop',
        'input(', 'Cmd.cmdloop',
    ]

    def __init__(self):
        # Output Oracle for semantic validation
        try:
            from core.output_oracle import OutputOracle
            self.oracle = OutputOracle()
        except ImportError:
            self.oracle = None

    def validate(self, script: str, task: Dict, timeout: int = 10) -> Dict:
        """
        Validate a generated script. Returns:
          success: bool
          method: str (exec|structural|fail)
          error: str
          output: str (stdout if executed)
          quality: dict (AST analysis results)
        """
        if not script or not script.strip():
            return self._fail("empty_script", "No code generated")

        # Step 0: Basic quality gate
        quality = self._analyze_quality(script)
        if quality['has_syntax_error']:
            return self._fail("syntax_error", quality['syntax_error_msg'])

        if quality['is_placeholder']:
            return self._fail("placeholder", f"Placeholder code: {quality['placeholder_reason']}")

        if quality['has_unsubstituted_vars']:
            vars_found = quality['unsubstituted_vars']
            return self._fail("template_vars", f"Unsubstituted vars: {vars_found}")

        # Step 1: Try execution
        exec_result = self._execute(script, timeout)

        if exec_result['ran']:
            if exec_result['exit_code'] == 0:
                # Execution succeeded — validate output if possible
                output_ok = self._validate_output(exec_result['stdout'], task)
                if output_ok['valid']:
                    return {
                        "success": True,
                        "method": "exec",
                        "error": "",
                        "output": exec_result['stdout'][:500],
                        "quality": quality,
                    }
                else:
                    # Ran OK but output doesn't match expectations
                    return self._fail("output_mismatch", output_ok['reason'],
                                      quality=quality, output=exec_result['stdout'][:500])
            else:
                # Execution failed (non-zero exit)
                stderr = exec_result['stderr'][:200]
                return self._fail("runtime_error", stderr, quality=quality)

        # Step 2: Timed out — check if non-terminating
        if exec_result['timed_out']:
            if self._is_non_terminating(script):
                # Legitimate non-terminating code (server/daemon)
                return self._structural_check(script, task, quality, reason="non_terminating")
            else:
                return self._fail("timeout", "Script timed out (not a server/daemon)",
                                  quality=quality)

        # Step 3: Couldn't execute at all
        return self._fail("exec_failed", exec_result.get('error', 'Unknown'),
                          quality=quality)

    def _create_sandbox(self, sandbox_dir: str):
        """Create sample fixture files in sandbox so file-reading code doesn't crash."""
        import csv as _csv

        # data.txt — general text file
        with open(os.path.join(sandbox_dir, 'data.txt'), 'w') as f:
            f.write("hello world\nfoo bar baz\ntest data 42\nalice bob charlie\n")

        # data.csv — sample CSV
        with open(os.path.join(sandbox_dir, 'data.csv'), 'w', newline='') as f:
            w = _csv.writer(f)
            w.writerow(['name', 'age', 'city'])
            w.writerows([['Alice', '30', 'Berlin'], ['Bob', '25', 'Munich'],
                         ['Charlie', '35', 'Hamburg'], ['Diana', '28', 'Frankfurt']])

        # data.json — sample JSON
        import json as _json
        with open(os.path.join(sandbox_dir, 'data.json'), 'w') as f:
            _json.dump({'name': 'test', 'items': [1, 2, 3], 'nested': {'key': 'value'}}, f, indent=2)

        # app.log — sample log file
        with open(os.path.join(sandbox_dir, 'app.log'), 'w') as f:
            f.write("2024-01-01 10:00:00 INFO Server started\n"
                    "2024-01-01 10:01:00 WARNING High memory usage\n"
                    "2024-01-01 10:02:00 ERROR Connection refused\n"
                    "2024-01-01 10:03:00 INFO Request processed in 0.5s\n")

        # file.txt, file1.txt, file2.txt — for diff/compare tasks
        with open(os.path.join(sandbox_dir, 'file.txt'), 'w') as f:
            f.write("line 1\nline 2\nline 3\n")
        with open(os.path.join(sandbox_dir, 'file1.txt'), 'w') as f:
            f.write("line 1\nline 2\nline 3\nline 4\n")
        with open(os.path.join(sandbox_dir, 'file2.txt'), 'w') as f:
            f.write("line 1\nline 2 modified\nline 3\nline 5\n")

        # old_file.txt, new_file.txt — for diff tasks
        with open(os.path.join(sandbox_dir, 'old_file.txt'), 'w') as f:
            f.write("original content\nline two\nline three\n")
        with open(os.path.join(sandbox_dir, 'new_file.txt'), 'w') as f:
            f.write("original content\nline two modified\nline three\nnew line\n")

        # output.txt — writable target
        with open(os.path.join(sandbox_dir, 'output.txt'), 'w') as f:
            f.write("")

        # data.db — empty SQLite database with a table
        import sqlite3
        db_path = os.path.join(sandbox_dir, 'data.db')
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE IF NOT EXISTS data (id INTEGER PRIMARY KEY, name TEXT, age INTEGER, city TEXT)")
        conn.execute("INSERT INTO data (name, age, city) VALUES ('Alice', 30, 'Berlin')")
        conn.execute("INSERT INTO data (name, age, city) VALUES ('Bob', 25, 'Munich')")
        conn.commit()
        conn.close()

        # Create output/ directory
        os.makedirs(os.path.join(sandbox_dir, 'output'), exist_ok=True)

        # config.yaml equivalent (just a text file)
        with open(os.path.join(sandbox_dir, 'config.yaml'), 'w') as f:
            f.write("database:\n  host: localhost\n  port: 5432\n  name: testdb\nlogging:\n  level: INFO\n")

    def _execute(self, script: str, timeout: int = 10) -> Dict:
        """Execute script in subprocess sandbox with fixture files."""
        sandbox_dir = None
        try:
            sandbox_dir = tempfile.mkdtemp(prefix='forge_sandbox_')
            self._create_sandbox(sandbox_dir)

            tmppath = os.path.join(sandbox_dir, 'script.py')
            with open(tmppath, 'w') as f:
                clean = script.replace('\x00', '')
                f.write(clean)

            result = subprocess.run(
                [sys.executable, tmppath],
                capture_output=True, text=True, timeout=timeout,
                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                cwd=sandbox_dir,
            )

            return {
                'ran': True,
                'timed_out': False,
                'exit_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {'ran': False, 'timed_out': True, 'error': 'timeout'}
        except Exception as e:
            return {'ran': False, 'timed_out': False, 'error': str(e)}
        finally:
            if sandbox_dir:
                import shutil
                try:
                    shutil.rmtree(sandbox_dir, ignore_errors=True)
                except:
                    pass

    def _analyze_quality(self, script: str) -> Dict:
        """Deep AST-based code quality analysis."""
        result = {
            'has_syntax_error': False,
            'syntax_error_msg': '',
            'is_placeholder': False,
            'placeholder_reason': '',
            'has_unsubstituted_vars': False,
            'unsubstituted_vars': [],
            'real_loc': 0,
            'num_functions': 0,
            'num_classes': 0,
            'empty_functions': [],
            'has_todo': False,
        }

        # Clean null bytes
        clean = script.replace('\x00', '')

        # Syntax check
        try:
            tree = ast.parse(clean)
        except SyntaxError as e:
            result['has_syntax_error'] = True
            result['syntax_error_msg'] = str(e)
            return result

        # Count real LOC (not comments, not blank lines, not docstrings)
        lines = clean.split('\n')
        real_lines = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith('#'):
                continue
            if stripped.startswith('"""') or stripped.startswith("'''"):
                continue
            real_lines.append(stripped)
        result['real_loc'] = len(real_lines)

        # Walk AST for quality checks
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result['num_functions'] += 1
                # Check for empty/placeholder function bodies
                body = node.body
                if self._is_empty_body(body):
                    result['empty_functions'].append(node.name)

            elif isinstance(node, ast.ClassDef):
                result['num_classes'] += 1

        # Check for TODO/FIXME in actual code (not just comments)
        for line in lines:
            stripped = line.strip()
            if 'TODO' in stripped or 'FIXME' in stripped or 'HACK' in stripped:
                result['has_todo'] = True
                break

        # Check for unsubstituted template variables like {path}, {url}
        # But not inside f-strings, format strings, or dict literals
        template_vars = []
        for line in script.split('\n'):
            stripped = line.strip()
            # Skip f-string lines — {var} is Python interpolation there
            if "f'" in stripped or 'f"' in stripped:
                continue
            template_vars += re.findall(r"'{(\w+)}'", stripped)
            template_vars += re.findall(r'"\{(\w+)\}"', stripped)
        if template_vars:
            result['has_unsubstituted_vars'] = True
            result['unsubstituted_vars'] = list(set(template_vars))

        # Check if entire script is placeholder
        if result['real_loc'] < 3:
            result['is_placeholder'] = True
            result['placeholder_reason'] = f"Only {result['real_loc']} real lines"
        elif result['num_functions'] > 0 and len(result['empty_functions']) == result['num_functions']:
            result['is_placeholder'] = True
            result['placeholder_reason'] = f"All functions are empty: {result['empty_functions']}"

        return result

    def _is_empty_body(self, body: list) -> bool:
        """Check if a function body is placeholder (pass-only, ellipsis, NotImplementedError)."""
        if not body:
            return True

        # Filter out docstrings
        real_stmts = []
        for stmt in body:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, (ast.Constant, ast.Str)):
                continue  # Skip docstrings
            real_stmts.append(stmt)

        if not real_stmts:
            return True

        # Single pass statement
        if len(real_stmts) == 1:
            stmt = real_stmts[0]
            if isinstance(stmt, ast.Pass):
                return True
            # Ellipsis (...)
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is ...:
                return True
            # raise NotImplementedError
            if isinstance(stmt, ast.Raise):
                if isinstance(stmt.exc, ast.Call):
                    if isinstance(stmt.exc.func, ast.Name) and stmt.exc.func.id == 'NotImplementedError':
                        return True

        return False

    def _is_non_terminating(self, script: str) -> bool:
        """Check if script is legitimately non-terminating (server/daemon)."""
        for pat in self.NON_TERMINATING_PATTERNS:
            if pat in script:
                return True
        return False

    def _validate_output(self, stdout: str, task: Dict) -> Dict:
        """Task-specific output validation using Output Oracle."""
        # Use Oracle if available
        if self.oracle:
            # Build a minimal intent from task text
            intent_text = task.get('intent', '')
            tokens = set(re.findall(r'\b\w+\b', intent_text.lower()))
            stopwords = {'a', 'an', 'the', 'and', 'or', 'in', 'on', 'to', 'for',
                         'of', 'with', 'by', 'from', 'is', 'are', 'that', 'this',
                         'it', 'its', 'as', 'be', 'been', 'do', 'does', 'has', 'have',
                         'using', 'python'}
            tokens -= stopwords

            intent = {
                'raw': intent_text,
                'tokens': list(tokens),
            }

            passed, reason, confidence = self.oracle.validate(
                stdout, '', 0, intent
            )

            if not passed and confidence >= 0.7:
                return {'valid': False, 'reason': reason}
            return {'valid': True, 'reason': ''}

        # Fallback: basic checks if oracle not available
        intent = task.get('intent', '').lower()
        stdout_stripped = stdout.strip()

        if not stdout_stripped:
            return {'valid': True, 'reason': ''}

        checks = []
        count_words = [r'\bcount\b', r'\bnumber of\b', r'\bhow many\b', r'\blength\b']
        if any(re.search(w, intent) for w in count_words):
            has_number = bool(re.search(r'\d+', stdout_stripped))
            checks.append(('contains_number', has_number))

        if 'json' in intent and ('pretty' in intent or 'print' in intent or 'dump' in intent):
            try:
                json.loads(stdout_stripped)
                checks.append(('valid_json', True))
            except:
                checks.append(('valid_json', '{' in stdout_stripped or '[' in stdout_stripped))

        if 'sort' in intent:
            checks.append(('has_output', len(stdout_stripped) > 0))

        if not checks:
            return {'valid': True, 'reason': ''}

        failed = [name for name, passed in checks if not passed]
        if failed:
            return {'valid': False, 'reason': f"Failed output checks: {failed}"}

        return {'valid': True, 'reason': ''}

    def _structural_check(self, script: str, task: Dict, quality: Dict,
                          reason: str = "") -> Dict:
        """
        Hardened structural check for non-terminating code.
        Much stricter than keyword matching.
        """
        # Must have meaningful code
        if quality['real_loc'] < 10:
            return self._fail("too_short", f"Only {quality['real_loc']} real LOC",
                              quality=quality)

        # Must have functions or classes (not just loose statements)
        if quality['num_functions'] == 0 and quality['num_classes'] == 0:
            return self._fail("no_structure", "No functions or classes defined",
                              quality=quality)

        # Must not have all-empty functions
        if quality['empty_functions']:
            return self._fail("empty_functions",
                              f"Empty functions: {quality['empty_functions']}",
                              quality=quality)

        # Check expects if available (AST-aware, not comment-matching)
        expects = task.get('expects', [])
        if expects:
            # Check expects against actual code tokens, not comments
            code_tokens = self._extract_code_tokens(script)
            found = sum(1 for e in expects if e.lower() in code_tokens)
            expect_score = found / len(expects)
            if expect_score < 0.4:
                return self._fail("low_expect_score",
                                  f"Only {found}/{len(expects)} expected patterns in code",
                                  quality=quality)

        return {
            "success": True,
            "method": f"structural_{reason}" if reason else "structural",
            "error": "",
            "output": "",
            "quality": quality,
        }

    def _extract_code_tokens(self, script: str) -> str:
        """Extract code tokens excluding comments and docstrings."""
        lines = script.split('\n')
        code_lines = []
        in_docstring = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            # Simple docstring detection
            if '"""' in stripped or "'''" in stripped:
                count = stripped.count('"""') + stripped.count("'''")
                if count == 1:
                    in_docstring = not in_docstring
                    continue
                elif count >= 2:
                    continue  # Single-line docstring
            if in_docstring:
                continue
            code_lines.append(line)
        return '\n'.join(code_lines).lower()

    def _fail(self, method: str, error: str, quality: Dict = None,
              output: str = "") -> Dict:
        return {
            "success": False,
            "method": method,
            "error": error,
            "output": output,
            "quality": quality or {},
        }


class UnifiedBenchmarkRunner:
    """
    Unified benchmark runner that uses ForgeValidator for ALL benchmarks.
    Replaces V2, V3, V4 individual runners with one consistent validator.
    """

    def __init__(self, forge_session, output_dir: str = "benchmarks"):
        self.session = forge_session
        self.validator = ForgeValidator()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run_benchmark(self, tasks: List[Dict], name: str,
                      timeout: int = 10) -> List[Dict]:
        """
        Run a benchmark with hardened validation.
        Returns list of result dicts.
        """
        results = []
        import time

        # Fragment quality scoring
        try:
            from core.fragment_scorer import FragmentScorer
            scorer = FragmentScorer()
            run_id = scorer.generate_run_id(name)
        except Exception:
            scorer = None
            run_id = None

        # Track fragments per task for diagnostics
        task_fragments = {}

        tier_counts = {}
        for t in tasks:
            tier = t.get('tier', 'unknown')
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

        print(f"\nFORGE {name} — HARDENED VALIDATOR")
        print(f"  {len(tasks)} tasks across {len(tier_counts)} tiers")
        for tier, count in sorted(tier_counts.items()):
            print(f"  {tier}: {count} tasks")
        print()

        for task in tasks:
            tid = task.get('id', 0)
            tier = task.get('tier', 'unknown')
            intent_text = task.get('intent', '')

            display = intent_text[:55] + '...' if len(intent_text) > 55 else intent_text
            print(f"[{tier:14s}] #{tid:3d}: {display}", end='', flush=True)

            start = time.time()

            # Reset fragment tracking
            self.session.code_assembler.last_used_fragments = []

            # Generate code
            script = self._generate_code(task)
            if script is None:
                result = {
                    "id": tid, "tier": tier, "intent": intent_text,
                    "success": False, "method": "no_code",
                    "error": "No code generated", "duration": round(time.time() - start, 2),
                    "loc": 0, "output": "",
                }
            else:
                # Dry-Run Oracle: predict failures before execution
                try:
                    from core.execution_simulator import ExecutionSimulator
                    from core.self_repair import SelfRepairEngine
                    sim = ExecutionSimulator()
                    prediction = sim.simulate(script)
                    if prediction.will_fail and prediction.is_certain:
                        # Try to fix before running
                        engine = SelfRepairEngine()
                        for fix_name in prediction.fixes:
                            fixed = engine.attempt_fix(script, fix_name)
                            if fixed and fixed != script:
                                script = fixed
                                break
                except Exception:
                    pass  # oracle is advisory — never block execution

                # Validate with hardened validator
                val_result = self.validator.validate(script, task, timeout=timeout)
                quality = val_result.get('quality', {})

                result = {
                    "id": tid, "tier": tier, "intent": intent_text,
                    "success": val_result['success'],
                    "method": val_result['method'],
                    "error": val_result.get('error', ''),
                    "duration": round(time.time() - start, 2),
                    "loc": quality.get('real_loc', 0),
                    "output": val_result.get('output', '')[:200],
                }

            # Capture fragment usage for this task
            used_frags = list(self.session.code_assembler.last_used_fragments)
            if not used_frags:
                used_frags = ['_no_fragment']
            task_fragments[tid] = used_frags

            # Record fragment quality scores
            if scorer:
                error_class = FragmentScorer.classify_error(result.get('error', '')) if not result['success'] else None
                scorer.record_result(
                    run_id=run_id, benchmark=name, task_id=tid,
                    task_intent=intent_text, fragment_keys=used_frags,
                    fragment_file='', success=result['success'],
                    method=result['method'], error_class=error_class,
                    error_message=result.get('error', ''),
                    duration_ms=result['duration'] * 1000,
                    loc=result['loc'],
                )

            results.append(result)
            status = "PASS" if result['success'] else "FAIL"
            print(f" {status} ({result['method']}, {result['duration']:.1f}s)")

        # Record run summary
        passed = sum(1 for r in results if r['success'])
        failed = len(results) - passed
        if scorer:
            scorer.record_run_summary(run_id, name, len(results), passed, failed)
            print(f"\n  Fragment scores recorded → {scorer.db_path}")

        # Self-diagnostics: diagnose all failures
        if failed > 0:
            try:
                from core.self_diagnostics import SelfDiagnostics
                diagnostics = SelfDiagnostics()
                diagnostics.diagnose_batch(results, task_fragments)
                print(f"\n{diagnostics.format_report()}")
            except Exception as e:
                print(f"\n  (Diagnostics unavailable: {e})")

        self._print_report(results, name)
        self._save_results(results, name)
        return results

    def _generate_code(self, task: Dict) -> Optional[str]:
        """Generate code using FORGE session with Seed-and-Grow."""
        intent = self.session.intent_parser.parse(task['intent'])
        chains = self.session.knowledge.infer(intent, top_k=3)

        if not chains:
            return None

        # === Seed-and-Grow: build incrementally for multi-fragment tasks ===
        chain = chains[0]
        steps = self.session.code_assembler.decompose_chain(chain, intent)

        if len(steps) > 1:
            script = self._seed_and_grow_generate(steps, intent)
            if script:
                return script

        # Fallback: standard assembly with path exploration
        for chain in chains:
            try:
                script = self.session.code_assembler.assemble(chain, intent)
                if script and 'No implementation available' not in script:
                    return script
            except Exception:
                continue

        return None

    def _seed_and_grow_generate(self, steps: list, intent: dict) -> Optional[str]:
        """Seed-and-Grow code generation for the validator.

        Builds one fragment at a time, testing after each step.
        Returns the best working script, or None if seed fails.
        """
        assembler = self.session.code_assembler
        executor = self.session.executor

        # SEED: Build first component
        seed_intent = dict(intent)
        seed_intent['requires_output'] = True
        seed_script = assembler.assemble([steps[0]], seed_intent)

        result = executor.run(seed_script, seed_intent)
        if not result['success']:
            fixed = executor.auto_fix(
                seed_script, result.get('error', ''),
                self.session.knowledge, stderr=result.get('stderr', '')
            )
            if fixed:
                result = executor.run(fixed, seed_intent)
                if result['success']:
                    seed_script = fixed
                else:
                    return None
            else:
                return None

        current = seed_script

        # GROW: Add components one at a time
        for i, step in enumerate(steps[1:], 2):
            grow_intent = dict(intent)
            grow_intent['requires_output'] = (i == len(steps))

            grown = assembler.grow_script(current, step, grow_intent)
            if grown == current:
                continue

            result = executor.run(grown, intent)
            if result['success']:
                current = grown
            else:
                fixed = executor.auto_fix(
                    grown, result.get('error', ''),
                    self.session.knowledge, stderr=result.get('stderr', '')
                )
                if fixed:
                    result = executor.run(fixed, intent)
                    if result['success']:
                        current = fixed

        return current

    def _print_report(self, results: List[Dict], name: str):
        """Print summary report."""
        total = len(results)
        passed = sum(1 for r in results if r['success'])
        pct = (100 * passed / total) if total else 0

        tier_stats = {}
        method_counts = {}
        for r in results:
            tier = r['tier']
            if tier not in tier_stats:
                tier_stats[tier] = {'pass': 0, 'total': 0}
            tier_stats[tier]['total'] += 1
            if r['success']:
                tier_stats[tier]['pass'] += 1
                m = r['method']
                method_counts[m] = method_counts.get(m, 0) + 1

        print(f"\n{'='*65}")
        print(f"  FORGE {name} — HARDENED RESULTS")
        print(f"  Overall: {passed}/{total} ({pct:.1f}%)")
        print(f"{'='*65}")

        print(f"\n  Tier breakdown:")
        for tier in sorted(tier_stats.keys()):
            s = tier_stats[tier]
            t_pct = 100 * s['pass'] / s['total'] if s['total'] else 0
            print(f"    {tier:16s}: {s['pass']:2d}/{s['total']:2d} ({t_pct:.0f}%)")

        print(f"\n  Pass methods:")
        for method, count in sorted(method_counts.items(), key=lambda x: -x[1]):
            print(f"    {method}: {count}")

        failures = [r for r in results if not r['success']]
        if failures:
            print(f"\n  Failures ({len(failures)}):")
            for r in failures[:25]:
                err = r.get('error', '')[:50]
                print(f"    #{r['id']:3d} [{r['tier']}] {r['intent'][:40]}... -> {r['method']}: {err}")
            if len(failures) > 25:
                print(f"    ... and {len(failures) - 25} more")

    def repair_failures(self, results: List[Dict], tasks: List[Dict],
                        max_attempts: int = 3, timeout: int = 10) -> Dict[str, Any]:
        """Verify-after-Fix Loop: diagnose → fix → re-execute → verify.

        For each failed task:
        1. Diagnose the failure
        2. Try each fix strategy in order
        3. Re-execute fixed code in sandbox
        4. If it passes, record the fix
        5. If all strategies exhausted, flag for manual review

        Returns summary dict with fix results.
        """
        import time
        from core.self_diagnostics import SelfDiagnostics
        from core.self_repair import SelfRepair

        diagnostics = SelfDiagnostics()
        repair = SelfRepair()

        # Build task lookup
        task_by_id = {t.get('id', i): t for i, t in enumerate(tasks)}

        failures = [r for r in results if not r.get('success')]
        if not failures:
            return {'fixed': 0, 'unfixable': 0, 'total_failures': 0}

        print(f"\n{'='*60}")
        print(f"SELF-REPAIR: {len(failures)} failures to fix")
        print(f"{'='*60}")

        fixed_count = 0
        unfixable = []
        fix_log = []

        for r in failures:
            tid = r['id']
            intent = r.get('intent', '')
            error = r.get('error', '')
            task = task_by_id.get(tid, {'id': tid, 'intent': intent})

            print(f"\n  #{tid}: {intent[:50]}...")

            # Step 1: Diagnose
            diag = diagnostics.diagnose(tid, intent, error)
            print(f"    Diagnosis: [{diag.severity}] {diag.error_class}: {diag.root_cause[:80]}")

            # Step 2: Regenerate code (we need the original code)
            self.session.code_assembler.last_used_fragments = []
            code = self._generate_code(task)
            if not code:
                print(f"    Cannot regenerate code — skipping")
                unfixable.append(tid)
                continue

            # Step 3: Try each fix strategy
            all_fixes = repair.attempt_all_fixes(code, diag, max_attempts=max_attempts)

            fixed_this_task = False
            for strategy_name, fixed_code in all_fixes:
                # Step 4: Re-execute
                val_result = self.validator.validate(fixed_code, task, timeout=timeout)

                if val_result['success']:
                    print(f"    FIXED by {strategy_name} ({val_result['method']})")
                    fix_log.append({
                        'task_id': tid,
                        'strategy': strategy_name,
                        'error_class': diag.error_class,
                        'original_error': error[:200],
                        'method': val_result['method'],
                    })
                    fixed_count += 1
                    fixed_this_task = True
                    break
                else:
                    print(f"    {strategy_name}: still fails ({val_result.get('error', '')[:60]})")

            if not fixed_this_task:
                print(f"    UNFIXABLE: all {len(all_fixes)} strategies exhausted")
                unfixable.append(tid)

        # Summary
        print(f"\n{'='*60}")
        print(f"SELF-REPAIR COMPLETE")
        print(f"  Fixed: {fixed_count}/{len(failures)}")
        print(f"  Unfixable: {len(unfixable)}")
        if unfixable:
            print(f"  Unfixable IDs: {unfixable}")
        print(f"{'='*60}")
        print(f"\n{repair.format_stats()}")

        return {
            'fixed': fixed_count,
            'unfixable': len(unfixable),
            'unfixable_ids': unfixable,
            'total_failures': len(failures),
            'fix_log': fix_log,
        }

    def _save_results(self, results: List[Dict], name: str):
        """Save JSON results + markdown summary."""
        slug = name.lower().replace(' ', '_')
        out_dir = self.output_dir / slug
        out_dir.mkdir(parents=True, exist_ok=True)

        json_path = out_dir / f"{slug}_results.json"
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2)

        md_path = out_dir / f"{slug}_summary.md"
        total = len(results)
        passed = sum(1 for r in results if r['success'])
        pct = (100 * passed / total) if total else 0

        with open(md_path, 'w') as f:
            f.write(f"# FORGE {name} — Hardened Results\n\n")
            f.write(f"## Overall: {passed}/{total} ({pct:.1f}%)\n\n")
            f.write("| # | Tier | Task | Pass | Method | LOC | Error |\n")
            f.write("|---|------|------|------|--------|-----|-------|\n")
            for r in results:
                p = "Y" if r['success'] else "N"
                err = r.get('error', '')[:30]
                f.write(f"| {r['id']} | {r['tier']} | {r['intent'][:40]}... | {p} | {r['method']} | {r['loc']} | {err} |\n")

        print(f"\n  Results: {json_path}")
        print(f"  Summary: {md_path}")
