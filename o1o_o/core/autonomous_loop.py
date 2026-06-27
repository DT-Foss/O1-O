"""Autonomous Self-Repair Loop: Full closed-loop pipeline.

Wires together all Phase 0-6 components into a single autonomous cycle:

  BENCHMARK → DIAGNOSE → SIMULATE → REPAIR → EVALUATE → VALIDATE → LEARN

No human, no LLM, fully offline, fully deterministic.

Safety: max 3 repair cycles per task, then STOP for manual review.
Every fix is regression-tested before acceptance.

Part of FORGE Phase 7: Closed Loop Integration.
"""
# Dependencies: execution_simulator, fix_evaluator, fix_history, fragment_analyzer, fragment_generator, fragment_scorer, meta_optimizer, proactive_detector, self_diagnostics, self_repair
# Depended by: none (leaf module)

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple


class AutonomousLoop:
    """Full autonomous repair cycle for FORGE."""

    MAX_REPAIR_CYCLES = 3
    MAX_TOTAL_REPAIRS = 50  # safety cap per run

    def __init__(self):
        self._init_components()
        self.stats = {
            'tasks_processed': 0,
            'original_passes': 0,
            'repaired_passes': 0,
            'repair_attempts': 0,
            'fixes_applied': 0,
            'fixes_rejected': 0,
            'generated_fragments': 0,
            'cycle_time_ms': 0,
        }

    def _init_components(self):
        """Lazy-initialize all pipeline components."""
        self._diagnostics = None
        self._simulator = None
        self._repair_engine = None
        self._evaluator = None
        self._history = None
        self._analyzer = None
        self._detector = None
        self._optimizer = None
        self._generator = None
        self._scorer = None

    @property
    def diagnostics(self):
        if self._diagnostics is None:
            from o1o_o.core.self_diagnostics import SelfDiagnostics
            self._diagnostics = SelfDiagnostics()
        return self._diagnostics

    @property
    def simulator(self):
        if self._simulator is None:
            from o1o_o.core.execution_simulator import ExecutionSimulator
            self._simulator = ExecutionSimulator()
        return self._simulator

    @property
    def repair_engine(self):
        if self._repair_engine is None:
            from o1o_o.core.self_repair import SelfRepairEngine
            self._repair_engine = SelfRepairEngine()
        return self._repair_engine

    @property
    def evaluator(self):
        if self._evaluator is None:
            from o1o_o.core.fix_evaluator import FixEvaluator
            self._evaluator = FixEvaluator()
        return self._evaluator

    @property
    def history(self):
        if self._history is None:
            from o1o_o.core.fix_history import FixHistory
            self._history = FixHistory()
        return self._history

    @property
    def analyzer(self):
        if self._analyzer is None:
            from o1o_o.core.fragment_analyzer import FragmentAnalyzer
            self._analyzer = FragmentAnalyzer()
            self._analyzer.load_all_fragments()
            self._analyzer.analyze_patterns()
        return self._analyzer

    @property
    def detector(self):
        if self._detector is None:
            from o1o_o.core.proactive_detector import ProactiveDetector
            self._detector = ProactiveDetector()
        return self._detector

    @property
    def optimizer(self):
        if self._optimizer is None:
            from o1o_o.core.meta_optimizer import MetaOptimizer
            self._optimizer = MetaOptimizer()
        return self._optimizer

    @property
    def generator(self):
        if self._generator is None:
            from o1o_o.core.fragment_generator import FragmentGenerator
            self._generator = FragmentGenerator()
        return self._generator

    @property
    def scorer(self):
        if self._scorer is None:
            from o1o_o.core.fragment_scorer import FragmentScorer
            self._scorer = FragmentScorer()
        return self._scorer

    def run(self, benchmark_name: str = 'v2',
            max_tasks: int = 0) -> Dict[str, Any]:
        """Run the full autonomous loop on a benchmark.

        Pipeline per task:
        1. Generate code
        2. Pre-flight: simulate for predicted failures
        3. Pre-fix: apply simulator-suggested fixes
        4. Execute in sandbox
        5. If fail: diagnose → repair loop (max 3 cycles)
        6. Record results + history

        Args:
            benchmark_name: Which benchmark to run (v2, v3, v4, cir)
            max_tasks: Limit tasks (0 = all)

        Returns:
            Stats dict with pass rates and repair metrics
        """
        start_time = time.time()

        # Load benchmark tasks
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tests'))
        from forge_validator import ForgeValidator, UnifiedBenchmarkRunner
        tasks = self._load_tasks(benchmark_name)
        if not tasks:
            return {'error': f'No tasks found for benchmark: {benchmark_name}'}

        if max_tasks > 0:
            tasks = tasks[:max_tasks]

        # Initialize session
        try:
            from o1o import ForgeSession
            session = ForgeSession()
        except Exception as e:
            return {'error': f'Failed to init ForgeSession: {e}'}

        validator = ForgeValidator()
        total_repairs = 0

        print(f"\nFORGE Autonomous Loop — {benchmark_name}")
        print(f"  Tasks: {len(tasks)}, Max repairs/task: {self.MAX_REPAIR_CYCLES}")
        print(f"  Pipeline: Generate → Simulate → Fix → Execute → Diagnose → Repair")
        print()

        results = []
        for task in tasks:
            tid = task.get('id', 0)
            intent_text = task.get('intent', '')
            display = intent_text[:50] + '...' if len(intent_text) > 50 else intent_text
            print(f"  #{tid:3d}: {display}", end='', flush=True)

            self.stats['tasks_processed'] += 1

            # 1. Generate code (full Seed-and-Grow pipeline)
            try:
                script = self._generate_code(session, intent_text)
            except Exception:
                script = None

            if script is None:
                results.append(self._make_result(task, False, 'no_code', 'No code generated'))
                print(f" FAIL (no_code)")
                continue

            # 2. Pre-flight simulation
            sim_result = self.simulator.simulate(script)
            if sim_result.will_fail and sim_result.is_certain:
                # 3. Pre-fix: apply simulator fixes
                for fix_name in sim_result.fixes:
                    fixed = self.repair_engine.attempt_fix(script, fix_name)
                    if fixed and fixed != script:
                        script = fixed
                        total_repairs += 1
                        self.stats['fixes_applied'] += 1
                        break

            # 4. Execute in sandbox
            val_result = validator.validate(script, task, timeout=10)

            if val_result.get('success'):
                results.append(self._make_result(
                    task, True, val_result['method'], ''))
                self.stats['original_passes'] += 1
                print(f" PASS ({val_result['method']})")
                continue

            # 5. Diagnose failure
            error_msg = val_result.get('error', '')
            diagnosis = self.diagnostics.diagnose(
                task_id=tid, error_text=error_msg,
                fragment_keys=list(session.code_assembler.last_used_fragments))

            # 6. Repair loop (max cycles)
            repaired = False
            for cycle in range(self.MAX_REPAIR_CYCLES):
                if total_repairs >= self.MAX_TOTAL_REPAIRS:
                    break

                self.stats['repair_attempts'] += 1

                # Get fix candidates
                candidates = {}
                for fix_name in (diagnosis.fix_strategies if diagnosis else []):
                    fixed = self.repair_engine.attempt_fix(script, fix_name)
                    if fixed and fixed != script:
                        candidates[fix_name] = fixed

                if not candidates:
                    break

                # Evaluate candidates
                best = self.evaluator.best_fix(
                    script, candidates,
                    diagnosis.error_class if diagnosis else '')

                if best is None:
                    break

                # Apply best fix
                script = best.code
                total_repairs += 1

                # Re-execute
                val_result = validator.validate(script, task, timeout=10)

                # Record fix history
                success = val_result.get('success', False)
                self.history.record(
                    error_class=diagnosis.error_class if diagnosis else 'unknown',
                    fix_name=best.name, success=success,
                    task_id=tid, task_intent=intent_text)

                if success:
                    repaired = True
                    self.stats['repaired_passes'] += 1
                    self.stats['fixes_applied'] += 1
                    results.append(self._make_result(
                        task, True, val_result['method'], '',
                        repaired=True, fix=best.name))
                    print(f" PASS (repaired:{best.name})")
                    break
                else:
                    self.stats['fixes_rejected'] += 1
                    # Re-diagnose for next cycle
                    error_msg = val_result.get('error', '')
                    diagnosis = self.diagnostics.diagnose(
                        task_id=tid, error_text=error_msg,
                        fragment_keys=[])

            if not repaired:
                results.append(self._make_result(
                    task, False, val_result.get('method', 'fail'),
                    val_result.get('error', '')))
                print(f" FAIL ({val_result.get('method', 'fail')})")

        # Compute stats
        elapsed = time.time() - start_time
        self.stats['cycle_time_ms'] = round(elapsed * 1000)
        passed = sum(1 for r in results if r['success'])

        print(f"\n{'='*60}")
        print(f"  Result: {passed}/{len(results)} ({100*passed/len(results):.1f}%)")
        print(f"  Original passes: {self.stats['original_passes']}")
        print(f"  Repaired passes: {self.stats['repaired_passes']}")
        print(f"  Repair attempts: {self.stats['repair_attempts']}")
        print(f"  Fixes applied: {self.stats['fixes_applied']}")
        print(f"  Fixes rejected: {self.stats['fixes_rejected']}")
        print(f"  Time: {elapsed:.1f}s")

        # Run meta-optimizer
        print(f"\n  Running meta-optimizer...")
        recs = self.optimizer.generate_recommendations()
        if recs:
            print(f"  Recommendations ({len(recs)}):")
            for r in recs[:5]:
                print(f"    {r}")

        return {
            'results': results,
            'stats': self.stats,
            'recommendations': recs,
        }

    def _generate_code(self, session, intent_text: str) -> Optional[str]:
        """Generate code using full Seed-and-Grow pipeline.

        Mirrors UnifiedBenchmarkRunner._generate_code() logic:
        1. Parse intent + infer chains
        2. Multi-step tasks → Seed-and-Grow incremental build
        3. Fallback: try all chains with standard assembly
        """
        intent = session.intent_parser.parse(intent_text)
        chains = session.knowledge.infer(intent, top_k=3)

        if not chains:
            return None

        # Seed-and-Grow for multi-fragment tasks
        chain = chains[0]
        steps = session.code_assembler.decompose_chain(chain, intent)

        if len(steps) > 1:
            script = self._seed_and_grow(session, steps, intent)
            if script:
                return script

        # Fallback: standard assembly with path exploration
        for chain in chains:
            try:
                script = session.code_assembler.assemble(chain, intent)
                if script and 'No implementation available' not in script:
                    return script
            except Exception:
                continue

        return None

    def _seed_and_grow(self, session, steps: list,
                       intent: dict) -> Optional[str]:
        """Seed-and-Grow: build code incrementally, one fragment at a time.

        SEED: Build first component, test it
        GROW: Add components one at a time, keeping only working additions
        """
        assembler = session.code_assembler
        executor = session.executor

        # SEED: Build first component
        seed_intent = dict(intent)
        seed_intent['requires_output'] = True
        seed_script = assembler.assemble([steps[0]], seed_intent)

        if not seed_script:
            return None

        result = executor.run(seed_script, seed_intent)
        if not result['success']:
            fixed = executor.auto_fix(
                seed_script, result.get('error', ''),
                session.knowledge, stderr=result.get('stderr', ''))
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
                    session.knowledge, stderr=result.get('stderr', ''))
                if fixed:
                    result = executor.run(fixed, intent)
                    if result['success']:
                        current = fixed

        return current

    def _load_tasks(self, benchmark_name: str) -> List[Dict]:
        """Load benchmark tasks by name."""
        task_files = {
            'v2': 'tests/blind_v2_tasks.json',
            'v3': 'tests/blind_v3_tasks.json',
            'v4': 'tests/blind_v4_tasks.json',
            'cir': 'tests/cir_red_tasks.json',
        }

        path = task_files.get(benchmark_name)
        if not path or not os.path.exists(path):
            return []

        with open(path) as f:
            return json.load(f)

    def _make_result(self, task: Dict, success: bool, method: str,
                     error: str, repaired: bool = False,
                     fix: str = '') -> Dict:
        """Create a result dict."""
        return {
            'id': task.get('id', 0),
            'intent': task.get('intent', ''),
            'success': success,
            'method': method,
            'error': error,
            'repaired': repaired,
            'fix': fix,
        }

    def format_stats(self) -> str:
        """Format stats as readable string."""
        s = self.stats
        lines = [
            "Autonomous Loop Statistics",
            "=" * 40,
            f"Tasks processed:   {s['tasks_processed']}",
            f"Original passes:   {s['original_passes']}",
            f"Repaired passes:   {s['repaired_passes']}",
            f"Total passes:      {s['original_passes'] + s['repaired_passes']}",
            f"Repair attempts:   {s['repair_attempts']}",
            f"Fixes applied:     {s['fixes_applied']}",
            f"Fixes rejected:    {s['fixes_rejected']}",
            f"Cycle time:        {s['cycle_time_ms']}ms",
        ]
        total = s['tasks_processed']
        if total > 0:
            rate = (s['original_passes'] + s['repaired_passes']) / total
            lines.append(f"Pass rate:         {rate:.1%}")
        return '\n'.join(lines)
