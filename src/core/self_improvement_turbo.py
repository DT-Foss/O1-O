"""
Self-Improvement Turbo Loop — FORGE learns autonomously

Runs 1000+ cycles/hour:
1. Pick random V3 task
2. Generate code (using Phase G architecture engine + role-matched fragments)
3. Execute + validate (Output Oracle)
4. Learn from success/failure (Failure Memory + Auto Harvester)
5. Record metrics + repeat

This is where all infrastructure (Phases A-F) comes together.
"""
# Dependencies: monte_carlo_ranker
# Depended by: none (leaf module)


import random
import time
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
import json
from core.monte_carlo_ranker import MonteCarloRanker


class TurboMetricsCollector:
    """Real-time metrics collection for turbo loop."""

    def __init__(self, num_tasks: int = 104):
        self.cycles = []
        self.start_time = None
        self.current_score = 0
        self.baseline_score = 0
        self.successes = 0
        self.failures = 0
        self.num_tasks = num_tasks
        self.solved_tasks = set()  # Track UNIQUE tasks that passed

    def start(self, baseline_score: int):
        """Initialize metrics with baseline."""
        self.start_time = time.time()
        self.baseline_score = baseline_score
        self.current_score = baseline_score

    def _apply_validation_gates(self, result: Dict[str, Any], verification: Dict[str, Any]) -> bool:
        """Apply STRICT validation gates — all must pass for real success.

        Gates:
        1. Execution success (returncode == 0)
        2. Formal verifier passed (is_proven=True)
        3. No stderr errors
        4. Non-empty output
        """
        # Gate 1: Execution success
        if not result.get('success', False):
            return False

        # Gate 2: Formal verifier must pass
        if verification and not verification.get('is_proven', False):
            return False

        # Gate 3: No stderr errors
        if result.get('stderr', '').strip():
            return False

        # Gate 4: Non-empty output (not just "OK" or whitespace)
        output = result.get('stdout', '').strip()
        if not output or output in ['OK', 'ok', 'Done', 'done', '', 'None']:
            return False

        return True

    def record_cycle(self, cycle_num: int, task: str, result: Dict[str, Any], verification: Dict[str, Any] = None):
        """Record outcome of a single cycle with HONEST validation."""
        # Apply strict validation gates
        honest_success = self._apply_validation_gates(result, verification) if verification else result.get('success', False)
        error_type = result.get('error', 'UNKNOWN')

        cycle_data = {
            'cycle': cycle_num,
            'timestamp': datetime.now().isoformat(),
            'task': task[:80],
            'success': honest_success,  # HONEST success, not inflated
            'error_type': error_type,
            'stderr': result.get('stderr', '')[:200],
            'stdout_length': len(result.get('stdout', '')),
            'verified': verification.get('is_proven', False) if verification else False,
        }
        self.cycles.append(cycle_data)

        if honest_success:
            self.successes += 1
            self.solved_tasks.add(task[:80])  # Track unique solved tasks
        else:
            self.failures += 1

        # Score = unique tasks solved (max = num_tasks)
        self.current_score = len(self.solved_tasks)

    def get_summary(self) -> Dict[str, Any]:
        """Get current metrics summary."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        cycles_per_hour = (len(self.cycles) / elapsed * 3600) if elapsed > 0 else 0

        return {
            'total_cycles': len(self.cycles),
            'successes': self.successes,
            'failures': self.failures,
            'success_rate': self.successes / max(1, len(self.cycles)),
            'current_score': self.current_score,
            'baseline_score': self.baseline_score,
            'improvement': self.current_score - self.baseline_score,
            'improvement_pct': ((self.current_score - self.baseline_score) / max(1, self.baseline_score) * 100),
            'elapsed_seconds': elapsed,
            'cycles_per_hour': cycles_per_hour,
            'num_tasks': self.num_tasks,
        }

    def print_progress(self, verbose: bool = True):
        """Print progress summary."""
        if not verbose:
            return

        summary = self.get_summary()
        print(f"\n📊 Turbo Cycle #{summary['total_cycles']}")
        print(f"   Unique tasks solved: {summary['current_score']}/{summary['num_tasks']}")
        print(f"   Cycle success rate: {summary['success_rate']*100:.1f}% ({summary['successes']}/{summary['total_cycles']})")
        print(f"   Speed: {summary['cycles_per_hour']:.0f} cycles/hour")


class SelfImprovementTurbo:
    """Autonomous self-improvement loop — 1000+ cycles/hour."""

    def __init__(self, forge_session, v3_tasks: List[str], use_monte_carlo: bool = True):
        """
        Args:
            forge_session: ForgeSession instance
            v3_tasks: List of V3 "impossible" tasks to learn from
            use_monte_carlo: Enable parallel candidate ranking (default: True)
        """
        self.session = forge_session
        self.tasks = v3_tasks
        self.executor = forge_session.executor
        self.learning = forge_session.learning
        self.failure_memory = getattr(forge_session, 'failure_memory', None)
        self.metrics = TurboMetricsCollector(num_tasks=len(v3_tasks))

        # Monte Carlo ranker (parallel candidate generation + ranking)
        self.use_monte_carlo = use_monte_carlo
        if use_monte_carlo:
            self.mc_ranker = MonteCarloRanker(
                self.executor,
                forge_session.code_assembler,
                forge_session.knowledge
            )

        # Track learned patterns
        self.learned_patterns = set()
        self.failed_patterns = set()
        self.mc_scores = []  # Track Monte Carlo rankings

    def run(self, num_cycles: int = 1000, print_every: int = 50, verbose: bool = True) -> Dict[str, Any]:
        """
        Run autonomous self-improvement loop.

        Args:
            num_cycles: Number of cycles to run
            print_every: Print progress every N cycles
            verbose: Enable progress printing

        Returns:
            Summary dict with metrics
        """
        # Calculate baseline: how many V3 tasks currently pass
        baseline = self._get_baseline()
        print(f"🚀 Starting Turbo Loop (baseline: {baseline}/{len(self.tasks)})")

        self.metrics.start(baseline)

        # Main loop
        for cycle in range(1, num_cycles + 1):
            # Pick random task
            task = random.choice(self.tasks)

            # Generate code
            intent = self.session.intent_parser.parse(task)
            code = self._generate_code(intent)

            if not code:
                # Generation failed
                self.metrics.record_cycle(cycle, task, {'success': False, 'error': 'GENERATION_FAILED'})
                continue

            # Execute + validate
            result = self.executor.run(code, intent)

            # Formal verification (required for honest success metrics)
            verification = self.session.formal_verifier.verify(code, intent)

            # Learn ONLY from honest successes (after validation gates)
            honest_success = self.metrics._apply_validation_gates(result, verification)
            if honest_success:
                self._learn_from_success(task, code, result)
            else:
                self._learn_from_failure(task, code, result)

            # Record metrics with HONEST validation gates
            self.metrics.record_cycle(cycle, task, result, verification)

            # Progress reporting + periodic learning save
            if verbose and cycle % print_every == 0:
                self.metrics.print_progress(verbose=True)
                # Periodically save learned triplets so we see progress
                self.learning.save_learned()

        # Final summary
        return self._generate_report()

    def _get_baseline(self) -> int:
        """Get current baseline score (how many tasks pass with HONEST validation)."""
        # Quick baseline: test first 5 tasks with strict validation gates
        passing = 0
        for task in self.tasks[:5]:
            intent = self.session.intent_parser.parse(task)
            code = self._generate_code(intent)
            if code:
                result = self.executor.run(code, intent)
                verification = self.session.formal_verifier.verify(code, intent)
                # Apply STRICT validation gates
                if self.metrics._apply_validation_gates(result, verification):
                    passing += 1
        # Extrapolate to total tasks (104 offensive security tasks)
        baseline = int((passing / 5) * len(self.tasks))
        # For new tasks, use actual baseline (no artificial minimum)
        # Only apply minimum if we have prior data
        if passing == 0:
            return 0  # New tasks, no prior performance data
        return baseline

    def _generate_code(self, intent: Dict[str, Any]) -> Optional[str]:
        """Generate code using Phase G architecture engine + Monte Carlo ranking."""
        # Monte Carlo: Generate multiple candidates and rank them
        if self.use_monte_carlo:
            try:
                candidates = self.mc_ranker.generate_candidates(intent)
                if candidates:
                    best_code, best_score, _ = self.mc_ranker.rank_candidates(candidates, intent, timeout=5)
                    self.mc_scores.append(best_score)
                    if best_code and 'No implementation' not in best_code:
                        return best_code
            except Exception:
                # MC failed, continue to fallback paths
                pass

        # Fallback: Original architecture-aware assembly
        try:
            candidate_chains = self.session.knowledge.infer(intent, top_k=3)
            if not candidate_chains:
                return None

            # Try assemble_v4 first (component-role semantic matching)
            script = self.session.code_assembler.assemble_v4_architecture_aware(intent)
            if script and 'No implementation' not in script:
                return script

            # Fallback to v3 assembly
            script = self.session.code_assembler.assemble(candidate_chains[0], intent)
            return script if script and 'No implementation' not in script else None

        except Exception:
            return None

    def _learn_from_success(self, task: str, code: str, result: Dict[str, Any]):
        """Learn from successful code generation."""
        # Record in learning system
        intent = self.session.intent_parser.parse(task)
        chains = self.session.knowledge.infer(intent, top_k=1)
        if chains:
            self.learning.learn_from_success(intent, chains[0], code)

        # Track learned pattern
        pattern_hash = hash(code[:100])
        self.learned_patterns.add(pattern_hash)

        # Try to harvest new knowledge (if output oracle exists and approves)
        output_oracle = getattr(self.session, 'output_oracle', None)
        if output_oracle and output_oracle.validate(code, result['stdout'], intent):
            # Maybe add to harvester queue
            pass

    def _learn_from_failure(self, task: str, code: str, result: Dict[str, Any]):
        """Learn from failed code generation."""
        error_type = result.get('error', 'UNKNOWN_ERROR')
        stderr = result.get('stderr', '')

        # Record failure pattern
        pattern_hash = hash(code[:100])
        self.failed_patterns.add(pattern_hash)

        # Generate hypotheses via Failure Memory
        if self.failure_memory:
            hypotheses = self.failure_memory.generate_hypotheses(error_type, stderr)
            # Record failure + hypotheses
            self.failure_memory.record_failure(
                task, code, result,
                hypotheses=[h.get('hypothesis', '') for h in hypotheses[:3]]
            )

    def _generate_report(self) -> Dict[str, Any]:
        """Generate final turbo loop report."""
        summary = self.metrics.get_summary()

        # Monte Carlo stats
        mc_stats = {}
        if self.use_monte_carlo and self.mc_scores:
            mc_stats = {
                'monte_carlo_enabled': True,
                'mc_avg_score': sum(self.mc_scores) / len(self.mc_scores),
                'mc_max_score': max(self.mc_scores),
                'mc_high_quality': sum(1 for s in self.mc_scores if s >= 10),  # Success cases
            }

        report = {
            'turbo_complete': True,
            'total_cycles': summary['total_cycles'],
            'baseline_score': summary['baseline_score'],
            'final_score': summary['current_score'],
            'improvement': summary['improvement'],
            'improvement_pct': summary['improvement_pct'],
            'success_rate': summary['success_rate'],
            'cycles_per_hour': summary['cycles_per_hour'],
            'elapsed_seconds': summary['elapsed_seconds'],
            'learned_patterns': len(self.learned_patterns),
            'failed_patterns': len(self.failed_patterns),
            'metrics_history': self.metrics.cycles[-50:],  # Last 50 cycles for inspection
            **mc_stats,  # Include Monte Carlo stats
        }

        return report
