#!/usr/bin/env python3
"""
Profile Turbo Loop — Identify performance bottlenecks
Measures time breakdown for each cycle component
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, List
import cProfile
import pstats
from io import StringIO

# Setup paths
sys.path.insert(0, str(Path(__file__).parent))

from o1o import ForgeSession
from o1o_o.core.self_improvement_turbo import SelfImprovementTurbo

# Timing tracker
class TimingTracker:
    def __init__(self):
        self.times: Dict[str, List[float]] = {}

    def record(self, operation: str, elapsed: float):
        if operation not in self.times:
            self.times[operation] = []
        self.times[operation].append(elapsed)

    def summary(self):
        print(f"\n{'='*60}")
        print(f"⏱️  PERFORMANCE PROFILING SUMMARY")
        print(f"{'='*60}")

        for op in sorted(self.times.keys(), key=lambda x: sum(self.times[x]), reverse=True):
            times = self.times[op]
            total = sum(times)
            avg = total / len(times)
            min_t = min(times)
            max_t = max(times)

            print(f"\n{op}:")
            print(f"  Total:   {total:.2f}s ({len(times)} calls)")
            print(f"  Avg:     {avg:.4f}s/call")
            print(f"  Min/Max: {min_t:.4f}s / {max_t:.4f}s")

        total_time = sum(sum(v) for v in self.times.values())
        print(f"\n{'='*60}")
        print(f"Total profiled time: {total_time:.2f}s")
        print(f"{'='*60}\n")


# Instrumented turbo loop
class ProfiledTurbo(SelfImprovementTurbo):
    def __init__(self, forge_session, v3_tasks: List[str], tracker: TimingTracker):
        super().__init__(forge_session, v3_tasks)
        self.tracker = tracker

    def run(self, num_cycles: int = 100, print_every: int = 25, verbose: bool = True):
        """Run with timing instrumentation"""
        baseline = self._get_baseline()
        print(f"🚀 Starting Profiled Turbo Loop (baseline: {baseline}/50)")
        self.metrics.start(baseline)

        for cycle in range(1, num_cycles + 1):
            # Pick task
            import random
            task = random.choice(self.tasks)

            # Parse intent
            t0 = time.time()
            intent = self.session.intent_parser.parse(task)
            self.tracker.record("intent_parser.parse", time.time() - t0)

            # Generate code (includes architecture decomposition)
            t0 = time.time()
            code = self._generate_code(intent)
            self.tracker.record("code_generation", time.time() - t0)

            if not code:
                self.metrics.record_cycle(cycle, task, {'success': False, 'error': 'GENERATION_FAILED'})
                continue

            # Execute
            t0 = time.time()
            result = self.executor.run(code, intent)
            self.tracker.record("executor.run", time.time() - t0)

            # Learn
            t0 = time.time()
            if result['success']:
                self._learn_from_success(task, code, result)
            else:
                self._learn_from_failure(task, code, result)
            self.tracker.record("learning", time.time() - t0)

            # Record
            self.metrics.record_cycle(cycle, task, result)

            if verbose and cycle % print_every == 0:
                print(f"  ✓ Cycle {cycle}/{num_cycles}")

        return self._generate_report()


def main():
    print("🔍 Turbo Loop Profiling — 100 cycles with timing instrumentation\n")

    # Initialize
    print("Initializing FORGE session...")
    session = ForgeSession()

    # Load tasks
    tasks_file = Path("tests/blind_v3_tasks.json")
    with open(tasks_file) as f:
        all_tasks = json.load(f)
    blind_v3_tasks = [t.get('intent', '') for t in all_tasks if t.get('intent')]
    print(f"✓ Loaded {len(blind_v3_tasks)} V3 tasks\n")

    # Create tracker
    tracker = TimingTracker()

    # Run profiled turbo loop
    print("Running profiled turbo loop (100 cycles)...\n")
    turbo = ProfiledTurbo(session, blind_v3_tasks, tracker)

    start = time.time()
    report = turbo.run(num_cycles=100, print_every=25, verbose=True)
    elapsed = time.time() - start

    # Print timing summary
    tracker.summary()

    # Print turbo results
    print(f"📊 Turbo Loop Results:")
    print(f"  Baseline:    {report['baseline_score']}/50 ({report['baseline_score']*2}%)")
    print(f"  Final:       {report['final_score']}/50 ({report['final_score']*2}%)")
    print(f"  Improvement: +{report['improvement']} ({report['improvement_pct']:+.1f}%)")
    print(f"  Success:     {report['success_rate']*100:.1f}%")
    print(f"  Speed:       {report['cycles_per_hour']:.0f} cycles/hour")
    print(f"  Elapsed:     {elapsed:.1f}s for 100 cycles\n")

    # Identify bottleneck
    print(f"🎯 BOTTLENECK ANALYSIS:")
    bottlenecks = sorted(tracker.times.items(), key=lambda x: sum(x[1]), reverse=True)
    for i, (op, times) in enumerate(bottlenecks[:3], 1):
        pct = (sum(times) / elapsed) * 100
        print(f"  {i}. {op}: {pct:.1f}% of total time ({sum(times):.2f}s)")

    # Recommendations
    print(f"\n💡 OPTIMIZATION RECOMMENDATIONS:")
    top_op = bottlenecks[0][0]
    if "executor" in top_op:
        print(f"  → Executor is the bottleneck. Consider:")
        print(f"    • Caching imports/modules")
        print(f"    • Using compiled Python (PyPy)")
        print(f"    • Parallel execution")
    elif "code_generation" in top_op:
        print(f"  → Code generation is the bottleneck. Consider:")
        print(f"    • Cache fragment lookups")
        print(f"    • Pre-compile architecture patterns")
        print(f"    • Reduce inference cycles")
    elif "intent" in top_op:
        print(f"  → Intent parsing is the bottleneck. Consider:")
        print(f"    • Pre-compile parsing rules")
        print(f"    • Cache common intents")

    print()


if __name__ == "__main__":
    main()
