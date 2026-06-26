"""Fix Evaluator: Multi-criteria decision engine for competing fix strategies.

When multiple fixes are available for a failure, this module evaluates all
candidates and picks the best one based on:
  1. Correctness — does the fix actually resolve the failure?
  2. Minimality — smallest code change (diff) wins
  3. Safety — simulation predicts no new failures
  4. History — empirical success rate from past runs

Part of FORGE Phase 5: Intelligent Fix Selection.
"""
# Dependencies: execution_simulator, fix_history
# Depended by: autonomous_loop

import difflib
from typing import Any, Dict, List, Optional, Tuple

from core.execution_simulator import ExecutionSimulator, SimulationResult


class FixCandidate:
    """A candidate fix with evaluation metrics."""

    def __init__(self, name: str, code: str, original: str):
        self.name = name
        self.code = code
        self.original = original
        # Scores (0.0 - 1.0)
        self.correctness = 0.0  # fixes the issue
        self.minimality = 0.0   # smallest change
        self.safety = 0.0       # no new failures
        self.history = 0.5      # past success rate (default 50%)
        self.total_score = 0.0

    @property
    def diff_size(self) -> int:
        """Number of changed lines."""
        orig_lines = self.original.splitlines()
        fix_lines = self.code.splitlines()
        diff = list(difflib.unified_diff(orig_lines, fix_lines, lineterm=''))
        return sum(1 for line in diff if line.startswith('+') or line.startswith('-'))

    def __repr__(self):
        return (f"FixCandidate({self.name}, score={self.total_score:.2f}, "
                f"diff={self.diff_size})")


class FixEvaluator:
    """Evaluates and ranks competing fix strategies."""

    # Scoring weights
    WEIGHTS = {
        'correctness': 0.40,
        'minimality': 0.25,
        'safety': 0.20,
        'history': 0.15,
    }

    def __init__(self):
        self.simulator = ExecutionSimulator()
        self._history_cache: Dict[str, float] = {}

    def evaluate_candidates(self, original_code: str,
                            candidates: Dict[str, str],
                            error_class: str = ''
                            ) -> List[FixCandidate]:
        """Evaluate all fix candidates and return ranked list.

        Args:
            original_code: The failing code
            candidates: {fix_name: fixed_code}
            error_class: The error class being fixed

        Returns:
            Sorted list of FixCandidates (best first)
        """
        if not candidates:
            return []

        # Simulate original to get baseline failures
        orig_sim = self.simulator.simulate(original_code)
        orig_failure_checks = {f['check'] for f in orig_sim.failures}

        evaluated = []
        max_diff = 1  # avoid division by zero

        for name, fixed_code in candidates.items():
            candidate = FixCandidate(name, fixed_code, original_code)

            # Skip if code is unchanged
            if fixed_code == original_code:
                continue

            # 1. Correctness: does simulation show fewer failures?
            fix_sim = self.simulator.simulate(fixed_code)
            fix_failure_checks = {f['check'] for f in fix_sim.failures}
            resolved = orig_failure_checks - fix_failure_checks
            if orig_failure_checks:
                candidate.correctness = len(resolved) / len(orig_failure_checks)
            else:
                candidate.correctness = 0.5  # original had no known failures

            # 2. Safety: no NEW failures introduced?
            new_failures = fix_failure_checks - orig_failure_checks
            if not new_failures:
                candidate.safety = 1.0
            else:
                candidate.safety = max(0.0, 1.0 - 0.3 * len(new_failures))

            # 3. Minimality: track diff size for later normalization
            if candidate.diff_size > max_diff:
                max_diff = candidate.diff_size

            # 4. History: check past success rate
            candidate.history = self._get_history_score(name, error_class)

            evaluated.append(candidate)

        # Normalize minimality (smaller diff = higher score)
        for c in evaluated:
            c.minimality = 1.0 - (c.diff_size / (max_diff + 1))

        # Compute weighted total
        for c in evaluated:
            c.total_score = (
                self.WEIGHTS['correctness'] * c.correctness +
                self.WEIGHTS['minimality'] * c.minimality +
                self.WEIGHTS['safety'] * c.safety +
                self.WEIGHTS['history'] * c.history
            )

        # Sort by total score descending
        evaluated.sort(key=lambda x: x.total_score, reverse=True)
        return evaluated

    def best_fix(self, original_code: str,
                 candidates: Dict[str, str],
                 error_class: str = '') -> Optional[FixCandidate]:
        """Return the single best fix, or None if no good fix found."""
        ranked = self.evaluate_candidates(original_code, candidates, error_class)
        if ranked and ranked[0].total_score > 0.3:
            return ranked[0]
        return None

    def _get_history_score(self, fix_name: str, error_class: str) -> float:
        """Get historical success rate for a fix strategy.

        Uses fix_history DB if available, otherwise returns 0.5 (neutral).
        """
        cache_key = f"{fix_name}:{error_class}"
        if cache_key in self._history_cache:
            return self._history_cache[cache_key]

        score = 0.5  # default: neutral
        try:
            from core.fix_history import FixHistory
            history = FixHistory()
            rate = history.success_rate(fix_name, error_class)
            score = rate
        except Exception:
            pass

        self._history_cache[cache_key] = score
        return score

    def format_evaluation(self, candidates: List[FixCandidate]) -> str:
        """Format evaluation results as readable string."""
        if not candidates:
            return "No fix candidates to evaluate."

        lines = []
        lines.append("Fix Evaluation Results")
        lines.append("=" * 50)
        for i, c in enumerate(candidates):
            lines.append(f"  #{i+1} {c.name} (score: {c.total_score:.2f})")
            lines.append(f"      correctness={c.correctness:.2f}  "
                         f"minimality={c.minimality:.2f}  "
                         f"safety={c.safety:.2f}  "
                         f"history={c.history:.2f}")
            lines.append(f"      diff: {c.diff_size} lines changed")

        winner = candidates[0]
        lines.append(f"\n  Winner: {winner.name} ({winner.total_score:.2f})")
        return '\n'.join(lines)


if __name__ == '__main__':
    # Test with example
    evaluator = FixEvaluator()

    original = '''
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--input", required=True)
args = parser.parse_args()
with open(args.input) as f:
    print(f.read())
'''

    fix_a = '''
class _Args:
    input = "data.txt"
args = _Args()
with open(args.input) as f:
    print(f.read())
'''

    fix_b = '''
import sys
input_file = sys.argv[1] if len(sys.argv) > 1 else "data.txt"
with open(input_file) as f:
    print(f.read())
'''

    candidates = {'fix_argparse_to_defaults': fix_a, 'fix_sys_argv_fallback': fix_b}
    ranked = evaluator.evaluate_candidates(original, candidates, 'argparse_exit')
    print(evaluator.format_evaluation(ranked))
