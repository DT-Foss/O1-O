"""Meta Optimizer: FORGE analyzes its own pipeline performance.

Identifies bottlenecks, detects failing patterns, and generates optimization
recommendations. Reads from fragment_scores.db and fix_history.db to build
a complete picture of where FORGE succeeds and fails.

Part of FORGE Phase 6: Self-Optimization.
"""
# Dependencies: none
# Depended by: autonomous_loop

import json
import os
import re
import sqlite3
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple


class PipelineBottleneck:
    """A detected bottleneck in FORGE's pipeline."""

    def __init__(self, stage: str, description: str,
                 affected_tasks: List[int], severity: str = 'moderate',
                 recommendation: str = ''):
        self.stage = stage  # fragment_selection, assembly, execution, validation
        self.description = description
        self.affected_tasks = affected_tasks
        self.severity = severity
        self.recommendation = recommendation

    def __repr__(self):
        return (f"[{self.severity}] {self.stage}: {self.description} "
                f"({len(self.affected_tasks)} tasks)")


class MetaOptimizer:
    """Analyzes FORGE's pipeline to find optimization opportunities."""

    def __init__(self, scores_db: str = 'knowledge/fragment_scores.db',
                 history_db: str = 'knowledge/fix_history.db',
                 results_dir: str = 'benchmarks/hardened'):
        self.scores_db = scores_db
        self.history_db = history_db
        self.results_dir = results_dir
        self.bottlenecks: List[PipelineBottleneck] = []

    def analyze(self) -> List[PipelineBottleneck]:
        """Run full pipeline analysis and return bottlenecks."""
        self.bottlenecks = []
        self._analyze_fragment_failures()
        self._analyze_error_patterns()
        self._analyze_method_distribution()
        self._analyze_timing()
        self._analyze_fragment_combinations()
        return self.bottlenecks

    def _load_all_results(self) -> List[Dict]:
        """Load benchmark results from all result files."""
        all_results = []
        if not os.path.exists(self.results_dir):
            return all_results

        for dirpath, _, filenames in os.walk(self.results_dir):
            for fname in filenames:
                if fname.endswith('_results.json'):
                    path = os.path.join(dirpath, fname)
                    try:
                        with open(path) as f:
                            results = json.load(f)
                        if isinstance(results, list):
                            for r in results:
                                r['_benchmark'] = fname
                            all_results.extend(results)
                    except (json.JSONDecodeError, OSError):
                        pass

        return all_results

    def _analyze_fragment_failures(self):
        """Find fragments with consistently high failure rates."""
        if not os.path.exists(self.scores_db):
            return

        try:
            with sqlite3.connect(self.scores_db) as conn:
                rows = conn.execute('''
                    SELECT fragment_key,
                           COUNT(*) as total,
                           SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as fails
                    FROM fragment_runs
                    WHERE fragment_key != '_no_fragment'
                    GROUP BY fragment_key
                    HAVING total >= 3 AND fails > 0
                    ORDER BY (CAST(fails AS REAL) / total) DESC
                    LIMIT 20
                ''').fetchall()

            for frag_key, total, fails in rows:
                rate = fails / total
                if rate >= 0.5:
                    self.bottlenecks.append(PipelineBottleneck(
                        'fragment_quality',
                        f"Fragment '{frag_key}' fails {fails}/{total} ({rate:.0%})",
                        [],
                        severity='hard' if rate >= 0.8 else 'moderate',
                        recommendation=f"Review fragment '{frag_key}' for structural issues"
                    ))
        except sqlite3.OperationalError:
            pass

    def _analyze_error_patterns(self):
        """Find recurring error patterns across benchmarks."""
        results = self._load_all_results()
        if not results:
            return

        error_counts = defaultdict(list)
        for r in results:
            if not r.get('success', True):
                error = r.get('error', '')
                # Normalize error to class
                if 'ImportError' in error or 'ModuleNotFoundError' in error:
                    error_counts['import_error'].append(r.get('id', 0))
                elif 'SyntaxError' in error:
                    error_counts['syntax_error'].append(r.get('id', 0))
                elif 'SystemExit' in error or 'argparse' in error:
                    error_counts['argparse_exit'].append(r.get('id', 0))
                elif 'FileNotFoundError' in error:
                    error_counts['file_not_found'].append(r.get('id', 0))
                elif 'TimeoutError' in error or 'timeout' in error.lower():
                    error_counts['timeout'].append(r.get('id', 0))
                elif 'NameError' in error:
                    error_counts['name_error'].append(r.get('id', 0))
                elif error:
                    error_counts['other'].append(r.get('id', 0))

        for error_class, task_ids in error_counts.items():
            if len(task_ids) >= 2:
                self.bottlenecks.append(PipelineBottleneck(
                    'recurring_error',
                    f"{error_class} occurs in {len(task_ids)} tasks",
                    task_ids,
                    severity='hard' if len(task_ids) >= 5 else 'moderate',
                    recommendation=f"Add fix strategy for '{error_class}' to self_repair.py"
                ))

    def _analyze_method_distribution(self):
        """Check the balance of pass methods (exec vs structural)."""
        results = self._load_all_results()
        if not results:
            return

        method_counts = defaultdict(int)
        for r in results:
            if r.get('success'):
                method_counts[r.get('method', 'unknown')] += 1

        total = sum(method_counts.values())
        if total == 0:
            return

        structural = method_counts.get('structural_non_terminating', 0)
        if structural > 0:
            rate = structural / total
            if rate > 0.2:
                self.bottlenecks.append(PipelineBottleneck(
                    'validation_method',
                    f"{structural}/{total} ({rate:.0%}) pass via structural (non-exec)",
                    [],
                    severity='moderate',
                    recommendation="Improve code generation to produce executable output"
                ))

    def _analyze_timing(self):
        """Find tasks that take unusually long."""
        results = self._load_all_results()
        if not results:
            return

        durations = [r.get('duration', 0) for r in results if r.get('duration', 0) > 0]
        if not durations:
            return

        avg = sum(durations) / len(durations)
        slow_tasks = [r.get('id', 0) for r in results
                      if r.get('duration', 0) > avg * 5 and r.get('duration', 0) > 5]

        if slow_tasks:
            self.bottlenecks.append(PipelineBottleneck(
                'performance',
                f"{len(slow_tasks)} tasks take >5x average ({avg:.1f}s)",
                slow_tasks,
                severity='trivial',
                recommendation="Check for infinite loops or network timeouts"
            ))

    def _analyze_fragment_combinations(self):
        """Find fragment combinations that always fail together."""
        if not os.path.exists(self.scores_db):
            return

        try:
            with sqlite3.connect(self.scores_db) as conn:
                # Get task IDs that failed
                fail_tasks = conn.execute('''
                    SELECT DISTINCT task_id FROM fragment_runs
                    WHERE success = 0
                ''').fetchall()

                # Get fragments used in failed tasks
                for (task_id,) in fail_tasks[:50]:
                    frags = conn.execute('''
                        SELECT fragment_key FROM fragment_runs
                        WHERE task_id = ? AND success = 0
                    ''', (task_id,)).fetchall()

                    frag_list = [f[0] for f in frags if f[0] != '_no_fragment']
                    if len(frag_list) >= 2:
                        # Check if this combination always fails
                        combo = tuple(sorted(frag_list[:3]))
                        all_uses = conn.execute('''
                            SELECT COUNT(*), SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END)
                            FROM fragment_runs WHERE fragment_key = ?
                        ''', (frag_list[0],)).fetchone()

                        if all_uses and all_uses[0] >= 3 and all_uses[1] == 0:
                            self.bottlenecks.append(PipelineBottleneck(
                                'toxic_fragment',
                                f"Fragment '{frag_list[0]}' never succeeds",
                                [task_id],
                                severity='hard',
                                recommendation=f"Review or remove fragment '{frag_list[0]}'"
                            ))
        except sqlite3.OperationalError:
            pass

    def generate_recommendations(self) -> List[str]:
        """Generate actionable optimization recommendations."""
        if not self.bottlenecks:
            self.analyze()

        recs = []
        # Deduplicate recommendations
        seen = set()
        for b in sorted(self.bottlenecks, key=lambda x: {'hard': 0, 'moderate': 1, 'trivial': 2}[x.severity]):
            if b.recommendation and b.recommendation not in seen:
                recs.append(f"[{b.severity}] {b.recommendation}")
                seen.add(b.recommendation)

        return recs

    def format_report(self) -> str:
        """Generate comprehensive optimization report."""
        if not self.bottlenecks:
            self.analyze()

        lines = []
        lines.append("FORGE Meta-Optimization Report")
        lines.append("=" * 50)
        lines.append(f"Bottlenecks found: {len(self.bottlenecks)}")

        # Group by stage
        by_stage = defaultdict(list)
        for b in self.bottlenecks:
            by_stage[b.stage].append(b)

        for stage, items in sorted(by_stage.items()):
            lines.append(f"\n{stage} ({len(items)} issues):")
            for b in items:
                lines.append(f"  [{b.severity}] {b.description}")
                if b.recommendation:
                    lines.append(f"    → {b.recommendation}")

        recs = self.generate_recommendations()
        if recs:
            lines.append(f"\nTop Recommendations:")
            for i, rec in enumerate(recs[:10]):
                lines.append(f"  {i+1}. {rec}")

        return '\n'.join(lines)


if __name__ == '__main__':
    opt = MetaOptimizer()
    print(opt.format_report())
