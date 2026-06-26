"""
Fragment Quality Scorer — Phase 0 of FORGE Self-Repair

Tracks per-fragment success/failure across benchmark runs.
SQLite-backed for persistence. Answers:
  - "Which fragments have the lowest success rate?"
  - "Which fragments cause the most failures?"
  - "What error classes affect which fragments?"

This is the foundation for all self-repair phases.
Without knowing which fragments work and which don't,
FORGE can't diagnose, fix, or improve itself.

Storage: knowledge/fragment_scores.db
"""
# Dependencies: none
# Depended by: autonomous_loop


import sqlite3
import time
import os
import re
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from collections import defaultdict


class FragmentScorer:
    """Track fragment quality across benchmark runs."""

    def __init__(self, db_path: str = None):
        if db_path is None:
            base = Path(__file__).parent.parent / 'knowledge'
            base.mkdir(parents=True, exist_ok=True)
            db_path = str(base / 'fragment_scores.db')

        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS fragment_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                benchmark TEXT NOT NULL,
                task_id INTEGER NOT NULL,
                task_intent TEXT NOT NULL,
                fragment_key TEXT NOT NULL,
                fragment_file TEXT,
                success INTEGER NOT NULL,
                method TEXT,
                error_class TEXT,
                error_message TEXT,
                duration_ms REAL,
                loc INTEGER,
                timestamp REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS run_metadata (
                run_id TEXT PRIMARY KEY,
                benchmark TEXT NOT NULL,
                total_tasks INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                failed INTEGER NOT NULL,
                pass_rate REAL NOT NULL,
                timestamp REAL NOT NULL
            )
        """)
        # Indexes for fast lookup
        conn.execute("CREATE INDEX IF NOT EXISTS idx_frag_key ON fragment_runs(fragment_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_run_id ON fragment_runs(run_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_error_class ON fragment_runs(error_class)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_benchmark ON fragment_runs(benchmark)")
        conn.commit()
        conn.close()

    def generate_run_id(self, benchmark: str) -> str:
        """Generate a unique run ID."""
        ts = int(time.time())
        return f"{benchmark}_{ts}"

    def record_result(self, run_id: str, benchmark: str, task_id: int,
                      task_intent: str, fragment_keys: List[str],
                      fragment_file: str, success: bool,
                      method: str = None, error_class: str = None,
                      error_message: str = None, duration_ms: float = None,
                      loc: int = None):
        """Record a single task result with its fragment(s)."""
        conn = sqlite3.connect(self.db_path)
        ts = time.time()

        for frag_key in fragment_keys:
            conn.execute("""
                INSERT INTO fragment_runs
                (run_id, benchmark, task_id, task_intent, fragment_key,
                 fragment_file, success, method, error_class, error_message,
                 duration_ms, loc, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (run_id, benchmark, task_id, task_intent, frag_key,
                  fragment_file, int(success), method, error_class,
                  error_message[:500] if error_message else None,
                  duration_ms, loc, ts))

        conn.commit()
        conn.close()

    def record_run_summary(self, run_id: str, benchmark: str,
                           total: int, passed: int, failed: int):
        """Record run-level summary."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT OR REPLACE INTO run_metadata
            (run_id, benchmark, total_tasks, passed, failed, pass_rate, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (run_id, benchmark, total, passed, failed,
              passed / total if total > 0 else 0.0, time.time()))
        conn.commit()
        conn.close()

    # ── Error Classification ──

    @staticmethod
    def classify_error(error_str: str) -> str:
        """Classify an error string into a canonical error class.

        Returns one of ~30 error classes. This is the foundation
        for Phase 1's full error taxonomy.
        """
        if not error_str:
            return 'unknown'

        e = error_str.strip()

        # Python exception types (most specific first)
        if 'SyntaxError' in e:
            return 'syntax_error'
        if 'IndentationError' in e:
            return 'indentation_error'
        if 'ImportError' in e or 'ModuleNotFoundError' in e:
            return 'import_error'
        if 'NameError' in e:
            return 'name_error'
        if 'TypeError' in e:
            if 'argument' in e.lower():
                return 'type_error_args'
            return 'type_error'
        if 'AttributeError' in e:
            return 'attribute_error'
        if 'KeyError' in e:
            return 'key_error'
        if 'IndexError' in e:
            return 'index_error'
        if 'ValueError' in e:
            return 'value_error'
        if 'FileNotFoundError' in e:
            return 'file_not_found'
        if 'PermissionError' in e:
            return 'permission_error'
        if 'ConnectionError' in e or 'ConnectionRefused' in e:
            return 'connection_error'
        if 'TimeoutError' in e or 'timed out' in e.lower():
            return 'timeout'
        if 'SystemExit' in e:
            return 'system_exit'
        if 'RecursionError' in e:
            return 'recursion_error'
        if 'OverflowError' in e:
            return 'overflow_error'
        if 'ZeroDivisionError' in e:
            return 'zero_division'
        if 'UnicodeError' in e or 'UnicodeDecodeError' in e:
            return 'unicode_error'
        if 'OSError' in e or 'IOError' in e:
            return 'os_error'
        if 'AssertionError' in e:
            return 'assertion_error'
        if 'StopIteration' in e:
            return 'stop_iteration'

        # Forge-specific error patterns
        if 'empty_functions' in e.lower() or 'Empty functions' in e:
            return 'empty_functions'
        if 'No implementation' in e:
            return 'no_implementation'
        if 'timeout' in e.lower() or 'timed out' in e.lower():
            return 'timeout'
        if 'infinite loop' in e.lower():
            return 'infinite_loop'
        if 'column' in e.lower() and 'mismatch' in e.lower():
            return 'column_mismatch'
        if 'unresolved' in e.lower() and 'variable' in e.lower():
            return 'unresolved_variable'

        # Generic categories
        if 'Traceback' in e:
            return 'runtime_error'
        if 'Error' in e:
            return 'generic_error'

        return 'unknown'

    # ── Query Methods ──

    def fragment_stats(self, min_runs: int = 1) -> List[Dict[str, Any]]:
        """Get success rate per fragment, sorted by failure rate (worst first).

        Returns list of dicts: fragment_key, total_runs, successes, failures,
        success_rate, error_classes (list), last_seen.
        """
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("""
            SELECT
                fragment_key,
                COUNT(*) as total,
                SUM(success) as successes,
                COUNT(*) - SUM(success) as failures,
                ROUND(CAST(SUM(success) AS FLOAT) / COUNT(*) * 100, 1) as rate,
                MAX(timestamp) as last_seen
            FROM fragment_runs
            GROUP BY fragment_key
            HAVING COUNT(*) >= ?
            ORDER BY rate ASC, failures DESC
        """, (min_runs,)).fetchall()

        results = []
        for key, total, ok, fail, rate, last in rows:
            # Get error classes for this fragment
            errors = conn.execute("""
                SELECT error_class, COUNT(*) as cnt
                FROM fragment_runs
                WHERE fragment_key = ? AND success = 0 AND error_class IS NOT NULL
                GROUP BY error_class
                ORDER BY cnt DESC
            """, (key,)).fetchall()

            results.append({
                'fragment_key': key,
                'total_runs': total,
                'successes': ok,
                'failures': fail,
                'success_rate': rate,
                'error_classes': [(ec, cnt) for ec, cnt in errors],
                'last_seen': last,
            })

        conn.close()
        return results

    def worst_fragments(self, top_n: int = 20) -> List[Dict[str, Any]]:
        """Get the N worst-performing fragments."""
        stats = self.fragment_stats(min_runs=1)
        return stats[:top_n]

    def perfect_fragments(self) -> List[str]:
        """Get fragments with 100% success rate."""
        stats = self.fragment_stats(min_runs=1)
        return [s['fragment_key'] for s in stats if s['success_rate'] == 100.0]

    def error_class_distribution(self) -> List[Tuple[str, int]]:
        """Get overall error class distribution across all fragments."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("""
            SELECT error_class, COUNT(*) as cnt
            FROM fragment_runs
            WHERE success = 0 AND error_class IS NOT NULL
            GROUP BY error_class
            ORDER BY cnt DESC
        """).fetchall()
        conn.close()
        return rows

    def fragment_history(self, fragment_key: str) -> List[Dict[str, Any]]:
        """Get full history for a specific fragment."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("""
            SELECT run_id, benchmark, task_id, task_intent, success,
                   method, error_class, error_message, duration_ms, loc, timestamp
            FROM fragment_runs
            WHERE fragment_key = ?
            ORDER BY timestamp DESC
        """, (fragment_key,)).fetchall()
        conn.close()

        return [{
            'run_id': r[0], 'benchmark': r[1], 'task_id': r[2],
            'task_intent': r[3], 'success': bool(r[4]), 'method': r[5],
            'error_class': r[6], 'error_message': r[7],
            'duration_ms': r[8], 'loc': r[9], 'timestamp': r[10],
        } for r in rows]

    def run_history(self) -> List[Dict[str, Any]]:
        """Get summary of all benchmark runs."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("""
            SELECT run_id, benchmark, total_tasks, passed, failed,
                   pass_rate, timestamp
            FROM run_metadata
            ORDER BY timestamp DESC
        """).fetchall()
        conn.close()

        return [{
            'run_id': r[0], 'benchmark': r[1], 'total': r[2],
            'passed': r[3], 'failed': r[4], 'pass_rate': r[5],
            'timestamp': r[6],
        } for r in rows]

    def unused_fragments(self, all_fragment_keys: List[str]) -> List[str]:
        """Find fragments that have never been used in any benchmark."""
        conn = sqlite3.connect(self.db_path)
        used = set(r[0] for r in conn.execute(
            "SELECT DISTINCT fragment_key FROM fragment_runs"
        ).fetchall())
        conn.close()
        return [k for k in all_fragment_keys if k not in used]

    def summary(self) -> Dict[str, Any]:
        """Get a high-level summary of fragment quality."""
        conn = sqlite3.connect(self.db_path)

        total_runs = conn.execute(
            "SELECT COUNT(*) FROM fragment_runs"
        ).fetchone()[0]
        total_fragments = conn.execute(
            "SELECT COUNT(DISTINCT fragment_key) FROM fragment_runs"
        ).fetchone()[0]
        total_successes = conn.execute(
            "SELECT SUM(success) FROM fragment_runs"
        ).fetchone()[0] or 0
        total_failures = total_runs - total_successes

        # Fragments with <100% success rate
        imperfect = conn.execute("""
            SELECT COUNT(*) FROM (
                SELECT fragment_key
                FROM fragment_runs
                GROUP BY fragment_key
                HAVING CAST(SUM(success) AS FLOAT) / COUNT(*) < 1.0
            )
        """).fetchone()[0]

        benchmark_runs = conn.execute(
            "SELECT COUNT(*) FROM run_metadata"
        ).fetchone()[0]

        conn.close()

        return {
            'total_fragment_runs': total_runs,
            'unique_fragments_seen': total_fragments,
            'total_successes': total_successes,
            'total_failures': total_failures,
            'overall_success_rate': round(total_successes / total_runs * 100, 1) if total_runs > 0 else 0.0,
            'imperfect_fragments': imperfect,
            'benchmark_runs': benchmark_runs,
        }

    def format_report(self, top_n: int = 20) -> str:
        """Generate a human-readable quality report."""
        s = self.summary()
        lines = [
            "=== FORGE Fragment Quality Report ===",
            f"Benchmark runs:     {s['benchmark_runs']}",
            f"Fragment evaluations: {s['total_fragment_runs']}",
            f"Unique fragments:   {s['unique_fragments_seen']}",
            f"Overall success:    {s['overall_success_rate']}%",
            f"Imperfect fragments: {s['imperfect_fragments']}",
            "",
        ]

        # Error distribution
        errors = self.error_class_distribution()
        if errors:
            lines.append("Error Distribution:")
            for ec, cnt in errors[:15]:
                lines.append(f"  {ec}: {cnt}")
            lines.append("")

        # Worst fragments
        worst = self.worst_fragments(top_n)
        if worst:
            lines.append(f"Bottom {min(top_n, len(worst))} Fragments (by success rate):")
            for f in worst:
                if f['success_rate'] < 100.0:
                    errs = ', '.join(f"{ec}({c})" for ec, c in f['error_classes'][:3])
                    lines.append(
                        f"  {f['fragment_key']}: {f['success_rate']}% "
                        f"({f['successes']}/{f['total_runs']}) "
                        f"[{errs}]"
                    )

        return '\n'.join(lines)
