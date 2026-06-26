"""Fix History Learning: Track empirical success rates for fix strategies.

Records which fixes actually worked after execution, building a knowledge base
that improves fix selection over time. Stored in SQLite alongside fragment scores.

Part of FORGE Phase 5: Intelligent Fix Selection.
"""
# Dependencies: none
# Depended by: autonomous_loop, fix_evaluator

import os
import sqlite3
import time
from typing import Dict, List, Optional, Tuple


class FixHistory:
    """Persistent store for fix attempt outcomes."""

    def __init__(self, db_path: str = 'knowledge/fix_history.db'):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS fix_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    error_class TEXT,
                    fix_name TEXT,
                    success INTEGER,
                    task_id INTEGER,
                    task_intent TEXT,
                    fragment_key TEXT,
                    diff_size INTEGER,
                    execution_time_ms REAL
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_fix_error
                ON fix_attempts(error_class, fix_name)
            ''')

    def record(self, error_class: str, fix_name: str, success: bool,
               task_id: int = 0, task_intent: str = '',
               fragment_key: str = '', diff_size: int = 0,
               execution_time_ms: float = 0.0):
        """Record a fix attempt result."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO fix_attempts
                (timestamp, error_class, fix_name, success, task_id,
                 task_intent, fragment_key, diff_size, execution_time_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (time.time(), error_class, fix_name, int(success),
                  task_id, task_intent, fragment_key, diff_size,
                  execution_time_ms))

    def success_rate(self, fix_name: str, error_class: str = '') -> float:
        """Get historical success rate for a fix strategy.

        Returns 0.5 if no data available (neutral prior).
        """
        with sqlite3.connect(self.db_path) as conn:
            if error_class:
                row = conn.execute('''
                    SELECT COUNT(*), SUM(success) FROM fix_attempts
                    WHERE fix_name = ? AND error_class = ?
                ''', (fix_name, error_class)).fetchone()
            else:
                row = conn.execute('''
                    SELECT COUNT(*), SUM(success) FROM fix_attempts
                    WHERE fix_name = ?
                ''', (fix_name,)).fetchone()

        total, successes = row
        if total == 0:
            return 0.5  # no data → neutral
        return successes / total

    def best_fix_for_error(self, error_class: str,
                           min_attempts: int = 2) -> Optional[str]:
        """Find the fix with highest success rate for an error class.

        Requires at least min_attempts records to be considered.
        """
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute('''
                SELECT fix_name, COUNT(*) as total, SUM(success) as wins
                FROM fix_attempts
                WHERE error_class = ?
                GROUP BY fix_name
                HAVING total >= ?
                ORDER BY (CAST(wins AS REAL) / total) DESC, total DESC
                LIMIT 1
            ''', (error_class, min_attempts)).fetchall()

        if rows:
            return rows[0][0]
        return None

    def all_stats(self) -> Dict[str, Dict]:
        """Get statistics for all fix strategies."""
        stats = {}
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute('''
                SELECT fix_name, error_class,
                       COUNT(*) as total, SUM(success) as wins
                FROM fix_attempts
                GROUP BY fix_name, error_class
                ORDER BY fix_name, error_class
            ''').fetchall()

        for fix_name, error_class, total, wins in rows:
            if fix_name not in stats:
                stats[fix_name] = {
                    'total': 0, 'wins': 0, 'errors': {}
                }
            stats[fix_name]['total'] += total
            stats[fix_name]['wins'] += wins
            stats[fix_name]['errors'][error_class] = {
                'total': total, 'wins': wins,
                'rate': wins / total if total > 0 else 0.0
            }

        # Add overall rates
        for name, data in stats.items():
            data['rate'] = data['wins'] / data['total'] if data['total'] > 0 else 0.0

        return stats

    def format_report(self) -> str:
        """Generate human-readable history report."""
        stats = self.all_stats()

        lines = []
        lines.append("Fix History Report")
        lines.append("=" * 50)

        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute('SELECT COUNT(*) FROM fix_attempts').fetchone()[0]
        lines.append(f"Total fix attempts: {total}")
        lines.append(f"Unique strategies: {len(stats)}")
        lines.append("")

        for name, data in sorted(stats.items(), key=lambda x: x[1]['rate'], reverse=True):
            lines.append(f"  {name}: {data['wins']}/{data['total']} ({data['rate']:.0%})")
            for err, err_data in data['errors'].items():
                lines.append(f"    {err}: {err_data['wins']}/{err_data['total']} ({err_data['rate']:.0%})")

        return '\n'.join(lines)


if __name__ == '__main__':
    # Test
    history = FixHistory()

    # Simulate some fix attempts
    history.record('import_error', 'fix_stdlib_alternative', True, task_id=1)
    history.record('import_error', 'fix_stdlib_alternative', True, task_id=2)
    history.record('import_error', 'fix_stdlib_alternative', False, task_id=3)
    history.record('argparse_exit', 'fix_argparse_to_defaults', True, task_id=4)
    history.record('argparse_exit', 'fix_argparse_to_defaults', True, task_id=5)
    history.record('file_not_found', 'fix_create_inline_data', True, task_id=6)
    history.record('file_not_found', 'fix_create_inline_data', False, task_id=7)

    print(history.format_report())
    print()
    print(f"Best for import_error: {history.best_fix_for_error('import_error')}")
    print(f"Rate for fix_argparse_to_defaults: {history.success_rate('fix_argparse_to_defaults'):.0%}")
