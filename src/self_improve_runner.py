#!/usr/bin/env python3
"""
O1-O Overnight Self-Improvement Runner

Run this before going to sleep. O1-O will play against the Python runtime
all night, discovering and verifying knowledge autonomously.

Usage:
    python self_improve_runner.py                  # Default: 500 iter, 8h
    python self_improve_runner.py --iterations 1000 --hours 12
    python self_improve_runner.py --quick          # 50 iter, 0.5h (test run)
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from o1o import ForgeSession


def main():
    parser = argparse.ArgumentParser(description='O1-O Self-Improvement Runner')
    parser.add_argument('--iterations', '-n', type=int, default=500,
                        help='Maximum iterations (default: 500)')
    parser.add_argument('--hours', '-t', type=float, default=8.0,
                        help='Time budget in hours (default: 8)')
    parser.add_argument('--quick', action='store_true',
                        help='Quick test run (50 iterations, 30 min)')
    args = parser.parse_args()

    if args.quick:
        args.iterations = 50
        args.hours = 0.5

    print("Initializing O1-O...")
    session = ForgeSession()

    stats = session.self_improve(
        max_iterations=args.iterations,
        time_budget_hours=args.hours
    )

    # Exit code: 0 if success rate > 50%, 1 otherwise
    rate = stats['successes'] / max(stats['iterations'], 1)
    sys.exit(0 if rate > 0.3 else 1)


if __name__ == '__main__':
    main()
