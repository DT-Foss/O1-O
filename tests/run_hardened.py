#!/usr/bin/env python3
"""
FORGE Hardened Benchmark — Run V2, V3, V4, CIR with honest validation.

All tasks: execution-first, no keyword-matching shortcuts, no inflated scores.
"""

import sys
import json
import argparse
import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from forge import ForgeSession
sys.path.insert(0, str(Path(__file__).parent))
from forge_validator import UnifiedBenchmarkRunner


def write_combined_report(all_results, benchmarks, output_dir):
    """Write a combined .md report for all benchmarks run."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    grand_total = sum(len(r) for r in all_results.values())
    grand_pass = sum(sum(1 for x in r if x['success']) for r in all_results.values())
    grand_pct = (100 * grand_pass / grand_total) if grand_total else 0

    md_path = out_dir / "combined_results.md"
    with open(md_path, 'w') as f:
        f.write(f"# FORGE Combined Benchmark Results\n\n")
        f.write(f"**Date:** {now}  \n")
        f.write(f"**Overall: {grand_pass}/{grand_total} ({grand_pct:.1f}%)**\n\n")
        f.write(f"---\n\n")

        # Summary table
        f.write("## Summary\n\n")
        f.write("| Benchmark | Passed | Total | Rate |\n")
        f.write("|-----------|--------|-------|------|\n")
        for bm, results in all_results.items():
            total = len(results)
            passed = sum(1 for r in results if r['success'])
            pct = (100 * passed / total) if total else 0
            name = benchmarks.get(bm, (None, bm))[1]
            f.write(f"| {name} | {passed} | {total} | {pct:.1f}% |\n")
        f.write(f"| **TOTAL** | **{grand_pass}** | **{grand_total}** | **{grand_pct:.1f}%** |\n")
        f.write("\n")

        # Per-benchmark detail
        for bm, results in all_results.items():
            name = benchmarks.get(bm, (None, bm))[1]
            total = len(results)
            passed = sum(1 for r in results if r['success'])
            pct = (100 * passed / total) if total else 0

            f.write(f"---\n\n## {name}: {passed}/{total} ({pct:.1f}%)\n\n")

            # Tier breakdown
            tier_stats = {}
            for r in results:
                tier = r['tier']
                if tier not in tier_stats:
                    tier_stats[tier] = {'pass': 0, 'total': 0}
                tier_stats[tier]['total'] += 1
                if r['success']:
                    tier_stats[tier]['pass'] += 1

            if len(tier_stats) > 1:
                f.write("### Tier Breakdown\n\n")
                f.write("| Tier | Passed | Total | Rate |\n")
                f.write("|------|--------|-------|------|\n")
                for tier in sorted(tier_stats.keys()):
                    s = tier_stats[tier]
                    t_pct = 100 * s['pass'] / s['total'] if s['total'] else 0
                    f.write(f"| {tier} | {s['pass']} | {s['total']} | {t_pct:.0f}% |\n")
                f.write("\n")

            # Failures
            failures = [r for r in results if not r['success']]
            if failures:
                f.write(f"### Failures ({len(failures)})\n\n")
                f.write("| # | Tier | Task | Error |\n")
                f.write("|---|------|------|-------|\n")
                for r in failures:
                    err = r.get('error', '')[:80].replace('|', '\\|')
                    task = r['intent'][:60].replace('|', '\\|')
                    f.write(f"| {r['id']} | {r['tier']} | {task} | {err} |\n")
                f.write("\n")
            else:
                f.write("**All tasks passed!**\n\n")

    print(f"\n  Combined report: {md_path}")
    return md_path


def main():
    parser = argparse.ArgumentParser(description="FORGE Hardened Benchmarks")
    parser.add_argument('--benchmark', choices=['v2', 'v3', 'v4', 'cir', 'cir+v4', 'all'], default='all')
    parser.add_argument('--timeout', type=int, default=10, help='Execution timeout per task')
    args = parser.parse_args()

    session = ForgeSession()
    session.knowledge.zero_shot = True
    runner = UnifiedBenchmarkRunner(session, output_dir="benchmarks/hardened")

    benchmarks = {
        'v2': ('tests/blind_v2_tasks.json', 'V2 Blind (100 tasks)'),
        'v3': ('tests/blind_v3_tasks.json', 'V3 Impossible (50 tasks)'),
        'v4': ('tests/blind_v4_tasks.json', 'V4 StackOverflow (104 tasks)'),
        'cir_red': ('tests/cir_red_tasks.json', 'CIR Red Team (60 tasks)'),
        'cir_blue': ('tests/cir_blue_tasks.json', 'CIR Blue Team (35 tasks)'),
    }

    if args.benchmark == 'cir':
        run_list = ['cir_red', 'cir_blue']
    elif args.benchmark == 'cir+v4':
        run_list = ['cir_red', 'cir_blue', 'v4']
    elif args.benchmark == 'all':
        run_list = ['v2', 'v3', 'v4', 'cir_red', 'cir_blue']
    else:
        run_list = [args.benchmark]

    all_results = {}
    for bm in run_list:
        tasks_file, name = benchmarks[bm]
        tasks_path = Path(tasks_file)
        if not tasks_path.exists():
            print(f"\nSkipping {name}: {tasks_file} not found")
            continue

        with open(tasks_path) as f:
            tasks = json.load(f)

        results = runner.run_benchmark(tasks, name, timeout=args.timeout)
        all_results[bm] = results

    # Final summary
    if len(all_results) > 1:
        print(f"\n{'='*65}")
        print(f"  FORGE HARDENED BENCHMARK — FINAL SUMMARY")
        print(f"{'='*65}")
        grand_total = 0
        grand_pass = 0
        for bm, results in all_results.items():
            total = len(results)
            passed = sum(1 for r in results if r['success'])
            pct = (100 * passed / total) if total else 0
            _, name = benchmarks[bm]
            print(f"  {name}: {passed}/{total} ({pct:.1f}%)")
            grand_total += total
            grand_pass += passed

        grand_pct = (100 * grand_pass / grand_total) if grand_total else 0
        print(f"  {'─'*50}")
        print(f"  TOTAL: {grand_pass}/{grand_total} ({grand_pct:.1f}%)")

    # Write combined .md report
    if all_results:
        write_combined_report(all_results, benchmarks, "benchmarks/hardened")


if __name__ == '__main__':
    main()
