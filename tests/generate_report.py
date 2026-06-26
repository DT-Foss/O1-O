#!/usr/bin/env python3
"""
FORGE Verification Report Generator

Generates a detailed .md report with full generated code, execution output,
and verification details for every single task. Nothing hidden.
"""

import sys
import json
import time
import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from forge import ForgeSession

sys.path.insert(0, str(Path(__file__).parent))
from forge_validator import ForgeValidator, UnifiedBenchmarkRunner


def generate_report(benchmarks_to_run, output_path):
    """Generate a comprehensive verification report."""
    session = ForgeSession()
    session.knowledge.zero_shot = True
    validator = ForgeValidator()
    runner = UnifiedBenchmarkRunner(session, output_dir="benchmarks/hardened")

    now = datetime.datetime.now()
    all_entries = []
    section_stats = {}

    for section_name, tasks_file in benchmarks_to_run:
        tasks_path = Path(tasks_file)
        if not tasks_path.exists():
            print(f"Skipping {section_name}: {tasks_file} not found")
            continue

        with open(tasks_path) as f:
            tasks = json.load(f)

        print(f"\n{'='*70}")
        print(f"  {section_name} — {len(tasks)} tasks")
        print(f"{'='*70}\n")

        section_passed = 0
        section_total = 0

        for task in tasks:
            tid = task.get('id', 0)
            intent = task.get('intent', '')
            display = intent[:60] + '...' if len(intent) > 60 else intent
            print(f"  [{tid:3d}] {display}", end='', flush=True)

            start = time.time()

            # Generate code
            script = runner._generate_code(task)
            duration = round(time.time() - start, 2)

            entry = {
                'section': section_name,
                'id': tid,
                'intent': intent,
                'duration': duration,
            }

            if script is None:
                entry['status'] = 'FAIL'
                entry['method'] = 'no_code'
                entry['error'] = 'No code generated'
                entry['code'] = None
                entry['output'] = ''
                entry['loc'] = 0
                print(f" FAIL (no code, {duration:.1f}s)")
            else:
                val_result = validator.validate(script, task, timeout=10)
                quality = val_result.get('quality', {})

                entry['status'] = 'PASS' if val_result['success'] else 'FAIL'
                entry['method'] = val_result['method']
                entry['error'] = val_result.get('error', '')
                entry['code'] = script
                entry['output'] = val_result.get('output', '')
                entry['loc'] = quality.get('real_loc', 0)

                status = entry['status']
                print(f" {status} ({entry['method']}, {entry['loc']} LOC, {duration:.1f}s)")

            all_entries.append(entry)
            section_total += 1
            if entry['status'] == 'PASS':
                section_passed += 1

        section_stats[section_name] = (section_passed, section_total)
        pct = 100 * section_passed / section_total if section_total else 0
        print(f"\n  {section_name}: {section_passed}/{section_total} ({pct:.1f}%)")

    # Write report
    total_pass = sum(v[0] for v in section_stats.values())
    total_all = sum(v[1] for v in section_stats.values())
    total_pct = 100 * total_pass / total_all if total_all else 0

    with open(output_path, 'w') as f:
        f.write(f"# FORGE Output Verification Report\n\n")
        f.write(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')}  \n")
        f.write(f"**Tasks:** {total_all}  \n")
        f.write(f"**Passed:** {total_pass}/{total_all} ({total_pct:.1f}%)  \n")
        f.write(f"**Method:** Deterministic code generation (zero AI, zero LLM)  \n")
        f.write(f"**Validation:** Real execution in sandboxed subprocess  \n\n")
        f.write(f"---\n\n")

        # Summary table
        f.write(f"## Results Overview\n\n")
        f.write(f"| Campaign | Passed | Total | Rate |\n")
        f.write(f"|----------|--------|-------|------|\n")
        for name, (p, t) in section_stats.items():
            pct = 100 * p / t if t else 0
            f.write(f"| {name} | {p} | {t} | {pct:.1f}% |\n")
        f.write(f"| **Total** | **{total_pass}** | **{total_all}** | **{total_pct:.1f}%** |\n\n")
        f.write(f"---\n\n")

        # Detail for every task
        current_section = None
        for entry in all_entries:
            if entry['section'] != current_section:
                current_section = entry['section']
                sp, st = section_stats[current_section]
                spct = 100 * sp / st if st else 0
                f.write(f"# {current_section} — {sp}/{st} ({spct:.1f}%)\n\n")

            status_icon = "PASS" if entry['status'] == 'PASS' else "FAIL"
            f.write(f"## Task {entry['id']}: {status_icon}\n\n")
            f.write(f"**Prompt:** {entry['intent']}  \n")
            f.write(f"**Result:** {entry['status']} | Method: `{entry['method']}` | ")
            f.write(f"LOC: {entry['loc']} | Time: {entry['duration']}s\n\n")

            if entry['error']:
                f.write(f"**Error:** `{entry['error'][:200]}`\n\n")

            if entry['output']:
                output_lines = entry['output'].strip()
                # Truncate very long output
                if len(output_lines) > 1500:
                    output_lines = output_lines[:1500] + '\n... (truncated)'
                f.write(f"**Execution Output:**\n```\n{output_lines}\n```\n\n")

            if entry['code']:
                code = entry['code']
                # Show full code for shorter scripts, truncate very long ones
                if len(code) > 8000:
                    code_lines = code.split('\n')
                    # Show first 80 and last 20 lines
                    if len(code_lines) > 120:
                        shown = '\n'.join(code_lines[:80])
                        shown += f'\n\n# ... ({len(code_lines) - 100} lines omitted) ...\n\n'
                        shown += '\n'.join(code_lines[-20:])
                        code = shown

                f.write(f"**Generated Code ({entry['loc']} lines):**\n")
                f.write(f"```python\n{code}\n```\n\n")

            f.write(f"---\n\n")

    print(f"\n{'='*70}")
    print(f"  REPORT: {output_path}")
    print(f"  {total_pass}/{total_all} ({total_pct:.1f}%)")
    print(f"{'='*70}")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="FORGE Verification Report")
    parser.add_argument('--benchmark', choices=['cir', 'v4', 'cir+v4', 'all'],
                        default='cir+v4')
    parser.add_argument('--output', type=str, default=None)
    args = parser.parse_args()

    benchmarks = []
    if args.benchmark in ('cir', 'cir+v4', 'all'):
        benchmarks.append(('Red Team (60 tasks)', 'tests/cir_red_tasks.json'))
        benchmarks.append(('Blue Team (35 tasks)', 'tests/cir_blue_tasks.json'))
    if args.benchmark in ('v4', 'cir+v4', 'all'):
        benchmarks.append(('General Python (104 tasks)', 'tests/blind_v4_tasks.json'))
    if args.benchmark == 'all':
        benchmarks.append(('Blind V2 (100 tasks)', 'tests/blind_v2_tasks.json'))
        benchmarks.append(('Impossible V3 (50 tasks)', 'tests/blind_v3_tasks.json'))

    if args.output:
        out = args.output
    else:
        date = datetime.datetime.now().strftime('%Y-%m-%d')
        out = f'FORGE_VERIFICATION_{date}.md'

    generate_report(benchmarks, out)
