"""Autonomous Hunt Loop: Full cycle target analysis and fuzzing.

Picks targets from queue, generates harnesses, fuzzes, triages crashes,
classifies primitives, stores findings, and moves to next target.
Runs autonomously without human input.

Part of FORGE Phase N: Autonomous Hunt Loop.
"""
# Dependencies: crash_analyzer, finding_aggregator, fuzz_generator, platform_adapter, target_queue
# Depended by: none (leaf module)

import json
import os
import time
import subprocess
import tempfile
import hashlib
import shutil
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path


# ─── Hunt Loop ──────────────────────────────────────────────────────

class HuntLoop:
    """Autonomous hunting engine.

    Cycle:
    1. Pick highest-priority target from queue
    2. Analyze binary (platform_adapter)
    3. Generate fuzz harness (fuzz_generator)
    4. Run fuzzer for N iterations
    5. Triage any crashes (crash_analyzer)
    6. Classify exploit primitives
    7. Store findings (finding_aggregator)
    8. Update target status and move to next
    """

    def __init__(self, work_dir: str = '/tmp/forge_hunt'):
        self.work_dir = work_dir
        os.makedirs(work_dir, exist_ok=True)

        # Lazy imports to avoid circular deps
        self._queue = None
        self._aggregator = None
        self._adapter = None

        # Runtime stats
        self.cycles = 0
        self.total_crashes = 0
        self.total_findings = 0
        self.start_time = 0
        self.running = False
        self.log = []

    @property
    def queue(self):
        if self._queue is None:
            from core.target_queue import TargetQueue
            self._queue = TargetQueue()
        return self._queue

    @property
    def aggregator(self):
        if self._aggregator is None:
            from core.finding_aggregator import FindingAggregator
            self._aggregator = FindingAggregator()
        return self._aggregator

    @property
    def adapter(self):
        if self._adapter is None:
            from core.platform_adapter import PlatformAdapter
            self._adapter = PlatformAdapter()
        return self._adapter

    def _log(self, msg: str, level: str = 'info'):
        entry = {'time': time.time(), 'level': level, 'msg': msg}
        self.log.append(entry)
        if len(self.log) > 1000:
            self.log = self.log[-500:]

    # ─── Single Cycle ────────────────────────────────────────────

    def run_cycle(self) -> dict:
        """Run one complete hunt cycle. Returns cycle report."""
        self.cycles += 1
        cycle_start = time.time()
        report = {
            'cycle': self.cycles,
            'target': None,
            'analysis': None,
            'fuzz_results': None,
            'crashes': 0,
            'findings': [],
            'duration': 0,
            'status': 'started',
        }

        # Step 1: Pick target
        target = self.queue.next()
        if not target:
            report['status'] = 'no_targets'
            self._log("No targets in queue", 'warn')
            return report

        report['target'] = {
            'name': target.name,
            'path': target.path,
            'platform': target.platform,
            'priority': target.priority,
        }
        self._log(f"Cycle {self.cycles}: target={target.name} (pri={target.priority:.1f})")

        # Step 2: Analyze binary
        binary_info = None
        if os.path.isfile(target.path):
            binary_info = self.adapter.analyze(target.path)
            report['analysis'] = {
                'format': binary_info.format,
                'arch': binary_info.arch,
                'security_score': binary_info.security_score(),
                'sections': len(binary_info.sections),
                'libraries': len(binary_info.libraries),
            }
            self._log(f"  Analyzed: {binary_info.format} {binary_info.arch} "
                       f"score={binary_info.security_score()}")

            # Generate analysis triplets
            triplets = self.adapter.to_triplets(binary_info)
            report['triplets_generated'] = len(triplets)

        # Step 3: Generate fuzzer
        harness_code = self._generate_harness(target, binary_info)
        if not harness_code:
            report['status'] = 'harness_failed'
            self.queue.fail(target.id, 'harness generation failed')
            return report

        # Step 4: Run fuzzer
        fuzz_results = self._run_fuzzer(target, harness_code)
        report['fuzz_results'] = fuzz_results

        # Step 5: Triage crashes
        if fuzz_results.get('crashes'):
            crashes = self._triage_crashes(target, fuzz_results['crash_dir'])
            report['crashes'] = len(crashes)
            self.total_crashes += len(crashes)

            # Step 6: Store findings
            for crash in crashes:
                from core.finding_aggregator import Finding
                finding = Finding(
                    target_id=target.id,
                    target_name=target.name,
                    target_path=target.path,
                    primitive_type=crash.get('primitive', 'unknown'),
                    severity=crash.get('severity', 'medium'),
                    confidence=crash.get('confidence', 0.5),
                    title=crash.get('title', f'Crash in {target.name}'),
                    signal=crash.get('signal', ''),
                    fault_address=crash.get('fault_address', 0),
                    faulting_function=crash.get('function', ''),
                    stack_trace=crash.get('stack_trace', ''),
                    platform=target.platform,
                    arch=target.arch,
                    found_by='hunt_loop',
                    input_file=crash.get('input_file', ''),
                )
                is_new, fid = self.aggregator.add(finding)
                if is_new:
                    self.total_findings += 1
                    report['findings'].append({
                        'id': fid,
                        'primitive': finding.primitive_type,
                        'title': finding.title,
                    })
                    self._log(f"  NEW FINDING: {finding.primitive_type} — "
                              f"{finding.title}", 'critical')

        # Step 7: Update target
        self.queue.complete(target.id, findings=len(report['findings']))

        report['duration'] = round(time.time() - cycle_start, 2)
        report['status'] = 'completed'
        self._log(f"  Cycle {self.cycles} done: {len(report['findings'])} findings "
                   f"in {report['duration']}s")

        return report

    # ─── Multi-Cycle Run ─────────────────────────────────────────

    def run(self, cycles: int = 10, callback=None) -> dict:
        """Run multiple hunt cycles.

        Args:
            cycles: Number of cycles to run
            callback: Optional function called after each cycle with report

        Returns:
            Summary of all cycles
        """
        self.start_time = time.time()
        self.running = True
        reports = []

        try:
            for i in range(cycles):
                if not self.running:
                    break

                report = self.run_cycle()
                reports.append(report)

                if callback:
                    callback(report)

                # No targets left
                if report['status'] == 'no_targets':
                    # Try requeuing
                    self.queue.requeue_all()
                    if not self.queue.list_queued(1):
                        self._log("Queue exhausted, stopping", 'warn')
                        break
        finally:
            self.running = False

        total_time = time.time() - self.start_time
        return {
            'cycles_run': len(reports),
            'cycles_requested': cycles,
            'total_crashes': sum(r['crashes'] for r in reports),
            'total_findings': sum(len(r.get('findings', [])) for r in reports),
            'targets_processed': sum(1 for r in reports if r['status'] == 'completed'),
            'duration': round(total_time, 2),
            'cycles_per_minute': round(len(reports) / max(total_time / 60, 0.01), 1),
            'reports': reports,
        }

    def stop(self):
        """Stop the hunt loop gracefully."""
        self.running = False

    # ─── Internal: Harness Generation ────────────────────────────

    def _generate_harness(self, target, binary_info) -> Optional[str]:
        """Generate a fuzz harness for the target."""
        try:
            from core.fuzz_generator import FuzzGenerator
            gen = FuzzGenerator()

            # Determine best harness type
            vuln_type = 'buffer_overflow'  # Default
            harness_type = 'python_mutator'

            # Use binary analysis to pick better harness
            if binary_info:
                if not binary_info.stack_canary:
                    vuln_type = 'buffer_overflow'
                elif binary_info.rwx_sections > 0:
                    vuln_type = 'code_injection'
                elif binary_info.format == 'macho':
                    vuln_type = 'macho'
                    harness_type = 'macho_fuzzer'

            context = {
                'binary': target.path,
                'function': 'main',
                'input_type': 'file',
                'target_name': target.name,
            }

            code = gen.generate(vuln_type, context, harness_type)
            self._log(f"  Generated {harness_type} harness ({len(code)} chars)")
            return code

        except Exception as e:
            self._log(f"  Harness generation failed: {e}", 'error')
            return None

    def _run_fuzzer(self, target, harness_code: str) -> dict:
        """Run the generated fuzzer and collect crashes."""
        result = {
            'iterations': 0,
            'crashes': 0,
            'crash_dir': '',
            'duration': 0,
        }

        # Create work directory for this cycle
        cycle_dir = os.path.join(self.work_dir, f"cycle_{self.cycles}")
        crash_dir = os.path.join(cycle_dir, "crashes")
        os.makedirs(crash_dir, exist_ok=True)
        result['crash_dir'] = crash_dir

        # Write harness
        harness_path = os.path.join(cycle_dir, "harness.py")
        with open(harness_path, 'w') as f:
            f.write(harness_code)

        # Run harness in subprocess with timeout
        start = time.time()
        try:
            proc = subprocess.run(
                ['python3', harness_path],
                capture_output=True, text=True,
                timeout=30,  # 30 second timeout per cycle
                cwd=cycle_dir,
                env={**os.environ, 'FUZZ_CRASH_DIR': crash_dir}
            )
            result['duration'] = round(time.time() - start, 2)

            # Check for crashes (files in crash_dir)
            if os.path.isdir(crash_dir):
                crash_files = [f for f in os.listdir(crash_dir) if f.startswith('crash_')]
                result['crashes'] = len(crash_files)

            # Parse iteration count from output
            for line in proc.stdout.split('\n'):
                if 'iterations' in line.lower() or 'cycle' in line.lower():
                    import re
                    nums = re.findall(r'\d+', line)
                    if nums:
                        result['iterations'] = int(nums[-1])

            self._log(f"  Fuzzer ran: {result['iterations']} iterations, "
                       f"{result['crashes']} crashes in {result['duration']}s")

        except subprocess.TimeoutExpired:
            result['duration'] = 30
            self._log(f"  Fuzzer timed out after 30s")
        except Exception as e:
            self._log(f"  Fuzzer error: {e}", 'error')

        return result

    def _triage_crashes(self, target, crash_dir: str) -> List[dict]:
        """Triage crashes using crash_analyzer."""
        crashes = []

        if not os.path.isdir(crash_dir):
            return crashes

        crash_files = [os.path.join(crash_dir, f)
                       for f in os.listdir(crash_dir)
                       if f.startswith('crash_')]

        if not crash_files:
            return crashes

        try:
            from core.crash_analyzer import CrashAnalyzer
            analyzer = CrashAnalyzer()

            for cf in crash_files[:20]:  # Cap at 20 crashes per cycle
                try:
                    analysis = analyzer.analyze_any(cf)
                    if analysis:
                        crash = {
                            'primitive': analysis.get('primitive', {}).get('type', 'dos'),
                            'severity': analysis.get('severity', 'medium'),
                            'confidence': analysis.get('primitive', {}).get('confidence', 0.5),
                            'title': f"{analysis.get('signal', 'crash')} in "
                                     f"{analysis.get('process', target.name)}",
                            'signal': analysis.get('signal', ''),
                            'fault_address': analysis.get('fault_address', 0),
                            'function': analysis.get('faulting_frame', {}).get('symbol', ''),
                            'stack_trace': '\n'.join(
                                f.get('symbol', '') for f in
                                analysis.get('crashed_thread_frames', [])[:10]
                            ),
                            'input_file': cf,
                        }
                        crashes.append(crash)
                except Exception:
                    # Not a recognized crash format, skip
                    pass

        except ImportError:
            self._log("  crash_analyzer not available for triage", 'warn')

        return crashes

    # ─── Status & Metrics ────────────────────────────────────────

    def status(self) -> dict:
        """Current hunt loop status."""
        q_stats = self.queue.stats()
        f_stats = self.aggregator.stats()

        runtime = time.time() - self.start_time if self.start_time else 0
        cpm = self.cycles / max(runtime / 60, 0.01) if runtime > 0 else 0

        return {
            'running': self.running,
            'cycles_completed': self.cycles,
            'cycles_per_minute': round(cpm, 1),
            'total_crashes': self.total_crashes,
            'total_findings': self.total_findings,
            'runtime_seconds': round(runtime, 1),
            'queue': q_stats,
            'findings': f_stats,
            'recent_log': self.log[-10:],
        }

    def format_status(self) -> str:
        """Human-readable status."""
        s = self.status()
        lines = [
            f"HUNT LOOP — {'RUNNING' if s['running'] else 'STOPPED'}",
            f"  Cycles:    {s['cycles_completed']}",
            f"  Speed:     {s['cycles_per_minute']} cycles/min",
            f"  Crashes:   {s['total_crashes']}",
            f"  Findings:  {s['total_findings']}",
            f"  Runtime:   {s['runtime_seconds']}s",
            f"",
            f"  Queue:     {s['queue']['queued']} queued, "
            f"{s['queue']['active']} active, "
            f"{s['queue']['completed']} done",
            f"  Total:     {s['findings']['total']} findings in DB",
        ]

        if s['recent_log']:
            lines.append(f"")
            lines.append(f"  Recent:")
            for entry in s['recent_log'][-5:]:
                lines.append(f"    [{entry['level']}] {entry['msg']}")

        return '\n'.join(lines)

    # ─── Cleanup ─────────────────────────────────────────────────

    def cleanup(self, keep_crashes: bool = True):
        """Clean up work directory."""
        if os.path.isdir(self.work_dir):
            if keep_crashes:
                # Only remove harness files, keep crash inputs
                for d in os.listdir(self.work_dir):
                    full = os.path.join(self.work_dir, d)
                    if os.path.isdir(full):
                        harness = os.path.join(full, 'harness.py')
                        if os.path.isfile(harness):
                            os.unlink(harness)
            else:
                shutil.rmtree(self.work_dir, ignore_errors=True)
                os.makedirs(self.work_dir, exist_ok=True)
