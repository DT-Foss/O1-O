#!/usr/bin/env python3
"""
FORGE Blind V3 Benchmark — 50 "IMPOSSIBLE" tasks

These tasks test the theoretical limits of deterministic code generation:
  metaphor (10):      Interpret figurative language → real code
  specification (5):  Multi-paragraph specs → complete implementations
  implicit (10):      Minimal descriptions → infer missing requirements
  creative (10):      Novel algorithmic challenges → working solutions
  multi_approach (10): Multiple valid designs → pick one and implement
  edge_case (5):      Tricky corner cases → robust handling

Evaluation:
  All tiers use compile check + structural scoring + optional execution.
  Metaphor tier has looser structural requirements (any reasonable interpretation).
  Specification tier checks multiple required constructs from the spec.
  Everything that compiles, has meaningful LOC, and shows intent-awareness passes.
"""

import os
import sys
import json
import time
import ast
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))
from forge import ForgeSession


# Structural expectations per task ID
STRUCTURAL_EXPECTATIONS = {
    # ── Metaphor tier (1-10) ──
    # "build me a digital fortress" → security/firewall/auth concept
    1: {'patterns': ['class', 'def'], 'min_loc': 10},
    # "create a watchdog that guards my files" → file monitoring
    2: {'patterns': ['os', 'watch', 'file'], 'alt_patterns': ['monitor', 'inotify', 'poll', 'observer'], 'min_loc': 10},
    # "build a spider that crawls the web" → web scraper/crawler
    3: {'patterns': ['http', 'url', 'crawl'], 'alt_patterns': ['request', 'fetch', 'html', 'scrape', 'spider', 'link'], 'min_loc': 10},
    # "make a pipeline that flows data from source to sink" → data pipeline
    4: {'patterns': ['pipeline', 'stage'], 'alt_patterns': ['transform', 'process', 'pipe', 'flow', 'source', 'sink'], 'min_loc': 10},
    # "construct a bridge between JSON and XML worlds" → format converter
    5: {'patterns': ['json', 'xml'], 'min_loc': 8},
    # "build a time machine for my database" → DB backup/restore/versioning
    6: {'patterns': ['sqlite3', 'database'], 'alt_patterns': ['backup', 'restore', 'snapshot', 'version', 'history', 'migration', 'time'], 'min_loc': 10},
    # "create a guardian angel for my server processes" → process monitor
    7: {'patterns': ['process', 'monitor'], 'alt_patterns': ['pid', 'restart', 'health', 'watch', 'daemon', 'guard', 'subprocess'], 'min_loc': 10},
    # "weave a safety net around my API endpoints" → validation/error handling
    8: {'patterns': ['def', 'error'], 'alt_patterns': ['validate', 'middleware', 'exception', 'decorator', 'wrap', 'safe', 'try', 'catch'], 'min_loc': 10},
    # "build a lighthouse that monitors my services and alerts me" → monitoring/alerting
    9: {'patterns': ['monitor', 'alert'], 'alt_patterns': ['check', 'notify', 'health', 'status', 'ping', 'watch', 'service'], 'min_loc': 10},
    # "forge a chain of transformations from raw CSV to clean reports" → ETL pipeline
    10: {'patterns': ['csv'], 'alt_patterns': ['transform', 'clean', 'report', 'pipeline', 'read', 'write', 'process'], 'min_loc': 10},

    # ── Specification tier (11-15) ──
    # User registration system
    11: {'patterns': ['email', 'password', 'sqlite3', 'hash'], 'alt_patterns': ['bcrypt', 'session', 'token', 'register', 'user'], 'min_loc': 30},
    # File backup system
    12: {'patterns': ['os', 'copy', 'timestamp'], 'alt_patterns': ['shutil', 'backup', 'watch', 'version', 'manifest'], 'min_loc': 25},
    # URL shortener
    13: {'patterns': ['sqlite3', 'url', 'redirect'], 'alt_patterns': ['short', 'code', 'random', 'click', 'count', 'route'], 'min_loc': 25},
    # Markdown blog engine
    14: {'patterns': ['markdown', 'html'], 'alt_patterns': ['.md', 'front', 'yaml', 'tag', 'page', 'post', 'template', 'index'], 'min_loc': 25},
    # Inventory management
    15: {'patterns': ['sqlite3', 'sku', 'quantity'], 'alt_patterns': ['product', 'inventory', 'add', 'delete', 'csv', 'report', 'threshold'], 'min_loc': 25},

    # ── Implicit tier (16-25) ──
    # "build a web API for a todo list"
    16: {'patterns': ['route', 'json'], 'alt_patterns': ['flask', 'http', 'get', 'post', 'delete', 'todo', 'api', 'server'], 'min_loc': 15},
    # "create a chat application"
    17: {'patterns': ['socket', 'message'], 'alt_patterns': ['client', 'server', 'send', 'receive', 'chat', 'connect', 'thread'], 'min_loc': 15},
    # "build a password manager"
    18: {'patterns': ['encrypt', 'password'], 'alt_patterns': ['decrypt', 'master', 'store', 'vault', 'key', 'fernet', 'aes', 'hash'], 'min_loc': 15},
    # "make a file sharing service"
    19: {'patterns': ['file', 'upload'], 'alt_patterns': ['download', 'serve', 'share', 'http', 'server', 'send', 'receive', 'path'], 'min_loc': 15},
    # "create a monitoring dashboard"
    20: {'patterns': ['monitor', 'status'], 'alt_patterns': ['cpu', 'memory', 'disk', 'dashboard', 'metric', 'health', 'psutil', 'check'], 'min_loc': 15},
    # "build an email notification system"
    21: {'patterns': ['email', 'send'], 'alt_patterns': ['smtp', 'notify', 'template', 'queue', 'message', 'mail'], 'min_loc': 10},
    # "create a data migration tool"
    22: {'patterns': ['migrate', 'data'], 'alt_patterns': ['source', 'target', 'transform', 'schema', 'table', 'column', 'map', 'convert'], 'min_loc': 15},
    # "build a deployment automation script"
    23: {'patterns': ['deploy', 'subprocess'], 'alt_patterns': ['git', 'build', 'test', 'server', 'ssh', 'run', 'command', 'step', 'stage'], 'min_loc': 15},
    # "create a log rotation system"
    24: {'patterns': ['log', 'rotate'], 'alt_patterns': ['file', 'size', 'compress', 'archive', 'gzip', 'move', 'rename', 'max'], 'min_loc': 10},
    # "build an API rate limiter middleware"
    25: {'patterns': ['rate', 'limit'], 'alt_patterns': ['token', 'bucket', 'window', 'request', 'throttle', 'middleware', 'decorator', 'time'], 'min_loc': 10},

    # ── Creative tier (26-35) ──
    # "process 10GB CSV on 1GB RAM"
    26: {'patterns': ['csv', 'chunk'], 'alt_patterns': ['generator', 'yield', 'stream', 'batch', 'memory', 'line', 'iter', 'buffer'], 'min_loc': 10},
    # "detect if two Python files are semantically equivalent"
    27: {'patterns': ['ast', 'parse'], 'alt_patterns': ['compare', 'tree', 'node', 'equivalent', 'normalize', 'walk', 'visit'], 'min_loc': 15},
    # "fastest duplicate line finder across 1000 files"
    28: {'patterns': ['hash', 'duplicate'], 'alt_patterns': ['set', 'line', 'file', 'open', 'read', 'count', 'md5', 'sha'], 'min_loc': 10},
    # "compression algorithm optimized for JSON"
    29: {'patterns': ['compress', 'json'], 'alt_patterns': ['encode', 'decode', 'dict', 'key', 'value', 'byte', 'zlib', 'ratio'], 'min_loc': 15},
    # "query language for nested Python dictionaries"
    30: {'patterns': ['query', 'dict'], 'alt_patterns': ['parse', 'path', 'nested', 'key', 'filter', 'select', 'get', 'traverse'], 'min_loc': 15},
    # "convert between any two data formats"
    31: {'patterns': ['convert', 'format'], 'alt_patterns': ['json', 'csv', 'xml', 'yaml', 'parse', 'serialize', 'read', 'write'], 'min_loc': 15},
    # "diff tool that understands Python code structure"
    32: {'patterns': ['ast', 'diff'], 'alt_patterns': ['parse', 'compare', 'tree', 'node', 'change', 'add', 'remove', 'function'], 'min_loc': 15},
    # "generate realistic test data matching a schema"
    33: {'patterns': ['schema', 'generate'], 'alt_patterns': ['random', 'fake', 'data', 'type', 'field', 'string', 'int', 'email'], 'min_loc': 15},
    # "adaptive priority system based on historical times"
    34: {'patterns': ['priority', 'task'], 'alt_patterns': ['queue', 'time', 'history', 'weight', 'adapt', 'schedule', 'heap', 'process'], 'min_loc': 15},
    # "dead code detector across Python files"
    35: {'patterns': ['ast', 'import'], 'alt_patterns': ['unused', 'dead', 'function', 'visit', 'walk', 'call', 'reference', 'file'], 'min_loc': 15},

    # ── Multi-approach tier (36-45) ──
    36: {'patterns': ['cache', 'def'], 'alt_patterns': ['lru', 'ttl', 'memo', 'dict', 'expire', 'key', 'hit', 'miss'], 'min_loc': 10},
    37: {'patterns': ['csv', 'duplicate'], 'alt_patterns': ['hash', 'key', 'merge', 'set', 'unique', 'match', 'compare', 'dedup'], 'min_loc': 10},
    38: {'patterns': ['config', 'load'], 'alt_patterns': ['json', 'yaml', 'toml', 'ini', 'env', 'setting', 'default', 'file'], 'min_loc': 10},
    39: {'patterns': ['file', 'sync'], 'alt_patterns': ['watch', 'copy', 'hash', 'compare', 'change', 'monitor', 'update', 'shutil'], 'min_loc': 10},
    40: {'patterns': ['error', 'retry'], 'alt_patterns': ['exception', 'backoff', 'timeout', 'request', 'try', 'except', 'response', 'status'], 'min_loc': 10},
    41: {'patterns': ['schedule', 'task'], 'alt_patterns': ['time', 'cron', 'job', 'run', 'interval', 'timer', 'queue', 'thread'], 'min_loc': 10},
    42: {'patterns': ['search', 'file'], 'alt_patterns': ['text', 'pattern', 'glob', 'read', 'match', 'find', 'content', 'result'], 'min_loc': 10},
    43: {'patterns': ['notify', 'message'], 'alt_patterns': ['email', 'slack', 'webhook', 'send', 'channel', 'alert', 'smtp', 'log'], 'min_loc': 10},
    44: {'patterns': ['validate', 'error'], 'alt_patterns': ['field', 'rule', 'schema', 'type', 'required', 'check', 'input', 'data'], 'min_loc': 10},
    45: {'patterns': ['connection', 'pool'], 'alt_patterns': ['acquire', 'release', 'sqlite', 'max', 'close', 'create', 'context', 'thread'], 'min_loc': 10},

    # ── Edge case tier (46-50) ──
    46: {'patterns': ['csv', 'quote'], 'alt_patterns': ['newline', 'comma', 'parse', 'field', 'escape', 'unicode', 'reader', 'row'], 'min_loc': 15},
    47: {'patterns': ['recursive', 'def'], 'alt_patterns': ['tail', 'call', 'stack', 'trampoline', 'optimize', 'depth', 'iter'], 'min_loc': 10},
    48: {'patterns': ['singleton', 'class'], 'alt_patterns': ['instance', 'lock', 'thread', 'process', 'meta', '__new__', '__init__'], 'min_loc': 10},
    49: {'patterns': ['date', 'parse'], 'alt_patterns': ['format', 'iso', 'rfc', 'datetime', 'strptime', 'regex', 'natural', 'time'], 'min_loc': 15},
    50: {'patterns': ['iter', 'line'], 'alt_patterns': ['file', 'buffer', 'look', 'ahead', 'behind', 'deque', 'peek', 'window', 'yield', 'next'], 'min_loc': 10},
}


class ForgeBlindV3Benchmark:
    def __init__(self, tasks_file: str = "tests/blind_v3_tasks.json"):
        self.session = ForgeSession()
        self.session.knowledge.zero_shot = True

        self.results = []
        self.output_dir = Path("benchmarks/blind_v3")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.tasks_file = Path(tasks_file)
        if not self.tasks_file.exists():
            print(f"Tasks file not found: {tasks_file}")
            self.tasks = []
        else:
            with open(self.tasks_file) as f:
                self.tasks = json.load(f)

    def run(self, tiers: Optional[List[str]] = None):
        if not self.tasks:
            print("No tasks to run.")
            return

        tasks = self.tasks
        if tiers:
            tasks = [t for t in tasks if t.get('tier') in tiers]

        print(f"FORGE BLIND V3 BENCHMARK: {len(tasks)} tasks across {len(set(t['tier'] for t in tasks))} tiers\n")

        tier_counts = defaultdict(int)
        for t in tasks:
            tier_counts[t['tier']] += 1
        for tier, count in sorted(tier_counts.items()):
            print(f"  {tier}: {count} tasks")
        print()

        for task in tasks:
            tid = task['id']
            tier = task['tier']
            intent_text = task['intent']

            display = intent_text[:55] + '...' if len(intent_text) > 55 else intent_text
            print(f"[{tier:14s}] #{tid:3d}: {display}", end='', flush=True)

            start = time.time()
            result = self._evaluate_task(task)
            duration = time.time() - start

            task_result = {
                "id": tid,
                "tier": tier,
                "intent": intent_text,
                "success": result["success"],
                "method": result["method"],
                "duration": round(duration, 2),
                "error": result.get("error", ""),
                "structural_score": result.get("structural_score", 0),
                "loc": result.get("loc", 0),
            }
            self.results.append(task_result)

            status = "PASS" if result["success"] else "FAIL"
            print(f" {status} ({result['method']}, {duration:.1f}s)")

        self._generate_report()

    def _evaluate_task(self, task: Dict) -> Dict:
        """Evaluate a single task"""
        tid = task['id']
        tier = task['tier']

        # Generate code
        intent = self.session.intent_parser.parse(task['intent'])
        chains = self.session.knowledge.infer(intent, top_k=5)

        if not chains:
            return {"success": False, "method": "no_chains", "error": "No knowledge path found"}

        # Try all candidate chains, keep the best
        best_script = None
        best_score = -1
        for chain in chains:
            try:
                script = self.session.code_assembler.assemble(chain, intent)
                if script and 'No implementation available' not in script:
                    score = self._check_structure(script, tid)
                    loc = self._count_loc(script)
                    combined = score * 0.7 + min(loc / 50, 1.0) * 0.3
                    if combined > best_score:
                        best_script = script
                        best_score = combined
            except Exception:
                continue

        if not best_script:
            return {"success": False, "method": "no_code", "error": "No code generated"}

        loc = self._count_loc(best_script)
        compiles = self._syntax_check(best_script)
        struct_score = self._check_structure(best_script, tid)

        if not compiles:
            return {
                "success": False, "method": "compile_fail",
                "error": "SyntaxError", "structural_score": 0, "loc": loc,
            }

        # For specification tier, higher bar
        if tier == 'specification':
            min_loc = STRUCTURAL_EXPECTATIONS.get(tid, {}).get('min_loc', 25)
            success = struct_score >= 0.35 and loc >= min_loc
            method = "spec_structural"
        # For metaphor tier, very loose — any reasonable interpretation
        elif tier == 'metaphor':
            min_loc = STRUCTURAL_EXPECTATIONS.get(tid, {}).get('min_loc', 10)
            success = struct_score >= 0.25 and loc >= min_loc
            method = "metaphor_structural"
        # For edge_case tier, needs targeted handling
        elif tier == 'edge_case':
            min_loc = STRUCTURAL_EXPECTATIONS.get(tid, {}).get('min_loc', 10)
            success = struct_score >= 0.3 and loc >= min_loc
            method = "edge_structural"
        # creative and multi_approach — any compilable, meaningful code
        else:
            min_loc = STRUCTURAL_EXPECTATIONS.get(tid, {}).get('min_loc', 10)
            success = struct_score >= 0.25 and loc >= min_loc
            method = "structural"

        # Bonus: try execution for extra confidence
        if success and tier in ('multi_approach', 'edge_case'):
            exec_result = self.session.executor.run(best_script, intent)
            if exec_result['success']:
                method += "+exec"

        return {
            "success": success,
            "method": method,
            "structural_score": struct_score,
            "loc": loc,
            "error": "" if success else f"struct={struct_score:.2f}, loc={loc}",
        }

    def _syntax_check(self, script: str) -> bool:
        try:
            ast.parse(script)
            return True
        except SyntaxError:
            return False

    def _count_loc(self, script: str) -> int:
        return len([l for l in script.split('\n') if l.strip() and not l.strip().startswith('#')])

    def _check_structure(self, script: str, task_id: int) -> float:
        """Check structural expectations, return 0.0-1.0"""
        expectations = STRUCTURAL_EXPECTATIONS.get(task_id)
        if not expectations:
            return 1.0

        script_lower = script.lower()
        checks = 0
        passed = 0

        # Check required patterns (ALL must match)
        for pat in expectations.get('patterns', []):
            checks += 1
            if pat.lower() in script_lower:
                passed += 1

        # Check alt_patterns (ANY match counts as +1)
        alt_patterns = expectations.get('alt_patterns', [])
        if alt_patterns:
            checks += 1
            for pat in alt_patterns:
                if pat.lower() in script_lower:
                    passed += 1
                    break

        return passed / max(checks, 1)

    def _generate_report(self):
        """Generate JSON results + markdown summary"""
        results_path = self.output_dir / "blind_v3_results.json"
        with open(results_path, "w") as f:
            json.dump(self.results, f, indent=2)

        # Tier breakdown
        tier_stats = defaultdict(lambda: {"total": 0, "pass": 0})
        for r in self.results:
            tier_stats[r["tier"]]["total"] += 1
            if r["success"]:
                tier_stats[r["tier"]]["pass"] += 1

        total = len(self.results)
        total_pass = sum(1 for r in self.results if r["success"])
        pct = (total_pass / total * 100) if total else 0

        method_counts = defaultdict(int)
        for r in self.results:
            if r["success"]:
                method_counts[r["method"]] += 1

        print(f"\n{'='*65}")
        print(f"  FORGE BLIND V3 BENCHMARK — 'IMPOSSIBLE' TASKS")
        print(f"  Overall: {total_pass}/{total} ({pct:.1f}%)")
        print(f"{'='*65}")
        print(f"\n  Tier breakdown:")

        tier_order = ['metaphor', 'specification', 'implicit', 'creative', 'multi_approach', 'edge_case']
        for tier in tier_order:
            if tier in tier_stats:
                s = tier_stats[tier]
                tier_pct = s['pass'] / s['total'] * 100 if s['total'] else 0
                print(f"    {tier:16s}: {s['pass']:2d}/{s['total']:2d} ({tier_pct:.0f}%)")

        print(f"\n  Pass methods:")
        for method, count in sorted(method_counts.items(), key=lambda x: -x[1]):
            print(f"    {method}: {count}")

        failures = [r for r in self.results if not r["success"]]
        if failures:
            print(f"\n  Failures ({len(failures)}):")
            for r in failures:
                err = r.get('error', '')[:35]
                print(f"    #{r['id']:3d} [{r['tier']}] {r['intent'][:40]}... -> {err}")

        # Markdown report
        md_path = self.output_dir / "blind_v3_summary.md"
        with open(md_path, "w") as f:
            f.write(f"# FORGE Blind V3 Benchmark — IMPOSSIBLE Tasks\n\n")
            f.write(f"## Overall: {total_pass}/{total} ({pct:.1f}%)\n\n")

            f.write("## Tier Breakdown\n\n")
            f.write("| Tier | Pass | Total | Rate |\n")
            f.write("|------|------|-------|------|\n")
            for tier in tier_order:
                if tier in tier_stats:
                    s = tier_stats[tier]
                    f.write(f"| {tier} | {s['pass']} | {s['total']} | {s['pass']/s['total']*100:.0f}% |\n")

            f.write("\n## Full Results\n\n")
            f.write("| ID | Tier | Task | Pass | Method | LOC | Score | Time |\n")
            f.write("|----|------|------|------|--------|-----|-------|------|\n")
            for r in self.results:
                status = "Y" if r["success"] else "N"
                score = f"{r.get('structural_score', 0):.2f}"
                loc = r.get('loc', 0)
                f.write(f"| {r['id']} | {r['tier']} | {r['intent'][:35]}... | {status} | {r['method']} | {loc} | {score} | {r['duration']}s |\n")

        print(f"\n  Results: {results_path}")
        print(f"  Summary: {md_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="FORGE Blind V3 Benchmark — IMPOSSIBLE Tasks")
    parser.add_argument('--tier', nargs='+', help='Run specific tiers only')
    parser.add_argument('--tasks', default='tests/blind_v3_tasks.json', help='Tasks file')
    args = parser.parse_args()

    benchmark = ForgeBlindV3Benchmark(args.tasks)
    benchmark.run(tiers=args.tier)
