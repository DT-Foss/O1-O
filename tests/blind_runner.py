import os
import sys
import json
import time
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))
from forge import ForgeSession

class ForgeBlindBenchmark:
    def __init__(self, tasks_file: str = "tests/blind_tasks.json"):
        self.session = ForgeSession()
        # Enable Zero-Shot for benchmarking
        self.session.knowledge.zero_shot = True
        
        self.results = []
        self.output_dir = Path("benchmarks/blind")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.tasks_file = Path(tasks_file)
        if not self.tasks_file.exists():
            print(f"⚠️ Warning: {tasks_file} not found. Please provide it to run the benchmark.")
            self.tasks = []
        else:
            with open(self.tasks_file, "r") as f:
                self.tasks = json.load(f)

    def run(self):
        if not self.tasks:
            print("❌ No tasks to run.")
            return

        print(f"🕵️ FORGE V7 BLIND BENCHMARK: Starting {len(self.tasks)} unknown tests...\n")
        
        for task in self.tasks:
            print(f"[{task.get('tier', 'Unknown')}] {task.get('id', '?')}: {task['intent']}...")
            
            start_time = time.time()
            result = self.execute_task(task['intent'])
            duration = time.time() - start_time
            
            task_result = {
                "id": task.get("id", "?"),
                "tier": task.get("tier", "Unknown"),
                "intent": task["intent"],
                "success": result["success"],
                "iterations": result["iterations"],
                "duration": round(duration, 2),
                "error": result.get("error", "")
            }
            self.results.append(task_result)
            
            status = "✅ PASS" if result["success"] else "❌ FAIL"
            print(f"  Result: {status} ({result['iterations']} turns, {round(duration, 2)}s)\n")

        self.generate_report()

    def execute_task(self, prompt: str) -> Dict[str, Any]:
        """Runs the Forge logic with path re-ranking and debug loop (Zero-Shot)"""
        max_tries_per_path = 2
        
        intent = self.session.intent_parser.parse(prompt)
        candidate_chains = self.session.knowledge.infer(intent, top_k=3)
        
        if not candidate_chains:
            return {"success": False, "iterations": 1, "error": "No knowledge path found"}
        
        total_iterations = 0
        for path_idx, chain in enumerate(candidate_chains):
            # Attempt this path
            script = self.session.code_assembler.assemble(chain, intent)
            iterations = 0
            
            exec_result = self.session.executor.run(script, intent)
            iterations += 1
            total_iterations += 1
            
            if exec_result["success"]:
                return {"success": True, "iterations": total_iterations}
                
            # Internal Debug Loop for this path
            while iterations < max_tries_per_path:
                error_msg = exec_result.get("error", "UNKNOWN")
                fix_intent = {
                    "mode": "FIX",
                    "raw": f"fix this error: {error_msg}",
                    "entities": intent.get("entities", []),
                    "context_script": script,
                    "is_incremental": True
                }
                
                # For fixing, we still use the best fix path
                fix_chains = self.session.knowledge.infer(fix_intent, top_k=1)
                if not fix_chains: break
                    
                script = self.session.code_assembler.assemble(fix_chains[0], fix_intent)
                exec_result = self.session.executor.run(script, fix_intent)
                iterations += 1
                total_iterations += 1
                
                if exec_result["success"]:
                    return {"success": True, "iterations": total_iterations}
                    
        return {"success": False, "iterations": total_iterations, "error": exec_result.get("error", "All paths failed")}

    def generate_report(self):
        report_path = self.output_dir / "blind_results.json"
        with open(report_path, "w") as f:
            json.dump(self.results, f, indent=2)
            
        # Markdown Summary
        md_path = self.output_dir / "blind_summary.md"
        success_count = sum(1 for r in self.results if r["success"])
        total = len(self.results)
        pct = (success_count / total) * 100 if total > 0 else 0
        
        with open(md_path, "w") as f:
            f.write(f"# FORGE V7 Blind Benchmark Results\n\n")
            f.write(f"## Overall score: {success_count}/{total} ({round(pct, 1)}%)\n\n")
            f.write("| ID | Tier | Task | Success | Iterations | Time |\n")
            f.write("|----|------|------|---------|------------|------|\n")
            for r in self.results:
                status = "✅" if r["success"] else "❌"
                f.write(f"| {r['id']} | {r['tier']} | {r['intent']} | {status} | {r['iterations']} | {r['duration']}s |\n")
        
        print(f"📊 Blind Benchmark Summary saved to {md_path}")

if __name__ == "__main__":
    benchmark = ForgeBlindBenchmark()
    benchmark.run()
