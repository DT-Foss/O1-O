import os
import json
import time
from pathlib import Path
from typing import List, Dict, Any
from forge import ForgeSession

class ForgeBenchmark:
    def __init__(self):
        self.session = ForgeSession()
        self.results = []
        self.output_dir = Path("benchmarks")
        self.output_dir.mkdir(exist_ok=True)
        
        # Test Case Definition
        self.tasks = [
            # TIER 1: EASY (System & I/O)
            {"id": "E1", "tier": "Easy", "intent": "list all python files in the current directory recursively"},
            {"id": "E2", "tier": "Easy", "intent": "read a file named 'README.md' and print the first 50 characters"},
            {"id": "E3", "tier": "Easy", "intent": "calculate the sha256 hash of the string 'FORGE'"},
            {"id": "E4", "tier": "Easy", "intent": "write a list of numbers from 1 to 10 to a file called 'numbers.txt'"},
            {"id": "E5", "tier": "Easy", "intent": "get the size of the 'forge.py' file in bytes"},
            
            # TIER 2: MEDIUM (Web & Data)
            {"id": "M1", "tier": "Medium", "intent": "scrape https://example.com and print all h1 tags"},
            {"id": "M2", "tier": "Medium", "intent": "download the content of https://www.google.com and save it to 'google.html'"},
            {"id": "M3", "tier": "Medium", "intent": "create a json file 'data.json' with keys name, version, and author"},
            {"id": "M4", "tier": "Medium", "intent": "read 'data.json' and update the version to '2.0.0'"},
            {"id": "M5", "tier": "Medium", "intent": "sort a list of dictionaries by the 'id' key"},
            
            # TIER 3: HARD (Logic & State)
            {"id": "H1", "tier": "Hard", "intent": "create a sqlite database 'audit.db' with a table logs (msg, time)"},
            {"id": "H2", "tier": "Hard", "intent": "save 'Hello World' with current timestamp to 'audit.db'"},
            {"id": "H3", "tier": "Hard", "intent": "find all '.causal' files and count how many exist"},
            {"id": "H4", "tier": "Hard", "intent": "convert a markdown table string to a list of dicts"},
            {"id": "H5", "tier": "Hard", "intent": "check if a port 8080 is open on localhost"}
        ]

    def run(self):
        print(f"🚀 FORGE V5 BENCHMARK: Starting {len(self.tasks)} tests...\n")
        
        for task in self.tasks:
            print(f"[{task['tier']}] {task['id']}: {task['intent']}...")
            
            start_time = time.time()
            # Simulation of REPL interaction
            # Note: We use the session logic but skip input()
            result = self.execute_task(task['intent'])
            duration = time.time() - start_time
            
            task_result = {
                "id": task["id"],
                "tier": task["tier"],
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
        """Runs the Forge logic with path re-ranking and debug loop"""
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
        report_path = self.output_dir / "benchmark_results.json"
        with open(report_path, "w") as f:
            json.dump(self.results, f, indent=2)
            
        # Markdown Summary
        md_path = self.output_dir / "summary.md"
        success_count = sum(1 for r in self.results if r["success"])
        total = len(self.results)
        pct = (success_count / total) * 100 if total > 0 else 0
        
        with open(md_path, "w") as f:
            f.write(f"# FORGE V5 Benchmark Results\n\n")
            f.write(f"## Overall Score: {success_count}/{total} ({round(pct, 1)}%)\n\n")
            f.write("| ID | Tier | Task | Success | Iterations | Time |\n")
            f.write("|----|------|------|---------|------------|------|\n")
            for r in self.results:
                status = "✅" if r["success"] else "❌"
                f.write(f"| {r['id']} | {r['tier']} | {r['intent']} | {status} | {r['iterations']} | {r['duration']}s |\n")
        
        print(f"📊 Benchmark Summary saved to {md_path}")

if __name__ == "__main__":
    benchmark = ForgeBenchmark()
    benchmark.run()
