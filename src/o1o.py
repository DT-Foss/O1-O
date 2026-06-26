#!/usr/bin/env python3
"""
O1-O — Deterministic Code Generation via .causal Knowledge Graphs
Main session module (ForgeSession class is kept for backward compatibility).
"""

import sys
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add src/ (this directory) to path so `core.*` imports resolve
sys.path.insert(0, str(Path(__file__).parent))

# Repo root is the parent of src/ — knowledge/ and fragments/ live there
_REPO_ROOT = Path(__file__).resolve().parent.parent

from core.intent_parser import IntentParser
from core.knowledge_engine import KnowledgeEngine
from core.code_assembler import CodeAssembler
from core.executor import Executor
from core.learning import LearningLoop
from core.session_memory import SessionMemory
from core.chat_engine import ChatEngine
from core.project_generator import ProjectGenerator
from core.native_engine import NativeEngine
from core.verifier import Verifier
from core.repository_indexer import RepositoryIndexer
from core.web_harvester import WebHarvester
from core.formal_verifier import FormalVerifier
from core.mathematical_engine import MathematicalEngine
from core.self_improve import SelfImproveLoop
from core.ast_engine import ASTEngine
from core.reverse_forge import ReverseForge
from core.test_generator import TestGenerator
from core.dependency_manager import DependencyManager
from core.dependency_parser import DependencyParser
from core.monte_carlo_ranker import MonteCarloRanker
from core.self_improvement_turbo import SelfImprovementTurbo
from core.taint_analyzer import TaintAnalyzer

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class ForgeSession:
    """Main O1-O session handler (class name kept for compatibility with
    existing code that imports `ForgeSession`)."""

    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
        self.knowledge_dir = _REPO_ROOT / "knowledge"
        self.fragments_dir = _REPO_ROOT / "fragments"

        # Initialize core components
        self.knowledge = KnowledgeEngine(self.knowledge_dir)
        self.intent_parser = IntentParser(self.knowledge)
        self.native = NativeEngine(Path.cwd() / "native_builds")
        self.empirical_verifier = Verifier()
        self.formal_verifier = FormalVerifier(self.knowledge)
        self.math_engine = MathematicalEngine(self.knowledge)
        self.code_assembler = CodeAssembler(
            self.fragments_dir, 
            self.knowledge, 
            verifier=self.formal_verifier,
            math_engine=self.math_engine
        )
        
        # V2: Universal Persistent Memory
        self.indexer = RepositoryIndexer(self.knowledge)
        local_triplets = self.indexer.index_directory(Path.cwd())
        if local_triplets:
            self.knowledge.load_transient_triplets(local_triplets, "local_repo")

        # V4: Web Autonomous Learner
        self.web_harvester = WebHarvester(self.knowledge)

        # V3 & V8: Memory and Orchestration
        self.memory = SessionMemory()
        self.chat = ChatEngine(self.knowledge)
        self.project_generator = ProjectGenerator(self.fragments_dir, self.knowledge, self.code_assembler)
        self.learning = LearningLoop(self.knowledge)
        
        # V5: Executor
        self.executor = Executor()

        # Monte Carlo Candidate Ranker
        self.monte_carlo_ranker = MonteCarloRanker(self.executor, self.code_assembler, self.knowledge)

        # Taint Analyzer (dataflow security analysis)
        self.taint_analyzer = TaintAnalyzer(self.knowledge)

        # V9: Domain Bootstrapper
        from core.domain_bootstrapper import DomainBootstrapper
        self.bootstrapper = DomainBootstrapper(self.knowledge, self.web_harvester)

        # V10: Advanced Dev-Tool modules
        self.ast_engine = ASTEngine()
        self.reverse_forge = ReverseForge()
        self.test_generator = TestGenerator()
        self.dependency_manager = DependencyManager()
        self.dependency_parser = DependencyParser()

        # Symbolic executor + property verifier (deep analysis)
        from core.symbolic_executor import SymbolicExecutor
        from core.property_verifier import PropertyVerifier
        self.symbolic_executor = SymbolicExecutor()
        self.property_verifier = PropertyVerifier()

    def print(self, text, style=None):
        """Print with optional Rich formatting"""
        if self.console and style:
            self.console.print(text, style=style)
        else:
            print(text)

    def banner(self):
        """Print welcome banner"""
        banner_text = """
╔═══════════════════════════════════════════════════════╗
║                      F O R G E                        ║
║        Deterministic Code Generation Engine          ║
║                                                       ║
║  Type your request in natural language                ║
║  /build /debug /learn /test /analyze /deps /harden   ║
║  /verify /symbolic                                   ║
╚═══════════════════════════════════════════════════════╝
        """
        if self.console:
            self.console.print(Panel(banner_text, style="bold cyan"))
        else:
            print(banner_text)

    def handle_input(self, user_input: str):
        """Process user input and route to appropriate handler"""

        # Parse intent
        intent = self.intent_parser.parse(user_input)

        # Resolve references (it, that, etc.) via session memory
        intent = self.memory.resolve_references(intent)

        if intent['mode'] == 'BUILD':
            result = self.handle_build(intent)
            self.memory.add_turn(intent, str(result), script=result if isinstance(result, str) and 'import' in result else None)
            return result
        elif intent['mode'] == 'DEBUG':
            result = self.handle_debug(intent)
            self.memory.add_turn(intent, str(result))
            return result
        elif intent['mode'] == 'CHAT':
            result = self.handle_chat(intent)
            self.memory.add_turn(intent, str(result))
            return result
        elif intent['mode'] == 'LEARN':
            # Check for URL
            raw = intent['raw'].strip()
            if raw.startswith('http'):
                return self.handle_teach(raw)
            result = self.handle_learn(intent)
            self.memory.add_turn(intent, str(result))
            return result
        elif intent['mode'] == 'DOMAIN':
            return self.handle_domain(intent)
        else:
            return "I don't understand that request. Try /build, /debug, /chat, /learn, or /domain."

    def handle_build(self, intent):
        """BUILD mode: Generate code from intent"""
        self.print("\n🔨 BUILD mode activated", "bold green")

        # Check if this is a project (multi-file)
        p_type = self.project_generator.detect_project_type(intent)
        if p_type:
            self.print(f"📦 Project detected: {p_type}", "bold blue")
            project_files = self.project_generator.generate_project(p_type, intent)
            
            self.print(f"\n📝 Generated {len(project_files)} files:", "bold")
            for filename in project_files:
                self.print(f"  - {filename}", "dim")

            # Ask to save
            if self.console:
                save = Prompt.ask("\n💾 Create project directory?", choices=["y", "n"], default="y")
            else:
                save = input("\n💾 Create project directory? (y/n) [y]: ").lower() or 'y'

            if save == 'y':
                target_name = intent.get('raw', 'forge_project').lower().replace(' ', '_')[:20]
                target_dir = Path.cwd() / f"output_{target_name}"
                self.project_generator.save_project(project_files, target_dir)
                
                # V10: Verify the system
                self.print("\n🛡️ Verifying system integrity...", "yellow")
                all_proven = True
                for filename, content in project_files.items():
                    if filename.endswith('.py'):
                        res = self.formal_verifier.verify(content, intent)
                        if res['is_proven']:
                            self.print(f"  ✓ {filename}: {res['cert']}", "green")
                        else:
                            self.print(f"  ✗ {filename}: {res['violations']}", "red")
                            all_proven = False
                
                if all_proven:
                    self.print(f"\n✅ Project saved and MATHEMATICALLY VERIFIED to: {target_dir}", "bold green")
                else:
                    self.print(f"\n⚠️ Project saved to {target_dir} but some agents failed verification.", "bold yellow")
                
                return f"Project generated in {target_dir}"
            return "Project generated but not saved."

        # Query knowledge graph (for single script)
        candidate_chains = self.knowledge.infer(intent, top_k=3)

        if not candidate_chains:
            return "❌ I don't have enough knowledge to build this. Can you teach me? (use /learn)"

        # === Seed-and-Grow: try incremental build first ===
        # This builds one fragment at a time, verifying each step works
        # before adding the next. Prevents variable collisions and
        # logic conflicts that plague multi-fragment assembly.
        sg_result = self._seed_and_grow_build(candidate_chains, intent)
        if sg_result:
            return sg_result

        # Monte Carlo mode: for composition tasks, generate ALL candidates first
        is_composition = intent.get('is_composition', False)

        if is_composition and len(candidate_chains) >= 1:
            mc_result = self._monte_carlo_build(candidate_chains, intent)
            if mc_result and not mc_result.startswith('❌'):
                return mc_result
            # If Monte Carlo fails, try multi-file project approach
            self.print(f"\n📦 Monte Carlo failed, attempting multi-file project generation...", "bold yellow")
            project_result = self._multifile_project_build(candidate_chains, intent)
            if project_result:
                return project_result
            return mc_result

        # Standard sequential path exploration
        for path_idx, inference_chain in enumerate(candidate_chains):
            if path_idx > 0:
                self.print(f"\n🔄 PATH RE-RANKING: Attempting alternative strategy (Path {path_idx+1})...", "bold yellow")

            # Assemble code
            script = self.code_assembler.assemble(inference_chain, intent)

            self.print(f"\n📝 Generated script ({len(script.split(chr(10)))} lines):", "bold")

            # V10: Formal Verification
            self.print("🛡️ Verifying mathematical correctness...", "yellow")
            verification = self.formal_verifier.verify(script, intent)
            if verification['is_proven']:
                self.print(f"✅ VERIFIED: {verification['cert']}", "bold green")
            else:
                self.print(f"⚠️ VERIFICATION FAILED: {verification['violations']}", "bold red")

            # Taint Analysis
            taint_findings = self.taint_analyzer.analyze(script)
            if taint_findings:
                vuln = [f for f in taint_findings if not f.sanitized]
                safe = [f for f in taint_findings if f.sanitized]
                if vuln:
                    self.print(f"🔍 TAINT: {len(vuln)} vulnerable flow(s) detected", "bold yellow")
                    for f in vuln[:3]:
                        self.print(f"  {f}", "yellow")
                if safe:
                    self.print(f"🛡️ TAINT: {len(safe)} sanitized flow(s)", "dim green")

            # Symbolic Analysis (lightweight: div-by-zero, overflow, dead branches)
            sym_result = self.symbolic_executor.analyze(script)
            sym_findings = sym_result.get('findings', [])
            if sym_findings:
                high_sev = [f for f in sym_findings if f['severity'] in ('HIGH', 'CRITICAL')]
                if high_sev:
                    self.print(f"⚡ SYMBOLIC: {len(high_sev)} issue(s) detected", "bold yellow")
                    for f in high_sev[:3]:
                        self.print(f"  L{f['line']}: {f['type']} — {f['message']}", "yellow")

            # Execution Logic
            current_script = script
            max_attempts = 2 # Reduced for faster path switching

            for attempt in range(1, max_attempts + 1):
                result = self.executor.run(current_script, intent)

                if result['success']:
                    self.print(f"\n✅ Success! Output:", "bold green")
                    if result['stdout']:
                        self.print(result['stdout'], "dim")

                    # Learn from success
                    self.print("\n📚 Learning from success...", "cyan")
                    self.learning.learn_from_success(intent, inference_chain, current_script)
                    return current_script

                else:
                    self.print(f"\n❌ Attempt {attempt} failed: {result['error']}", "bold red")

                    if attempt < max_attempts:
                        # Try to auto-fix
                        self.print("🔧 Attempting auto-fix...", "yellow")
                        error_type = result.get('error', 'UNKNOWN_ERROR')
                        fixed = self.executor.auto_fix(
                            current_script, error_type, self.knowledge,
                            stderr=result.get('stderr', '')
                        )

                        if fixed and fixed != current_script:
                            self.print("✓ Fix applied, retrying...", "green")
                            current_script = fixed
                        else:
                            self.print("✗ No fix available", "red")
                            break
                    else:
                        self.print(f"\n💥 Failed after {max_attempts} attempts", "bold red")
                        if result['stderr']:
                            self.print("\nError details:", "red")
                            self.print(result['stderr'][:500], "dim")

        return script

    def _seed_and_grow_build(self, candidate_chains, intent):
        """Seed-and-Grow: Build smallest viable unit, then grow incrementally.

        Instead of assembling all fragments at once (which causes variable
        collisions and logic conflicts), builds one component at a time,
        verifying each step works before adding the next.

        Returns the final working script, or None if seed-and-grow can't work
        (e.g. only 1 fragment, or seed fails).
        """
        chain = candidate_chains[0]

        # Decompose into ordered single-step items
        steps = self.code_assembler.decompose_chain(chain, intent)

        if len(steps) <= 1:
            return None  # Single step — fall back to normal build

        self.print(f"\n🌱 SEED-AND-GROW: {len(steps)} components detected", "bold cyan")

        # === SEED: Build the first component alone ===
        seed_chain = [steps[0]]
        seed_intent = dict(intent)
        seed_intent['requires_output'] = True  # Ensure seed has visible output for verification

        seed_script = self.code_assembler.assemble(seed_chain, seed_intent)
        result = self.executor.run(seed_script, seed_intent)

        if not result['success']:
            # Try auto-fix on seed
            fixed = self.executor.auto_fix(
                seed_script, result.get('error', ''),
                self.knowledge, stderr=result.get('stderr', '')
            )
            if fixed:
                result = self.executor.run(fixed, seed_intent)
                if result['success']:
                    seed_script = fixed
                else:
                    self.print("  ❌ Seed failed after auto-fix, falling back", "red")
                    return None
            else:
                self.print("  ❌ Seed failed, falling back to standard assembly", "red")
                return None

        step_name = steps[0]['triplet']['outcome']
        self.print(f"  🌱 Seed verified ✓ ({step_name})", "green")
        current_script = seed_script
        components_added = 1

        # === GROW: Add one component at a time ===
        for i, step in enumerate(steps[1:], 2):
            step_name = step['triplet']['outcome']

            # Grow: add this fragment to the working script
            grow_intent = dict(intent)
            # Only require output on the last step
            grow_intent['requires_output'] = (i == len(steps))

            grown_script = self.code_assembler.grow_script(
                current_script, step, grow_intent
            )

            if grown_script == current_script:
                self.print(f"  ⚠️ Step {i}/{len(steps)} skipped (no fragment: {step_name})", "yellow")
                continue

            result = self.executor.run(grown_script, intent)

            if result['success']:
                current_script = grown_script
                components_added += 1
                self.print(f"  🌿 Step {i}/{len(steps)} verified ✓ ({step_name})", "green")
            else:
                # Try auto-fix
                fixed = self.executor.auto_fix(
                    grown_script, result.get('error', ''),
                    self.knowledge, stderr=result.get('stderr', '')
                )
                if fixed:
                    result = self.executor.run(fixed, intent)
                    if result['success']:
                        current_script = fixed
                        components_added += 1
                        self.print(f"  🔧 Step {i}/{len(steps)} fixed ✓ ({step_name})", "yellow")
                        continue

                # This step fails — skip it, keep the working script
                self.print(f"  ⚠️ Step {i}/{len(steps)} failed, skipping ({step_name})", "yellow")

        self.print(f"\n✅ Seed-and-Grow: {components_added}/{len(steps)} components built", "bold green")

        # Learn from success
        if components_added > 0:
            self.learning.learn_from_success(intent, chain, current_script)

        return current_script

    def _monte_carlo_build(self, candidate_chains, intent):
        """Monte Carlo code generation: generate multiple candidates, execute in parallel, pick best."""
        self.print(f"\n🎲 MONTE CARLO: Generating candidate scripts...", "bold cyan")

        # Generate candidates using different assembly strategies
        candidates = self.monte_carlo_ranker.generate_candidates(intent)

        if not candidates:
            return "❌ Monte Carlo: No valid candidates generated."

        self.print(f"  Generated {len(candidates)} candidates", "dim")

        # Phase 2: Execute all in parallel and select best
        self.print("  Executing all candidates in parallel...", "dim")
        best_code, best_score, all_results = self.monte_carlo_ranker.rank_candidates(candidates, intent)

        # Phase 3: Report and return best
        self.print(f"\n📊 Monte Carlo Results:", "bold")
        self.print(f"  Tested {len(candidates)} candidates", "dim")
        if all_results:
            for code, score, result in all_results[:3]:
                status = "✅" if result.get('success') else "❌"
                self.print(f"  {status} Candidate score: {score}", "dim")

        if all_results:
            best_result = all_results[0][2]  # Get result for best candidate
            if best_result.get('success'):
                self.print(f"\n✅ Best candidate succeeded (score={best_score}):", "bold green")
                if best_result.get('stdout'):
                    self.print(best_result['stdout'][:500], "dim")

                # Learn from success
                self.print("\n📚 Learning from success...", "cyan")
                if candidate_chains:
                    self.learning.learn_from_success(intent, candidate_chains[0], best_code)
                return best_code
            else:
                # No candidate succeeded — try auto-fix on the best-scoring one
                self.print(f"\n⚠️ Best candidate failed. Attempting auto-fix...", "yellow")
                error_type = best_result.get('error', 'UNKNOWN_ERROR')
                fixed = self.executor.auto_fix(
                    best_code, error_type, self.knowledge,
                    stderr=best_result.get('stderr', '')
                )
                if fixed:
                    result = self.executor.run(fixed, intent)
                    if result['success']:
                        self.print(f"\n✅ Auto-fix succeeded!", "bold green")
                        if result.get('stdout'):
                            self.print(result['stdout'][:500], "dim")
                        return fixed

                self.print(f"\n💥 Monte Carlo best candidate failed", "bold red")
                return best_code

        return "❌ Monte Carlo: No results generated."

    def _multifile_project_build(self, candidate_chains, intent):
        """Multi-file project generation: Phase D fallback for failing composition tasks.

        Generates TDD-style multi-file projects with:
        - test_main.py (specification/tests first)
        - main.py (implementation)
        - __init__.py, requirements.txt, README.md, config.yaml

        Returns best project's test_main.py output or None if all fail.
        """
        self.print(f"\n📦 MULTI-FILE PROJECT: Generating {len(candidate_chains)} project candidates...", "bold cyan")

        # Phase 1: Generate multi-file project candidates
        project_candidates = []
        for chain_idx, chain in enumerate(candidate_chains):
            try:
                project_files = self.code_assembler.assemble_project(chain, intent)
                if project_files and 'test_main.py' in project_files:
                    project_candidates.append({
                        'chain_idx': chain_idx,
                        'files': project_files,
                        'chain': chain
                    })
            except Exception as e:
                pass

        if not project_candidates:
            self.print(f"  ❌ No valid project candidates generated", "dim")
            return None

        self.print(f"  Generated {len(project_candidates)} project candidates", "dim")

        # Phase 2: Execute projects in order, pick best
        self.print("  Executing projects (tests first)...", "dim")
        results = []
        for cand in project_candidates:
            try:
                result = self.executor.run_project(cand['files'], intent)
                if result['success']:
                    results.append({
                        'score': 10 + (1 if result.get('test_passed') else 0),
                        'project': cand,
                        'result': result
                    })
                else:
                    results.append({
                        'score': -1 if result.get('error') else 0,
                        'project': cand,
                        'result': result
                    })
            except Exception as e:
                results.append({
                    'score': -1,
                    'project': cand,
                    'result': {'success': False, 'error': str(e)}
                })

        # Sort by score
        results.sort(key=lambda x: -x['score'])
        best = results[0]

        self.print(f"\n📊 Project Results:", "bold")
        for i, r in enumerate(results[:3]):  # Show top 3
            status = "✅" if r['result']['success'] else "❌"
            test_status = "✓" if r['result'].get('test_passed') else "✗"
            self.print(f"  {status} Project {i+1} [tests: {test_status}]: score={r['score']:.1f}", "dim")

        if best['result']['success']:
            self.print(f"\n✅ Best project generated (score={best['score']:.1f}):", "bold green")
            winning_chain = best['project']['chain']

            # Return the main.py output (test_main.py serves as verification)
            if best['result'].get('main_output'):
                self.print(best['result']['main_output'][:500], "dim")
            elif best['result'].get('test_output'):
                self.print(best['result']['test_output'][:500], "dim")

            # Learn from success
            self.print("\n📚 Learning from success...", "cyan")
            self.learning.learn_from_success(intent, winning_chain, best['project']['files']['main.py'])

            # Return the project files as a multi-file success indicator
            return f"📦 Multi-file project generated successfully\n" + \
                   f"Files: {', '.join(best['project']['files'].keys())}"
        else:
            self.print(f"\n⚠️ No project succeeded", "yellow")
            return None

    def handle_debug(self, intent):
        """DEBUG mode: Analyze error and suggest fix"""
        self.print("\n🐛 DEBUG mode activated", "bold yellow")

        error_text = intent.get('raw', '')
        tokens = intent.get('tokens', [])

        # Try to identify the error type
        error_type = None
        for token in tokens:
            if token.endswith('error') or token in {
                'error', 'crash', 'bug', 'traceback', 'exception'
            }:
                # Look for specific error types in the raw input
                import re
                error_match = re.search(
                    r'(ModuleNotFoundError|FileNotFoundError|IndexError|KeyError|'
                    r'TypeError|ValueError|AttributeError|ImportError|SyntaxError|'
                    r'NameError|ZeroDivisionError|PermissionError|RecursionError|'
                    r'StopIteration|OSError|RuntimeError|ConnectionError)',
                    error_text
                )
                if error_match:
                    error_type = error_match.group(1)
                break

        # Query error_patterns.causal for known fixes
        if error_type:
            results = self.knowledge.query_entity(error_type)
            if results:
                self.print(f"\n🔍 Found {len(results)} known patterns for {error_type}:", "cyan")
                for r in results[:5]:
                    t = r['triplet']
                    self.print(f"  {t['trigger']} → {t['mechanism']} → {t['outcome']}", "dim")

                # Suggest fix
                for r in results:
                    t = r['triplet']
                    if 'fix' in t['mechanism'].lower() or 'solved' in t['mechanism'].lower():
                        self.print(f"\n💡 Suggested fix: {t['outcome']}", "bold green")
                        return f"Try: {t['outcome']}"

                return f"Known causes for {error_type}: " + ', '.join(
                    r['triplet']['outcome'] for r in results[:3]
                )
            else:
                return f"I don't have patterns for {error_type} yet. Use /learn to teach me!"

        # No specific error found — give general advice
        if not error_type:
            self.print("\n💡 Tips:", "cyan")
            self.print("  Paste the full error message for better analysis", "dim")
            self.print("  Example: 'ModuleNotFoundError: No module named pandas'", "dim")
            return "Paste your error message and I'll look up known fixes."

    def handle_chat(self, intent):
        """CHAT mode: Answer questions"""
        response = self.chat.answer(intent)
        return response

    def handle_learn(self, intent):
        """LEARN mode: Add new knowledge from user input"""
        self.print("\n📚 LEARN mode activated", "bold blue")

        raw = intent.get('raw', '')
        entities = [e['matched'] for e in intent.get('entities', [])]

        # Try to parse "X can do Y" or "X uses Y" patterns
        import re
        patterns = [
            r'(\w+)\s+(?:can|uses?|reads?|writes?|creates?)\s+(.+)',
            r'(\w+)\s+(?:is|works with)\s+(.+)',
            r'teach.*?(\w+)\s+(\w+)',
        ]

        trigger = None
        outcome = None
        mechanism = 'uses'

        for pattern in patterns:
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                trigger = match.group(1).strip()
                outcome = match.group(2).strip()
                break

        # Fallback: use entities directly
        if not trigger and len(entities) >= 2:
            trigger = entities[0]
            outcome = entities[1]

        if not trigger or not outcome:
            self.print("  I couldn't parse that. Try:", "yellow")
            self.print("  'pandas can read parquet files'", "dim")
            self.print("  'teach: requests downloads webpages'", "dim")
            return "Could not parse knowledge. Use format: 'X uses Y' or 'X can do Y'"

        # Create and save the triplet
        new_triplet = {
            'trigger': trigger,
            'mechanism': mechanism,
            'outcome': outcome,
            'confidence': 0.85,
            'source': 'user_teaching',
        }

        self.learning.learned_triplets.append(new_triplet)
        self.learning.save_learned()
        # Inject into live knowledge engine so it's usable immediately
        self.knowledge.load_transient_triplets([new_triplet], 'learned')

        self.print(f"\n✅ Learned: {trigger} → {mechanism} → {outcome}", "bold green")
        self.print(f"  Saved to learned.causal ({len(self.learning.learned_triplets)} total)", "dim")
    def handle_domain(self, intent: Dict[str, Any]):
        """V9: Manage knowledge domains"""
        raw = intent['raw'].lower().replace('/domain', '').strip()
        
        if raw.startswith('create'):
            domain_name = raw.replace('create', '').strip()
            if not domain_name: return "Usage: /domain create <name>"
            
            domain_path = self.knowledge_dir / domain_name
            domain_path.mkdir(exist_ok=True)
            self.print(f"✅ Created domain: {domain_name}", "bold green")
            return f"Domain '{domain_name}' initialized at {domain_path}"
            
        if raw.startswith('switch') or raw.startswith('use'):
            domain_name = raw.replace('switch', '').replace('use', '').strip()
            return self.switch_domain(domain_name)
            
        if raw.startswith('list'):
            domains = [d.name for d in self.knowledge_dir.iterdir() if d.is_dir()]
            return "Active Domains: " + ", ".join(domains)

        if raw.startswith('bootstrap'):
            url = raw.replace('bootstrap', '').strip()
            if not url: return "Usage: /domain bootstrap <url>"
            
            self.print(f"🚀 Bootstrapping active domain from {url}...", "bold blue")
            results = self.bootstrapper.bootstrap_domain(self.knowledge.knowledge_dir.name, [url])
            
            # Persist newly learned knowledge
            self.knowledge.save_as_causal("bootstrap.causal")
            
            return f"Bootstrapped {results['triplets_harvested']} triplets into active domain."

        return "Commands: create, switch, list, bootstrap"

    def self_improve(self, max_iterations: int = 500, time_budget_hours: float = 8.0):
        """Run self-improvement loop: O1-O plays against the Python runtime"""
        loop = SelfImproveLoop(self)
        stats = loop.run(
            max_iterations=max_iterations,
            time_budget_hours=time_budget_hours,
            verbose=True
        )
        report = loop.get_report()
        self.print(f"\n{report}")
        return stats

    def switch_domain(self, domain_name: str):
        """Swaps the active knowledge graph"""
        domain_path = self.knowledge_dir / domain_name
        if not domain_path.exists():
            return f"❌ Domain '{domain_name}' not found."
            
        # Re-initialize engine with specific domain
        self.knowledge = KnowledgeEngine(domain_path)
        self.intent_parser.knowledge = self.knowledge
        self.code_assembler.knowledge = self.knowledge
        
        self.print(f"🔄 Switched to domain: {domain_name}", "bold yellow")
        return f"Now using knowledge from {domain_name}"

    def handle_teach(self, url: str):
        """Autonomous learning from a web URL with empirical validation"""
        self.print(f"\n🌐 WEB TEACHING mode activated (Autonomous Feedback Loop)", "bold blue")
        
        # 1. Harvest
        pre_harvest_count = len(self.knowledge.all_triplets)
        count = self.web_harvester.harvest_url(url)
        
        if count > 0:
            self.print(f"✅ Harvested {count} raw triplets. Starting Autonomous Validation...", "bold green")
            
            # 2. Extract new triplets (those added after harvest)
            new_triplets = self.knowledge.all_triplets[pre_harvest_count:]
            validated_count = self.run_autonomous_validation(new_triplets)
            
            # 3. Prune failures
            pruned = self.knowledge.prune_knowledge(threshold=0.30)
            
            self.print(f"\n📊 RESULTS: {validated_count} validated, {pruned} pruned.", "bold yellow")
            return f"Web-Learning complete: {validated_count} survivors from {url}"
        else:
            return "No new causal knowledge discovered."

    def run_autonomous_validation(self, triplets: List[Dict[str, Any]]) -> int:
        """Execute and score newly learned triplets (No Human in loop)"""
        validated = 0
        from core.executor import Executor
        executor = Executor()
        
        for t in triplets:
            trigger = t['trigger']
            outcome = t['outcome']
            mechanism = t['mechanism']
            
            self.print(f"🧪 Testing: {trigger} -> {outcome}...", "dim")
            
            # Create a minimalist test intent
            test_intent = {
                'mode': 'BUILD',
                'entities': [{'matched': trigger, 'confidence': 1.0}, {'matched': outcome, 'confidence': 1.0}],
                'raw': f"use {trigger} for {outcome}",
                'requires_output': True,
                'safe_mode': True
            }
            
            # Assemble & Execute
            chain = self.knowledge.infer(test_intent)
            if chain:
                script = self.code_assembler.assemble(chain, test_intent)
                result = executor.run(script)
                
                if result['success']:
                    self.print(f"  ✅ SUCCESS: Boosting triplet.", "green")
                    self.knowledge.reward_triplet(trigger, outcome)
                    validated += 1
                else:
                    self.print(f"  ❌ FAIL: Penalizing triplet. ({result.get('error', 'unknown')})", "red")
                    self.knowledge.penalize_triplet(trigger, outcome)
            else:
                self.print(f"  ⚠️ No code path found for validation.", "yellow")
                self.knowledge.penalize_triplet(trigger, outcome, penalty=0.1) # Soft penalty for unreachable knowledge

        return validated

    def handle_turbo(self, num_cycles: int = 250, benchmark: bool = False) -> str:
        """Run autonomous turbo loop on V3 tasks"""
        import json

        # Load V3 tasks
        v3_tasks_path = Path(__file__).parent / "tests" / "blind_v3_tasks.json"
        if not v3_tasks_path.exists():
            return "❌ V3 tasks file not found"

        with open(v3_tasks_path) as f:
            v3_data = json.load(f)
            tasks = [t['intent'] for t in v3_data.get('tasks', [])]

        if not tasks:
            return "❌ No V3 tasks available"

        # Run turbo loop
        turbo = SelfImprovementTurbo(self, tasks, use_monte_carlo=True)
        report = turbo.run(
            num_cycles=num_cycles,
            print_every=max(1, num_cycles // 10),  # Print every 10% of cycles
            verbose=True
        )

        # Format report
        result_lines = [
            f"⚡ TURBO LOOP COMPLETE",
            f"",
            f"📊 Results:",
            f"  Baseline: {report.get('baseline_score', 0)}/50",
            f"  Final:    {report.get('final_score', 0)}/50",
            f"  Improvement: +{report.get('improvement', 0)} ({report.get('improvement_pct', 0):.1f}%)",
            f"  Success rate: {report.get('success_rate', 0)*100:.1f}%",
            f"  Speed: {report.get('cycles_per_hour', 0):.0f} cycles/hour",
            f"  Cycles: {report.get('total_cycles', 0)}",
        ]

        if report.get('monte_carlo_enabled'):
            result_lines.extend([
                f"",
                f"🎲 Monte Carlo Stats:",
                f"  Avg score: {report.get('mc_avg_score', 0):.1f}",
                f"  High quality: {report.get('mc_high_quality', 0)} cases",
            ])

        result_lines.extend([
            f"",
            f"📚 Learning:",
            f"  Patterns learned: {report.get('learned_patterns', 0)}",
            f"  Patterns failed: {report.get('failed_patterns', 0)}",
        ])

        return "\n".join(result_lines)

    def run(self):
        """Main REPL loop"""
        self.banner()

        while True:
            try:
                if self.console:
                    user_input = Prompt.ask("\n[bold cyan]forge>[/bold cyan]")
                else:
                    user_input = input("\nforge> ")

                if not user_input.strip():
                    continue

                # Handle commands
                if user_input.startswith('/quit') or user_input.startswith('/exit'):
                    self.print("\n👋 Goodbye!", "bold")
                    break

                if user_input.startswith('/analyze'):
                    # Analyze code or project
                    arg = user_input.replace('/analyze', '').strip()
                    if arg and os.path.isfile(arg):
                        result = self.reverse_forge.analyze_file(arg)
                        self.print(f"\nAnalysis of {arg}:", "bold")
                        self.print(f"  Triplets extracted: {len(result)}", "dim")
                        for t in result[:10]:
                            self.print(f"  {t['trigger']} -> {t['mechanism']} -> {t['outcome']}", "dim")
                    else:
                        analysis = self.project_generator.analyze_project()
                        self.print(f"\nProject analysis:", "bold")
                        self.print(f"  Python files: {len(analysis['python_files'])}", "dim")
                        self.print(f"  Functions: {len(analysis['functions'])}", "dim")
                        self.print(f"  Classes: {len(analysis['classes'])}", "dim")
                        self.print(f"  Framework: {analysis['framework'] or 'none'}", "dim")
                        self.print(f"  Has tests: {analysis['has_tests']}", "dim")
                    continue

                if user_input.startswith('/test'):
                    # Generate tests for last script
                    if self.memory.current_script:
                        tests = self.test_generator.generate(self.memory.current_script)
                        self.print(f"\nGenerated tests ({len(tests.split(chr(10)))} lines):", "bold")
                        self.print(tests, "dim")
                    else:
                        self.print("No script in memory to test. Build something first.", "yellow")
                    continue

                if user_input.startswith('/deps'):
                    # Analyze dependencies
                    if self.memory.current_script:
                        analysis = self.dependency_manager.analyze_code(self.memory.current_script)
                        self.print(f"\nDependency analysis:", "bold")
                        self.print(f"  Stdlib: {', '.join(analysis['stdlib'][:10])}", "dim")
                        self.print(f"  Third-party: {', '.join(analysis['third_party'][:10])}", "dim")
                        self.print(f"  Missing: {', '.join(analysis['missing'][:10])}", "dim")
                        if analysis['requirements']:
                            self.print(f"\nrequirements.txt:", "cyan")
                            self.print(analysis['requirements'], "dim")
                    else:
                        self.print("No script in memory. Build something first.", "yellow")
                    continue

                if user_input.startswith('/harden'):
                    # Security harden: AST transform + SecurityAnalyzer full analysis
                    if self.memory.current_script:
                        # Layer 1: AST hardening
                        hardened = self.ast_engine.transform(self.memory.current_script, [
                            'add_error_handling', 'add_logging', 'security_harden'
                        ])
                        self.print(f"\nHardened script ({len(hardened.split(chr(10)))} lines):", "bold")
                        self.print(hardened, "dim")
                        self.memory.current_script = hardened

                        # Layer 2: SecurityAnalyzer deep analysis
                        from core.security_analyzer import SecurityAnalyzer
                        sa = SecurityAnalyzer(self.knowledge)
                        report = sa.full_analysis(hardened)
                        arch = report['architecture']
                        summary = report['summary']

                        self.print(f"\n  SECURITY ANALYSIS", "bold")
                        self.print(f"  Network exposed: {arch['network_exposed']}", "dim")
                        self.print(f"  Privileges: {', '.join(arch['privileges']) or 'none'}", "dim")
                        self.print(f"  Validation: {'yes' if arch['has_validation'] else 'NO'}", "green" if arch['has_validation'] else "red")
                        self.print(f"  Auth: {'yes' if arch['has_auth'] else 'NO'}", "green" if arch['has_auth'] else "red")
                        self.print(f"  Findings: {summary['total_findings']} total, {summary['reachable_vulnerable']} reachable", "")
                        if summary['max_impact_score'] > 0:
                            self.print(f"  Max impact: {summary['max_impact_score']}/10.0", "bold yellow")
                        for rec in report['recommendations'][:5]:
                            self.print(f"  → {rec}", "yellow")
                    else:
                        self.print("No script in memory. Build something first.", "yellow")
                    continue

                if user_input.startswith('/verify'):
                    # Property-based verification on last script
                    if self.memory.current_script:
                        results = self.property_verifier.verify(self.memory.current_script)
                        if results:
                            summary = self.property_verifier.summary(results)
                            self.print(f"\n  PROPERTY VERIFICATION: {summary['holds']}/{summary['total_checks']} hold", "bold")
                            for r in results:
                                status = '✓' if r.holds else '✗'
                                color = 'green' if r.holds else 'red'
                                self.print(f"  {status} {r.property_name}({r.function_name}): [{r.tests_passed}/{r.tests_run}]", color)
                                if r.counterexample and not r.holds:
                                    self.print(f"    counterexample: {r.counterexample}", "dim red")
                        else:
                            self.print("No testable functions found in script.", "yellow")
                    else:
                        self.print("No script in memory. Build something first.", "yellow")
                    continue

                if user_input.startswith('/symbolic'):
                    # Symbolic execution analysis on last script
                    if self.memory.current_script:
                        result = self.symbolic_executor.analyze(self.memory.current_script)
                        summary = result['summary']
                        self.print(f"\n  SYMBOLIC ANALYSIS", "bold")
                        self.print(f"  Variables tracked: {summary['variables_tracked']}", "dim")
                        self.print(f"  Paths explored: {summary['paths_explored']}", "dim")
                        self.print(f"  Dead paths: {summary['dead_paths']}", "dim" if summary['dead_paths'] == 0 else "yellow")
                        self.print(f"  Findings: {summary['total_findings']}", "dim" if summary['total_findings'] == 0 else "yellow")
                        for f in result['findings']:
                            sev_color = {'CRITICAL': 'bold red', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'dim'}.get(f['severity'], 'dim')
                            self.print(f"  [{f['severity']}] L{f['line']}: {f['type']} — {f['message']}", sev_color)
                    else:
                        self.print("No script in memory. Build something first.", "yellow")
                    continue

                if user_input.startswith('/self-improve') or user_input.startswith('/evolve'):
                    # Parse optional args: /self-improve 100 2h
                    parts = user_input.split()
                    max_iter = 500
                    hours = 8.0
                    for p in parts[1:]:
                        if p.endswith('h'):
                            try: hours = float(p[:-1])
                            except: pass
                        elif p.isdigit():
                            max_iter = int(p)
                    self.self_improve(max_iterations=max_iter, time_budget_hours=hours)
                    continue

                if user_input.startswith('/self-repair'):
                    # Self-Repair Loop: run benchmark, diagnose failures, fix them
                    # Usage: /self-repair [v2|v3|v4|cir] [max_attempts]
                    parts = user_input.split()
                    benchmark = 'v2'
                    max_attempts = 3
                    for p in parts[1:]:
                        if p in ('v2', 'v3', 'v4', 'cir'):
                            benchmark = p
                        elif p.isdigit():
                            max_attempts = int(p)

                    self.print(f"\n🔧 SELF-REPAIR: Running {benchmark} benchmark + auto-fix (max {max_attempts} attempts)", "bold cyan")

                    from tests.forge_validator import UnifiedBenchmarkRunner
                    import json
                    runner = UnifiedBenchmarkRunner(self)

                    # Load tasks
                    task_dir = Path(f"benchmarks/hardened")
                    if benchmark == 'v2':
                        task_file = task_dir / "v2_blind_(100_tasks)" / "v2_blind_(100_tasks).json"
                        name = "V2 Blind (100 tasks)"
                    elif benchmark == 'v3':
                        task_file = task_dir / "v3_impossible_(50_tasks)" / "v3_impossible_(50_tasks).json"
                        name = "V3 Impossible (50 tasks)"
                    elif benchmark == 'v4':
                        task_file = task_dir / "v4_stackoverflow_(104_tasks)" / "v4_stackoverflow_(104_tasks).json"
                        name = "V4 StackOverflow (104 tasks)"
                    else:
                        task_file = task_dir / "cir_red_team_(60_tasks)" / "cir_red_team_(60_tasks).json"
                        name = "CIR Red Team (60 tasks)"

                    with open(task_file) as f:
                        tasks = json.load(f)

                    # Run benchmark
                    results = runner.run_benchmark(tasks, name)

                    # Attempt repairs
                    failures = [r for r in results if not r['success']]
                    if failures:
                        repair_result = runner.repair_failures(results, tasks, max_attempts=max_attempts)
                        self.print(f"\n✅ {repair_result['fixed']} fixed, {repair_result['unfixable']} unfixable", "bold green")
                    else:
                        self.print(f"\n✅ No failures to repair — 100%!", "bold green")
                    continue

                if user_input.startswith('/cve'):
                    # CVE/NVD Auto-Fetcher: search CVEs and extract triplets
                    # Usage: /cve <keyword|CWE-ID|CVE-ID>
                    cve_query = user_input[len('/cve'):].strip()
                    if not cve_query:
                        self.print("Usage: /cve <query>", "yellow")
                        self.print("  /cve buffer overflow macOS              — keyword search", "dim")
                        self.print("  /cve CWE-416                            — search by CWE", "dim")
                        self.print("  /cve CVE-2024-1234                      — fetch specific CVE", "dim")
                        self.print("  /cve use-after-free Apple --learn        — search + extract triplets", "dim")
                        continue

                    from core.cve_fetcher import CVEFetcher, TripletExtractor, format_cve
                    fetcher = CVEFetcher()
                    extractor = TripletExtractor()

                    learn_mode = '--learn' in cve_query
                    cve_query = cve_query.replace('--learn', '').strip()

                    self.print(f"\n🔍 NVD SEARCH: {cve_query}", "bold cyan")

                    try:
                        if cve_query.startswith('CVE-'):
                            cve = fetcher.fetch_cve(cve_query)
                            cves = [cve] if cve else []
                        elif cve_query.startswith('CWE-'):
                            cves = fetcher.search(cwe_id=cve_query, results_per_page=10)
                        else:
                            cves = fetcher.search(keyword=cve_query, results_per_page=10)

                        if not cves:
                            self.print("  No CVEs found.", "yellow")
                            continue

                        self.print(f"  Found {len(cves)} CVEs:\n", "green")
                        for cve in cves:
                            self.print(format_cve(cve))
                            self.print("")

                        # Extract triplets
                        triplets = extractor.extract_batch(cves)
                        self.print(f"  Extracted {len(triplets)} causal triplets", "cyan")
                        for t in triplets[:10]:
                            self.print(f"    {t['trigger']} →[{t['mechanism']}]→ {t['outcome']}", "dim")
                        if len(triplets) > 10:
                            self.print(f"    ... and {len(triplets) - 10} more", "dim")

                        # Learn mode: merge into bridge_triplets.json
                        if learn_mode and triplets:
                            bridge_path = str(self.fragments_dir.parent / 'bridge_triplets.json')
                            added = extractor.merge_into_bridge_triplets(triplets, bridge_path)
                            self.print(f"\n  📚 Learned {added} new triplets → bridge_triplets.json", "bold green")

                    except Exception as e:
                        self.print(f"  Error: {e}", "red")
                    continue

                if user_input.startswith('/synthesize'):
                    # Fragment Synthesizer: auto-generate fragments from CVE patterns
                    # Usage: /synthesize <keyword|CWE-ID>
                    synth_query = user_input[len('/synthesize'):].strip()
                    if not synth_query:
                        self.print("Usage: /synthesize <query>", "yellow")
                        self.print("  /synthesize CWE-787                     — synthesize from CWE", "dim")
                        self.print("  /synthesize buffer overflow Apple        — keyword search + synthesize", "dim")
                        self.print("\nFetches CVEs → generates fragments → sandbox validates → stores", "dim")
                        continue

                    from core.cve_fetcher import CVEFetcher, TripletExtractor
                    from core.fragment_synthesizer import FragmentSynthesizer
                    fetcher = CVEFetcher()
                    synthesizer = FragmentSynthesizer(fragments_dir=str(self.fragments_dir))
                    extractor = TripletExtractor()

                    self.print(f"\n🧬 FRAGMENT SYNTHESIS: {synth_query}", "bold magenta")

                    try:
                        # Fetch CVEs
                        if synth_query.startswith('CWE-'):
                            cves = fetcher.search(cwe_id=synth_query, results_per_page=10)
                        else:
                            cves = fetcher.search(keyword=synth_query, results_per_page=10)

                        if not cves:
                            self.print("  No CVEs found.", "yellow")
                            continue

                        self.print(f"  Found {len(cves)} CVEs, synthesizing...", "cyan")

                        # Synthesize and validate
                        fragments = synthesizer.synthesize_batch(cves, validate=True)
                        self.print(f"  Generated {len(fragments)} validated fragments:", "green")

                        for frag in fragments:
                            self.print(f"    {frag['name']}: {frag['template_used']} "
                                       f"({frag['cve_id']})", "green")

                        # Store fragments
                        stored = synthesizer.store_fragments(fragments)
                        self.print(f"\n  Stored {stored} new fragments", "bold green")

                        # Extract and merge triplets
                        triplets = extractor.extract_batch(cves)
                        bridge_path = str(self.fragments_dir.parent / 'bridge_triplets.json')
                        added = extractor.merge_into_bridge_triplets(triplets, bridge_path)
                        self.print(f"  Learned {added} new triplets → bridge_triplets.json", "bold green")

                    except Exception as e:
                        self.print(f"  Error: {e}", "red")
                    continue

                if user_input.startswith('/crash'):
                    # Crash Analyzer: parse crash logs and classify exploit primitives
                    # Usage: /crash <file_or_dir>
                    analyze_target = user_input[len('/crash'):].strip()
                    if not analyze_target:
                        self.print("Usage: /crash <crash_file_or_directory>", "yellow")
                        self.print("  /crash report.ips                      — single macOS crash", "dim")
                        self.print("  /crash ~/crashes/                      — batch analyze directory", "dim")
                        self.print("  /crash asan_report.txt                 — ASan/GDB/kernel oops", "dim")
                        self.print("\nClassifies crash → DoS | InfoLeak | Write | Execute", "dim")
                        continue

                    from core.crash_analyzer import CrashAnalyzer
                    analyzer = CrashAnalyzer()
                    target_path = os.path.expanduser(analyze_target)

                    if os.path.isdir(target_path):
                        self.print(f"\n🔬 BATCH CRASH ANALYSIS: {target_path}", "bold red")
                        results = analyzer.batch_analyze(target_path)
                        if not results:
                            self.print("  No crash files found (.ips, .crash, .txt, .log)", "yellow")
                            continue

                        # Summary table
                        severity_icon = {'dos': '🟡 DoS', 'info_leak': '🟠 InfoLeak',
                                         'write': '🔴 Write', 'execute': '💀 Execute'}
                        for r in results:
                            if 'error' in r:
                                self.print(f"  ❌ {os.path.basename(r['file'])}: {r['error']}", "red")
                            else:
                                p = r['primitive']
                                icon = severity_icon.get(p['type'], p['type'])
                                self.print(f"  {icon} {os.path.basename(r['file'])} — "
                                           f"{r['app']} ({r['signal']}) "
                                           f"conf={p['confidence']:.0%} ctrl={p['controllability']}",
                                           "bold" if p['type'] in ('write', 'execute') else "")

                        # Stats
                        types = [r['primitive']['type'] for r in results if 'error' not in r]
                        self.print(f"\n  Summary: {len(results)} crashes — "
                                   f"{types.count('dos')} DoS, "
                                   f"{types.count('info_leak')} InfoLeak, "
                                   f"{types.count('write')} Write, "
                                   f"{types.count('execute')} Execute", "bold")
                    elif os.path.isfile(target_path):
                        self.print(f"\n🔬 CRASH ANALYSIS: {target_path}", "bold red")
                        analysis = analyzer.analyze_any(target_path)
                        self.print(analyzer.format_analysis(analysis))
                    else:
                        self.print(f"  File not found: {target_path}", "red")
                    continue

                if user_input.startswith('/binary'):
                    # Platform Adapter: unified binary analysis
                    # Usage: /binary <file_or_dir> [--compare file2]
                    binary_args = user_input[len('/binary'):].strip()
                    if not binary_args:
                        self.print("Usage: /binary <file_or_directory>", "yellow")
                        self.print("  /binary /usr/bin/ls                    — analyze any binary", "dim")
                        self.print("  /binary malware.exe                    — PE security check", "dim")
                        self.print("  /binary /usr/lib/                      — batch analyze dir", "dim")
                        self.print("  /binary a.exe --compare b.exe          — compare two binaries", "dim")
                        self.print("\nAuto-detects Mach-O, PE, ELF. Security score 0-100.", "dim")
                        continue

                    from core.platform_adapter import PlatformAdapter
                    adapter = PlatformAdapter()

                    if '--compare' in binary_args:
                        parts = binary_args.split('--compare')
                        path_a = os.path.expanduser(parts[0].strip())
                        path_b = os.path.expanduser(parts[1].strip())
                        if not os.path.isfile(path_a) or not os.path.isfile(path_b):
                            self.print("  Both files must exist for comparison", "red")
                            continue
                        a = adapter.analyze(path_a)
                        b = adapter.analyze(path_b)
                        self.print(f"\n  A: {a.summary()}", "")
                        self.print(f"\n  B: {b.summary()}", "")
                        diff = adapter.compare(path_a, path_b)
                        delta = diff['score_delta']
                        sign = '+' if delta > 0 else ''
                        self.print(f"\n  Score delta: {sign}{delta} "
                                   f"(A={diff['a']['score']}/{diff['a']['risk']} vs "
                                   f"B={diff['b']['score']}/{diff['b']['risk']})", "bold")
                        if diff['security_diff']:
                            for feat, vals in diff['security_diff'].items():
                                self.print(f"    {feat}: A={vals['a']} B={vals['b']}", "yellow")
                    elif os.path.isdir(os.path.expanduser(binary_args)):
                        target = os.path.expanduser(binary_args)
                        self.print(f"\n  Batch analysis: {target}", "bold")
                        results = adapter.analyze_directory(target)
                        if not results:
                            self.print("  No binaries found", "yellow")
                            continue
                        for info in results:
                            self.print(f"  [{info.security_score():3d}/100 {info.risk_level():8s}] "
                                       f"{info.format.upper():5s} {info.arch:8s} {os.path.basename(info.file)}",
                                       "bold" if info.risk_level() in ('HIGH', 'CRITICAL') else "")
                        avg = sum(i.security_score() for i in results) / len(results)
                        self.print(f"\n  {len(results)} binaries, avg score: {avg:.0f}/100", "bold")
                    elif os.path.isfile(os.path.expanduser(binary_args)):
                        info = adapter.analyze(os.path.expanduser(binary_args))
                        self.print(f"\n{info.summary()}", "")
                        triplets = adapter.to_triplets(info)
                        self.print(f"\n  {len(triplets)} causal triplets generated", "dim")
                    else:
                        self.print(f"  File not found: {binary_args}", "red")
                    continue

                if user_input.startswith('/xref'):
                    # Cross-reference analysis
                    # Usage: /xref <binary>
                    xref_target = user_input[len('/xref'):].strip()
                    if not xref_target:
                        self.print("Usage: /xref <binary_file>", "yellow")
                        self.print("  /xref /usr/bin/ls                      — call graph + data flow", "dim")
                        self.print("  /xref malware.exe                      — sink analysis", "dim")
                        self.print("\nTraces user input → dangerous sinks (memcpy, system, etc.)", "dim")
                        continue

                    from core.xref_engine import XRefEngine
                    xref_engine = XRefEngine()
                    target_path = os.path.expanduser(xref_target)

                    if not os.path.isfile(target_path):
                        self.print(f"  File not found: {target_path}", "red")
                        continue

                    result = xref_engine.analyze(target_path)
                    self.print(f"\n{xref_engine.format_analysis(result)}", "")

                    if result.get('error'):
                        self.print(f"  Note: {result['error']}", "yellow")

                    triplets = xref_engine.to_triplets()
                    if triplets:
                        self.print(f"\n  {len(triplets)} causal triplets from cross-references", "dim")
                    continue

                if user_input.startswith('/decomp'):
                    # Decompilation-to-Triplet Pipeline
                    # Usage: /decomp <binary>
                    decomp_target = user_input[len('/decomp'):].strip()
                    if not decomp_target:
                        self.print("Usage: /decomp <binary_file>", "yellow")
                        self.print("  /decomp /usr/bin/sshd                  — full vulnerability analysis", "dim")
                        self.print("  /decomp malware.exe                    — PE decompilation + vulns", "dim")
                        self.print("  /decomp firmware.elf                   — ELF stack/sink analysis", "dim")
                        self.print("\nCombines CFG + XRef + Platform analysis into vulnerability knowledge.", "dim")
                        self.print("Outputs: function profiles, vuln scores, hotspots, causal triplets.", "dim")
                        continue

                    from core.decompiler import DecompPipeline
                    pipeline = DecompPipeline()
                    target_path = os.path.expanduser(decomp_target)

                    if not os.path.isfile(target_path):
                        self.print(f"  File not found: {target_path}", "red")
                        continue

                    self.print(f"  Analyzing {target_path}...", "dim")
                    result = pipeline.analyze(target_path)
                    self.print(f"\n{pipeline.format_report(result)}", "")

                    if result.get('error'):
                        self.print(f"  Error: {result['error']}", "red")

                    triplets = pipeline.to_triplets()
                    if triplets:
                        self.print(f"\n  {len(triplets)} causal triplets from decompilation", "dim")
                    continue

                if user_input.startswith('/mutate'):
                    # Payload Mutation Engine
                    # Usage: /mutate <file> [--count N] [--level 1-5]
                    mut_args = user_input[len('/mutate'):].strip()
                    if not mut_args:
                        self.print("Usage: /mutate <python_file> [options]", "yellow")
                        self.print("  /mutate payload.py                     — 5 variants, level 3", "dim")
                        self.print("  /mutate payload.py --count 10          — 10 variants", "dim")
                        self.print("  /mutate payload.py --level 5           — max mutation", "dim")
                        self.print("\nLevels: 1=comments, 2=+rename, 3=+dead code, 4=+CFG, 5=all max", "dim")
                        continue

                    from core.mutation_engine import MutationEngine
                    me = MutationEngine()

                    count = 5
                    level = 3
                    if '--count' in mut_args:
                        m = re.search(r'--count\s+(\d+)', mut_args)
                        if m: count = int(m.group(1))
                        mut_args = re.sub(r'--count\s+\d+', '', mut_args).strip()
                    if '--level' in mut_args:
                        m = re.search(r'--level\s+(\d+)', mut_args)
                        if m: level = min(5, max(1, int(m.group(1))))
                        mut_args = re.sub(r'--level\s+\d+', '', mut_args).strip()

                    target = os.path.expanduser(mut_args.strip())
                    if not os.path.isfile(target):
                        self.print(f"  File not found: {target}", "red")
                        continue

                    with open(target) as f:
                        code = f.read()

                    self.print(f"\n  Mutating {target} ({len(code)} bytes, level={level})...", "bold")
                    variants = me.generate_variants(code, count=count, level=level)
                    self.print(f"\n{me.format_report(code, variants)}", "")

                    # Save variants
                    out_dir = Path('output_mutations')
                    out_dir.mkdir(exist_ok=True)
                    base = Path(target).stem
                    for i, v in enumerate(variants, 1):
                        vpath = out_dir / f"{base}_v{i}.py"
                        vpath.write_text(v['variant'])
                    self.print(f"\n  Saved {len(variants)} variants to {out_dir}/", "bold green")
                    continue

                if user_input.startswith('/detect'):
                    # Detection Self-Test
                    detect_args = user_input[len('/detect'):].strip()
                    if not detect_args:
                        self.print("Usage: /detect <file.py> [--mutate]", "yellow")
                        self.print("  /detect payload.py                     — scan against detection rules", "dim")
                        self.print("  /detect payload.py --mutate            — scan + auto-mutate until clean", "dim")
                        self.print(f"\nScans against {len(__import__('core.detection_test', fromlist=['STRING_SIGNATURES']).STRING_SIGNATURES)} string + import + behavior rules.", "dim")
                        continue

                    auto_mutate = '--mutate' in detect_args
                    target_file = detect_args.replace('--mutate', '').strip()
                    target_file = os.path.expanduser(target_file)

                    if not os.path.isfile(target_file):
                        self.print(f"  File not found: {target_file}", "red")
                        continue

                    with open(target_file, 'r') as f:
                        code = f.read()

                    from core.detection_test import DetectionEngine
                    detector = DetectionEngine()

                    if auto_mutate:
                        result = detector.scan_and_mutate(code)
                        self.print(f"\n{detector.format_mutate_result(result)}", "")
                        if result['final_clean']:
                            clean_path = os.path.splitext(target_file)[0] + '_clean.py'
                            with open(clean_path, 'w') as f:
                                f.write(result['final_code'])
                            self.print(f"\n  Clean variant saved: {clean_path}", "dim")
                    else:
                        scan = detector.scan(code)
                        self.print(f"\n{detector.format_scan(scan)}", "")

                    stats = detector.stats()
                    self.print(f"\n  Rules: {stats['total_rules']} ({stats['string_rules']} string, "
                              f"{stats['import_rules']} import, {stats['behavior_rules']} behavior)", "dim")
                    continue

                if user_input.startswith('/package'):
                    # Mission Package Builder
                    pkg_args = user_input[len('/package'):].strip()
                    if not pkg_args:
                        self.print("Usage: /package <payload.py> [name] [platform]", "yellow")
                        self.print("  /package exploit.py                    — build from Python payload", "dim")
                        self.print("  /package exploit.py 'Op Alpha' linux   — named package", "dim")
                        self.print("\nCreates: payload + variants, validation, cleanup, OpSec, reports", "dim")
                        continue

                    parts = pkg_args.split(None, 2)
                    target_file = os.path.expanduser(parts[0])
                    task_name = parts[1].strip("'\"") if len(parts) > 1 else ''
                    platform = parts[2] if len(parts) > 2 else 'linux'

                    if not os.path.isfile(target_file):
                        self.print(f"  File not found: {target_file}", "red")
                        continue

                    with open(target_file, 'r') as f:
                        code = f.read()

                    from core.mission_package import MissionPackageBuilder
                    builder = MissionPackageBuilder()
                    result = builder.build_from_forge_output(code, task_name or os.path.basename(target_file), platform)
                    self.print(f"\n{builder.format_report(result)}", "")
                    continue

                if user_input.startswith('/cfg'):
                    # Control Flow Graph recovery
                    # Usage: /cfg <binary>
                    cfg_target = user_input[len('/cfg'):].strip()
                    if not cfg_target:
                        self.print("Usage: /cfg <binary_file>", "yellow")
                        self.print("  /cfg /usr/bin/ls                       — extract CFG from binary", "dim")
                        self.print("  /cfg malware.exe                       — PE control flow analysis", "dim")
                        self.print("  /cfg firmware.elf                      — ELF function graph", "dim")
                        self.print("\nExtracts functions, basic blocks, branches, loops, cyclomatic complexity.", "dim")
                        continue

                    from core.cfg_engine import CFGEngine
                    cfg_engine = CFGEngine()
                    target_path = os.path.expanduser(cfg_target)

                    if not os.path.isfile(target_path):
                        self.print(f"  File not found: {target_path}", "red")
                        continue

                    result = cfg_engine.analyze(target_path)
                    self.print(f"\n{cfg_engine.format_summary(result)}", "")

                    if result.get('error'):
                        self.print(f"  Note: {result['error']}", "yellow")

                    triplets = cfg_engine.to_triplets()
                    if triplets:
                        self.print(f"\n  {len(triplets)} causal triplets from call graph", "dim")
                    continue

                if user_input.startswith('/fuzz'):
                    # Fuzzing Harness Generator
                    # Usage: /fuzz <type> [target] [--harness=type]
                    fuzz_args = user_input[len('/fuzz'):].strip()
                    if not fuzz_args:
                        self.print("Usage: /fuzz <vuln_type> [options]", "yellow")
                        self.print("  /fuzz buffer_overflow                  — generic overflow fuzzer", "dim")
                        self.print("  /fuzz uaf                              — use-after-free fuzzer", "dim")
                        self.print("  /fuzz integer_overflow                 — integer overflow fuzzer", "dim")
                        self.print("  /fuzz macho                            — Mach-O code sig fuzzer", "dim")
                        self.print("  /fuzz --from-crash report.ips          — fuzzer from crash log", "dim")
                        self.print("\nHarness types: python_mutator, afl_harness, libfuzzer_harness, macho_fuzzer", "dim")
                        continue

                    from core.fuzz_generator import FuzzGenerator
                    gen = FuzzGenerator()

                    # Parse options
                    harness_type = 'python_mutator'
                    if '--harness=' in fuzz_args:
                        ht_match = re.search(r'--harness=(\w+)', fuzz_args)
                        if ht_match:
                            harness_type = ht_match.group(1)
                            fuzz_args = fuzz_args.replace(ht_match.group(0), '').strip()

                    if fuzz_args.startswith('--from-crash'):
                        crash_path = fuzz_args.replace('--from-crash', '').strip()
                        if not crash_path:
                            self.print("  Provide crash file path", "red")
                            continue
                        from core.crash_analyzer import CrashAnalyzer
                        analyzer = CrashAnalyzer()
                        crash_path = os.path.expanduser(crash_path)
                        crash = analyzer.analyze_any(crash_path)
                        code = gen.generate_from_crash(crash)
                        self.print(f"\n🎯 FUZZER FROM CRASH: {crash['app']}", "bold red")
                    elif fuzz_args == 'macho':
                        code = gen.generate('buffer_overflow', {
                            'binary': 'codesign',
                            'function': 'verify_signature',
                            'input_type': 'file',
                        }, 'macho_fuzzer')
                        self.print(f"\n🎯 MACH-O CODE SIGNATURE FUZZER", "bold red")
                    else:
                        vuln_type = fuzz_args.split()[0]
                        code = gen.generate(vuln_type, {
                            'binary': './target',
                            'function': 'parse_input',
                            'input_type': 'file',
                        }, harness_type)
                        self.print(f"\n🎯 FUZZER: {vuln_type} ({harness_type})", "bold red")

                    # Save
                    output_dir = Path('output_fuzzers')
                    output_dir.mkdir(exist_ok=True)
                    safe_name = re.sub(r'[^\w]', '_', fuzz_args[:40]).strip('_')
                    ext = '.py' if 'python' in harness_type or harness_type == 'macho_fuzzer' else '.c'
                    output_path = output_dir / f"fuzz_{safe_name}{ext}"
                    output_path.write_text(code)

                    self.print(f"  {len(code)} chars, {code.count(chr(10))} lines")
                    self.print(f"  Saved to: {output_path}", "bold green")
                    continue

                if user_input.startswith('/decompile'):
                    # Decompilation-to-Triplet Pipeline
                    # Usage: /decompile <binary> [--json]
                    dec_args = user_input[len('/decompile'):].strip()
                    if not dec_args:
                        self.print("Usage: /decompile <binary_file>", "yellow")
                        self.print("  /decompile /usr/bin/ls                 — full decompilation pipeline", "dim")
                        self.print("  /decompile malware.exe                 — PE vuln analysis", "dim")
                        self.print("  /decompile firmware.elf --json         — JSON output", "dim")
                        self.print("\nCombines: binary analysis + CFG + cross-references → triplets", "dim")
                        continue

                    from core.decompiler import Decompiler
                    dec = Decompiler()

                    want_json = '--json' in dec_args
                    dec_args = dec_args.replace('--json', '').strip()
                    target_path = os.path.expanduser(dec_args)

                    if not os.path.isfile(target_path):
                        self.print(f"  File not found: {target_path}", "red")
                        continue

                    self.print(f"\n  Decompiling {target_path}...", "bold")
                    result = dec.analyze(target_path)

                    if want_json:
                        import json
                        self.print(json.dumps(result, indent=2, default=str))
                    else:
                        self.print(f"\n{dec.format_report(result)}", "")

                    if result.get('stats', {}).get('triplets', 0):
                        self.print(f"\n  {result['stats']['triplets']} causal triplets generated", "dim")
                    continue

                if user_input.startswith('/evasion'):
                    # Evasion Intelligence Engine
                    # Usage: /evasion [list|search|chain|detail|triplets]
                    ev_args = user_input[len('/evasion'):].strip()
                    from core.evasion_engine import EvasionEngine
                    ev = EvasionEngine()

                    if not ev_args or ev_args == 'list':
                        self.print(f"\n{ev.format_catalog()}", "")

                    elif ev_args == 'stats':
                        s = ev.stats()
                        self.print(f"\n  EVASION ENGINE STATS", "bold")
                        self.print(f"  Techniques:    {s['total_techniques']}")
                        self.print(f"  MITRE IDs:     {s['mitre_ids']}")
                        self.print(f"  With detection: {s['with_detection']}")
                        self.print(f"  With bypass:   {s['with_bypass_code']}")
                        self.print(f"  Categories:    {', '.join(f'{k}({v})' for k,v in s['categories'].items())}")

                    elif ev_args.startswith('search '):
                        query = ev_args[7:].strip()
                        results = ev.search(query)
                        if results:
                            for t in results:
                                self.print(f"  {t.id:8s} {t.name[:40]:<40s} [{t.category}]")
                        else:
                            self.print(f"  No results for: {query}", "yellow")

                    elif ev_args.startswith('chain'):
                        parts = ev_args.split()
                        platform = parts[1] if len(parts) > 1 else 'windows'
                        stealth = int(parts[2]) if len(parts) > 2 else 3
                        chain = ev.recommend_chain(platform, stealth)
                        self.print(f"\n{ev.format_chain(chain)}", "")

                    elif ev_args.startswith('detail ') or ev_args.startswith('show '):
                        tech_id = ev_args.split(maxsplit=1)[1].strip().upper()
                        self.print(f"\n{ev.format_technique(tech_id)}", "")

                    elif ev_args == 'triplets':
                        triplets = ev.to_triplets()
                        self.print(f"  {len(triplets)} evasion triplets generated", "bold green")
                        for t in triplets[:10]:
                            self.print(f"    {t['trigger'][:30]} -> {t['mechanism'][:25]} -> {t['outcome'][:30]}", "dim")
                        if len(triplets) > 10:
                            self.print(f"    ... ({len(triplets)-10} more)", "dim")

                    else:
                        self.print("Usage: /evasion [command]", "yellow")
                        self.print("  /evasion                    — list all techniques", "dim")
                        self.print("  /evasion stats              — technique statistics", "dim")
                        self.print("  /evasion search <query>     — search techniques", "dim")
                        self.print("  /evasion chain [platform] [stealth]  — recommend chain", "dim")
                        self.print("  /evasion detail <ID>        — technique detail", "dim")
                        self.print("  /evasion triplets           — generate triplets", "dim")
                    continue

                if user_input.startswith('/ops'):
                    # Operation Replay Engine
                    # Usage: /ops [list|stats|show|replay|best|similar|triplets]
                    ops_args = user_input[len('/ops'):].strip()
                    from core.operation_replay import OperationReplayEngine

                    replay = OperationReplayEngine()

                    if not ops_args or ops_args == 'list':
                        self.print(f"\n{replay.format_list()}")

                    elif ops_args == 'stats':
                        self.print(f"\n{replay.format_stats()}")

                    elif ops_args.startswith('show '):
                        op_id = ops_args[5:].strip()
                        self.print(f"\n{replay.format_operation(op_id)}")

                    elif ops_args.startswith('replay '):
                        parts = ops_args[7:].strip().split()
                        if len(parts) >= 2:
                            op_id, new_target = parts[0], parts[1]
                            plan = replay.create_replay_plan(op_id, new_target)
                            if 'error' in plan:
                                self.print(f"  {plan['error']}", "red")
                            else:
                                self.print(f"\n  REPLAY PLAN", "bold")
                                self.print(f"  Source: {plan['source_target']} -> {plan['new_target']}")
                                self.print(f"  Steps: {plan['total_steps']}")
                                for s in plan['steps']:
                                    self.print(f"    {s['step']}: [{s['type']}] {s['action']}")
                        else:
                            self.print("Usage: /ops replay <operation_id> <new_target>", "yellow")

                    elif ops_args.startswith('best '):
                        target_type = ops_args[5:].strip()
                        best = replay.best_methodology_for(target_type)
                        if best:
                            self.print(f"\n  BEST METHODOLOGY for '{target_type}'", "bold")
                            self.print(f"  Source: {best['target']} ({best['operation_id']})")
                            self.print(f"  Method: {' -> '.join(best['methodology'])}")
                            self.print(f"  Score: {best['score']} | Findings: {best['total_findings']}")
                        else:
                            self.print(f"  No operations found for type '{target_type}'", "yellow")

                    elif ops_args.startswith('similar '):
                        target = ops_args[8:].strip()
                        similar = replay.similar_operations(target)
                        if similar:
                            self.print(f"\n  SIMILAR OPERATIONS to '{target}'", "bold")
                            for s in similar:
                                status = 'OK' if s['success'] else 'FAIL'
                                self.print(f"    [{s['similarity']}] {s['target']} — "
                                          f"{' -> '.join(s['methodology'])} ({s['findings']} findings, {status})")
                        else:
                            self.print(f"  No similar operations found", "yellow")

                    elif ops_args == 'triplets':
                        triplets = replay.to_triplets()
                        self.print(f"\n  Operation triplets: {len(triplets)}", "bold")
                        for t in triplets[:10]:
                            self.print(f"    {t['trigger'][:40]} -> {t['outcome'][:30]}")
                        if len(triplets) > 10:
                            self.print(f"    ... ({len(triplets)-10} more)", "dim")

                    else:
                        self.print("Usage: /ops [command]", "yellow")
                        self.print("  /ops                        — list all operations", "dim")
                        self.print("  /ops stats                  — strategy statistics", "dim")
                        self.print("  /ops show <id>              — show operation details", "dim")
                        self.print("  /ops replay <id> <target>   — create replay plan", "dim")
                        self.print("  /ops best <target_type>     — best methodology for type", "dim")
                        self.print("  /ops similar <target>       — find similar operations", "dim")
                        self.print("  /ops triplets               — export learned strategies", "dim")
                    continue

                if user_input.startswith('/kb'):
                    # Knowledge Base Versioning
                    kb_args = user_input[len('/kb'):].strip()
                    from core.kb_versioning import KBVersioning

                    kbv = KBVersioning()

                    if not kb_args or kb_args == 'status':
                        self.print(f"\n{kbv.format_status()}")

                    elif kb_args.startswith('snapshot'):
                        label = kb_args[9:].strip() if len(kb_args) > 9 else ''
                        v = kbv.snapshot(label)
                        self.print(f"\n  Snapshot created: {v.label}", "bold green")
                        self.print(f"  Files: {len(v.files)} | "
                                  f"Triplets: {v.stats.get('bridge_triplets', 0)} | "
                                  f"Causal: {v.stats.get('causal_files', 0)}")

                    elif kb_args == 'versions':
                        self.print(f"\n{kbv.format_versions()}")

                    elif kb_args.startswith('diff'):
                        parts = kb_args.split()
                        if len(parts) == 3:
                            d = kbv.diff(int(parts[1]), int(parts[2]))
                        else:
                            d = kbv.diff()
                        self.print(f"\n{kbv.format_diff(d)}")

                    elif kb_args == 'verify':
                        result = kbv.verify_integrity()
                        if result['ok']:
                            self.print(f"\n  Integrity: OK ({result['files_checked']} files)", "bold green")
                        else:
                            self.print(f"\n  Integrity: VIOLATION", "bold red")
                            if result.get('corrupted'):
                                for c in result['corrupted']:
                                    self.print(f"    CORRUPTED: {c['file']}", "red")
                            if result.get('missing'):
                                for m in result['missing']:
                                    self.print(f"    MISSING: {m}", "yellow")

                    elif kb_args == 'suspects':
                        suspects = kbv.detect_suspect_triplets()
                        self.print(f"\n  Suspect triplets: {len(suspects)}", "bold")
                        for s in suspects[:20]:
                            self.print(f"    [{s['index']}] {s['trigger'][:40]} — {', '.join(s['reasons'])}")
                        if len(suspects) > 20:
                            self.print(f"    ... ({len(suspects)-20} more)", "dim")

                    elif kb_args.startswith('quarantine '):
                        indices = [int(x) for x in kb_args[11:].split() if x.isdigit()]
                        if indices:
                            result = kbv.quarantine_triplets(indices)
                            self.print(f"\n  Quarantined: {result['quarantined']} triplets", "bold")
                            self.print(f"  Remaining: {result['remaining_triplets']}")
                        else:
                            self.print("Usage: /kb quarantine <index1> <index2> ...", "yellow")

                    elif kb_args.startswith('rollback '):
                        vid = int(kb_args[9:].strip())
                        result = kbv.rollback(vid)
                        if 'error' in result:
                            self.print(f"  {result['error']}", "red")
                        else:
                            self.print(f"\n  Rolled back to: {result['rolled_back_to']}", "bold green")
                            self.print(f"  Restored: {result['restored_files']} files")
                            self.print(f"  Quarantined: {result['quarantined_files']} files")

                    elif kb_args == 'growth':
                        timeline = kbv.growth_timeline()
                        if timeline:
                            self.print(f"\n  KB GROWTH TIMELINE", "bold")
                            for t in timeline:
                                self.print(f"    {t['version']}: {t['date']} — "
                                          f"{t.get('bridge_triplets', '?')} triplets, "
                                          f"{t['files']} files")
                        else:
                            self.print("  No versions recorded yet", "yellow")

                    else:
                        self.print("Usage: /kb [command]", "yellow")
                        self.print("  /kb                         — knowledge base status", "dim")
                        self.print("  /kb snapshot [label]        — create version snapshot", "dim")
                        self.print("  /kb versions                — list all versions", "dim")
                        self.print("  /kb diff [v1 v2]            — diff versions (or vs current)", "dim")
                        self.print("  /kb verify                  — integrity check", "dim")
                        self.print("  /kb suspects                — detect bad triplets", "dim")
                        self.print("  /kb quarantine <idx> ...    — quarantine suspect triplets", "dim")
                        self.print("  /kb rollback <version_id>   — rollback to version", "dim")
                        self.print("  /kb growth                  — growth timeline", "dim")
                    continue

                if user_input.startswith('/intel'):
                    # Cross-Operation Intelligence
                    intel_args = user_input[len('/intel'):].strip()
                    from core.cross_intel import CrossIntelEngine

                    intel = CrossIntelEngine()

                    if not intel_args or intel_args == 'summary':
                        self.print(f"\n{intel.format_summary()}", "")

                    elif intel_args == 'patterns':
                        patterns = intel.detect_patterns()
                        self.print(f"\n{intel.format_patterns(patterns)}", "")

                    elif intel_args == 'profiles':
                        profiles = intel.build_family_profiles()
                        self.print(f"\n{intel.format_profiles(profiles)}", "")

                    elif intel_args == 'insights':
                        insights = intel.generate_insights()
                        self.print(f"\n{intel.format_insights(insights)}", "")

                    elif intel_args == 'correlation':
                        self.print(f"\n{intel.format_correlation()}", "")

                    else:
                        self.print("Usage: /intel <subcommand>", "yellow")
                        self.print("  /intel                      — full intelligence summary", "dim")
                        self.print("  /intel summary              — summary overview", "dim")
                        self.print("  /intel patterns             — vulnerability patterns", "dim")
                        self.print("  /intel profiles             — target family profiles", "dim")
                        self.print("  /intel insights             — strategic insights", "dim")
                        self.print("  /intel correlation          — technique × vuln matrix", "dim")
                    continue

                if user_input.startswith('/report'):
                    # Vulnerability Report Generator
                    # Usage: /report <findings_dir_or_file> [--format apple|bsi|json|all] [--output dir]
                    rpt_args = user_input[len('/report'):].strip()

                    if not rpt_args:
                        self.print("Usage: /report <source> [options]", "yellow")
                        self.print("  /report findings.json                  — generate from JSON findings", "dim")
                        self.print("  /report output_sota_audit/zday_03/     — generate from directory", "dim")
                        self.print("  /report --demo                         — demo with sample findings", "dim")
                        self.print("  Options:", "dim")
                        self.print("    --format apple|bsi|json|all          — output format (default: all)", "dim")
                        self.print("    --output <dir>                       — output directory", "dim")
                        self.print("    --title 'Report Title'               — set report title", "dim")
                        continue

                    from core.vuln_report import VulnReportGenerator, cvss_score
                    import glob

                    gen = VulnReportGenerator()

                    # Parse options
                    parts = rpt_args.split()
                    fmt = 'all'
                    output_dir = None
                    title = None
                    source = None
                    i = 0
                    while i < len(parts):
                        if parts[i] == '--format' and i + 1 < len(parts):
                            fmt = parts[i + 1]
                            i += 2
                        elif parts[i] == '--output' and i + 1 < len(parts):
                            output_dir = parts[i + 1]
                            i += 2
                        elif parts[i] == '--title' and i + 1 < len(parts):
                            title = parts[i + 1]
                            i += 2
                        elif parts[i] == '--demo':
                            source = '__demo__'
                            i += 1
                        elif not source:
                            source = parts[i]
                            i += 1
                        else:
                            i += 1

                    if source == '__demo__':
                        # Demo findings
                        gen.add_findings([
                            {'pattern': 'deserialization', 'code': 'pickle.loads(user_input)',
                             'severity': 'CRITICAL', 'cwe': 'CWE-502', 'line': 42,
                             'description': 'Pickle deserialization of untrusted input',
                             'cve_examples': ['CVE-2019-6446']},
                            {'pattern': 'command_injection', 'code': 'os.system(cmd)',
                             'severity': 'HIGH', 'cwe': 'CWE-78', 'line': 87,
                             'description': 'OS command constructed from user input'},
                            {'pattern': 'toctou', 'code': 'os.path.exists(f) then open(f)',
                             'severity': 'MEDIUM', 'cwe': 'CWE-367', 'line': 15,
                             'description': 'File existence check then open — race window'},
                        ])
                        gen.set_metadata(title='Demo Vulnerability Report',
                                        target='sample_application.py')
                    elif source and os.path.isfile(source):
                        with open(source) as fh:
                            data = json.load(fh)
                        if isinstance(data, list):
                            gen.add_findings(data)
                        elif isinstance(data, dict) and 'findings' in data:
                            gen.add_findings(data['findings'])
                        gen.set_metadata(target=source)
                    elif source and os.path.isdir(source):
                        # Load from directory (JSON files + .ips crash logs)
                        for jf in sorted(glob.glob(os.path.join(source, '*.json'))):
                            try:
                                with open(jf) as fh:
                                    data = json.load(fh)
                                if isinstance(data, list):
                                    gen.add_findings(data)
                                elif isinstance(data, dict):
                                    gen.add_finding(data)
                            except (json.JSONDecodeError, KeyError):
                                pass
                        # Also try crash logs
                        for ips in sorted(glob.glob(os.path.join(source, '*.ips'))):
                            try:
                                from core.crash_analyzer import CrashAnalyzer
                                ca = CrashAnalyzer()
                                analysis = ca.analyze_file(ips)
                                gen.add_finding(analysis)
                            except Exception:
                                pass
                        gen.set_metadata(target=source)
                    else:
                        self.print(f"Source not found: {source}", "red")
                        continue

                    if title:
                        gen.set_metadata(title=title)

                    if not gen.findings:
                        self.print("No findings loaded.", "yellow")
                        continue

                    # Display summary
                    self.print(f"\n{gen.format_summary()}")

                    # Determine formats
                    if fmt == 'all':
                        formats = ['markdown', 'apple', 'bsi', 'json']
                    else:
                        formats = [fmt]

                    # Save
                    if not output_dir:
                        output_dir = os.path.join('output_sota_audit', 'vuln_report')
                    saved = gen.save(output_dir, formats)

                    self.print(f"\n  Reports saved:", "bold green")
                    for fmt_name, fpath in saved.items():
                        self.print(f"    {fmt_name}: {fpath}")

                    # Show triplet count
                    triplets = gen.to_triplets()
                    self.print(f"\n  Exportable triplets: {len(triplets)}")
                    continue

                if user_input.startswith('/targets'):
                    # Target Queue Manager
                    # Usage: /targets [add|next|stats|list|preset|clear]
                    tq_args = user_input[len('/targets'):].strip()
                    from core.target_queue import TargetQueue, Target

                    tq = TargetQueue()

                    if not tq_args or tq_args == 'list':
                        self.print(f"\n{tq.format_queue()}")

                    elif tq_args == 'stats':
                        s = tq.stats()
                        self.print(f"\n  TARGET QUEUE STATS", "bold")
                        self.print(f"  Total:     {s['total']}")
                        self.print(f"  Queued:    {s['queued']}")
                        self.print(f"  Active:    {s['active']}")
                        self.print(f"  Completed: {s['completed']}")
                        self.print(f"  Failed:    {s['failed']}")
                        self.print(f"  Findings:  {s['total_findings']}")
                        self.print(f"  Avg Score: {s['avg_priority']}", "bold green")

                    elif tq_args == 'next':
                        t = tq.next()
                        if t:
                            self.print(f"\n  NEXT TARGET: {t.name}", "bold")
                            self.print(f"  Path:     {t.path}")
                            self.print(f"  Platform: {t.platform} ({t.arch})")
                            self.print(f"  Priority: {t.priority:.1f}")
                            self.print(f"  Priv:     {t.privilege_level}")
                            self.print(f"  Network:  {t.network_exposure}")
                        else:
                            self.print("  Queue empty", "yellow")

                    elif tq_args.startswith('add '):
                        filepath = tq_args[4:].strip()
                        if os.path.isdir(filepath):
                            count = tq.import_directory(filepath)
                            self.print(f"  Imported {count} targets from {filepath}", "bold green")
                        elif os.path.isfile(filepath):
                            t = tq.import_from_binary(filepath)
                            if t:
                                self.print(f"  Added: {t.name} (priority={t.priority:.1f})", "bold green")
                            else:
                                self.print(f"  Not a recognized binary: {filepath}", "red")
                        else:
                            self.print(f"  Not found: {filepath}", "red")

                    elif tq_args.startswith('preset '):
                        preset = tq_args[7:].strip()
                        presets = {
                            'macos': TargetQueue.macos_high_value,
                            'linux': TargetQueue.linux_high_value,
                            'windows': TargetQueue.windows_high_value,
                        }
                        if preset in presets:
                            targets = presets[preset]()
                            added = tq.add_batch(targets)
                            self.print(f"  Added {added} {preset} targets", "bold green")
                        else:
                            self.print(f"  Presets: macos, linux, windows", "yellow")

                    elif tq_args == 'requeue':
                        tq.requeue_all()
                        self.print("  All targets re-scored and requeued", "green")

                    elif tq_args.startswith('clear'):
                        status = tq_args[6:].strip() if len(tq_args) > 5 else None
                        tq.clear(status or None)
                        self.print(f"  Cleared {'all' if not status else status} targets", "yellow")

                    else:
                        self.print("Usage: /targets [command]", "yellow")
                        self.print("  /targets                    — show queue", "dim")
                        self.print("  /targets stats              — queue statistics", "dim")
                        self.print("  /targets next               — get next target", "dim")
                        self.print("  /targets add <path>         — add binary/directory", "dim")
                        self.print("  /targets preset macos       — load preset targets", "dim")
                        self.print("  /targets requeue            — re-score all targets", "dim")
                        self.print("  /targets clear              — clear queue", "dim")
                    continue

                if user_input.startswith('/findings'):
                    # Finding Aggregator
                    # Usage: /findings [stats|top|search|query]
                    fa_args = user_input[len('/findings'):].strip()
                    from core.finding_aggregator import FindingAggregator

                    fa = FindingAggregator()

                    if not fa_args or fa_args == 'top':
                        findings = fa.top_findings(15)
                        self.print(f"\n{fa.format_findings(findings)}")

                    elif fa_args == 'stats':
                        self.print(f"\n{fa.format_stats()}")

                    elif fa_args.startswith('search '):
                        query = fa_args[7:].strip()
                        results = fa.search(query)
                        self.print(f"\n  Search: \"{query}\" — {len(results)} results")
                        self.print(fa.format_findings(results))

                    elif fa_args.startswith('target '):
                        target = fa_args[7:].strip()
                        results = fa.by_target(target)
                        self.print(f"\n  Findings for \"{target}\" — {len(results)} results")
                        self.print(fa.format_findings(results, verbose=True))

                    elif fa_args.startswith('prim '):
                        prim = fa_args[5:].strip()
                        results = fa.query(primitive_type=prim)
                        self.print(f"\n  {prim.upper()} primitives — {len(results)} results")
                        self.print(fa.format_findings(results))

                    elif fa_args == 'timeline':
                        results = fa.timeline(24)
                        self.print(f"\n  Last 24h — {len(results)} findings")
                        self.print(fa.format_findings(results))

                    else:
                        self.print("Usage: /findings [command]", "yellow")
                        self.print("  /findings                   — top findings", "dim")
                        self.print("  /findings stats             — statistics", "dim")
                        self.print("  /findings search <text>     — search findings", "dim")
                        self.print("  /findings target <name>     — by target", "dim")
                        self.print("  /findings prim write        — by primitive type", "dim")
                        self.print("  /findings timeline          — last 24h", "dim")
                    continue

                if user_input.startswith('/hunt'):
                    # Autonomous Hunt Loop
                    # Usage: /hunt [cycles] [--status] [--stop]
                    hunt_args = user_input[len('/hunt'):].strip()
                    from core.hunt_loop import HuntLoop

                    if not hasattr(self, '_hunt_loop'):
                        self._hunt_loop = HuntLoop()

                    if hunt_args == 'status':
                        self.print(f"\n{self._hunt_loop.format_status()}")

                    elif hunt_args == 'stop':
                        self._hunt_loop.stop()
                        self.print("  Hunt loop stopped", "yellow")

                    elif hunt_args == 'cleanup':
                        self._hunt_loop.cleanup()
                        self.print("  Work directory cleaned", "green")

                    elif not hunt_args:
                        self.print("Usage: /hunt [cycles]", "yellow")
                        self.print("  /hunt 5                     — run 5 hunt cycles", "dim")
                        self.print("  /hunt status                — show hunt status", "dim")
                        self.print("  /hunt stop                  — stop running hunt", "dim")
                        self.print("  /hunt cleanup               — clean work dir", "dim")

                    else:
                        try:
                            cycles = int(hunt_args.split()[0])
                        except ValueError:
                            self.print("  Usage: /hunt <number>", "red")
                            continue

                        self.print(f"\n  HUNT LOOP — {cycles} cycles", "bold")
                        self.print(f"  Queue: {self._hunt_loop.queue.stats()['queued']} targets")

                        if self._hunt_loop.queue.stats()['queued'] == 0:
                            self.print("  Queue empty! Use /targets to add targets first.", "red")
                            continue

                        def cycle_callback(report):
                            status = report['status']
                            target = report.get('target', {}).get('name', '?')
                            findings = len(report.get('findings', []))
                            crashes = report.get('crashes', 0)
                            self.print(f"  [{report['cycle']}] {target}: "
                                       f"{crashes} crashes, {findings} findings "
                                       f"({report.get('duration', 0):.1f}s)")

                        summary = self._hunt_loop.run(cycles, callback=cycle_callback)

                        self.print(f"\n  HUNT COMPLETE", "bold green")
                        self.print(f"  Cycles:   {summary['cycles_run']}")
                        self.print(f"  Targets:  {summary['targets_processed']}")
                        self.print(f"  Crashes:  {summary['total_crashes']}")
                        self.print(f"  Findings: {summary['total_findings']}")
                        self.print(f"  Duration: {summary['duration']:.1f}s")
                        self.print(f"  Speed:    {summary['cycles_per_minute']} cycles/min")
                    continue

                if user_input.startswith('/chain'):
                    # Kill Chain Composer: auto-compose attack chains from fragments
                    # Usage: /chain <intent description>
                    chain_intent = user_input[len('/chain'):].strip()
                    if not chain_intent:
                        self.print("Usage: /chain <intent>", "yellow")
                        self.print("  /chain remote macos compromise with persistence", "dim")
                        self.print("  /chain active directory lateral movement with credential theft", "dim")
                        self.print("  /chain local privilege escalation to root", "dim")
                        self.print("  /chain network recon and service enumeration", "dim")
                        continue

                    from core.chain_composer import ChainComposer
                    composer = ChainComposer(fragments_dir=str(self.fragments_dir))

                    self.print(f"\n🔗 KILL CHAIN: {chain_intent}", "bold red")

                    # Resolve intent
                    params = composer.graph.resolve_intent_to_chain(chain_intent)
                    self.print(f"  Entry: {', '.join(params['entry_caps'])}", "dim")
                    self.print(f"  Objectives: {', '.join(params['objectives'])}", "dim")
                    if params['required_stages']:
                        self.print(f"  Required stages: {', '.join(params['required_stages'])}", "dim")

                    # Compose chains
                    results = composer.compose_chain(chain_intent, max_chains=3)

                    if not results:
                        self.print("\n  No kill chains found for this intent.", "yellow")
                        continue

                    self.print(f"\n  Found {len(results)} kill chain(s):\n", "green")

                    for i, r in enumerate(results, 1):
                        chain = r['chain']
                        self.print(f"  {'═' * 56}", "bold")
                        self.print(f"  Chain {i} — Score: {r['score']}, "
                                   f"{len(chain['fragments'])} fragments, "
                                   f"{len(chain['stages'])} stages", "bold cyan")
                        self.print(f"  {'═' * 56}", "bold")
                        self.print(f"  Stages: {' → '.join(chain['stages'])}", "cyan")
                        self.print(f"  Fragments: {', '.join(chain['fragments'])}", "green")

                        # ATT&CK mapping
                        if r['att_ck']:
                            self.print(f"  ATT&CK:", "yellow")
                            for t in r['att_ck'][:8]:
                                self.print(f"    {t['id']}: {t['name']} [{t['tactic']}]", "yellow")

                        # Path
                        self.print(f"  Path:", "dim")
                        for src, mech, dst in chain['path']:
                            self.print(f"    {src} → [{mech}] → {dst}", "dim")

                        # Code stats
                        code_lines = r['code'].count('\n')
                        self.print(f"  Code: {len(r['code'])} chars, {code_lines} lines", "green")
                        self.print("")

                    # Save best chain to output
                    best = results[0]
                    output_dir = Path('output_chains')
                    output_dir.mkdir(exist_ok=True)
                    safe_name = re.sub(r'[^\w]', '_', chain_intent[:50]).strip('_')
                    output_path = output_dir / f"chain_{safe_name}.py"
                    output_path.write_text(best['code'])
                    self.print(f"  Best chain saved to: {output_path}", "bold green")
                    continue

                if user_input.startswith('/autonomous'):
                    # Full Autonomous Loop: generate → simulate → fix → execute → diagnose → repair
                    # Usage: /autonomous [v2|v3|v4] [max_tasks]
                    parts = user_input.split()
                    benchmark = 'v2'
                    max_tasks = 0
                    for p in parts[1:]:
                        if p in ('v2', 'v3', 'v4', 'cir'):
                            benchmark = p
                        elif p.isdigit():
                            max_tasks = int(p)

                    from core.autonomous_loop import AutonomousLoop
                    loop = AutonomousLoop()
                    result = loop.run(benchmark_name=benchmark, max_tasks=max_tasks)
                    self.print(f"\n{loop.format_stats()}", "bold cyan")
                    continue

                if user_input.startswith('/fragment-stats'):
                    # Fragment Quality Report
                    from core.fragment_scorer import FragmentScorer
                    scorer = FragmentScorer()
                    parts = user_input.split()
                    if len(parts) > 1 and parts[1].isdigit():
                        top_n = int(parts[1])
                    else:
                        top_n = 20
                    report = scorer.format_report(top_n)
                    self.print(f"\n{report}", "cyan")
                    continue

                if user_input.startswith('/turbo'):
                    # Turbo Loop: autonomous self-improvement on V3 tasks
                    # Usage: /turbo [num_cycles] [--benchmark]
                    parts = user_input.split()
                    num_cycles = 250  # Default
                    benchmark = False

                    for p in parts[1:]:
                        if p.isdigit():
                            num_cycles = int(p)
                        elif p == '--benchmark':
                            benchmark = True

                    self.print(f"\n⚡ TURBO LOOP: {num_cycles} cycles on V3 tasks", "bold cyan")
                    result = self.handle_turbo(num_cycles, benchmark)
                    self.print(f"\n{result}", "bold green")
                    continue

                # Process input
                response = self.handle_input(user_input)

                if response:
                    self.print(f"\n{response}")

            except KeyboardInterrupt:
                self.print("\n\n👋 Goodbye!", "bold")
                break
            except Exception as e:
                self.print(f"\n❌ Error: {e}", "bold red")
                if '--debug' in sys.argv:
                    raise


def main():
    """Entry point"""
    session = ForgeSession()
    session.run()


if __name__ == "__main__":
    main()
