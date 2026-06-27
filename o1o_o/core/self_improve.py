"""
Self-Improvement Engine — O1-O extends itself by playing against the Python runtime

1. GapDetector: Analyze knowledge base for weak spots
2. TaskGenerator: Convert gaps into natural language BUILD queries
3. SelfImproveLoop: Execute tasks, learn from results, repeat

Usage:
    from o1o_o.core.self_improve import SelfImproveLoop
    loop = SelfImproveLoop(session)
    loop.run(max_iterations=500, time_budget_hours=8)
"""
# Dependencies: auto_bridge, auto_harvester, failure_memory, fragment_registry, output_oracle
# Depended by: none (leaf module)


import time
import random
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict


class GapDetector:
    """Analyze the knowledge base to find weak spots worth testing"""

    def __init__(self, knowledge_engine, fragments: Dict[str, str],
                 bridge_triplets: List[Dict], composition_triplets: List[Dict]):
        self.knowledge = knowledge_engine
        self.fragments = fragments
        self.bridge_triplets = bridge_triplets
        self.composition_triplets = composition_triplets

    def detect_all(self) -> List[Dict[str, Any]]:
        """Return all detected gaps, sorted by priority (highest first)"""
        gaps = []
        gaps.extend(self._find_orphan_fragments())
        gaps.extend(self._find_low_confidence_triplets())
        gaps.extend(self._find_untested_compositions())
        gaps.extend(self._find_underconnected_entities())

        # Sort by priority descending
        gaps.sort(key=lambda g: g['priority'], reverse=True)
        return gaps

    def _find_orphan_fragments(self) -> List[Dict]:
        """Find fragments that no bridge triplet points to.

        These fragments exist in code but are unreachable — FORGE can never
        select them because no user query maps to them.
        """
        # Collect all fragment keys that ARE referenced by bridges
        bridged_keys = set()
        for t in self.bridge_triplets:
            outcome = t.get('outcome', '')
            bridged_keys.add(outcome)
            # Also handle composition outcomes (key1+key2)
            if '+' in outcome:
                for part in outcome.split('+'):
                    bridged_keys.add(part.strip())

        for t in self.composition_triplets:
            outcome = t.get('outcome', '')
            if '+' in outcome:
                for part in outcome.split('+'):
                    bridged_keys.add(part.strip())
            else:
                bridged_keys.add(outcome)

        gaps = []
        for frag_key in self.fragments:
            if frag_key not in bridged_keys:
                gaps.append({
                    'type': 'orphan_fragment',
                    'fragment_key': frag_key,
                    'priority': 9,  # Highest — unreachable code is worst
                    'description': f'Fragment "{frag_key}" has no bridge pointing to it',
                })

        return gaps

    def _find_low_confidence_triplets(self) -> List[Dict]:
        """Find triplets with confidence below 0.5 that need verification."""
        gaps = []
        for t in self.knowledge.all_triplets:
            conf = t.get('confidence', 0.5)
            if conf < 0.5 and not t.get('is_inferred'):
                # Skip meta-triplets and learning artifacts
                mech = t.get('mechanism', '')
                if mech in ('effective_for', 'often_paired_with', 'solved_by',
                            'implements_with'):
                    continue

                gaps.append({
                    'type': 'low_confidence',
                    'triplet': t,
                    'priority': 5 + (0.5 - conf) * 4,  # Lower conf = higher priority
                    'description': f'Triplet "{t["trigger"]}→{mech}→{t["outcome"]}" has conf={conf:.2f}',
                })

        return gaps

    def _find_untested_compositions(self) -> List[Dict]:
        """Find fragment pairs that could work together but have no composition triplet.

        We look for SOURCE→SINK pairs where the source produces something
        the sink consumes, but no composition triplet exists for the pair.
        """
        from o1o_o.core.fragment_registry import FragmentRegistry
        registry = FragmentRegistry()
        registry.analyze_all(self.fragments)

        sources = registry.get_sources()
        sinks = registry.get_sinks()
        transforms = registry.get_transforms()

        # All consumers = sinks + transforms
        consumers = sinks + transforms

        # Existing composition pairs
        existing_pairs = set()
        for t in self.composition_triplets:
            outcome = t.get('outcome', '')
            if '+' in outcome:
                parts = tuple(p.strip() for p in outcome.split('+'))
                existing_pairs.add(parts)

        gaps = []
        for source_key in sources:
            for consumer_key in consumers:
                if source_key == consumer_key:
                    continue

                pair = (source_key, consumer_key)
                if pair in existing_pairs:
                    continue

                # Check if wiring is possible
                wiring = registry.get_wiring(source_key, consumer_key)
                if wiring:
                    gaps.append({
                        'type': 'untested_composition',
                        'source': source_key,
                        'sink': consumer_key,
                        'wiring': wiring,
                        'priority': 7,
                        'description': f'Possible composition: {source_key} → {consumer_key}',
                    })

        # Limit to avoid explosion
        random.shuffle(gaps)
        return gaps[:50]

    def _find_underconnected_entities(self) -> List[Dict]:
        """Find entities that appear in only one triplet (fragile knowledge)."""
        entity_counts = defaultdict(int)
        for t in self.knowledge.all_triplets:
            if t.get('is_inferred'):
                continue
            entity_counts[t['trigger']] += 1
            entity_counts[t['outcome']] += 1

        gaps = []
        for entity, count in entity_counts.items():
            if count == 1 and len(entity) >= 4:
                # Check if it's a useful entity (not a stopword-like thing)
                if entity in self.fragments:
                    gaps.append({
                        'type': 'underconnected',
                        'entity': entity,
                        'count': count,
                        'priority': 3,
                        'description': f'Entity "{entity}" has only {count} triplet',
                    })

        return gaps


class TaskGenerator:
    """Convert knowledge gaps into natural language BUILD queries"""

    # Templates for generating natural language tasks from fragment keys
    FRAGMENT_TASK_TEMPLATES = {
        # Module → verb phrases that should trigger fragments from that module
        'os': [
            'list all files in {path}',
            'walk through directory {path}',
            'get current working directory',
            'rename file {old_path} to {new_path}',
        ],
        'csv': [
            'read a CSV file',
            'write data to CSV',
            'read CSV as dictionary',
        ],
        'json': [
            'parse JSON from file',
            'save data as JSON',
            'pretty print JSON file',
        ],
        'requests': [
            'download a webpage',
            'send HTTP POST request',
            'fetch JSON from API',
        ],
        'hashlib': [
            'compute SHA256 hash of a file',
            'hash a string with MD5',
        ],
        'sqlite3': [
            'connect to SQLite database',
            'create a database table',
            'query SQLite database',
        ],
        'socket': [
            'scan open ports on host',
            'create a TCP connection',
        ],
        're': [
            'find all email addresses in text',
            'extract numbers from string',
            'replace pattern in text',
        ],
        'tarfile': [
            'compress a folder into tar.gz',
            'extract tar archive',
        ],
        'zipfile': [
            'create a zip file from directory',
            'extract zip archive',
        ],
        'glob': [
            'find all Python files recursively',
            'find files matching pattern',
        ],
        'random': [
            'generate a random number',
            'shuffle a list randomly',
            'pick random items from list',
        ],
        'datetime': [
            'get current date and time',
            'format date as string',
            'calculate date difference',
        ],
        'itertools': [
            'generate all permutations of a list',
            'create combinations of items',
        ],
        'difflib': [
            'compare two files',
            'find differences between texts',
        ],
        'platform': [
            'get system information',
            'check operating system details',
        ],
        'collections': [
            'count word frequency',
            'create a default dictionary',
        ],
        'time': [
            'measure execution time of code',
            'add a delay or sleep',
        ],
        'shutil': [
            'copy files to directory',
            'move files between directories',
        ],
        'subprocess': [
            'run shell command and capture output',
            'execute system command',
        ],
    }

    # Composition task templates
    COMPOSITION_TEMPLATES = [
        'download a webpage and save it to file',
        'read CSV and convert to JSON',
        'download webpage and extract emails',
        'scan ports and save results to file',
        'hash all files in directory',
        'find duplicate files in directory',
        'compress a folder into tar.gz archive',
        'merge all CSV files in directory',
        'merge all JSON files in directory',
        'batch rename files in directory',
        'list files sorted by size',
        'list files grouped by type',
        'read file and count words',
        'download JSON from API and save to file',
        'compare two text files and show differences',
        'read CSV and filter rows',
        'extract URLs from webpage',
        'download webpage and parse HTML text',
    ]

    def __init__(self, fragments: Dict[str, str]):
        self.fragments = fragments

    def generate_from_gap(self, gap: Dict[str, Any]) -> Optional[str]:
        """Generate a natural language BUILD query from a gap"""
        gap_type = gap['type']

        if gap_type == 'orphan_fragment':
            return self._task_for_orphan(gap)
        elif gap_type == 'low_confidence':
            return self._task_for_low_confidence(gap)
        elif gap_type == 'untested_composition':
            return self._task_for_composition(gap)
        elif gap_type == 'underconnected':
            return self._task_for_underconnected(gap)
        return None

    def _task_for_orphan(self, gap: Dict) -> Optional[str]:
        """Generate a task that should trigger an orphan fragment"""
        frag_key = gap['fragment_key']
        code = self.fragments.get(frag_key, '')

        if not code:
            return None

        # Strategy 1: Extract the module and pick a template
        module = self._extract_module(code)
        if module and module in self.FRAGMENT_TASK_TEMPLATES:
            templates = self.FRAGMENT_TASK_TEMPLATES[module]
            # Pick the template that best matches the fragment key
            best_template = None
            best_score = 0
            key_words = set(frag_key.lower().split('_'))

            for template in templates:
                template_words = set(template.lower().split())
                overlap = len(key_words & template_words)
                if overlap > best_score:
                    best_score = overlap
                    best_template = template
            if best_template:
                return best_template

        # Strategy 2: Build task from fragment key
        # "csv_dictreader" → "read csv as dictionary"
        # "os_walk" → "walk through directory"
        words = frag_key.replace('_', ' ').lower()
        return f'use {words}'

    def _task_for_low_confidence(self, gap: Dict) -> Optional[str]:
        """Generate a task that tests a low-confidence triplet"""
        t = gap['triplet']
        trigger = t['trigger']
        outcome = t['outcome']
        mechanism = t.get('mechanism', 'uses')

        # "csv → reads → rows" → "read a CSV file and get the rows"
        if mechanism in ('uses', 'reads', 'writes', 'creates', 'provides'):
            return f'use {trigger} to {mechanism.rstrip("s")} {outcome}'
        elif mechanism in ('type_of', 'is'):
            return f'what is {trigger}'  # Will be CHAT, but tests entity resolution
        else:
            return f'{trigger} {outcome}'

    def _task_for_composition(self, gap: Dict) -> Optional[str]:
        """Generate a task that tests a composition pair"""
        source = gap['source']
        sink = gap['sink']

        # Clean fragment key → verb phrase
        source_phrase = source.replace('_', ' ')
        sink_phrase = sink.replace('_', ' ')

        return f'{source_phrase} and then {sink_phrase}'

    def _task_for_underconnected(self, gap: Dict) -> Optional[str]:
        """Generate a task for an underconnected entity"""
        entity = gap['entity']
        return f'use {entity}'

    def generate_random_tasks(self, n: int = 10) -> List[str]:
        """Generate N random tasks from templates (for warmup/diversity)"""
        all_templates = []
        for templates in self.FRAGMENT_TASK_TEMPLATES.values():
            all_templates.extend(templates)
        all_templates.extend(self.COMPOSITION_TEMPLATES)

        random.shuffle(all_templates)
        return all_templates[:n]

    def _extract_module(self, code: str) -> Optional[str]:
        """Extract primary module from code"""
        for line in code.split('\n'):
            stripped = line.strip()
            if stripped.startswith('import '):
                parts = stripped.split()
                if len(parts) >= 2:
                    return parts[1].split('.')[0]
            elif stripped.startswith('from '):
                parts = stripped.split()
                if len(parts) >= 2:
                    return parts[1].split('.')[0]
        return None


class SelfImproveLoop:
    """
    Main self-improvement loop.

    O1-O analyzes its knowledge base → finds gaps → generates tasks →
    executes via Monte Carlo → learns from results → repeats.

    The system plays against the Python runtime: every task that compiles,
    runs, and produces semantically valid output extends the knowledge
    graph; every failure is classified and cached with a fix strategy.

    v2: Output Oracle validates output semantics (not just exit code).
        Failure Memory learns from errors and builds fix strategies.
    """

    def __init__(self, forge_session):
        """
        Args:
            forge_session: A ForgeSession instance (has knowledge, parser,
                          assembler, executor, learning, etc.)
        """
        self.session = forge_session
        self.knowledge = forge_session.knowledge
        self.parser = forge_session.intent_parser
        self.assembler = forge_session.code_assembler
        self.executor = forge_session.executor
        self.learning = forge_session.learning

        # Load bridge and composition triplets from JSON for gap detection
        base_dir = Path(forge_session.knowledge_dir).parent
        self.bridge_triplets = self._load_json(base_dir / 'bridge_triplets.json')
        self.composition_triplets = self._load_json(base_dir / 'composition_triplets.json')

        # Output Oracle — semantic output validation
        from o1o_o.core.output_oracle import OutputOracle
        self.oracle = OutputOracle()

        # Failure Memory — learn from errors
        from o1o_o.core.failure_memory import FailureMemory
        self.failure_memory = FailureMemory(
            str(base_dir / 'knowledge' / 'failure_patterns.json')
        )

        # Autonomous Harvester — discover new knowledge
        from o1o_o.core.auto_harvester import AutoHarvester
        self.harvester = AutoHarvester(forge_session)
        self.enable_harvest = False  # Off by default, enabled via --enable-harvest

        # Statistics
        self.stats = {
            'iterations': 0,
            'successes': 0,
            'failures': 0,
            'oracle_rejects': 0,
            'memory_fixes': 0,
            'new_triplets': 0,
            'new_bridges': 0,
            'gaps_found': 0,
            'gaps_closed': 0,
            'start_time': None,
            'end_time': None,
        }

        # Track what we've already tried (avoid repeating failed tasks)
        self.attempted_tasks = set()

        # Results log
        self.results_log = []

    def _load_json(self, path: Path) -> List[Dict]:
        """Load JSON file, return empty list if missing"""
        if path.exists():
            with open(path) as f:
                return json.load(f)
        return []

    def run(self, max_iterations: int = 500, time_budget_hours: float = 8.0,
            verbose: bool = True, enable_harvest: bool = False) -> Dict[str, Any]:
        """
        Run the self-improvement loop.

        Args:
            max_iterations: Maximum number of build-test cycles
            time_budget_hours: Stop after this many hours
            verbose: Print progress
            enable_harvest: Enable autonomous GitHub harvesting for unknown domains

        Returns:
            Statistics dict
        """
        self.enable_harvest = enable_harvest
        self.stats['start_time'] = time.time()
        deadline = self.stats['start_time'] + (time_budget_hours * 3600)

        if verbose:
            print(f"\n{'='*60}")
            print(f"  FORGE SELF-IMPROVEMENT ENGINE")
            print(f"  Max iterations: {max_iterations}")
            print(f"  Time budget: {time_budget_hours}h")
            print(f"{'='*60}\n")

        # Phase 1: Detect gaps
        if verbose:
            print("Phase 1: Detecting knowledge gaps...")

        detector = GapDetector(
            self.knowledge,
            self.assembler.fragments,
            self.bridge_triplets,
            self.composition_triplets
        )
        gaps = detector.detect_all()
        self.stats['gaps_found'] = len(gaps)

        if verbose:
            # Summarize gaps by type
            type_counts = defaultdict(int)
            for g in gaps:
                type_counts[g['type']] += 1
            print(f"  Found {len(gaps)} gaps:")
            for gap_type, count in sorted(type_counts.items()):
                print(f"    {gap_type}: {count}")

        # Phase 1b: Auto-bridge orphan fragments (new bridges → recompile)
        orphan_count = sum(1 for g in gaps if g['type'] == 'orphan_fragment')
        if orphan_count > 0:
            if verbose:
                print(f"\nPhase 1b: Auto-bridging {orphan_count} orphan fragments...")
            try:
                from o1o_o.core.auto_bridge import AutoBridgeGenerator
                import json
                base_dir = Path(self.session.knowledge_dir).parent
                bridge_path = base_dir / 'bridge_triplets.json'
                with open(bridge_path) as f:
                    existing_bridges = json.load(f)
                gen = AutoBridgeGenerator(self.assembler.fragments, existing_bridges)
                new_bridges = gen.generate_bridges()
                if new_bridges:
                    # Deduplicate
                    existing_triggers = {t['trigger'].lower() for t in existing_bridges}
                    truly_new = [b for b in new_bridges
                                 if b['trigger'].lower() not in existing_triggers]
                    if truly_new:
                        existing_bridges.extend(truly_new)
                        with open(bridge_path, 'w') as f:
                            json.dump(existing_bridges, f, indent=2)
                        self.bridge_triplets = existing_bridges
                        self.stats['new_bridges'] = len(truly_new)
                        if verbose:
                            print(f"  Generated {len(truly_new)} new bridge triplets")
                        # Reload bridge knowledge
                        self.knowledge.load_transient_triplets(truly_new, 'bridge_intents')
                        # Remove orphan gaps from the list (they're now bridged)
                        gaps = [g for g in gaps if g['type'] != 'orphan_fragment']
            except Exception as e:
                if verbose:
                    print(f"  Auto-bridge failed: {e}")

        # Phase 2: Generate tasks from gaps
        if verbose:
            print("\nPhase 2: Generating tasks from gaps...")

        generator = TaskGenerator(self.assembler.fragments)
        tasks = []
        for gap in gaps:
            task = generator.generate_from_gap(gap)
            if task and task not in self.attempted_tasks:
                tasks.append((task, gap))

        # Add random diversity tasks
        random_tasks = generator.generate_random_tasks(20)
        for task in random_tasks:
            if task not in self.attempted_tasks:
                tasks.append((task, {'type': 'random', 'priority': 2,
                                     'description': 'Random diversity task'}))

        if verbose:
            print(f"  Generated {len(tasks)} tasks")

        # Phase 3: Execute and learn (multi-round)
        round_num = 0
        while self.stats['iterations'] < max_iterations and time.time() < deadline:
            round_num += 1

            if round_num > 1:
                # Re-detect gaps for subsequent rounds (knowledge has grown)
                if verbose:
                    print(f"\n  --- Round {round_num}: Re-detecting gaps... ---")
                detector = GapDetector(
                    self.knowledge,
                    self.assembler.fragments,
                    self.bridge_triplets,
                    self.composition_triplets
                )
                gaps = detector.detect_all()
                generator = TaskGenerator(self.assembler.fragments)
                tasks = []
                for gap in gaps:
                    task = generator.generate_from_gap(gap)
                    if task and task not in self.attempted_tasks:
                        tasks.append((task, gap))
                random_tasks = generator.generate_random_tasks(20)
                for task in random_tasks:
                    if task not in self.attempted_tasks:
                        tasks.append((task, {'type': 'random', 'priority': 2,
                                             'description': 'Random diversity task'}))
                if not tasks:
                    if verbose:
                        print(f"  No new tasks to try. Stopping.")
                    break

            if verbose:
                print(f"\nPhase 3 (round {round_num}): Self-play loop ({len(tasks)} tasks)...\n")

            for i, (task_query, gap) in enumerate(tasks):
                if self.stats['iterations'] >= max_iterations:
                    if verbose:
                        print(f"\n  Reached max iterations ({max_iterations})")
                    break

                if time.time() > deadline:
                    if verbose:
                        print(f"\n  Time budget exhausted ({time_budget_hours}h)")
                    break

                self.stats['iterations'] += 1
                self.attempted_tasks.add(task_query)

                # Execute one cycle
                result = self._execute_cycle(task_query, gap, verbose)
                self.results_log.append(result)

                # Progress report every 50 iterations
                if verbose and self.stats['iterations'] % 50 == 0:
                    elapsed = time.time() - self.stats['start_time']
                    rate = self.stats['iterations'] / max(elapsed, 1)
                    print(f"\n  --- Progress: {self.stats['iterations']}/{max_iterations} "
                          f"({self.stats['successes']} ok, {self.stats['failures']} fail, "
                          f"{rate:.1f} iter/s) ---\n")

            # If we processed all tasks in this round, continue to next round
            if self.stats['iterations'] >= max_iterations:
                break

        # Phase 4: Persist results + failure memory
        self.stats['end_time'] = time.time()
        elapsed = self.stats['end_time'] - self.stats['start_time']
        self.failure_memory.save()

        if verbose:
            print(f"\n{'='*60}")
            print(f"  SELF-IMPROVEMENT COMPLETE")
            print(f"  Duration: {elapsed/60:.1f} min")
            print(f"  Iterations: {self.stats['iterations']}")
            print(f"  Successes: {self.stats['successes']}")
            print(f"  Failures: {self.stats['failures']}")
            print(f"  Oracle rejects: {self.stats['oracle_rejects']}")
            print(f"  Memory fixes: {self.stats['memory_fixes']}")
            print(f"  Success rate: {self.stats['successes']/max(self.stats['iterations'],1)*100:.1f}%")
            print(f"  New triplets: {self.stats['new_triplets']}")
            print(f"  Gaps closed: {self.stats['gaps_closed']}")
            fm_stats = self.failure_memory.get_stats()
            print(f"  Failure patterns: {fm_stats['total_error_patterns']}")
            print(f"  Fix strategies: {fm_stats['total_fix_strategies']}")
            if self.enable_harvest:
                h_stats = self.harvester.get_stats()
                print(f"  Domains harvested: {h_stats['domains_harvested']}")
                print(f"  Harvest triplets: {h_stats['triplets_extracted']}")
            print(f"{'='*60}")

        # Save results log
        self._save_results_log()

        return self.stats

    def _execute_cycle(self, task_query: str, gap: Dict, verbose: bool) -> Dict:
        """Execute one self-improvement cycle with Oracle + Failure Memory.

        Flow: parse → infer → seed-and-grow OR assemble → execute →
              oracle validation → fix (failure memory + auto_fix, up to 3) →
              learn from success / record failure
        """
        result = {
            'task': task_query,
            'gap_type': gap['type'],
            'success': False,
            'error': None,
            'new_triplets': 0,
            'fix_iterations': 0,
            'oracle_passed': None,
        }

        try:
            # Step 1: Parse intent
            intent = self.parser.parse(task_query)
            intent['mode'] = 'BUILD'

            if verbose:
                gap_label = gap['type'][:12].ljust(12)
                print(f"  [{self.stats['iterations']:4d}] {gap_label} \"{task_query[:50]}\"", end='')

            # Step 2: Infer chains
            chains = self.knowledge.infer(intent, top_k=3)
            if not chains:
                # Try autonomous harvesting if enabled
                if self.enable_harvest:
                    domain = self.harvester.identify_domain(task_query, intent)
                    if domain and self.harvester.should_harvest(domain):
                        if verbose:
                            print(f" -> harvesting '{domain}'...")
                        new_triplets = self.harvester.harvest(domain, verbose=verbose)
                        if new_triplets > 0:
                            # Retry inference after harvesting
                            chains = self.knowledge.infer(intent, top_k=3)

                if not chains:
                    if verbose:
                        print(f" -> no chains")
                    result['error'] = 'no_chains'
                    self.stats['failures'] += 1
                    return result

            # Step 3: Generate code — Seed-and-Grow first, then fallback
            best_script = None
            best_chain = chains[0]

            # Try seed-and-grow for multi-fragment tasks
            steps = self.assembler.decompose_chain(chains[0], intent)
            if len(steps) > 1:
                best_script = self._seed_and_grow_generate(steps, intent)

            # Fallback: standard assembly with Monte Carlo
            if not best_script:
                candidates = []
                for chain in chains:
                    try:
                        script = self.assembler.assemble(chain, intent)
                        if script and 'No implementation available' not in script:
                            candidates.append((script, chain))
                    except Exception:
                        pass

                if not candidates:
                    if verbose:
                        print(f" -> no candidates")
                    result['error'] = 'no_candidates'
                    self.stats['failures'] += 1
                    return result

                if len(candidates) > 1:
                    scripts = [c[0] for c in candidates]
                    batch_results = self.executor.run_batch(scripts, intent)
                    best = batch_results[0]
                    best_script = best['script']
                    best_chain = candidates[min(best['index'], len(candidates)-1)][1]
                else:
                    best_script = candidates[0][0]
                    best_chain = candidates[0][1]

            # Step 4: Execute + multi-iteration fix loop (up to 3 attempts)
            current_script = best_script
            max_fix_attempts = 3
            exec_result = None

            for attempt in range(max_fix_attempts):
                exec_result = self.executor.run(current_script, intent)

                if exec_result['success']:
                    # === OUTPUT ORACLE: validate output semantics ===
                    oracle_pass, oracle_reason, oracle_conf = self.oracle.validate(
                        exec_result.get('stdout', ''),
                        exec_result.get('stderr', ''),
                        exec_result.get('exit_code', 0),
                        intent,
                        current_script,
                    )
                    result['oracle_passed'] = oracle_pass

                    if oracle_pass:
                        self.stats['successes'] += 1
                        self.stats['gaps_closed'] += 1
                        result['success'] = True
                        result['fix_iterations'] = attempt

                        # Record fix success in failure memory (if we fixed something)
                        if attempt > 0:
                            self.failure_memory.record_fix(
                                exec_result.get('error', ''),
                                exec_result.get('stderr', ''),
                                best_script, current_script,
                                f"Fixed after {attempt} attempts"
                            )

                        # Learn from success
                        pre_count = len(self.learning.learned_triplets)
                        self.learning.learn_from_success(intent, best_chain, current_script)
                        new_count = len(self.learning.learned_triplets) - pre_count
                        self.stats['new_triplets'] += new_count
                        result['new_triplets'] = new_count

                        # Boost confidence on used triplets
                        for item in (best_chain if isinstance(best_chain, list) else []):
                            t = item.get('triplet', item)
                            if 'trigger' in t and 'outcome' in t:
                                self.knowledge.reward_triplet(
                                    t['trigger'], t['outcome'], boost=0.03
                                )

                        suffix = f" (fix #{attempt})" if attempt > 0 else ""
                        if verbose:
                            print(f" -> OK{suffix} (+{new_count} triplets)")
                        return result
                    else:
                        # Oracle rejected output — record but don't retry
                        self.stats['oracle_rejects'] += 1
                        if verbose:
                            print(f" -> ORACLE_REJECT ({oracle_reason[:40]})")
                        result['error'] = f'oracle_reject: {oracle_reason}'
                        self.stats['failures'] += 1
                        return result

                # Failed — try failure memory first, then auto_fix
                error_type = exec_result.get('error', 'UNKNOWN_ERROR')
                stderr = exec_result.get('stderr', '')

                # Record the failure
                fragment_key = ''
                if best_chain and isinstance(best_chain, list) and best_chain:
                    item = best_chain[0] if isinstance(best_chain[0], dict) else {}
                    t = item.get('triplet', item)
                    fragment_key = t.get('outcome', '')
                self.failure_memory.record_failure(
                    error_type, stderr, task_query, current_script, fragment_key
                )

                # Try failure memory fix first
                fixed = self.failure_memory.lookup_fix(error_type, stderr, current_script)
                if fixed and fixed != current_script:
                    self.stats['memory_fixes'] += 1
                    current_script = fixed
                    continue

                # Fallback: executor auto_fix
                fixed = self.executor.auto_fix(
                    current_script, error_type, self.knowledge,
                    stderr=stderr
                )

                if fixed and fixed != current_script:
                    # Record this fix attempt for failure memory learning
                    current_script = fixed
                else:
                    break  # No fix available

            # All attempts failed
            self.stats['failures'] += 1
            result['error'] = exec_result.get('error', 'UNKNOWN') if exec_result else 'no_exec'

            # Penalize failing triplets gently
            for item in (best_chain if isinstance(best_chain, list) else []):
                t = item.get('triplet', item)
                if 'trigger' in t and 'outcome' in t:
                    self.knowledge.penalize_triplet(
                        t['trigger'], t['outcome'], penalty=0.05
                    )

            if verbose:
                print(f" -> FAIL ({result['error']})")

        except Exception as e:
            result['error'] = str(e)
            self.stats['failures'] += 1
            if verbose:
                print(f" -> ERROR ({str(e)[:40]})")

        return result

    def _seed_and_grow_generate(self, steps: list, intent: dict):
        """Seed-and-Grow code generation for self-improvement.

        Builds one fragment at a time, testing after each step.
        Returns the best working script, or None if seed fails.
        """
        # SEED: Build first component
        seed_intent = dict(intent)
        seed_intent['requires_output'] = True
        seed_script = self.assembler.assemble([steps[0]], seed_intent)

        result = self.executor.run(seed_script, seed_intent)
        if not result['success']:
            fixed = self.executor.auto_fix(
                seed_script, result.get('error', ''),
                self.knowledge, stderr=result.get('stderr', '')
            )
            if fixed:
                result = self.executor.run(fixed, seed_intent)
                if result['success']:
                    seed_script = fixed
                else:
                    return None
            else:
                return None

        current = seed_script

        # GROW: Add components one at a time
        for i, step in enumerate(steps[1:], 2):
            grow_intent = dict(intent)
            grow_intent['requires_output'] = (i == len(steps))

            grown = self.assembler.grow_script(current, step, grow_intent)
            if grown == current:
                continue

            result = self.executor.run(grown, intent)
            if result['success']:
                current = grown
            else:
                fixed = self.executor.auto_fix(
                    grown, result.get('error', ''),
                    self.knowledge, stderr=result.get('stderr', '')
                )
                if fixed:
                    result = self.executor.run(fixed, intent)
                    if result['success']:
                        current = fixed

        return current

    def _save_results_log(self):
        """Save results log to JSON for analysis"""
        log_path = Path(self.session.knowledge_dir) / '..' / 'self_improve_log.json'
        log_path = log_path.resolve()

        summary = {
            'stats': self.stats,
            'results': self.results_log[-200:],  # Last 200 results
        }

        try:
            with open(log_path, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
        except Exception:
            pass

    def get_report(self) -> str:
        """Generate a human-readable report"""
        s = self.stats
        elapsed = (s.get('end_time', 0) or 0) - (s.get('start_time', 0) or 0)

        lines = [
            "FORGE Self-Improvement Report",
            "=" * 40,
            f"Duration: {elapsed/60:.1f} minutes",
            f"Iterations: {s['iterations']}",
            f"Successes: {s['successes']} ({s['successes']/max(s['iterations'],1)*100:.1f}%)",
            f"Failures: {s['failures']}",
            f"Gaps found: {s['gaps_found']}",
            f"Gaps closed: {s['gaps_closed']}",
            f"New triplets: {s['new_triplets']}",
            "",
            "Gap Type Breakdown:",
        ]

        # Breakdown by gap type
        type_stats = defaultdict(lambda: {'total': 0, 'success': 0})
        for r in self.results_log:
            gt = r.get('gap_type', 'unknown')
            type_stats[gt]['total'] += 1
            if r.get('success'):
                type_stats[gt]['success'] += 1

        for gt, ts in sorted(type_stats.items()):
            pct = ts['success'] / max(ts['total'], 1) * 100
            lines.append(f"  {gt}: {ts['success']}/{ts['total']} ({pct:.0f}%)")

        return '\n'.join(lines)
