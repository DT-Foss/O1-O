# Dependencies: none
# Depended by: none (leaf module)

import ast
import zlib
import msgpack
from pathlib import Path
from typing import List, Dict, Any, Optional

class PatternExtractor:
    """Analyze successful scripts to discover idioms via AST"""

    def extract_idioms(self, script: str) -> List[Dict[str, Any]]:
        """Parse AST to find common patterns (imports, with-statements, etc.)"""
        try:
            tree = ast.parse(script)
            idioms = []
            
            for node in ast.walk(tree):
                # Detect 'with' statements (context managers)
                if isinstance(node, ast.With):
                    idioms.append({'type': 'context_manager', 'node': 'with'})
                
                # Detect specific patterns like 'try-except'
                if isinstance(node, ast.Try):
                    idioms.append({'type': 'error_handling', 'node': 'try_except'})
                
                # Detect loops
                if isinstance(node, ast.For) or isinstance(node, ast.While):
                    idioms.append({'type': 'loop', 'node': 'iteration'})

            return idioms
        except Exception:
            return []

class LearningLoop:
    """Learn from successful tasks (deterministic)"""

    def __init__(self, knowledge_engine):
        self.knowledge = knowledge_engine
        self.learned_path = knowledge_engine.knowledge_dir / "learned.causal"
        self.learned_triplets = []
        self.pattern_extractor = PatternExtractor()

        # Load existing learned knowledge
        if self.learned_path.exists():
            self.load_learned()

    def load_learned(self):
        """Load learned.causal and inject into knowledge engine"""
        try:
            with open(self.learned_path, 'rb') as f:
                magic = f.read(6)
                if magic != b'CAUSAL':
                    return

                version = int.from_bytes(f.read(2), 'big')
                compressed = f.read()
                data = zlib.decompress(compressed)
                graph = msgpack.unpackb(data, raw=False)

                self.learned_triplets = graph.get('triplets', [])
                print(f"✅ Loaded {len(self.learned_triplets)} learned triplets")

                # CRITICAL: Inject learned triplets into the live knowledge engine
                # Without this, learning is write-only — the engine never sees what it learned
                if self.learned_triplets:
                    self.knowledge.load_transient_triplets(
                        self.learned_triplets, 'learned'
                    )

        except Exception as e:
            print(f"⚠️  Could not load learned.causal: {e}")

    def reload_learned(self):
        """Reload learned.causal from disk and update knowledge engine (removes old duplicates)"""
        try:
            with open(self.learned_path, 'rb') as f:
                magic = f.read(6)
                if magic != b'CAUSAL':
                    return

                version = int.from_bytes(f.read(2), 'big')
                compressed = f.read()
                data = zlib.decompress(compressed)
                graph = msgpack.unpackb(data, raw=False)

                new_triplets = graph.get('triplets', [])
                old_count = len(self.knowledge.all_triplets)

                # Remove old learned triplets from knowledge engine's all_triplets
                self.knowledge.all_triplets = [
                    t for t in self.knowledge.all_triplets
                    if t.get('_source_graph') != 'learned'
                ]
                removed = old_count - len(self.knowledge.all_triplets)

                # Re-inject fresh learned triplets
                if new_triplets:
                    self.knowledge.load_transient_triplets(new_triplets, 'learned')
                    self.knowledge._inference_done = False  # Force re-inference
                    print(f"   [Reload: removed {removed} old, added {len(new_triplets)} fresh → inference recalc]")

        except Exception as e:
            pass  # Silently fail if file doesn't exist yet

    def learn_from_success(self, intent: Dict[str, Any], inference_chain: List[Dict], script: str):
        """
        Extract new knowledge and meta-rules from successful task
        """
        entities = [e['matched'] for e in intent.get('entities', [])]
        mode = intent['mode']
        libraries = self.extract_libraries(script)
        tokens = intent.get('tokens', [])

        # 1. Boost confidence for triplets in the inference chain
        used_passes = set()
        for item in inference_chain:
            triplet = item['triplet']
            self.boost_confidence(triplet)
            if 'source' in triplet:
                used_passes.add(triplet['source'])

        new_triplets = []

        # 2. Library pairing (only for composition tasks with 2+ distinct libraries)
        # Skip noisy meta-triplets like "pass1 effective_for os" — M×N explosion
        # Only learn genuinely useful pairings when multiple distinct libs cooperate
        non_stdlib_libs = [l for l in libraries if l not in (
            'os', 'sys', 're', 'json', 'math', 'time', 'datetime', 'collections',
            'functools', 'itertools', 'pathlib', 'io', 'string', 'textwrap',
        )]
        if len(non_stdlib_libs) >= 2:
            for i in range(len(non_stdlib_libs)):
                for j in range(i + 1, len(non_stdlib_libs)):
                    new_triplets.append({
                        'trigger': non_stdlib_libs[i],
                        'mechanism': 'often_paired_with',
                        'outcome': non_stdlib_libs[j],
                        'confidence': 0.75,
                        'source': 'rule_discovery'
                    })

        # Type 1: Task → Library mapping (Original logic)
        if entities and libraries:
            task_sig = '_'.join(entities[:3])
            lib_combo = '_'.join(sorted(set(libraries)))

            new_triplets.append({
                'trigger': f"{mode}_{task_sig}",
                'mechanism': 'solved_by',
                'outcome': lib_combo,
                'confidence': 0.85,
                'source': 'learning_loop',
                'evidence': f'Success at {self.get_timestamp()}'
            })

        # Pattern Extraction (Original logic)
        idioms = self.pattern_extractor.extract_idioms(script)
        for idiom in idioms:
            for lib in libraries:
                new_triplets.append({
                    'trigger': lib,
                    'mechanism': 'implements_with',
                    'outcome': idiom['type'],
                    'confidence': 0.70,
                    'source': 'pattern_extractor'
                })

        # Add all new triplets
        actually_new = []
        for triplet in new_triplets:
            is_duplicate = any(
                t['trigger'] == triplet['trigger'] and
                t['mechanism'] == triplet['mechanism'] and
                t['outcome'] == triplet['outcome']
                for t in self.learned_triplets
            )

            if not is_duplicate:
                self.learned_triplets.append(triplet)
                actually_new.append(triplet)
                print(f"📚 Genetic Engine: {triplet['trigger']} → {triplet['mechanism']} → {triplet['outcome']}")

        if actually_new:
            self.save_learned()
            # reload_learned() inside save_learned() already re-injects all learned triplets
            # No need to inject again here — that would cause duplicates

    def boost_confidence(self, triplet: Dict[str, Any]):
        """Increase confidence for triplets that lead to success"""
        # Find the triplet in our graphs and boost it
        # Note: Since triplets are immutables in some views, we check source
        current_conf = triplet.get('confidence', 0.5)
        new_conf = min(0.99, current_conf + 0.02)
        triplet['confidence'] = round(new_conf, 3)
        
        # If it's a learned triplet, it will be saved in the next cycle
        # If it's a base triplet, we'd need to re-compile, which we defer for now

    def extract_libraries(self, script: str) -> List[str]:
        """Extract imported libraries from script"""
        import re
        libraries = []
        import_pattern = r'import\s+(\w+)'
        from_pattern = r'from\s+(\w+)'
        libraries.extend(re.findall(import_pattern, script))
        libraries.extend(re.findall(from_pattern, script))
        return list(set(libraries))

    def get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()

    def save_learned(self):
        """Save learned triplets to learned.causal and reload into knowledge engine"""
        try:
            graph = {
                'triplets': self.learned_triplets,
                'metadata': {
                    'version': 1,
                    'source': 'FORGE_learning_loop',
                    'created': self.get_timestamp()
                }
            }
            packed = msgpack.packb(graph, use_bin_type=True)
            compressed = zlib.compress(packed, level=9)
            with open(self.learned_path, 'wb') as f:
                f.write(b'CAUSAL')
                f.write((1).to_bytes(2, 'big'))
                f.write(compressed)
            print(f"💾 Saved {len(self.learned_triplets)} learned triplets")

            # CRITICAL: Reload from disk to update knowledge engine with new triplets
            # This removes duplicates and recalculates inference
            self.reload_learned()

        except Exception as e:
            print(f"❌ Failed to save learned.causal: {e}")
