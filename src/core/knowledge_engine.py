"""
Knowledge Engine — .causal graph query + 3-pass inference

Loads .causal knowledge graphs and performs:
1. Entity lookup
2. Triplet retrieval
3. 3-pass inference:
   - Pass 1: Exact keyword chaining (A→B + B→C = A→C)
   - Pass 2: Semantic direction propagation (positive/negative mechanism chaining)
   - Pass 3: Jaro-Winkler fuzzy entity matching (bridge similar entities)
"""
# Dependencies: none
# Depended by: domain_bootstrapper, project_planner


import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
import msgpack
import zlib
import jellyfish


class KnowledgeEngine:
    """Query .causal knowledge graphs with 3-pass inference"""

    # Mechanism direction classification
    POSITIVE_MECHANISMS = {
        'uses', 'requires', 'reads', 'writes', 'creates', 'generates',
        'returns', 'produces', 'manages', 'provides', 'enables', 'supports',
        'implements', 'handles', 'processes', 'converts', 'parses', 'solves',
        'solved_by', 'implemented_via', 'processed_by', 'type_of', 'is',
        'iterates over', 'traverses', 'lists', 'displays', 'formats',
        'idiom', 'composition', 'pipeline', 'bridge',
    }

    NEGATIVE_MECHANISMS = {
        'caused_by', 'raises', 'throws', 'blocks', 'prevents', 'breaks',
        'conflicts_with', 'deprecates', 'removes', 'deletes',
    }

    # Direction chaining rules
    DIRECTION_CHAINS = {
        ('positive', 'positive'): ('positive', 0.80),
        ('negative', 'negative'): ('positive', 0.75),
        ('positive', 'negative'): ('negative', 0.75),
        ('negative', 'positive'): ('negative', 0.75),
        ('neutral', 'neutral'): ('neutral', 0.70),
    }

    def __init__(self, knowledge_dir: Path):
        self.knowledge_dir = Path(knowledge_dir)
        self.graphs = {}  # Cache loaded graphs
        self.entity_index = {}  # entity → [triplet refs]
        self.trigger_index = {}  # trigger → [triplets]
        self.outcome_index = {}  # outcome → [triplets]
        self.all_triplets = []  # flat list of all triplets
        self.inferred_triplets = []  # results of 3-pass inference
        self._inference_done = False
        self.zero_shot = False  # V7: Disable learning/decay if True

        # Load all .causal files
        self.load_all()

    def load_all(self):
        """Load all .causal files in knowledge directory"""
        if not self.knowledge_dir.exists():
            print(f"Warning: Knowledge directory not found: {self.knowledge_dir}")
            return

        for causal_file in self.knowledge_dir.glob("*.causal"):
            self.load_graph(causal_file)

        # Inject V3 verification bridges
        self.all_triplets.append({
            'trigger': 'scraper',
            'mechanism': 'use',
            'outcome': 'scraper',
            'confidence': 1.0,
            '_source_graph': 'bridge_intents'
        })

        # Fix: supply chain attack should map to dedicated fragment, not macro_document_builder
        self.all_triplets.append({
            'trigger': 'supply chain attack package dependency confusion',
            'mechanism': 'BUILD',
            'outcome': 'supply_chain_dependency_confusion',
            'confidence': 1.0,
            '_source_graph': 'bridge_intents'
        })

        # iOS security fragment bridge triplets
        self.all_triplets.append({
            'trigger': 'app transport security ats configuration analysis',
            'mechanism': 'ANALYZE',
            'outcome': 'ats_configuration_analyzer',
            'confidence': 1.0,
            '_source_graph': 'bridge_intents'
        })
        self.all_triplets.append({
            'trigger': 'mobile provisioning profile entitlements analysis',
            'mechanism': 'ANALYZE',
            'outcome': 'mobile_provisioning_analyzer',
            'confidence': 1.0,
            '_source_graph': 'bridge_intents'
        })
        self.all_triplets.append({
            'trigger': 'jailbreak detection bypass ios security',
            'mechanism': 'ANALYZE',
            'outcome': 'jailbreak_detection_comprehensive',
            'confidence': 1.0,
            '_source_graph': 'bridge_intents'
        })

        # Build indexes after all graphs loaded
        self._build_indexes()

    def load_graph(self, filepath: Path):
        """Load a single .causal file"""
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(6)
                if magic != b'CAUSAL':
                    print(f"Warning: Invalid .causal file: {filepath}")
                    return

                version = int.from_bytes(f.read(2), 'big')
                compressed = f.read()
                data = zlib.decompress(compressed)
                graph = msgpack.unpackb(data, raw=False)

                name = filepath.stem
                self.graphs[name] = graph

                triplets = graph.get('triplets', [])
                for triplet in triplets:
                    triplet['_source_graph'] = name
                self.all_triplets.extend(triplets)

                print(f"Loaded {name}: {len(triplets)} triplets")

        except Exception as e:
            print(f"Failed to load {filepath}: {e}")
    def load_transient_triplets(self, triplets: List[Dict[str, Any]], source_name: str):
        """Add triplets to memory without a .causal file"""
        for triplet in triplets:
            triplet['_source_graph'] = source_name
            self.all_triplets.append(triplet)
        
        # Re-build indexes to include new triplets
        self._build_indexes()
        self._inference_done = False # Re-run inference with new data
        print(f"Index: Injected {len(triplets)} transient triplets from {source_name}")

    def _build_indexes(self):
        """Build fast lookup indexes from all triplets"""
        self.entity_index.clear()
        self.trigger_index.clear()
        self.outcome_index.clear()

        for triplet in self.all_triplets:
            trigger = triplet['trigger']
            outcome = triplet['outcome']

            # Entity index (both trigger and outcome)
            for entity in [trigger, outcome]:
                if entity not in self.entity_index:
                    self.entity_index[entity] = []
                self.entity_index[entity].append(triplet)
                
                # Word-level alias indexing
                # Split by space or underscore
                words = re.split(r'[ _]', entity)
                if len(words) > 1:
                    for word in words:
                        if len(word) > 3:
                            if word not in self.entity_index:
                                self.entity_index[word] = []
                            self.entity_index[word].append(triplet)

            # Trigger index
            if trigger not in self.trigger_index:
                self.trigger_index[trigger] = []
            self.trigger_index[trigger].append(triplet)

            # Outcome index
            if outcome not in self.outcome_index:
                self.outcome_index[outcome] = []
            self.outcome_index[outcome].append(triplet)

    def save_as_causal(self, filename: str):
        """Standardizes .causal as a portable knowledge format. Saves current triplets."""
        filepath = self.knowledge_dir / filename
        data = {
            "version": 1,
            "triplets": [t for t in self.all_triplets if not t.get('is_inferred')]
        }
        packed = msgpack.packb(data, use_bin_type=True)
        compressed = zlib.compress(packed)
        
        with open(filepath, 'wb') as f:
            f.write(b'CAUSAL') # Magic bytes
            f.write((1).to_bytes(2, 'big')) # Version
            f.write(compressed)
            
        print(f"✅ Knowledge persisted to {filepath}")

    def get_all_entities(self) -> List[str]:
        """Return all known entities across all graphs, including word-level aliases"""
        entities = set(self.entity_index.keys())
        # Also include individual words from multi-word entities
        for entity in list(entities):
            if ' ' in entity:
                for word in entity.split():
                    if len(word) > 3: entities.add(word)
        return list(entities)

    def query_entity(self, entity: str) -> List[Dict[str, Any]]:
        """Get all triplets involving an entity"""
        results = []
        for triplet in self.entity_index.get(entity, []):
            results.append({
                'graph': triplet.get('_source_graph', 'unknown'),
                'triplet': triplet
            })
        return results

    def get_triplet(self, trigger: str, outcome: str) -> Optional[Dict[str, Any]]:
        """Find triplet connecting trigger → outcome"""
        for triplet in self.trigger_index.get(trigger, []):
            if triplet['outcome'] == outcome:
                return triplet
        return None

    def reward_triplet(self, trigger: str, outcome: str, boost: float = 0.05):
        """Reward a successful triplet by increasing confidence"""
        if self.zero_shot: return False
        triplet = self.get_triplet(trigger, outcome)
        if triplet:
            triplet['confidence'] = min(0.99, triplet.get('confidence', 0.5) + boost)
            return True
        return False

    def penalize_triplet(self, trigger: str, outcome: str, penalty: float = 0.20):
        """Penalize a failing triplet by decreasing confidence"""
        if self.zero_shot: return False
        triplet = self.get_triplet(trigger, outcome)
        if triplet:
            triplet['confidence'] = max(0.01, triplet.get('confidence', 0.5) - penalty)
            return True
        return False

    def prune_knowledge(self, threshold: float = 0.30):
        """Delete triplets with confidence below threshold (Natural Selection)"""
        initial_count = len(self.all_triplets)
        self.all_triplets = [t for t in self.all_triplets if t.get('confidence', 0.5) >= threshold]
        pruned_count = initial_count - len(self.all_triplets)
        
        if pruned_count > 0:
            self._build_indexes()
            print(f"💀 Natural Selection: Pruned {pruned_count} weak triplets.")
        return pruned_count

    # ========== 3-PASS INFERENCE ENGINE ==========

    def run_inference(self):
        """Run full 3-pass inference and cache results"""
        if self._inference_done:
            return

        self.inferred_triplets = []
        seen = set()  # (trigger, mechanism, outcome) dedup

        # Mark existing triplets
        for t in self.all_triplets:
            seen.add((t['trigger'], t['mechanism'], t['outcome']))

        # Pass 1: Exact keyword chaining
        pass1 = self._pass1_exact_chain(seen)
        self.inferred_triplets.extend(pass1)
        for t in pass1:
            seen.add((t['trigger'], t['mechanism'], t['outcome']))

        # Pass 2: Semantic direction propagation
        pass2 = self._pass2_semantic_direction(seen)
        self.inferred_triplets.extend(pass2)
        for t in pass2:
            seen.add((t['trigger'], t['mechanism'], t['outcome']))

        # Pass 3: Fuzzy entity matching
        pass3 = self._pass3_fuzzy_match(seen)
        self.inferred_triplets.extend(pass3)
        for t in pass3:
            seen.add((t['trigger'], t['mechanism'], t['outcome']))

        # Pass 4: Analogical Reasoning
        pass4 = self._pass4_analogical(seen)
        self.inferred_triplets.extend(pass4)
        for t in pass4:
            seen.add((t['trigger'], t['mechanism'], t['outcome']))

        # Pass 5: Cross-Domain Analogy Discovery
        pass5 = self._pass5_cross_domain(seen)
        self.inferred_triplets.extend(pass5)
        for t in pass5:
            seen.add((t['trigger'], t['mechanism'], t['outcome']))

        # Pass 6: Contextual Cross-Graph Inference
        pass6 = self._pass6_contextual(seen)
        self.inferred_triplets.extend(pass6)
        for t in pass6:
            seen.add((t['trigger'], t['mechanism'], t['outcome']))

        # Pass 7: Creative Recombination
        pass7 = self._pass7_recombination(seen)
        self.inferred_triplets.extend(pass7)

        # Decay unused triplets (confidence decay)
        self._apply_confidence_decay()

        # Index inferred triplets
        for triplet in self.inferred_triplets:
            trigger = triplet['trigger']
            outcome = triplet['outcome']

            for entity in [trigger, outcome]:
                if entity not in self.entity_index:
                    self.entity_index[entity] = []
                self.entity_index[entity].append(triplet)

            if trigger not in self.trigger_index:
                self.trigger_index[trigger] = []
            self.trigger_index[trigger].append(triplet)

        self._inference_done = True

        total = len(self.inferred_triplets)
        explicit = len(self.all_triplets)
        if explicit > 0:
            amp = (total / explicit) * 100
            print(f"Inference: {total} inferred from {explicit} explicit ({amp:.0f}% amplification)")

    def _pass1_exact_chain(self, seen: Set[Tuple]) -> List[Dict]:
        """Pass 1: If A→mech→B and B→mech2→C, infer A→chains_to→C"""
        inferred = []
        max_inferred = 8000

        # For each entity that appears as both outcome and trigger
        bridge_entities = set(self.outcome_index.keys()) & set(self.trigger_index.keys())

        for bridge in bridge_entities:
            incoming = self.outcome_index.get(bridge, [])
            outgoing = self.trigger_index.get(bridge, [])

            for t1 in incoming:
                for t2 in outgoing:
                    # Cycle detection: don't chain A→B→A
                    if t1['trigger'] == t2['outcome']:
                        continue
                    # Don't chain if trigger/outcome overlap with bridge (trivial chains)
                    if t1['trigger'] == bridge or t2['outcome'] == bridge:
                        continue

                    key = (t1['trigger'], 'chains_to', t2['outcome'])
                    if key in seen:
                        continue

                    conf1 = t1.get('confidence', 0.5)
                    conf2 = t2.get('confidence', 0.5)
                    new_conf = conf1 * conf2 * 0.85

                    if new_conf < 0.30:
                        continue

                    inferred.append({
                        'trigger': t1['trigger'],
                        'mechanism': 'chains_to',
                        'outcome': t2['outcome'],
                        'confidence': round(new_conf, 3),
                        'source': 'inference_pass1',
                        'is_inferred': True,
                        '_chain': [
                            f"{t1['trigger']}→{t1['mechanism']}→{bridge}",
                            f"{bridge}→{t2['mechanism']}→{t2['outcome']}",
                        ],
                        '_source_graph': 'inferred',
                    })

                    if len(inferred) >= max_inferred:
                        return inferred

        return inferred

    def _classify_mechanism(self, mechanism: str) -> str:
        """Classify mechanism as positive, negative, or neutral"""
        mech_lower = mechanism.lower()
        for pos in self.POSITIVE_MECHANISMS:
            if pos in mech_lower:
                return 'positive'
        for neg in self.NEGATIVE_MECHANISMS:
            if neg in mech_lower:
                return 'negative'
        return 'neutral'

    def _pass2_semantic_direction(self, seen: Set[Tuple]) -> List[Dict]:
        """Pass 2: Chain mechanism directions (positive+positive=positive, etc.)"""
        inferred = []
        max_inferred = 5000

        bridge_entities = set(self.outcome_index.keys()) & set(self.trigger_index.keys())

        for bridge in bridge_entities:
            incoming = self.outcome_index.get(bridge, [])
            outgoing = self.trigger_index.get(bridge, [])

            for t1 in incoming:
                dir1 = self._classify_mechanism(t1['mechanism'])
                for t2 in outgoing:
                    if t1['trigger'] == t2['outcome']:
                        continue

                    dir2 = self._classify_mechanism(t2['mechanism'])

                    # Look up direction chain rule
                    chain_key = (dir1, dir2)
                    if chain_key not in self.DIRECTION_CHAINS:
                        # Use neutral fallback
                        chain_key = ('neutral', 'neutral')

                    result_dir, gamma = self.DIRECTION_CHAINS[chain_key]

                    # Build inferred mechanism name
                    if result_dir == 'positive':
                        mech = f"indirectly_{t2['mechanism']}"
                    elif result_dir == 'negative':
                        mech = f"inversely_{t2['mechanism']}"
                    else:
                        mech = f"relates_to"

                    key = (t1['trigger'], mech, t2['outcome'])
                    if key in seen:
                        continue

                    conf1 = t1.get('confidence', 0.5)
                    conf2 = t2.get('confidence', 0.5)
                    new_conf = conf1 * conf2 * gamma

                    if new_conf < 0.30:
                        continue

                    inferred.append({
                        'trigger': t1['trigger'],
                        'mechanism': mech,
                        'outcome': t2['outcome'],
                        'confidence': round(new_conf, 3),
                        'source': 'inference_pass2',
                        'is_inferred': True,
                        '_direction': result_dir,
                        '_source_graph': 'inferred',
                    })

                    if len(inferred) >= max_inferred:
                        return inferred

        return inferred

    def _pass3_fuzzy_match(self, seen: Set[Tuple]) -> List[Dict]:
        """Pass 3: Bridge similar entities via prefix-limited Jaro-Winkler"""
        inferred = []
        max_inferred = 2000
        threshold = 0.90 # Higher threshold for speed/precision

        entities = list(self.entity_index.keys())
        
        # Group entities by first 3 letters for faster local search
        buckets = {}
        for e in entities:
            if len(e) < 3: continue
            prefix = e.lower()[:3]
            if prefix not in buckets: buckets[prefix] = []
            buckets[prefix].append(e)

        for prefix, members in buckets.items():
            if len(members) < 2: continue
            # Only compare within the same prefix bucket
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    e1, e2 = members[i], members[j]
                    sim = jellyfish.jaro_winkler_similarity(e1.lower(), e2.lower())
                    if sim >= threshold:
                        # Bridge triplets (e1 as trigger -> e2)
                        for triplet in self.trigger_index.get(e1, []):
                            key = (e2, triplet['mechanism'], triplet['outcome'])
                            if key not in seen:
                                inferred.append({
                                    'trigger': e2,
                                    'mechanism': triplet['mechanism'],
                                    'outcome': triplet['outcome'],
                                    'confidence': round(triplet.get('confidence', 0.5) * sim * 0.75, 3),
                                    'source': 'inference_pass3_optimized',
                                    'is_inferred': True,
                                    '_fuzzy_bridge': f"{e1} ~ {e2}",
                                    '_source_graph': 'inferred'
                                })
                                seen.add(key)
                                if len(inferred) >= max_inferred: return inferred
                        
                        # Bridge triplets (e2 as trigger -> e1)
                        for triplet in self.trigger_index.get(e2, []):
                            key = (e1, triplet['mechanism'], triplet['outcome'])
                            if key not in seen:
                                inferred.append({
                                    'trigger': e1,
                                    'mechanism': triplet['mechanism'],
                                    'outcome': triplet['outcome'],
                                    'confidence': round(triplet.get('confidence', 0.5) * sim * 0.75, 3),
                                    'source': 'inference_pass3_optimized',
                                    'is_inferred': True,
                                    '_fuzzy_bridge': f"{e1} ~ {e2}",
                                    '_source_graph': 'inferred'
                                })
                                seen.add(key)
                                if len(inferred) >= max_inferred: return inferred
        return inferred

    def _pass4_analogical(self, seen: Set[Tuple]) -> List[Dict]:
        """
        Pass 4: Analogical Reasoning
        If A→uses→X and B is similar_to A, and X→provides→Y,
        then B might also benefit from Y.
        """
        inferred = []
        max_inferred = 2000
        
        # We use already matched fuzzy pairs or just similar entities
        entity_patterns = {} # entity -> set of (mechanism, outcome)
        for t in self.all_triplets:
            e = t['trigger']
            if e not in entity_patterns:
                entity_patterns[e] = set()
            entity_patterns[e].add((t['mechanism'], t['outcome']))
            
        entities = list(entity_patterns.keys())
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                e1, e2 = entities[i], entities[j]
                common = entity_patterns[e1] & entity_patterns[e2]
                if len(common) >= 2: # Significant structural similarity
                    # Transfer unique patterns from e1 to e2
                    for mech, outcome in entity_patterns[e1] - common:
                        key = (e2, mech, outcome)
                        if key not in seen:
                            inferred.append({
                                'trigger': e2,
                                'mechanism': mech,
                                'outcome': outcome,
                                'confidence': 0.65,
                                'source': 'inference_pass4_analogy',
                                'is_inferred': True,
                                '_analogy_source': e1,
                                '_source_graph': 'inferred'
                            })
                            seen.add(key)
                            if len(inferred) >= max_inferred: return inferred

                    # Transfer unique patterns from e2 to e1
                    for mech, outcome in entity_patterns[e2] - common:
                        key = (e1, mech, outcome)
                        if key not in seen:
                            inferred.append({
                                'trigger': e1,
                                'mechanism': mech,
                                'outcome': outcome,
                                'confidence': 0.65,
                                'source': 'inference_pass4_analogy',
                                'is_inferred': True,
                                '_analogy_source': e2,
                                '_source_graph': 'inferred'
                            })
                            seen.add(key)
                            if len(inferred) >= max_inferred: return inferred
        return inferred

    def _pass5_cross_domain(self, seen: Set[Tuple]) -> List[Dict]:
        """
        Pass 5: Cross-Domain Analogy Discovery

        THE key differentiator. Finds functional analogies BETWEEN domains
        by ignoring entity names and looking at mechanism-structure patterns.

        Example: (port_scanner, scans, network) ≈ (nmap_automation, scans, network)
        → Transfer knowledge from one to the other.

        Also discovers inverse patterns for offense↔defense knowledge transfer:
        (exploit_X, attacks, target) ↔ (defense_Y, protects, target)
        """
        inferred = []
        max_inferred = 3000

        # Build mechanism-structure signatures per source graph
        # signature = frozenset of (mechanism, outcome_generalized) pairs
        graph_signatures = {}  # graph_name → {entity → set of (mechanism, outcome)}
        graph_entities = {}    # graph_name → set of entities

        for t in self.all_triplets:
            if t.get('is_inferred'):
                continue
            graph = t.get('_source_graph', 'unknown')
            if graph not in graph_signatures:
                graph_signatures[graph] = {}
                graph_entities[graph] = set()

            trigger = t['trigger']
            mech = t['mechanism']
            outcome = t['outcome']

            if trigger not in graph_signatures[graph]:
                graph_signatures[graph][trigger] = set()
            graph_signatures[graph][trigger].add((mech, outcome))
            graph_entities[graph].add(trigger)
            graph_entities[graph].add(outcome)

        # Compare entities ACROSS different graphs
        graph_names = list(graph_signatures.keys())

        for i in range(len(graph_names)):
            for j in range(i + 1, len(graph_names)):
                g1, g2 = graph_names[i], graph_names[j]
                entities1 = graph_signatures.get(g1, {})
                entities2 = graph_signatures.get(g2, {})

                for e1, patterns1 in entities1.items():
                    for e2, patterns2 in entities2.items():
                        if e1 == e2:
                            continue

                        # Compare mechanism signatures (ignore entity names)
                        mechs1 = {m for m, _ in patterns1}
                        mechs2 = {m for m, _ in patterns2}
                        common_mechs = mechs1 & mechs2

                        # Need at least 2 shared mechanisms to establish analogy
                        if len(common_mechs) < 2:
                            continue

                        # Structural similarity score
                        sim = len(common_mechs) / max(len(mechs1 | mechs2), 1)
                        if sim < 0.3:
                            continue

                        # Transfer unique patterns from e1→e2 and e2→e1
                        for mech, outcome in patterns1:
                            if mech not in mechs2:
                                key = (e2, mech, outcome)
                                if key not in seen:
                                    inferred.append({
                                        'trigger': e2,
                                        'mechanism': mech,
                                        'outcome': outcome,
                                        'confidence': round(0.55 * sim, 3),
                                        'source': 'inference_pass5_cross_domain',
                                        'is_inferred': True,
                                        '_analogy': f'{e1}({g1}) ~ {e2}({g2})',
                                        '_source_graph': 'inferred',
                                    })
                                    seen.add(key)
                                    if len(inferred) >= max_inferred:
                                        return inferred

                        for mech, outcome in patterns2:
                            if mech not in mechs1:
                                key = (e1, mech, outcome)
                                if key not in seen:
                                    inferred.append({
                                        'trigger': e1,
                                        'mechanism': mech,
                                        'outcome': outcome,
                                        'confidence': round(0.55 * sim, 3),
                                        'source': 'inference_pass5_cross_domain',
                                        'is_inferred': True,
                                        '_analogy': f'{e2}({g2}) ~ {e1}({g1})',
                                        '_source_graph': 'inferred',
                                    })
                                    seen.add(key)
                                    if len(inferred) >= max_inferred:
                                        return inferred

        return inferred

    def _pass6_contextual(self, seen: Set[Tuple]) -> List[Dict]:
        """
        Pass 6: Contextual Cross-Graph Inference

        When two entities co-occur in user intent, activate the intersection
        of their subgraphs. "Flask + slow" triggers the whole subgraph of
        probable causes: caching, database queries, template rendering, etc.

        This is pre-computed as: if A and B share neighbors, those neighbors
        are contextually relevant to A+B queries.
        """
        inferred = []
        max_inferred = 2000

        # Build neighbor sets: entity → set of connected entities
        neighbors = {}
        for t in self.all_triplets:
            if t.get('is_inferred'):
                continue
            trigger = t['trigger']
            outcome = t['outcome']

            if trigger not in neighbors:
                neighbors[trigger] = set()
            neighbors[trigger].add(outcome)

            if outcome not in neighbors:
                neighbors[outcome] = set()
            neighbors[outcome].add(trigger)

        # For entities that share 2+ neighbors, create contextual links
        entities = list(neighbors.keys())
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                e1, e2 = entities[i], entities[j]
                n1 = neighbors.get(e1, set())
                n2 = neighbors.get(e2, set())
                shared = n1 & n2

                if len(shared) < 2:
                    continue

                # e1 + e2 context → shared neighbors are contextually relevant
                key = (e1, 'contextually_linked_to', e2)
                if key not in seen:
                    inferred.append({
                        'trigger': e1,
                        'mechanism': 'contextually_linked_to',
                        'outcome': e2,
                        'confidence': round(min(0.70, len(shared) * 0.15), 3),
                        'source': 'inference_pass6_contextual',
                        'is_inferred': True,
                        '_shared_context': list(shared)[:5],
                        '_source_graph': 'inferred',
                    })
                    seen.add(key)
                    if len(inferred) >= max_inferred:
                        return inferred

        return inferred

    def _pass7_recombination(self, seen: Set[Tuple]) -> List[Dict]:
        """
        Pass 7: Creative Recombination

        Systematic combinatorics: find entities that appear in different
        subgraphs and create bridge connections. If entity X appears in
        subgraph A (via mechanism M1) and subgraph B (via mechanism M2),
        then the endpoints of A and B might be creatively connected.

        Like genetic crossover: take useful traits from two parents.
        """
        inferred = []
        max_inferred = 1500

        # Group triplets by source graph
        graph_triplets = {}
        for t in self.all_triplets:
            if t.get('is_inferred'):
                continue
            graph = t.get('_source_graph', 'unknown')
            if graph not in graph_triplets:
                graph_triplets[graph] = []
            graph_triplets[graph].append(t)

        # Find entities that appear in multiple graphs (bridge entities)
        entity_graphs = {}  # entity → set of graph names
        for t in self.all_triplets:
            if t.get('is_inferred'):
                continue
            graph = t.get('_source_graph', 'unknown')
            for e in [t['trigger'], t['outcome']]:
                if e not in entity_graphs:
                    entity_graphs[e] = set()
                entity_graphs[e].add(graph)

        bridge_entities = {e for e, gs in entity_graphs.items() if len(gs) >= 2}

        # For each bridge entity, cross-connect endpoints from different graphs
        for bridge in bridge_entities:
            # Get all triplets involving this entity, grouped by graph
            by_graph = {}
            for t in self.entity_index.get(bridge, []):
                if t.get('is_inferred'):
                    continue
                graph = t.get('_source_graph', 'unknown')
                if graph not in by_graph:
                    by_graph[graph] = []
                by_graph[graph].append(t)

            graph_names = list(by_graph.keys())
            if len(graph_names) < 2:
                continue

            # Cross-connect: take trigger from graph A, outcome from graph B
            for gi in range(len(graph_names)):
                for gj in range(gi + 1, len(graph_names)):
                    triplets_a = by_graph[graph_names[gi]]
                    triplets_b = by_graph[graph_names[gj]]

                    for ta in triplets_a[:3]:  # Limit per graph pair
                        for tb in triplets_b[:3]:
                            # Connect ta's trigger to tb's outcome
                            if ta['trigger'] != tb['outcome']:
                                key = (ta['trigger'], 'recombines_with', tb['outcome'])
                                if key not in seen:
                                    conf_a = ta.get('confidence', 0.5)
                                    conf_b = tb.get('confidence', 0.5)
                                    inferred.append({
                                        'trigger': ta['trigger'],
                                        'mechanism': 'recombines_with',
                                        'outcome': tb['outcome'],
                                        'confidence': round(conf_a * conf_b * 0.5, 3),
                                        'source': 'inference_pass7_recombination',
                                        'is_inferred': True,
                                        '_bridge': bridge,
                                        '_graphs': [graph_names[gi], graph_names[gj]],
                                        '_source_graph': 'inferred',
                                    })
                                    seen.add(key)
                                    if len(inferred) >= max_inferred:
                                        return inferred

        return inferred

    def contextual_query(self, entities: List[str]) -> List[Dict]:
        """
        Contextual cross-graph query: given multiple entities,
        find the intersection of their subgraphs.

        "Flask + slow" → returns all triplets that connect Flask and slow
        through shared neighbors.
        """
        self.run_inference()

        if len(entities) < 2:
            return self._get_entity_candidates(entities)

        # Get candidates for each entity
        candidate_sets = []
        for entity in entities:
            entity_triplets = self.entity_index.get(entity, [])
            candidate_sets.append(set(
                (t['trigger'], t['mechanism'], t['outcome'])
                for t in entity_triplets
            ))

        # Find triplets that touch multiple query entities
        all_candidates = []
        for entity in entities:
            for t in self.entity_index.get(entity, []):
                # Score by how many query entities this triplet touches
                touches = sum(
                    1 for e in entities
                    if e in t['trigger'] or e in t['outcome']
                    or e in str(t.get('_shared_context', []))
                )
                if touches >= 1:
                    all_candidates.append({
                        'triplet': t,
                        'score': t.get('confidence', 0.5) + touches * 0.3
                    })

        # Sort by score and deduplicate
        all_candidates.sort(key=lambda x: x['score'], reverse=True)
        seen = set()
        result = []
        for c in all_candidates:
            key = (c['triplet']['trigger'], c['triplet']['outcome'])
            if key not in seen:
                seen.add(key)
                result.append(c)

        return result[:20]

    def _apply_confidence_decay(self):
        """Reduce confidence of triplets over time (simulated via metadata)"""
        from datetime import datetime, timedelta
        now = datetime.now()
        decay_threshold = now - timedelta(days=30)
        
        for triplet in self.all_triplets:
            last_used_str = triplet.get('last_used')
            if last_used_str:
                try:
                    last_used = datetime.fromisoformat(last_used_str)
                    if last_used < decay_threshold:
                        triplet['confidence'] = round(triplet.get('confidence', 0.5) * 0.95, 3)
                except ValueError:
                    pass

    # ========== BRIDGE LOOKUP ==========

    # Stopwords to ignore in bridge word-overlap matching
    BRIDGE_STOPWORDS = {
        'a', 'an', 'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
        'of', 'with', 'by', 'from', 'as', 'is', 'it', 'into', 'that', 'this',
    }

    def _bridge_lookup(self, raw_input: str) -> List[Dict]:
        """Match raw input phrases against bridge and composition triplet triggers.

        Bridge triplets map natural language directly to fragment keys:
        "list files in directory" → uses → os_listdir

        Composition triplets map multi-step tasks to fragment chains:
        "download webpage and extract emails" → composition → requests_get+regex_extract_emails

        This MUST run before entity-based inference, because bridge
        triplets use multi-word phrases that individual token matching misses.
        """
        raw_lower = raw_input.lower().strip()
        # Normalize hyphens, underscores, and extra whitespace for matching
        raw_lower = raw_lower.replace('-', ' ').replace('_', ' ')
        raw_lower = ' '.join(raw_lower.split())
        # Strip /command prefixes
        for prefix in ['/build ', '/make ', '/debug ', '/learn ', '/teach ']:
            if raw_lower.startswith(prefix):
                raw_lower = raw_lower[len(prefix):]

        matches = []
        # Search both bridge_intents AND composition graphs
        bridge_sources = {'bridge_intents', 'composition'}

        for triplet in self.all_triplets:
            if triplet.get('_source_graph') not in bridge_sources:
                continue

            trigger = triplet['trigger'].lower().replace('-', ' ').replace('_', ' ')

            # Composition triplets get a priority boost
            is_composition = triplet.get('mechanism') == 'composition'
            comp_bonus = 0.5 if is_composition else 0.0

            # Exact substring match: bridge trigger contained in user input
            if trigger in raw_lower:
                # Score by trigger length (longer = more specific = better)
                length_bonus = len(trigger) / max(len(raw_lower), 1)
                matches.append({
                    'triplet': triplet,
                    'score': triplet.get('confidence', 0.9) + length_bonus + 1.0 + comp_bonus,
                })
                continue

            # Word overlap: filter stopwords, then count shared content words
            trigger_words = set(trigger.split()) - self.BRIDGE_STOPWORDS
            input_words = set(raw_lower.split()) - self.BRIDGE_STOPWORDS
            if not trigger_words:
                continue
            overlap = trigger_words & input_words
            # Need at least 2 overlapping content words, or all trigger words match
            if len(overlap) >= 2 or (len(trigger_words) <= 3 and overlap == trigger_words):
                overlap_ratio = len(overlap) / len(trigger_words)
                if overlap_ratio >= 0.6:
                    # Auto-generated bridges are less reliable than manual ones
                    auto_penalty = -0.2 if triplet.get('_auto_bridge') else 0.0
                    matches.append({
                        'triplet': triplet,
                        'score': triplet.get('confidence', 0.9) * overlap_ratio + 0.5 + comp_bonus + auto_penalty,
                    })

        # Sort by score (best first), deduplicate by outcome
        matches.sort(key=lambda x: x['score'], reverse=True)
        seen_outcomes = set()
        deduped = []
        for m in matches:
            outcome = m['triplet']['outcome']
            if outcome not in seen_outcomes:
                seen_outcomes.add(outcome)
                deduped.append(m)

        return deduped[:5]

    # ========== QUERY WITH INFERENCE ==========

    def infer(self, intent: Dict[str, Any], top_k: int = 3) -> List[List[Dict[str, Any]]]:
        """
        Run inference and return multiple candidate paths (chains).
        Each path is a List[Dict] (the inference chain).

        Priority order:
        1. Bridge lookup (phrase → fragment key, highest priority)
        2. Entity-based inference (individual token matching)
        """
        self.run_inference()

        raw_input = intent.get('raw', '')

        # === PRIORITY 1: Bridge lookup (phrase matching) ===
        bridge_matches = self._bridge_lookup(raw_input)
        if bridge_matches:
            paths = [bridge_matches]
            # Still try entity-based as fallback path
            entity_path = self._entity_based_chain(intent)
            if entity_path:
                paths.append(entity_path)
            return paths[:top_k]

        # === PRIORITY 2: Entity-based inference ===
        entities = [e['matched'] for e in intent.get('entities', [])]
        if not entities:
            return []

        paths = []
        entity_path = self._entity_based_chain(intent)
        if entity_path:
            paths.append(entity_path)

        # Strategy B: Alternative source path (Diverse)
        if len(paths) < top_k and entity_path:
            all_candidates = self._get_entity_candidates(entities)
            candidates = sorted(all_candidates, key=lambda x: x['score'], reverse=True)
            alt_chain = []
            seen_sources = {t['triplet'].get('_source_graph') for t in entity_path}
            for item in candidates:
                t = item['triplet']
                if t.get('_source_graph') not in seen_sources:
                    alt_chain.append(item)
                    if len(alt_chain) >= 2: break
            if alt_chain: paths.append(alt_chain)

        # Strategy C: Idiom-first path
        if len(paths) < top_k:
            all_candidates = self._get_entity_candidates(entities)
            idiom_chain = [c for c in all_candidates if c['triplet'].get('mechanism') == 'idiom']
            if idiom_chain: paths.append(idiom_chain[:4])

        return paths[:top_k]

    def _get_entity_candidates(self, entities: List[str]) -> List[Dict]:
        """Get all candidate triplets for a set of entities"""
        candidates = []
        for entity in entities:
            for triplet in self.entity_index.get(entity, []):
                candidates.append({'triplet': triplet, 'score': triplet.get('confidence', 0.5)})
        return candidates

    def _entity_based_chain(self, intent: Dict[str, Any]) -> Optional[List[Dict]]:
        """Build best chain from entity-based matching with query-relevance scoring"""
        entities = [e['matched'] for e in intent.get('entities', [])]
        if not entities:
            return None

        all_candidates = self._get_entity_candidates(entities)
        if not all_candidates:
            return None

        # Query-specific re-ranking: boost candidates that overlap with query tokens
        raw_tokens = set(intent.get('tokens', []))
        entity_set = set(e.lower() for e in entities)

        for item in all_candidates:
            t = item['triplet']
            base_score = t.get('confidence', 0.5)

            # Relevance boost: how many query entities does this triplet touch?
            entity_overlap = 0
            for e in entities:
                e_lower = e.lower()
                if e_lower in t['trigger'].lower() or e_lower in t['outcome'].lower():
                    entity_overlap += 1
            relevance = entity_overlap / max(len(entities), 1)

            # Token overlap: check trigger/outcome against raw tokens
            triplet_words = set(t['trigger'].lower().split('_') + t['outcome'].lower().split('_'))
            token_overlap = len(raw_tokens & triplet_words)
            token_score = min(token_overlap * 0.15, 0.5)

            # Bridge triplets get priority (they map directly to fragments)
            bridge_bonus = 0.3 if t.get('_source_graph') == 'bridge_intents' else 0.0

            item['score'] = base_score + relevance * 0.5 + token_score + bridge_bonus

        best_chain = []
        covered = set()
        candidates = sorted(all_candidates, key=lambda x: x['score'], reverse=True)

        for item in candidates:
            t = item['triplet']
            if t['trigger'] in entities or t['outcome'] in entities:
                best_chain.append(item)
                covered.add(t['trigger'])
                covered.add(t['outcome'])
            if len(covered) >= len(entities) and len(best_chain) >= 2:
                break

        return best_chain if best_chain else None

    # ========== TAINT / DATAFLOW QUERIES ==========

    def query_by_flow_type(self, flow_type: str) -> List[Dict[str, Any]]:
        """Get all triplets with a specific flow_type (e.g., 'command_injection')"""
        return [t for t in self.all_triplets if t.get('flow_type') == flow_type]

    def query_by_taint(self, taint: str) -> List[Dict[str, Any]]:
        """Get all triplets with a specific taint level (untrusted/sanitized/semi_trusted)"""
        return [t for t in self.all_triplets if t.get('taint') == taint]

    def get_taint_flows(self, source: str) -> List[Dict[str, Any]]:
        """Get all data-flow paths from a given source entity.
        Returns triplets where source is the trigger and mechanism is flows_through."""
        return [
            t for t in self.all_triplets
            if t['trigger'] == source and t.get('mechanism') == 'flows_through'
        ]

    def get_sanitizers(self, source: str) -> List[Dict[str, Any]]:
        """Get all sanitization triplets for a given source.
        Returns triplets where source is the trigger and mechanism is sanitized_by."""
        return [
            t for t in self.all_triplets
            if t['trigger'] == source and t.get('mechanism') == 'sanitized_by'
        ]

    def get_safe_sinks(self) -> List[Dict[str, Any]]:
        """Get all safe sink triplets (sanitizer → safe destination)."""
        return [
            t for t in self.all_triplets
            if t.get('flow_type') == 'safe_sink'
        ]

    def trace_taint_path(self, source: str, sink: str) -> Dict[str, Any]:
        """Trace whether data can flow from source to sink, and if sanitization exists.
        Returns: {reachable, sanitizable, flows, sanitizers}"""
        flows = [
            t for t in self.all_triplets
            if t['trigger'] == source
            and t.get('mechanism') == 'flows_through'
            and t['outcome'] == sink
        ]
        sanitizers = self.get_sanitizers(source)
        safe_sinks = [
            t for t in self.all_triplets
            if t.get('flow_type') == 'safe_sink' and t['outcome'] == sink
        ]
        return {
            'reachable': len(flows) > 0,
            'flow_type': flows[0].get('flow_type') if flows else None,
            'taint': flows[0].get('taint') if flows else None,
            'sanitizable': len(sanitizers) > 0,
            'sanitizers': [s['outcome'] for s in sanitizers],
            'safe_paths': [s['trigger'] for s in safe_sinks],
            'flows': flows,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Return knowledge base statistics"""
        self.run_inference()
        dataflow_count = sum(1 for t in self.all_triplets if t.get('flow_type'))
        return {
            'graphs_loaded': len(self.graphs),
            'explicit_triplets': len(self.all_triplets),
            'inferred_triplets': len(self.inferred_triplets),
            'total_triplets': len(self.all_triplets) + len(self.inferred_triplets),
            'entities': len(self.entity_index),
            'dataflow_triplets': dataflow_count,
            'amplification_pct': round(
                len(self.inferred_triplets) / max(len(self.all_triplets), 1) * 100, 1
            ),
        }
