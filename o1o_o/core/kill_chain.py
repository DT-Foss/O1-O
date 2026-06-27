"""Kill Chain Graph: MITRE ATT&CK-mapped fragment traversal engine.

Loads the kill chain ontology and builds a traversable graph of
attack stages, techniques, and fragments. Enables automatic
composition of complete kill chains from target descriptions.

Core capability: graph traversal over FORGE's fragment library
to find all valid attack paths from entry to objective.

Part of FORGE Phase H: Sovereign Cyber Intelligence Platform.
"""
# Dependencies: none
# Depended by: chain_composer

import json
import os
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


ONTOLOGY_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'knowledge', 'kill_chain_ontology.json')


class KillChainNode:
    """A node in the kill chain graph (a capability/state)."""

    def __init__(self, name: str, node_type: str = 'capability'):
        self.name = name
        self.node_type = node_type  # capability, stage, technique
        self.edges_out: List['KillChainEdge'] = []
        self.edges_in: List['KillChainEdge'] = []

    def __repr__(self):
        return f"Node({self.name})"


class KillChainEdge:
    """An edge connecting two nodes via a fragment or mechanism."""

    def __init__(self, source: KillChainNode, target: KillChainNode,
                 mechanism: str, fragment: str = '',
                 stage: str = '', technique: str = ''):
        self.source = source
        self.target = target
        self.mechanism = mechanism
        self.fragment = fragment
        self.stage = stage
        self.technique = technique

    def __repr__(self):
        return f"Edge({self.source.name} --[{self.mechanism}]--> {self.target.name})"


class KillChainGraph:
    """Traversable graph of attack capabilities connected by fragments.

    Nodes = capabilities/states (shell_access, credentials, c2_channel, etc.)
    Edges = fragments that transform one capability into another
    """

    def __init__(self, ontology_path: str = ONTOLOGY_PATH):
        self.nodes: Dict[str, KillChainNode] = {}
        self.edges: List[KillChainEdge] = []
        self.ontology: Dict = {}
        self.fragment_index: Dict[str, Dict] = {}  # fragment_name → mapping info
        self.stage_order: Dict[str, int] = {}
        self.technique_index: Dict[str, Dict] = {}

        self._load_ontology(ontology_path)
        self._build_graph()

    def _load_ontology(self, path: str):
        """Load kill chain ontology from JSON."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Kill chain ontology not found: {path}")

        with open(path) as f:
            self.ontology = json.load(f)

        self.stage_order = {
            name: info['order']
            for name, info in self.ontology['stages'].items()
        }
        self.technique_index = self.ontology.get('techniques', {})
        self.fragment_index = self.ontology.get('fragment_mappings', {})

    def _get_node(self, name: str, node_type: str = 'capability') -> KillChainNode:
        """Get or create a node."""
        if name not in self.nodes:
            self.nodes[name] = KillChainNode(name, node_type)
        return self.nodes[name]

    def _build_graph(self):
        """Build the traversable graph from ontology data."""
        # 1. Build edges from fragment mappings (requires → provides)
        for frag_name, info in self.fragment_index.items():
            requires = info.get('requires', [])
            provides = info.get('provides', [])
            stages = info.get('stages', [])
            techniques = info.get('techniques', [])

            stage = stages[0] if stages else ''
            technique = techniques[0] if techniques else ''

            # Each fragment creates edges from its requirements to its outputs
            if not requires:
                # No requirements = entry point
                for output in provides:
                    src = self._get_node('_entry', 'entry')
                    dst = self._get_node(output)
                    edge = KillChainEdge(src, dst, frag_name, frag_name,
                                        stage, technique)
                    src.edges_out.append(edge)
                    dst.edges_in.append(edge)
                    self.edges.append(edge)
            else:
                for req in requires:
                    for output in provides:
                        src = self._get_node(req)
                        dst = self._get_node(output)
                        edge = KillChainEdge(src, dst, frag_name, frag_name,
                                            stage, technique)
                        src.edges_out.append(edge)
                        dst.edges_in.append(edge)
                        self.edges.append(edge)

        # 2. Build edges from chain triplets
        for triplet in self.ontology.get('chain_triplets', []):
            trigger = triplet['trigger']
            mechanism = triplet['mechanism']
            outcome = triplet['outcome']

            src = self._get_node(trigger)
            dst = self._get_node(outcome)

            # Find fragment that implements this mechanism
            frag = self._find_fragment_for_mechanism(
                mechanism, trigger, outcome)

            edge = KillChainEdge(
                src, dst, mechanism, frag or '',
                triplet.get('stage_to', ''),
                '')
            src.edges_out.append(edge)
            dst.edges_in.append(edge)
            self.edges.append(edge)

    def _find_fragment_for_mechanism(self, mechanism: str,
                                     trigger: str, outcome: str) -> Optional[str]:
        """Find the best fragment that implements a mechanism."""
        candidates = []
        for frag_name, info in self.fragment_index.items():
            provides = set(info.get('provides', []))
            requires = set(info.get('requires', []))

            # Fragment provides the outcome
            if outcome in provides:
                # And requires the trigger (or has no requirements)
                if trigger in requires or not requires:
                    candidates.append(frag_name)

        if candidates:
            # Prefer fragments whose name matches the mechanism
            for c in candidates:
                if mechanism in c or c in mechanism:
                    return c
            return candidates[0]

        return None

    def find_paths(self, start: str, goal: str,
                   max_depth: int = 8,
                   max_paths: int = 10) -> List[List[KillChainEdge]]:
        """Find all paths from start capability to goal capability.

        Uses DFS with depth limit to find valid attack chains.

        Args:
            start: Starting capability (e.g., 'target_ip')
            goal: Goal capability (e.g., 'c2_channel')
            max_depth: Maximum chain length
            max_paths: Maximum paths to return

        Returns:
            List of paths, each path is a list of edges
        """
        if start not in self.nodes or goal not in self.nodes:
            return []

        paths = []
        visited = set()

        def dfs(node: KillChainNode, path: List[KillChainEdge], depth: int):
            if len(paths) >= max_paths:
                return
            if depth > max_depth:
                return
            if node.name == goal:
                paths.append(list(path))
                return

            visited.add(node.name)
            for edge in node.edges_out:
                if edge.target.name not in visited:
                    path.append(edge)
                    dfs(edge.target, path, depth + 1)
                    path.pop()
            visited.discard(node.name)

        start_node = self.nodes[start]
        dfs(start_node, [], 0)

        # Sort by path length (shortest first)
        paths.sort(key=len)
        return paths

    def find_kill_chain(self, entry_caps: List[str],
                        objectives: List[str],
                        required_stages: Optional[List[str]] = None,
                        max_depth: int = 10) -> List[Dict]:
        """Find complete kill chains from entry capabilities to objectives.

        Args:
            entry_caps: Starting capabilities (e.g., ['target_ip'])
            objectives: Goal capabilities (e.g., ['c2_channel', 'persistent_access'])
            required_stages: Kill chain stages that must appear (optional)
            max_depth: Maximum chain depth

        Returns:
            List of chain dicts with path, fragments, stages, and score
        """
        chains = []

        for entry in entry_caps:
            for goal in objectives:
                paths = self.find_paths(entry, goal, max_depth=max_depth)
                for path in paths:
                    chain = self._score_chain(path, required_stages)
                    if chain:
                        chains.append(chain)

        # Sort by score (highest first)
        chains.sort(key=lambda c: c['score'], reverse=True)
        return chains[:20]

    def _score_chain(self, path: List[KillChainEdge],
                     required_stages: Optional[List[str]] = None) -> Optional[Dict]:
        """Score a kill chain path."""
        if not path:
            return None

        fragments = []
        stages = set()
        techniques = set()

        for edge in path:
            if edge.fragment:
                fragments.append(edge.fragment)
            if edge.stage:
                stages.add(edge.stage)
            if edge.technique:
                techniques.add(edge.technique)

        # Check required stages
        if required_stages:
            if not all(s in stages for s in required_stages):
                return None

        # Score: prefer chains with more fragments (= more capability),
        # more stages covered, and shorter total length
        fragment_score = len(set(fragments)) * 10
        stage_score = len(stages) * 15
        length_penalty = len(path) * 2
        technique_score = len(techniques) * 5

        score = fragment_score + stage_score + technique_score - length_penalty

        return {
            'path': [(e.source.name, e.mechanism, e.target.name) for e in path],
            'fragments': list(dict.fromkeys(fragments)),  # unique, ordered
            'stages': sorted(stages, key=lambda s: self.stage_order.get(s, 99)),
            'techniques': sorted(techniques),
            'score': max(0, score),
            'length': len(path),
        }

    def get_fragments_for_stage(self, stage: str) -> List[str]:
        """Get all fragments mapped to a kill chain stage."""
        result = []
        for frag_name, info in self.fragment_index.items():
            if stage in info.get('stages', []):
                result.append(frag_name)
        return result

    def get_stage_for_fragment(self, fragment: str) -> List[str]:
        """Get the kill chain stage(s) for a fragment."""
        info = self.fragment_index.get(fragment, {})
        return info.get('stages', [])

    def get_techniques_for_fragment(self, fragment: str) -> List[str]:
        """Get ATT&CK technique IDs for a fragment."""
        info = self.fragment_index.get(fragment, {})
        return info.get('techniques', [])

    def resolve_intent_to_chain(self, intent: str) -> Dict:
        """Parse a natural language intent into kill chain parameters.

        Maps keywords to entry capabilities, objectives, and required stages.

        Args:
            intent: Natural language description (e.g., "remote macos compromise
                    with persistence and credential theft")

        Returns:
            Dict with entry_caps, objectives, required_stages
        """
        intent_lower = intent.lower()

        # Entry capabilities based on access level
        entry_caps = []
        if any(w in intent_lower for w in ['remote', 'external', 'internet', 'network']):
            entry_caps.extend(['target_ip', 'target_domain', 'target_url'])
        if any(w in intent_lower for w in ['local', 'insider', 'physical']):
            entry_caps.extend(['shell_access', 'macos_access'])
        if any(w in intent_lower for w in ['domain', 'active directory', 'ad ']):
            entry_caps.extend(['domain_access'])
        if any(w in intent_lower for w in ['macos', 'mac ', 'apple', 'ios']):
            entry_caps.extend(['macos_access', 'target_binary'])
        if any(w in intent_lower for w in ['web', 'http', 'api']):
            entry_caps.extend(['target_url'])
        if any(w in intent_lower for w in ['wifi', 'wireless']):
            entry_caps.extend(['wifi_interface'])
        if not entry_caps:
            entry_caps = ['target_ip']

        # Objectives based on desired outcome
        objectives = []
        if any(w in intent_lower for w in ['c2', 'command', 'control', 'implant', 'beacon']):
            objectives.append('c2_channel')
            objectives.append('encrypted_c2')
        if any(w in intent_lower for w in ['persist', 'backdoor', 'maintain']):
            objectives.append('persistent_access')
        if any(w in intent_lower for w in ['cred', 'password', 'hash', 'token']):
            objectives.append('credentials')
            objectives.append('ntlm_hashes')
        if any(w in intent_lower for w in ['exfil', 'steal', 'extract']):
            objectives.append('exfil_complete')
            objectives.append('staged_data')
        if any(w in intent_lower for w in ['ransom', 'encrypt', 'destruct', 'wipe']):
            objectives.append('encrypted_files')
            objectives.append('destroyed_data')
        if any(w in intent_lower for w in ['root', 'admin', 'privilege', 'escalat']):
            objectives.append('elevated_access')
            objectives.append('root_access')
        if any(w in intent_lower for w in ['compromise', 'own', 'pwn', 'hack']):
            objectives.extend(['shell_access', 'c2_channel', 'persistent_access'])
        if any(w in intent_lower for w in ['lateral', 'spread', 'pivot']):
            objectives.append('remote_access')
            objectives.append('remote_shell')
        if any(w in intent_lower for w in ['recon', 'scan', 'enum', 'discover']):
            objectives.extend(['open_ports', 'service_info', 'network_map'])
        if any(w in intent_lower for w in ['dos', 'denial', 'crash']):
            objectives.append('dos_attack')
            objectives.append('crash_trigger')
        if any(w in intent_lower for w in ['sandbox', 'escape']):
            objectives.append('sandbox_escape_chain')
        if any(w in intent_lower for w in ['kernel', 'ring0']):
            objectives.append('kernel_chain')
        if not objectives:
            objectives = ['shell_access', 'c2_channel']

        # Required stages
        required_stages = []
        stage_keywords = {
            'reconnaissance': ['recon', 'scan', 'enum'],
            'initial_access': ['initial', 'entry', 'access'],
            'execution': ['exec', 'run', 'shell'],
            'persistence': ['persist', 'backdoor', 'maintain'],
            'privilege_escalation': ['privesc', 'escalat', 'root', 'admin'],
            'defense_evasion': ['evas', 'stealth', 'bypass', 'avoid'],
            'credential_access': ['cred', 'password', 'hash', 'dump'],
            'lateral_movement': ['lateral', 'pivot', 'spread'],
            'exfiltration': ['exfil', 'steal', 'extract'],
            'impact': ['ransom', 'destruct', 'wipe', 'dos'],
        }
        for stage, keywords in stage_keywords.items():
            if any(kw in intent_lower for kw in keywords):
                required_stages.append(stage)

        return {
            'entry_caps': list(dict.fromkeys(entry_caps)),
            'objectives': list(dict.fromkeys(objectives)),
            'required_stages': required_stages,
        }

    def format_chain(self, chain: Dict) -> str:
        """Format a kill chain as readable output."""
        lines = []
        lines.append(f"Kill Chain (score: {chain['score']}, "
                     f"length: {chain['length']})")
        lines.append(f"  Stages: {' → '.join(chain['stages'])}")
        lines.append(f"  Fragments: {', '.join(chain['fragments'])}")

        if chain.get('techniques'):
            tech_names = []
            for tid in chain['techniques'][:5]:
                info = self.technique_index.get(tid, {})
                name = info.get('name', tid)
                tech_names.append(f"{tid} ({name})")
            lines.append(f"  ATT&CK: {', '.join(tech_names)}")

        lines.append(f"  Path:")
        for src, mech, dst in chain['path']:
            lines.append(f"    {src} --[{mech}]--> {dst}")

        return '\n'.join(lines)

    def stats(self) -> Dict:
        """Get graph statistics."""
        stage_frags = defaultdict(int)
        for info in self.fragment_index.values():
            for s in info.get('stages', []):
                stage_frags[s] += 1

        return {
            'nodes': len(self.nodes),
            'edges': len(self.edges),
            'fragments_mapped': len(self.fragment_index),
            'techniques': len(self.technique_index),
            'stages': len(self.stage_order),
            'chain_triplets': len(self.ontology.get('chain_triplets', [])),
            'fragments_per_stage': dict(stage_frags),
        }


if __name__ == '__main__':
    graph = KillChainGraph()
    s = graph.stats()
    print(f"Kill Chain Graph loaded:")
    print(f"  Nodes: {s['nodes']}")
    print(f"  Edges: {s['edges']}")
    print(f"  Fragments mapped: {s['fragments_mapped']}")
    print(f"  ATT&CK techniques: {s['techniques']}")
    print()

    # Test: find chains for "remote compromise with persistence"
    params = graph.resolve_intent_to_chain(
        "remote macos compromise with persistence and credential theft")
    print(f"Intent resolved:")
    print(f"  Entry: {params['entry_caps']}")
    print(f"  Objectives: {params['objectives']}")
    print(f"  Required stages: {params['required_stages']}")
    print()

    chains = graph.find_kill_chain(
        params['entry_caps'],
        params['objectives'],
        params.get('required_stages'))

    print(f"Found {len(chains)} kill chains:")
    for i, chain in enumerate(chains[:5]):
        print()
        print(f"--- Chain {i+1} ---")
        print(graph.format_chain(chain))
