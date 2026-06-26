"""
Chain Consistency Engine — Validates inference chains for logical coherence

Checks:
1. Contradiction detection: same (trigger, mechanism) → different outcomes
2. Cycle detection: A→B→A chains
3. Confidence floor: chains with dangerously low confidence
4. Redundancy detection: duplicate triplets in a chain
"""
# Dependencies: none
# Depended by: none (leaf module)


from typing import List, Dict, Any, Set, Tuple


class MathematicalEngine:
    """Logic-based validation of inference chains"""

    def __init__(self, knowledge_engine):
        self.ke = knowledge_engine

    def validate_chain(self, chain: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Verify that a triplet chain is logically consistent.

        Checks:
        - No contradictions (same trigger+mechanism → different outcomes)
        - No cycles (A→B→A)
        - No dangerously low confidence chains
        - No duplicate triplets
        """
        results = {
            'is_consistent': True,
            'contradictions': [],
            'cycles': [],
            'warnings': [],
            'chain_confidence': 1.0,
            'triplet_count': 0,
        }

        states = {}  # (trigger, mechanism) → outcome
        edges = set()  # (trigger, outcome) pairs for cycle detection
        seen_triplets = set()  # dedup

        chain_conf = 1.0

        for item in chain:
            triplet = item.get('triplet')
            if not triplet:
                continue

            trigger = triplet.get('trigger', '')
            mechanism = triplet.get('mechanism', '')
            outcome = triplet.get('outcome', '')
            conf = triplet.get('confidence', 0.5)

            if not all([trigger, mechanism, outcome]):
                continue

            results['triplet_count'] += 1

            # Check 1: Contradiction detection
            state_key = (trigger, mechanism)
            if state_key in states:
                if states[state_key] != outcome:
                    results['is_consistent'] = False
                    results['contradictions'].append(
                        f'{trigger} + {mechanism} → {states[state_key]} AND {outcome}'
                    )
            else:
                states[state_key] = outcome

            # Check 2: Cycle detection
            edge = (trigger, outcome)
            reverse = (outcome, trigger)
            if reverse in edges:
                results['cycles'].append(f'{trigger} ↔ {outcome}')
                results['warnings'].append(f'Cycle: {trigger} → {outcome} → {trigger}')
            edges.add(edge)

            # Check 3: Confidence tracking
            chain_conf *= conf

            # Check 4: Duplicate detection
            triplet_key = (trigger, mechanism, outcome)
            if triplet_key in seen_triplets:
                results['warnings'].append(f'Duplicate: {trigger}→{mechanism}→{outcome}')
            seen_triplets.add(triplet_key)

        results['chain_confidence'] = round(chain_conf, 4)

        # Low confidence warning (but not a failure)
        if chain_conf < 0.10 and results['triplet_count'] > 0:
            results['warnings'].append(
                f'Very low chain confidence: {chain_conf:.4f}'
            )

        # Cycles are warnings, not failures (they can still produce valid code)
        # Only contradictions break consistency
        return results
