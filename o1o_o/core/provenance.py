"""
Provenance — Explanation chains for every decision

Tracks WHY every decision was made:
- Which triplets were used
- What their confidence was
- What alternatives existed
- Why one was chosen over another
"""
# Dependencies: none
# Depended by: none (leaf module)


from typing import Dict, Any, List


class ProvenanceTracker:
    """Track decision provenance"""

    def __init__(self):
        self.chains = []

    def record_decision(self, decision_type: str, chosen: Any,
                       alternatives: List[Any], reason: str):
        """
        Record a decision with full context

        Args:
            decision_type: Type of decision (library_selection, pattern_choice, etc.)
            chosen: What was chosen
            alternatives: What else was available
            reason: Why this was chosen
        """
        self.chains.append({
            'type': decision_type,
            'chosen': chosen,
            'alternatives': alternatives,
            'reason': reason
        })

    def explain(self) -> str:
        """
        Generate human-readable explanation

        Returns:
            Full explanation of all decisions
        """
        if not self.chains:
            return "No decisions recorded."

        lines = ["Decision chain:"]

        for i, decision in enumerate(self.chains, 1):
            lines.append(f"\n{i}. {decision['type']}:")
            lines.append(f"   Chose: {decision['chosen']}")
            if decision['alternatives']:
                lines.append(f"   Alternatives: {', '.join(str(a) for a in decision['alternatives'])}")
            lines.append(f"   Reason: {decision['reason']}")

        return '\n'.join(lines)

    def get_confidence_chain(self) -> List[float]:
        """Return confidence scores of all decisions"""
        confidences = []
        for decision in self.chains:
            if isinstance(decision['chosen'], dict) and 'confidence' in decision['chosen']:
                confidences.append(decision['chosen']['confidence'])
        return confidences

    def overall_confidence(self) -> float:
        """Calculate overall confidence (product of all confidences)"""
        confidences = self.get_confidence_chain()
        if not confidences:
            return 0.0

        result = 1.0
        for c in confidences:
            result *= c

        return result
