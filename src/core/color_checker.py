"""Color Type Constraint Checker: Validate assembly chains pre-execution.

Ensures fragment pipelines have valid color type transitions BEFORE code is
generated. Catches impossible chains early, reports type mismatches, and
suggests converter fragments.

Part of FORGE Phase 3: Cross-Fragment Generalization.
"""
# Dependencies: color_types
# Depended by: color_assembler

import re
from typing import Dict, List, Optional, Set, Tuple

from core.color_types import (
    ALL_COLORS, COLOR_REGISTRY, COLOR_CONVERTERS, INTENT_COLOR_CHAINS,
    TEXT, STRUCT, TABULAR, BYTES, SERIAL, PATH, RESPONSE, VOID
)


class ColorViolation:
    """A color type constraint violation."""

    def __init__(self, kind: str, message: str,
                 fragment_key: str = '', position: int = -1,
                 expected_color: str = '', actual_color: str = '',
                 severity: str = 'error'):
        self.kind = kind  # mismatch, missing_converter, orphan, unknown_fragment
        self.message = message
        self.fragment_key = fragment_key
        self.position = position
        self.expected_color = expected_color
        self.actual_color = actual_color
        self.severity = severity  # error, warning, info

    def __repr__(self):
        return f"[{self.severity}] {self.kind}: {self.message}"


class ColorChecker:
    """Validates color type constraints on fragment assembly pipelines."""

    # Colors that are identity-convertible (no actual conversion needed)
    IDENTITY_PAIRS = {
        (TEXT, SERIAL), (SERIAL, TEXT),  # text IS serial
    }

    # Colors that can be implicitly converted via accessor
    IMPLICIT_PAIRS = {
        (RESPONSE, TEXT): '.text',
        (RESPONSE, STRUCT): '.json()',
        (BYTES, TEXT): '.decode()',
        (TEXT, BYTES): '.encode()',
    }

    def validate_chain(self, fragment_keys: List[str],
                       expected_chain: Optional[List[str]] = None
                       ) -> List[ColorViolation]:
        """Validate a sequence of fragments forms a valid color chain.

        Args:
            fragment_keys: Ordered list of fragment keys in the pipeline
            expected_chain: Optional expected color sequence

        Returns:
            List of violations (empty = valid chain)
        """
        violations = []

        if not fragment_keys:
            return violations

        # Check all fragments exist in registry
        fragment_colors = []
        for i, key in enumerate(fragment_keys):
            colors = COLOR_REGISTRY.get(key)
            if colors is None:
                violations.append(ColorViolation(
                    'unknown_fragment',
                    f"Fragment '{key}' not in COLOR_REGISTRY — cannot type-check",
                    fragment_key=key, position=i, severity='warning'
                ))
                fragment_colors.append(None)
            else:
                fragment_colors.append(colors)

        # Check transitions between consecutive fragments
        for i in range(len(fragment_colors) - 1):
            curr = fragment_colors[i]
            next_frag = fragment_colors[i + 1]

            if curr is None or next_frag is None:
                continue  # can't check if unknown

            output_color = curr[1]
            input_color = next_frag[0]

            if output_color == input_color:
                continue  # exact match

            if (output_color, input_color) in self.IDENTITY_PAIRS:
                continue  # identity conversion

            if (output_color, input_color) in self.IMPLICIT_PAIRS:
                continue  # implicit conversion available

            # Check if there's a converter
            converter = COLOR_CONVERTERS.get((output_color, input_color))
            if converter is not None:
                violations.append(ColorViolation(
                    'needs_converter',
                    f"Color mismatch {output_color}→{input_color} between "
                    f"'{fragment_keys[i]}' and '{fragment_keys[i+1]}' "
                    f"— converter '{converter}' available",
                    fragment_key=fragment_keys[i], position=i,
                    expected_color=input_color, actual_color=output_color,
                    severity='warning'
                ))
            else:
                violations.append(ColorViolation(
                    'mismatch',
                    f"Incompatible colors: '{fragment_keys[i]}' outputs {output_color} "
                    f"but '{fragment_keys[i+1]}' expects {input_color} — no converter exists",
                    fragment_key=fragment_keys[i], position=i,
                    expected_color=input_color, actual_color=output_color,
                    severity='error'
                ))

        # Validate against expected chain if provided
        if expected_chain and len(expected_chain) == len(fragment_keys) + 1:
            for i, key in enumerate(fragment_keys):
                colors = fragment_colors[i]
                if colors is None:
                    continue
                if colors[0] != expected_chain[i]:
                    violations.append(ColorViolation(
                        'chain_mismatch',
                        f"Fragment '{key}' input is {colors[0]} but chain expects {expected_chain[i]}",
                        fragment_key=key, position=i,
                        expected_color=expected_chain[i], actual_color=colors[0],
                        severity='error'
                    ))
                if colors[1] != expected_chain[i + 1]:
                    violations.append(ColorViolation(
                        'chain_mismatch',
                        f"Fragment '{key}' output is {colors[1]} but chain expects {expected_chain[i+1]}",
                        fragment_key=key, position=i,
                        expected_color=expected_chain[i + 1], actual_color=colors[1],
                        severity='error'
                    ))

        return violations

    def validate_intent(self, intent: str) -> List[ColorViolation]:
        """Validate that an intent maps to a valid color chain."""
        violations = []

        # Find matching chain
        matched_chain = None
        for pattern, chain in INTENT_COLOR_CHAINS:
            if re.search(pattern, intent, re.IGNORECASE):
                matched_chain = chain
                break

        if matched_chain is None:
            violations.append(ColorViolation(
                'no_chain',
                f"No color chain matches intent: '{intent[:80]}'",
                severity='info'
            ))
            return violations

        # Verify each transition in the chain has available fragments
        for i in range(len(matched_chain) - 1):
            from_color = matched_chain[i]
            to_color = matched_chain[i + 1]

            if from_color == to_color:
                continue  # identity

            if (from_color, to_color) in self.IDENTITY_PAIRS:
                continue

            # Find fragments that can make this transition
            available = [
                key for key, (inp, out) in COLOR_REGISTRY.items()
                if inp == from_color and out == to_color
            ]

            if not available:
                # Check converters
                converter = COLOR_CONVERTERS.get((from_color, to_color))
                if converter:
                    available = [converter]
                elif (from_color, to_color) in self.IMPLICIT_PAIRS:
                    continue  # implicit conversion

            if not available:
                violations.append(ColorViolation(
                    'impossible_transition',
                    f"No fragment can perform {from_color}→{to_color} "
                    f"(step {i+1} of chain)",
                    severity='error'
                ))

        return violations

    def suggest_converters(self, from_color: str, to_color: str) -> List[str]:
        """Suggest fragments that can convert between two colors."""
        if from_color == to_color:
            return []

        suggestions = []

        # Direct converter
        converter = COLOR_CONVERTERS.get((from_color, to_color))
        if converter:
            suggestions.append(converter)

        # Any fragment with matching colors
        for key, (inp, out) in COLOR_REGISTRY.items():
            if inp == from_color and out == to_color and key not in suggestions:
                suggestions.append(key)

        # Two-hop: from→mid→to
        if not suggestions:
            for mid_color in ALL_COLORS:
                if mid_color in (from_color, to_color):
                    continue
                hop1 = COLOR_CONVERTERS.get((from_color, mid_color))
                hop2 = COLOR_CONVERTERS.get((mid_color, to_color))
                if hop1 and hop2:
                    suggestions.append(f"{hop1} → {hop2}")

        return suggestions

    def audit_registry(self) -> Dict[str, List[str]]:
        """Audit the COLOR_REGISTRY for completeness and issues."""
        issues = {
            'orphan_fragments': [],
            'missing_converters': [],
            'dead_transitions': [],
        }

        # Check all registered colors are valid
        for key, (inp, out) in COLOR_REGISTRY.items():
            if inp not in ALL_COLORS:
                issues['orphan_fragments'].append(
                    f"{key}: invalid input color '{inp}'"
                )
            if out not in ALL_COLORS:
                issues['orphan_fragments'].append(
                    f"{key}: invalid output color '{out}'"
                )

        # Find color transitions with no available fragment
        for from_c in ALL_COLORS:
            for to_c in ALL_COLORS:
                if from_c == to_c:
                    continue
                if (from_c, to_c) in self.IDENTITY_PAIRS:
                    continue
                if (from_c, to_c) in self.IMPLICIT_PAIRS:
                    continue

                has_fragment = any(
                    inp == from_c and out == to_c
                    for inp, out in COLOR_REGISTRY.values()
                )
                has_converter = (from_c, to_c) in COLOR_CONVERTERS

                if not has_fragment and not has_converter:
                    issues['missing_converters'].append(
                        f"{from_c}→{to_c}: no fragment or converter"
                    )

        return issues

    def format_report(self) -> str:
        """Generate a full audit report."""
        issues = self.audit_registry()

        lines = []
        lines.append("Color Type System Audit")
        lines.append("=" * 50)
        lines.append(f"Registered fragments: {len(COLOR_REGISTRY)}")
        lines.append(f"Color converters: {len(COLOR_CONVERTERS)}")
        lines.append(f"Intent chains: {len(INTENT_COLOR_CHAINS)}")
        lines.append(f"Colors: {len(ALL_COLORS)}")
        lines.append("")

        # Color distribution
        input_dist = {}
        output_dist = {}
        for _, (inp, out) in COLOR_REGISTRY.items():
            input_dist[inp] = input_dist.get(inp, 0) + 1
            output_dist[out] = output_dist.get(out, 0) + 1

        lines.append("Color distribution (input → output):")
        for color in sorted(ALL_COLORS):
            i = input_dist.get(color, 0)
            o = output_dist.get(color, 0)
            lines.append(f"  {color:10s}  in={i:3d}  out={o:3d}")
        lines.append("")

        # Issues
        for category, items in issues.items():
            if items:
                lines.append(f"{category}: {len(items)}")
                for item in items[:10]:
                    lines.append(f"  {item}")
                if len(items) > 10:
                    lines.append(f"  ... +{len(items)-10} more")
                lines.append("")

        return '\n'.join(lines)


def run_audit() -> ColorChecker:
    """Run color type audit and print report."""
    checker = ColorChecker()
    print(checker.format_report())
    return checker


if __name__ == '__main__':
    run_audit()
