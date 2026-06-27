"""Cross-Operation Intelligence: Pattern detection across multiple operations.

Aggregates findings into strategic intelligence: identifies vulnerability
classes, systemic patterns, and target-family correlations.

Example insight: '3/5 root daemons had XPC type confusion — systemic Apple
problem' or 'all gRPC services vulnerable to deserialization'.

Part of FORGE Phase Q: Intelligence & Memory.
"""
# Dependencies: none
# Depended by: none (leaf module)

import json
import os
import time
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ─── Intelligence Data Models ──────────────────────────────────────

@dataclass
class VulnPattern:
    """A recurring vulnerability pattern across targets."""
    pattern_id: str = ''
    name: str = ''
    description: str = ''
    vuln_class: str = ''           # buffer_overflow, type_confusion, deserialization
    cwe_id: str = ''
    affected_targets: List[str] = field(default_factory=list)
    affected_count: int = 0
    total_targets_tested: int = 0
    prevalence: float = 0.0        # affected / total tested
    avg_severity: str = 'medium'
    avg_confidence: float = 0.0
    common_functions: List[str] = field(default_factory=list)
    common_techniques: List[str] = field(default_factory=list)
    is_systemic: bool = False      # True if prevalence > 50%
    tags: List[str] = field(default_factory=list)


@dataclass
class TargetFamilyProfile:
    """Intelligence profile for a class of targets (e.g., 'macOS daemons')."""
    family: str = ''               # daemon, xpc_service, library, web_service
    platform: str = ''
    targets_analyzed: int = 0
    total_findings: int = 0
    vuln_patterns: List[str] = field(default_factory=list)  # pattern IDs
    most_effective_strategy: str = ''
    avg_findings_per_target: float = 0.0
    common_weaknesses: List[str] = field(default_factory=list)
    common_mitigations: List[str] = field(default_factory=list)
    risk_level: str = 'medium'     # low, medium, high, critical


@dataclass
class StrategicInsight:
    """A strategic-level intelligence finding."""
    insight_id: str = ''
    title: str = ''
    description: str = ''
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0
    impact: str = 'medium'         # low, medium, high, critical
    recommendation: str = ''
    created_at: float = 0.0
    tags: List[str] = field(default_factory=list)


# ─── Vulnerability Class Taxonomy ──────────────────────────────────

VULN_CLASS_MAPPING = {
    # Primitive types → vulnerability classes
    'buffer_overflow': {'class': 'memory_corruption', 'cwe': 'CWE-120'},
    'heap_overflow': {'class': 'memory_corruption', 'cwe': 'CWE-122'},
    'stack_overflow': {'class': 'memory_corruption', 'cwe': 'CWE-121'},
    'use_after_free': {'class': 'memory_corruption', 'cwe': 'CWE-416'},
    'double_free': {'class': 'memory_corruption', 'cwe': 'CWE-415'},
    'null_deref': {'class': 'null_safety', 'cwe': 'CWE-476'},
    'integer_overflow': {'class': 'numeric_error', 'cwe': 'CWE-190'},
    'format_string': {'class': 'injection', 'cwe': 'CWE-134'},
    'command_injection': {'class': 'injection', 'cwe': 'CWE-78'},
    'sql_injection': {'class': 'injection', 'cwe': 'CWE-89'},
    'deserialization': {'class': 'deserialization', 'cwe': 'CWE-502'},
    'type_confusion': {'class': 'type_safety', 'cwe': 'CWE-843'},
    'race_condition': {'class': 'concurrency', 'cwe': 'CWE-362'},
    'path_traversal': {'class': 'access_control', 'cwe': 'CWE-22'},
    'info_leak': {'class': 'information_disclosure', 'cwe': 'CWE-200'},
    'write': {'class': 'memory_corruption', 'cwe': 'CWE-787'},
    'execute': {'class': 'code_execution', 'cwe': 'CWE-94'},
    'dos': {'class': 'availability', 'cwe': 'CWE-400'},
}

SEVERITY_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}


# ─── Cross-Operation Intelligence Engine ───────────────────────────

class CrossIntelEngine:
    """Analyze patterns and generate strategic intelligence across operations.

    Features:
    - Detect recurring vulnerability patterns across targets
    - Build target family profiles (which target types are most vulnerable)
    - Generate strategic insights from aggregate data
    - Track systemic weaknesses (>50% prevalence in a target class)
    - Correlation analysis: which techniques find which vuln classes
    """

    def __init__(self, ops_db: str = 'knowledge/operations.db',
                 findings_db: str = 'knowledge/findings.db'):
        self.ops_db = ops_db
        self.findings_db = findings_db

    # ─── Pattern Detection ────────────────────────────────────────

    def detect_patterns(self, min_occurrences: int = 2) -> List[VulnPattern]:
        """Detect recurring vulnerability patterns across all findings."""
        findings = self._load_all_findings()
        if not findings:
            return []

        # Group findings by vulnerability class
        class_groups = defaultdict(list)
        for f in findings:
            prim = f.get('primitive_type', 'unknown')
            cls_info = VULN_CLASS_MAPPING.get(prim, {'class': prim, 'cwe': ''})
            vuln_class = cls_info['class']
            class_groups[vuln_class].append(f)

        # Build patterns for classes with sufficient occurrences
        all_targets = set(f.get('target_name', '') for f in findings if f.get('target_name'))
        patterns = []

        for vuln_class, class_findings in class_groups.items():
            affected = set(f.get('target_name', '') for f in class_findings if f.get('target_name'))

            if len(affected) < min_occurrences:
                continue

            # Compute statistics
            severities = [f.get('severity', 'medium') for f in class_findings]
            avg_sev_rank = sum(SEVERITY_RANK.get(s, 0) for s in severities) / len(severities)
            avg_severity = 'critical' if avg_sev_rank >= 3.5 else \
                           'high' if avg_sev_rank >= 2.5 else \
                           'medium' if avg_sev_rank >= 1.5 else 'low'

            avg_conf = sum(f.get('confidence', 0) for f in class_findings) / len(class_findings)

            # Common functions
            functions = [f.get('faulting_function', '') for f in class_findings
                        if f.get('faulting_function')]
            func_counts = Counter(functions)
            common_funcs = [f for f, _ in func_counts.most_common(5)]

            # CWE
            cwes = set()
            for f in class_findings:
                prim = f.get('primitive_type', '')
                cls_info = VULN_CLASS_MAPPING.get(prim, {})
                if cls_info.get('cwe'):
                    cwes.add(cls_info['cwe'])
                if f.get('cwe_id'):
                    cwes.add(f['cwe_id'])

            prevalence = len(affected) / max(len(all_targets), 1)

            pattern = VulnPattern(
                pattern_id=f"PAT-{vuln_class[:8].upper()}-{len(affected)}",
                name=f"{vuln_class.replace('_', ' ').title()} Pattern",
                description=f"{len(affected)} of {len(all_targets)} analyzed targets "
                            f"affected by {vuln_class}",
                vuln_class=vuln_class,
                cwe_id=', '.join(sorted(cwes)) if cwes else '',
                affected_targets=sorted(affected),
                affected_count=len(affected),
                total_targets_tested=len(all_targets),
                prevalence=round(prevalence, 3),
                avg_severity=avg_severity,
                avg_confidence=round(avg_conf, 3),
                common_functions=common_funcs,
                is_systemic=prevalence > 0.5,
            )
            patterns.append(pattern)

        return sorted(patterns, key=lambda p: (-p.affected_count, -p.prevalence))

    # ─── Target Family Profiles ───────────────────────────────────

    def build_family_profiles(self) -> List[TargetFamilyProfile]:
        """Build intelligence profiles per target family."""
        operations = self._load_all_operations()
        if not operations:
            return []

        # Group by target_type + platform
        families = defaultdict(list)
        for op in operations:
            key = (op.get('target_type', 'unknown'), op.get('target_platform', 'unknown'))
            families[key].append(op)

        profiles = []
        for (target_type, platform), ops in families.items():
            total_findings = sum(op.get('total_findings', 0) for op in ops)
            targets = len(ops)

            # Best strategy
            strategy_counts = Counter(op.get('strategy', '') for op in ops if op.get('strategy'))
            strategy_findings = defaultdict(int)
            for op in ops:
                if op.get('strategy'):
                    strategy_findings[op['strategy']] += op.get('total_findings', 0)
            best_strategy = max(strategy_findings, key=strategy_findings.get) \
                if strategy_findings else ''

            # Common weaknesses from findings
            weaknesses = []
            for op in ops:
                ft = op.get('finding_types', {})
                if isinstance(ft, str):
                    ft = json.loads(ft) if ft else {}
                for prim_type in ft:
                    weaknesses.append(prim_type)
            weakness_counts = Counter(weaknesses)
            common_weaknesses = [w for w, _ in weakness_counts.most_common(5)]

            # Risk level
            avg_findings = total_findings / max(targets, 1)
            risk = 'critical' if avg_findings > 5 else \
                   'high' if avg_findings > 2 else \
                   'medium' if avg_findings > 0.5 else 'low'

            profile = TargetFamilyProfile(
                family=target_type,
                platform=platform,
                targets_analyzed=targets,
                total_findings=total_findings,
                most_effective_strategy=best_strategy,
                avg_findings_per_target=round(avg_findings, 2),
                common_weaknesses=common_weaknesses,
                risk_level=risk,
            )
            profiles.append(profile)

        return sorted(profiles, key=lambda p: -p.avg_findings_per_target)

    # ─── Strategic Insights ───────────────────────────────────────

    def generate_insights(self) -> List[StrategicInsight]:
        """Generate strategic insights from cross-operation analysis."""
        insights = []
        patterns = self.detect_patterns()
        profiles = self.build_family_profiles()

        # Insight 1: Systemic patterns
        systemic = [p for p in patterns if p.is_systemic]
        for pat in systemic:
            targets_str = ', '.join(pat.affected_targets[:5])
            if len(pat.affected_targets) > 5:
                targets_str += f" (+{len(pat.affected_targets) - 5} more)"

            insights.append(StrategicInsight(
                insight_id=f"INS-SYS-{pat.vuln_class[:6].upper()}",
                title=f"Systemic {pat.vuln_class.replace('_', ' ')} "
                      f"across {pat.affected_count}/{pat.total_targets_tested} targets",
                description=f"{pat.prevalence:.0%} of analyzed targets are affected by "
                            f"{pat.vuln_class}. This suggests a systemic issue "
                            f"in the target platform or framework.",
                evidence=[
                    f"Affected: {targets_str}",
                    f"CWE: {pat.cwe_id}" if pat.cwe_id else "",
                    f"Avg severity: {pat.avg_severity}",
                ],
                confidence=min(pat.avg_confidence + 0.1, 1.0),
                impact='critical' if pat.avg_severity == 'critical' else 'high',
                recommendation=f"Prioritize {pat.vuln_class} testing across all "
                              f"similar targets. Consider architectural review.",
                created_at=time.time(),
                tags=['systemic', pat.vuln_class],
            ))

        # Insight 2: High-risk target families
        for prof in profiles:
            if prof.risk_level in ('critical', 'high') and prof.targets_analyzed >= 2:
                insights.append(StrategicInsight(
                    insight_id=f"INS-FAM-{prof.family[:6].upper()}",
                    title=f"{prof.family} targets on {prof.platform} are {prof.risk_level}-risk "
                          f"({prof.avg_findings_per_target:.1f} findings/target)",
                    description=f"Across {prof.targets_analyzed} analyzed {prof.family} targets, "
                                f"average of {prof.avg_findings_per_target:.1f} findings per target. "
                                f"Common weaknesses: {', '.join(prof.common_weaknesses[:3])}.",
                    evidence=[
                        f"Best strategy: {prof.most_effective_strategy}",
                        f"Total findings: {prof.total_findings}",
                    ],
                    confidence=min(0.5 + (prof.targets_analyzed * 0.1), 0.95),
                    impact=prof.risk_level,
                    recommendation=f"Use '{prof.most_effective_strategy}' strategy for "
                                  f"new {prof.family} targets on {prof.platform}.",
                    created_at=time.time(),
                    tags=['family_risk', prof.family, prof.platform],
                ))

        # Insight 3: Technique correlation
        technique_vuln_map = self._technique_vuln_correlation()
        for technique, vulns in technique_vuln_map.items():
            if len(vulns) >= 2:
                top_vulns = sorted(vulns.items(), key=lambda x: -x[1])[:3]
                vuln_str = ', '.join(f"{v} ({c})" for v, c in top_vulns)
                insights.append(StrategicInsight(
                    insight_id=f"INS-TECH-{technique[:6].upper()}",
                    title=f"'{technique}' technique most effective for "
                          f"{top_vulns[0][0] if top_vulns else 'unknown'}",
                    description=f"The '{technique}' analysis technique has found: {vuln_str}.",
                    evidence=[f"{v}: {c} findings" for v, c in top_vulns],
                    confidence=0.7,
                    impact='medium',
                    recommendation=f"Include '{technique}' in strategies targeting "
                                  f"{top_vulns[0][0] if top_vulns else 'unknown'} vulnerabilities.",
                    created_at=time.time(),
                    tags=['technique_correlation', technique],
                ))

        return sorted(insights, key=lambda i: -SEVERITY_RANK.get(i.impact, 0))

    # ─── Correlation Analysis ─────────────────────────────────────

    def _technique_vuln_correlation(self) -> Dict[str, Dict[str, int]]:
        """Map which techniques find which vulnerability classes."""
        operations = self._load_all_operations()
        correlation = defaultdict(lambda: defaultdict(int))

        for op in operations:
            steps = op.get('steps', [])
            if isinstance(steps, str):
                steps = json.loads(steps) if steps else []

            finding_types = op.get('finding_types', {})
            if isinstance(finding_types, str):
                finding_types = json.loads(finding_types) if finding_types else {}

            techniques = set()
            for step in steps:
                if isinstance(step, dict) and step.get('success'):
                    techniques.add(step.get('action', ''))

            for prim_type, count in finding_types.items():
                vuln_class = VULN_CLASS_MAPPING.get(prim_type, {}).get('class', prim_type)
                for tech in techniques:
                    if tech:
                        correlation[tech][vuln_class] += count

        return dict(correlation)

    def correlation_matrix(self) -> dict:
        """Build a technique × vulnerability class correlation matrix."""
        corr = self._technique_vuln_correlation()
        techniques = sorted(corr.keys())
        vuln_classes = sorted(set(v for vals in corr.values() for v in vals))

        matrix = {}
        for tech in techniques:
            matrix[tech] = {}
            for vc in vuln_classes:
                matrix[tech][vc] = corr.get(tech, {}).get(vc, 0)

        return {
            'techniques': techniques,
            'vuln_classes': vuln_classes,
            'matrix': matrix,
        }

    # ─── Data Loading ─────────────────────────────────────────────

    def _load_all_findings(self) -> List[dict]:
        """Load all findings from the findings database."""
        if not os.path.isfile(self.findings_db):
            return []

        with sqlite3.connect(self.findings_db) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM findings ORDER BY priority DESC").fetchall()
            return [dict(r) for r in rows]

    def _load_all_operations(self) -> List[dict]:
        """Load all completed operations."""
        if not os.path.isfile(self.ops_db):
            return []

        with sqlite3.connect(self.ops_db) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM operations WHERE status = 'completed' ORDER BY started_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    # ─── Display ──────────────────────────────────────────────────

    def format_patterns(self, patterns: List[VulnPattern]) -> str:
        if not patterns:
            return "  No vulnerability patterns detected (need more findings)"

        lines = [
            f"VULNERABILITY PATTERNS — {len(patterns)} detected",
            f"{'=' * 65}",
        ]

        for p in patterns:
            systemic_tag = " [SYSTEMIC]" if p.is_systemic else ""
            lines.append(f"")
            lines.append(
                f"  {p.pattern_id}: {p.name}{systemic_tag}"
            )
            lines.append(
                f"    Affected: {p.affected_count}/{p.total_targets_tested} "
                f"({p.prevalence:.0%}) — Severity: {p.avg_severity} — "
                f"Confidence: {p.avg_confidence:.0%}"
            )
            if p.cwe_id:
                lines.append(f"    CWE: {p.cwe_id}")
            targets = ', '.join(p.affected_targets[:5])
            if len(p.affected_targets) > 5:
                targets += f" (+{len(p.affected_targets) - 5})"
            lines.append(f"    Targets: {targets}")
            if p.common_functions:
                lines.append(f"    Functions: {', '.join(p.common_functions[:3])}")

        return '\n'.join(lines)

    def format_profiles(self, profiles: List[TargetFamilyProfile]) -> str:
        if not profiles:
            return "  No target family profiles (need completed operations)"

        lines = [
            f"TARGET FAMILY PROFILES — {len(profiles)} families",
            f"{'=' * 65}",
        ]

        for p in profiles:
            lines.append(f"")
            lines.append(
                f"  {p.family} ({p.platform}) — Risk: {p.risk_level.upper()}"
            )
            lines.append(
                f"    Analyzed: {p.targets_analyzed} targets, "
                f"{p.total_findings} total findings "
                f"({p.avg_findings_per_target:.1f}/target)"
            )
            if p.most_effective_strategy:
                lines.append(f"    Best strategy: {p.most_effective_strategy}")
            if p.common_weaknesses:
                lines.append(f"    Weaknesses: {', '.join(p.common_weaknesses[:4])}")

        return '\n'.join(lines)

    def format_insights(self, insights: List[StrategicInsight]) -> str:
        if not insights:
            return "  No strategic insights yet (need more operations and findings)"

        lines = [
            f"STRATEGIC INTELLIGENCE — {len(insights)} insight(s)",
            f"{'=' * 65}",
        ]

        for ins in insights:
            lines.append(f"")
            lines.append(f"  [{ins.impact.upper():>8}] {ins.title}")
            lines.append(f"    {ins.description}")
            if ins.evidence:
                for e in ins.evidence:
                    if e:
                        lines.append(f"      - {e}")
            if ins.recommendation:
                lines.append(f"    → {ins.recommendation}")

        return '\n'.join(lines)

    def format_correlation(self) -> str:
        """Format the technique × vuln class correlation matrix."""
        data = self.correlation_matrix()
        if not data['techniques']:
            return "  No correlation data (need operations with findings)"

        # Header
        vuln_short = [vc[:12] for vc in data['vuln_classes']]
        header = f"{'TECHNIQUE':<14}" + "".join(f"{v:<14}" for v in vuln_short)
        lines = [
            f"TECHNIQUE × VULNERABILITY CLASS CORRELATION",
            f"{'=' * (14 + 14 * len(vuln_short))}",
            header,
            '-' * (14 + 14 * len(vuln_short)),
        ]

        for tech in data['techniques']:
            row = f"{tech:<14}"
            for vc in data['vuln_classes']:
                val = data['matrix'][tech].get(vc, 0)
                cell = str(val) if val else '·'
                row += f"{cell:<14}"
            lines.append(row)

        return '\n'.join(lines)

    def format_summary(self) -> str:
        """Complete intelligence summary."""
        patterns = self.detect_patterns()
        profiles = self.build_family_profiles()
        insights = self.generate_insights()

        lines = [
            f"CROSS-OPERATION INTELLIGENCE SUMMARY",
            f"{'=' * 50}",
            f"  Patterns:  {len(patterns)} ({sum(1 for p in patterns if p.is_systemic)} systemic)",
            f"  Families:  {len(profiles)}",
            f"  Insights:  {len(insights)}",
        ]

        critical_insights = [i for i in insights if i.impact == 'critical']
        if critical_insights:
            lines.append(f"")
            lines.append(f"  CRITICAL INSIGHTS:")
            for ci in critical_insights:
                lines.append(f"    ! {ci.title}")

        return '\n'.join(lines)
