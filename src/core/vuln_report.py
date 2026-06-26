"""Automated Vulnerability Report Generator.

Takes findings from any FORGE engine and produces structured reports:
- Markdown (default, human-readable)
- Apple Security submission format
- BSI advisory format (German Federal Office for Information Security)
- JSON (machine-readable, for integration)

Inputs: VulnFinding, SecurityFinding, CrashReport analysis, CVEEntry,
        Decompiler results, or raw finding dicts.

CVSS v3.1 calculation follows FIRST.org specification.

Part of FORGE Phase P: Reporting & Packaging.
"""
# Dependencies: none
# Depended by: none (leaf module)


import json
import math
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ─── CVSS v3.1 Calculator ──────────────────────────────────────────

CVSS_METRICS = {
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20},
    'AC': {'L': 0.77, 'H': 0.44},
    'PR': {
        'N': {'U': 0.85, 'C': 0.85},
        'L': {'U': 0.62, 'C': 0.68},
        'H': {'U': 0.27, 'C': 0.50},
    },
    'UI': {'N': 0.85, 'R': 0.62},
    'C': {'H': 0.56, 'L': 0.22, 'N': 0.0},
    'I': {'H': 0.56, 'L': 0.22, 'N': 0.0},
    'A': {'H': 0.56, 'L': 0.22, 'N': 0.0},
}

CVSS_SEVERITY = {
    (0.0, 0.0): 'NONE',
    (0.1, 3.9): 'LOW',
    (4.0, 6.9): 'MEDIUM',
    (7.0, 8.9): 'HIGH',
    (9.0, 10.0): 'CRITICAL',
}


def cvss_score(vector: str) -> Tuple[float, str]:
    """Calculate CVSS v3.1 base score from vector string.

    Args:
        vector: CVSS vector like 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

    Returns:
        (score, severity_label)
    """
    parts = {}
    for segment in vector.replace('CVSS:3.1/', '').split('/'):
        if ':' in segment:
            key, val = segment.split(':', 1)
            parts[key] = val

    scope = parts.get('S', 'U')

    # ISS (Impact Sub-Score)
    c_val = CVSS_METRICS['C'].get(parts.get('C', 'N'), 0.0)
    i_val = CVSS_METRICS['I'].get(parts.get('I', 'N'), 0.0)
    a_val = CVSS_METRICS['A'].get(parts.get('A', 'N'), 0.0)
    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

    # Impact
    if scope == 'U':
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        return 0.0, 'NONE'

    # Exploitability
    av_val = CVSS_METRICS['AV'].get(parts.get('AV', 'N'), 0.85)
    ac_val = CVSS_METRICS['AC'].get(parts.get('AC', 'L'), 0.77)
    pr_key = parts.get('PR', 'N')
    pr_val = CVSS_METRICS['PR'].get(pr_key, CVSS_METRICS['PR']['N']).get(scope, 0.85)
    ui_val = CVSS_METRICS['UI'].get(parts.get('UI', 'N'), 0.85)

    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    # Final score
    if scope == 'U':
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)

    # Round up to 1 decimal
    score = math.ceil(score * 10) / 10

    # Severity label
    severity = 'NONE'
    for (low, high), label in CVSS_SEVERITY.items():
        if low <= score <= high:
            severity = label
            break

    return score, severity


# ─── Finding Normalizer ────────────────────────────────────────────

class NormalizedFinding:
    """Normalized finding from any FORGE engine."""

    def __init__(self):
        self.id: str = ''
        self.title: str = ''
        self.description: str = ''
        self.severity: str = 'MEDIUM'
        self.cvss_vector: str = ''
        self.cvss_score: float = 0.0
        self.cvss_severity: str = ''
        self.cwe: str = ''
        self.cve_references: List[str] = []
        self.affected_component: str = ''
        self.affected_function: str = ''
        self.affected_line: int = 0
        self.source_file: str = ''
        self.exploit_primitive: str = ''
        self.reproduction_steps: List[str] = []
        self.impact: str = ''
        self.remediation: str = ''
        self.mitigations: List[str] = []
        self.evidence: Dict[str, Any] = {}
        self.platform: str = ''
        self.reachable: bool = True
        self.confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cvss_vector': self.cvss_vector,
            'cvss_score': self.cvss_score,
            'cvss_severity': self.cvss_severity,
            'cwe': self.cwe,
            'cve_references': self.cve_references,
            'affected_component': self.affected_component,
            'affected_function': self.affected_function,
            'affected_line': self.affected_line,
            'source_file': self.source_file,
            'exploit_primitive': self.exploit_primitive,
            'reproduction_steps': self.reproduction_steps,
            'impact': self.impact,
            'remediation': self.remediation,
            'mitigations': self.mitigations,
            'platform': self.platform,
            'reachable': self.reachable,
            'confidence': self.confidence,
        }


def normalize_finding(raw: Dict[str, Any], index: int = 0) -> NormalizedFinding:
    """Normalize a finding dict from any FORGE engine into standard format."""
    f = NormalizedFinding()
    f.id = raw.get('id', f'FORGE-{index+1:04d}')

    # VulnFinding format
    if 'pattern' in raw and 'code' in raw:
        f.title = f"{raw['pattern'].replace('_', ' ').title()} ({raw.get('cwe', 'N/A')})"
        f.description = raw.get('description', '')
        f.severity = raw.get('severity', 'MEDIUM')
        f.cwe = raw.get('cwe', '')
        f.affected_line = raw.get('line', 0)
        f.cve_references = raw.get('cve_examples', [])
        f.evidence = {'code': raw.get('code', '')}

    # SecurityFinding format
    elif 'flow_type' in raw:
        f.title = f"{raw['flow_type'].replace('_', ' ').title()}: {raw.get('source', '')} -> {raw.get('sink', '')}"
        f.description = f"Taint flow from {raw.get('source', '?')} to {raw.get('sink', '?')}"
        f.severity = raw.get('severity', 'MEDIUM')
        f.cvss_vector = raw.get('cvss_vector', '')
        f.reachable = raw.get('reachable', True)
        f.affected_line = raw.get('line_source', 0)
        f.mitigations = raw.get('mitigations', [])
        f.evidence = {
            'source': raw.get('source', ''),
            'sink': raw.get('sink', ''),
            'architecture_context': raw.get('architecture_context', ''),
        }
        if raw.get('impact_score'):
            f.cvss_score = raw['impact_score']

    # CrashAnalyzer format
    elif 'primitive' in raw and isinstance(raw.get('primitive'), dict):
        prim = raw['primitive']
        f.title = f"Crash in {raw.get('app', 'unknown')}: {prim.get('type', 'unknown')}"
        f.description = '; '.join(prim.get('reasoning', []))
        f.exploit_primitive = prim.get('type', '')
        f.confidence = prim.get('confidence', 0.0)
        f.affected_function = raw.get('crashing_function', '')
        f.affected_component = raw.get('app', '')
        f.platform = raw.get('os', '')
        f.evidence = {
            'faulting_address': raw.get('faulting_address', ''),
            'signal': raw.get('signal', ''),
            'exception': raw.get('exception', ''),
            'stack_depth': raw.get('stack_depth', 0),
            'difficulty': prim.get('difficulty', ''),
            'cpu': raw.get('cpu', ''),
            'sip': raw.get('sip', False),
        }
        # Map primitive type to severity
        prim_severity = {
            'execute': 'CRITICAL', 'write': 'HIGH', 'info_leak': 'MEDIUM',
            'dos': 'MEDIUM', 'unknown': 'LOW',
        }
        f.severity = prim_severity.get(prim.get('type', ''), 'MEDIUM')

    # Decompiler format
    elif 'triplets' in raw and 'binary_info' in raw:
        bi = raw['binary_info']
        f.title = f"Binary Analysis: {bi.get('name', 'unknown')}"
        f.description = f"Security score: {bi.get('security_score', 'N/A')}/100"
        f.affected_component = bi.get('name', '')
        f.platform = bi.get('format', '')
        vulns = raw.get('vulnerability_candidates', [])
        if vulns:
            f.severity = 'HIGH'
            f.description += f"; {len(vulns)} vulnerability candidate(s)"
        else:
            f.severity = 'INFO'
        f.evidence = {
            'security_score': bi.get('security_score', 0),
            'vulnerability_candidates': vulns,
            'attack_surfaces': raw.get('attack_surfaces', []),
        }

    # Generic dict fallback
    else:
        f.title = raw.get('title', f'Finding {index+1}')
        f.description = raw.get('description', '')
        f.severity = raw.get('severity', 'MEDIUM')
        f.cwe = raw.get('cwe', '')
        f.cvss_vector = raw.get('cvss_vector', '')
        f.affected_component = raw.get('component', '')
        f.mitigations = raw.get('mitigations', [])

    # Calculate CVSS if vector provided but no score
    if f.cvss_vector and not f.cvss_score:
        f.cvss_score, f.cvss_severity = cvss_score(f.cvss_vector)
    elif f.cvss_vector and f.cvss_score and not f.cvss_severity:
        # Have score and vector but no severity label — derive label
        _, f.cvss_severity = cvss_score(f.cvss_vector)
    elif not f.cvss_vector:
        # Generate approximate vector from severity
        f.cvss_vector, f.cvss_score, f.cvss_severity = _severity_to_cvss(f.severity)

    return f


def _severity_to_cvss(severity: str) -> Tuple[str, float, str]:
    """Generate approximate CVSS vector from severity label."""
    vectors = {
        'CRITICAL': ('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'CRITICAL'),
        'HIGH': ('AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', 8.1, 'HIGH'),
        'MEDIUM': ('AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N', 5.4, 'MEDIUM'),
        'LOW': ('AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', 3.3, 'LOW'),
        'INFO': ('AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N', 0.0, 'NONE'),
    }
    return vectors.get(severity, vectors['MEDIUM'])


# ─── Report Templates ──────────────────────────────────────────────

CWE_DESCRIPTIONS = {
    'CWE-78': 'Improper Neutralization of Special Elements used in an OS Command',
    'CWE-79': 'Improper Neutralization of Input During Web Page Generation (XSS)',
    'CWE-89': 'Improper Neutralization of Special Elements used in an SQL Command',
    'CWE-94': 'Improper Control of Generation of Code (Code Injection)',
    'CWE-120': 'Buffer Copy without Checking Size of Input (Classic Buffer Overflow)',
    'CWE-125': 'Out-of-bounds Read',
    'CWE-134': 'Use of Externally-Controlled Format String',
    'CWE-190': 'Integer Overflow or Wraparound',
    'CWE-200': 'Exposure of Sensitive Information to an Unauthorized Actor',
    'CWE-269': 'Improper Privilege Management',
    'CWE-287': 'Improper Authentication',
    'CWE-362': 'Concurrent Execution using Shared Resource with Improper Synchronization',
    'CWE-367': 'Time-of-check Time-of-use (TOCTOU) Race Condition',
    'CWE-390': 'Detection of Error Condition Without Action',
    'CWE-400': 'Uncontrolled Resource Consumption',
    'CWE-415': 'Double Free',
    'CWE-416': 'Use After Free',
    'CWE-476': 'NULL Pointer Dereference',
    'CWE-480': 'Use of Incorrect Operator',
    'CWE-502': 'Deserialization of Untrusted Data',
    'CWE-617': 'Reachable Assertion',
    'CWE-732': 'Incorrect Permission Assignment for Critical Resource',
    'CWE-787': 'Out-of-bounds Write',
    'CWE-843': 'Access of Resource Using Incompatible Type (Type Confusion)',
    'CWE-862': 'Missing Authorization',
}


# ─── Report Generator ──────────────────────────────────────────────

class VulnReportGenerator:
    """Generate vulnerability reports in multiple formats."""

    def __init__(self):
        self.findings: List[NormalizedFinding] = []
        self.metadata: Dict[str, str] = {
            'author': 'FORGE Vulnerability Report Generator',
            'date': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            'version': '1.0',
        }

    def add_finding(self, raw: Dict[str, Any]):
        """Add a raw finding dict (from any FORGE engine)."""
        nf = normalize_finding(raw, len(self.findings))
        self.findings.append(nf)

    def add_findings(self, raws: List[Dict[str, Any]]):
        """Add multiple raw findings."""
        for raw in raws:
            self.add_finding(raw)

    def set_metadata(self, **kwargs):
        """Set report metadata (title, author, target, date, etc.)."""
        self.metadata.update(kwargs)

    def summary(self) -> Dict[str, Any]:
        """Get report summary statistics."""
        by_severity = {}
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        max_cvss = max((f.cvss_score for f in self.findings), default=0.0)
        reachable = sum(1 for f in self.findings if f.reachable)
        cwes = sorted(set(f.cwe for f in self.findings if f.cwe))

        return {
            'total': len(self.findings),
            'by_severity': by_severity,
            'max_cvss': max_cvss,
            'reachable': reachable,
            'unique_cwes': cwes,
            'overall_risk': 'CRITICAL' if by_severity.get('CRITICAL', 0) > 0
                           else 'HIGH' if by_severity.get('HIGH', 0) > 0
                           else 'MEDIUM' if by_severity.get('MEDIUM', 0) > 0
                           else 'LOW',
        }

    # ─── Markdown Format ────────────────────────────────────────

    def to_markdown(self) -> str:
        """Generate full Markdown report."""
        s = self.summary()
        now = self.metadata.get('date', datetime.now(timezone.utc).strftime('%Y-%m-%d'))
        title = self.metadata.get('title', 'Vulnerability Assessment Report')
        target = self.metadata.get('target', 'N/A')

        lines = [
            f'# {title}',
            '',
            f'**Date:** {now}  ',
            f'**Author:** {self.metadata.get("author", "FORGE")}  ',
            f'**Target:** {target}  ',
            f'**Classification:** {self.metadata.get("classification", "CONFIDENTIAL")}',
            '',
            '---',
            '',
            '## Executive Summary',
            '',
            f'This assessment identified **{s["total"]} finding(s)** '
            f'with an overall risk rating of **{s["overall_risk"]}**.',
            '',
            f'- Maximum CVSS Score: **{s["max_cvss"]:.1f}**',
            f'- Critical: {s["by_severity"].get("CRITICAL", 0)}',
            f'- High: {s["by_severity"].get("HIGH", 0)}',
            f'- Medium: {s["by_severity"].get("MEDIUM", 0)}',
            f'- Low: {s["by_severity"].get("LOW", 0)}',
            f'- Reachable/Exploitable: {s["reachable"]}/{s["total"]}',
            '',
        ]

        if s['unique_cwes']:
            lines.append(f'**CWE Coverage:** {", ".join(s["unique_cwes"])}')
            lines.append('')

        lines.extend([
            '---',
            '',
            '## Findings',
            '',
        ])

        # Sort by CVSS score descending
        sorted_findings = sorted(self.findings, key=lambda f: -f.cvss_score)

        for i, f in enumerate(sorted_findings, 1):
            sev_icon = {'CRITICAL': 'P1', 'HIGH': 'P2', 'MEDIUM': 'P3',
                        'LOW': 'P4', 'INFO': 'P5'}.get(f.severity, 'P3')
            lines.extend([
                f'### [{sev_icon}] {f.id}: {f.title}',
                '',
                f'| Field | Value |',
                f'|-------|-------|',
                f'| Severity | {f.severity} |',
                f'| CVSS Score | {f.cvss_score:.1f} ({f.cvss_severity}) |',
                f'| CVSS Vector | `{f.cvss_vector}` |',
            ])
            if f.cwe:
                cwe_desc = CWE_DESCRIPTIONS.get(f.cwe, '')
                lines.append(f'| CWE | {f.cwe}: {cwe_desc} |')
            if f.affected_component:
                lines.append(f'| Component | {f.affected_component} |')
            if f.affected_function:
                lines.append(f'| Function | `{f.affected_function}` |')
            if f.affected_line:
                lines.append(f'| Line | {f.affected_line} |')
            if f.exploit_primitive:
                lines.append(f'| Exploit Primitive | {f.exploit_primitive} |')
            if f.platform:
                lines.append(f'| Platform | {f.platform} |')
            lines.append(f'| Confidence | {f.confidence:.0%} |')
            lines.append('')

            lines.extend([
                '**Description:**',
                f'{f.description}',
                '',
            ])

            if f.evidence:
                lines.append('**Evidence:**')
                for ek, ev in f.evidence.items():
                    if isinstance(ev, list):
                        lines.append(f'- {ek}: {len(ev)} item(s)')
                    elif isinstance(ev, str) and len(ev) > 100:
                        lines.append(f'- {ek}: `{ev[:100]}...`')
                    else:
                        lines.append(f'- {ek}: `{ev}`')
                lines.append('')

            if f.reproduction_steps:
                lines.append('**Reproduction Steps:**')
                for j, step in enumerate(f.reproduction_steps, 1):
                    lines.append(f'{j}. {step}')
                lines.append('')

            if f.impact:
                lines.extend(['**Impact:**', f'{f.impact}', ''])

            if f.remediation:
                lines.extend(['**Remediation:**', f'{f.remediation}', ''])

            if f.mitigations:
                lines.append('**Mitigations:**')
                for m in f.mitigations:
                    lines.append(f'- {m}')
                lines.append('')

            if f.cve_references:
                lines.append('**Related CVEs:**')
                for cve in f.cve_references:
                    lines.append(f'- {cve}')
                lines.append('')

            lines.extend(['---', ''])

        # Appendix
        lines.extend([
            '## Appendix: CVSS Score Breakdown',
            '',
            '| Finding | CVSS | Severity | Vector |',
            '|---------|------|----------|--------|',
        ])
        for f in sorted_findings:
            lines.append(f'| {f.id} | {f.cvss_score:.1f} | {f.severity} | `{f.cvss_vector}` |')
        lines.append('')

        lines.extend([
            '---',
            f'*Generated by FORGE v{self.metadata.get("version", "1.0")} — '
            f'{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}*',
        ])

        return '\n'.join(lines)

    # ─── Apple Security Submission ──────────────────────────────

    def to_apple_security(self) -> str:
        """Generate Apple Security Research submission format.

        Format follows Apple's Security Bounty program structure:
        https://security.apple.com/research/
        """
        s = self.summary()
        now = self.metadata.get('date', datetime.now(timezone.utc).strftime('%Y-%m-%d'))
        lines = [
            '# Apple Security Research — Vulnerability Report',
            '',
            f'**Submission Date:** {now}',
            f'**Researcher:** {self.metadata.get("researcher", self.metadata.get("author", ""))}',
            f'**Contact:** {self.metadata.get("contact", "")}',
            '',
        ]

        sorted_findings = sorted(self.findings, key=lambda f: -f.cvss_score)

        for i, f in enumerate(sorted_findings, 1):
            lines.extend([
                f'## Vulnerability {i}',
                '',
                f'**Title:** {f.title}',
                '',
                '### Affected Software',
                f'- **Product:** {f.affected_component or self.metadata.get("target", "macOS")}',
                f'- **Version:** {self.metadata.get("version_affected", "latest")}',
                f'- **Platform:** {f.platform or self.metadata.get("platform", "macOS")}',
                '',
                '### Description',
                f'{f.description}',
                '',
                '### Impact',
                f'- **CVSS v3.1 Base Score:** {f.cvss_score:.1f} ({f.cvss_severity})',
                f'- **Vector:** `{f.cvss_vector}`',
            ])
            if f.cwe:
                lines.append(f'- **CWE:** {f.cwe}')
            if f.exploit_primitive:
                lines.append(f'- **Exploit Primitive:** {f.exploit_primitive}')
            lines.append('')

            if f.impact:
                lines.extend([f'{f.impact}', ''])
            else:
                # Auto-generate impact statement
                impact_map = {
                    'execute': 'An attacker could achieve arbitrary code execution with the privileges of the affected process.',
                    'write': 'An attacker could achieve an arbitrary write primitive, potentially leading to code execution.',
                    'info_leak': 'An attacker could read sensitive process memory, potentially defeating ASLR.',
                    'dos': 'An attacker could cause the affected process to crash (denial of service).',
                }
                impact_text = impact_map.get(f.exploit_primitive,
                    f'Exploitation of this vulnerability could lead to {f.severity.lower()}-severity impact.')
                lines.extend([impact_text, ''])

            lines.extend([
                '### Steps to Reproduce',
            ])
            if f.reproduction_steps:
                for j, step in enumerate(f.reproduction_steps, 1):
                    lines.append(f'{j}. {step}')
            else:
                lines.extend([
                    '1. [Build or obtain the test binary/input]',
                    '2. [Execute the trigger command]',
                    '3. [Observe the crash in Console.app or crash logs]',
                    f'4. Crash log location: `/Library/Logs/DiagnosticReports/`',
                ])
            lines.append('')

            if f.evidence:
                lines.append('### Evidence')
                if 'faulting_address' in f.evidence:
                    lines.append(f'- Faulting Address: `{f.evidence["faulting_address"]}`')
                if 'signal' in f.evidence:
                    lines.append(f'- Signal: `{f.evidence["signal"]}`')
                if 'exception' in f.evidence:
                    lines.append(f'- Exception: `{f.evidence["exception"]}`')
                if 'code' in f.evidence:
                    lines.extend(['', '```', f.evidence['code'], '```'])
                lines.append('')

            if f.remediation:
                lines.extend([
                    '### Suggested Fix',
                    f'{f.remediation}',
                    '',
                ])

            lines.extend(['---', ''])

        lines.extend([
            '### Additional Information',
            f'- Tool: FORGE Automated Vulnerability Research',
            f'- Analysis Date: {now}',
            f'- Findings: {s["total"]} total, {s["by_severity"].get("CRITICAL", 0)} critical',
        ])

        return '\n'.join(lines)

    # ─── BSI Advisory Format ───────────────────────────────────

    def to_bsi_advisory(self) -> str:
        """Generate BSI (Bundesamt fuer Informationssicherheit) advisory format.

        Structure follows BSI-CERT advisories (WID-SEC-YYYY-NNNN).
        """
        s = self.summary()
        now = self.metadata.get('date', datetime.now(timezone.utc).strftime('%Y-%m-%d'))
        advisory_id = self.metadata.get('advisory_id',
                                         f'WID-SEC-{datetime.now().year}-{int(time.time()) % 10000:04d}')

        risk_de = {
            'CRITICAL': 'sehr hoch', 'HIGH': 'hoch',
            'MEDIUM': 'mittel', 'LOW': 'niedrig', 'INFO': 'info',
        }

        lines = [
            f'# {advisory_id}',
            '',
            f'**Titel:** {self.metadata.get("title", "Sicherheitslücke")}',
            f'**Datum:** {now}',
            f'**Risikostufe:** {risk_de.get(s["overall_risk"], "mittel")} (CVSS {s["max_cvss"]:.1f})',
            f'**Betroffene Systeme:** {self.metadata.get("target", "N/A")}',
            '',
            '## Beschreibung',
            '',
        ]

        sorted_findings = sorted(self.findings, key=lambda f: -f.cvss_score)

        for i, f in enumerate(sorted_findings, 1):
            lines.extend([
                f'### Schwachstelle {i}: {f.title}',
                '',
                f'{f.description}',
                '',
                f'- **CVSS Base Score:** {f.cvss_score:.1f}',
                f'- **CVSS Vector:** `{f.cvss_vector}`',
                f'- **Risikostufe:** {risk_de.get(f.severity, "mittel")}',
            ])
            if f.cwe:
                lines.append(f'- **CWE:** {f.cwe}')
            if f.affected_component:
                lines.append(f'- **Betroffene Komponente:** {f.affected_component}')
            lines.append('')

        lines.extend([
            '## Empfehlung',
            '',
        ])

        all_mitigations = set()
        for f in self.findings:
            all_mitigations.update(f.mitigations)
        if all_mitigations:
            for m in sorted(all_mitigations):
                lines.append(f'- {m}')
        else:
            lines.append('- Hersteller-Patches anwenden, sobald verfügbar')
            lines.append('- Netzwerkzugang einschränken')
            lines.append('- Monitoring auf Exploitation-Indikatoren')
        lines.append('')

        lines.extend([
            '## Quellen',
            '',
            f'- FORGE Automated Vulnerability Research ({now})',
        ])
        all_cves = set()
        for f in self.findings:
            all_cves.update(f.cve_references)
        for cve in sorted(all_cves):
            lines.append(f'- {cve}')

        return '\n'.join(lines)

    # ─── JSON Format ───────────────────────────────────────────

    def to_json(self) -> str:
        """Generate machine-readable JSON report."""
        return json.dumps({
            'metadata': self.metadata,
            'summary': self.summary(),
            'findings': [f.to_dict() for f in self.findings],
        }, indent=2)

    # ─── Triplet Export ────────────────────────────────────────

    def to_triplets(self) -> List[Dict[str, str]]:
        """Export findings as causal triplets for FORGE knowledge base."""
        triplets = []
        for f in self.findings:
            # Main finding triplet
            triplets.append({
                'trigger': f.title,
                'mechanism': f.description[:200] if f.description else 'vulnerability detected',
                'outcome': f'CVSS {f.cvss_score:.1f} {f.severity} vulnerability',
                'confidence': f.confidence,
            })

            # CWE mapping triplet
            if f.cwe:
                cwe_desc = CWE_DESCRIPTIONS.get(f.cwe, f.cwe)
                triplets.append({
                    'trigger': f.cwe,
                    'mechanism': cwe_desc,
                    'outcome': f'{f.severity} impact on {f.affected_component or "target"}',
                    'confidence': 0.9,
                })

            # Remediation triplet
            if f.mitigations:
                triplets.append({
                    'trigger': f.title,
                    'mechanism': '; '.join(f.mitigations[:3]),
                    'outcome': 'vulnerability mitigated',
                    'confidence': 0.8,
                })

        return triplets

    # ─── File Output ───────────────────────────────────────────

    def save(self, output_dir: str, formats: List[str] = None):
        """Save reports in specified formats.

        Args:
            output_dir: Directory to save reports
            formats: List of formats: 'markdown', 'apple', 'bsi', 'json'
                    Default: all formats.

        Returns:
            Dict of format → filepath
        """
        if formats is None:
            formats = ['markdown', 'apple', 'bsi', 'json']

        os.makedirs(output_dir, exist_ok=True)
        saved = {}

        generators = {
            'markdown': ('report.md', self.to_markdown),
            'apple': ('apple_security_submission.md', self.to_apple_security),
            'bsi': ('bsi_advisory.md', self.to_bsi_advisory),
            'json': ('report.json', self.to_json),
        }

        for fmt in formats:
            if fmt in generators:
                filename, gen_func = generators[fmt]
                filepath = os.path.join(output_dir, filename)
                content = gen_func()
                with open(filepath, 'w') as fh:
                    fh.write(content)
                saved[fmt] = filepath

        return saved

    def format_summary(self) -> str:
        """Format a brief summary for CLI output."""
        s = self.summary()
        lines = [
            f"VULNERABILITY REPORT SUMMARY",
            f"{'=' * 50}",
            f"  Findings: {s['total']}",
            f"  Overall Risk: {s['overall_risk']}",
            f"  Max CVSS: {s['max_cvss']:.1f}",
            f"  Critical: {s['by_severity'].get('CRITICAL', 0)} | "
            f"High: {s['by_severity'].get('HIGH', 0)} | "
            f"Medium: {s['by_severity'].get('MEDIUM', 0)} | "
            f"Low: {s['by_severity'].get('LOW', 0)}",
            f"  Reachable: {s['reachable']}/{s['total']}",
        ]
        if s['unique_cwes']:
            lines.append(f"  CWEs: {', '.join(s['unique_cwes'][:10])}")
        return '\n'.join(lines)
