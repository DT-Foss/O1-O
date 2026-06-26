"""Automated Vulnerability Report Generator.

Transforms FORGE findings into structured security reports:
  - CVSS v3.1 score calculation
  - Impact assessment and severity classification
  - Reproduction steps from crash/finding data
  - Executive summary generation
  - Multiple output formats (Markdown, JSON, SARIF)
  - Compatible with Apple Security, BSI CERT-Bund, NATO STANAG

Part of FORGE Phase P: Professional Output.
"""
# Dependencies: none
# Depended by: mission_package

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ─── CVSS v3.1 Calculator ───────────────────────────────────────────

CVSS_METRICS = {
    # Attack Vector (AV)
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20},
    # Attack Complexity (AC)
    'AC': {'L': 0.77, 'H': 0.44},
    # Privileges Required (PR) — scope unchanged
    'PR_U': {'N': 0.85, 'L': 0.62, 'H': 0.27},
    # Privileges Required (PR) — scope changed
    'PR_C': {'N': 0.85, 'L': 0.68, 'H': 0.50},
    # User Interaction (UI)
    'UI': {'N': 0.85, 'R': 0.62},
    # Scope (S)
    'S': {'U': False, 'C': True},
    # Confidentiality (C)
    'C': {'H': 0.56, 'L': 0.22, 'N': 0.0},
    # Integrity (I)
    'I': {'H': 0.56, 'L': 0.22, 'N': 0.0},
    # Availability (A)
    'A': {'H': 0.56, 'L': 0.22, 'N': 0.0},
}


def compute_cvss(av='N', ac='L', pr='N', ui='N', s='U', c='H', i='H', a='H') -> dict:
    """Compute CVSS v3.1 Base Score.

    Args:
        av: Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)
        ac: Attack Complexity (L=Low, H=High)
        pr: Privileges Required (N=None, L=Low, H=High)
        ui: User Interaction (N=None, R=Required)
        s: Scope (U=Unchanged, C=Changed)
        c: Confidentiality Impact (H=High, L=Low, N=None)
        i: Integrity Impact (H=High, L=Low, N=None)
        a: Availability Impact (H=High, L=Low, N=None)

    Returns:
        {score, severity, vector, breakdown}
    """
    scope_changed = CVSS_METRICS['S'][s]

    # Exploitability
    pr_key = 'PR_C' if scope_changed else 'PR_U'
    exploitability = 8.22 * CVSS_METRICS['AV'][av] * CVSS_METRICS['AC'][ac] * \
                     CVSS_METRICS[pr_key][pr] * CVSS_METRICS['UI'][ui]

    # Impact
    isc_base = 1 - (1 - CVSS_METRICS['C'][c]) * (1 - CVSS_METRICS['I'][i]) * (1 - CVSS_METRICS['A'][a])

    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = min(10.0, 1.08 * (impact + exploitability))
    else:
        score = min(10.0, impact + exploitability)

    # Round up to nearest 0.1
    score = round(score * 10) / 10
    if score != int(score):
        import math
        score = math.ceil(score * 10) / 10

    # Severity rating
    if score == 0:
        severity = 'None'
    elif score < 4.0:
        severity = 'Low'
    elif score < 7.0:
        severity = 'Medium'
    elif score < 9.0:
        severity = 'High'
    else:
        severity = 'Critical'

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    return {
        'score': score,
        'severity': severity,
        'vector': vector,
        'exploitability': round(exploitability, 2),
        'impact': round(impact, 2),
    }


def _primitive_to_cvss(primitive_type: str, platform: str = '') -> dict:
    """Map exploit primitive to CVSS metrics."""
    mappings = {
        'execute': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'C', 'c': 'H', 'i': 'H', 'a': 'H'},
        'write': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'N', 'i': 'H', 'a': 'H'},
        'read': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'H', 'i': 'N', 'a': 'N'},
        'dos': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'N', 'i': 'N', 'a': 'H'},
        'buffer_overflow': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'H', 'i': 'H', 'a': 'H'},
        'command_injection': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'C', 'c': 'H', 'i': 'H', 'a': 'H'},
        'format_string': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'H', 'i': 'H', 'a': 'H'},
        'privilege_escalation': {'av': 'L', 'ac': 'L', 'pr': 'L', 'ui': 'N', 's': 'C', 'c': 'H', 'i': 'H', 'a': 'H'},
        'code_injection': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'C', 'c': 'H', 'i': 'H', 'a': 'H'},
        'integer_overflow': {'av': 'N', 'ac': 'H', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'L', 'i': 'L', 'a': 'H'},
        'use_after_free': {'av': 'N', 'ac': 'H', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'H', 'i': 'H', 'a': 'H'},
        'stack_buffer_overflow': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'H', 'i': 'H', 'a': 'H'},
        'heap_overflow': {'av': 'N', 'ac': 'H', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'H', 'i': 'H', 'a': 'H'},
        'race_condition': {'av': 'L', 'ac': 'H', 'pr': 'L', 'ui': 'N', 's': 'U', 'c': 'H', 'i': 'H', 'a': 'H'},
        'info_leak': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'H', 'i': 'N', 'a': 'N'},
        'unknown': {'av': 'N', 'ac': 'H', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'L', 'i': 'L', 'a': 'L'},
    }

    # Find best match
    ptype = primitive_type.lower()
    for key in mappings:
        if key in ptype:
            return mappings[key]

    return mappings['unknown']


# ─── Report Generator ───────────────────────────────────────────────

class VulnReport:
    """Single vulnerability report."""

    def __init__(self):
        self.id = ''
        self.title = ''
        self.summary = ''
        self.primitive_type = ''
        self.severity = ''
        self.cvss = {}
        self.target = ''
        self.platform = ''
        self.affected_function = ''
        self.affected_address = ''
        self.description = ''
        self.impact = ''
        self.reproduction_steps = []
        self.stack_trace = ''
        self.mitigations = []
        self.references = []
        self.evidence = []
        self.found_by = 'FORGE'
        self.found_at = ''
        self.cve_id = ''


class ReportGenerator:
    """Generate structured vulnerability reports from FORGE findings."""

    def __init__(self, analyst: str = 'FORGE Automated Analysis',
                 organization: str = ''):
        self.analyst = analyst
        self.organization = organization
        self.reports: List[VulnReport] = []
        self.report_counter = 0

    def generate_from_finding(self, finding: dict) -> VulnReport:
        """Generate a report from a FindingAggregator finding.

        Args:
            finding: Dict with keys from FindingAggregator (primitive_type,
                     severity, target_name, faulting_function, stack_trace, etc.)
        """
        self.report_counter += 1
        report = VulnReport()

        # ID
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d')
        report.id = f"FORGE-{timestamp}-{self.report_counter:04d}"
        report.found_at = datetime.now(timezone.utc).isoformat()

        # Basic info
        report.primitive_type = finding.get('primitive_type', 'unknown')
        report.target = finding.get('target_name', finding.get('target_path', 'Unknown'))
        report.platform = finding.get('platform', '')
        report.affected_function = finding.get('faulting_function', '')
        report.affected_address = finding.get('fault_address', '')
        report.stack_trace = finding.get('stack_trace', '')
        report.cve_id = finding.get('cve_id', '')

        # CVSS
        cvss_params = _primitive_to_cvss(report.primitive_type, report.platform)
        report.cvss = compute_cvss(**cvss_params)
        report.severity = report.cvss['severity']

        # Title
        report.title = self._generate_title(finding, report)

        # Summary
        report.summary = self._generate_summary(finding, report)

        # Description
        report.description = self._generate_description(finding, report)

        # Impact
        report.impact = self._generate_impact(finding, report)

        # Reproduction steps
        report.reproduction_steps = self._generate_repro_steps(finding, report)

        # Mitigations
        report.mitigations = self._generate_mitigations(finding, report)

        # Evidence
        if report.stack_trace:
            report.evidence.append({
                'type': 'stack_trace',
                'data': report.stack_trace,
            })
        if finding.get('input_file'):
            report.evidence.append({
                'type': 'crash_input',
                'path': finding['input_file'],
            })

        self.reports.append(report)
        return report

    def generate_from_decompiler(self, decomp_result: dict) -> List[VulnReport]:
        """Generate reports from decompiler analysis hotspots."""
        reports = []

        for hotspot in decomp_result.get('hotspots', []):
            if hotspot.get('score', 0) < 30:
                continue  # Skip low-score functions

            finding = {
                'primitive_type': 'buffer_overflow',  # Default, refined below
                'severity': 'medium',
                'target_name': decomp_result.get('name', 'binary'),
                'faulting_function': hotspot.get('function', ''),
                'fault_address': hotspot.get('addr', ''),
                'platform': decomp_result.get('binary', {}).get('format', ''),
                'stack_size': hotspot.get('stack_size', 0),
                'complexity': hotspot.get('complexity', 0),
                'dangerous_calls': hotspot.get('dangerous_calls', 0),
                'vuln_score': hotspot.get('score', 0),
            }

            report = self.generate_from_finding(finding)
            reports.append(report)

        return reports

    # ─── Content Generation ──────────────────────────────────────

    def _generate_title(self, finding: dict, report: VulnReport) -> str:
        ptype = report.primitive_type.replace('_', ' ').title()
        target = report.target
        func = report.affected_function
        if func:
            return f"{ptype} in {target}::{func}"
        return f"{ptype} in {target}"

    def _generate_summary(self, finding: dict, report: VulnReport) -> str:
        parts = [
            f"A {report.severity.lower()}-severity {report.primitive_type.replace('_', ' ')} "
            f"vulnerability was identified in {report.target}",
        ]
        if report.affected_function:
            parts[0] += f" (function: {report.affected_function})"
        parts[0] += "."

        parts.append(
            f"This vulnerability has a CVSS v3.1 base score of {report.cvss['score']} "
            f"({report.severity})."
        )

        if report.cvss['score'] >= 9.0:
            parts.append(
                "Immediate remediation is recommended due to the critical severity."
            )
        elif report.cvss['score'] >= 7.0:
            parts.append(
                "Remediation should be prioritized in the next maintenance window."
            )

        return ' '.join(parts)

    def _generate_description(self, finding: dict, report: VulnReport) -> str:
        lines = []

        ptype = report.primitive_type
        desc_map = {
            'buffer_overflow': (
                "A buffer overflow condition exists where data can be written beyond "
                "the allocated buffer boundary. This can lead to memory corruption, "
                "potentially allowing an attacker to execute arbitrary code or cause "
                "a denial of service."
            ),
            'command_injection': (
                "A command injection vulnerability allows an attacker to execute "
                "arbitrary operating system commands through the application. "
                "User-supplied input is insufficiently sanitized before being "
                "passed to a system command interpreter."
            ),
            'format_string': (
                "A format string vulnerability exists where user-controlled input "
                "is used as a format string argument. This can enable reading from "
                "and writing to arbitrary memory locations."
            ),
            'integer_overflow': (
                "An integer overflow condition exists where arithmetic operations "
                "on integer values produce results outside the representable range. "
                "This can lead to incorrect size calculations, buffer overflows, "
                "or logic errors."
            ),
            'use_after_free': (
                "A use-after-free vulnerability exists where memory is accessed "
                "after it has been freed. This can lead to arbitrary code execution "
                "if the freed memory is reallocated and controlled by an attacker."
            ),
            'stack_buffer_overflow': (
                "A stack-based buffer overflow exists where data written to a "
                "stack buffer exceeds its allocated size. Without stack canary "
                "protection, this enables return address overwrite and arbitrary "
                "code execution."
            ),
            'privilege_escalation': (
                "A privilege escalation vulnerability allows an attacker to gain "
                "elevated privileges beyond those initially granted. This can "
                "result in full system compromise."
            ),
            'race_condition': (
                "A race condition (TOCTOU) vulnerability exists where the state "
                "of a resource can change between checking and using it. This "
                "can be exploited for privilege escalation or file manipulation."
            ),
        }

        lines.append(desc_map.get(ptype, f"A {ptype.replace('_', ' ')} vulnerability was identified."))

        # Add specifics
        if finding.get('stack_size', 0) > 0:
            lines.append(
                f"\nThe affected function allocates a {finding['stack_size']}-byte stack frame"
                f"{' without stack canary protection' if not finding.get('has_canary') else ''}."
            )

        if finding.get('dangerous_calls', 0) > 0:
            lines.append(
                f"\n{finding['dangerous_calls']} calls to dangerous functions were identified "
                f"within the affected function."
            )

        return '\n'.join(lines)

    def _generate_impact(self, finding: dict, report: VulnReport) -> str:
        impacts = {
            'buffer_overflow': "Code execution, denial of service, information disclosure",
            'command_injection': "Full system compromise, lateral movement, data exfiltration",
            'format_string': "Arbitrary read/write, code execution, information disclosure",
            'integer_overflow': "Memory corruption, denial of service, potential code execution",
            'use_after_free': "Code execution, privilege escalation",
            'stack_buffer_overflow': "Return address overwrite, code execution, denial of service",
            'privilege_escalation': "Full system compromise, persistence, lateral movement",
            'race_condition': "Privilege escalation, file manipulation",
            'dos': "Service disruption, resource exhaustion",
            'info_leak': "Memory disclosure, ASLR bypass, credential exposure",
            'code_injection': "Arbitrary code execution, full system compromise",
        }

        impact = impacts.get(report.primitive_type, "Varies based on exploitation context")
        return f"Potential impact: {impact}."

    def _generate_repro_steps(self, finding: dict, report: VulnReport) -> List[str]:
        steps = []

        steps.append(f"1. Identify the target binary: {report.target}")

        if report.affected_function:
            steps.append(f"2. Locate the vulnerable function: {report.affected_function}")
            if report.affected_address:
                steps.append(f"   Address: {report.affected_address}")

        if finding.get('input_file'):
            steps.append(f"3. Use the provided crash input: {finding['input_file']}")
            steps.append(f"4. Execute the target with the crash input")
            steps.append(f"5. Observe the crash/anomalous behavior")
        else:
            steps.append(f"3. Craft input targeting the identified vulnerability pattern")
            steps.append(f"4. Deliver input through the identified attack vector")
            steps.append(f"5. Monitor for crash or anomalous behavior")

        if report.stack_trace:
            steps.append(f"6. Verify crash matches the expected stack trace")

        return steps

    def _generate_mitigations(self, finding: dict, report: VulnReport) -> List[str]:
        mitigations = []
        ptype = report.primitive_type

        if 'overflow' in ptype or 'buffer' in ptype:
            mitigations.extend([
                "Enable stack canaries (-fstack-protector-strong)",
                "Use bounds-checked functions (strncpy, snprintf instead of strcpy, sprintf)",
                "Enable ASLR and PIE for all binaries",
                "Consider using memory-safe languages for new components",
            ])
        elif 'injection' in ptype:
            mitigations.extend([
                "Sanitize and validate all user input",
                "Use parameterized commands instead of string concatenation",
                "Apply principle of least privilege to the execution context",
                "Implement input allowlisting where possible",
            ])
        elif 'format_string' in ptype:
            mitigations.extend([
                "Never pass user input as format string argument",
                "Use static format strings only",
                "Enable -Wformat-security compiler warnings",
            ])
        elif 'privilege' in ptype:
            mitigations.extend([
                "Apply principle of least privilege",
                "Drop unnecessary capabilities after initialization",
                "Use capability-based security model",
            ])

        # Universal mitigations
        mitigations.extend([
            "Enable all available compiler hardening flags",
            "Conduct regular security audits and code review",
        ])

        return mitigations

    # ─── Output Formats ──────────────────────────────────────────

    def to_markdown(self, report: VulnReport) -> str:
        """Generate Markdown vulnerability report."""
        lines = [
            f"# {report.title}",
            f"",
            f"**Report ID:** {report.id}  ",
            f"**Date:** {report.found_at}  ",
            f"**Analyst:** {self.analyst}  ",
        ]
        if self.organization:
            lines.append(f"**Organization:** {self.organization}  ")
        if report.cve_id:
            lines.append(f"**CVE:** {report.cve_id}  ")
        lines.append(f"")

        # CVSS
        lines.extend([
            f"## CVSS v3.1 Score",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| **Base Score** | **{report.cvss['score']}** |",
            f"| **Severity** | **{report.severity}** |",
            f"| **Vector** | `{report.cvss['vector']}` |",
            f"| Exploitability | {report.cvss['exploitability']} |",
            f"| Impact | {report.cvss['impact']} |",
            f"",
        ])

        # Summary
        lines.extend([
            f"## Executive Summary",
            f"",
            f"{report.summary}",
            f"",
        ])

        # Affected Component
        lines.extend([
            f"## Affected Component",
            f"",
            f"- **Target:** {report.target}",
            f"- **Platform:** {report.platform}",
        ])
        if report.affected_function:
            lines.append(f"- **Function:** {report.affected_function}")
        if report.affected_address:
            lines.append(f"- **Address:** {report.affected_address}")
        lines.append(f"")

        # Description
        lines.extend([
            f"## Vulnerability Description",
            f"",
            f"{report.description}",
            f"",
        ])

        # Impact
        lines.extend([
            f"## Impact Assessment",
            f"",
            f"{report.impact}",
            f"",
        ])

        # Reproduction
        if report.reproduction_steps:
            lines.extend([
                f"## Reproduction Steps",
                f"",
            ])
            for step in report.reproduction_steps:
                lines.append(step)
            lines.append(f"")

        # Evidence
        if report.evidence:
            lines.extend([
                f"## Evidence",
                f"",
            ])
            for ev in report.evidence:
                if ev['type'] == 'stack_trace':
                    lines.extend([
                        f"### Stack Trace",
                        f"```",
                        ev['data'],
                        f"```",
                        f"",
                    ])
                elif ev['type'] == 'crash_input':
                    lines.append(f"- Crash input file: `{ev['path']}`")
            lines.append(f"")

        # Mitigations
        if report.mitigations:
            lines.extend([
                f"## Recommended Mitigations",
                f"",
            ])
            for i, mit in enumerate(report.mitigations, 1):
                lines.append(f"{i}. {mit}")
            lines.append(f"")

        # Footer
        lines.extend([
            f"---",
            f"*Generated by FORGE Automated Security Analysis*  ",
            f"*Report ID: {report.id}*",
        ])

        return '\n'.join(lines)

    def to_json(self, report: VulnReport) -> dict:
        """Generate JSON report (machine-readable)."""
        return {
            'report_id': report.id,
            'title': report.title,
            'summary': report.summary,
            'cvss': report.cvss,
            'severity': report.severity,
            'primitive_type': report.primitive_type,
            'target': report.target,
            'platform': report.platform,
            'affected_function': report.affected_function,
            'affected_address': report.affected_address,
            'description': report.description,
            'impact': report.impact,
            'reproduction_steps': report.reproduction_steps,
            'mitigations': report.mitigations,
            'evidence': report.evidence,
            'cve_id': report.cve_id,
            'found_by': report.found_by,
            'found_at': report.found_at,
            'analyst': self.analyst,
            'organization': self.organization,
        }

    def to_sarif(self, reports: List[VulnReport] = None) -> dict:
        """Generate SARIF v2.1.0 output (GitHub/Azure DevOps compatible)."""
        if reports is None:
            reports = self.reports

        sarif = {
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
            'version': '2.1.0',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'FORGE',
                        'version': '1.0.0',
                        'informationUri': 'https://github.com/forge-security',
                        'rules': [],
                    }
                },
                'results': [],
            }]
        }

        run = sarif['runs'][0]
        rule_ids = set()

        for report in reports:
            rule_id = f"FORGE/{report.primitive_type}"

            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                run['tool']['driver']['rules'].append({
                    'id': rule_id,
                    'name': report.primitive_type.replace('_', ' ').title(),
                    'shortDescription': {'text': report.title},
                    'helpUri': f'https://cwe.mitre.org/data/definitions/119.html',
                    'properties': {
                        'precision': 'high',
                        'severity': report.severity.lower(),
                    },
                })

            result_entry = {
                'ruleId': rule_id,
                'level': {'Critical': 'error', 'High': 'error',
                          'Medium': 'warning', 'Low': 'note',
                          'None': 'none'}.get(report.severity, 'warning'),
                'message': {'text': report.summary},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': report.target,
                        },
                    },
                }],
                'properties': {
                    'cvss': report.cvss['score'],
                    'reportId': report.id,
                },
            }
            run['results'].append(result_entry)

        return sarif

    # ─── Batch Operations ────────────────────────────────────────

    def generate_all_reports(self, findings: List[dict]) -> List[VulnReport]:
        """Generate reports for all findings."""
        reports = []
        for finding in findings:
            report = self.generate_from_finding(finding)
            reports.append(report)
        return reports

    def save_reports(self, output_dir: str, format: str = 'markdown') -> List[str]:
        """Save all reports to files.

        Args:
            output_dir: Directory to save reports
            format: 'markdown', 'json', 'sarif', or 'all'

        Returns:
            List of saved file paths
        """
        os.makedirs(output_dir, exist_ok=True)
        saved = []

        if format in ('markdown', 'all'):
            for report in self.reports:
                path = os.path.join(output_dir, f"{report.id}.md")
                with open(path, 'w') as f:
                    f.write(self.to_markdown(report))
                saved.append(path)

        if format in ('json', 'all'):
            for report in self.reports:
                path = os.path.join(output_dir, f"{report.id}.json")
                with open(path, 'w') as f:
                    json.dump(self.to_json(report), f, indent=2)
                saved.append(path)

        if format in ('sarif', 'all'):
            path = os.path.join(output_dir, "forge_results.sarif")
            with open(path, 'w') as f:
                json.dump(self.to_sarif(), f, indent=2)
            saved.append(path)

        return saved

    def format_summary(self) -> str:
        """Format executive summary of all reports."""
        if not self.reports:
            return "  No vulnerability reports generated."

        # Count by severity
        by_sev = {}
        for r in self.reports:
            by_sev[r.severity] = by_sev.get(r.severity, 0) + 1

        lines = [
            f"VULNERABILITY REPORT SUMMARY",
            f"{'=' * 50}",
            f"  Total findings: {len(self.reports)}",
            f"  Analyst: {self.analyst}",
            f"",
        ]

        for sev in ['Critical', 'High', 'Medium', 'Low', 'None']:
            count = by_sev.get(sev, 0)
            if count:
                lines.append(f"  {sev:12s} {count}")

        lines.append(f"")
        lines.append(f"  {'ID':<25s} {'CVSS':>5s} {'Severity':<10s} Title")
        lines.append(f"  {'-' * 70}")
        for r in sorted(self.reports, key=lambda x: -x.cvss.get('score', 0)):
            lines.append(
                f"  {r.id:<25s} {r.cvss['score']:>5.1f} {r.severity:<10s} {r.title[:40]}"
            )

        return '\n'.join(lines)

    def stats(self) -> dict:
        return {
            'total_reports': len(self.reports),
            'by_severity': {
                sev: sum(1 for r in self.reports if r.severity == sev)
                for sev in ['Critical', 'High', 'Medium', 'Low']
            },
            'avg_cvss': round(
                sum(r.cvss.get('score', 0) for r in self.reports) / max(len(self.reports), 1), 1
            ),
        }
