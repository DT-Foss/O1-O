"""
Security Analyzer — Architecture-aware security analysis for generated code

Combines taint analysis (P1-02), AST analysis (P1-03), and knowledge engine
to provide three layers of security analysis:

1. Architecture Understanding: Identifies security boundaries, validation layers,
   and component roles (what validates what).
2. Reachability Analysis: Traces whether untrusted input can reach dangerous sinks
   through the actual control flow graph (not just pattern matching).
3. Impact Assessment: Scores findings by context (privileges, exposure, data access).
"""
# Dependencies: ast_engine, taint_analyzer, vuln_patterns
# Depended by: forge.py (/harden CLI command)


import ast
import re
from typing import List, Dict, Any, Optional, Set, Tuple

from o1o_o.core.taint_analyzer import TaintAnalyzer, TaintFinding, SOURCE_PATTERNS, SINK_PATTERNS, SANITIZER_PATTERNS
from o1o_o.core.ast_engine import ASTEngine
from o1o_o.core.vuln_patterns import VulnPatternEngine


# Security architecture component roles
COMPONENT_ROLES = {
    'validator': {
        'patterns': [
            r'\bvalidate\w*\s*\(', r'\bcheck\w*\s*\(', r'\bverify\w*\s*\(',
            r'\bassert\b', r'\bisinstance\s*\(', r'\bre\.(match|fullmatch)\b',
            r'\bschema\.validate\b', r'\bpydantic\b', r'\bmarshmallow\b',
        ],
        'description': 'Input validation / schema enforcement',
    },
    'authenticator': {
        'patterns': [
            r'\bauthenticat\w*', r'\blogin\b', r'\bpassword\b', r'\btoken\b',
            r'\bjwt\b', r'\boauth\b', r'\bsession\b', r'\bcredential\b',
            r'\b(login|auth)_required\b', r'\bFlask-Login\b',
        ],
        'description': 'Authentication / identity verification',
    },
    'authorizer': {
        'patterns': [
            r'\bauthoriz\w*', r'\bpermission\b', r'\brole\b', r'\baccess_control\b',
            r'\brbac\b', r'\bacl\b', r'\bcan_access\b', r'\bis_admin\b',
        ],
        'description': 'Authorization / access control',
    },
    'sanitizer': {
        'patterns': [
            r'\bsanitize\w*', r'\bescape\w*', r'\bclean\w*', r'\bfilter\w*',
            r'\bbleach\b', r'\bhtml\.escape\b', r'\bshlex\.quote\b',
            r'\bparameterize\w*', r'\bprepared_statement\b',
        ],
        'description': 'Output sanitization / encoding',
    },
    'rate_limiter': {
        'patterns': [
            r'\brate.?limit\w*', r'\bthrottle\w*', r'\bbackoff\b',
            r'\bFlask-Limiter\b', r'\bslowapi\b',
        ],
        'description': 'Rate limiting / DoS prevention',
    },
    'encryptor': {
        'patterns': [
            r'\bencrypt\w*', r'\bdecrypt\w*', r'\bcipher\b', r'\baes\b',
            r'\bcryptography\b', r'\bhashlib\b', r'\bbcrypt\b', r'\bscrypt\b',
            r'\bfernet\b', r'\bhmac\b',
        ],
        'description': 'Encryption / hashing',
    },
    'logger': {
        'patterns': [
            r'\blog(ging)?\.\w+\(', r'\baudit\w*\(', r'\bsyslog\b',
            r'\bwatchdog\b',
        ],
        'description': 'Security logging / audit trail',
    },
}

# Network exposure indicators
NETWORK_EXPOSURE = [
    r'\bFlask\b', r'\bDjango\b', r'\bFastAPI\b', r'\baiohttp\b',
    r'\btornado\b', r'\bbottle\b', r'\bsocket\.socket\b',
    r'\b0\.0\.0\.0\b', r'\blisten\b', r'\bbind\b', r'\bserve\b',
    r'\bapp\.run\b', r'\buvicorn\b', r'\bgunicorn\b',
    r'\b@app\.route\b', r'\b@router\.\w+\b',
]

# Privilege indicators
PRIVILEGE_INDICATORS = {
    'root': [r'\bsudo\b', r'\bos\.setuid\(0\)', r'\broot\b', r'\b/etc/shadow\b'],
    'system': [r'\bsubprocess\b', r'\bos\.system\b', r'\bos\.exec\w+\b', r'\bctypes\b'],
    'file': [r'\bopen\s*\(', r'\bos\.chmod\b', r'\bos\.remove\b', r'\bshutil\b'],
    'network': [r'\bsocket\b', r'\brequests\b', r'\burllib\b', r'\bhttp\b'],
    'database': [r'\bsqlite3\b', r'\bpsycopg\b', r'\bmysql\b', r'\bsqlalchemy\b'],
}


class SecurityFinding:
    """An enriched security finding with architecture context."""

    def __init__(self, taint: TaintFinding, reachable: bool = True,
                 architecture_context: str = '', impact_score: float = 0.0,
                 cvss_vector: str = '', mitigations: List[str] = None):
        self.taint = taint
        self.reachable = reachable
        self.architecture_context = architecture_context
        self.impact_score = impact_score
        self.cvss_vector = cvss_vector
        self.mitigations = mitigations or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.taint.to_dict(),
            'reachable': self.reachable,
            'architecture_context': self.architecture_context,
            'impact_score': round(self.impact_score, 1),
            'cvss_vector': self.cvss_vector,
            'mitigations': self.mitigations,
        }

    def __repr__(self):
        reach = 'REACHABLE' if self.reachable else 'UNREACHABLE'
        return (f"[{self.taint.severity} | {self.impact_score:.1f}] "
                f"{self.taint.source}→{self.taint.sink} "
                f"({self.taint.flow_type}) [{reach}]")


class SecurityAnalyzer:
    """Architecture-aware security analysis combining taint + AST + knowledge."""

    def __init__(self, knowledge_engine=None):
        self.knowledge = knowledge_engine
        self.taint_analyzer = TaintAnalyzer(knowledge_engine)
        self.ast_engine = ASTEngine()
        self.vuln_engine = VulnPatternEngine()

    def full_analysis(self, code: str) -> Dict[str, Any]:
        """Run complete security analysis: architecture + reachability + impact.

        Returns {architecture, findings, summary, recommendations}.
        """
        # Layer 1: Architecture Understanding
        architecture = self.analyze_architecture(code)

        # Layer 2: Taint + Reachability
        taint_findings = self.taint_analyzer.analyze(code)
        cfg = self.ast_engine.build_cfg(code)
        enriched = []

        for finding in taint_findings:
            # Check reachability through CFG
            reachable = self._check_reachability(cfg, finding.line_source, finding.line_sink)

            # Determine architecture context
            context = self._get_architecture_context(architecture, finding)

            # Layer 3: Impact Assessment
            impact = self._assess_impact(code, finding, architecture, reachable)

            enriched.append(SecurityFinding(
                taint=finding,
                reachable=reachable,
                architecture_context=context,
                impact_score=impact['score'],
                cvss_vector=impact['cvss_vector'],
                mitigations=impact['mitigations'],
            ))

        # Layer 4: Advanced vulnerability pattern detection
        vuln_findings = self.vuln_engine.analyze(code)

        # Generate recommendations
        recommendations = self._generate_recommendations(enriched, architecture)

        return {
            'architecture': architecture,
            'findings': [f.to_dict() for f in enriched],
            'vuln_patterns': [vf.to_dict() for vf in vuln_findings],
            'summary': self._summarize(enriched),
            'recommendations': recommendations,
        }

    def analyze_architecture(self, code: str) -> Dict[str, Any]:
        """Layer 1: Identify security architecture components and their roles."""
        lines = code.split('\n')
        components = {}  # role → [{line, code, function}]

        # Detect component roles
        for role, info in COMPONENT_ROLES.items():
            hits = []
            for i, line in enumerate(lines, 1):
                for pat in info['patterns']:
                    if re.search(pat, line, re.IGNORECASE):
                        # Find enclosing function
                        func = self._find_enclosing_function(code, i)
                        hits.append({
                            'line': i,
                            'code': line.strip()[:80],
                            'function': func,
                        })
                        break
            if hits:
                components[role] = {
                    'description': info['description'],
                    'instances': hits,
                }

        # Detect network exposure
        is_exposed = any(
            re.search(pat, code, re.IGNORECASE) for pat in NETWORK_EXPOSURE
        )

        # Detect privilege level
        privileges = set()
        for priv, patterns in PRIVILEGE_INDICATORS.items():
            for pat in patterns:
                if re.search(pat, code):
                    privileges.add(priv)
                    break

        # Security boundary analysis: what protects what?
        boundaries = self._detect_boundaries(code, components)

        return {
            'components': components,
            'network_exposed': is_exposed,
            'privileges': sorted(privileges),
            'boundaries': boundaries,
            'has_validation': 'validator' in components,
            'has_auth': 'authenticator' in components or 'authorizer' in components,
            'has_sanitization': 'sanitizer' in components,
            'has_rate_limiting': 'rate_limiter' in components,
            'has_encryption': 'encryptor' in components,
            'has_logging': 'logger' in components,
        }

    def _detect_boundaries(self, code: str, components: Dict) -> List[Dict[str, Any]]:
        """Detect security boundaries: validator/sanitizer protects which sinks."""
        boundaries = []

        # Find validation functions and what they're called before
        tree = self.ast_engine.parse(code)
        if not tree:
            return boundaries

        # Simple heuristic: if a validation/sanitizer call appears before a
        # dangerous operation in the same function, it's a boundary
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                validators_in_func = []
                dangerous_in_func = []

                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        name = self.ast_engine._call_name(child)
                        if name:
                            # Check if it's a validator
                            for role in ('validator', 'sanitizer'):
                                if role in components:
                                    for inst in components[role]['instances']:
                                        if inst['function'] == node.name:
                                            validators_in_func.append({
                                                'name': name,
                                                'line': child.lineno,
                                            })
                            # Check if it's a dangerous sink
                            for sink, patterns in SINK_PATTERNS.items():
                                for pat in patterns:
                                    if re.search(pat, name):
                                        dangerous_in_func.append({
                                            'name': name,
                                            'sink': sink,
                                            'line': child.lineno,
                                        })

                for v in validators_in_func:
                    for d in dangerous_in_func:
                        if v['line'] < d['line']:
                            boundaries.append({
                                'protector': v['name'],
                                'protects': d['sink'],
                                'function': node.name,
                                'validator_line': v['line'],
                                'sink_line': d['line'],
                            })

        return boundaries

    def _check_reachability(self, cfg: Dict, src_line: int, sink_line: int) -> bool:
        """Check if there's a path from source line to sink line in the CFG."""
        if not cfg['nodes'] or not cfg['edges']:
            return True  # Assume reachable if no CFG

        # Find nodes containing source and sink lines
        src_nodes = [n['id'] for n in cfg['nodes'] if n['line'] == src_line]
        sink_nodes = [n['id'] for n in cfg['nodes'] if n['line'] == sink_line]

        if not src_nodes or not sink_nodes:
            # Lines not in CFG — fall back to line ordering
            return src_line < sink_line

        # BFS from any source node to any sink node
        adjacency = {}
        for edge in cfg['edges']:
            adjacency.setdefault(edge['from'], []).append(edge['to'])

        visited: Set[int] = set()
        queue = list(src_nodes)

        while queue:
            current = queue.pop(0)
            if current in sink_nodes:
                return True
            if current in visited:
                continue
            visited.add(current)
            for neighbor in adjacency.get(current, []):
                if neighbor not in visited:
                    queue.append(neighbor)

        return False

    def _get_architecture_context(self, architecture: Dict, finding: TaintFinding) -> str:
        """Determine the architecture context of a finding."""
        parts = []

        # Check if finding is inside a protected boundary
        for boundary in architecture.get('boundaries', []):
            if boundary['sink_line'] == finding.line_sink:
                parts.append(f'protected by {boundary["protector"]} (L{boundary["validator_line"]})')

        if not parts:
            if finding.sanitized:
                parts.append(f'sanitized by {finding.sanitizer}')
            elif architecture.get('has_validation'):
                parts.append('validation exists but may not cover this path')
            else:
                parts.append('no validation layer detected')

        if architecture.get('network_exposed'):
            parts.append('network-exposed service')

        return '; '.join(parts)

    def _assess_impact(self, code: str, finding: TaintFinding,
                       architecture: Dict, reachable: bool) -> Dict[str, Any]:
        """Layer 3: Score the impact of a finding (0.0 - 10.0 CVSS-like)."""
        base_scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.0,
            'MEDIUM': 5.0,
            'LOW': 3.0,
            'INFO': 1.0,
        }
        score = base_scores.get(finding.severity, 5.0)

        # Modifiers
        if not reachable:
            score *= 0.3  # Unreachable = much lower impact
        if finding.sanitized:
            score *= 0.4  # Sanitized = much lower
        if architecture.get('network_exposed'):
            score = min(10.0, score * 1.3)  # Network exposure amplifies
        if 'root' in architecture.get('privileges', []):
            score = min(10.0, score * 1.2)  # Root amplifies
        if not architecture.get('has_auth'):
            score = min(10.0, score * 1.1)  # No auth = worse
        if architecture.get('has_rate_limiting'):
            score *= 0.9  # Rate limiting helps

        # CVSS-like vector
        av = 'N' if architecture.get('network_exposed') else 'L'
        ac = 'L' if reachable else 'H'
        pr = 'N' if not architecture.get('has_auth') else 'L'
        ui = 'N'
        ci = 'H' if finding.severity in ('CRITICAL', 'HIGH') else 'L'
        cvss = f'AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/C:{ci}/I:{ci}/A:{ci}'

        # Mitigations
        mitigations = []
        if not finding.sanitized:
            if finding.flow_type in ('injection_risk', 'code_injection'):
                mitigations.append('Use parameterized queries / prepared statements')
            if finding.flow_type == 'command_injection':
                mitigations.append('Use shlex.quote() or subprocess with list args')
            if finding.flow_type == 'xss':
                mitigations.append('Use html.escape() or template auto-escaping')
            if finding.flow_type == 'deserialization':
                mitigations.append('Use json instead of pickle/yaml.load; use yaml.safe_load')
            if finding.flow_type == 'path_traversal':
                mitigations.append('Use os.path.basename() or pathlib to restrict paths')
        if not architecture.get('has_validation'):
            mitigations.append('Add input validation layer')
        if architecture.get('network_exposed') and not architecture.get('has_rate_limiting'):
            mitigations.append('Add rate limiting for network-exposed endpoints')
        if not architecture.get('has_logging'):
            mitigations.append('Add security event logging')

        return {
            'score': round(score, 1),
            'cvss_vector': cvss,
            'mitigations': mitigations,
        }

    def _find_enclosing_function(self, code: str, line_num: int) -> str:
        """Find the function that encloses a given line number."""
        tree = self.ast_engine.parse(code)
        if not tree:
            return '<module>'

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                end_line = node.end_lineno or node.lineno
                if node.lineno <= line_num <= end_line:
                    return node.name
        return '<module>'

    def _generate_recommendations(self, findings: List[SecurityFinding],
                                   architecture: Dict) -> List[str]:
        """Generate prioritized security recommendations."""
        recs = []

        # Critical/reachable findings first
        critical_reachable = [f for f in findings if f.reachable and not f.taint.sanitized
                              and f.taint.severity in ('CRITICAL', 'HIGH')]
        if critical_reachable:
            recs.append(f'FIX IMMEDIATELY: {len(critical_reachable)} critical/high reachable vulnerability(s)')

        # Architecture gaps
        if not architecture.get('has_validation'):
            recs.append('Add input validation at all entry points')
        if not architecture.get('has_auth') and architecture.get('network_exposed'):
            recs.append('Add authentication for network-exposed endpoints')
        if not architecture.get('has_sanitization') and any(
                f.taint.flow_type in ('xss', 'stored_xss') for f in findings):
            recs.append('Add output sanitization (html.escape / template auto-escaping)')
        if not architecture.get('has_logging'):
            recs.append('Add security event logging for audit trail')
        if architecture.get('network_exposed') and not architecture.get('has_rate_limiting'):
            recs.append('Add rate limiting to prevent abuse')

        return recs

    def _summarize(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Summarize findings."""
        total = len(findings)
        reachable = sum(1 for f in findings if f.reachable and not f.taint.sanitized)
        sanitized = sum(1 for f in findings if f.taint.sanitized)
        unreachable = sum(1 for f in findings if not f.reachable)
        max_impact = max((f.impact_score for f in findings), default=0.0)

        by_severity = {}
        for f in findings:
            if f.reachable and not f.taint.sanitized:
                sev = f.taint.severity
                by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            'total_findings': total,
            'reachable_vulnerable': reachable,
            'sanitized': sanitized,
            'unreachable': unreachable,
            'max_impact_score': round(max_impact, 1),
            'by_severity': by_severity,
        }
