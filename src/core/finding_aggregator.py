"""Finding Aggregator: SQLite database for all security findings.

Stores crashes, exploit primitives, exploitability scores with
deduplication by crash hash. Supports querying by primitive type,
target, severity, and timeline. Links findings to targets and CVEs.

Part of FORGE Phase N: Autonomous Hunt Loop.
"""
# Dependencies: none
# Depended by: hunt_loop

import json
import os
import time
import hashlib
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict


# ─── Finding Data Model ─────────────────────────────────────────────

@dataclass
class Finding:
    """A security finding: crash, vulnerability, or exploit primitive."""
    id: str = ''                    # Auto-generated hash
    crash_hash: str = ''            # Dedup key (stack trace hash)
    target_id: str = ''             # Link to target_queue
    target_name: str = ''
    target_path: str = ''

    # Classification
    primitive_type: str = 'unknown' # dos, info_leak, write, execute
    severity: str = 'medium'        # critical, high, medium, low, info
    confidence: float = 0.0         # 0.0 - 1.0
    exploitability: str = 'unknown' # trivial, moderate, hard, impractical

    # Details
    title: str = ''                 # Short description
    description: str = ''           # Full analysis
    signal: str = ''                # SIGSEGV, SIGABRT, etc.
    fault_address: int = 0
    faulting_function: str = ''
    stack_trace: str = ''           # First 10 frames
    register_state: str = ''        # Key registers at crash

    # Context
    platform: str = ''              # macos, linux, windows
    arch: str = ''                  # x86_64, arm64
    cve_id: str = ''                # Linked CVE if known
    cwe_id: str = ''                # CWE classification

    # Metadata
    found_at: float = 0.0           # Unix timestamp
    found_by: str = ''              # fuzzer, crash_analyzer, manual
    input_file: str = ''            # Triggering input path
    crash_log: str = ''             # Path to original crash log
    attempts: int = 0               # Reproduction attempts
    reproduced: bool = False
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.found_at:
            self.found_at = time.time()
        if not self.id:
            self.id = hashlib.sha256(
                f"{self.crash_hash}:{self.target_id}:{self.title}:{self.found_at}".encode()
            ).hexdigest()[:16]
        if not self.crash_hash and self.stack_trace:
            self.crash_hash = hashlib.sha256(
                self.stack_trace.encode()
            ).hexdigest()[:16]


# ─── Severity Scoring ───────────────────────────────────────────────

PRIMITIVE_SEVERITY = {
    'execute': 'critical',
    'write': 'high',
    'info_leak': 'medium',
    'dos': 'low',
    'unknown': 'info',
}

EXPLOITABILITY_SCORE = {
    'trivial': 1.0,
    'moderate': 0.7,
    'hard': 0.4,
    'impractical': 0.1,
    'unknown': 0.5,
}


def compute_priority(finding: Finding) -> float:
    """Compute finding priority 0-100 for triage ordering."""
    score = 0.0

    # Primitive type weight (0-40)
    prim_weights = {'execute': 40, 'write': 30, 'info_leak': 20, 'dos': 10}
    score += prim_weights.get(finding.primitive_type, 5)

    # Confidence (0-20)
    score += finding.confidence * 20

    # Exploitability (0-20)
    score += EXPLOITABILITY_SCORE.get(finding.exploitability, 0.5) * 20

    # Severity bonus (0-10)
    sev_bonus = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 0}
    score += sev_bonus.get(finding.severity, 0)

    # CVE link bonus (0-10)
    if finding.cve_id:
        score += 10

    return min(100.0, round(score, 2))


# ─── Finding Aggregator DB ──────────────────────────────────────────

class FindingAggregator:
    """SQLite-backed finding database with dedup and querying.

    Supports:
    - Deduplication by crash_hash
    - Priority-ranked retrieval
    - Query by primitive type, severity, target, platform
    - Timeline view of discoveries
    - Statistics and trend analysis
    - CVE linking
    """

    def __init__(self, db_path: str = 'knowledge/findings.db'):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else '.', exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                crash_hash TEXT,
                target_id TEXT,
                target_name TEXT,
                target_path TEXT,
                primitive_type TEXT DEFAULT 'unknown',
                severity TEXT DEFAULT 'medium',
                confidence REAL DEFAULT 0.0,
                exploitability TEXT DEFAULT 'unknown',
                title TEXT,
                description TEXT,
                signal TEXT,
                fault_address INTEGER DEFAULT 0,
                faulting_function TEXT,
                stack_trace TEXT,
                register_state TEXT,
                platform TEXT,
                arch TEXT,
                cve_id TEXT,
                cwe_id TEXT,
                priority REAL DEFAULT 0.0,
                found_at REAL,
                found_by TEXT,
                input_file TEXT,
                crash_log TEXT,
                attempts INTEGER DEFAULT 0,
                reproduced INTEGER DEFAULT 0,
                tags TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}'
            )''')

            conn.execute('''CREATE INDEX IF NOT EXISTS idx_crash_hash
                ON findings(crash_hash)''')
            conn.execute('''CREATE INDEX IF NOT EXISTS idx_primitive
                ON findings(primitive_type)''')
            conn.execute('''CREATE INDEX IF NOT EXISTS idx_severity
                ON findings(severity)''')
            conn.execute('''CREATE INDEX IF NOT EXISTS idx_target
                ON findings(target_id)''')
            conn.execute('''CREATE INDEX IF NOT EXISTS idx_priority
                ON findings(priority DESC)''')
            conn.execute('''CREATE INDEX IF NOT EXISTS idx_found_at
                ON findings(found_at DESC)''')

    def _finding_to_row(self, f: Finding) -> tuple:
        return (f.id, f.crash_hash, f.target_id, f.target_name, f.target_path,
                f.primitive_type, f.severity, f.confidence, f.exploitability,
                f.title, f.description, f.signal, f.fault_address,
                f.faulting_function, f.stack_trace, f.register_state,
                f.platform, f.arch, f.cve_id, f.cwe_id,
                compute_priority(f), f.found_at, f.found_by, f.input_file,
                f.crash_log, f.attempts, int(f.reproduced),
                json.dumps(f.tags), json.dumps(f.metadata))

    def _row_to_finding(self, row) -> Finding:
        return Finding(
            id=row[0], crash_hash=row[1], target_id=row[2],
            target_name=row[3], target_path=row[4],
            primitive_type=row[5], severity=row[6], confidence=row[7],
            exploitability=row[8], title=row[9], description=row[10],
            signal=row[11], fault_address=row[12],
            faulting_function=row[13], stack_trace=row[14],
            register_state=row[15], platform=row[16], arch=row[17],
            cve_id=row[18], cwe_id=row[19], found_at=row[21],
            found_by=row[22], input_file=row[23], crash_log=row[24],
            attempts=row[25], reproduced=bool(row[26]),
            tags=json.loads(row[27]), metadata=json.loads(row[28])
        )

    # ─── CRUD ────────────────────────────────────────────────────

    def add(self, finding: Finding) -> Tuple[bool, str]:
        """Add finding. Returns (is_new, id). Deduplicates by crash_hash."""
        # Check for duplicate
        if finding.crash_hash:
            with sqlite3.connect(self.db_path) as conn:
                existing = conn.execute(
                    "SELECT id FROM findings WHERE crash_hash = ?",
                    (finding.crash_hash,)
                ).fetchone()
                if existing:
                    # Update attempts count on dupe
                    conn.execute(
                        "UPDATE findings SET attempts = attempts + 1 WHERE id = ?",
                        (existing[0],))
                    return False, existing[0]

        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''INSERT INTO findings VALUES
                (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                self._finding_to_row(finding))
        return True, finding.id

    def add_batch(self, findings: List[Finding]) -> Tuple[int, int]:
        """Add multiple findings. Returns (new, duplicate) counts."""
        new_count = 0
        dup_count = 0
        for f in findings:
            is_new, _ = self.add(f)
            if is_new:
                new_count += 1
            else:
                dup_count += 1
        return new_count, dup_count

    def get(self, finding_id: str) -> Optional[Finding]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            return self._row_to_finding(row) if row else None

    def update(self, finding_id: str, **kwargs):
        """Update specific fields of a finding."""
        allowed = {'severity', 'confidence', 'exploitability', 'title',
                   'description', 'cve_id', 'cwe_id', 'reproduced',
                   'attempts', 'tags', 'metadata'}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return

        with sqlite3.connect(self.db_path) as conn:
            for k, v in updates.items():
                if k in ('tags', 'metadata'):
                    v = json.dumps(v)
                elif k == 'reproduced':
                    v = int(v)
                conn.execute(f"UPDATE findings SET {k} = ? WHERE id = ?",
                             (v, finding_id))

    def delete(self, finding_id: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))

    # ─── Query Interface ─────────────────────────────────────────

    def query(self, primitive_type: Optional[str] = None,
              severity: Optional[str] = None,
              target_id: Optional[str] = None,
              platform: Optional[str] = None,
              cve_id: Optional[str] = None,
              min_confidence: float = 0.0,
              limit: int = 50) -> List[Finding]:
        """Flexible query with filters."""
        conditions = []
        params = []

        if primitive_type:
            conditions.append("primitive_type = ?")
            params.append(primitive_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if target_id:
            conditions.append("target_id = ?")
            params.append(target_id)
        if platform:
            conditions.append("platform = ?")
            params.append(platform)
        if cve_id:
            conditions.append("cve_id = ?")
            params.append(cve_id)
        if min_confidence > 0:
            conditions.append("confidence >= ?")
            params.append(min_confidence)

        where = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                f"SELECT * FROM findings WHERE {where} ORDER BY priority DESC LIMIT ?",
                params
            ).fetchall()
            return [self._row_to_finding(r) for r in rows]

    def search(self, text: str, limit: int = 20) -> List[Finding]:
        """Full-text search across title, description, function, stack."""
        pattern = f"%{text}%"
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                '''SELECT * FROM findings WHERE
                   title LIKE ? OR description LIKE ? OR
                   faulting_function LIKE ? OR stack_trace LIKE ?
                   ORDER BY priority DESC LIMIT ?''',
                (pattern, pattern, pattern, pattern, limit)
            ).fetchall()
            return [self._row_to_finding(r) for r in rows]

    def by_target(self, target_name: str, limit: int = 20) -> List[Finding]:
        """Get findings for a specific target."""
        pattern = f"%{target_name}%"
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                '''SELECT * FROM findings WHERE target_name LIKE ?
                   ORDER BY priority DESC LIMIT ?''',
                (pattern, limit)
            ).fetchall()
            return [self._row_to_finding(r) for r in rows]

    def timeline(self, hours: int = 24, limit: int = 50) -> List[Finding]:
        """Get findings from the last N hours, newest first."""
        cutoff = time.time() - (hours * 3600)
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                '''SELECT * FROM findings WHERE found_at >= ?
                   ORDER BY found_at DESC LIMIT ?''',
                (cutoff, limit)
            ).fetchall()
            return [self._row_to_finding(r) for r in rows]

    def top_findings(self, limit: int = 10) -> List[Finding]:
        """Top findings by priority score."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM findings ORDER BY priority DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return [self._row_to_finding(r) for r in rows]

    # ─── Statistics ──────────────────────────────────────────────

    def stats(self) -> dict:
        """Overall finding statistics."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            by_prim = dict(conn.execute(
                '''SELECT primitive_type, COUNT(*) FROM findings
                   GROUP BY primitive_type'''
            ).fetchall())
            by_sev = dict(conn.execute(
                '''SELECT severity, COUNT(*) FROM findings
                   GROUP BY severity'''
            ).fetchall())
            by_platform = dict(conn.execute(
                '''SELECT platform, COUNT(*) FROM findings
                   GROUP BY platform'''
            ).fetchall())
            unique_targets = conn.execute(
                "SELECT COUNT(DISTINCT target_id) FROM findings"
            ).fetchone()[0]
            with_cve = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE cve_id != ''"
            ).fetchone()[0]
            reproduced = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE reproduced = 1"
            ).fetchone()[0]
            avg_confidence = conn.execute(
                "SELECT AVG(confidence) FROM findings"
            ).fetchone()[0] or 0

            return {
                'total': total,
                'by_primitive': by_prim,
                'by_severity': by_sev,
                'by_platform': by_platform,
                'unique_targets': unique_targets,
                'with_cve': with_cve,
                'reproduced': reproduced,
                'avg_confidence': round(avg_confidence, 2),
            }

    # ─── Import from Crash Analyzer ──────────────────────────────

    def import_from_crash_analysis(self, analysis: dict,
                                    target_name: str = '',
                                    target_id: str = '') -> Tuple[bool, str]:
        """Import a crash analysis result from CrashAnalyzer."""
        finding = Finding(
            target_name=target_name or analysis.get('process', ''),
            target_id=target_id,
            primitive_type=analysis.get('primitive', {}).get('type', 'unknown'),
            severity=PRIMITIVE_SEVERITY.get(
                analysis.get('primitive', {}).get('type', ''), 'info'),
            confidence=analysis.get('primitive', {}).get('confidence', 0.0),
            exploitability=analysis.get('primitive', {}).get('exploitation_difficulty', 'unknown'),
            title=f"{analysis.get('signal', 'crash')} in {analysis.get('process', 'unknown')}",
            signal=analysis.get('signal', ''),
            fault_address=analysis.get('fault_address', 0),
            faulting_function=analysis.get('faulting_frame', {}).get('symbol', ''),
            stack_trace='\n'.join(
                f.get('symbol', '') for f in analysis.get('crashed_thread_frames', [])[:10]
            ),
            platform=analysis.get('platform', ''),
            arch=analysis.get('arch', ''),
            found_by='crash_analyzer',
            crash_log=analysis.get('source_file', ''),
        )

        # Generate crash hash from faulting function + fault address
        if not finding.crash_hash:
            hash_input = f"{finding.faulting_function}:{finding.fault_address}"
            finding.crash_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        return self.add(finding)

    # ─── Display ─────────────────────────────────────────────────

    def format_findings(self, findings: List[Finding], verbose: bool = False) -> str:
        """Format findings as table string."""
        if not findings:
            return "  No findings"

        lines = [
            f"{'PRI':>5}  {'SEV':<9} {'PRIM':<10} {'TARGET':<20} "
            f"{'FUNCTION':<25} {'CONF':<5} {'FOUND'}",
            '-' * 95,
        ]

        for f in findings:
            import datetime
            found = datetime.datetime.fromtimestamp(f.found_at).strftime('%m/%d %H:%M')
            func = f.faulting_function[:24] if f.faulting_function else '-'
            lines.append(
                f"{compute_priority(f):5.1f}  {f.severity:<9} {f.primitive_type:<10} "
                f"{f.target_name[:19]:<20} {func:<25} "
                f"{f.confidence:<5.1%} {found}"
            )

            if verbose and f.title:
                lines.append(f"       {f.title}")
            if verbose and f.cve_id:
                lines.append(f"       CVE: {f.cve_id}")

        return '\n'.join(lines)

    def format_stats(self) -> str:
        """Format statistics as string."""
        s = self.stats()
        lines = [
            f"FINDING AGGREGATOR — {s['total']} findings, "
            f"{s['unique_targets']} targets, "
            f"{s['reproduced']} reproduced",
            f"",
        ]

        if s['by_primitive']:
            lines.append("  By Primitive:")
            for prim, count in sorted(s['by_primitive'].items(),
                                       key=lambda x: -x[1]):
                lines.append(f"    {prim:<12} {count:>4}")

        if s['by_severity']:
            lines.append("  By Severity:")
            for sev, count in sorted(s['by_severity'].items(),
                                      key=lambda x: -x[1]):
                lines.append(f"    {sev:<12} {count:>4}")

        if s['with_cve']:
            lines.append(f"  CVE-linked: {s['with_cve']}")

        lines.append(f"  Avg Confidence: {s['avg_confidence']:.0%}")

        return '\n'.join(lines)
