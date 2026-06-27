"""Target Queue Manager: Autonomous target prioritization for FORGE.

Scores targets by attack surface (entrypoints, privilege level, network
exposure, historical CVE density). Maintains a priority queue with
auto-rotation and deduplication.

Part of FORGE Phase N: Autonomous Hunt Loop.
"""
# Dependencies: platform_adapter
# Depended by: hunt_loop

import json
import os
import time
import hashlib
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field, asdict


# ─── Target Data Model ──────────────────────────────────────────────

@dataclass
class Target:
    """A binary, service, or component to analyze/fuzz."""
    id: str = ''                  # SHA256-based unique ID
    name: str = ''                # Human-readable name
    path: str = ''                # File path or service endpoint
    target_type: str = 'binary'   # binary, service, library, driver, protocol
    platform: str = 'unknown'     # linux, windows, macos, ios, android
    arch: str = ''                # x86_64, arm64, etc.

    # Attack surface metrics (0.0-1.0 each)
    privilege_level: float = 0.0  # 0=user, 0.5=suid, 1.0=root/kernel
    network_exposure: float = 0.0 # 0=local-only, 0.5=LAN, 1.0=internet-facing
    entrypoints: int = 0          # Number of entry points (functions, handlers, etc.)
    input_complexity: float = 0.5 # 0=trivial, 1.0=complex parser (more bugs)
    cve_density: float = 0.0      # Historical CVE count per KLOC equivalent
    attack_surface_area: float = 0.0  # Combined metric

    # Security posture (from platform_adapter)
    security_score: int = 0       # 0-100 from BinaryInfo.security_score()
    has_nx: bool = True
    has_aslr: bool = True
    has_canary: bool = True
    has_cfg: bool = False

    # Queue management
    priority: float = 0.0         # Computed priority score (0-100)
    status: str = 'queued'        # queued, active, completed, skipped, failed
    attempts: int = 0             # Number of analysis/fuzz attempts
    last_attempt: float = 0.0     # Unix timestamp
    findings_count: int = 0       # Crashes/bugs found so far
    added_at: float = 0.0
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = hashlib.sha256(
                f"{self.name}:{self.path}:{self.target_type}".encode()
            ).hexdigest()[:16]
        if not self.added_at:
            self.added_at = time.time()


# ─── Priority Scoring Engine ────────────────────────────────────────

class PriorityScorer:
    """Scores targets to determine analysis order.

    Higher score = should be analyzed first.
    Factors:
    1. Attack surface: more entrypoints + complex input = more bugs
    2. Privilege level: root/kernel bugs are higher value
    3. Network exposure: internet-facing = higher risk
    4. CVE density: historically buggy software deserves attention
    5. Weak security posture: missing NX/ASLR = easier exploitation
    6. Diminishing returns: fewer attempts so far = higher priority
    """

    # Weights for each factor
    WEIGHTS = {
        'privilege':    20.0,  # Root/kernel targets score highest
        'network':      15.0,  # Internet-facing = priority
        'surface':      15.0,  # More entrypoints = more bugs
        'complexity':   10.0,  # Complex parsers = more vulns
        'cve_history':  10.0,  # History predicts future
        'weak_posture': 15.0,  # Missing mitigations = easier exploit
        'freshness':    15.0,  # Untested targets get priority
    }

    @classmethod
    def score(cls, target: Target) -> float:
        """Compute priority score 0-100."""
        s = 0.0

        # 1. Privilege level (0-20)
        s += cls.WEIGHTS['privilege'] * target.privilege_level

        # 2. Network exposure (0-15)
        s += cls.WEIGHTS['network'] * target.network_exposure

        # 3. Attack surface area (0-15)
        if target.entrypoints > 0:
            # Log scale: 1 ep=0.1, 10 ep=0.5, 100 ep=0.8, 1000+=1.0
            import math
            ep_score = min(1.0, math.log10(max(1, target.entrypoints)) / 3.0)
            s += cls.WEIGHTS['surface'] * ep_score

        # 4. Input complexity (0-10)
        s += cls.WEIGHTS['complexity'] * target.input_complexity

        # 5. CVE density (0-10)
        s += cls.WEIGHTS['cve_history'] * min(1.0, target.cve_density)

        # 6. Weak security posture (0-15)
        weakness = 0.0
        if not target.has_nx: weakness += 0.3
        if not target.has_aslr: weakness += 0.3
        if not target.has_canary: weakness += 0.2
        if not target.has_cfg: weakness += 0.2
        s += cls.WEIGHTS['weak_posture'] * weakness

        # 7. Freshness — untested targets get boost (0-15)
        if target.attempts == 0:
            s += cls.WEIGHTS['freshness']
        else:
            # Diminishing returns: 1/sqrt(attempts)
            import math
            freshness = 1.0 / math.sqrt(target.attempts + 1)
            s += cls.WEIGHTS['freshness'] * freshness

        return min(100.0, round(s, 2))


# ─── Target Queue ───────────────────────────────────────────────────

class TargetQueue:
    """Priority queue for autonomous target analysis.

    Persists to SQLite. Supports:
    - Priority-ordered retrieval
    - Auto-rotation (re-score on each dequeue)
    - Deduplication by target ID
    - Status tracking (queued → active → completed/failed)
    - Batch import from directories
    """

    def __init__(self, db_path: str = 'knowledge/target_queue.db'):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else '.', exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize SQLite schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                path TEXT,
                target_type TEXT DEFAULT 'binary',
                platform TEXT DEFAULT 'unknown',
                arch TEXT DEFAULT '',
                privilege_level REAL DEFAULT 0.0,
                network_exposure REAL DEFAULT 0.0,
                entrypoints INTEGER DEFAULT 0,
                input_complexity REAL DEFAULT 0.5,
                cve_density REAL DEFAULT 0.0,
                attack_surface_area REAL DEFAULT 0.0,
                security_score INTEGER DEFAULT 0,
                has_nx INTEGER DEFAULT 1,
                has_aslr INTEGER DEFAULT 1,
                has_canary INTEGER DEFAULT 1,
                has_cfg INTEGER DEFAULT 0,
                priority REAL DEFAULT 0.0,
                status TEXT DEFAULT 'queued',
                attempts INTEGER DEFAULT 0,
                last_attempt REAL DEFAULT 0.0,
                findings_count INTEGER DEFAULT 0,
                added_at REAL,
                tags TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}'
            )''')

            conn.execute('''CREATE INDEX IF NOT EXISTS idx_priority
                ON targets(priority DESC) WHERE status = 'queued' ''')
            conn.execute('''CREATE INDEX IF NOT EXISTS idx_status
                ON targets(status)''')

    def _target_to_row(self, t: Target) -> tuple:
        return (t.id, t.name, t.path, t.target_type, t.platform, t.arch,
                t.privilege_level, t.network_exposure, t.entrypoints,
                t.input_complexity, t.cve_density, t.attack_surface_area,
                t.security_score, int(t.has_nx), int(t.has_aslr),
                int(t.has_canary), int(t.has_cfg), t.priority, t.status,
                t.attempts, t.last_attempt, t.findings_count, t.added_at,
                json.dumps(t.tags), json.dumps(t.metadata))

    def _row_to_target(self, row) -> Target:
        return Target(
            id=row[0], name=row[1], path=row[2], target_type=row[3],
            platform=row[4], arch=row[5], privilege_level=row[6],
            network_exposure=row[7], entrypoints=row[8],
            input_complexity=row[9], cve_density=row[10],
            attack_surface_area=row[11], security_score=row[12],
            has_nx=bool(row[13]), has_aslr=bool(row[14]),
            has_canary=bool(row[15]), has_cfg=bool(row[16]),
            priority=row[17], status=row[18], attempts=row[19],
            last_attempt=row[20], findings_count=row[21],
            added_at=row[22], tags=json.loads(row[23]),
            metadata=json.loads(row[24])
        )

    # ─── Queue Operations ────────────────────────────────────────

    def add(self, target: Target) -> bool:
        """Add target to queue. Returns False if duplicate."""
        target.priority = PriorityScorer.score(target)
        with sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute('''INSERT INTO targets VALUES
                    (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    self._target_to_row(target))
                return True
            except sqlite3.IntegrityError:
                return False  # Duplicate

    def add_batch(self, targets: List[Target]) -> int:
        """Add multiple targets. Returns count of new targets added."""
        added = 0
        for t in targets:
            if self.add(t):
                added += 1
        return added

    def next(self) -> Optional[Target]:
        """Get next highest-priority queued target. Marks it 'active'."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                '''SELECT * FROM targets WHERE status = 'queued'
                   ORDER BY priority DESC LIMIT 1'''
            ).fetchone()
            if not row:
                return None
            target = self._row_to_target(row)
            target.status = 'active'
            target.attempts += 1
            target.last_attempt = time.time()
            conn.execute(
                '''UPDATE targets SET status = 'active', attempts = ?,
                   last_attempt = ? WHERE id = ?''',
                (target.attempts, target.last_attempt, target.id))
            return target

    def complete(self, target_id: str, findings: int = 0):
        """Mark target as completed with finding count."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                '''UPDATE targets SET status = 'completed',
                   findings_count = findings_count + ? WHERE id = ?''',
                (findings, target_id))

    def fail(self, target_id: str, reason: str = ''):
        """Mark target as failed."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE targets SET status = 'failed' WHERE id = ?",
                (target_id,))

    def requeue(self, target_id: str):
        """Requeue a completed/failed target with updated priority."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM targets WHERE id = ?", (target_id,)
            ).fetchone()
            if row:
                target = self._row_to_target(row)
                target.status = 'queued'
                target.priority = PriorityScorer.score(target)
                conn.execute(
                    '''UPDATE targets SET status = 'queued', priority = ?
                       WHERE id = ?''', (target.priority, target.id))

    def requeue_all(self):
        """Re-score and requeue all non-active targets."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM targets WHERE status != 'active'"
            ).fetchall()
            for row in rows:
                t = self._row_to_target(row)
                t.priority = PriorityScorer.score(t)
                conn.execute(
                    '''UPDATE targets SET status = 'queued', priority = ?
                       WHERE id = ?''', (t.priority, t.id))

    # ─── Query Operations ────────────────────────────────────────

    def get(self, target_id: str) -> Optional[Target]:
        """Get target by ID."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM targets WHERE id = ?", (target_id,)
            ).fetchone()
            return self._row_to_target(row) if row else None

    def list_queued(self, limit: int = 20) -> List[Target]:
        """List queued targets by priority."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                '''SELECT * FROM targets WHERE status = 'queued'
                   ORDER BY priority DESC LIMIT ?''', (limit,)
            ).fetchall()
            return [self._row_to_target(r) for r in rows]

    def list_all(self, limit: int = 50) -> List[Target]:
        """List all targets."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                '''SELECT * FROM targets ORDER BY priority DESC LIMIT ?''',
                (limit,)
            ).fetchall()
            return [self._row_to_target(r) for r in rows]

    def stats(self) -> dict:
        """Queue statistics."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            queued = conn.execute(
                "SELECT COUNT(*) FROM targets WHERE status='queued'"
            ).fetchone()[0]
            active = conn.execute(
                "SELECT COUNT(*) FROM targets WHERE status='active'"
            ).fetchone()[0]
            completed = conn.execute(
                "SELECT COUNT(*) FROM targets WHERE status='completed'"
            ).fetchone()[0]
            failed = conn.execute(
                "SELECT COUNT(*) FROM targets WHERE status='failed'"
            ).fetchone()[0]
            findings = conn.execute(
                "SELECT SUM(findings_count) FROM targets"
            ).fetchone()[0] or 0
            avg_priority = conn.execute(
                "SELECT AVG(priority) FROM targets WHERE status='queued'"
            ).fetchone()[0] or 0

            return {
                'total': total,
                'queued': queued,
                'active': active,
                'completed': completed,
                'failed': failed,
                'total_findings': findings,
                'avg_priority': round(avg_priority, 1),
            }

    def clear(self, status: Optional[str] = None):
        """Remove targets. If status given, only remove those."""
        with sqlite3.connect(self.db_path) as conn:
            if status:
                conn.execute("DELETE FROM targets WHERE status = ?", (status,))
            else:
                conn.execute("DELETE FROM targets")

    # ─── Import from Binary Analysis ─────────────────────────────

    def import_from_binary(self, filepath: str, **overrides) -> Optional[Target]:
        """Import a binary file as a target, auto-filling from platform_adapter."""
        try:
            from o1o_o.core.platform_adapter import analyze as pa_analyze
        except ImportError:
            return None

        info = pa_analyze(filepath)
        if not info.format or info.format == 'unknown':
            return None

        # Map format to platform
        platform_map = {
            'pe': 'windows',
            'elf': 'linux',
            'macho': 'macos',
            'macho_fat': 'macos',
        }

        target = Target(
            name=os.path.basename(filepath),
            path=filepath,
            target_type='binary',
            platform=platform_map.get(info.format, 'unknown'),
            arch=info.arch,
            security_score=info.security_score(),
            has_nx=info.nx,
            has_aslr=info.aslr,
            has_canary=info.stack_canary,
            has_cfg=info.cfg,
            entrypoints=len(info.sections),  # Rough proxy
            input_complexity=0.7 if info.libraries else 0.3,
        )

        # Apply overrides
        for k, v in overrides.items():
            if hasattr(target, k):
                setattr(target, k, v)

        self.add(target)
        return target

    def import_directory(self, dirpath: str, **overrides) -> int:
        """Import all binaries from a directory."""
        try:
            from o1o_o.core.platform_adapter import detect_format, BinaryFormat
        except ImportError:
            return 0

        count = 0
        for root, dirs, files in os.walk(dirpath):
            for f in files:
                full = os.path.join(root, f)
                fmt = detect_format(full)
                if fmt != BinaryFormat.UNKNOWN:
                    if self.import_from_binary(full, **overrides):
                        count += 1
        return count

    # ─── Predefined Target Sets ──────────────────────────────────

    @staticmethod
    def macos_high_value() -> List[Target]:
        """Pre-built target list for macOS high-value targets."""
        targets = []

        # System daemons (root, network-exposed)
        daemons = [
            ('syspolicyd', '/usr/libexec/syspolicyd', 1.0, 0.0, 0.8),
            ('opendirectoryd', '/usr/libexec/opendirectoryd', 1.0, 0.5, 0.9),
            ('configd', '/usr/libexec/configd', 1.0, 0.3, 0.7),
            ('mDNSResponder', '/usr/sbin/mDNSResponder', 1.0, 1.0, 0.8),
            ('cupsd', '/usr/sbin/cupsd', 1.0, 0.5, 0.9),
            ('bluetoothd', '/usr/sbin/bluetoothd', 1.0, 0.3, 0.7),
            ('airportd', '/usr/libexec/airportd', 1.0, 0.5, 0.8),
        ]

        for name, path, priv, net, complexity in daemons:
            targets.append(Target(
                name=name, path=path, target_type='binary',
                platform='macos', privilege_level=priv,
                network_exposure=net, input_complexity=complexity,
                cve_density=0.3,
            ))

        # User-space attack surface
        userland = [
            ('Safari', '/Applications/Safari.app/Contents/MacOS/Safari', 0.0, 1.0, 1.0),
            ('Preview', '/System/Applications/Preview.app/Contents/MacOS/Preview', 0.0, 0.0, 0.9),
            ('sshd', '/usr/sbin/sshd', 1.0, 1.0, 0.7),
            ('sudo', '/usr/bin/sudo', 1.0, 0.0, 0.5),
        ]

        for name, path, priv, net, complexity in userland:
            targets.append(Target(
                name=name, path=path, target_type='binary',
                platform='macos', privilege_level=priv,
                network_exposure=net, input_complexity=complexity,
                cve_density=0.5,
            ))

        return targets

    @staticmethod
    def linux_high_value() -> List[Target]:
        """Pre-built target list for Linux high-value targets."""
        targets = []

        services = [
            ('sshd', '/usr/sbin/sshd', 1.0, 1.0, 0.7, 0.6),
            ('nginx', '/usr/sbin/nginx', 0.5, 1.0, 0.9, 0.4),
            ('apache2', '/usr/sbin/apache2', 0.5, 1.0, 0.9, 0.5),
            ('systemd', '/lib/systemd/systemd', 1.0, 0.0, 0.8, 0.3),
            ('dbus-daemon', '/usr/bin/dbus-daemon', 0.5, 0.3, 0.7, 0.3),
            ('polkitd', '/usr/lib/polkit-1/polkitd', 1.0, 0.0, 0.6, 0.7),
            ('sudo', '/usr/bin/sudo', 1.0, 0.0, 0.5, 0.8),
            ('su', '/usr/bin/su', 1.0, 0.0, 0.3, 0.4),
            ('cron', '/usr/sbin/cron', 1.0, 0.0, 0.5, 0.2),
        ]

        for name, path, priv, net, complexity, cve in services:
            targets.append(Target(
                name=name, path=path, target_type='binary',
                platform='linux', privilege_level=priv,
                network_exposure=net, input_complexity=complexity,
                cve_density=cve,
            ))

        return targets

    @staticmethod
    def windows_high_value() -> List[Target]:
        """Pre-built target list for Windows high-value targets."""
        targets = []

        services = [
            ('lsass.exe', 'C:\\Windows\\System32\\lsass.exe', 1.0, 0.3, 0.9, 0.7),
            ('svchost.exe', 'C:\\Windows\\System32\\svchost.exe', 1.0, 0.5, 0.8, 0.5),
            ('smb', 'C:\\Windows\\System32\\drivers\\srv2.sys', 1.0, 1.0, 0.9, 0.8),
            ('spoolsv.exe', 'C:\\Windows\\System32\\spoolsv.exe', 1.0, 0.5, 0.8, 0.9),
            ('dns.exe', 'C:\\Windows\\System32\\dns.exe', 1.0, 1.0, 0.8, 0.5),
            ('RpcSs', 'C:\\Windows\\System32\\rpcss.dll', 1.0, 0.5, 0.9, 0.6),
            ('winlogon.exe', 'C:\\Windows\\System32\\winlogon.exe', 1.0, 0.0, 0.7, 0.4),
        ]

        for name, path, priv, net, complexity, cve in services:
            targets.append(Target(
                name=name, path=path, target_type='binary',
                platform='windows', privilege_level=priv,
                network_exposure=net, input_complexity=complexity,
                cve_density=cve,
            ))

        return targets

    # ─── Display ─────────────────────────────────────────────────

    def format_queue(self, limit: int = 15) -> str:
        """Format queue as table string."""
        targets = self.list_queued(limit)
        stats = self.stats()

        lines = [
            f"TARGET QUEUE — {stats['queued']} queued, "
            f"{stats['active']} active, {stats['completed']} done, "
            f"{stats['total_findings']} findings",
            f"{'PRI':>5}  {'NAME':<25} {'TYPE':<10} {'PLATFORM':<8} "
            f"{'PRIV':<5} {'NET':<5} {'SEC':<5} {'STATUS':<10}",
            '-' * 85,
        ]

        for t in targets:
            lines.append(
                f"{t.priority:5.1f}  {t.name:<25} {t.target_type:<10} "
                f"{t.platform:<8} {t.privilege_level:<5.1f} "
                f"{t.network_exposure:<5.1f} {t.security_score:<5} "
                f"{t.status:<10}"
            )

        if not targets:
            lines.append("  (empty queue)")

        return '\n'.join(lines)
