"""Knowledge Base Versioning.

Snapshot the triplet DB, diff between versions, rollback on poisoning.
Track knowledge growth over time. Detect and quarantine bad triplets.
Integrity verification via SHA-256 manifests.

Storage structure:
  knowledge/
    .kb_versions/
      manifest.json    — version history
      v001/            — snapshot dir
        bridge_triplets.json
        fragments/...
        *.causal

Part of FORGE Phase Q: Intelligence & Replay.
"""
# Dependencies: none
# Depended by: none (leaf module)


import json
import hashlib
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class KBVersion:
    """A single knowledge base version snapshot."""

    def __init__(self, version_id: int, timestamp: float, label: str = '',
                 files: Dict[str, str] = None, stats: Dict[str, int] = None):
        self.version_id = version_id
        self.timestamp = timestamp
        self.label = label or f'v{version_id:03d}'
        self.files = files or {}  # relative_path -> sha256 hash
        self.stats = stats or {}  # triplet_count, fragment_count, etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            'version_id': self.version_id,
            'timestamp': self.timestamp,
            'date': datetime.fromtimestamp(self.timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M'),
            'label': self.label,
            'files': self.files,
            'stats': self.stats,
        }

    @staticmethod
    def from_dict(d: Dict) -> 'KBVersion':
        return KBVersion(
            d['version_id'], d['timestamp'], d.get('label', ''),
            d.get('files', {}), d.get('stats', {}))


class KBVersioning:
    """Knowledge Base versioning, diffing, and rollback."""

    # Files to track
    TRACKED_PATTERNS = [
        'bridge_triplets.json',
        'knowledge/*.causal',
        'knowledge/*.json',
        'fragments/*.json',
    ]

    def __init__(self, forge_root: str = None):
        if forge_root is None:
            forge_root = str(Path(__file__).parent.parent)
        self.root = Path(forge_root)
        self.versions_dir = self.root / 'knowledge' / '.kb_versions'
        self.manifest_path = self.versions_dir / 'manifest.json'
        self.versions_dir.mkdir(parents=True, exist_ok=True)
        self.versions = self._load_manifest()

    def _load_manifest(self) -> List[KBVersion]:
        """Load version manifest."""
        if self.manifest_path.exists():
            try:
                with open(self.manifest_path) as f:
                    data = json.load(f)
                return [KBVersion.from_dict(d) for d in data.get('versions', [])]
            except (json.JSONDecodeError, KeyError):
                return []
        return []

    def _save_manifest(self):
        """Save version manifest."""
        with open(self.manifest_path, 'w') as f:
            json.dump({
                'versions': [v.to_dict() for v in self.versions],
                'current': self.versions[-1].version_id if self.versions else 0,
            }, f, indent=2)

    # ─── File Discovery ────────────────────────────────────────

    def _discover_files(self) -> Dict[str, str]:
        """Find all tracked knowledge files and compute hashes."""
        files = {}
        import glob as globmod

        for pattern in self.TRACKED_PATTERNS:
            full_pattern = str(self.root / pattern)
            for filepath in globmod.glob(full_pattern):
                rel = os.path.relpath(filepath, self.root)
                h = self._hash_file(filepath)
                files[rel] = h

        return files

    def _hash_file(self, filepath: str) -> str:
        """SHA-256 hash of a file."""
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()[:16]

    def _compute_stats(self) -> Dict[str, int]:
        """Compute current knowledge base statistics."""
        stats = {}

        # Bridge triplets
        bt_path = self.root / 'bridge_triplets.json'
        if bt_path.exists():
            try:
                with open(bt_path) as f:
                    data = json.load(f)
                stats['bridge_triplets'] = len(data) if isinstance(data, list) else 0
            except json.JSONDecodeError:
                stats['bridge_triplets'] = 0

        # Causal files
        import glob as globmod
        causal_files = globmod.glob(str(self.root / 'knowledge' / '*.causal'))
        stats['causal_files'] = len(causal_files)
        stats['causal_bytes'] = sum(os.path.getsize(f) for f in causal_files)

        # Fragment files
        frag_files = globmod.glob(str(self.root / 'fragments' / '*.json'))
        stats['fragment_files'] = len(frag_files)
        total_fragments = 0
        for ff in frag_files:
            try:
                with open(ff) as f:
                    data = json.load(f)
                if isinstance(data, list):
                    total_fragments += len(data)
            except json.JSONDecodeError:
                pass
        stats['total_fragments'] = total_fragments

        # Knowledge JSON files
        kj_files = globmod.glob(str(self.root / 'knowledge' / '*.json'))
        stats['knowledge_json_files'] = len(kj_files)

        return stats

    # ─── Snapshot ──────────────────────────────────────────────

    def snapshot(self, label: str = '') -> KBVersion:
        """Create a snapshot of the current knowledge base."""
        next_id = (self.versions[-1].version_id + 1) if self.versions else 1
        files = self._discover_files()
        stats = self._compute_stats()

        version = KBVersion(next_id, time.time(), label or f'v{next_id:03d}', files, stats)

        # Create snapshot directory
        snap_dir = self.versions_dir / f'v{next_id:03d}'
        snap_dir.mkdir(parents=True, exist_ok=True)

        # Copy tracked files
        for rel_path in files:
            src = self.root / rel_path
            dst = snap_dir / rel_path
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))

        self.versions.append(version)
        self._save_manifest()

        return version

    # ─── Diff ──────────────────────────────────────────────────

    def diff(self, v1_id: int = None, v2_id: int = None) -> Dict[str, Any]:
        """Diff between two versions (default: previous vs current).

        Returns: added, removed, modified files and stat changes.
        """
        if not self.versions:
            return {'error': 'No versions exist'}

        if v2_id is None:
            # Compare latest version with current state
            latest = self.versions[-1]
            current_files = self._discover_files()
            current_stats = self._compute_stats()

            v1_files = latest.files
            v2_files = current_files
            v1_stats = latest.stats
            v2_stats = current_stats
            v1_label = latest.label
            v2_label = 'current'
        else:
            v1 = self._find_version(v1_id)
            v2 = self._find_version(v2_id)
            if not v1 or not v2:
                return {'error': 'Version not found'}
            v1_files = v1.files
            v2_files = v2.files
            v1_stats = v1.stats
            v2_stats = v2.stats
            v1_label = v1.label
            v2_label = v2.label

        v1_set = set(v1_files.keys())
        v2_set = set(v2_files.keys())

        added = sorted(v2_set - v1_set)
        removed = sorted(v1_set - v2_set)
        common = v1_set & v2_set
        modified = sorted(f for f in common if v1_files[f] != v2_files[f])
        unchanged = sorted(f for f in common if v1_files[f] == v2_files[f])

        # Stat changes
        stat_changes = {}
        all_stat_keys = set(list(v1_stats.keys()) + list(v2_stats.keys()))
        for key in sorted(all_stat_keys):
            old = v1_stats.get(key, 0)
            new = v2_stats.get(key, 0)
            if old != new:
                stat_changes[key] = {'old': old, 'new': new, 'delta': new - old}

        return {
            'v1': v1_label,
            'v2': v2_label,
            'added': added,
            'removed': removed,
            'modified': modified,
            'unchanged_count': len(unchanged),
            'stat_changes': stat_changes,
        }

    # ─── Rollback ──────────────────────────────────────────────

    def rollback(self, version_id: int) -> Dict[str, Any]:
        """Rollback knowledge base to a specific version.

        DESTRUCTIVE: Overwrites current files with snapshot copies.
        Returns dict with restored/removed file counts.
        """
        version = self._find_version(version_id)
        if not version:
            return {'error': f'Version {version_id} not found'}

        snap_dir = self.versions_dir / f'v{version_id:03d}'
        if not snap_dir.exists():
            return {'error': f'Snapshot directory missing for v{version_id:03d}'}

        restored = 0
        removed_count = 0

        # Restore files from snapshot
        for rel_path in version.files:
            src = snap_dir / rel_path
            dst = self.root / rel_path
            if src.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src), str(dst))
                restored += 1

        # Remove files that didn't exist in the snapshot
        current_files = self._discover_files()
        for rel_path in current_files:
            if rel_path not in version.files:
                target = self.root / rel_path
                if target.exists():
                    # Move to quarantine instead of deleting
                    quarantine_dir = self.versions_dir / 'quarantine'
                    quarantine_dir.mkdir(exist_ok=True)
                    quarantine_path = quarantine_dir / rel_path.replace('/', '_')
                    shutil.move(str(target), str(quarantine_path))
                    removed_count += 1

        return {
            'rolled_back_to': version.label,
            'restored_files': restored,
            'quarantined_files': removed_count,
        }

    # ─── Integrity Verification ────────────────────────────────

    def verify_integrity(self) -> Dict[str, Any]:
        """Verify current knowledge base integrity against latest snapshot."""
        if not self.versions:
            return {'status': 'no_versions', 'message': 'No snapshots to verify against'}

        latest = self.versions[-1]
        current = self._discover_files()

        corrupted = []
        missing = []
        new_files = []

        for rel_path, expected_hash in latest.files.items():
            if rel_path not in current:
                missing.append(rel_path)
            elif current[rel_path] != expected_hash:
                corrupted.append({
                    'file': rel_path,
                    'expected': expected_hash,
                    'actual': current[rel_path],
                })

        for rel_path in current:
            if rel_path not in latest.files:
                new_files.append(rel_path)

        ok = not corrupted and not missing
        return {
            'status': 'ok' if ok else 'integrity_violation',
            'version': latest.label,
            'files_checked': len(latest.files),
            'corrupted': corrupted,
            'missing': missing,
            'new_untracked': new_files,
            'ok': ok,
        }

    # ─── Quarantine (Bad Triplet Detection) ────────────────────

    def quarantine_triplets(self, indices: List[int]) -> Dict[str, Any]:
        """Quarantine specific triplets from bridge_triplets.json by index.

        Moves them to a quarantine file instead of deleting.
        """
        bt_path = self.root / 'bridge_triplets.json'
        if not bt_path.exists():
            return {'error': 'bridge_triplets.json not found'}

        with open(bt_path) as f:
            triplets = json.load(f)

        quarantine_path = self.versions_dir / 'quarantined_triplets.json'
        quarantined = []
        if quarantine_path.exists():
            with open(quarantine_path) as f:
                quarantined = json.load(f)

        # Extract and remove (reverse order to preserve indices)
        removed = []
        for idx in sorted(indices, reverse=True):
            if 0 <= idx < len(triplets):
                t = triplets.pop(idx)
                t['_quarantined_at'] = time.time()
                t['_original_index'] = idx
                removed.append(t)
                quarantined.append(t)

        # Save
        with open(bt_path, 'w') as f:
            json.dump(triplets, f, indent=2)
        with open(quarantine_path, 'w') as f:
            json.dump(quarantined, f, indent=2)

        return {
            'quarantined': len(removed),
            'remaining_triplets': len(triplets),
            'total_quarantined': len(quarantined),
        }

    def detect_suspect_triplets(self) -> List[Dict]:
        """Detect potentially bad triplets (low confidence, empty fields, duplicates)."""
        bt_path = self.root / 'bridge_triplets.json'
        if not bt_path.exists():
            return []

        with open(bt_path) as f:
            triplets = json.load(f)

        suspects = []
        seen_hashes = set()

        for i, t in enumerate(triplets):
            reasons = []

            # Empty or very short fields
            trigger = t.get('trigger', '')
            mechanism = t.get('mechanism', '')
            outcome = t.get('outcome', '')

            if len(trigger) < 3:
                reasons.append('trigger too short')
            if len(outcome) < 3:
                reasons.append('outcome too short')
            if not mechanism:
                reasons.append('empty mechanism')

            # Low confidence
            conf = t.get('confidence', 1.0)
            if isinstance(conf, (int, float)) and conf < 0.3:
                reasons.append(f'low confidence ({conf})')

            # Duplicate detection
            h = hashlib.sha256(f"{trigger}:{mechanism}:{outcome}".encode()).hexdigest()[:12]
            if h in seen_hashes:
                reasons.append('duplicate')
            seen_hashes.add(h)

            # Self-referential
            if trigger and outcome and trigger.lower() == outcome.lower():
                reasons.append('self-referential (trigger == outcome)')

            if reasons:
                suspects.append({
                    'index': i,
                    'trigger': trigger[:50],
                    'outcome': outcome[:50],
                    'reasons': reasons,
                })

        return suspects

    # ─── Growth Tracking ───────────────────────────────────────

    def growth_timeline(self) -> List[Dict]:
        """Track knowledge base growth over time."""
        timeline = []
        for v in self.versions:
            timeline.append({
                'version': v.label,
                'date': datetime.fromtimestamp(v.timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M'),
                'files': len(v.files),
                **v.stats,
            })
        return timeline

    # ─── Formatting ────────────────────────────────────────────

    def format_status(self) -> str:
        """Format current KB status."""
        stats = self._compute_stats()
        integrity = self.verify_integrity() if self.versions else None

        lines = [
            "KNOWLEDGE BASE STATUS",
            "=" * 50,
            f"  Bridge Triplets: {stats.get('bridge_triplets', 0)}",
            f"  Causal Files: {stats.get('causal_files', 0)} ({stats.get('causal_bytes', 0) // 1024} KB)",
            f"  Fragment Files: {stats.get('fragment_files', 0)} ({stats.get('total_fragments', 0)} fragments)",
            f"  Knowledge JSON: {stats.get('knowledge_json_files', 0)}",
            f"  Versions: {len(self.versions)}",
        ]

        if integrity:
            status_str = 'OK' if integrity['ok'] else 'INTEGRITY VIOLATION'
            lines.append(f"  Integrity: {status_str}")
            if integrity.get('corrupted'):
                lines.append(f"    Corrupted: {len(integrity['corrupted'])} files")
            if integrity.get('missing'):
                lines.append(f"    Missing: {len(integrity['missing'])} files")

        return '\n'.join(lines)

    def format_versions(self) -> str:
        """Format version list."""
        if not self.versions:
            return "No versions recorded. Use /kb snapshot to create one."

        lines = [
            f"KB VERSIONS ({len(self.versions)})",
            f"{'=' * 60}",
            f"  {'ID':<5} {'Label':<10} {'Date':<18} {'Files':<7} {'Triplets':<10} {'Fragments'}",
            f"  {'-'*5} {'-'*10} {'-'*18} {'-'*7} {'-'*10} {'-'*9}",
        ]

        for v in self.versions:
            date = datetime.fromtimestamp(v.timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M')
            lines.append(
                f"  {v.version_id:<5} {v.label:<10} {date:<18} "
                f"{len(v.files):<7} {v.stats.get('bridge_triplets', '?'):<10} "
                f"{v.stats.get('total_fragments', '?')}"
            )

        return '\n'.join(lines)

    def format_diff(self, diff_result: Dict) -> str:
        """Format diff output."""
        if 'error' in diff_result:
            return diff_result['error']

        lines = [
            f"DIFF: {diff_result['v1']} -> {diff_result['v2']}",
            f"{'=' * 50}",
        ]

        if diff_result['added']:
            lines.append(f"  ADDED ({len(diff_result['added'])}):")
            for f in diff_result['added'][:10]:
                lines.append(f"    + {f}")
            if len(diff_result['added']) > 10:
                lines.append(f"    ... (+{len(diff_result['added'])-10} more)")

        if diff_result['removed']:
            lines.append(f"  REMOVED ({len(diff_result['removed'])}):")
            for f in diff_result['removed'][:10]:
                lines.append(f"    - {f}")

        if diff_result['modified']:
            lines.append(f"  MODIFIED ({len(diff_result['modified'])}):")
            for f in diff_result['modified'][:10]:
                lines.append(f"    ~ {f}")
            if len(diff_result['modified']) > 10:
                lines.append(f"    ... (+{len(diff_result['modified'])-10} more)")

        lines.append(f"  UNCHANGED: {diff_result['unchanged_count']}")

        if diff_result.get('stat_changes'):
            lines.extend(['', '  STAT CHANGES:'])
            for key, change in diff_result['stat_changes'].items():
                delta = change['delta']
                sign = '+' if delta > 0 else ''
                lines.append(f"    {key}: {change['old']} -> {change['new']} ({sign}{delta})")

        return '\n'.join(lines)

    # ─── Internal ──────────────────────────────────────────────

    def _find_version(self, version_id: int) -> Optional[KBVersion]:
        for v in self.versions:
            if v.version_id == version_id:
                return v
        return None
