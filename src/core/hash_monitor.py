"""
Threat Intel Hash Checker — Continuous monitoring of deployed payload hashes.

Queries MalwareBazaar, VirusTotal, and local hash DB to detect burned payloads.
On detection: updates DB status, fires event, triggers auto-response.

Modes:
- silent: auto-mutate + redeploy via C2
- controlled: alert operator, suggest replacement
- aggressive: mutate + redeploy + analyze detection vector
"""
import csv
import hashlib
import io
import json
import logging
import os
import sqlite3
import ssl
import struct
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from core.operations_db import OperationsDB


# ─── Threat Intel Sources ─────────────────────────────────────────

class MalwareBazaarClient:
    """MalwareBazaar API client (abuse.ch)."""

    API_URL = 'https://mb-api.abuse.ch/api/v1/'

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._ctx = ssl.create_default_context()

    def query_hash(self, sha256: str) -> dict:
        """Query MalwareBazaar for a SHA256 hash.

        Returns:
            {'known': bool, 'source': 'malwarebazaar', 'details': dict}
        """
        data = f'query=get_info&hash={sha256}'.encode()
        req = urllib.request.Request(
            self.API_URL,
            data=data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'FORGE-HashMonitor/1.0',
            },
        )
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx)
            result = json.loads(resp.read())

            if result.get('query_status') == 'ok':
                sample = result.get('data', [{}])[0] if result.get('data') else {}
                return {
                    'known': True,
                    'source': 'malwarebazaar',
                    'sha256': sha256,
                    'file_type': sample.get('file_type', 'unknown'),
                    'signature': sample.get('signature'),
                    'first_seen': sample.get('first_seen'),
                    'tags': sample.get('tags', []),
                    'detection_count': len(sample.get('vendor_intel', {})),
                }
            return {'known': False, 'source': 'malwarebazaar', 'sha256': sha256}

        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
            return {'known': False, 'source': 'malwarebazaar', 'sha256': sha256, 'error': str(e)}

    def batch_query(self, hashes: List[str]) -> List[dict]:
        """Query multiple hashes (sequential, respects rate limits)."""
        results = []
        for h in hashes:
            results.append(self.query_hash(h))
            time.sleep(0.5)  # Rate limit: 2 req/s
        return results


class VirusTotalClient:
    """VirusTotal API v3 client."""

    API_URL = 'https://www.virustotal.com/api/v3/files/'

    def __init__(self, api_key: str = None, timeout: float = 10.0):
        self.api_key = api_key or os.environ.get('VT_API_KEY', '')
        self.timeout = timeout
        self._ctx = ssl.create_default_context()

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def query_hash(self, sha256: str) -> dict:
        """Query VirusTotal for a SHA256 hash.

        Returns:
            {'known': bool, 'source': 'virustotal', 'detections': int, 'details': dict}
        """
        if not self.available:
            return {'known': False, 'source': 'virustotal', 'sha256': sha256, 'error': 'no_api_key'}

        url = f'{self.API_URL}{sha256}'
        req = urllib.request.Request(
            url,
            headers={
                'x-apikey': self.api_key,
                'User-Agent': 'FORGE-HashMonitor/1.0',
            },
        )
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx)
            result = json.loads(resp.read())
            attrs = result.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)

            return {
                'known': malicious > 0 or suspicious > 0,
                'source': 'virustotal',
                'sha256': sha256,
                'malicious': malicious,
                'suspicious': suspicious,
                'undetected': stats.get('undetected', 0),
                'total_engines': sum(stats.values()) if stats else 0,
                'type_tag': attrs.get('type_tag', ''),
                'names': attrs.get('names', [])[:5],
            }

        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {'known': False, 'source': 'virustotal', 'sha256': sha256}
            return {'known': False, 'source': 'virustotal', 'sha256': sha256, 'error': str(e)}
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
            return {'known': False, 'source': 'virustotal', 'sha256': sha256, 'error': str(e)}

    def batch_query(self, hashes: List[str]) -> List[dict]:
        """Query multiple hashes (4 req/min for free tier)."""
        results = []
        for h in hashes:
            results.append(self.query_hash(h))
            time.sleep(15.5)  # Free tier: 4 req/min
        return results


# ─── Local Hash Database (Air-Gap Mode) ──────────────────────────

class LocalHashDB:
    """SQLite database of known-bad hashes for air-gapped operations."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS known_hashes (
        sha256 TEXT PRIMARY KEY,
        md5 TEXT,
        sha1 TEXT,
        source TEXT NOT NULL DEFAULT 'manual',
        file_type TEXT,
        signature TEXT,
        first_seen TEXT,
        tags TEXT,
        imported_at REAL NOT NULL DEFAULT (strftime('%s','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_known_md5 ON known_hashes(md5);
    CREATE INDEX IF NOT EXISTS idx_known_sha1 ON known_hashes(sha1);
    """

    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(
            Path(__file__).parent.parent / 'knowledge' / 'known_bad_hashes.db'
        )
        self._conn = None

    def connect(self):
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(self.SCHEMA)
        self._conn.commit()

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def check_hash(self, sha256: str) -> dict:
        """Check if hash exists in local DB."""
        row = self._conn.execute(
            "SELECT * FROM known_hashes WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if row:
            return {
                'known': True,
                'source': 'local_db',
                'sha256': sha256,
                'file_type': row['file_type'],
                'signature': row['signature'],
                'first_seen': row['first_seen'],
                'tags': row['tags'],
            }
        return {'known': False, 'source': 'local_db', 'sha256': sha256}

    def batch_check(self, hashes: List[str]) -> List[dict]:
        """Check multiple hashes against local DB."""
        return [self.check_hash(h) for h in hashes]

    def import_csv(self, csv_path: str, source: str = 'csv_import') -> int:
        """Bulk import from CSV (MalwareBazaar or VirusTotal format).

        Expected columns: sha256_hash (or sha256), md5_hash (or md5),
                         sha1_hash (or sha1), file_type, signature, first_seen, tags

        Returns: number of imported hashes.
        """
        imported = 0
        with open(csv_path, 'r') as f:
            # Try to detect format
            reader = csv.DictReader(f)
            for row in reader:
                sha256 = row.get('sha256_hash') or row.get('sha256') or row.get('SHA256')
                if not sha256 or len(sha256) != 64:
                    continue

                md5 = row.get('md5_hash') or row.get('md5') or row.get('MD5')
                sha1 = row.get('sha1_hash') or row.get('sha1') or row.get('SHA1')
                file_type = row.get('file_type') or row.get('type') or ''
                signature = row.get('signature') or row.get('family') or ''
                first_seen = row.get('first_seen') or row.get('first_submission_date') or ''
                tags = row.get('tags') or ''

                try:
                    self._conn.execute(
                        """INSERT OR IGNORE INTO known_hashes
                           (sha256, md5, sha1, source, file_type, signature, first_seen, tags)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (sha256.lower(), md5, sha1, source, file_type, signature, first_seen, tags),
                    )
                    imported += 1
                except sqlite3.Error:
                    continue

        self._conn.commit()
        return imported

    def import_hashes(self, hashes: List[str], source: str = 'manual') -> int:
        """Import a list of SHA256 hashes."""
        imported = 0
        for h in hashes:
            h = h.strip().lower()
            if len(h) != 64:
                continue
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO known_hashes (sha256, source) VALUES (?, ?)",
                    (h, source),
                )
                imported += 1
            except sqlite3.Error:
                continue
        self._conn.commit()
        return imported

    def stats(self) -> dict:
        """Get database statistics."""
        total = self._conn.execute("SELECT COUNT(*) FROM known_hashes").fetchone()[0]
        sources = {}
        for row in self._conn.execute(
            "SELECT source, COUNT(*) FROM known_hashes GROUP BY source"
        ):
            sources[row[0]] = row[1]
        return {'total_hashes': total, 'sources': sources}


# ─── Hash Monitor Engine ─────────────────────────────────────────

class HashMonitor:
    """Continuous payload hash monitoring engine.

    Usage:
        monitor = HashMonitor(ops_db, op_id, mode='controlled')
        monitor.start()  # Runs check cycle
        monitor.check_all()  # Manual check

    Events emitted:
        payload_burned — hash found in threat intel
        payload_clean — all hashes clean this cycle
        hash_check_error — API error during check
    """

    def __init__(self, ops_db: OperationsDB, op_id: str,
                 mode: str = 'controlled',
                 event_callback: Callable = None,
                 check_interval: float = 60.0,
                 vt_api_key: str = None,
                 local_db_path: str = None,
                 air_gap: bool = False):
        self.db = ops_db
        self.op_id = op_id
        self.mode = mode  # silent, controlled, aggressive
        self._callback = event_callback or (lambda e: None)
        self.check_interval = check_interval
        self.air_gap = air_gap

        # Initialize sources
        self._mb = MalwareBazaarClient() if not air_gap else None
        self._vt = VirusTotalClient(api_key=vt_api_key) if not air_gap else None
        self._local = LocalHashDB(local_db_path)
        self._local.connect()

        # State
        self._known_hashes: Set[str] = set()
        self._burned_hashes: Set[str] = set()
        self._running = False
        self._last_check = 0
        self._check_count = 0
        self._burn_count = 0

    def _emit(self, event_type: str, severity: str, details: dict):
        """Emit event to callback and log to DB."""
        event = {
            'type': event_type,
            'severity': severity,
            'timestamp': time.time(),
            'data': details,
        }
        self._callback(event)
        try:
            self.db.log_event(self.op_id, event_type, severity, details=details)
        except Exception:
            pass

    def refresh_hashes(self):
        """Reload payload hashes from operations DB."""
        hashes = self.db.get_all_payload_hashes(self.op_id)
        self._known_hashes = {h for _, h in hashes if h}

    def check_hash(self, sha256: str) -> List[dict]:
        """Check a single hash against all sources.

        Returns list of results from each source.
        """
        results = []

        # 1. Local DB (always checked first, fast)
        local_result = self._local.check_hash(sha256)
        results.append(local_result)

        # 2. MalwareBazaar (if online)
        if self._mb:
            try:
                mb_result = self._mb.query_hash(sha256)
                results.append(mb_result)
            except Exception as e:
                results.append({'known': False, 'source': 'malwarebazaar', 'error': str(e)})

        # 3. VirusTotal (if key available)
        if self._vt and self._vt.available:
            try:
                vt_result = self._vt.query_hash(sha256)
                results.append(vt_result)
            except Exception as e:
                results.append({'known': False, 'source': 'virustotal', 'error': str(e)})

        return results

    def _handle_burn(self, sha256: str, detection: dict):
        """Handle a burned payload hash."""
        self._burned_hashes.add(sha256)
        self._burn_count += 1

        # Find payload ID
        hashes = self.db.get_all_payload_hashes(self.op_id)
        payload_id = None
        for pid, h in hashes:
            if h == sha256:
                payload_id = pid
                break

        # Update DB status
        if payload_id:
            try:
                self.db._conn.execute(
                    "UPDATE payloads SET detection_status = 'flagged' WHERE payload_id = ?",
                    (payload_id,),
                )
                self.db._conn.commit()
            except Exception:
                pass

        # Emit event
        self._emit('payload_burned', 'critical', {
            'payload_id': payload_id,
            'sha256': sha256[:16] + '...',
            'detected_by': detection.get('source', 'unknown'),
            'mode': self.mode,
            'details': {k: v for k, v in detection.items() if k != 'sha256'},
        })

        # Auto-response based on mode
        if self.mode == 'silent':
            self._emit('auto_mutate_triggered', 'warning', {
                'payload_id': payload_id,
                'action': 'mutate_and_redeploy',
            })
        elif self.mode == 'aggressive':
            self._emit('auto_mutate_triggered', 'warning', {
                'payload_id': payload_id,
                'action': 'mutate_redeploy_analyze',
                'analysis': 'detection_vector_investigation',
            })
        # controlled mode: event is sufficient (operator decides)

    def check_all(self) -> dict:
        """Run a full check cycle against all sources.

        Returns:
            {'checked': int, 'clean': int, 'burned': int, 'errors': int, 'details': list}
        """
        self.refresh_hashes()
        self._check_count += 1

        checked = 0
        clean = 0
        burned = 0
        errors = 0
        details = []

        for sha256 in self._known_hashes:
            if sha256 in self._burned_hashes:
                continue  # Already burned, skip

            checked += 1
            results = self.check_hash(sha256)

            is_burned = False
            for r in results:
                if r.get('error'):
                    errors += 1
                if r.get('known'):
                    is_burned = True
                    self._handle_burn(sha256, r)
                    details.append(r)
                    break

            if not is_burned:
                clean += 1

        self._last_check = time.time()

        summary = {
            'checked': checked,
            'clean': clean,
            'burned': burned + len([d for d in details if d.get('known')]),
            'errors': errors,
            'total_known': len(self._known_hashes),
            'total_burned': len(self._burned_hashes),
            'check_number': self._check_count,
            'details': details,
        }

        if not details:
            self._emit('payload_clean', 'info', {
                'checked': checked,
                'check_number': self._check_count,
            })

        return summary

    async def run_async(self):
        """Async monitoring loop (for use with operations daemon)."""
        import asyncio
        self._running = True
        while self._running:
            try:
                self.check_all()
            except Exception as e:
                self._emit('hash_check_error', 'warning', {'error': str(e)})
            await asyncio.sleep(self.check_interval)

    def stop(self):
        self._running = False

    def status(self) -> dict:
        """Get monitor status."""
        return {
            'running': self._running,
            'mode': self.mode,
            'air_gap': self.air_gap,
            'known_hashes': len(self._known_hashes),
            'burned_hashes': len(self._burned_hashes),
            'check_count': self._check_count,
            'burn_count': self._burn_count,
            'last_check': self._last_check,
            'sources': {
                'malwarebazaar': self._mb is not None,
                'virustotal': self._vt.available if self._vt else False,
                'local_db': True,
            },
        }

    def close(self):
        self._running = False
        self._local.close()
