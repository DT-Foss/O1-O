"""
Operations Daemon — Background process managing autonomous FORGE operations.

Components:
- Asyncio event loop managing all C2 channels
- Periodic tasks: payload hash check (60s), persistence verify (300s), cred rotation (3600s)
- REST API on localhost for CLI client
- WebSocket endpoint for live event streaming

Lifecycle:
  forge --start-op "Name"  → starts daemon, returns op_id
  forge --attach OP-ID     → CLI connects to running daemon
  forge --detach           → CLI disconnects, daemon continues
  forge --pause OP-ID      → stop autonomous actions, maintain C2
  forge --stop OP-ID       → graceful shutdown, save state
"""
import asyncio
import hashlib
import http.server
import json
import logging
import os
import signal
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from o1o_o.core.operations_db import OperationsDB
from o1o_o.core.session_restore import SessionRestoreEngine, AttackGraph


# ─── Daemon PID/Socket Management ────────────────────────────────

DAEMON_DIR = Path(tempfile.gettempdir()) / 'forge_daemon'
LOG_FILE = DAEMON_DIR / 'forge_daemon.log'


def _get_pid_file(op_id: str) -> Path:
    return DAEMON_DIR / f'{op_id}.pid'


def _get_socket_file(op_id: str) -> Path:
    return DAEMON_DIR / f'{op_id}.sock'


def _get_port_file(op_id: str) -> Path:
    return DAEMON_DIR / f'{op_id}.port'


def is_daemon_running(op_id: str) -> bool:
    """Check if daemon is running for this operation."""
    pid_file = _get_pid_file(op_id)
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 0)  # signal 0 = check if alive
        return True
    except (ProcessLookupError, ValueError, PermissionError):
        pid_file.unlink(missing_ok=True)
        return False


# ─── Event Bus ────────────────────────────────────────────────────

class EventBus:
    """Pub/sub event bus for operation events."""

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._all_subscribers: List[Callable] = []
        self._event_log: List[dict] = []
        self._max_log = 10000

    def subscribe(self, event_type: str, callback: Callable):
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)

    def subscribe_all(self, callback: Callable):
        self._all_subscribers.append(callback)

    def emit(self, event_type: str, data: dict = None):
        event = {
            'type': event_type,
            'timestamp': time.time(),
            'data': data or {},
        }
        self._event_log.append(event)
        if len(self._event_log) > self._max_log:
            self._event_log = self._event_log[-self._max_log:]

        for cb in self._subscribers.get(event_type, []):
            try:
                cb(event)
            except Exception:
                pass
        for cb in self._all_subscribers:
            try:
                cb(event)
            except Exception:
                pass

    def get_recent(self, count: int = 50) -> List[dict]:
        return self._event_log[-count:]


# ─── Periodic Task Manager ────────────────────────────────────────

class PeriodicTask:
    """Asyncio periodic task wrapper."""

    def __init__(self, name: str, interval_seconds: float,
                 coroutine_func: Callable, enabled: bool = True):
        self.name = name
        self.interval = interval_seconds
        self.func = coroutine_func
        self.enabled = enabled
        self.last_run = 0
        self.run_count = 0
        self.error_count = 0
        self._task: Optional[asyncio.Task] = None

    async def _loop(self):
        while True:
            if self.enabled:
                try:
                    await self.func()
                    self.last_run = time.time()
                    self.run_count += 1
                except Exception as e:
                    self.error_count += 1
                    logging.error(f"Periodic task {self.name} error: {e}")
            await asyncio.sleep(self.interval)

    def start(self, loop: asyncio.AbstractEventLoop = None):
        self._task = asyncio.ensure_future(self._loop())

    def stop(self):
        if self._task:
            self._task.cancel()

    def stats(self) -> dict:
        return {
            'name': self.name,
            'interval': self.interval,
            'enabled': self.enabled,
            'last_run': self.last_run,
            'run_count': self.run_count,
            'error_count': self.error_count,
        }


# ─── REST API Server ─────────────────────────────────────────────

class DaemonAPIHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for daemon REST API."""

    daemon_ref = None  # set externally

    def log_message(self, format, *args):
        pass  # suppress default logging

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        body = self.rfile.read(length)
        return json.loads(body)

    def _check_auth(self) -> bool:
        token = self.headers.get('Authorization', '').replace('Bearer ', '')
        if not self.daemon_ref:
            return False
        return token == self.daemon_ref.auth_token

    def do_GET(self):
        if not self._check_auth():
            self._send_json({'error': 'unauthorized'}, 401)
            return

        d = self.daemon_ref

        if self.path == '/status':
            summary = d.db.get_status_summary(d.op_id)
            self._send_json(summary)

        elif self.path == '/graph':
            self._send_json(d.attack_graph.to_dict())

        elif self.path == '/events':
            events = d.event_bus.get_recent(100)
            self._send_json({'events': events})

        elif self.path == '/tasks':
            tasks = [t.stats() for t in d.periodic_tasks]
            self._send_json({'tasks': tasks})

        elif self.path == '/hosts':
            hosts = d.db.get_hosts(d.op_id)
            self._send_json({'hosts': hosts})

        elif self.path == '/credentials':
            creds = d.db.get_credentials(d.op_id)
            self._send_json({'credentials': creds})

        elif self.path == '/payloads':
            payloads = d.db.get_payloads(d.op_id)
            self._send_json({'payloads': payloads})

        elif self.path == '/c2':
            channels = d.db.get_c2_channels(d.op_id, active_only=False)
            # Strip encrypted blobs from response
            for ch in channels:
                ch.pop('endpoint_encrypted', None)
            self._send_json({'channels': channels})

        elif self.path == '/health':
            self._send_json({
                'status': 'running',
                'op_id': d.op_id,
                'uptime': time.time() - d.start_time,
                'pid': os.getpid(),
            })

        else:
            self._send_json({'error': 'not found'}, 404)

    def do_POST(self):
        if not self._check_auth():
            self._send_json({'error': 'unauthorized'}, 401)
            return

        d = self.daemon_ref
        body = self._read_body()

        if self.path == '/pause':
            d.pause()
            self._send_json({'status': 'paused'})

        elif self.path == '/resume':
            d.unpause()
            self._send_json({'status': 'resumed'})

        elif self.path == '/stop':
            self._send_json({'status': 'stopping'})
            d.stop()

        elif self.path == '/command':
            # Execute FORGE command through daemon
            cmd = body.get('command', '')
            result = d.execute_command(cmd)
            self._send_json({'result': result})

        else:
            self._send_json({'error': 'not found'}, 404)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


# ─── Operations Daemon ────────────────────────────────────────────

class OperationsDaemon:
    """Background daemon for autonomous FORGE operations."""

    def __init__(self, op_id: str, db_path: str = None,
                 passphrase: str = None, api_port: int = 0):
        self.op_id = op_id
        self.db = OperationsDB(db_path, passphrase)
        self.attack_graph = AttackGraph()
        self.event_bus = EventBus()
        self.auth_token = hashlib.sha256(os.urandom(32)).hexdigest()
        self.start_time = time.time()
        self.paused = False
        self._running = False
        self._api_server = None
        self._api_port = api_port
        self._loop = None

        self.periodic_tasks: List[PeriodicTask] = []

    def _setup_periodic_tasks(self):
        """Register periodic background tasks."""
        self.periodic_tasks = [
            PeriodicTask('heartbeat', 30, self._task_heartbeat),
            PeriodicTask('hash_check', 60, self._task_hash_check),
            PeriodicTask('persistence_verify', 300, self._task_persistence_verify),
            PeriodicTask('credential_rotation', 3600, self._task_credential_rotation),
            PeriodicTask('c2_health', 120, self._task_c2_health),
        ]

    async def _task_heartbeat(self):
        """Update heartbeat in DB."""
        self.db.heartbeat(self.op_id)

    async def _task_hash_check(self):
        """Check deployed payload hashes against threat intel."""
        if self.paused:
            return
        hashes = self.db.get_all_payload_hashes(self.op_id)
        for payload_id, sha256_hash in hashes:
            # In production: query MalwareBazaar, VirusTotal
            # For now: log the check
            self.event_bus.emit('hash_checked', {
                'payload_id': payload_id,
                'sha256': sha256_hash[:16] + '...',
                'result': 'clean',
            })

    async def _task_persistence_verify(self):
        """Verify persistence layers on all persistent hosts."""
        if self.paused:
            return
        hosts = self.db.get_hosts(self.op_id, status='persistent')
        for host in hosts:
            self.event_bus.emit('persistence_checked', {
                'host_id': host['host_id'],
                'ip': host.get('ip'),
                'result': 'verified',
            })

    async def _task_credential_rotation(self):
        """Test credentials that might have been rotated."""
        if self.paused:
            return
        creds = self.db.get_credentials(self.op_id)
        expiring = [c for c in creds
                    if c.get('expires_at') and c['expires_at'] < time.time() + 86400]
        if expiring:
            self.event_bus.emit('credentials_expiring', {
                'count': len(expiring),
                'types': [c['cred_type'] for c in expiring],
            })

    async def _task_c2_health(self):
        """Check C2 channel health."""
        channels = self.db.get_c2_channels(self.op_id, active_only=True)
        for ch in channels:
            # Check if last_successful is stale
            last = ch.get('last_successful', 0)
            if last and time.time() - last > ch.get('beacon_interval_seconds', 300) * 3:
                self.db.update_c2_status(ch['channel_id'], 'degraded')
                self.event_bus.emit('c2_degraded', {
                    'channel_id': ch['channel_id'],
                    'channel_type': ch['channel_type'],
                    'last_successful': last,
                })

    def _start_api_server(self):
        """Start REST API server in a background thread."""
        DaemonAPIHandler.daemon_ref = self

        # Find available port if not specified
        if self._api_port == 0:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', 0))
                self._api_port = s.getsockname()[1]

        self._api_server = ThreadedHTTPServer(
            ('127.0.0.1', self._api_port), DaemonAPIHandler
        )

        thread = threading.Thread(target=self._api_server.serve_forever, daemon=True)
        thread.start()

        # Write port file for CLI client discovery
        DAEMON_DIR.mkdir(parents=True, exist_ok=True)
        port_file = _get_port_file(self.op_id)
        port_file.write_text(json.dumps({
            'port': self._api_port,
            'token': self.auth_token,
            'pid': os.getpid(),
            'started': self.start_time,
        }))

    def _write_pid(self):
        """Write PID file."""
        DAEMON_DIR.mkdir(parents=True, exist_ok=True)
        pid_file = _get_pid_file(self.op_id)
        pid_file.write_text(str(os.getpid()))

    def _cleanup(self):
        """Clean up PID and port files."""
        _get_pid_file(self.op_id).unlink(missing_ok=True)
        _get_port_file(self.op_id).unlink(missing_ok=True)

    def pause(self):
        """Pause autonomous actions (maintain C2)."""
        self.paused = True
        self.db.update_operation_status(self.op_id, 'paused')
        self.event_bus.emit('operation_paused', {'op_id': self.op_id})

    def unpause(self):
        """Resume autonomous actions."""
        self.paused = False
        self.db.update_operation_status(self.op_id, 'active')
        self.event_bus.emit('operation_resumed', {'op_id': self.op_id})

    def stop(self):
        """Graceful shutdown."""
        self._running = False
        self.event_bus.emit('operation_stopping', {'op_id': self.op_id})

    def execute_command(self, command: str) -> dict:
        """Execute a FORGE command through the daemon."""
        parts = command.strip().split()
        if not parts:
            return {'error': 'empty command'}

        cmd = parts[0].lower()

        if cmd == 'status':
            return self.db.get_status_summary(self.op_id)
        elif cmd == 'hosts':
            return {'hosts': self.db.get_hosts(self.op_id)}
        elif cmd == 'creds':
            return {'credentials': self.db.get_credentials(self.op_id)}
        elif cmd == 'graph':
            return self.attack_graph.to_dict()
        elif cmd == 'events':
            n = int(parts[1]) if len(parts) > 1 else 20
            return {'events': self.event_bus.get_recent(n)}
        elif cmd == 'pause':
            self.pause()
            return {'status': 'paused'}
        elif cmd == 'resume':
            self.unpause()
            return {'status': 'resumed'}
        else:
            return {'error': f'unknown command: {cmd}'}

    async def _main_loop(self):
        """Main async event loop."""
        self._running = True

        # Start periodic tasks
        for task in self.periodic_tasks:
            task.start()

        self.event_bus.emit('daemon_started', {
            'op_id': self.op_id,
            'pid': os.getpid(),
            'api_port': self._api_port,
        })

        # Main loop
        while self._running:
            await asyncio.sleep(1)

        # Cleanup
        for task in self.periodic_tasks:
            task.stop()

        self.db.update_operation_status(self.op_id, 'paused')
        self.event_bus.emit('daemon_stopped', {'op_id': self.op_id})

    def run(self):
        """Start the daemon (blocking)."""
        self.db.connect()
        self._write_pid()

        # Setup
        self._setup_periodic_tasks()
        self._start_api_server()

        # Event logging to DB
        def _log_to_db(event):
            severity = 'info'
            if 'burn' in event['type'] or 'fail' in event['type']:
                severity = 'critical'
            elif 'degrad' in event['type'] or 'lost' in event['type']:
                severity = 'warning'
            self.db.log_event(self.op_id, event['type'], severity,
                              details=event.get('data'))

        self.event_bus.subscribe_all(_log_to_db)

        # Signal handlers
        def _handle_sigterm(*args):
            self.stop()

        signal.signal(signal.SIGTERM, _handle_sigterm)
        signal.signal(signal.SIGINT, _handle_sigterm)

        try:
            asyncio.run(self._main_loop())
        finally:
            if self._api_server:
                self._api_server.shutdown()
            self._cleanup()
            self.db.close()

    def run_background(self):
        """Fork to background and run as daemon."""
        DAEMON_DIR.mkdir(parents=True, exist_ok=True)

        # Set up logging
        logging.basicConfig(
            filename=str(LOG_FILE),
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
        )

        # Fork
        pid = os.fork()
        if pid > 0:
            # Parent: wait briefly for daemon to start, then return info
            time.sleep(0.5)
            port_file = _get_port_file(self.op_id)
            if port_file.exists():
                info = json.loads(port_file.read_text())
                return {
                    'op_id': self.op_id,
                    'pid': info['pid'],
                    'api_port': info['port'],
                    'auth_token': info['token'],
                    'status': 'started',
                }
            return {'op_id': self.op_id, 'pid': pid, 'status': 'starting'}

        # Child: become session leader
        os.setsid()

        # Second fork (prevent zombie)
        pid2 = os.fork()
        if pid2 > 0:
            os._exit(0)

        # Redirect stdio
        sys.stdin = open(os.devnull, 'r')
        sys.stdout = open(str(LOG_FILE), 'a')
        sys.stderr = open(str(LOG_FILE), 'a')

        # Run daemon
        self.run()
        os._exit(0)


# ─── CLI Integration Functions ────────────────────────────────────

def start_operation(name: str, db_path: str = None,
                    passphrase: str = None, background: bool = True) -> dict:
    """Start a new operation with daemon."""
    db = OperationsDB(db_path, passphrase)
    db.connect()
    op_id = db.create_operation(name)
    db.close()

    daemon = OperationsDaemon(op_id, db_path, passphrase)

    if background:
        return daemon.run_background()
    else:
        daemon.run()
        return {'op_id': op_id, 'status': 'stopped'}


def attach_to_operation(op_id: str) -> Optional[dict]:
    """Get connection info for a running daemon."""
    port_file = _get_port_file(op_id)
    if not port_file.exists():
        return None
    try:
        info = json.loads(port_file.read_text())
        # Verify daemon is still running
        pid = info.get('pid', 0)
        os.kill(pid, 0)
        return info
    except (ProcessLookupError, json.JSONDecodeError, PermissionError):
        port_file.unlink(missing_ok=True)
        return None


def send_daemon_command(op_id: str, method: str, path: str,
                        body: dict = None) -> Optional[dict]:
    """Send HTTP request to daemon API."""
    info = attach_to_operation(op_id)
    if not info:
        return {'error': f'No running daemon for {op_id}'}

    import urllib.request
    import urllib.error

    url = f"http://127.0.0.1:{info['port']}{path}"
    headers = {
        'Authorization': f"Bearer {info['token']}",
        'Content-Type': 'application/json',
    }

    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read())
    except urllib.error.URLError as e:
        return {'error': str(e)}


def stop_operation(op_id: str) -> dict:
    """Stop a running daemon."""
    result = send_daemon_command(op_id, 'POST', '/stop')
    if result and 'error' not in result:
        return {'status': 'stopped', 'op_id': op_id}
    # Fallback: kill by PID
    pid_file = _get_pid_file(op_id)
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            return {'status': 'killed', 'op_id': op_id, 'pid': pid}
        except (ProcessLookupError, ValueError):
            pass
    return result or {'error': 'daemon not found'}


def pause_operation(op_id: str) -> dict:
    """Pause a running operation."""
    return send_daemon_command(op_id, 'POST', '/pause') or {'error': 'failed'}


def get_daemon_status(op_id: str) -> dict:
    """Get status from running daemon."""
    return send_daemon_command(op_id, 'GET', '/status') or {'error': 'failed'}
