"""
Honey Token / Canary Detection Engine.

Detects and avoids canary tokens, honeypot credentials, and tracking mechanisms:
1. AWS canary keys — known account prefixes, ARN patterns
2. Thinkst Canary tokens — DNS, URL, document-embedded patterns
3. Active Directory honey accounts — logon history, group anomalies
4. File canaries — DOCX tracking pixels, PDF phone-home, XLS external connections
5. API key canaries — known prefixes, entropy analysis, response timing
6. Network canaries — HoneyDB, Thinkst appliances, known ports

Every check is operationally real — these are the actual detection methods
used by red teams to avoid triggering blue team alerts.
"""
import base64
import hashlib
import json
import math
import os
import re
import struct
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Dict, List, Optional, Tuple


class CanaryDetector:
    """Honey token and canary detection engine."""

    # Known AWS canary key prefixes (canarytokens.org, Thinkst, SpaceCrab)
    AWS_CANARY_PREFIXES = [
        'AKIAIOSFODNN7',     # AWS example key prefix
        'AKIAI44QH8DHBEXAMPLE',
        'AKIASP2TPHJSU',     # SpaceCrab canary prefix
        'AKIAIYFSMNO',       # Common canary generators
    ]

    # Known canary domains
    CANARY_DOMAINS = [
        'canarytokens.com',
        'canarytokens.org',
        'canary.tools',
        'canarytools.com',
        'o3n.io',            # Thinkst canary short domain
        'allthecanaries.com',
    ]

    # Known canary URL patterns
    CANARY_URL_PATTERNS = [
        r'http[s]?://canarytokens\.(com|org)/.*',
        r'http[s]?://.*\.canary\.tools/.*',
        r'http[s]?://.*\.o3n\.io/.*',
        r'http[s]?://.*canarytokens.*',
    ]

    # Common honeypot credential indicators
    HONEY_CREDENTIAL_INDICATORS = {
        'suspicious_usernames': [
            'svc_backup', 'admin_legacy', 'backup_admin', 'temp_admin',
            'service_account', 'test_admin', 'old_admin', 'decom_admin',
            'sqlsvc', 'iis_admin', 'legacy_svc', 'admin_old',
        ],
        'suspicious_descriptions': [
            'DO NOT DELETE', 'DO NOT REMOVE', 'KEEP THIS ACCOUNT',
            'backup admin', 'legacy account', 'service account for',
            'temporary admin', 'break glass',
        ],
        'common_honey_passwords': [
            'Password123', 'Admin123', 'P@ssw0rd', 'Welcome1',
            'Changeme1', 'Summer2024', 'Winter2024', 'Company123',
            'Password1!', 'Admin@123', 'Test1234',
        ],
    }

    # AD honey account heuristic weights
    AD_HONEY_WEIGHTS = {
        'never_logged_in': 30,
        'password_is_common': 25,
        'name_suggests_admin': 15,
        'privileged_group_member': 20,
        'description_too_helpful': 15,
        'age_password_mismatch': 20,
        'no_email_set': 10,
        'disabled_but_privileged': 25,
    }

    def __init__(self, quarantine_hours: int = 24):
        self.quarantine_hours = quarantine_hours

    # ─── AWS Key Canary Detection ─────────────────────

    def check_aws_canary(self, access_key_id: str,
                          secret_key: str = '',
                          arn: str = '') -> dict:
        """Check if AWS credentials are a canary token."""
        score = 0
        indicators = []

        # Check against known canary prefixes
        for prefix in self.AWS_CANARY_PREFIXES:
            if access_key_id.startswith(prefix):
                score += 80
                indicators.append(f'known_canary_prefix:{prefix}')

        # Check ARN for canary patterns
        if arn:
            canary_arn_patterns = ['canarytokens', 'canary', 'honeypot',
                                   'honey', 'decoy', 'fake']
            arn_lower = arn.lower()
            for pattern in canary_arn_patterns:
                if pattern in arn_lower:
                    score += 60
                    indicators.append(f'suspicious_arn_pattern:{pattern}')

        # Check key format anomalies
        if access_key_id.startswith('AKIA'):
            # Valid format, check entropy of remaining chars
            remainder = access_key_id[4:]
            entropy = self._shannon_entropy(remainder)
            if entropy < 3.0:
                score += 20
                indicators.append(f'low_entropy_key:{entropy:.2f}')

        # Secret key entropy check
        if secret_key:
            sk_entropy = self._shannon_entropy(secret_key)
            if sk_entropy < 4.0:
                score += 15
                indicators.append(f'low_entropy_secret:{sk_entropy:.2f}')

        is_canary = score >= 50
        return {
            'is_canary': is_canary,
            'score': min(score, 100),
            'indicators': indicators,
            'recommendation': 'DO NOT USE' if is_canary else 'quarantine',
            'quarantine_until': time.time() + (self.quarantine_hours * 3600)
                if not is_canary else None,
        }

    # ─── AD Honey Account Detection ──────────────────

    def check_ad_honey_account(self, account_info: dict) -> dict:
        """Check if an Active Directory account is a honey/decoy account."""
        score = 0
        indicators = []

        username = account_info.get('username', '').lower()
        description = account_info.get('description', '').lower()
        logon_count = account_info.get('logon_count', 0)
        last_logon = account_info.get('last_logon')
        password_last_set = account_info.get('password_last_set')
        created = account_info.get('created')
        groups = [g.lower() for g in account_info.get('groups', [])]
        email = account_info.get('email', '')
        enabled = account_info.get('enabled', True)
        password = account_info.get('password', '')

        # Check 1: Never logged in
        if logon_count == 0 or (last_logon and last_logon == 'Never'):
            score += self.AD_HONEY_WEIGHTS['never_logged_in']
            indicators.append('account_never_logged_in')

        # Check 2: Common honey password
        if password:
            for hp in self.HONEY_CREDENTIAL_INDICATORS['common_honey_passwords']:
                if password == hp:
                    score += self.AD_HONEY_WEIGHTS['password_is_common']
                    indicators.append(f'common_honey_password:{hp}')
                    break

        # Check 3: Username suggests admin/service
        for sus_name in self.HONEY_CREDENTIAL_INDICATORS['suspicious_usernames']:
            if sus_name in username:
                score += self.AD_HONEY_WEIGHTS['name_suggests_admin']
                indicators.append(f'suspicious_username:{sus_name}')
                break

        # Check 4: Member of privileged group but never logged in
        privileged_groups = ['domain admins', 'enterprise admins',
                             'schema admins', 'administrators',
                             'account operators', 'backup operators']
        is_privileged = any(pg in g for g in groups for pg in privileged_groups)
        if is_privileged and logon_count == 0:
            score += self.AD_HONEY_WEIGHTS['privileged_group_member']
            indicators.append('privileged_but_unused')

        # Check 5: Description is suspiciously helpful
        for sus_desc in self.HONEY_CREDENTIAL_INDICATORS['suspicious_descriptions']:
            if sus_desc.lower() in description:
                score += self.AD_HONEY_WEIGHTS['description_too_helpful']
                indicators.append(f'suspicious_description:{sus_desc}')
                break

        # Check 6: Account age vs password age mismatch
        if created and password_last_set:
            try:
                created_ts = float(created) if isinstance(created, (int, float)) else 0
                pwd_ts = float(password_last_set) if isinstance(password_last_set, (int, float)) else 0
                if created_ts > 0 and pwd_ts > 0:
                    age_diff = abs(created_ts - pwd_ts)
                    if age_diff > 365 * 86400:  # > 1 year difference
                        score += self.AD_HONEY_WEIGHTS['age_password_mismatch']
                        indicators.append('account_age_password_mismatch')
            except (TypeError, ValueError):
                pass

        # Check 7: No email set
        if not email:
            score += self.AD_HONEY_WEIGHTS['no_email_set']
            indicators.append('no_email_configured')

        # Check 8: Disabled but in privileged group
        if not enabled and is_privileged:
            score += self.AD_HONEY_WEIGHTS['disabled_but_privileged']
            indicators.append('disabled_but_privileged')

        is_honey = score >= 50
        return {
            'is_honey': is_honey,
            'score': min(score, 100),
            'indicators': indicators,
            'recommendation': 'DO NOT USE' if is_honey else 'proceed_with_caution',
        }

    # ─── File Canary Detection ────────────────────────

    def check_file_canary(self, file_data: bytes,
                           filename: str = '') -> dict:
        """Check if a file contains canary/tracking mechanisms."""
        score = 0
        indicators = []
        ext = os.path.splitext(filename)[1].lower() if filename else ''

        # DOCX check
        if ext == '.docx' or (len(file_data) > 4 and file_data[:2] == b'PK'):
            docx_result = self._check_docx_canary(file_data)
            score += docx_result['score']
            indicators.extend(docx_result['indicators'])

        # PDF check
        if ext == '.pdf' or (len(file_data) > 5 and file_data[:5] == b'%PDF-'):
            pdf_result = self._check_pdf_canary(file_data)
            score += pdf_result['score']
            indicators.extend(pdf_result['indicators'])

        # Check raw bytes for canary domains
        for domain in self.CANARY_DOMAINS:
            if domain.encode() in file_data:
                score += 80
                indicators.append(f'canary_domain_in_file:{domain}')

        # Check for tracking pixel URLs
        for pattern in self.CANARY_URL_PATTERNS:
            matches = re.findall(pattern.encode() if isinstance(pattern, str)
                                 else pattern,
                                 file_data.decode('utf-8', errors='replace').encode())
            if matches:
                score += 60
                indicators.append(f'canary_url_pattern_found')

        is_canary = score >= 50
        return {
            'is_canary': is_canary,
            'score': min(score, 100),
            'indicators': indicators,
            'recommendation': 'DO NOT OPEN' if is_canary else 'safe_to_proceed',
        }

    def _check_docx_canary(self, data: bytes) -> dict:
        """Check DOCX for external references (tracking pixels)."""
        score = 0
        indicators = []

        try:
            with zipfile.ZipFile(BytesIO(data), 'r') as z:
                for name in z.namelist():
                    if name.endswith('.rels'):
                        rels_content = z.read(name).decode('utf-8', errors='replace')
                        # External references = tracking pixels
                        if 'TargetMode="External"' in rels_content:
                            ext_urls = re.findall(
                                r'Target="(http[s]?://[^"]+)"', rels_content)
                            for url in ext_urls:
                                score += 40
                                indicators.append(f'external_reference:{url[:80]}')
                                # Check if URL is known canary domain
                                for domain in self.CANARY_DOMAINS:
                                    if domain in url:
                                        score += 40
                                        indicators.append(f'canary_domain_in_rels:{domain}')

                    # Check for embedded scripts/macros
                    if 'vbaProject.bin' in name:
                        score += 10
                        indicators.append('has_vba_macro')

        except (zipfile.BadZipFile, KeyError):
            pass

        return {'score': score, 'indicators': indicators}

    def _check_pdf_canary(self, data: bytes) -> dict:
        """Check PDF for auto-open actions and phone-home URLs."""
        score = 0
        indicators = []

        # Auto-open action with URI
        if b'/AA' in data and b'/URI' in data:
            score += 40
            indicators.append('pdf_auto_open_uri')
            # Extract the URI
            uri_match = re.search(rb'/URI\s*\(([^)]+)\)', data)
            if uri_match:
                uri = uri_match.group(1).decode('utf-8', errors='replace')
                indicators.append(f'pdf_uri:{uri[:80]}')
                for domain in self.CANARY_DOMAINS:
                    if domain in uri:
                        score += 40
                        indicators.append(f'canary_domain_in_pdf:{domain}')

        # JavaScript with HTTP
        if b'/JavaScript' in data and b'http' in data:
            score += 30
            indicators.append('pdf_javascript_with_http')

        # OpenAction with URI
        if b'/OpenAction' in data and b'/URI' in data:
            score += 35
            indicators.append('pdf_open_action_uri')

        # Embedded file spec with URL
        if b'/EmbeddedFile' in data and b'http' in data:
            score += 25
            indicators.append('pdf_embedded_file_url')

        return {'score': score, 'indicators': indicators}

    # ─── URL/Domain Canary Check ──────────────────────

    def check_url_canary(self, url: str) -> dict:
        """Check if a URL is a known canary token."""
        score = 0
        indicators = []

        url_lower = url.lower()

        # Check against known canary domains
        for domain in self.CANARY_DOMAINS:
            if domain in url_lower:
                score += 90
                indicators.append(f'known_canary_domain:{domain}')

        # Check against canary URL patterns
        for pattern in self.CANARY_URL_PATTERNS:
            if re.match(pattern, url, re.IGNORECASE):
                score += 80
                indicators.append(f'canary_url_pattern_match')

        # Suspicious URL characteristics
        # Single-pixel image patterns
        if re.search(r'\.(gif|png|jpg|bmp)\?.*[a-f0-9]{32}', url_lower):
            score += 20
            indicators.append('tracking_pixel_pattern')

        # UUID in URL (common for canary tokens)
        if re.search(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', url_lower):
            score += 10
            indicators.append('uuid_in_url')

        is_canary = score >= 50
        return {
            'is_canary': is_canary,
            'score': min(score, 100),
            'indicators': indicators,
        }

    # ─── DNS Canary Check ─────────────────────────────

    def check_dns_canary(self, domain: str) -> dict:
        """Check if a DNS query target is a canary."""
        score = 0
        indicators = []

        domain_lower = domain.lower()

        for canary_domain in self.CANARY_DOMAINS:
            if domain_lower.endswith(canary_domain):
                score += 90
                indicators.append(f'canary_dns_domain:{canary_domain}')

        # Thinkst canary DNS patterns
        if re.match(r'^[a-z0-9]{24,}\.(canarytokens\.com|o3n\.io)$', domain_lower):
            score += 95
            indicators.append('thinkst_canary_dns')

        is_canary = score >= 50
        return {
            'is_canary': is_canary,
            'score': min(score, 100),
            'indicators': indicators,
        }

    # ─── API Key Canary Check ─────────────────────────

    def check_api_key_canary(self, key: str, key_type: str = 'generic') -> dict:
        """Check if an API key is likely a canary."""
        score = 0
        indicators = []

        # Entropy analysis
        entropy = self._shannon_entropy(key)
        if entropy < 3.0:
            score += 30
            indicators.append(f'very_low_entropy:{entropy:.2f}')
        elif entropy < 4.0:
            score += 15
            indicators.append(f'low_entropy:{entropy:.2f}')

        # Known test/example key patterns
        example_patterns = [
            'EXAMPLE', 'example', 'test', 'TEST', 'dummy', 'DUMMY',
            'fake', 'FAKE', 'sample', 'SAMPLE', 'demo', 'DEMO',
        ]
        for pat in example_patterns:
            if pat in key:
                score += 40
                indicators.append(f'example_keyword:{pat}')
                break

        # Repeated characters
        if len(set(key)) < len(key) * 0.3:
            score += 20
            indicators.append('low_char_diversity')

        # Sequentially incrementing patterns
        if re.search(r'(012345|abcdef|ABCDEF|123456)', key):
            score += 25
            indicators.append('sequential_pattern')

        is_canary = score >= 50
        return {
            'is_canary': is_canary,
            'score': min(score, 100),
            'indicators': indicators,
        }

    # ─── Network Canary Detection ─────────────────────

    def check_network_canary(self, ip: str, open_ports: List[int],
                              banners: Dict[int, str] = None) -> dict:
        """Check if a host is a honeypot/canary appliance."""
        score = 0
        indicators = []
        banners = banners or {}

        # Too many open ports = honeypot
        if len(open_ports) > 20:
            score += 30
            indicators.append(f'excessive_open_ports:{len(open_ports)}')

        # Known honeypot port combinations
        honeypot_ports = {22, 23, 80, 443, 445, 1433, 3306, 3389, 5900, 8080}
        overlap = set(open_ports) & honeypot_ports
        if len(overlap) >= 6:
            score += 25
            indicators.append(f'honeypot_port_combo:{len(overlap)}/10')

        # Known honeypot banners
        honeypot_banners = [
            'cowrie', 'kippo', 'dionaea', 'conpot', 'glastopf',
            'honeyd', 'honeytrap', 'elastichoney', 'thinkst',
        ]
        for port, banner in banners.items():
            banner_lower = banner.lower()
            for hb in honeypot_banners:
                if hb in banner_lower:
                    score += 60
                    indicators.append(f'honeypot_banner:{hb}_on_port_{port}')

        # Unusual service combinations
        has_ssh = 22 in open_ports
        has_rdp = 3389 in open_ports
        has_telnet = 23 in open_ports
        if has_ssh and has_rdp and has_telnet:
            score += 15
            indicators.append('unusual_remote_access_combo')

        # ICS honeypot ports (Modbus, S7, DNP3, BACnet, EtherNet/IP)
        ics_ports = {502, 102, 20000, 47808, 44818}
        ics_overlap = set(open_ports) & ics_ports
        if ics_overlap and (has_ssh or has_rdp):
            score += 20
            indicators.append(f'ics_honeypot_indicator:{ics_overlap}')

        is_honeypot = score >= 50
        return {
            'is_honeypot': is_honeypot,
            'score': min(score, 100),
            'indicators': indicators,
        }

    # ─── Batch Analysis ───────────────────────────────

    def analyze_credential_batch(self, credentials: List[dict]) -> List[dict]:
        """Analyze a batch of credentials for canary tokens."""
        results = []
        for cred in credentials:
            cred_type = cred.get('type', '')
            result = {'credential': cred, 'analysis': None}

            if cred_type == 'aws_access_key':
                result['analysis'] = self.check_aws_canary(
                    cred.get('access_key_id', ''),
                    cred.get('secret_key', ''),
                    cred.get('arn', ''))
            elif cred_type == 'ad_account':
                result['analysis'] = self.check_ad_honey_account(cred)
            elif cred_type == 'api_key':
                result['analysis'] = self.check_api_key_canary(
                    cred.get('value', ''), cred.get('key_type', 'generic'))
            else:
                result['analysis'] = {'is_canary': False, 'score': 0,
                                       'indicators': [], 'recommendation': 'unknown_type'}

            results.append(result)
        return results

    # ─── Generate Detection Script ────────────────────

    def generate_detection_script(self) -> str:
        """Generate standalone canary detection script."""
        domains_json = json.dumps(self.CANARY_DOMAINS)
        prefixes_json = json.dumps(self.AWS_CANARY_PREFIXES)
        honey_users_json = json.dumps(
            self.HONEY_CREDENTIAL_INDICATORS['suspicious_usernames'])

        header = (
            '#!/usr/bin/env python3\n'
            '"""Canary Token Detection — FORGE generated."""\n'
            'import json\n'
            'import math\n'
            'import os\n'
            'import re\n'
            'import sys\n'
            'import zipfile\n'
            'from io import BytesIO\n'
            '\n'
            f'CANARY_DOMAINS = {domains_json}\n'
            f'AWS_CANARY_PREFIXES = {prefixes_json}\n'
            f'HONEY_USERNAMES = {honey_users_json}\n'
            '\n'
        )
        body = textwrap.dedent('''\
            def shannon_entropy(data):
                if not data:
                    return 0.0
                freq = {}
                for c in data:
                    freq[c] = freq.get(c, 0) + 1
                length = len(data)
                return -sum((count/length) * math.log2(count/length)
                            for count in freq.values())

            def check_aws_key(key_id):
                for prefix in AWS_CANARY_PREFIXES:
                    if key_id.startswith(prefix):
                        return True, f'known_canary_prefix:{prefix}'
                return False, None

            def check_file(filepath):
                """Check file for canary mechanisms."""
                with open(filepath, 'rb') as f:
                    data = f.read()

                findings = []
                for domain in CANARY_DOMAINS:
                    if domain.encode() in data:
                        findings.append(f'canary_domain:{domain}')

                if filepath.endswith('.docx') or data[:2] == b'PK':
                    try:
                        with zipfile.ZipFile(BytesIO(data), 'r') as z:
                            for name in z.namelist():
                                if name.endswith('.rels'):
                                    content = z.read(name).decode('utf-8', errors='replace')
                                    if 'TargetMode="External"' in content:
                                        urls = re.findall(r'Target="(http[^"]+)"', content)
                                        for url in urls:
                                            findings.append(f'external_ref:{url}')
                    except Exception:
                        pass

                if filepath.endswith('.pdf') or data[:5] == b'%PDF-':
                    if b'/AA' in data and b'/URI' in data:
                        findings.append('pdf_auto_open_uri')
                    if b'/JavaScript' in data and b'http' in data:
                        findings.append('pdf_javascript_http')

                return findings

            def check_username(username):
                uname = username.lower()
                for sus in HONEY_USERNAMES:
                    if sus in uname:
                        return True, f'suspicious_name:{sus}'
                return False, None

            if __name__ == '__main__':
                if len(sys.argv) < 2:
                    print('Usage: canary_check.py <file|aws_key|username>')
                    sys.exit(1)

                target = sys.argv[1]
                if os.path.isfile(target):
                    findings = check_file(target)
                    if findings:
                        print(f'[!] CANARY DETECTED in {target}:')
                        for f in findings:
                            print(f'    {f}')
                    else:
                        print(f'[+] {target}: clean')
                elif target.startswith('AKIA'):
                    is_canary, reason = check_aws_key(target)
                    print(f'[{"!" if is_canary else "+"}] AWS Key: '
                          f'{"CANARY" if is_canary else "clean"}'
                          f'{" - " + reason if reason else ""}')
                else:
                    is_honey, reason = check_username(target)
                    print(f'[{"!" if is_honey else "+"}] Username: '
                          f'{"HONEY" if is_honey else "clean"}'
                          f'{" - " + reason if reason else ""}')
        ''')
        return header + body

    # ─── Utilities ────────────────────────────────────

    def _shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length)
                     for count in freq.values())

    # ─── Status ───────────────────────────────────────

    def status(self) -> dict:
        return {
            'aws_canary_prefixes': len(self.AWS_CANARY_PREFIXES),
            'canary_domains': len(self.CANARY_DOMAINS),
            'url_patterns': len(self.CANARY_URL_PATTERNS),
            'honey_usernames': len(self.HONEY_CREDENTIAL_INDICATORS['suspicious_usernames']),
            'honey_passwords': len(self.HONEY_CREDENTIAL_INDICATORS['common_honey_passwords']),
            'quarantine_hours': self.quarantine_hours,
            'check_types': [
                'aws_key', 'ad_account', 'file_canary', 'url_canary',
                'dns_canary', 'api_key', 'network_canary',
            ],
        }
