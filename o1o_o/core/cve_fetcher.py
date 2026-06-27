"""CVE/NVD Auto-Fetcher + Triplet Extractor.

Fetches CVE data from NVD API 2.0, parses vulnerability details,
and extracts causal triplets for FORGE's knowledge base.

Pipeline:
  NVD API → CVE JSON → Parse → Triplet Extraction → bridge_triplets.json

Supports:
  - Keyword search (e.g., "buffer overflow macOS")
  - CWE-based search (e.g., CWE-787)
  - Date range filtering
  - Offline mode with cached data
  - Rate-limited (NVD allows 5 req/30s without API key)

Part of FORGE Phase J: Self-Learning Pipeline.
"""
# Dependencies: none
# Depended by: fragment_synthesizer

import json
import os
import re
import time
import urllib.request
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


# ─── NVD API Configuration ──────────────────────────────────────────

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT_DELAY = 6.5  # seconds between requests (no API key)
CACHE_DIR = os.path.join(os.path.dirname(__file__), '..', 'knowledge', 'cve_cache')


# ─── CWE → Exploit Primitive Mapping ────────────────────────────────

CWE_TO_PRIMITIVE = {
    # Write primitives
    'CWE-787': 'write',       # Out-of-bounds Write
    'CWE-122': 'write',       # Heap-based Buffer Overflow
    'CWE-121': 'write',       # Stack-based Buffer Overflow
    'CWE-120': 'write',       # Classic Buffer Overflow
    'CWE-119': 'write',       # Improper Buffer Restrictions
    'CWE-416': 'write',       # Use After Free
    'CWE-415': 'write',       # Double Free
    'CWE-190': 'write',       # Integer Overflow
    'CWE-191': 'write',       # Integer Underflow
    'CWE-823': 'write',       # Use of Out-of-range Pointer Offset
    'CWE-122': 'write',       # Heap Overflow
    'CWE-131': 'write',       # Incorrect Calculation of Buffer Size

    # Execute primitives
    'CWE-94': 'execute',      # Code Injection
    'CWE-78': 'execute',      # OS Command Injection
    'CWE-79': 'info_leak',    # XSS (usually info leak first)
    'CWE-434': 'execute',     # Unrestricted Upload of Dangerous File Type
    'CWE-502': 'execute',     # Deserialization of Untrusted Data
    'CWE-917': 'execute',     # Expression Language Injection
    'CWE-1321': 'execute',    # Prototype Pollution
    'CWE-77': 'execute',      # Command Injection

    # Info leak primitives
    'CWE-125': 'info_leak',   # Out-of-bounds Read
    'CWE-200': 'info_leak',   # Exposure of Sensitive Information
    'CWE-209': 'info_leak',   # Generation of Error Message with Sensitive Info
    'CWE-532': 'info_leak',   # Insertion of Sensitive Info into Log File
    'CWE-908': 'info_leak',   # Use of Uninitialized Resource
    'CWE-457': 'info_leak',   # Use of Uninitialized Variable
    'CWE-824': 'info_leak',   # Uninitialized Pointer
    'CWE-126': 'info_leak',   # Buffer Over-read

    # DoS primitives
    'CWE-476': 'dos',         # NULL Pointer Dereference
    'CWE-400': 'dos',         # Uncontrolled Resource Consumption
    'CWE-674': 'dos',         # Uncontrolled Recursion
    'CWE-835': 'dos',         # Loop with Unreachable Exit
    'CWE-770': 'dos',         # Allocation without Limits
    'CWE-20': 'dos',          # Improper Input Validation (typically DoS)
    'CWE-369': 'dos',         # Divide By Zero
    'CWE-617': 'dos',         # Reachable Assertion

    # Privilege escalation
    'CWE-269': 'privilege_escalation',   # Improper Privilege Management
    'CWE-250': 'privilege_escalation',   # Execution with Unnecessary Privileges
    'CWE-732': 'privilege_escalation',   # Incorrect Permission Assignment
    'CWE-862': 'privilege_escalation',   # Missing Authorization
    'CWE-863': 'privilege_escalation',   # Incorrect Authorization

    # Auth bypass
    'CWE-287': 'auth_bypass',  # Improper Authentication
    'CWE-306': 'auth_bypass',  # Missing Authentication
    'CWE-307': 'auth_bypass',  # Improper Restriction of Auth Attempts
}

# ─── Platform keyword detection ──────────────────────────────────────

PLATFORM_KEYWORDS = {
    'macos': ['macos', 'mac os', 'darwin', 'apple', 'xnu', 'iokit', 'coreaudio',
              'coregraphics', 'webkit', 'safari', 'appkit', 'foundation'],
    'ios': ['ios', 'iphone', 'ipad', 'ipados', 'mobile safari', 'springboard'],
    'linux': ['linux', 'kernel', 'glibc', 'systemd', 'ubuntu', 'debian',
              'centos', 'rhel', 'fedora', 'arch linux'],
    'windows': ['windows', 'win32', 'ntfs', 'mshtml', 'edge', 'ie11',
                'win32k', 'ntoskrnl', 'smb', 'rdp', 'active directory'],
    'android': ['android', 'dalvik', 'bionic', 'surfaceflinger', 'binder'],
}


class CVEEntry:
    """Parsed CVE entry with all relevant fields."""

    def __init__(self):
        self.cve_id: str = ''
        self.description: str = ''
        self.cvss_v3_score: float = 0.0
        self.cvss_v3_vector: str = ''
        self.cvss_severity: str = ''
        self.cwes: List[str] = []
        self.affected_products: List[str] = []
        self.platforms: List[str] = []
        self.published: str = ''
        self.modified: str = ''
        self.references: List[str] = []
        self.exploit_primitive: str = ''
        self.attack_vector: str = ''
        self.raw: Dict = {}

    def __repr__(self):
        return (f"CVE({self.cve_id}, CVSS={self.cvss_v3_score}, "
                f"CWE={','.join(self.cwes)}, prim={self.exploit_primitive})")


class CVEFetcher:
    """Fetch and parse CVEs from NVD API 2.0."""

    def __init__(self, api_key: str = '', cache_dir: str = CACHE_DIR):
        self.api_key = api_key
        self.cache_dir = os.path.abspath(cache_dir)
        os.makedirs(self.cache_dir, exist_ok=True)
        self._last_request_time = 0

    def search(self, keyword: str = '', cwe_id: str = '',
               cvss_min: float = 0.0, results_per_page: int = 20,
               start_index: int = 0,
               use_cache: bool = True) -> List[CVEEntry]:
        """Search NVD for CVEs matching criteria.

        Args:
            keyword: Search keyword (e.g., "buffer overflow macOS")
            cwe_id: CWE identifier (e.g., "CWE-787")
            cvss_min: Minimum CVSS v3 score
            results_per_page: Max results (1-2000)
            start_index: Pagination offset
            use_cache: Use cached results if available

        Returns:
            List of CVEEntry objects
        """
        # Build cache key
        cache_key = f"search_{keyword}_{cwe_id}_{cvss_min}_{start_index}"
        cache_key = re.sub(r'[^\w]', '_', cache_key)
        cache_path = os.path.join(self.cache_dir, f"{cache_key}.json")

        # Check cache
        if use_cache and os.path.exists(cache_path):
            cache_age = time.time() - os.path.getmtime(cache_path)
            if cache_age < 86400:  # 24 hour cache
                with open(cache_path) as f:
                    data = json.load(f)
                return self._parse_response(data)

        # Build query
        params = {
            'resultsPerPage': min(results_per_page, 2000),
            'startIndex': start_index,
        }

        if keyword:
            params['keywordSearch'] = keyword

        if cwe_id:
            params['cweId'] = cwe_id

        if cvss_min > 0:
            params['cvssV3Severity'] = (
                'LOW' if cvss_min < 4.0 else
                'MEDIUM' if cvss_min < 7.0 else
                'HIGH' if cvss_min < 9.0 else
                'CRITICAL')

        # Rate limit
        self._rate_limit()

        # Fetch
        url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"
        headers = {'Accept': 'application/json'}
        if self.api_key:
            headers['apiKey'] = self.api_key

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
        except Exception as e:
            # Try cache even if expired
            if os.path.exists(cache_path):
                with open(cache_path) as f:
                    data = json.load(f)
                return self._parse_response(data)
            raise RuntimeError(f"NVD API error: {e}")

        # Cache response
        with open(cache_path, 'w') as f:
            json.dump(data, f)

        return self._parse_response(data)

    def fetch_cve(self, cve_id: str, use_cache: bool = True) -> Optional[CVEEntry]:
        """Fetch a single CVE by ID (e.g., CVE-2024-1234)."""
        cache_path = os.path.join(self.cache_dir, f"{cve_id}.json")

        if use_cache and os.path.exists(cache_path):
            with open(cache_path) as f:
                data = json.load(f)
            entries = self._parse_response(data)
            return entries[0] if entries else None

        self._rate_limit()
        url = f"{NVD_API_BASE}?cveId={cve_id}"
        headers = {'Accept': 'application/json'}
        if self.api_key:
            headers['apiKey'] = self.api_key

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
        except Exception as e:
            if os.path.exists(cache_path):
                with open(cache_path) as f:
                    data = json.load(f)
                entries = self._parse_response(data)
                return entries[0] if entries else None
            return None

        with open(cache_path, 'w') as f:
            json.dump(data, f)

        entries = self._parse_response(data)
        return entries[0] if entries else None

    def _rate_limit(self):
        """Enforce NVD rate limit."""
        delay = RATE_LIMIT_DELAY if not self.api_key else 0.6
        elapsed = time.time() - self._last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request_time = time.time()

    def _parse_response(self, data: Dict) -> List[CVEEntry]:
        """Parse NVD API response into CVEEntry objects."""
        entries = []
        for vuln in data.get('vulnerabilities', []):
            cve_data = vuln.get('cve', {})
            entry = CVEEntry()
            entry.raw = cve_data

            entry.cve_id = cve_data.get('id', '')
            entry.published = cve_data.get('published', '')
            entry.modified = cve_data.get('lastModified', '')

            # Description (English)
            for desc in cve_data.get('descriptions', []):
                if desc.get('lang') == 'en':
                    entry.description = desc.get('value', '')
                    break

            # CVSS v3
            metrics = cve_data.get('metrics', {})
            for cvss_key in ('cvssMetricV31', 'cvssMetricV30'):
                cvss_list = metrics.get(cvss_key, [])
                if cvss_list:
                    cvss = cvss_list[0].get('cvssData', {})
                    entry.cvss_v3_score = cvss.get('baseScore', 0.0)
                    entry.cvss_v3_vector = cvss.get('vectorString', '')
                    entry.cvss_severity = cvss.get('baseSeverity', '')
                    entry.attack_vector = cvss.get('attackVector', '')
                    break

            # CWEs
            for weakness in cve_data.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    cwe = desc.get('value', '')
                    if cwe.startswith('CWE-') and cwe not in entry.cwes:
                        entry.cwes.append(cwe)

            # Affected products (CPE)
            for config in cve_data.get('configurations', []):
                for node in config.get('nodes', []):
                    for match in node.get('cpeMatch', []):
                        cpe = match.get('criteria', '')
                        if cpe:
                            entry.affected_products.append(cpe)

            # References
            for ref in cve_data.get('references', []):
                entry.references.append(ref.get('url', ''))

            # Determine exploit primitive from CWEs
            for cwe in entry.cwes:
                if cwe in CWE_TO_PRIMITIVE:
                    entry.exploit_primitive = CWE_TO_PRIMITIVE[cwe]
                    break

            # If no CWE mapping, infer from description
            if not entry.exploit_primitive:
                entry.exploit_primitive = self._infer_primitive(entry.description)

            # Detect platforms
            desc_lower = entry.description.lower()
            for platform, keywords in PLATFORM_KEYWORDS.items():
                if any(kw in desc_lower for kw in keywords):
                    entry.platforms.append(platform)

            entries.append(entry)

        return entries

    @staticmethod
    def _infer_primitive(description: str) -> str:
        """Infer exploit primitive from CVE description text."""
        desc = description.lower()

        # Execute indicators
        if any(kw in desc for kw in ['arbitrary code', 'code execution',
                                      'remote code', 'rce', 'command injection',
                                      'execute arbitrary']):
            return 'execute'

        # Write indicators
        if any(kw in desc for kw in ['buffer overflow', 'heap overflow',
                                      'stack overflow', 'out-of-bounds write',
                                      'use after free', 'double free',
                                      'memory corruption']):
            return 'write'

        # Info leak indicators
        if any(kw in desc for kw in ['information disclosure', 'memory leak',
                                      'out-of-bounds read', 'sensitive information',
                                      'information exposure']):
            return 'info_leak'

        # DoS indicators
        if any(kw in desc for kw in ['denial of service', 'crash', 'null pointer',
                                      'assertion failure', 'infinite loop']):
            return 'dos'

        # Privilege escalation
        if any(kw in desc for kw in ['privilege escalation', 'elevated privileges',
                                      'gain root', 'local privilege']):
            return 'privilege_escalation'

        return 'unknown'


class TripletExtractor:
    """Extract causal triplets from CVE data for FORGE knowledge base."""

    def extract_from_cve(self, cve: CVEEntry) -> List[Dict]:
        """Extract causal triplets from a single CVE entry.

        Generates triplets like:
        - trigger → mechanism → outcome
        - vulnerability_type → enables → impact
        - cwe_class → causes → exploit_primitive
        """
        triplets = []

        if not cve.description:
            return triplets

        # 1. CWE → Primitive triplet
        for cwe in cve.cwes:
            primitive = CWE_TO_PRIMITIVE.get(cwe, '')
            if primitive:
                triplets.append({
                    'trigger': cwe.lower().replace('-', '_'),
                    'mechanism': 'causes',
                    'outcome': f'{primitive}_primitive',
                    'confidence': 0.90,
                    'source': cve.cve_id,
                })

        # 2. CVE description → Impact triplets
        desc = cve.description.lower()

        # Buffer overflow patterns
        if 'buffer overflow' in desc or 'out-of-bounds write' in desc:
            trigger = self._extract_trigger(desc, 'overflow')
            if trigger:
                triplets.append({
                    'trigger': trigger,
                    'mechanism': 'causes',
                    'outcome': 'heap_corruption',
                    'confidence': 0.85,
                    'source': cve.cve_id,
                })

        # Use-after-free patterns
        if 'use after free' in desc or 'use-after-free' in desc:
            trigger = self._extract_trigger(desc, 'use_after_free')
            if trigger:
                triplets.append({
                    'trigger': trigger,
                    'mechanism': 'causes',
                    'outcome': 'dangling_pointer',
                    'confidence': 0.85,
                    'source': cve.cve_id,
                })

        # Integer overflow patterns
        if 'integer overflow' in desc or 'integer underflow' in desc:
            trigger = self._extract_trigger(desc, 'integer_overflow')
            if trigger:
                triplets.append({
                    'trigger': trigger,
                    'mechanism': 'causes',
                    'outcome': 'incorrect_size_calculation',
                    'confidence': 0.80,
                    'source': cve.cve_id,
                })
                triplets.append({
                    'trigger': 'incorrect_size_calculation',
                    'mechanism': 'enables',
                    'outcome': 'heap_corruption',
                    'confidence': 0.75,
                    'source': cve.cve_id,
                })

        # 3. Attack vector → Impact
        if cve.attack_vector:
            av = cve.attack_vector.lower()
            if av == 'network':
                triplets.append({
                    'trigger': 'network_input',
                    'mechanism': 'reaches',
                    'outcome': cve.exploit_primitive or 'vulnerability',
                    'confidence': 0.80,
                    'source': cve.cve_id,
                })
            elif av == 'local':
                triplets.append({
                    'trigger': 'local_access',
                    'mechanism': 'reaches',
                    'outcome': cve.exploit_primitive or 'vulnerability',
                    'confidence': 0.80,
                    'source': cve.cve_id,
                })

        # 4. Platform-specific triplets
        for platform in cve.platforms:
            if cve.exploit_primitive:
                triplets.append({
                    'trigger': f'{platform}_vulnerability',
                    'mechanism': 'enables',
                    'outcome': f'{platform}_{cve.exploit_primitive}',
                    'confidence': 0.75,
                    'source': cve.cve_id,
                })

        # 5. CVSS-based severity triplet
        if cve.cvss_v3_score >= 9.0:
            triplets.append({
                'trigger': cve.exploit_primitive or 'vulnerability',
                'mechanism': 'rated',
                'outcome': 'critical_severity',
                'confidence': 0.95,
                'source': cve.cve_id,
            })
        elif cve.cvss_v3_score >= 7.0:
            triplets.append({
                'trigger': cve.exploit_primitive or 'vulnerability',
                'mechanism': 'rated',
                'outcome': 'high_severity',
                'confidence': 0.90,
                'source': cve.cve_id,
            })

        return triplets

    def extract_batch(self, cves: List[CVEEntry]) -> List[Dict]:
        """Extract triplets from a batch of CVEs, deduplicating."""
        all_triplets = []
        seen = set()

        for cve in cves:
            for triplet in self.extract_from_cve(cve):
                key = (triplet['trigger'], triplet['mechanism'], triplet['outcome'])
                if key not in seen:
                    seen.add(key)
                    all_triplets.append(triplet)

        return all_triplets

    @staticmethod
    def _extract_trigger(desc: str, vuln_type: str) -> str:
        """Extract the trigger component from CVE description.

        Looks for patterns like "X in Y allows..." or "A vulnerability in Z".
        """
        # Try "in <component>" pattern
        match = re.search(r'(?:vulnerability|issue|flaw|bug) in (\w+[\w\s]*?)(?:\s+(?:allows|could|enables|permits|may))', desc)
        if match:
            component = match.group(1).strip()[:40]
            return f'{vuln_type}_in_{component}'.replace(' ', '_').lower()

        # Try "<component> has" pattern
        match = re.search(r'(\w+[\w\s]*?) (?:has|contains|suffers from) (?:a|an) ', desc)
        if match:
            component = match.group(1).strip()[:40]
            return f'{vuln_type}_in_{component}'.replace(' ', '_').lower()

        return vuln_type

    def merge_into_bridge_triplets(self, new_triplets: List[Dict],
                                    bridge_path: str) -> int:
        """Merge extracted triplets into bridge_triplets.json.

        Returns count of new triplets added.
        """
        with open(bridge_path) as f:
            existing = json.load(f)

        existing_keys = {(t['trigger'], t['mechanism'], t['outcome'])
                         for t in existing}

        added = 0
        for t in new_triplets:
            key = (t['trigger'], t['mechanism'], t['outcome'])
            if key not in existing_keys:
                existing.append(t)
                existing_keys.add(key)
                added += 1

        if added > 0:
            with open(bridge_path, 'w') as f:
                json.dump(existing, f, indent=2)

        return added


def format_cve(cve: CVEEntry) -> str:
    """Format CVE entry for display."""
    lines = []
    severity_colors = {'CRITICAL': '💀', 'HIGH': '🔴', 'MEDIUM': '🟠', 'LOW': '🟡'}
    icon = severity_colors.get(cve.cvss_severity, '⚪')

    lines.append(f"{icon} {cve.cve_id} — CVSS {cve.cvss_v3_score} ({cve.cvss_severity})")
    lines.append(f"  CWE: {', '.join(cve.cwes) if cve.cwes else 'N/A'}")
    lines.append(f"  Primitive: {cve.exploit_primitive}")
    lines.append(f"  Platforms: {', '.join(cve.platforms) if cve.platforms else 'N/A'}")
    lines.append(f"  Published: {cve.published[:10]}")

    # Truncated description
    desc = cve.description
    if len(desc) > 200:
        desc = desc[:197] + '...'
    lines.append(f"  {desc}")

    return '\n'.join(lines)


if __name__ == '__main__':
    import sys

    fetcher = CVEFetcher()
    extractor = TripletExtractor()

    keyword = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else 'buffer overflow macOS'
    print(f"Searching NVD for: {keyword}")

    try:
        cves = fetcher.search(keyword=keyword, results_per_page=10)
        print(f"Found {len(cves)} CVEs\n")

        for cve in cves:
            print(format_cve(cve))
            print()

        # Extract triplets
        triplets = extractor.extract_batch(cves)
        print(f"\nExtracted {len(triplets)} triplets:")
        for t in triplets[:20]:
            print(f"  {t['trigger']} →[{t['mechanism']}]→ {t['outcome']} "
                  f"(conf={t['confidence']:.0%}, src={t.get('source', '')})")

    except Exception as e:
        print(f"Error: {e}")
        print("Try with cached data or check network connectivity.")
