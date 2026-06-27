"""Fragment Synthesizer: Auto-generate security fragments from CVE patterns.

When FORGE learns new vulnerability patterns from CVE data, this module
synthesizes detection/exploitation fragments, validates them in sandbox,
and stores them for future use.

Pipeline:
  CVE patterns → Template Selection → Code Generation → Sandbox Validation → Fragment Store

Part of FORGE Phase J: Self-Learning Pipeline.
"""
# Dependencies: cve_fetcher
# Depended by: none (leaf module)

import json
import os
import re
import subprocess
import tempfile
import textwrap
from typing import Any, Dict, List, Optional, Tuple


# ─── Fragment Templates ──────────────────────────────────────────────

# Templates for different vulnerability classes.
# Each template generates a complete, runnable Python module.

TEMPLATES = {
    'buffer_overflow_detector': {
        'cwes': ['CWE-787', 'CWE-122', 'CWE-121', 'CWE-120', 'CWE-119', 'CWE-131'],
        'primitive': 'write',
        'template': textwrap.dedent('''\
            """Buffer Overflow Detector — {cve_id}

            Detects potential buffer overflow conditions based on CVE pattern:
            {description}

            CWE: {cwes}
            CVSS: {cvss}
            """
            import struct
            import os
            import sys


            VULN_PATTERN = {{
                'cve': '{cve_id}',
                'cwes': {cwe_list},
                'primitive': 'write',
                'attack_vector': '{attack_vector}',
            }}


            def check_boundary_conditions(data, max_size):
                """Check for buffer boundary violations."""
                violations = []

                if len(data) > max_size:
                    violations.append({{
                        'type': 'overflow',
                        'actual_size': len(data),
                        'max_allowed': max_size,
                        'overflow_bytes': len(data) - max_size,
                    }})

                # Check for integer overflow in size calculation
                for multiplier in [2, 4, 8, 16]:
                    product = len(data) * multiplier
                    if product > 0xFFFFFFFF:
                        violations.append({{
                            'type': 'integer_overflow',
                            'size': len(data),
                            'multiplier': multiplier,
                            'wrapped_value': product & 0xFFFFFFFF,
                        }})

                return violations


            def generate_overflow_payload(target_size, overflow_amount=64):
                """Generate a test payload that overflows by specified amount."""
                # Pattern fill for easy offset identification
                payload = bytearray()
                for i in range(target_size + overflow_amount):
                    payload.append((i % 256))
                return bytes(payload)


            def analyze_binary_input(data):
                """Analyze binary input for potential overflow triggers."""
                results = {{
                    'total_size': len(data),
                    'findings': [],
                }}

                # Check for size fields in binary data
                if len(data) >= 4:
                    # Check 32-bit size fields
                    for offset in range(0, min(len(data) - 4, 64), 4):
                        size_le = struct.unpack_from('<I', data, offset)[0]
                        size_be = struct.unpack_from('>I', data, offset)[0]

                        for size_val, endian in [(size_le, 'LE'), (size_be, 'BE')]:
                            if size_val > len(data) and size_val < 0x10000000:
                                results['findings'].append({{
                                    'offset': offset,
                                    'endian': endian,
                                    'claimed_size': size_val,
                                    'actual_size': len(data),
                                    'overflow': size_val - len(data),
                                }})

                return results


            def demo():
                """Test buffer overflow detection."""
                print(f"Buffer Overflow Detector — {{VULN_PATTERN['cve']}}")

                # Test 1: Size boundary check
                data = b'A' * 1024
                violations = check_boundary_conditions(data, 512)
                print(f"  Boundary check: {{len(violations)}} violations")
                for v in violations:
                    print(f"    {{v['type']}}: {{v}}")

                # Test 2: Overflow payload
                payload = generate_overflow_payload(256, 32)
                print(f"  Payload: {{len(payload)}} bytes (256 + 32 overflow)")

                # Test 3: Binary analysis
                test_data = struct.pack('<I', 0x10000) + b'\\x00' * 64
                results = analyze_binary_input(test_data)
                print(f"  Binary analysis: {{len(results['findings'])}} findings")

                print("  Detection ready")


            demo()
        '''),
    },

    'uaf_detector': {
        'cwes': ['CWE-416', 'CWE-415'],
        'primitive': 'write',
        'template': textwrap.dedent('''\
            """Use-After-Free Detector — {cve_id}

            Detects potential UAF conditions based on CVE pattern:
            {description}

            CWE: {cwes}
            CVSS: {cvss}
            """
            import ctypes
            import weakref
            import sys


            VULN_PATTERN = {{
                'cve': '{cve_id}',
                'cwes': {cwe_list},
                'primitive': 'write',
                'attack_vector': '{attack_vector}',
            }}


            class LifetimeTracker:
                """Track object lifetimes to detect UAF patterns."""

                def __init__(self):
                    self.allocations = {{}}  # id -> (type, size, alive)
                    self.freed = set()
                    self.use_after_free = []

                def alloc(self, obj_id, obj_type, size):
                    self.allocations[obj_id] = {{
                        'type': obj_type, 'size': size, 'alive': True
                    }}

                def free(self, obj_id):
                    if obj_id in self.freed:
                        self.use_after_free.append({{
                            'type': 'double_free',
                            'id': obj_id,
                            'info': self.allocations.get(obj_id, {{}}),
                        }})
                    elif obj_id in self.allocations:
                        self.allocations[obj_id]['alive'] = False
                        self.freed.add(obj_id)
                    else:
                        self.use_after_free.append({{
                            'type': 'invalid_free',
                            'id': obj_id,
                        }})

                def access(self, obj_id):
                    if obj_id in self.freed:
                        self.use_after_free.append({{
                            'type': 'use_after_free',
                            'id': obj_id,
                            'info': self.allocations.get(obj_id, {{}}),
                        }})
                        return False
                    return True

                def report(self):
                    return {{
                        'total_allocations': len(self.allocations),
                        'freed': len(self.freed),
                        'violations': self.use_after_free,
                    }}


            def detect_weak_ref_uaf(obj):
                """Use weak references to detect UAF patterns."""
                ref = weakref.ref(obj)
                del obj
                return ref() is None  # True = properly freed


            def demo():
                """Test UAF detection."""
                print(f"Use-After-Free Detector — {{VULN_PATTERN['cve']}}")

                tracker = LifetimeTracker()

                # Simulate allocation pattern
                tracker.alloc('buf_0', 'buffer', 1024)
                tracker.alloc('buf_1', 'buffer', 2048)

                # Normal use
                assert tracker.access('buf_0')

                # Free buf_0
                tracker.free('buf_0')

                # Use after free
                tracker.access('buf_0')

                # Double free
                tracker.free('buf_0')

                report = tracker.report()
                print(f"  Allocations: {{report['total_allocations']}}")
                print(f"  Violations: {{len(report['violations'])}}")
                for v in report['violations']:
                    print(f"    {{v['type']}}: id={{v['id']}}")

                print("  Detection ready")


            demo()
        '''),
    },

    'integer_overflow_detector': {
        'cwes': ['CWE-190', 'CWE-191'],
        'primitive': 'write',
        'template': textwrap.dedent('''\
            """Integer Overflow Detector — {cve_id}

            Detects integer overflow/underflow conditions based on CVE pattern:
            {description}

            CWE: {cwes}
            CVSS: {cvss}
            """
            import struct
            import sys


            VULN_PATTERN = {{
                'cve': '{cve_id}',
                'cwes': {cwe_list},
                'primitive': 'write',
                'attack_vector': '{attack_vector}',
            }}

            INT32_MAX = 0x7FFFFFFF
            INT32_MIN = -0x80000000
            UINT32_MAX = 0xFFFFFFFF
            INT64_MAX = 0x7FFFFFFFFFFFFFFF
            UINT64_MAX = 0xFFFFFFFFFFFFFFFF


            def check_multiply_overflow(a, b, bits=32):
                """Check if a * b overflows at given bit width."""
                mask = (1 << bits) - 1
                product = a * b
                wrapped = product & mask
                return {{
                    'overflow': product != wrapped,
                    'original': product,
                    'wrapped': wrapped,
                    'bits': bits,
                }}


            def check_add_overflow(a, b, bits=32):
                """Check if a + b overflows at given bit width."""
                mask = (1 << bits) - 1
                total = a + b
                wrapped = total & mask
                return {{
                    'overflow': total != wrapped,
                    'original': total,
                    'wrapped': wrapped,
                    'bits': bits,
                }}


            def find_overflow_inputs(target_alloc_size, element_size, bits=32):
                """Find input count that causes malloc(count * element_size) to wrap."""
                mask = (1 << bits) - 1
                # We want: count * element_size > mask but (count * element_size) & mask < target
                candidates = []
                for wrap_mult in range(1, 10):
                    # count * element_size = mask * wrap_mult + target_alloc_size
                    total = mask * wrap_mult + target_alloc_size
                    if total % element_size == 0:
                        count = total // element_size
                        wrapped = (count * element_size) & mask
                        if wrapped == target_alloc_size:
                            candidates.append({{
                                'count': count,
                                'element_size': element_size,
                                'real_product': count * element_size,
                                'wrapped_product': wrapped,
                                'target': target_alloc_size,
                            }})
                return candidates


            def demo():
                """Test integer overflow detection."""
                print(f"Integer Overflow Detector — {{VULN_PATTERN['cve']}}")

                # Test multiply overflow
                result = check_multiply_overflow(0x80000001, 32, bits=32)
                print(f"  0x80000001 * 32 @ 32-bit: overflow={{result['overflow']}}, "
                      f"wrapped=0x{{result['wrapped']:x}}")

                # Find exploitable overflow inputs
                candidates = find_overflow_inputs(target_alloc_size=64, element_size=32, bits=32)
                print(f"  Overflow inputs for malloc(n*32) → 64: {{len(candidates)}} found")
                for c in candidates[:3]:
                    print(f"    count={{c['count']}}, product={{c['real_product']}}, "
                          f"wraps to={{c['wrapped_product']}}")

                print("  Detection ready")


            demo()
        '''),
    },

    'null_deref_detector': {
        'cwes': ['CWE-476'],
        'primitive': 'dos',
        'template': textwrap.dedent('''\
            """NULL Pointer Dereference Detector — {cve_id}

            Detects NULL dereference patterns based on CVE:
            {description}

            CWE: {cwes}
            CVSS: {cvss}
            """
            import os
            import sys


            VULN_PATTERN = {{
                'cve': '{cve_id}',
                'cwes': {cwe_list},
                'primitive': 'dos',
                'attack_vector': '{attack_vector}',
            }}


            def analyze_null_deref_pattern(code_lines):
                """Analyze code for NULL dereference patterns."""
                findings = []

                null_patterns = [
                    (r'if\\s*\\(.*==\\s*NULL\\)', 'null_check_before_use'),
                    (r'\\.\\w+\\s*=.*malloc', 'malloc_without_null_check'),
                    (r'return\\s+NULL', 'function_returns_null'),
                ]

                for i, line in enumerate(code_lines):
                    for pattern, ptype in null_patterns:
                        import re
                        if re.search(pattern, line):
                            findings.append({{
                                'line': i + 1,
                                'type': ptype,
                                'code': line.strip(),
                            }})

                return findings


            def generate_null_trigger():
                """Generate input that may cause NULL returns."""
                triggers = [
                    b'',           # empty input
                    b'\\x00',       # null byte
                    b'\\x00' * 256, # all nulls
                    b'\\xff' * 4,   # invalid size
                ]
                return triggers


            def demo():
                """Test NULL dereference detection."""
                print(f"NULL Deref Detector — {{VULN_PATTERN['cve']}}")

                sample_code = [
                    'buf = malloc(size);',
                    'buf->data = input;',  # no null check!
                    'if (buf == NULL) return -1;',
                    'ptr = lookup(key);',
                    'result = ptr->value;',  # no null check!
                ]

                findings = analyze_null_deref_pattern(sample_code)
                print(f"  Analyzed {{len(sample_code)}} lines, {{len(findings)}} findings")
                for f in findings:
                    print(f"    Line {{f['line']}}: {{f['type']}}")

                triggers = generate_null_trigger()
                print(f"  Generated {{len(triggers)}} NULL trigger inputs")

                print("  Detection ready")


            demo()
        '''),
    },

    'info_leak_detector': {
        'cwes': ['CWE-125', 'CWE-200', 'CWE-908', 'CWE-457'],
        'primitive': 'info_leak',
        'template': textwrap.dedent('''\
            """Information Leak Detector — {cve_id}

            Detects OOB read and info leak patterns based on CVE:
            {description}

            CWE: {cwes}
            CVSS: {cvss}
            """
            import struct
            import os


            VULN_PATTERN = {{
                'cve': '{cve_id}',
                'cwes': {cwe_list},
                'primitive': 'info_leak',
                'attack_vector': '{attack_vector}',
            }}


            def check_oob_read(data, offset, read_size):
                """Check if read goes out of bounds."""
                if offset + read_size > len(data):
                    return {{
                        'oob': True,
                        'data_size': len(data),
                        'read_end': offset + read_size,
                        'oob_bytes': (offset + read_size) - len(data),
                    }}
                return {{'oob': False}}


            def detect_uninitialized_patterns(data, pattern_size=4):
                """Detect patterns that suggest uninitialized memory."""
                patterns = {{
                    b'\\xcd' * pattern_size: 'MSVC_DEBUG_UNINIT',
                    b'\\xdd' * pattern_size: 'MSVC_FREED_HEAP',
                    b'\\xfd' * pattern_size: 'MSVC_GUARD_BYTES',
                    b'\\xcc' * pattern_size: 'MSVC_UNINIT_STACK',
                    b'\\xaa' * pattern_size: 'CUSTOM_PATTERN',
                    b'\\xbe\\xef' * (pattern_size // 2): 'DEADBEEF_PATTERN',
                }}

                findings = []
                for i in range(0, len(data) - pattern_size + 1, pattern_size):
                    chunk = data[i:i + pattern_size]
                    if chunk in patterns:
                        findings.append({{
                            'offset': i,
                            'pattern': patterns[chunk],
                            'data': chunk.hex(),
                        }})

                return findings


            def demo():
                """Test info leak detection."""
                print(f"Info Leak Detector — {{VULN_PATTERN['cve']}}")

                data = b'A' * 64
                result = check_oob_read(data, 60, 8)
                print(f"  OOB check (60+8 on 64-byte buf): oob={{result['oob']}}")
                if result['oob']:
                    print(f"    Leaked bytes: {{result['oob_bytes']}}")

                # Test uninitialized memory detection
                test_mem = b'\\xcd' * 16 + b'\\x00' * 16 + b'\\xdd' * 16
                findings = detect_uninitialized_patterns(test_mem)
                print(f"  Uninit patterns: {{len(findings)}} found")
                for f in findings:
                    print(f"    offset={{f['offset']}}: {{f['pattern']}}")

                print("  Detection ready")


            demo()
        '''),
    },
}


class FragmentSynthesizer:
    """Synthesize FORGE fragments from CVE patterns."""

    def __init__(self, fragments_dir: str = 'fragments'):
        self.fragments_dir = fragments_dir
        self.templates = TEMPLATES

    def synthesize_from_cve(self, cve) -> Optional[Dict]:
        """Generate a fragment from a CVE entry.

        Args:
            cve: CVEEntry from cve_fetcher

        Returns:
            Dict with 'name', 'code', 'template_used', or None if no match
        """
        # Find matching template
        template_key = self._match_template(cve)
        if not template_key:
            return None

        template = self.templates[template_key]

        # Generate fragment code
        code = template['template'].format(
            cve_id=cve.cve_id,
            description=cve.description[:200].replace("'", "\\'"),
            cwes=', '.join(cve.cwes),
            cwe_list=cve.cwes,
            cvss=f"{cve.cvss_v3_score} ({cve.cvss_severity})",
            attack_vector=cve.attack_vector or 'unknown',
        )

        # Generate fragment name
        cwe_part = cve.cwes[0].lower().replace('-', '') if cve.cwes else 'generic'
        name = f"cve_{cve.cve_id.lower().replace('-', '_')}_{cwe_part}"

        return {
            'name': name,
            'code': code,
            'template_used': template_key,
            'cve_id': cve.cve_id,
            'primitive': template['primitive'],
        }

    def synthesize_batch(self, cves, validate: bool = True) -> List[Dict]:
        """Synthesize fragments from a batch of CVEs.

        Args:
            cves: List of CVEEntry objects
            validate: If True, sandbox-validate each fragment

        Returns:
            List of validated fragment dicts
        """
        results = []

        for cve in cves:
            fragment = self.synthesize_from_cve(cve)
            if not fragment:
                continue

            if validate:
                is_valid, error = self._sandbox_validate(fragment['code'])
                fragment['valid'] = is_valid
                fragment['validation_error'] = error
                if not is_valid:
                    continue
            else:
                fragment['valid'] = True

            results.append(fragment)

        return results

    def store_fragments(self, fragments: List[Dict],
                        target_file: str = 'cve_synthesized_fragments.json') -> int:
        """Store validated fragments into fragment file.

        Returns count of fragments stored.
        """
        target_path = os.path.join(self.fragments_dir, target_file)

        # Load existing
        existing = {}
        if os.path.exists(target_path):
            with open(target_path) as f:
                existing = json.load(f)

        added = 0
        for frag in fragments:
            if frag.get('valid') and frag['name'] not in existing:
                existing[frag['name']] = frag['code']
                added += 1

        if added > 0:
            with open(target_path, 'w') as f:
                json.dump(existing, f, indent=2)

        return added

    def _match_template(self, cve) -> Optional[str]:
        """Find the best template for a CVE based on CWE mapping."""
        for template_key, template in self.templates.items():
            for cwe in cve.cwes:
                if cwe in template['cwes']:
                    return template_key

        # Fall back to primitive-based matching
        primitive_map = {
            'write': 'buffer_overflow_detector',
            'execute': 'buffer_overflow_detector',
            'info_leak': 'info_leak_detector',
            'dos': 'null_deref_detector',
        }
        return primitive_map.get(cve.exploit_primitive)

    def _sandbox_validate(self, code: str) -> Tuple[bool, str]:
        """Validate fragment code in sandbox.

        Runs the code in a subprocess with timeout.
        Returns (is_valid, error_message).
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py',
                                          delete=False) as f:
            f.write(code)
            tmppath = f.name

        try:
            result = subprocess.run(
                ['python3', tmppath],
                capture_output=True, text=True,
                timeout=10,
                cwd=tempfile.gettempdir(),
            )

            if result.returncode == 0:
                return True, ''
            else:
                return False, result.stderr[:500]
        except subprocess.TimeoutExpired:
            return False, 'Timeout (10s)'
        except Exception as e:
            return False, str(e)
        finally:
            os.unlink(tmppath)


if __name__ == '__main__':
    from o1o_o.core.cve_fetcher import CVEFetcher, TripletExtractor

    fetcher = CVEFetcher()
    synthesizer = FragmentSynthesizer()
    extractor = TripletExtractor()

    # Search for CVEs to synthesize from
    print("Searching NVD for CWE-416 (use-after-free)...")
    cves = fetcher.search(cwe_id='CWE-416', cvss_min=7.0, results_per_page=5)
    print(f"Found {len(cves)} CVEs")

    # Synthesize fragments
    fragments = synthesizer.synthesize_batch(cves, validate=True)
    print(f"\nSynthesized {len(fragments)} validated fragments:")
    for f in fragments:
        print(f"  {f['name']}: {f['template_used']} "
              f"(valid={f['valid']}, cve={f['cve_id']})")

    # Store
    stored = synthesizer.store_fragments(fragments)
    print(f"\nStored {stored} new fragments")
