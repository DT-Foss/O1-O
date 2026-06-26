"""AV/EDR Evasion Knowledge Base: Detection-evasion relationships as causal triplets.

Encodes structured knowledge about:
  - AV/EDR detection methods (signatures, heuristics, behavior, AMSI, ETW)
  - Evasion techniques (obfuscation, encryption, LOTL, unhooking, patching)
  - Detection-evasion pairings (which technique bypasses which detection)
  - Platform-specific considerations (Windows vs Linux vs macOS)
  - Confidence scores for each relationship

Used by the Payload Mutation Engine (O2) to make informed evasion decisions.
The knowledge is stored as causal triplets: trigger → mechanism → outcome.

Part of FORGE Phase O: Operational Evasion Intelligence.
"""
# Dependencies: none
# Depended by: evasion_engine

from typing import Dict, List, Optional, Set, Tuple


# ─── Detection Methods ──────────────────────────────────────────────

DETECTION_METHODS = {
    # Signature-based
    'static_signature': {
        'category': 'signature',
        'desc': 'Pattern matching against known malware signatures',
        'platforms': ['windows', 'linux', 'macos'],
        'effectiveness': 0.7,
        'evasion_difficulty': 0.3,  # Easy to evade
    },
    'yara_rules': {
        'category': 'signature',
        'desc': 'YARA rule matching on file content and memory',
        'platforms': ['windows', 'linux', 'macos'],
        'effectiveness': 0.8,
        'evasion_difficulty': 0.4,
    },
    'import_table_analysis': {
        'category': 'signature',
        'desc': 'Suspicious API import combinations',
        'platforms': ['windows'],
        'effectiveness': 0.6,
        'evasion_difficulty': 0.4,
    },
    'string_analysis': {
        'category': 'signature',
        'desc': 'Known bad strings, URLs, IPs in binary',
        'platforms': ['windows', 'linux', 'macos'],
        'effectiveness': 0.5,
        'evasion_difficulty': 0.2,
    },

    # Heuristic-based
    'entropy_analysis': {
        'category': 'heuristic',
        'desc': 'High entropy sections indicate encryption/packing',
        'platforms': ['windows', 'linux', 'macos'],
        'effectiveness': 0.7,
        'evasion_difficulty': 0.5,
    },
    'packer_detection': {
        'category': 'heuristic',
        'desc': 'Known packer signatures (UPX, Themida, VMProtect)',
        'platforms': ['windows'],
        'effectiveness': 0.8,
        'evasion_difficulty': 0.3,
    },
    'section_anomaly': {
        'category': 'heuristic',
        'desc': 'Unusual section names, permissions, sizes',
        'platforms': ['windows', 'linux'],
        'effectiveness': 0.6,
        'evasion_difficulty': 0.4,
    },
    'certificate_validation': {
        'category': 'heuristic',
        'desc': 'Code signing certificate verification',
        'platforms': ['windows', 'macos'],
        'effectiveness': 0.7,
        'evasion_difficulty': 0.8,
    },

    # Behavior-based
    'api_monitoring': {
        'category': 'behavior',
        'desc': 'Runtime API call sequence monitoring via hooks',
        'platforms': ['windows'],
        'effectiveness': 0.85,
        'evasion_difficulty': 0.6,
    },
    'process_injection_detect': {
        'category': 'behavior',
        'desc': 'Detect WriteProcessMemory + CreateRemoteThread patterns',
        'platforms': ['windows'],
        'effectiveness': 0.8,
        'evasion_difficulty': 0.6,
    },
    'syscall_monitoring': {
        'category': 'behavior',
        'desc': 'Direct syscall/ntdll monitoring (kernel callbacks)',
        'platforms': ['windows', 'linux'],
        'effectiveness': 0.9,
        'evasion_difficulty': 0.8,
    },
    'network_behavior': {
        'category': 'behavior',
        'desc': 'C2 traffic patterns, beaconing, DNS tunneling detection',
        'platforms': ['windows', 'linux', 'macos'],
        'effectiveness': 0.7,
        'evasion_difficulty': 0.6,
    },
    'file_system_monitoring': {
        'category': 'behavior',
        'desc': 'Minifilter drivers monitoring file I/O',
        'platforms': ['windows'],
        'effectiveness': 0.75,
        'evasion_difficulty': 0.5,
    },

    # Windows-specific
    'amsi': {
        'category': 'windows_specific',
        'desc': 'Antimalware Scan Interface — script content scanning',
        'platforms': ['windows'],
        'effectiveness': 0.8,
        'evasion_difficulty': 0.4,
    },
    'etw': {
        'category': 'windows_specific',
        'desc': 'Event Tracing for Windows — telemetry collection',
        'platforms': ['windows'],
        'effectiveness': 0.85,
        'evasion_difficulty': 0.5,
    },
    'pppl': {
        'category': 'windows_specific',
        'desc': 'Protected Process Light — prevents tampering with AV',
        'platforms': ['windows'],
        'effectiveness': 0.9,
        'evasion_difficulty': 0.9,
    },
    'wdac': {
        'category': 'windows_specific',
        'desc': 'Windows Defender Application Control — allowlisting',
        'platforms': ['windows'],
        'effectiveness': 0.95,
        'evasion_difficulty': 0.8,
    },

    # EDR-specific
    'kernel_callbacks': {
        'category': 'edr',
        'desc': 'PsSetCreateProcessNotifyRoutine, thread/image callbacks',
        'platforms': ['windows'],
        'effectiveness': 0.9,
        'evasion_difficulty': 0.85,
    },
    'userland_hooks': {
        'category': 'edr',
        'desc': 'Inline hooks in ntdll.dll, kernel32.dll',
        'platforms': ['windows'],
        'effectiveness': 0.8,
        'evasion_difficulty': 0.5,
    },
    'memory_scanning': {
        'category': 'edr',
        'desc': 'Periodic memory scanning for known payloads',
        'platforms': ['windows', 'linux'],
        'effectiveness': 0.75,
        'evasion_difficulty': 0.6,
    },
    'call_stack_analysis': {
        'category': 'edr',
        'desc': 'Verify call stack legitimacy (unbacked memory detection)',
        'platforms': ['windows'],
        'effectiveness': 0.85,
        'evasion_difficulty': 0.7,
    },
}


# ─── Evasion Techniques ─────────────────────────────────────────────

EVASION_TECHNIQUES = {
    # Obfuscation
    'string_encryption': {
        'category': 'obfuscation',
        'desc': 'Encrypt strings, decrypt at runtime',
        'evades': ['static_signature', 'string_analysis', 'yara_rules'],
        'platforms': ['windows', 'linux', 'macos'],
        'opsec_risk': 0.2,
        'implementation_complexity': 0.3,
    },
    'control_flow_flattening': {
        'category': 'obfuscation',
        'desc': 'Flatten control flow with switch-based dispatch',
        'evades': ['static_signature', 'yara_rules'],
        'platforms': ['windows', 'linux', 'macos'],
        'opsec_risk': 0.3,
        'implementation_complexity': 0.6,
    },
    'dead_code_insertion': {
        'category': 'obfuscation',
        'desc': 'Insert non-functional code to change signatures',
        'evades': ['static_signature', 'entropy_analysis'],
        'platforms': ['windows', 'linux', 'macos'],
        'opsec_risk': 0.1,
        'implementation_complexity': 0.2,
    },
    'variable_renaming': {
        'category': 'obfuscation',
        'desc': 'Rename variables/functions to random names',
        'evades': ['string_analysis', 'yara_rules'],
        'platforms': ['windows', 'linux', 'macos'],
        'opsec_risk': 0.1,
        'implementation_complexity': 0.1,
    },

    # Encryption/Encoding
    'xor_encoding': {
        'category': 'encryption',
        'desc': 'XOR encode payload with single/rolling key',
        'evades': ['static_signature', 'string_analysis', 'yara_rules'],
        'platforms': ['windows', 'linux', 'macos'],
        'opsec_risk': 0.3,
        'implementation_complexity': 0.2,
    },
    'aes_encryption': {
        'category': 'encryption',
        'desc': 'AES encrypt payload, decrypt in memory at runtime',
        'evades': ['static_signature', 'memory_scanning', 'yara_rules'],
        'platforms': ['windows', 'linux', 'macos'],
        'opsec_risk': 0.2,
        'implementation_complexity': 0.4,
    },
    'staged_decryption': {
        'category': 'encryption',
        'desc': 'Multi-stage: stub decrypts loader, loader decrypts payload',
        'evades': ['static_signature', 'entropy_analysis', 'memory_scanning'],
        'platforms': ['windows', 'linux'],
        'opsec_risk': 0.3,
        'implementation_complexity': 0.6,
    },

    # Polymorphic/Metamorphic
    'polymorphic_encoding': {
        'category': 'polymorphic',
        'desc': 'Each generation produces different encoded output',
        'evades': ['static_signature', 'yara_rules', 'packer_detection'],
        'platforms': ['windows', 'linux', 'macos'],
        'opsec_risk': 0.3,
        'implementation_complexity': 0.5,
    },
    'metamorphic_mutation': {
        'category': 'metamorphic',
        'desc': 'Code rewrites itself with equivalent instructions',
        'evades': ['static_signature', 'yara_rules', 'packer_detection', 'entropy_analysis'],
        'platforms': ['windows', 'linux'],
        'opsec_risk': 0.4,
        'implementation_complexity': 0.8,
    },

    # Living-off-the-Land
    'lotl_powershell': {
        'category': 'lotl',
        'desc': 'Use PowerShell for execution (fileless)',
        'evades': ['static_signature', 'file_system_monitoring', 'import_table_analysis'],
        'platforms': ['windows'],
        'opsec_risk': 0.5,
        'implementation_complexity': 0.3,
    },
    'lotl_wmic': {
        'category': 'lotl',
        'desc': 'Use WMIC/CIM for execution and recon',
        'evades': ['static_signature', 'file_system_monitoring'],
        'platforms': ['windows'],
        'opsec_risk': 0.4,
        'implementation_complexity': 0.2,
    },
    'lotl_msbuild': {
        'category': 'lotl',
        'desc': 'Use MSBuild to compile/execute inline code',
        'evades': ['static_signature', 'wdac', 'certificate_validation'],
        'platforms': ['windows'],
        'opsec_risk': 0.4,
        'implementation_complexity': 0.4,
    },
    'lotl_certutil': {
        'category': 'lotl',
        'desc': 'Use certutil for download/decode operations',
        'evades': ['static_signature', 'file_system_monitoring'],
        'platforms': ['windows'],
        'opsec_risk': 0.6,
        'implementation_complexity': 0.1,
    },
    'lotl_bash_builtins': {
        'category': 'lotl',
        'desc': 'Use bash builtins (/dev/tcp, printf) for network ops',
        'evades': ['static_signature', 'file_system_monitoring'],
        'platforms': ['linux', 'macos'],
        'opsec_risk': 0.3,
        'implementation_complexity': 0.2,
    },
    'lotl_python_stdlib': {
        'category': 'lotl',
        'desc': 'Use Python standard library for offensive operations',
        'evades': ['static_signature', 'import_table_analysis'],
        'platforms': ['linux', 'macos'],
        'opsec_risk': 0.3,
        'implementation_complexity': 0.2,
    },

    # API/Hook Evasion
    'ntdll_unhooking': {
        'category': 'unhooking',
        'desc': 'Restore original ntdll.dll from disk to remove EDR hooks',
        'evades': ['userland_hooks', 'api_monitoring'],
        'platforms': ['windows'],
        'opsec_risk': 0.5,
        'implementation_complexity': 0.5,
    },
    'direct_syscalls': {
        'category': 'unhooking',
        'desc': 'Invoke NT syscalls directly, bypassing ntdll hooks',
        'evades': ['userland_hooks', 'api_monitoring', 'call_stack_analysis'],
        'platforms': ['windows'],
        'opsec_risk': 0.4,
        'implementation_complexity': 0.6,
    },
    'indirect_syscalls': {
        'category': 'unhooking',
        'desc': 'Jump into ntdll after syscall instruction for valid call stack',
        'evades': ['userland_hooks', 'api_monitoring', 'call_stack_analysis'],
        'platforms': ['windows'],
        'opsec_risk': 0.3,
        'implementation_complexity': 0.7,
    },
    'hardware_breakpoint_hooks': {
        'category': 'unhooking',
        'desc': 'Use hardware breakpoints to intercept before EDR hooks',
        'evades': ['userland_hooks', 'api_monitoring'],
        'platforms': ['windows'],
        'opsec_risk': 0.4,
        'implementation_complexity': 0.7,
    },

    # Memory evasion
    'module_stomping': {
        'category': 'memory',
        'desc': 'Load payload into legitimately loaded DLL memory',
        'evades': ['memory_scanning', 'call_stack_analysis'],
        'platforms': ['windows'],
        'opsec_risk': 0.4,
        'implementation_complexity': 0.6,
    },
    'phantom_dll_hollowing': {
        'category': 'memory',
        'desc': 'Map transacted DLL section, overwrite with payload',
        'evades': ['memory_scanning', 'call_stack_analysis', 'kernel_callbacks'],
        'platforms': ['windows'],
        'opsec_risk': 0.3,
        'implementation_complexity': 0.8,
    },
    'rw_rx_toggle': {
        'category': 'memory',
        'desc': 'Toggle RW↔RX permissions to avoid RWX detection',
        'evades': ['memory_scanning', 'section_anomaly'],
        'platforms': ['windows', 'linux'],
        'opsec_risk': 0.3,
        'implementation_complexity': 0.4,
    },

    # Windows-specific bypasses
    'amsi_patch': {
        'category': 'bypass',
        'desc': 'Patch AmsiScanBuffer to return clean result',
        'evades': ['amsi'],
        'platforms': ['windows'],
        'opsec_risk': 0.6,
        'implementation_complexity': 0.3,
    },
    'amsi_register_bypass': {
        'category': 'bypass',
        'desc': 'Unregister AMSI provider or corrupt COM interface',
        'evades': ['amsi'],
        'platforms': ['windows'],
        'opsec_risk': 0.5,
        'implementation_complexity': 0.5,
    },
    'etw_patch': {
        'category': 'bypass',
        'desc': 'Patch EtwEventWrite/NtTraceEvent to suppress telemetry',
        'evades': ['etw'],
        'platforms': ['windows'],
        'opsec_risk': 0.6,
        'implementation_complexity': 0.4,
    },
    'clr_profiler_bypass': {
        'category': 'bypass',
        'desc': 'Disable .NET profiler to prevent assembly inspection',
        'evades': ['amsi', 'etw'],
        'platforms': ['windows'],
        'opsec_risk': 0.4,
        'implementation_complexity': 0.5,
    },

    # Process manipulation
    'process_hollowing': {
        'category': 'injection',
        'desc': 'Create suspended process, replace memory with payload',
        'evades': ['static_signature', 'file_system_monitoring'],
        'platforms': ['windows'],
        'opsec_risk': 0.6,
        'implementation_complexity': 0.5,
    },
    'process_doppelganging': {
        'category': 'injection',
        'desc': 'Use NTFS transactions to create process from transacted file',
        'evades': ['static_signature', 'file_system_monitoring', 'kernel_callbacks'],
        'platforms': ['windows'],
        'opsec_risk': 0.4,
        'implementation_complexity': 0.8,
    },
    'thread_execution_hijack': {
        'category': 'injection',
        'desc': 'Suspend thread, modify context to point to payload',
        'evades': ['process_injection_detect'],
        'platforms': ['windows'],
        'opsec_risk': 0.5,
        'implementation_complexity': 0.6,
    },
    'early_bird_injection': {
        'category': 'injection',
        'desc': 'APC injection before process entry point',
        'evades': ['process_injection_detect', 'api_monitoring'],
        'platforms': ['windows'],
        'opsec_risk': 0.4,
        'implementation_complexity': 0.6,
    },

    # Timing/Environment
    'sandbox_detection': {
        'category': 'anti_analysis',
        'desc': 'Detect VM/sandbox via timing, hardware, artifacts',
        'evades': ['api_monitoring'],
        'platforms': ['windows', 'linux', 'macos'],
        'opsec_risk': 0.2,
        'implementation_complexity': 0.4,
    },
    'delayed_execution': {
        'category': 'anti_analysis',
        'desc': 'Sleep/timer-based delay to outlast sandbox analysis',
        'evades': ['api_monitoring', 'network_behavior'],
        'platforms': ['windows', 'linux', 'macos'],
        'opsec_risk': 0.2,
        'implementation_complexity': 0.1,
    },
    'user_interaction_gate': {
        'category': 'anti_analysis',
        'desc': 'Require user interaction (click, scroll) before executing',
        'evades': ['api_monitoring'],
        'platforms': ['windows', 'macos'],
        'opsec_risk': 0.1,
        'implementation_complexity': 0.3,
    },
}


# ─── Triplet Generation ─────────────────────────────────────────────

def generate_evasion_triplets() -> List[dict]:
    """Generate causal triplets from evasion knowledge base.

    Produces triplets for:
      1. Detection capabilities
      2. Evasion techniques
      3. Detection-evasion relationships (which bypasses what)
      4. Platform constraints
      5. Composite evasion strategies
    """
    triplets = []

    # 1. Detection method triplets
    for name, det in DETECTION_METHODS.items():
        # Detection capability
        triplets.append({
            'trigger': f'{det["category"]}_detection_active',
            'mechanism': f'{name}_scanning',
            'outcome': f'malware_detected_by_{name}',
            'confidence': det['effectiveness'],
        })

        # Platform applicability
        for platform in det['platforms']:
            triplets.append({
                'trigger': f'target_platform_{platform}',
                'mechanism': f'{name}_available',
                'outcome': f'{name}_detection_active_on_{platform}',
                'confidence': 0.9,
            })

    # 2. Evasion technique triplets
    for name, tech in EVASION_TECHNIQUES.items():
        # Technique description
        triplets.append({
            'trigger': f'evasion_need_{tech["category"]}',
            'mechanism': f'apply_{name}',
            'outcome': f'{name}_evasion_active',
            'confidence': 1.0 - tech['opsec_risk'],
        })

        # What it evades (key intelligence)
        for evaded in tech['evades']:
            det = DETECTION_METHODS.get(evaded, {})
            # Confidence = inverse of evasion difficulty * (1 - opsec_risk)
            evasion_conf = (1.0 - det.get('evasion_difficulty', 0.5)) * (1.0 - tech['opsec_risk'])
            triplets.append({
                'trigger': f'{evaded}_detection_active',
                'mechanism': f'apply_{name}',
                'outcome': f'{evaded}_bypassed',
                'confidence': round(min(0.95, evasion_conf + 0.3), 2),
            })

        # Platform constraints
        for platform in tech['platforms']:
            triplets.append({
                'trigger': f'target_platform_{platform}',
                'mechanism': f'{name}_compatible',
                'outcome': f'{name}_available_on_{platform}',
                'confidence': 0.95,
            })

    # 3. Counter-detection chains (composite evasion)
    chains = _build_evasion_chains()
    for chain in chains:
        triplets.append({
            'trigger': f'edr_with_{"+".join(chain["detections"][:3])}',
            'mechanism': f'chain_{"+".join(chain["techniques"][:3])}',
            'outcome': f'edr_evaded_confidence_{chain["confidence"]}',
            'confidence': chain['confidence'],
        })

    # 4. OPSEC risk triplets
    for name, tech in EVASION_TECHNIQUES.items():
        if tech['opsec_risk'] >= 0.5:
            triplets.append({
                'trigger': f'apply_{name}',
                'mechanism': f'opsec_risk_{tech["opsec_risk"]}',
                'outcome': f'increased_detection_risk_{name}',
                'confidence': tech['opsec_risk'],
            })

    return triplets


def _build_evasion_chains() -> List[dict]:
    """Build composite evasion chains for common EDR configurations."""
    chains = []

    # Chain 1: Full Windows EDR bypass
    chains.append({
        'detections': ['userland_hooks', 'amsi', 'etw', 'kernel_callbacks'],
        'techniques': ['indirect_syscalls', 'amsi_patch', 'etw_patch', 'module_stomping'],
        'confidence': 0.65,
        'desc': 'Full Windows EDR bypass chain',
    })

    # Chain 2: Signature evasion (basic)
    chains.append({
        'detections': ['static_signature', 'string_analysis', 'yara_rules'],
        'techniques': ['string_encryption', 'polymorphic_encoding', 'dead_code_insertion'],
        'confidence': 0.85,
        'desc': 'Signature-only evasion',
    })

    # Chain 3: Fileless execution
    chains.append({
        'detections': ['file_system_monitoring', 'static_signature', 'packer_detection'],
        'techniques': ['lotl_powershell', 'staged_decryption', 'process_hollowing'],
        'confidence': 0.7,
        'desc': 'Fileless execution chain',
    })

    # Chain 4: Memory-only persistence
    chains.append({
        'detections': ['memory_scanning', 'call_stack_analysis', 'section_anomaly'],
        'techniques': ['phantom_dll_hollowing', 'rw_rx_toggle', 'indirect_syscalls'],
        'confidence': 0.6,
        'desc': 'Memory-only with stack spoofing',
    })

    # Chain 5: Linux/macOS evasion
    chains.append({
        'detections': ['static_signature', 'string_analysis', 'network_behavior'],
        'techniques': ['lotl_bash_builtins', 'xor_encoding', 'delayed_execution'],
        'confidence': 0.75,
        'desc': 'Linux/macOS LOTL chain',
    })

    # Chain 6: Anti-analysis sandbox escape
    chains.append({
        'detections': ['api_monitoring', 'network_behavior'],
        'techniques': ['sandbox_detection', 'delayed_execution', 'user_interaction_gate'],
        'confidence': 0.7,
        'desc': 'Anti-sandbox chain',
    })

    return chains


# ─── Query Interface ─────────────────────────────────────────────────

class EvasionKB:
    """Query interface for the evasion knowledge base."""

    def __init__(self):
        self.triplets = generate_evasion_triplets()
        self._index_built = False
        self._evades_index = {}  # detection → [techniques]
        self._evaded_by_index = {}  # technique → [detections]

    def _build_index(self):
        """Build lookup indexes."""
        if self._index_built:
            return

        for tech_name, tech in EVASION_TECHNIQUES.items():
            self._evaded_by_index[tech_name] = tech['evades']
            for det in tech['evades']:
                if det not in self._evades_index:
                    self._evades_index[det] = []
                self._evades_index[det].append(tech_name)

        self._index_built = True

    def suggest_evasion(self, detections: List[str],
                        platform: str = 'windows') -> List[dict]:
        """Given active detections, suggest evasion techniques.

        Args:
            detections: List of active detection method names
            platform: Target platform

        Returns:
            Ranked list of evasion technique recommendations
        """
        self._build_index()
        scores = {}

        for det in detections:
            for tech_name in self._evades_index.get(det, []):
                tech = EVASION_TECHNIQUES[tech_name]
                if platform not in tech['platforms']:
                    continue

                if tech_name not in scores:
                    scores[tech_name] = {
                        'technique': tech_name,
                        'category': tech['category'],
                        'desc': tech['desc'],
                        'evades_active': [],
                        'coverage': 0,
                        'opsec_risk': tech['opsec_risk'],
                        'complexity': tech['implementation_complexity'],
                        'score': 0,
                    }

                scores[tech_name]['evades_active'].append(det)

        # Score: coverage * (1 - risk) * (1 - complexity/2)
        for name, info in scores.items():
            coverage = len(info['evades_active']) / max(len(detections), 1)
            info['coverage'] = round(coverage, 2)
            info['score'] = round(
                coverage * (1 - info['opsec_risk']) * (1 - info['complexity'] / 2), 3
            )

        ranked = sorted(scores.values(), key=lambda x: -x['score'])
        return ranked

    def get_technique_detail(self, name: str) -> Optional[dict]:
        """Get full details for an evasion technique."""
        tech = EVASION_TECHNIQUES.get(name)
        if not tech:
            return None
        self._build_index()
        return {
            **tech,
            'name': name,
            'evades_count': len(tech['evades']),
            'counter_detections': tech['evades'],
        }

    def get_detection_detail(self, name: str) -> Optional[dict]:
        """Get full details for a detection method."""
        det = DETECTION_METHODS.get(name)
        if not det:
            return None
        self._build_index()
        return {
            **det,
            'name': name,
            'bypassed_by': self._evades_index.get(name, []),
        }

    def platform_techniques(self, platform: str) -> List[str]:
        """Get all evasion techniques available on a platform."""
        return [name for name, tech in EVASION_TECHNIQUES.items()
                if platform in tech['platforms']]

    def stats(self) -> dict:
        """Knowledge base statistics."""
        return {
            'detection_methods': len(DETECTION_METHODS),
            'evasion_techniques': len(EVASION_TECHNIQUES),
            'triplets': len(self.triplets),
            'categories': {
                'detection': list(set(d['category'] for d in DETECTION_METHODS.values())),
                'evasion': list(set(t['category'] for t in EVASION_TECHNIQUES.values())),
            },
            'platforms': ['windows', 'linux', 'macos'],
        }

    def format_stats(self) -> str:
        """Formatted statistics."""
        s = self.stats()
        lines = [
            f"EVASION KNOWLEDGE BASE",
            f"  Detection methods:  {s['detection_methods']}",
            f"  Evasion techniques: {s['evasion_techniques']}",
            f"  Causal triplets:    {s['triplets']}",
            f"",
            f"  Detection categories: {', '.join(s['categories']['detection'])}",
            f"  Evasion categories:   {', '.join(s['categories']['evasion'])}",
            f"  Platforms:            {', '.join(s['platforms'])}",
        ]
        return '\n'.join(lines)

    def format_suggestion(self, suggestions: List[dict]) -> str:
        """Format evasion suggestions as text."""
        if not suggestions:
            return "  No applicable evasion techniques found."

        lines = [
            f"  {'Technique':<30s} {'Score':>6s} {'Cover':>6s} {'Risk':>6s} {'Evades'}",
            f"  {'-' * 70}",
        ]
        for s in suggestions[:15]:
            evades = ', '.join(s['evades_active'][:3])
            if len(s['evades_active']) > 3:
                evades += f' +{len(s["evades_active"])-3}'
            lines.append(
                f"  {s['technique']:<30s} {s['score']:>6.3f} {s['coverage']:>5.0%} "
                f"{s['opsec_risk']:>5.0%}  {evades}"
            )
        return '\n'.join(lines)
