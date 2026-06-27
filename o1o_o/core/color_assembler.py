"""
Color Assembler — Deterministic fragment chaining via color type matching.

Assembly algorithm:
  1. Detect color chain from intent (e.g., [PATH, TEXT, STRUCT, VOID])
  2. For each transition (A→B), find a fragment with input=A, output=B
  3. Chain fragments in order
  4. Done. No scoring. No Monte Carlo. Binary: colors match or they don't.
"""
# Dependencies: color_types
# Depended by: code_assembler


import re
from typing import List, Dict, Tuple, Optional, Set
from o1o_o.core.color_types import (
    COLOR_REGISTRY, COLOR_CONVERTERS, INTENT_COLOR_CHAINS,
    ALL_COLORS, TEXT, STRUCT, TABULAR, BYTES, SERIAL, PATH, RESPONSE, VOID,
)
from o1o_o.core.color_checker import ColorChecker


class ColorAssembler:
    """Deterministic fragment assembly via color type matching."""

    def __init__(self, fragments: Dict[str, str]):
        self.fragments = fragments
        self.checker = ColorChecker()
        # Build index: (input_color, output_color) → [fragment_keys]
        self._by_transition: Dict[Tuple[str, str], List[str]] = {}

        for frag_key, (in_c, out_c) in COLOR_REGISTRY.items():
            if frag_key in fragments:
                pair = (in_c, out_c)
                if pair not in self._by_transition:
                    self._by_transition[pair] = []
                self._by_transition[pair].append(frag_key)

    def detect_chain(self, intent_text: str) -> Optional[List[str]]:
        """Detect required color chain from intent text."""
        intent_lower = intent_text.lower()
        for pattern, chain in INTENT_COLOR_CHAINS:
            if re.search(pattern, intent_lower):
                return chain
        return None

    def resolve_chain(self, color_chain: List[str]) -> Optional[List[str]]:
        """
        Resolve a color chain to fragment keys.

        Given [PATH, TEXT, STRUCT, VOID], finds:
          - fragment with PATH→TEXT  (e.g., file_read)
          - fragment with TEXT→STRUCT (e.g., json_loads)
          - fragment with STRUCT→VOID (e.g., json_dump)

        Returns list of fragment keys, or None if any transition has no fragment.
        """
        if len(color_chain) < 2:
            return None

        # Special case: [VOID, VOID] — handled by _build_void_pipeline
        if color_chain == [VOID, VOID]:
            return None  # Signal to use void pipeline instead

        # Single transition: same color in→out
        if len(color_chain) == 2 and color_chain[0] == color_chain[1]:
            pair = (color_chain[0], color_chain[1])
            candidates = self._by_transition.get(pair, [])
            return [candidates[0]] if candidates else None

        frag_keys = []
        used = set()

        for i in range(len(color_chain) - 1):
            from_color = color_chain[i]
            to_color = color_chain[i + 1]

            if from_color == to_color:
                # Same color transition — find a transform fragment
                pair = (from_color, to_color)
                candidates = self._by_transition.get(pair, [])
                candidates = [k for k in candidates if k not in used]
                if candidates:
                    frag_keys.append(candidates[0])
                    used.add(candidates[0])
                continue

            # Find a fragment for this transition
            pair = (from_color, to_color)
            candidates = self._by_transition.get(pair, [])
            candidates = [k for k in candidates if k not in used]

            if not candidates:
                # Try converter
                converter = COLOR_CONVERTERS.get(pair)
                if converter and converter in self.fragments and converter not in used:
                    candidates = [converter]

            if not candidates:
                return None  # No fragment for this transition = pipeline impossible

            frag_keys.append(candidates[0])
            used.add(candidates[0])

        return frag_keys if frag_keys else None

    def build_pipeline(self, intent_text: str) -> Optional[List[Tuple[str, str]]]:
        """
        Build a complete fragment pipeline for an intent.

        Returns list of (fragment_key, fragment_code) or None.
        """
        chain = self.detect_chain(intent_text)
        if not chain:
            return None

        # VOID→VOID: domain-specific, not color-chainable
        if chain == [VOID, VOID]:
            return self._build_void_pipeline(intent_text)

        frag_keys = self.resolve_chain(chain)
        if not frag_keys:
            return None

        # Validate chain with ColorChecker before building
        violations = self.checker.validate_chain(frag_keys, expected_chain=chain)
        errors = [v for v in violations if v.severity == 'error']
        if errors:
            return None  # Chain has type errors — bail out

        result = []
        for key in frag_keys:
            if key in self.fragments:
                result.append((key, self.fragments[key]))

        return result if result else None

    def _build_void_pipeline(self, intent_text: str) -> Optional[List[Tuple[str, str]]]:
        """
        Handle VOID→VOID intents: servers, schedulers, management systems.
        These don't form color chains — select fragments by domain keyword.
        """
        intent_lower = intent_text.lower()
        result = []
        used = set()

        VOID_PATTERNS = [
            # ── Operations Chain Modules (Tasks 151-167) — before generic offensive ──
            # Operations infrastructure
            (r'(?:operations?|campaign).*(?:database|db|state|persist)', ['operations_db_setup']),
            (r'(?:session|state).*(?:restore|resume|recover)', ['session_restore_engine']),
            (r'(?:operations?|campaign).*(?:daemon|scheduler|background)', ['operations_daemon_launcher']),
            # Payload mutation
            (r'(?:payload|code).*(?:mutate|mutation|morph|transform)', ['ast_payload_mutator_output']),
            (r'(?:ast|syntax.*tree).*(?:mutate|transform)', ['ast_payload_mutator_output']),
            # Hash surveillance
            (r'(?:hash|payload).*(?:monitor|surveil|track|check)', ['hash_surveillance_engine']),
            (r'(?:threat.*intel|vt|virustotal).*(?:hash|check)', ['hash_surveillance_engine']),
            # Polyglot files
            (r'polyglot.*(?:file|generate|pdf|html|zip)', ['polyglot_pdf_js']),
            (r'(?:dual|multi).*format.*(?:file|payload)', ['polyglot_pdf_js']),
            # Credential trigger
            (r'credential.*(?:trigger|auto.*exploit|chain|cascade)', ['credential_auto_trigger']),
            (r'(?:auto|automatic).*(?:exploit|lateral).*credential', ['credential_auto_trigger']),
            # Miner deployment
            (r'(?:crypto)?miner.*(?:deploy|download|install)', ['miner_download_script']),
            (r'(?:hardware.*adaptive|gpu.*detect).*min(?:er|ing)', ['miner_hardware_config']),
            (r'miner.*(?:config|setup|hardware)', ['miner_hardware_config']),
            # WiFi exploitation
            (r'(?:evil.*twin|rogue.*ap|fake.*wifi)', ['wifi_captive_portal_server', 'wifi_captive_portal_html']),
            (r'captive.*portal', ['wifi_captive_portal_server', 'wifi_captive_portal_html']),
            (r'(?:wifi|wlan).*(?:enum|recon|network.*scan)', ['wifi_network_enum_script']),
            # USB exploitation
            (r'(?:usb|rubber.*ducky|badusb).*(?:attack|payload|autoinfect)', ['usb_usb_monitor_script']),
            (r'(?:usb|removable).*(?:monitor|watch|autorun)', ['usb_usb_monitor_script', 'usb_autorun_inf']),
            (r'(?:macro|vba).*(?:docx|document|office)', ['usb_docx_macro']),
            # VPN exploitation
            (r'(?:vpn|openvpn).*(?:clone|hijack|redirect)', ['vpn_openvpn_clone']),
            (r'(?:vpn|openvpn|wireguard).*(?:config|manipulat|exploit)', ['vpn_openvpn_clone']),
            # Email exploitation
            (r'(?:ews|exchange.*web.*service).*(?:exploit|enum|harvest)', ['email_ews_exploit']),
            (r'(?:imap|pop3).*(?:exploit|enum|harvest)', ['email_imap_exploit']),
            (r'(?:spearphish|phishing.*email).*(?:generate|create|build)', ['email_spearphish_generator']),
            (r'(?:microsoft.*graph|graph.*api).*(?:exploit|mail)', ['email_ews_exploit']),
            (r'(?:email|mail).*(?:exploit|harvest|credential)', ['email_ews_exploit', 'email_imap_exploit']),
            # ML/AI exploitation
            (r'(?:ml|ai|llm|model).*(?:exploit|attack|discover)', ['ml_exploit_script']),
            (r'(?:ollama|lm.*studio|localai|mlx).*(?:exploit|enum|steal)', ['ml_exploit_script', 'ml_model_theft_commands']),
            (r'(?:model).*(?:theft|steal|exfil)', ['ml_model_theft_commands']),
            (r'(?:prompt.*inject|model.*poison)', ['ml_exploit_script']),
            # EDR subversion
            (r'(?:edr|endpoint.*detect).*(?:identify|detect|enumerate)', ['edr_detect_windows', 'edr_detect_linux']),
            (r'(?:edr|endpoint.*detect).*(?:bypass|subvert|evade)', ['edr_full_bypass_script']),
            (r'(?:ntdll|userland).*(?:unhook|bypass|restore)', ['edr_ntdll_unhook']),
            (r'(?:defender|windows.*defender).*(?:exclusion|bypass)', ['edr_defender_exclusion_powershell']),
            (r'(?:telemetry|edr.*phone.*home).*(?:block|disable)', ['edr_telemetry_block']),
            (r'(?:syscall|ssn).*(?:direct|stub|generate)', ['edr_syscall_ntallocatevirtualmemory']),
            # Canary/honeypot detection
            (r'(?:canary|honey.*token).*(?:detect|check|scan)', ['canary_detection_script']),
            (r'(?:aws.*canary|fake.*credential).*(?:detect|check)', ['canary_detection_script']),
            (r'(?:honey.*account|ad.*honey).*(?:detect|check)', ['canary_detection_script']),
            (r'(?:file.*canary|tracking.*pixel).*(?:detect|scan)', ['canary_detection_script']),
            (r'(?:network.*honeypot|honeypot).*(?:detect|identify)', ['canary_detection_script']),
            # Operations TUI
            (r'(?:operations?|campaign).*(?:tui|dashboard|console)', ['operations_tui_dashboard']),
            (r'(?:curses|terminal).*(?:dashboard|panel)', ['operations_tui_dashboard']),

            # ── Offensive security tools (must be before generic patterns) ──
            # SMB reconnaissance
            (r'smb.*(?:recon|scan|enum|negot|version|signing)', ['smb_negotiate', 'smb2_negotiate']),
            # SQL injection
            (r'sql.*inject.*(?:scan|detect|tool)|sqli(?!te).*(?:scan|detect|tool)', ['blind_boolean_bisection', 'time_based_delay', 'union_column_count', 'error_based_extract', 'db_fingerprint']),
            (r'sql.*inject|sqli(?!te)|blind.*sql', ['blind_boolean_bisection', 'time_based_delay', 'union_column_count', 'error_based_extract']),
            (r'error.*based.*sql', ['error_based_extract']),
            (r'union.*sql|union.*inject', ['union_column_count']),
            (r'waf.*bypass|tamper.*(?:sql|payload)', ['tamper_base64encode', 'tamper_between', 'tamper_charencode']),
            # NTLM / Auth capture
            (r'ntlm.*(?:hash|capture)|hash.*capture.*(?:ntlm|smb)', ['rogue_smb_auth_server', 'ntlm_type1_message', 'ntlm_type3_response']),
            (r'rogue.*(?:auth|smb).*server', ['rogue_smb_auth_server', 'ntlm_type1_message', 'ntlm_type3_response']),
            (r'ntlm.*relay', ['ntlm_type1_message', 'ntlm_type3_response', 'smb_negotiate']),
            (r'responder.*(?:attack|tool|poison)', ['llmnr_poison_response', 'nbns_poison_response', 'rogue_smb_auth_server']),
            # Credentials
            (r'credential.*(?:harvest|dump|extract|recover)', ['chrome_passwords', 'firefox_passwords', 'wifi_passwords_windows', 'ssh_private_keys']),
            (r'(?:chrome|browser).*password', ['chrome_passwords', 'firefox_passwords']),
            (r'firefox.*password', ['firefox_passwords']),
            (r'wifi.*password|password.*wifi', ['wifi_passwords_windows', 'wifi_passwords_linux']),
            (r'password.*(?:extract|dump|harvest)', ['chrome_passwords', 'firefox_passwords', 'wifi_passwords_windows']),
            (r'ssh.*(?:key|private|extract)', ['ssh_private_keys']),
            # DNS C2
            (r'(?:doh|dns.?over.?https).*(?:c2|channel|beacon)', ['doh_c2_channel']),
            (r'dns.*c2|dns.*command.*control', ['dns_c2_channel', 'dns_query_craft', 'dns_response_spoof']),
            (r'dns.*tunnel', ['dns_c2_channel', 'dns_query_craft']),
            (r'dns.*exfil|covert.*dns', ['dns_c2_channel', 'dns_query_craft']),
            # C2 / Implant / Resilience
            # Lateral Movement
            (r'lateral.*(?:movement|pivot).*(?:orchestrat|pipeline|auto)', ['lateral_movement_orchestrator']),
            (r'(?:pivot|hop).*(?:network|host|subnet)', ['lateral_movement_orchestrator']),
            (r'(?:ssh|port).*forward(?:er|ing)?', ['ssh_port_forwarder']),
            (r'(?:multi.?hop|chain).*(?:tunnel|ssh)', ['ssh_port_forwarder']),
            (r'socks.*proxy.*ssh', ['ssh_port_forwarder']),
            # Credential Harvesting Pipeline
            (r'credential.*(?:harvest|pipeline|extract|dump).*(?:all|full|complete|multi|auto)', ['credential_harvest_pipeline']),
            (r'(?:harvest|extract|dump).*(?:all|every).*credential', ['credential_harvest_pipeline']),
            (r'credential.*exfil(?:trate)?.*encrypt', ['credential_exfil_encrypted']),
            # Phase 5 persistence watchdog (before generic persistence_chain)
            (r'persist.*(?:watchdog|health.*check|layer.*(?:status|monitor))', ['persistence_watchdog']),
            (r'(?:multi.?layer|all.*layer|5.*layer|layered).*persist', ['persistence_watchdog']),
            (r'(?:self.?heal|auto.?repair|auto.?restore).*persist', ['persistence_watchdog']),
            # Phase 9 — Autonomous Decision Engine (before Phase 8 and generic)
            (r'(?:autonomous|decision).*(?:engine|orchestrat|chain)', ['autonomous_decision_engine']),
            (r'(?:operation|kill).*chain.*(?:orchestrat|automat|engine|full)', ['autonomous_decision_engine']),
            (r'(?:10.?phase|full.*chain|end.?to.?end).*(?:operation|attack|campaign)', ['autonomous_decision_engine']),
            (r'(?:mission|operation).*(?:config|profile|roe|constraint|parameter)', ['operation_chain_config']),
            (r'(?:stealth.*recon|smash.*grab|full.*compromise|infrastructure.*attack|counter.*operation).*(?:profile|config|mission)', ['operation_chain_config']),
            (r'(?:rules.*of.*engagement|roe).*(?:config|set|defin)', ['operation_chain_config']),
            # Phase 8 — Enhanced Anti-Forensics (before Phase 7 and generic)
            (r'(?:enhanced|full|complete).*anti.?forensic', ['enhanced_anti_forensics']),
            (r'(?:log|trace|history).*(?:clear|wipe|eliminat|manipulat|sanitiz)', ['enhanced_anti_forensics']),
            (r'(?:timestomp|timestamp).*(?:alter|manipulat|modify)', ['enhanced_anti_forensics']),
            (r'(?:secure|overwrite).*delet', ['enhanced_anti_forensics']),
            (r'(?:evidence|false.*flag|attribution).*(?:plant|misdirect|fake)', ['evidence_planter']),
            (r'(?:apt|nation.*state).*(?:false.*flag|misdirect|attribut)', ['evidence_planter']),
            (r'(?:memory|heap).*(?:forensic|evasion|cleanup|scrambl)', ['memory_forensics_evasion']),
            (r'(?:string.*obfuscat|xor.*string|stack.*string)', ['memory_forensics_evasion']),
            # Phase 7 — Objective Modules (before Phase 6 and generic patterns)
            (r'(?:intel|intelligence).*(?:collect|gather|harvest|target)', ['objective_intel_collection']),
            (r'(?:document|file).*(?:harvest|collect|steal).*(?:priority|target)', ['objective_intel_collection']),
            (r'(?:enterprise|targeted).*ransomware', ['objective_ransomware_enterprise']),
            (r'ransomware.*(?:enterprise|campaign|deploy)', ['objective_ransomware_enterprise']),
            (r'(?:ics|ot|scada|plc).*(?:sabotage|disrupt|destroy|corrupt)', ['objective_sabotage_ics']),
            (r'(?:modbus|plc).*(?:register|coil).*(?:manipulat|corrupt|overwrite)', ['objective_sabotage_ics']),
            (r'(?:counter.?intel|competing.*(?:implant|operator)).*(?:detect|assess|find)', ['objective_counter_intel']),
            (r'(?:honeypot|honey.*pot).*(?:detect|check|identify|assess)', ['objective_counter_intel']),
            (r'(?:edr|siem|monitoring).*(?:detect|check|evade)', ['objective_counter_intel']),
            (r'(?:objective|mission).*(?:select|plan|recommend|choose)', ['objective_selector']),
            (r'(?:autonomous|auto).*(?:objective|mission).*(?:plan|select)', ['objective_selector']),
            # Phase 6 — Multi-Channel C2 (before generic C2 patterns)
            (r'(?:doh|dns.?over.?https).*(?:c2|channel|beacon)', ['doh_c2_channel']),
            (r'(?:email|smtp|imap).*(?:c2|channel|dead.*drop)', ['email_c2_channel']),
            (r'(?:stego|steganograph).*(?:c2|channel|covert)', ['stego_c2_channel']),
            (r'(?:blockchain|bitcoin|btc|op.?return).*(?:c2|dead.*drop|channel)', ['blockchain_c2_dead_drop']),
            (r'(?:websocket|wss?).*(?:c2|channel|beacon)', ['websocket_c2_channel']),
            (r'c2.*(?:orchestrat|failover|multi.*channel|priority)', ['c2_orchestrator_failover']),
            (r'(?:multi.*channel|channel.*(?:select|switch|failover)).*c2', ['c2_orchestrator_failover']),
            (r'(?:failover|fallback).*c2.*(?:orchestrat|manag)', ['c2_orchestrator_failover']),
            # Resilience
            (r'(?:resilient|fallback|multi.?channel).*c2|c2.*(?:fallback|resilient|multi.?channel)', ['resilient_c2_multi_channel']),
            (r'(?:watchdog|respawn|auto.?restart).*(?:process|implant|agent)', ['watchdog_respawn']),
            (r'persistence.*chain|multi.*persist.*deploy|persist.*(?:all|every)', ['persistence_chain']),
            (r'adaptive.*(?:beacon|c2|jitter)', ['adaptive_beacon']),
            (r'c2.*beacon|http.*beacon', ['http_beacon', 'aes_cbc_transport', 'registry_persistence']),
            (r'c2.*implant|command.*and.*control', ['http_beacon', 'dns_c2_channel', 'aes_cbc_transport']),
            # Packet crafting
            (r'arp.*(?:spoof|poison)', ['arp_spoof_reply']),
            (r'tcp.*syn.*(?:scan|flood)', ['raw_tcp_syn', 'syn_flood']),
            (r'(?:packet|frame).*craft', ['raw_tcp_syn', 'arp_spoof_reply', 'dns_query_craft']),
            (r'raw.*(?:tcp|packet)', ['raw_tcp_syn', 'raw_tcp_rst_inject']),
            (r'icmp.*exfil', ['icmp_echo_exfil']),
            # Network poisoning
            (r'llmnr.*(?:poison|spoof)', ['llmnr_poison_response', 'nbns_poison_response']),
            (r'nbns.*(?:poison|spoof)', ['nbns_poison_response', 'llmnr_poison_response']),
            (r'network.*poison', ['llmnr_poison_response', 'nbns_poison_response', 'arp_spoof_reply']),
            # Command injection
            (r'(?:command|cmd|os).*inject', ['results_based_injection', 'blind_time_injection', 'command_obfuscation']),
            (r'reverse.*shell', ['reverse_shell_payloads']),
            (r'bind.*shell', ['bind_shell_payloads']),
            (r'webshell', ['webshell_generator']),
            # AD attacks
            (r'kerberoast|kerberos.*attack', ['kerberos_as_req']),
            (r'pass.*the.*hash', ['pass_the_hash', 'smb_negotiate']),
            (r'lateral.*movement', ['pass_the_hash', 'smb_negotiate']),
            # Post-exploitation
            (r'keylog', ['keylogger_hook']),
            (r'screenshot.*capture', ['screenshot_capture']),
            (r'(?:registry|run.*key).*persist', ['registry_persistence']),
            (r'(?:schtask|scheduled.*task).*persist', ['scheduled_task_persist']),
            (r'persist.*(?:mechanism|technique)', ['persistence_mechanism']),
            (r'file.*exfil', ['data_exfiltration_tool']),
            (r'privilege.*(?:check|escal)', ['privilege_check']),
            # DCE/RPC
            (r'dce.*rpc|dcerpc', ['dcerpc_bind_request']),
            # Evasion / AV bypass
            (r'(?:av|antivirus|edr).*(?:bypass|evas)', ['sandbox_detector', 'polymorphic_wrapper', 'xor_payload_encoder', 'lolbin_executor']),
            (r'amsi.*bypass', ['amsi_bypass']),
            (r'etw.*(?:patch|bypass|blind)', ['etw_patching', 'etw_patchguard_blind']),
            (r'sandbox.*(?:detect|evas|bypass)', ['sandbox_detector', 'vm_detection']),
            (r'anti.*debug', ['anti_debugging', 'anti_debug']),
            (r'polymorphic|metamorphic', ['polymorphic_engine', 'polymorphic_wrapper']),
            (r'(?:xor|encode).*payload', ['xor_payload_encoder', 'shellcode_encoder']),
            (r'lolbin|living.*off.*the.*land', ['lolbin_executor']),
            (r'ppid.*spoof', ['ppid_spoofing']),
            (r'sleep.*obfuscat', ['sleep_obfuscation']),
            (r'control.*flow.*flatten', ['control_flow_flattener']),
            (r'string.*encrypt', ['string_encryption_engine']),
            (r'api.*hash.*resolv', ['api_hashing_resolver']),
            (r'direct.*syscall', ['direct_syscall_stub']),
            (r'(?:log|event).*(?:clear|erase|wipe|tamper)', ['log_clearing_manipulation', 'log_eraser']),
            (r'timestomp', ['timestomping']),
            (r'anti.*forensic', ['anti_forensics']),
            (r'token.*(?:manipulat|impersonat)', ['token_manipulation']),
            (r'named.*pipe.*impersonat', ['named_pipe_impersonation']),
            # Exploit development
            (r'buffer.*overflow|stack.*overflow.*exploit', ['buffer_overflow_exploit', 'cyclic_offset_finder']),
            (r'rop.*chain|return.*oriented', ['rop_chain_builder']),
            (r'format.*string.*(?:exploit|vuln|attack)', ['format_string_exploit']),
            (r'shellcode.*(?:encode|generat|run|load|inject|exec)', ['shellcode_runner_linux', 'fileless_loader']),
            (r'(?:fileless|memory).*(?:load|exec|inject)', ['fileless_loader', 'reflective_python_loader']),
            (r'pwntools|pwn.*exploit', ['pwntools_exploit_template']),
            (r'fuzz(?:er|ing)|harness', ['fuzzer_harness']),
            (r'checksec|binary.*(?:protect|mitigat)', ['checksec_analyzer']),
            (r'cve.*(?:poc|proof|exploit)', ['cve_poc_generator']),
            # Steganography
            (r'steganograph|stego|lsb.*(?:embed|extract|hide)', ['lsb_image_embed', 'lsb_image_extract', 'steganography_data_hiding']),
            (r'audio.*watermark', ['audio_watermark_embed', 'audio_watermark_detect']),
            # Web attacks
            (r'xxe|xml.*external.*entity', ['xxe_attack']),
            (r'ldap.*inject', ['ldap_injection']),
            (r'nosql.*inject', ['nosql_injection']),
            (r'cors.*bypass', ['cors_bypass']),
            (r'cookie.*(?:steal|hijack)', ['cookie_stealer']),
            (r'session.*(?:fixat|hijack)', ['session_fixation']),
            (r'deserializ.*(?:exploit|attack|vuln)', ['deserialization_exploit']),
            (r'race.*condition.*(?:exploit|attack)', ['race_condition']),
            (r'timing.*(?:attack|side.*channel)', ['timing_attack']),
            (r'path.*traversal|directory.*traversal', ['path_traversal_scanner']),
            (r'http.*param.*pollut', ['http_param_pollution']),
            (r'graphql.*inject', ['graphql_injection']),
            (r'cache.*poison', ['cache_poisoning_attack']),
            (r'phishing.*(?:page|site|login)', ['phishing_page', 'phishing_page_generator']),
            # Wireless / RF
            (r'wifi.*scan', ['wifi_scanner']),
            (r'bluetooth.*scan', ['bluetooth_scanner']),
            (r'rf.*(?:signal|analyz)', ['rf_signal_analyzer']),
            (r'ble.*(?:beacon|sniff)', ['ble_beacon_sniffer']),
            # Signal intelligence
            (r'sigint|signal.*intercept', ['signal_interceptor', 'frequency_scanner', 'signal_classifier']),
            (r'frequency.*scan', ['frequency_scanner']),
            (r'direction.*(?:find|arrival)|aoa|doa', ['direction_of_arrival', 'rf_direction_finder']),
            (r'signal.*(?:classif|fingerprint)', ['signal_classifier', 'signal_fingerprinter']),
            (r'spectrum.*analyz', ['spectrum_analyzer']),
            (r'demodulat', ['demodulator_am_fm']),
            (r'pulse.*descriptor', ['pulse_descriptor']),
            # Military EW
            (r'gps.*(?:spoof|denial|jam)', ['gps_spoofing_drift', 'gps_spoofing_jump', 'gps_denial_attack']),
            (r'gps.*(?:detect|anti.*spoof)', ['spoofing_detector_ensemble', 'clock_jump_detector']),
            (r'link.?16|tadil', ['link16_tdma_message']),
            (r'frequency.*hop', ['frequency_hopper']),
            (r'esm.*(?:threat|detect)', ['esm_threat_detector', 'threat_library_matcher']),
            (r'counter.*(?:uas|drone|uav)', ['counter_uas_jammer', 'counter_uas_gps_denial']),
            (r'mavlink', ['mavlink_heartbeat']),
            (r'(?:barrage|spot).*jam', ['russian_ew_barrage_jammer']),
            (r'drfm.*spoof', ['russian_ew_drfm_spoofer']),
            (r'electronic.*(?:warfare|attack|countermeasure)', ['russian_ew_barrage_jammer', 'russian_ew_drfm_spoofer', 'frequency_hopper']),
            # Ransomware / Destructive
            (r'ransomware|file.*encrypt.*ransom', ['ransomware_encrypt', 'ransomware_decrypt', 'ransomware_rsa_aes']),
            (r'(?:data|disk).*(?:wipe|destruct|destroy)', ['data_destruction_wiper', 'destroy_data']),
            (r'crypto.*min(?:er|ing)', ['crypto_miner']),
            # Phase 5 — Multi-Layer Persistence + Watchdog (BEFORE generic persist patterns)
            (r'(?:userland|user.?land|user.?level).*persist', ['persistence_layer1_userland']),
            (r'(?:layer\s*1|l1).*persist', ['persistence_layer1_userland']),
            (r'(?:service|system).?level.*persist', ['persistence_layer2_service']),
            (r'(?:layer\s*2|l2).*persist', ['persistence_layer2_service']),
            (r'(?:pam.*exec|launchdaemon).*(?:backdoor|persist)', ['persistence_layer2_service']),
            (r'(?:infrastructure|domain|ad).?level.*persist', ['persistence_layer3_infrastructure']),
            (r'(?:layer\s*3|l3).*persist', ['persistence_layer3_infrastructure']),
            (r'(?:skeleton.*key|shadow.*credential|adcs.*cert|adminsdholder).*(?:persist|implant|backdoor)', ['persistence_layer3_infrastructure']),
            (r'(?:supply.*chain|pre.?commit|setup\.py).*(?:inject|persist|backdoor|implant)', ['persistence_layer4_supply_chain']),
            (r'(?:layer\s*4|l4).*persist', ['persistence_layer4_supply_chain']),
            (r'(?:npm.*preinstall|package.*json).*(?:inject|backdoor|persist)', ['persistence_layer4_supply_chain']),
            (r'(?:firmware|uefi|efi|bmc|ipmi|bios).*(?:persist|implant|assess|backdoor)', ['persistence_layer5_firmware']),
            (r'(?:layer\s*5|l5).*persist', ['persistence_layer5_firmware']),
            (r'(?:secure.*boot|bootloader).*(?:assess|check|bypass|persist)', ['persistence_layer5_firmware']),
            (r'(?:full|complete|all|multi).*persist.*(?:deploy|install|suite|framework)', ['persistence_layer1_userland', 'persistence_layer2_service', 'persistence_layer3_infrastructure']),
            # Persistence (advanced)
            (r'wmi.*(?:persist|subscript|event)', ['wmi_event_subscription']),
            (r'com.*(?:hijack|object).*persist', ['com_object_hijacking']),
            (r'dll.*(?:sideload|hijack)', ['dll_sideloading', 'dll_injector']),
            (r'dll.*inject', ['dll_injector']),
            (r'bootkit|mbr.*(?:infect|persist)', ['bootkit_mbr']),
            (r'cron.*persist|persist.*cron', ['persistence_cron']),
            (r'systemd.*persist|persist.*systemd', ['persistence_systemd']),
            (r'ssh.*key.*(?:persist|backdoor)', ['persistence_ssh_key']),
            (r'startup.*folder', ['startup_folder_persist']),
            (r'ld.*preload|preload.*hijack', ['ld_preload_hijack', 'rootkit_ld_preload']),
            # Lateral movement (extended)
            (r'wmi.*(?:exec|lateral|remote)', ['wmi_lateral_movement']),
            (r'ssh.*(?:lateral|brute)', ['ssh_lateral_movement', 'ssh_brute_force']),
            (r'process.*hollow', ['process_hollowing', 'process_hollowing_basic']),
            (r'fileless.*(?:load|exec|attack)', ['fileless_loader']),
            # Network recon / scanning
            (r'port.*scan', ['port_scanner_socket', 'port_scanner_syn']),
            (r'network.*recon', ['network_recon']),
            (r'packet.*sniff', ['packet_sniffer']),
            (r'banner.*grab', ['banner_grabber']),
            (r'traceroute', ['traceroute_tool']),
            # Brute force
            (r'ssh.*brute', ['ssh_brute_force']),
            (r'redis.*(?:brute|exploit)', ['redis_brute_force', 'redis_exploitation']),
            (r'hash.*crack|crack.*hash|password.*crack', ['hash_cracker']),
            (r'credential.*(?:stuff|spray|test)|(?:stuff|spray).*credential', ['password_brute_forcer', 'ssh_brute_paramiko']),
            (r'password.*spray|spray.*password', ['password_brute_forcer']),
            # OSINT / Social engineering
            (r'phishing.*(?:email|credential)', ['phishing_credential_harvest', 'email_spoofer']),
            (r'email.*spoof', ['email_spoofer']),
            (r'osint.*recon', ['osint_recon']),
            (r'macro.*(?:document|build|payload)', ['macro_document_builder']),
            (r'obfuscat.*powershell|powershell.*obfuscat', ['obfuscated_powershell']),
            # Firmware / IoT
            (r'firmware.*(?:extract|dump|analyz)', ['firmware_extractor']),
            (r'mqtt.*(?:monitor|listen|sniff|subscrib)', ['mqtt_monitor']),
            (r'mqtt.*(?:publish|inject|fuzz)', ['mqtt_publish_inject']),
            (r'mqtt.*(?:client|attack)', ['mqtt_client']),
            (r'shodan', ['shodan_search']),
            # Phase 2 — Situational Awareness
            (r'(?:full|complete|deep).*(?:environment|env).*(?:dump|scan|extract)', ['full_environment_dump']),
            (r'(?:situational|post.?exploit).*(?:awareness|recon|enum)', ['situational_awareness_orchestrator']),
            (r'(?:dev|development).*(?:environment|env).*(?:scan|enum|recon)', ['dev_environment_scan']),
            (r'(?:vscode|ide|extension).*(?:scan|enum|token)', ['dev_environment_scan']),
            (r'(?:ai|ml|llm).*(?:environment|infra).*(?:scan|enum|detect)', ['ai_ml_environment_scan']),
            (r'(?:ollama|huggingface|lm.?studio|mlx).*(?:scan|enum|detect|discover)', ['ai_ml_environment_scan']),
            (r'(?:full|complete|deep).*network.*(?:discover|enum|recon)', ['network_discovery_full']),
            (r'(?:arp|routing).*(?:table|dump|enum)', ['network_discovery_full']),
            (r'(?:smb.*share|nfs.*mount).*(?:scan|enum|discover)', ['network_discovery_full']),
            (r'(?:iot.*device|ip.*camera).*(?:scan|enum|discover)', ['network_discovery_full']),
            (r'(?:full|complete|all).*cloud.*(?:enum|scan|recon)', ['cloud_enumerator_full']),
            (r'(?:azure).*(?:enum|scan|recon|list)', ['cloud_enumerator_full']),
            (r'(?:gcp|google.*cloud).*(?:enum|scan|recon|list)', ['cloud_enumerator_full']),
            (r'(?:full|complete|deep|extended).*(?:ad|active.*directory).*(?:enum|recon|scan)', ['ad_enumerator_full']),
            (r'(?:adcs|certificate.*template|esc[1-8]).*(?:enum|scan|check|vuln)', ['ad_enumerator_full']),
            (r'(?:laps|gmsa).*(?:enum|dump|extract|scan)', ['ad_enumerator_full']),
            (r'(?:gpo|trust.*relat|as.?rep).*(?:enum|dump|scan)', ['ad_enumerator_full']),
            # Phase 3 — Credential Harvesting
            (r'(?:process|live).*(?:memory|mem).*(?:extract|dump|credential|harvest)', ['process_memory_extractor']),
            (r'(?:chrome|firefox|edge|browser).*(?:process|memory|mem).*(?:dump|extract)', ['process_memory_extractor']),
            (r'(?:dpapi|data.*protection).*(?:full|pipeline|decrypt|master.*key)', ['dpapi_full_pipeline']),
            (r'(?:kerberos|krb5?).*(?:ticket|tgt|tgs|harvest|extract|ccache)', ['kerberos_ticket_harvester']),
            (r'(?:pass.*the.*ticket|ptt|kirbi|ccache).*(?:extract|convert|dump)', ['kerberos_ticket_harvester']),
            (r'(?:ntlm|sam).*(?:hash|dump|extract)', ['kerberos_ticket_harvester']),
            (r'(?:filesystem|file.*system|disk).*(?:credential|cred|secret).*(?:sweep|scan|harvest)', ['filesystem_credential_sweep']),
            (r'(?:password.*manager|keepass|1password|bitwarden|lastpass).*(?:find|scan|extract|dump)', ['filesystem_credential_sweep']),
            (r'(?:certificate|cert|pfx|p12|pkcs).*(?:extract|find|harvest|sweep)', ['filesystem_credential_sweep']),
            (r'(?:terraform|ansible.*vault|k8s.*secret|kubernetes.*secret).*(?:extract|dump|find)', ['filesystem_credential_sweep']),
            (r'(?:app|application).*(?:credential|cred|password).*(?:harvest|extract|dump)', ['app_credential_harvester']),
            (r'(?:vpn|openvpn|wireguard|forticlient|anyconnect).*(?:config|credential|key).*(?:extract|harvest)', ['app_credential_harvester']),
            (r'(?:rdp|remote.*desktop).*(?:file|credential|password).*(?:extract|harvest|find)', ['app_credential_harvester']),
            (r'(?:email|outlook|thunderbird).*(?:credential|password|account).*(?:extract|harvest)', ['app_credential_harvester']),
            (r'(?:discord|slack|teams|telegram).*(?:token|credential|session).*(?:extract|harvest)', ['app_credential_harvester']),
            (r'(?:credential|cred|password).*(?:spray|bridge|reuse|stuffing|test)', ['credential_spray_bridger']),
            (r'(?:full|complete|all).*(?:credential|cred).*(?:harvest|extract|sweep|pipeline)', ['credential_harvest_orchestrator']),
            # Phase 4 — Attack Graph + Lateral Movement
            (r'(?:attack|pivot).*(?:graph|map|network).*(?:build|create|engine)', ['attack_graph_engine']),
            (r'(?:lateral.*movement|pivot).*(?:graph|plan|auto|recursive)', ['recursive_graph_expander']),
            (r'(?:pass.*the.*hash|pth).*(?:attack|exec|smb|winrm)', ['pass_the_hash_executor']),
            (r'(?:wmi|dcom).*(?:exec|lateral|remote|command)', ['wmi_dcom_lateral']),
            (r'(?:winrm|psexec|smbexec).*(?:exec|lateral|remote|command)', ['wmi_dcom_lateral']),
            (r'(?:overpass.*the.*hash|pass.*the.*key|opth)', ['overpass_the_hash']),
            (r'(?:recursive|auto).*(?:graph|pivot|expand|lateral)', ['recursive_graph_expander']),
            (r'(?:shortest.*path|path.*to).*(?:domain.*admin|objective|dc)', ['attack_graph_engine']),
            # AD Enterprise (extended)
            (r'(?:active.*directory|ad).*enum', ['ad_enumerator']),
            (r'bloodhound|sharphound', ['bloodhound_collector']),
            (r'dcsync', ['dcsync_attack']),
            (r'golden.*ticket', ['golden_ticket_forger']),
            (r'lsass.*(?:dump|extract)', ['lsass_memory_dump', 'lsass_dump_concept']),
            (r'dpapi.*(?:extract|decrypt)', ['dpapi_credential_extraction', 'credential_extractor_dpapi']),
            (r'browser.*credential', ['browser_credential_harvest', 'credential_harvester_browser']),
            # Protocol attacks (extended)
            (r'dns.*(?:spoof|poison)', ['dns_spoofer', 'dns_cache_poisoning', 'dns_response_spoof']),
            (r'bgp.*hijack', ['bgp_hijack']),
            (r'icmp.*redirect', ['icmp_redirect_builder']),
            (r'ip.*fragment', ['ip_fragmentation']),
            (r'ping.*of.*death', ['ping_of_death']),
            # Tunneling / Pivoting
            (r'(?:icmp|covert).*(?:channel|tunnel)', ['icmp_covert_channel_sender', 'icmp_covert_channel_receiver', 'covert_icmp_channel']),
            (r'dns.*tunnel', ['dns_tunnel_client', 'dns_tunnel_server', 'dns_tunneling_c2']),
            (r'http.*tunnel', ['http_tunnel_proxy']),
            (r'socks.*proxy|socks5', ['socks5_proxy']),
            (r'port.*forward', ['port_forwarder']),
            (r'network.*pivot', ['network_pivot_scanner']),
            # Encrypted C2
            (r'encrypted.*c2|c2.*encrypt', ['encrypted_c2_server', 'encrypted_c2_client']),
            (r'domain.*front', ['http_c2_domain_fronting']),
            (r'custom.*protocol.*c2', ['custom_protocol_c2']),
            (r'c2.*(?:stag|load|drop)', ['c2_stager', 'c2_loader']),
            (r'c2.*(?:server|operator)', ['c2_server', 'c2_operator']),
            # Crypto tools
            (r'jwt.*(?:forg|crack|exploit)', ['jwt_forger']),
            (r'hmac.*auth', ['hmac_authenticator']),
            (r'aes.*(?:encrypt|tool)', ['aes_encryption_tool']),
            # Malware analysis (blue-adjacent)
            (r'yara.*(?:rule|generat)', ['yara_rule_generator']),
            (r'ioc.*extract', ['ioc_extractor_basic']),
            (r'(?:dynamic|malware).*sandbox', ['dynamic_sandbox']),
            (r'volatility|memory.*forensic', ['volatility_automator', 'memory_dump_analyzer']),
            (r'binary.*analy[sz]', ['binary_analyzer']),
            # Malware components
            (r'worm.*(?:spread|propagat)', ['worm_spreader']),
            (r'botnet.*(?:client|node)', ['botnet_client']),
            (r'rootkit', ['rootkit_basic', 'rootkit_ld_preload']),
            # iOS / macOS security
            (r'(?:ios|iphone).*(?:keychain|extract)', ['ios_keychain_extractor', 'keychain_database_parser']),
            (r'(?:ios|iphone).*backup.*forensic', ['ios_backup_forensics']),
            (r'jailbreak.*(?:detect|bypass)', ['jailbreak_detection_bypass', 'jailbreak_detection_comprehensive']),
            (r'ssl.*pin.*bypass', ['ssl_pinning_bypass']),
            (r'(?:ios|macho).*binary', ['macho_binary_parser', 'ipa_binary_analysis']),
            (r'tcc.*(?:bypass|database|parse)', ['tcc_database_parser', 'tcc_bypass_engine', 'tcc_injection_poc']),
            (r'dylib.*(?:inject|hijack)', ['dylib_injection_engine', 'dylib_hijack_validator']),
            (r'xpc.*(?:enum|attack|probe)', ['xpc_service_enumerator', 'xpc_attack_prober', 'xpc_method_enumerator']),
            (r'gatekeeper|notariz', ['gatekeeper_notarization_analyzer']),
            (r'entitlement.*(?:chain|kill)', ['entitlement_killchain']),
            (r'sandbox.*(?:profile|escape|chain)', ['ios_sandbox_escape', 'sandbox_profile_decompiler', 'sandbox_chain_validator']),
            (r'(?:exfil|data).*(?:https|cloud)', ['exfil_https_cloud', 'exfiltrate_multi']),
            (r'(?:exfil|data).*dns', ['staged_exfil_dns', 'exfiltration_dns', 'exfil_dns_tunnel']),
            (r'webshell.*deploy', ['webshell_deployment']),
            (r'supply.*chain|dependency.*confus', ['supply_chain_dependency_confusion']),
            (r'sam.*dump', ['sam_dump']),
            (r'ssl.*cert.*check', ['ssl_certificate_checker']),
            (r'deleted.*file.*recov', ['deleted_file_recovery']),
            (r'disable.*defense|kill.*(?:av|edr)', ['disable_defenses']),
            (r'(?:list|enum).*(?:running.*)?process(?:es)?$|pid.*list|process.*enum', ['process_list']),
            (r'payload.*deliver', ['payload_delivery_triple_fallback']),
            (r'ddos|(?:syn|udp).*flood', ['ddos_syn_flood', 'syn_flood', 'udp_flood']),
            # ── CIR essential fragments (21 full implementations) ──
            # Network analysis
            (r'network.*sniff|sniff.*(?:network|traffic|packet)', ['network_sniffer']),
            (r'(?:network|traffic).*analy[sz]|pcap.*analy[sz]|traffic.*monitor', ['network_traffic_analyzer']),
            # Reconnaissance
            (r'subdomain.*(?:enum|brute|discover|scan)|(?:enum|discover|scan).*subdomain', ['subdomain_enumerator']),
            (r'service.*fingerprint|fingerprint.*service|(?:service|version).*detect', ['service_fingerprinter']),
            (r'dns.*(?:zone.*transfer|axfr)|axfr|zone.*transfer', ['dns_zone_transfer']),
            # Web attacks (extended)
            (r'xss.*(?:scan|detect|find|test)|(?:scan|detect|find|test).*xss|cross.*site.*script', ['xss_scanner']),
            # Backdoors & RATs
            (r'(?:tcp|reverse).*backdoor|backdoor.*(?:tcp|reverse|shell)', ['backdoor_reverse_tcp']),
            (r'(?:remote.*access.*trojan|rat\b)(?!.*detect)', ['remote_access_trojan']),
            (r'botnet.*(?:control|c2|command|manag|server)', ['botnet_controller']),
            # Persistence (extended — maps to full multi-vector implementation)
            (r'persist.*(?:mechanism|technique|multi|all|deploy|install|vector|windows)|multi.*persist|linux.*persist|windows.*persist', ['persistence_mechanism']),
            # Credential harvesting (extended)
            (r'mimikatz|cred.*(?:harvest|dump).*(?:linux|all|system)|linux.*cred.*(?:harvest|dump)', ['mimikatz_alternative']),
            (r'(?:brute.*force|brute.*attack).*(?:password|login|auth|ssh|ftp|http)', ['password_brute_forcer']),
            (r'password.*brute|login.*brute', ['password_brute_forcer']),
            # Screenshot
            (r'screenshot.*(?:tool|captur|grab|take)|(?:captur|take).*screenshot', ['screenshot_capture']),
            # Data theft
            (r'(?:data|file).*exfil|exfil.*(?:data|file|tool)', ['data_exfiltration_tool']),
            (r'(?:file.*steal|steal.*file|collect.*sensitive|sensitive.*file)', ['file_stealer']),
            # Process manipulation
            (r'(?:process|code).*inject(?:ion|or)?|inject.*(?:process|code)|ptrace.*inject', ['process_injection']),
            # MITM
            (r'man.*in.*(?:the|da).*middle|mitm|arp.*(?:dns|poison).*mitm', ['mitm_arp_dns']),
            # ICS/SCADA/Maritime
            (r'modbus.*(?:scan|enum|discover|probe)|(?:scan|probe).*modbus|plc.*scan', ['modbus_scanner']),
            (r'modbus.*(?:write|manipulat|attack|fuzz)', ['modbus_write_registers']),
            (r'nmea.*(?:read|decode|pars)|ais.*(?:read|decode|listen)', ['nmea_ais_reader']),
            (r'(?:nmea|ais).*(?:spoof|inject|fake|ghost)', ['nmea_ais_spoofer']),
            (r'hmi.*(?:probe|scan|web|attack|login)', ['hmi_web_probe']),
            (r'snmp.*(?:scan|brute|walk|community|enum)', ['snmp_scanner']),
            (r'ssh.*(?:brute|credential|auth.*test|password)', ['ssh_brute_paramiko']),
            (r'ssh.*(?:test|check|audit|scan|enum)', ['ssh_brute_paramiko', 'ssh_brute_force']),
            (r'ics.*(?:protocol|fuzz|scan|probe)', ['ics_protocol_fuzzer']),
            (r'scada.*(?:scan|probe|attack|enum)', ['modbus_scanner', 'hmi_web_probe']),
            # Wireless
            (r'(?:wifi|wlan).*(?:deauth|disassoc|kick|jam)|deauth.*(?:wifi|wlan|802)', ['wifi_deauth']),
            # Analysis tools
            (r'(?:log|syslog|event).*analy[sz]|analy[sz].*(?:log|syslog|event)', ['log_analyzer_tool']),
            (r'malware.*(?:analy[sz]|static|reverse)|(?:static|reverse).*analy[sz].*(?:malware|binary|pe|elf)', ['malware_static_analyzer']),

            # ── Design patterns (must be before generic patterns) ──
            (r'observer.*pattern|event.*(?:registration|emitter|listener)', ['observer_pattern']),
            (r'circuit.*breaker', ['circuit_breaker']),
            (r'pub.?sub|message.*broker', ['pub_sub_broker']),
            (r'(?:function|method).*returns?\s+itself|self.?returning', ['self_returning_function']),
            (r'toml.*(?:pars|read|writ|config)', ['toml_parser']),
            (r'command.*line.*arg|argparse|cli.*arg', ['argparse_basic']),
            (r'^make it work|^process the input|^do (?:the|it)|^just (?:do|make)', ['generic_data_processor']),
            (r'(?:fetch|scrape).*(?:link|url|page|web)|(?:link|url).*(?:check|status|extract)', ['link_checker']),
            (r'(?:query|select).*(?:sqlite|database|db).*(?:csv|export)', ['sqlite3_query_to_csv']),
            (r'(?:csv.*sqlite|sqlite.*csv|csv.*(?:table|database|db)|(?:table|database|db).*csv)', ['csv_to_sqlite']),
            # ── Self-contained code snippets (single fragment, no wiring) ──
            (r'ternary.*operator|conditional.*expression', ['ternary_operator']),
            (r'global.*variable|variable.*global', ['global_variable']),
            (r'(?:string|text).*(?:contains|substring)', ['string_contains']),
            (r'(?:delete|remove).*(?:file|folder|directory)', ['delete_file_folder']),
            (r'(?:list|array).*(?:empty|is empty)', ['check_list_empty']),
            (r'(?:string|text).*(?:is empty|empty)', ['string_is_empty']),
            (r'(?:escape|literal).*(?:curly|brace|format)', ['format_string_braces']),
            (r'import.*(?:from|different).*(?:folder|directory|path)', ['import_from_folder']),
            (r'getattr|call.*function.*(?:name|string)', ['getattr_call_by_name']),
            (r'(?:pretty.*print|format).*json', ['json_pretty_print']),
            (r'(?:last|final).*element.*(?:list|array)', ['list_last_element']),
            (r'(?:iterate|loop).*(?:rows|dataframe)', ['pandas_iterrows']),
            (r'(?:select|filter).*(?:rows|dataframe)', ['pandas_select_rows']),
            (r'rename.*column', ['pandas_rename_cols']),
            (r'(?:delete|drop|remove).*column', ['pandas_drop_column']),
            (r'(?:row.*count|count.*row|shape).*(?:dataframe|pandas)', ['pandas_row_count']),
            (r'thread.*safe.*counter', ['thread_safe_counter']),
            (r'binary.*tree|bst.*(?:insert|search)', ['binary_tree']),
            (r'retry.*(?:decorator|backoff)|(?:decorator|backoff).*retry', ['retry_backoff']),
            (r'trie|prefix.*tree', ['trie_prefix_tree']),
            (r'(?:key.*value|kv).*store.*(?:ttl|expir)', ['cache_eviction']),
            # ── Complex systems (multi-fragment) ──
            (r'(?:web.*api|rest.*api|api|endpoint|server)', [
                'flask_app', 'api_endpoint', 'http_server']),
            (r'(?:database|inventory|management|crud|store|record)', [
                'sqlite3_create', 'sqlite3_query', 'database_insert']),
            (r'(?:url.*short|todo|registration)', [
                'sqlite3_create', 'flask_app', 'sqlite3_query']),
            (r'(?:schedule|cron|job|timer)', [
                'sched_scheduler', 'datetime_now', 'threading_thread']),
            (r'(?:log.*rotat)', ['log_rotation_system']),
            (r'(?:synchroniz|sync.*director|file.*sync)', ['file_sync_system']),
            (r'(?:thread|concurrent|parallel|singleton|multiprocess)', [
                'threading_thread', 'threading_pool']),
            (r'(?:monitor|watch|alert|guard|lighthouse)', [
                'subprocess_run', 'datetime_now', 'time_sleep_loop']),
            (r'(?:test.*data|realistic.*data|mock|fake|generat)', [
                'datetime_now', 'json_dump', 'csv_write']),
            (r'(?:priority|queue|adaptive)', [
                'sqlite3_create', 'datetime_now', 'list_sort']),
            (r'(?:error.*handl|retry|fallback|safety.*net)', [
                'http_get', 'file_write']),
            (r'(?:config|settings|preference)', [
                'json_load', 'file_read', 'json_dump']),
        ]

        for pattern, frag_keys in VOID_PATTERNS:
            if re.search(pattern, intent_lower):
                for key in frag_keys:
                    if key in self.fragments and key not in used:
                        result.append((key, self.fragments[key]))
                        used.add(key)
                break

        return result if result else None
