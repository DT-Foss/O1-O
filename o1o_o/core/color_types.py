"""
Color Type System — Deterministic data-flow typing for fragment assembly.

Every fragment declares ONE input color and ONE output color.
Assembly = chain fragments where output_color[A] == input_color[B].
No scoring. No fuzzy matching. Binary: colors match or they don't.

Colors represent data-flow categories:
  TEXT     = plaintext strings, file content, readable text
  STRUCT   = structured data: dicts, lists, parsed objects
  TABULAR  = rows/records: CSV data, database results
  BYTES    = raw binary data, byte streams
  SERIAL   = serialized format: JSON/XML/YAML strings
  PATH     = file/directory paths, filesystem references
  RESPONSE = HTTP/network response objects
  VOID     = no meaningful input (standalone) or no meaningful output (side-effect)
"""
# Dependencies: none
# Depended by: code_assembler, color_assembler, color_checker


# ─── Color constants ─────────────────────────────────────────
TEXT     = 'TEXT'
STRUCT   = 'STRUCT'
TABULAR  = 'TABULAR'
BYTES    = 'BYTES'
SERIAL   = 'SERIAL'
PATH     = 'PATH'
RESPONSE = 'RESPONSE'
VOID     = 'VOID'

ALL_COLORS = {TEXT, STRUCT, TABULAR, BYTES, SERIAL, PATH, RESPONSE, VOID}

# ─── Fragment Color Registry ─────────────────────────────────
# Maps fragment_key → (input_color, output_color)
# One line per fragment. No ambiguity.

COLOR_REGISTRY = {
    # ── File I/O ──
    'file_read':          (PATH, TEXT),
    'file_readline':      (PATH, TEXT),
    'file_readlines':     (PATH, TEXT),
    'file_read_binary':   (PATH, BYTES),
    'file_write':         (TEXT, VOID),
    'file_writelines':    (TEXT, VOID),
    'file_append':        (TEXT, VOID),
    'file_write_binary':  (BYTES, VOID),

    # ── JSON ──
    'json_load':          (PATH, STRUCT),
    'json_loads':         (SERIAL, STRUCT),
    'json_dump':          (STRUCT, VOID),
    'json_dumps':         (STRUCT, SERIAL),

    # ── CSV ──
    'csv_read':           (PATH, TABULAR),
    'csv_dictreader':     (PATH, TABULAR),
    'csv_write':          (TABULAR, VOID),
    'csv_dictwriter':     (TABULAR, VOID),

    # ── XML ──
    'xml_parse':          (PATH, STRUCT),
    'xml_read':           (SERIAL, STRUCT),

    # ── Data transform ──
    'list_filter':        (STRUCT, STRUCT),
    'list_comprehension': (STRUCT, STRUCT),
    'set_dedup':          (STRUCT, STRUCT),
    'dict_dedup':         (STRUCT, STRUCT),
    'list_sort':          (STRUCT, STRUCT),
    'sorted_call':        (STRUCT, STRUCT),
    'collections_counter':(STRUCT, STRUCT),
    'statistics_mean':    (STRUCT, TEXT),
    'flatten_list':       (STRUCT, STRUCT),
    'statistics_basic':   (STRUCT, TEXT),

    # ── Regex / String ──
    'string_split':       (TEXT, STRUCT),     # safe default for TEXT→STRUCT
    're_match':           (TEXT, TEXT),
    're_search':          (TEXT, TEXT),
    're_findall':         (TEXT, STRUCT),
    're_finditer':        (TEXT, STRUCT),
    're_sub':             (TEXT, TEXT),
    're_split':           (TEXT, STRUCT),
    'string_format':      (STRUCT, TEXT),
    'template_render':    (STRUCT, TEXT),
    'string_title_case':  (TEXT, TEXT),
    'string_palindrome':  (TEXT, TEXT),
    'string_word_count':  (TEXT, TEXT),

    # ── Hash / Crypto ──
    'hashlib_md5':        (TEXT, TEXT),
    'hashlib_sha256':     (TEXT, TEXT),
    'hash_file':          (PATH, TEXT),
    'aes_encrypt':        (TEXT, BYTES),
    'aes_decrypt':        (BYTES, TEXT),
    'fernet_encrypt':     (TEXT, BYTES),
    'fernet_decrypt':     (BYTES, TEXT),

    # ── HTTP / Network ──
    'requests_get':       (TEXT, RESPONSE),
    'urllib_get':          (TEXT, RESPONSE),
    'http_get':           (TEXT, RESPONSE),
    'requests_post':      (STRUCT, RESPONSE),
    'http_post':          (STRUCT, RESPONSE),
    'http_server':        (VOID, VOID),
    'flask_app':          (VOID, VOID),
    'api_endpoint':       (VOID, VOID),

    # ── Socket ──
    'socket_server':      (VOID, VOID),
    'tcp_listener':       (VOID, VOID),
    'socket_client':      (TEXT, BYTES),
    'tcp_connect':        (TEXT, BYTES),

    # ── Database ──
    'sqlite3_create':     (VOID, VOID),
    'sqlite3_query':      (TEXT, TABULAR),
    'sqlite3_select':     (TEXT, TABULAR),
    'sqlite3_insert':     (STRUCT, VOID),
    'database_insert':    (STRUCT, VOID),

    # ── Filesystem ──
    'os_listdir':         (PATH, STRUCT),
    'os_walk':            (PATH, STRUCT),
    'glob_glob':          (TEXT, STRUCT),
    'glob_rglob':         (PATH, STRUCT),
    'shutil_copy':        (PATH, VOID),
    'shutil_copytree':    (PATH, VOID),
    'os_remove':          (PATH, VOID),
    'shutil_rmtree':      (PATH, VOID),
    'shutil_move':        (PATH, VOID),
    'os_rename':          (PATH, VOID),
    'os_makedirs':        (PATH, VOID),
    'os_mkdir':           (PATH, VOID),
    'path_exists':        (PATH, TEXT),
    'path_is_file':       (PATH, TEXT),
    'path_is_dir':        (PATH, TEXT),
    'path_join':          (TEXT, PATH),
    'os_getcwd':          (VOID, PATH),

    # ── Time ──
    'datetime_now':       (VOID, TEXT),
    'datetime_strftime':  (VOID, TEXT),
    'datetime_timestamp': (VOID, TEXT),
    'datetime_strptime':  (TEXT, TEXT),
    'datetime_timedelta': (VOID, TEXT),

    # ── System ──
    'subprocess_run':     (TEXT, TEXT),
    'subprocess_check_output': (TEXT, TEXT),
    'subprocess_popen':   (TEXT, TEXT),
    'signal_handler':     (VOID, VOID),

    # ── Threading ──
    'threading_thread':   (VOID, VOID),
    'threading_pool':     (STRUCT, STRUCT),

    # ── Scheduling ──
    'sched_scheduler':    (VOID, VOID),
    'time_sleep_loop':    (VOID, VOID),

    # ── Compression ──
    'zipfile_create':     (PATH, VOID),
    'tarfile_create':     (PATH, VOID),
    'gzip_compress':      (PATH, VOID),
    'zipfile_extract':    (PATH, VOID),
    'tarfile_extract':    (PATH, VOID),
    'gzip_decompress':    (PATH, BYTES),

    # ── Serialization ──
    'pickle_dump':        (STRUCT, VOID),
    'pickle_load':        (PATH, STRUCT),

    # ── Algorithms ──
    'binary_search':      (STRUCT, TEXT),
    'prime_sieve':        (VOID, STRUCT),
    'math_gcd':           (VOID, TEXT),
    'math_factorial':     (VOID, TEXT),
    'matrix_transpose':   (STRUCT, STRUCT),
    'lru_cache_impl':     (VOID, VOID),
    'observer_pattern':   (VOID, VOID),
    'qrcode_generate':    (TEXT, VOID),

    # ── Self-contained systems ──
    'log_rotation_system': (VOID, VOID),
    'file_sync_system':    (VOID, VOID),

    # ── Self-contained snippets (StackOverflow-style) ──
    'ternary_operator':     (VOID, VOID),
    'global_variable':      (VOID, VOID),
    'string_contains':      (VOID, VOID),
    'delete_file_folder':   (VOID, VOID),
    'check_list_empty':     (VOID, VOID),
    'string_is_empty':      (VOID, VOID),
    'format_string_braces': (VOID, VOID),
    'import_from_folder':   (VOID, VOID),
    'getattr_call_by_name': (VOID, VOID),
    'json_pretty_print':    (VOID, VOID),
    'list_last_element':    (VOID, VOID),
    'thread_safe_counter':  (VOID, VOID),
    'binary_tree':          (VOID, VOID),
    'trie_prefix_tree':     (VOID, VOID),
    'retry_backoff':        (VOID, VOID),
    'cache_eviction':       (VOID, VOID),
    'pandas_iterrows':      (VOID, VOID),
    'pandas_select_rows':   (VOID, VOID),
    'pandas_rename_cols':   (VOID, VOID),
    'pandas_drop_column':   (VOID, VOID),
    'pandas_row_count':     (VOID, VOID),

    # ── Offensive Security Tools (all VOID→VOID, self-contained) ──
    # SSH
    'ssh_brute_force':              (VOID, VOID),
    'ssh_brute_paramiko':           (VOID, VOID),
    'ssh_lateral_movement':         (VOID, VOID),
    'ssh_key_harvester':            (VOID, VOID),
    'ssh_key_theft':                (VOID, VOID),
    'ssh_private_keys':             (VOID, VOID),
    'ssh_key_persistence_chattr':   (VOID, VOID),
    'persistence_ssh_key':          (VOID, VOID),
    'compound_kill_chain_ssh':      (VOID, VOID),
    # Port scanners
    'port_scanner_socket':          (VOID, VOID),
    'port_scanner_syn':             (VOID, VOID),
    'port_scan_stealth':            (VOID, VOID),
    'network_recon':                (VOID, VOID),
    # Credential harvesters
    'credential_harvester_browser': (VOID, VOID),
    'credential_harvester_env':     (VOID, VOID),
    'credential_harvester_wifi':    (VOID, VOID),
    'credential_file_scanner_http': (VOID, VOID),
    'credential_extractor_dpapi':   (VOID, VOID),
    'browser_credential_harvest':   (VOID, VOID),
    'chrome_passwords':             (VOID, VOID),
    'firefox_passwords':            (VOID, VOID),
    'wifi_passwords_linux':         (VOID, VOID),
    'wifi_passwords_windows':       (VOID, VOID),
    'env_file_secrets':             (VOID, VOID),
    'git_credential_extract':       (VOID, VOID),
    'windows_credential_vault':     (VOID, VOID),
    'browser_cookies':              (VOID, VOID),
    'keepass_finder':               (VOID, VOID),
    'dpapi_credential_extraction':  (VOID, VOID),
    # C2 / Reverse shells
    'c2_server':                    (VOID, VOID),
    'c2_client':                    (VOID, VOID),
    'c2_implant':                   (VOID, VOID),
    'c2_stager':                    (VOID, VOID),
    'c2_loader':                    (VOID, VOID),
    'c2_operator':                  (VOID, VOID),
    'reverse_shell_socket':         (VOID, VOID),
    'reverse_shell_pty':            (VOID, VOID),
    'reverse_shell_listener':       (VOID, VOID),
    'encrypted_c2_server':          (VOID, VOID),
    'encrypted_c2_client':          (VOID, VOID),
    'http_c2_domain_fronting':      (VOID, VOID),
    'dns_tunneling_c2':             (VOID, VOID),
    'custom_protocol_c2':           (VOID, VOID),
    'covert_icmp_channel':          (VOID, VOID),
    'http_beacon':                  (VOID, VOID),
    'dns_c2_channel':               (VOID, VOID),
    'aes_cbc_transport':            (VOID, VOID),
    'xor_transport_cipher':         (VOID, VOID),
    # Persistence
    'persistence_systemd':          (VOID, VOID),
    'persistence_cron':             (VOID, VOID),
    'registry_persistence':         (VOID, VOID),
    'scheduled_task_persist':       (VOID, VOID),
    'wmi_event_subscription':       (VOID, VOID),
    'dll_sideloading':              (VOID, VOID),
    'com_object_hijacking':         (VOID, VOID),
    'bootkit_mbr':                  (VOID, VOID),
    'rootkit_ld_preload':           (VOID, VOID),
    # Exfiltration
    'exfil_dns_tunnel':             (VOID, VOID),
    'exfiltrate_multi':             (VOID, VOID),
    'file_exfiltrator':             (VOID, VOID),
    'file_exfiltration':            (VOID, VOID),
    'exfil_https_cloud':            (VOID, VOID),
    'staged_exfil_dns':             (VOID, VOID),
    'icmp_echo_exfil':              (VOID, VOID),
    # Network attacks
    'arp_spoofer':                  (VOID, VOID),
    'arp_spoof_reply':              (VOID, VOID),
    'dns_spoofer':                  (VOID, VOID),
    'dns_cache_poisoning':          (VOID, VOID),
    'packet_sniffer':               (VOID, VOID),
    'packet_injector':              (VOID, VOID),
    'syn_flood':                    (VOID, VOID),
    'udp_flood':                    (VOID, VOID),
    'raw_tcp_syn':                  (VOID, VOID),
    'raw_tcp_rst_inject':           (VOID, VOID),
    'llmnr_poison_response':        (VOID, VOID),
    'nbns_poison_response':         (VOID, VOID),
    'pass_the_hash':                (VOID, VOID),
    'ntlm_type1_message':           (VOID, VOID),
    'ntlm_type3_response':          (VOID, VOID),
    'rogue_smb_auth_server':        (VOID, VOID),
    'smb_negotiate':                (VOID, VOID),
    'smb2_negotiate':               (VOID, VOID),
    'dns_query_craft':              (VOID, VOID),
    'dns_response_spoof':           (VOID, VOID),
    # SQL injection
    'sql_injection_scanner':        (VOID, VOID),
    'blind_boolean_bisection':      (VOID, VOID),
    'time_based_delay':             (VOID, VOID),
    'union_column_count':           (VOID, VOID),
    'error_based_extract':          (VOID, VOID),
    'stacked_query_exec':           (VOID, VOID),
    'db_fingerprint':               (VOID, VOID),
    'file_read_via_sql':            (VOID, VOID),
    # Command injection
    'results_based_injection':      (VOID, VOID),
    'webshell_generator':           (VOID, VOID),
    'bind_shell_payloads':          (VOID, VOID),
    'reverse_shell_payloads':       (VOID, VOID),
    'command_obfuscation':          (VOID, VOID),
    'os_command_exfiltration':      (VOID, VOID),
    # Evasion
    'amsi_bypass':                  (VOID, VOID),
    'etw_patching':                 (VOID, VOID),
    'anti_debugging':               (VOID, VOID),
    'vm_detection':                 (VOID, VOID),
    'process_hollowing':            (VOID, VOID),
    'fileless_loader':              (VOID, VOID),
    'polymorphic_engine':           (VOID, VOID),
    'string_encryption_engine':     (VOID, VOID),
    'sleep_obfuscation':            (VOID, VOID),
    'ppid_spoofing':                (VOID, VOID),
    'direct_syscall_stub':          (VOID, VOID),
    'api_hashing_resolver':         (VOID, VOID),
    'control_flow_flattener':       (VOID, VOID),
    'api_hooking':                  (VOID, VOID),
    'etw_patchguard_blind':         (VOID, VOID),
    'frequency_analysis':           (VOID, VOID),
    # AD / Kerberos
    'kerberoasting_attack':         (VOID, VOID),
    'golden_ticket_forger':         (VOID, VOID),
    'dcsync_attack':                (VOID, VOID),
    'lsass_memory_dump':            (VOID, VOID),
    'wmi_lateral_movement':         (VOID, VOID),
    # Web attacks
    'cookie_stealer':               (VOID, VOID),
    'xxe_attack':                   (VOID, VOID),
    'nosql_injection':              (VOID, VOID),
    'deserialization_exploit':      (VOID, VOID),
    'ldap_injection':               (VOID, VOID),
    'session_fixation':             (VOID, VOID),
    'cors_bypass':                  (VOID, VOID),
    'race_condition':               (VOID, VOID),
    'timing_attack':                (VOID, VOID),
    'path_traversal_lfi':           (VOID, VOID),
    'phishing_page':                (VOID, VOID),
    'phishing_credential_harvest':  (VOID, VOID),
    'webshell_deployment':          (VOID, VOID),
    # Red team
    'keylogger_pynput':             (VOID, VOID),
    'keylogger_evdev':              (VOID, VOID),
    'keylogger_hook':               (VOID, VOID),
    'ransomware_encrypt':           (VOID, VOID),
    'ransomware_decrypt':           (VOID, VOID),
    'data_destruction_wiper':       (VOID, VOID),
    'hash_cracker':                 (VOID, VOID),
    'privilege_escalation_scanner': (VOID, VOID),
    'steganography_data_hiding':    (VOID, VOID),
    'anti_forensics':               (VOID, VOID),
    'anti_forensics_self_delete':   (VOID, VOID),
    'log_clearing_manipulation':    (VOID, VOID),
    'timestomping':                 (VOID, VOID),
    'token_manipulation':           (VOID, VOID),
    'named_pipe_impersonation':     (VOID, VOID),
    'obfuscated_powershell':        (VOID, VOID),
    'macro_document_builder':       (VOID, VOID),
    'process_injector_linux':       (VOID, VOID),
    'shellcode_runner_linux':       (VOID, VOID),
    'reflective_python_loader':     (VOID, VOID),
    'process_hollowing_basic':      (VOID, VOID),
    'privilege_check':              (VOID, VOID),
    'process_list':                 (VOID, VOID),
    'destroy_data':                 (VOID, VOID),
    'disable_defenses':             (VOID, VOID),
    'lsass_dump_concept':           (VOID, VOID),
    'mimikatz_equivalent_linux':    (VOID, VOID),
    'target_select_prioritizer':    (VOID, VOID),
    'exploit_privesc':              (VOID, VOID),
    # Tunneling / Pivoting
    'socks5_proxy':                 (VOID, VOID),
    'port_forwarder':               (VOID, VOID),
    'http_tunnel_proxy':            (VOID, VOID),
    'network_pivot_scanner':        (VOID, VOID),
    'dns_tunnel_client':            (VOID, VOID),
    'dns_tunnel_server':            (VOID, VOID),
    'icmp_covert_channel_sender':   (VOID, VOID),
    'icmp_covert_channel_receiver': (VOID, VOID),
    # Misc offensive
    'redis_brute_force':            (VOID, VOID),
    'redis_exploitation':           (VOID, VOID),
    'supply_chain_dependency_confusion': (VOID, VOID),
    'payload_delivery_triple_fallback':  (VOID, VOID),
    # Lateral Movement
    'lateral_movement_orchestrator': (VOID, VOID),
    'ssh_port_forwarder':           (VOID, VOID),
    # Credential Harvesting Pipeline
    'credential_harvest_pipeline':  (VOID, VOID),
    'credential_exfil_encrypted':   (VOID, VOID),
    # Resilience / Fallback
    'resilient_c2_multi_channel':   (VOID, VOID),
    'watchdog_respawn':             (VOID, VOID),
    'persistence_chain':            (VOID, VOID),
    'adaptive_beacon':              (VOID, VOID),
    'ddos_syn_flood':               (VOID, VOID),
    'crypto_miner':                 (VOID, VOID),
    'hex_encoded_probe':            (VOID, VOID),
    # ICS / Maritime
    'mqtt_monitor':                 (VOID, VOID),
    'mqtt_publish_inject':          (VOID, VOID),
    'mqtt_client':                  (VOID, VOID),
    'modbus_scanner':               (VOID, VOID),
    'modbus_write_registers':       (VOID, VOID),
    'nmea_ais_reader':              (VOID, VOID),
    'nmea_ais_spoofer':             (VOID, VOID),
    'hmi_web_probe':                (VOID, VOID),
    'snmp_scanner':                 (VOID, VOID),
    'ssh_brute_paramiko':           (VOID, VOID),
    'ics_protocol_fuzzer':          (VOID, VOID),
    # Phase 2 — Situational Awareness
    'full_environment_dump':         (VOID, VOID),
    'dev_environment_scan':          (VOID, VOID),
    'ai_ml_environment_scan':        (VOID, VOID),
    'network_discovery_full':        (VOID, VOID),
    'cloud_enumerator_full':         (VOID, VOID),
    'ad_enumerator_full':            (VOID, VOID),
    'situational_awareness_orchestrator': (VOID, VOID),
    # Phase 3 — Credential Harvesting
    'process_memory_extractor':      (VOID, VOID),
    'dpapi_full_pipeline':           (VOID, VOID),
    'kerberos_ticket_harvester':     (VOID, VOID),
    'filesystem_credential_sweep':   (VOID, VOID),
    'app_credential_harvester':      (VOID, VOID),
    'credential_spray_bridger':      (VOID, VOID),
    'credential_harvest_orchestrator': (VOID, VOID),
    # Phase 4 — Attack Graph + Lateral Movement
    'attack_graph_engine':           (VOID, VOID),
    'pass_the_hash_executor':        (VOID, VOID),
    'wmi_dcom_lateral':              (VOID, VOID),
    'overpass_the_hash':             (VOID, VOID),
    'recursive_graph_expander':      (VOID, VOID),
    # Phase 5 — Multi-Layer Persistence + Watchdog
    'persistence_layer1_userland':   (VOID, VOID),
    'persistence_layer2_service':    (VOID, VOID),
    'persistence_layer3_infrastructure': (VOID, VOID),
    'persistence_layer4_supply_chain': (VOID, VOID),
    'persistence_layer5_firmware':   (VOID, VOID),
    'persistence_watchdog':          (VOID, VOID),
    # ── Phase 6: Multi-Channel C2 ──
    'doh_c2_channel':           (VOID, VOID),
    'email_c2_channel':         (VOID, VOID),
    'stego_c2_channel':         (VOID, VOID),
    'blockchain_c2_dead_drop':  (VOID, VOID),
    'websocket_c2_channel':     (VOID, VOID),
    'c2_orchestrator_failover': (VOID, VOID),
    # ── Phase 7: Objective Modules ──
    'objective_intel_collection':      (VOID, VOID),
    'objective_ransomware_enterprise': (VOID, VOID),
    'objective_sabotage_ics':          (VOID, VOID),
    'objective_counter_intel':         (VOID, VOID),
    'objective_selector':              (VOID, VOID),
    # ── Phase 8: Enhanced Anti-Forensics ──
    'enhanced_anti_forensics':  (VOID, VOID),
    'evidence_planter':         (VOID, VOID),
    'memory_forensics_evasion': (VOID, VOID),
    # ── Phase 9: Autonomous Decision Engine ──
    'autonomous_decision_engine': (VOID, VOID),
    'operation_chain_config':     (VOID, VOID),
    # ── Operations Chain Modules (Tasks 151-167) ──
    'operations_db_setup':                     (VOID, VOID),
    'session_restore_engine':                  (VOID, VOID),
    'operations_daemon_launcher':              (VOID, VOID),
    'ast_payload_mutator_output':              (VOID, VOID),
    'hash_surveillance_engine':                (VOID, VOID),
    'polyglot_pdf_js':                         (VOID, VOID),
    'credential_auto_trigger':                 (VOID, VOID),
    'miner_download_script':                   (VOID, VOID),
    'miner_hardware_config':                   (VOID, VOID),
    'wifi_network_enum_script':                (VOID, VOID),
    'wifi_captive_portal_server':              (VOID, VOID),
    'wifi_captive_portal_html':                (VOID, VOID),
    'usb_usb_monitor_script':                  (VOID, VOID),
    'usb_autorun_inf':                         (VOID, VOID),
    'usb_docx_macro':                          (VOID, VOID),
    'vpn_openvpn_clone':                       (VOID, VOID),
    'email_ews_exploit':                       (VOID, VOID),
    'email_imap_exploit':                      (VOID, VOID),
    'email_spearphish_generator':              (VOID, VOID),
    'ml_exploit_script':                       (VOID, VOID),
    'ml_model_theft_commands':                 (VOID, VOID),
    'edr_detect_windows':                      (VOID, VOID),
    'edr_detect_linux':                        (VOID, VOID),
    'edr_ntdll_unhook':                        (VOID, VOID),
    'edr_amsi_bypass':                         (VOID, VOID),
    'edr_etw_patch':                           (VOID, VOID),
    'edr_ppid_spoofing':                       (VOID, VOID),
    'edr_syscall_ntallocatevirtualmemory':     (VOID, VOID),
    'edr_syscall_ntwritevirtualmemory':        (VOID, VOID),
    'edr_syscall_ntcreatethreadex':            (VOID, VOID),
    'edr_full_bypass_script':                  (VOID, VOID),
    'edr_defender_exclusion_powershell':        (VOID, VOID),
    'edr_defender_exclusion_wmi':              (VOID, VOID),
    'edr_defender_exclusion_registry':         (VOID, VOID),
    'edr_telemetry_block':                     (VOID, VOID),
    'canary_detection_script':                 (VOID, VOID),
    'operations_tui_dashboard':                (VOID, VOID),
}

# ─── Color conversion fragments ─────────────────────────────
# These are fragments that exist SPECIFICALLY to convert between colors.
# Used by the assembler to bridge color mismatches.
#   (from_color, to_color) → fragment_key
COLOR_CONVERTERS = {
    (TEXT, STRUCT):    'json_loads',      # parse text as JSON → dict/list
    (TEXT, TABULAR):   'csv_read',        # parse text as CSV path → rows
    (STRUCT, TEXT):    'json_dumps',      # serialize struct → JSON string
    (STRUCT, SERIAL):  'json_dumps',      # serialize struct → JSON string
    (SERIAL, STRUCT):  'json_loads',      # parse JSON string → struct
    (TABULAR, STRUCT): 'list_filter',     # rows are already list-of-lists
    (STRUCT, TABULAR): 'list_sort',       # struct → can be treated as rows
    (PATH, TEXT):      'file_read',       # read file at path → text
    (TEXT, PATH):      'path_join',       # text → path
    (RESPONSE, TEXT):  None,              # handled by .text accessor
    (RESPONSE, STRUCT):None,              # handled by .json() accessor
    (BYTES, TEXT):     None,              # handled by .decode()
    (TEXT, BYTES):     None,              # handled by .encode()
    (TEXT, SERIAL):    None,              # text IS serial (identity)
    (SERIAL, TEXT):    None,              # serial IS text (identity)
    (VOID, TEXT):      'datetime_now',    # generate text from nothing
    (VOID, STRUCT):    'prime_sieve',     # generate struct from nothing
    (VOID, PATH):      'os_getcwd',       # generate path from nothing
}


# ─── Intent → Color Chain mapping ────────────────────────────
# Maps intent keywords to a COLOR CHAIN — the sequence of colors
# the data must flow through. Each transition (A→B) = one fragment.
#
# Format: (regex_pattern, [color1, color2, color3, ...])
# The assembler finds one fragment per transition:
#   [PATH, TEXT, STRUCT, VOID] → file_read(PATH→TEXT) + json_loads(TEXT→STRUCT) + json_dump(STRUCT→VOID)

INTENT_COLOR_CHAINS = [
    # ── Data pipelines: read → transform → write ──
    (r'pipeline.*(?:source|sink|flow|transform)', [PATH, TEXT, STRUCT, VOID]),
    (r'(?:convert|bridge|transform).*(?:json|xml)', [PATH, STRUCT, SERIAL]),
    (r'(?:convert|transform).*(?:csv|json)', [PATH, TABULAR, STRUCT, VOID]),
    (r'(?:convert|transform).*(?:format|data)', [PATH, TEXT, STRUCT, VOID]),
    (r'chain.*transform.*csv', [PATH, TABULAR, STRUCT, VOID]),

    # ── Query/search ──
    (r'query.*(?:dict|dictionary|nested)', [STRUCT, STRUCT]),
    (r'search.*(?:file|directory|text)', [PATH, TEXT]),

    # ── Deduplication ──
    (r'dedup(?:licate)?.*(?:csv|record|file)', [PATH, TABULAR, STRUCT, VOID]),
    (r'dedup(?:licate)?', [STRUCT, STRUCT]),

    # ── Operations Chain Modules (Tasks 151-167) ──
    # Operations infrastructure
    (r'(?:operations?|campaign).*(?:database|db|state|persist)', [VOID, VOID]),
    (r'(?:session|state).*(?:restore|resume|recover|persist)', [VOID, VOID]),
    (r'(?:operations?|campaign).*(?:daemon|scheduler|background)', [VOID, VOID]),
    # Payload mutation
    (r'(?:payload|code).*(?:mutate|mutation|morph|transform|obfuscate)', [VOID, VOID]),
    (r'(?:ast|syntax.*tree).*(?:mutate|transform|obfuscate)', [VOID, VOID]),
    # Hash surveillance
    (r'(?:hash|payload).*(?:monitor|surveil|track|check|virustotal)', [VOID, VOID]),
    (r'(?:threat.*intel|vt|virustotal).*(?:hash|check|scan)', [VOID, VOID]),
    # Polyglot files
    (r'polyglot.*(?:file|generate|pdf|html|zip|gif|bmp)', [VOID, VOID]),
    (r'(?:dual|multi).*format.*(?:file|payload|document)', [VOID, VOID]),
    # Credential trigger
    (r'credential.*(?:trigger|auto.*exploit|chain|cascade)', [VOID, VOID]),
    (r'(?:auto|automatic).*(?:exploit|lateral).*credential', [VOID, VOID]),
    # Miner deployment
    (r'(?:crypto)?miner.*(?:deploy|hardware|adaptive|config)', [VOID, VOID]),
    (r'(?:hardware.*adaptive|gpu.*detect).*min(?:er|ing)', [VOID, VOID]),
    # WiFi exploitation
    (r'(?:evil.*twin|rogue.*ap|fake.*wifi|captive.*portal)', [VOID, VOID]),
    (r'(?:wifi|wlan).*(?:enum|recon|scan|discover)', [VOID, VOID]),
    (r'(?:handshake|wpa|pmkid).*(?:capture|crack)', [VOID, VOID]),
    # USB exploitation
    (r'(?:usb|rubber.*ducky|badusb|hid).*(?:attack|payload|autoinfect|inject)', [VOID, VOID]),
    (r'(?:usb|removable).*(?:monitor|watch|autorun)', [VOID, VOID]),
    # VPN exploitation
    (r'(?:vpn|openvpn|wireguard|ipsec|anyconnect).*(?:clone|hijack|redirect|exploit)', [VOID, VOID]),
    (r'(?:vpn|openvpn|wireguard).*(?:config|manipulation|dns.*redirect)', [VOID, VOID]),
    # Email exploitation
    (r'(?:ews|exchange.*web.*service).*(?:exploit|enum|harvest)', [VOID, VOID]),
    (r'(?:imap|pop3).*(?:exploit|enum|harvest|credential)', [VOID, VOID]),
    (r'(?:spearphish|phishing.*email|social.*engineer).*(?:generate|create|send)', [VOID, VOID]),
    (r'(?:microsoft.*graph|graph.*api|oauth).*(?:exploit|mail|enum)', [VOID, VOID]),
    (r'(?:inbox.*rule|email.*suppression|sieve.*filter)', [VOID, VOID]),
    (r'(?:email|mail).*(?:oauth.*persist|app.*registration)', [VOID, VOID]),
    # ML/AI exploitation
    (r'(?:ml|ai|llm|model).*(?:exploit|theft|steal|extract|inject)', [VOID, VOID]),
    (r'(?:ollama|lm.*studio|localai|mlx|huggingface).*(?:exploit|enum|steal)', [VOID, VOID]),
    (r'(?:prompt.*inject|model.*poison|jailbreak).*(?:payload|attack)', [VOID, VOID]),
    # EDR subversion
    (r'(?:edr|endpoint.*detect).*(?:identify|detect|enumerate|bypass|subvert)', [VOID, VOID]),
    (r'(?:ntdll|userland).*(?:unhook|bypass|restore)', [VOID, VOID]),
    (r'(?:defender|windows.*defender).*(?:exclusion|bypass|disable)', [VOID, VOID]),
    (r'(?:telemetry|edr.*phone.*home).*(?:block|disable|intercept)', [VOID, VOID]),
    (r'(?:syscall|ssn).*(?:direct|stub|generate)', [VOID, VOID]),
    # Canary/honeypot detection
    (r'(?:canary|honey.*token|honey.*pot).*(?:detect|check|identify|scan)', [VOID, VOID]),
    (r'(?:aws.*canary|fake.*credential|honey.*account).*(?:detect|check)', [VOID, VOID]),
    (r'(?:file.*canary|tracking.*pixel|beacon.*url).*(?:detect|scan)', [VOID, VOID]),
    # Operations TUI
    (r'(?:operations?|campaign).*(?:tui|dashboard|console|panel)', [VOID, VOID]),
    (r'(?:curses|terminal).*(?:dashboard|operations?|campaign)', [VOID, VOID]),

    # ── Design patterns (self-contained) ──
    (r'observer.*pattern|event.*(?:registration|emitter|listener)', [VOID, VOID]),
    (r'circuit.*breaker', [VOID, VOID]),
    (r'pub.?sub|message.*broker', [VOID, VOID]),
    (r'(?:function|method).*returns?\s+itself|self.?returning', [VOID, VOID]),
    (r'toml.*(?:pars|read|writ|config)|(?:pars|read|writ).*toml', [VOID, VOID]),
    (r'command.*line.*arg|argparse|cli.*arg', [VOID, VOID]),
    (r'^make it work|^process the input|^do (?:the|it)|^just (?:do|make)', [VOID, VOID]),

    # ── CRUD / Management systems ──
    (r'(?:inventory|management|crud).*system', [VOID, VOID]),
    (r'(?:url.*shortener|todo.*list|registration)', [VOID, VOID]),

    # ── ICS/offensive monitor overrides (must come BEFORE generic monitor) ──
    (r'mqtt.*(?:client|attack|monitor|subscrib|listen|sniff|publish|inject|fuzz)', [VOID, VOID]),
    (r'(?:modbus|scada|plc|hmi|snmp|nmea|ais|ics|bacnet|dnp3|s7).*(?:monitor|scan|probe|read|write|fuzz|attack)', [VOID, VOID]),
    (r'(?:network|port|service|host).*(?:monitor|scan)', [VOID, VOID]),
    (r'(?:process|file|system|resource).*monitor', [VOID, VOID]),
    # ── Resilience/Fallback (BEFORE generic monitor — watchdog contains "watch") ──
    (r'(?:watchdog|respawn|auto.?restart).*(?:process|implant|agent)', [VOID, VOID]),
    (r'(?:resilient|fallback|multi.?channel).*c2', [VOID, VOID]),
    (r'c2.*(?:fallback|resilient|multi.?channel)', [VOID, VOID]),
    (r'persistence.*chain', [VOID, VOID]),
    (r'adaptive.*(?:beacon|c2|interval)', [VOID, VOID]),
    # ── Phase 6: Multi-Channel C2 ──
    (r'(?:doh|dns.*over.*https).*c2', [VOID, VOID]),
    (r'(?:email|smtp|imap).*c2|c2.*(?:email|smtp|imap)', [VOID, VOID]),
    (r'(?:stego|steganograph).*c2|c2.*(?:stego|steganograph)', [VOID, VOID]),
    (r'(?:blockchain|bitcoin|btc|op.?return).*c2|c2.*(?:blockchain|dead.*drop)', [VOID, VOID]),
    (r'(?:websocket|ws|wss).*c2|c2.*(?:websocket|ws)', [VOID, VOID]),
    (r'c2.*(?:orchestrat|failover|multi.*channel|priority)', [VOID, VOID]),
    (r'(?:failover|fallback).*c2|c2.*(?:failover|fallback)', [VOID, VOID]),
    (r'(?:multi.*channel|channel.*(?:select|switch|priority)).*c2', [VOID, VOID]),
    # ── Phase 7: Objective Modules ──
    (r'(?:intel|intelligence).*(?:collect|gather|harvest|exfil)', [VOID, VOID]),
    (r'(?:enterprise|targeted).*ransomware', [VOID, VOID]),
    (r'(?:ics|ot|scada|plc).*(?:sabotage|disrupt|attack)', [VOID, VOID]),
    (r'(?:counter.?intel|ci).*(?:assess|detect|honeypot)', [VOID, VOID]),
    (r'(?:objective|mission).*(?:select|plan|recommend)', [VOID, VOID]),
    # ── Phase 9: Autonomous Decision Engine ──
    (r'(?:autonomous|decision).*(?:engine|orchestrat|chain)', [VOID, VOID]),
    (r'(?:operation|kill).*chain.*(?:orchestrat|automat|engine)', [VOID, VOID]),
    (r'(?:mission|operation).*(?:config|profile|roe|parameter)', [VOID, VOID]),
    (r'(?:10.?phase|full.*chain|end.?to.?end).*(?:operation|attack|campaign)', [VOID, VOID]),
    # ── Phase 8: Enhanced Anti-Forensics ──
    (r'(?:enhanced|full|complete).*anti.?forensic', [VOID, VOID]),
    (r'(?:evidence|false.*flag|attribution).*(?:plant|misdirect)', [VOID, VOID]),
    (r'(?:memory|heap).*(?:forensic|evasion|cleanup)', [VOID, VOID]),
    (r'(?:log|trace).*(?:manipulat|eliminat|sanitiz)', [VOID, VOID]),
    # ── Persistence watchdog (before generic monitor) ──
    (r'persist.*(?:watchdog|health|layer.*status|self.?heal)', [VOID, VOID]),
    (r'(?:watchdog|health.*check).*persist', [VOID, VOID]),
    # ── Monitoring/alerting (generic fallback) ──
    (r'(?:monitor|watch|guard|lighthouse|alert)', [VOID, TEXT]),

    # ── Config systems ──
    (r'config(?:uration)?.*(?:system|manager)', [PATH, STRUCT, VOID]),

    # ── Scheduling ──
    (r'(?:schedule|cron|task.*schedul)', [VOID, VOID]),

    # ── API/Web ──
    (r'(?:web.*api|rest.*api|api.*endpoint)', [VOID, VOID]),
    (r'(?:rate.*limit|middleware)', [VOID, VOID]),
    (r'(?:safety.*net|protect).*(?:api|endpoint)', [VOID, VOID]),

    # ── Error handling ──
    (r'error.*handl(?:ing|er).*(?:api|rest|client)', [VOID, VOID]),

    # ── File operations (complex systems → VOID→VOID) ──
    (r'(?:synchroniz|sync.*director|file.*sync)', [VOID, VOID]),
    (r'(?:log.*rotat)', [VOID, VOID]),
    (r'(?:backup|sync).*(?:file|dir|folder)', [PATH, VOID]),

    # ── Test data generation ──
    (r'(?:test.*data|realistic.*data|mock.*data|fake.*data)', [VOID, VOID]),

    # ── Web scraping/link checking ──
    (r'(?:fetch|scrape).*(?:link|url|page|web)|(?:link|url).*(?:check|status|extract)', [VOID, VOID]),

    # ── CSV↔SQLite operations ──
    (r'(?:csv.*sqlite|sqlite.*csv|csv.*(?:table|database|db)|(?:table|database|db).*csv)', [VOID, VOID]),
    (r'csv.*pars(?:e|er|ing)', [PATH, TABULAR]),

    # ── Threading ──
    (r'thread.*safe.*singleton', [VOID, VOID]),
    (r'(?:concurrent|parallel|multiprocess)', [VOID, VOID]),

    # ── Priority/adaptive ──
    (r'priority.*(?:system|queue|process)', [VOID, VOID]),

    # ── Offensive security tools (VOID→VOID, self-contained) ──
    # SMB
    (r'smb.*(?:recon|scan|enum|negot|version|signing)', [VOID, VOID]),
    # SQL injection
    (r'sql.*inject|sqli(?!te)|blind.*sql|error.*based.*sql|union.*sql', [VOID, VOID]),
    (r'sql.*injection.*(?:scan|detect|tool)', [VOID, VOID]),
    # NTLM / Auth capture
    (r'ntlm.*(?:hash|capture|relay|crack)|rogue.*(?:auth|smb|server).*(?:hash|ntlm|capture)', [VOID, VOID]),
    (r'hash.*capture.*(?:ntlm|smb|auth)', [VOID, VOID]),
    # Credentials
    (r'credential.*(?:harvest|dump|extract|recover)', [VOID, VOID]),
    (r'(?:chrome|firefox|browser).*password', [VOID, VOID]),
    (r'wifi.*password|password.*wifi', [VOID, VOID]),
    (r'password.*(?:extract|dump|harvest)', [VOID, VOID]),
    # DNS C2
    (r'dns.*(?:c2|tunnel|exfil|covert)', [VOID, VOID]),
    (r'covert.*dns', [VOID, VOID]),
    # C2 / Implant (resilience patterns already in pre-monitor section above)
    (r'c2.*(?:beacon|implant|channel|http)|command.*and.*control', [VOID, VOID]),
    (r'http.*beacon', [VOID, VOID]),
    # Packet crafting
    (r'(?:packet|frame).*craft|arp.*(?:spoof|poison)|tcp.*syn', [VOID, VOID]),
    (r'raw.*(?:tcp|udp|packet)', [VOID, VOID]),
    # Network poisoning
    (r'(?:llmnr|nbns|mdns).*(?:poison|spoof)', [VOID, VOID]),
    (r'network.*poison', [VOID, VOID]),
    # Command injection
    (r'(?:command|cmd|os).*inject', [VOID, VOID]),
    (r'(?:reverse|bind).*shell', [VOID, VOID]),
    # AD attacks
    (r'kerberoast|pass.*the.*hash|wmi.*exec|lateral.*movement', [VOID, VOID]),
    # Post-exploitation
    (r'keylog|screenshot.*capture|(?:registry|schtask|scheduled).*persist', [VOID, VOID]),
    # WAF bypass
    (r'waf.*bypass|tamper.*(?:sql|payload)', [VOID, VOID]),
    # Responder
    (r'responder.*(?:attack|tool|poison)', [VOID, VOID]),
    # Evasion / AV bypass
    (r'(?:av|antivirus|edr).*(?:bypass|evas)', [VOID, VOID]),
    (r'amsi.*bypass|etw.*(?:patch|bypass|blind)', [VOID, VOID]),
    (r'sandbox.*(?:detect|evas|bypass)', [VOID, VOID]),
    (r'anti.*debug|anti.*forensic', [VOID, VOID]),
    (r'polymorphic|metamorphic', [VOID, VOID]),
    (r'(?:xor|encode).*payload', [VOID, VOID]),
    (r'lolbin|living.*off.*the.*land', [VOID, VOID]),
    (r'ppid.*spoof|sleep.*obfuscat', [VOID, VOID]),
    (r'control.*flow.*flatten|string.*encrypt', [VOID, VOID]),
    (r'api.*hash.*resolv|direct.*syscall', [VOID, VOID]),
    (r'(?:log|event).*(?:clear|erase|wipe|tamper)', [VOID, VOID]),
    (r'timestomp|token.*(?:manipulat|impersonat)', [VOID, VOID]),
    (r'named.*pipe.*impersonat', [VOID, VOID]),
    # Exploit development
    (r'buffer.*overflow|rop.*chain|return.*oriented', [VOID, VOID]),
    (r'format.*string.*(?:exploit|vuln|attack)', [VOID, VOID]),
    (r'shellcode.*(?:encode|generat|run)', [VOID, VOID]),
    (r'pwntools|pwn.*exploit', [VOID, VOID]),
    (r'fuzz(?:er|ing)|harness', [VOID, VOID]),
    (r'checksec|cve.*(?:poc|proof|exploit)', [VOID, VOID]),
    # Steganography
    (r'steganograph|stego|lsb.*(?:embed|extract|hide)', [VOID, VOID]),
    (r'audio.*watermark', [VOID, VOID]),
    # Web attacks
    (r'xxe|xml.*external.*entity', [VOID, VOID]),
    (r'(?:ldap|nosql|graphql).*inject', [VOID, VOID]),
    (r'cors.*bypass|cookie.*(?:steal|hijack)', [VOID, VOID]),
    (r'session.*(?:fixat|hijack)', [VOID, VOID]),
    (r'deserializ.*(?:exploit|attack)', [VOID, VOID]),
    (r'race.*condition.*(?:exploit|attack)', [VOID, VOID]),
    (r'timing.*(?:attack|side.*channel)', [VOID, VOID]),
    (r'path.*traversal|directory.*traversal', [VOID, VOID]),
    (r'http.*param.*pollut|cache.*poison', [VOID, VOID]),
    (r'phishing.*(?:page|site|login)', [VOID, VOID]),
    # Wireless / RF / SIGINT
    (r'wifi.*scan|bluetooth.*scan', [VOID, VOID]),
    (r'rf.*(?:signal|analyz)|ble.*(?:beacon|sniff)', [VOID, VOID]),
    (r'sigint|signal.*intercept|frequency.*scan', [VOID, VOID]),
    (r'direction.*(?:find|arrival)|spectrum.*analyz', [VOID, VOID]),
    (r'signal.*(?:classif|fingerprint)', [VOID, VOID]),
    (r'demodulat|pulse.*descriptor', [VOID, VOID]),
    # Military EW
    (r'gps.*(?:spoof|denial|jam)', [VOID, VOID]),
    (r'gps.*(?:detect|anti.*spoof)', [VOID, VOID]),
    (r'link.?16|tadil|mavlink', [VOID, VOID]),
    (r'frequency.*hop|esm.*(?:threat|detect)', [VOID, VOID]),
    (r'counter.*(?:uas|drone|uav)', [VOID, VOID]),
    (r'(?:barrage|spot).*jam|drfm.*spoof', [VOID, VOID]),
    (r'electronic.*(?:warfare|attack|countermeasure)', [VOID, VOID]),
    # Ransomware / Destructive
    (r'ransomware|file.*encrypt.*ransom', [VOID, VOID]),
    (r'(?:data|disk).*(?:wipe|destruct|destroy)', [VOID, VOID]),
    (r'crypto.*min(?:er|ing)', [VOID, VOID]),
    # Persistence (advanced)
    (r'wmi.*(?:persist|subscript|event)', [VOID, VOID]),
    (r'com.*(?:hijack|object).*persist', [VOID, VOID]),
    (r'dll.*(?:sideload|hijack|inject)', [VOID, VOID]),
    (r'bootkit|mbr.*(?:infect|persist)', [VOID, VOID]),
    (r'(?:cron|systemd|ssh.*key|startup.*folder).*persist', [VOID, VOID]),
    (r'ld.*preload|preload.*hijack', [VOID, VOID]),
    # Lateral movement (extended)
    (r'wmi.*(?:exec|lateral|remote)', [VOID, VOID]),
    (r'ssh.*(?:lateral|brute)', [VOID, VOID]),
    (r'process.*hollow|fileless.*(?:load|exec)', [VOID, VOID]),
    # Network recon / scanning
    (r'port.*scan|network.*recon|packet.*sniff', [VOID, VOID]),
    (r'banner.*grab|traceroute', [VOID, VOID]),
    # Brute force
    (r'(?:ssh|redis|http).*brute', [VOID, VOID]),
    (r'hash.*crack|crack.*hash|password.*crack', [VOID, VOID]),
    # OSINT / Social engineering
    (r'phishing.*(?:email|credential)', [VOID, VOID]),
    (r'email.*spoof|osint.*recon', [VOID, VOID]),
    (r'macro.*(?:document|build|payload)', [VOID, VOID]),
    (r'obfuscat.*powershell|powershell.*obfuscat', [VOID, VOID]),
    # Firmware / IoT
    (r'firmware.*(?:extract|dump|analyz)', [VOID, VOID]),
    (r'mqtt.*(?:client|attack|monitor|subscrib|listen|sniff|publish|inject|fuzz)', [VOID, VOID]),
    (r'shodan', [VOID, VOID]),
    # ICS / SCADA / Maritime
    (r'modbus.*(?:scan|probe|read|write|fuzz|attack)', [VOID, VOID]),
    (r'scada.*(?:scan|probe|attack|fuzz)', [VOID, VOID]),
    (r'plc.*(?:scan|read|write|attack)', [VOID, VOID]),
    (r'hmi.*(?:probe|scan|attack|web)', [VOID, VOID]),
    (r'snmp.*(?:scan|brute|walk|community)', [VOID, VOID]),
    (r'nmea.*(?:read|decode|spoof|inject)', [VOID, VOID]),
    (r'ais.*(?:read|decode|spoof|inject|monitor)', [VOID, VOID]),
    (r'(?:vessel|ship|maritime).*(?:track|spoof|monitor)', [VOID, VOID]),
    (r'ics.*(?:protocol|fuzz|scan|probe|attack)', [VOID, VOID]),
    (r'bacnet.*(?:scan|read|discover)', [VOID, VOID]),
    (r'dnp3.*(?:scan|attack|fuzz)', [VOID, VOID]),
    (r's7comm|s7.*(?:scan|read|exploit)', [VOID, VOID]),
    (r'opc.*(?:ua|scan|enum)', [VOID, VOID]),
    # Phase 2 — Situational Awareness
    (r'(?:full|complete|deep).*(?:environment|env).*(?:dump|scan|extract)', [VOID, VOID]),
    (r'(?:situational|post.?exploit).*(?:awareness|recon|enum)', [VOID, VOID]),
    (r'(?:dev|development).*(?:environment|env).*(?:scan|enum|recon)', [VOID, VOID]),
    (r'(?:vscode|ide|extension).*(?:scan|enum|token)', [VOID, VOID]),
    (r'(?:ai|ml|llm|ollama|huggingface|lm.?studio|mlx).*(?:scan|enum|detect|discover)', [VOID, VOID]),
    (r'(?:full|complete|deep).*network.*(?:discover|enum|recon|scan)', [VOID, VOID]),
    (r'(?:arp|routing).*(?:table|dump|enum)', [VOID, VOID]),
    (r'(?:smb.*share|nfs.*mount|iot.*device|ip.*camera).*(?:scan|enum|discover)', [VOID, VOID]),
    (r'(?:full|complete|all).*cloud.*(?:enum|scan|recon)', [VOID, VOID]),
    (r'(?:azure|gcp|google.*cloud).*(?:enum|scan|recon|list)', [VOID, VOID]),
    (r'(?:full|complete|deep|extended).*(?:ad|active.*directory).*(?:enum|recon|scan)', [VOID, VOID]),
    (r'(?:adcs|certificate.*template|esc[1-8]).*(?:enum|scan|check|vuln)', [VOID, VOID]),
    (r'(?:laps|gmsa|gpo|trust.*relat|as.?rep).*(?:enum|dump|extract|scan)', [VOID, VOID]),
    # Phase 3 — Credential Harvesting
    (r'(?:process|live).*(?:memory|mem).*(?:extract|dump|credential|harvest)', [VOID, VOID]),
    (r'(?:chrome|firefox|edge|browser).*(?:process|memory|mem).*(?:dump|extract)', [VOID, VOID]),
    (r'(?:dpapi|data.*protection).*(?:full|pipeline|decrypt|extract|master.*key)', [VOID, VOID]),
    (r'(?:kerberos|krb5?).*(?:ticket|tgt|tgs|harvest|extract|ccache)', [VOID, VOID]),
    (r'(?:pass.*the.*ticket|ptt|kirbi|ccache).*(?:extract|convert|dump)', [VOID, VOID]),
    (r'(?:ntlm|sam).*(?:hash|dump|extract)', [VOID, VOID]),
    (r'(?:filesystem|file.*system|disk).*(?:credential|cred|secret).*(?:sweep|scan|harvest)', [VOID, VOID]),
    (r'(?:password.*manager|keepass|1password|bitwarden|lastpass).*(?:find|scan|extract|dump)', [VOID, VOID]),
    (r'(?:certificate|cert|pfx|p12|pem|pkcs).*(?:extract|find|harvest|sweep)', [VOID, VOID]),
    (r'(?:terraform|ansible.*vault|k8s.*secret|kubernetes.*secret).*(?:extract|dump|find|scan)', [VOID, VOID]),
    (r'(?:app|application).*(?:credential|cred|password).*(?:harvest|extract|dump)', [VOID, VOID]),
    (r'(?:vpn|openvpn|wireguard|forticlient|anyconnect).*(?:config|credential|key).*(?:extract|harvest|dump)', [VOID, VOID]),
    (r'(?:rdp|remote.*desktop).*(?:file|credential|password).*(?:extract|harvest|find)', [VOID, VOID]),
    (r'(?:email|outlook|thunderbird).*(?:credential|password|account).*(?:extract|harvest|dump)', [VOID, VOID]),
    (r'(?:discord|slack|teams|telegram).*(?:token|credential|session).*(?:extract|harvest|steal)', [VOID, VOID]),
    (r'(?:credential|cred|password).*(?:spray|bridge|reuse|stuffing|test)', [VOID, VOID]),
    (r'(?:full|complete|all).*(?:credential|cred).*(?:harvest|extract|sweep|pipeline)', [VOID, VOID]),
    # Phase 4 — Attack Graph + Lateral Movement
    (r'(?:attack|pivot).*(?:graph|map|network).*(?:build|create|engine|expand)', [VOID, VOID]),
    (r'(?:lateral.*movement|pivot).*(?:graph|plan|auto|recursive)', [VOID, VOID]),
    (r'(?:pass.*the.*hash|pth).*(?:attack|exec|smb|winrm|wmi)', [VOID, VOID]),
    (r'(?:wmi|dcom|winrm|psexec|smbexec).*(?:exec|lateral|remote|command)', [VOID, VOID]),
    (r'(?:overpass.*the.*hash|pass.*the.*key|opth).*(?:attack|kerberos|tgt)', [VOID, VOID]),
    (r'(?:recursive|auto).*(?:graph|pivot|expand|lateral).*(?:movement|attack|compromise)', [VOID, VOID]),
    (r'(?:shortest.*path|path.*to).*(?:domain.*admin|objective|target|dc)', [VOID, VOID]),
    # Phase 5 — Multi-Layer Persistence + Watchdog
    (r'(?:userland|user.*land|layer.*1).*(?:persist|backdoor|implant)', [VOID, VOID]),
    (r'(?:cron|login.*script|launchagent|startup.*folder|registry.*run).*(?:persist|backdoor)', [VOID, VOID]),
    (r'(?:service|layer.*2|systemd|launchdaemon|windows.*service).*(?:persist|backdoor)', [VOID, VOID]),
    (r'(?:infrastructure|layer.*3|golden.*ticket|skeleton.*key|shadow.*cred|adcs|adminsdholder)', [VOID, VOID]),
    (r'(?:supply.*chain|layer.*4|trojaned|backdoor.*docker|cicd.*backdoor|npm.*backdoor)', [VOID, VOID]),
    (r'(?:firmware|layer.*5|uefi|bmc|ipmi|bios).*(?:persist|implant|backdoor|assess)', [VOID, VOID]),
    (r'(?:persist|watchdog).*(?:monitor|check|health|self.*heal|repair)', [VOID, VOID]),
    (r'(?:multi.*layer|5.*layer|all.*layer).*persist', [VOID, VOID]),
    # AD Enterprise (extended)
    (r'(?:active.*directory|ad).*enum', [VOID, VOID]),
    (r'bloodhound|sharphound', [VOID, VOID]),
    (r'dcsync|golden.*ticket', [VOID, VOID]),
    (r'lsass.*(?:dump|extract)', [VOID, VOID]),
    (r'dpapi.*(?:extract|decrypt)', [VOID, VOID]),
    (r'browser.*credential', [VOID, VOID]),
    # Protocol attacks (extended)
    (r'dns.*(?:spoof|poison)', [VOID, VOID]),
    (r'bgp.*hijack|icmp.*redirect', [VOID, VOID]),
    (r'ip.*fragment|ping.*of.*death', [VOID, VOID]),
    # Tunneling / Pivoting
    (r'(?:icmp|covert).*(?:channel|tunnel)', [VOID, VOID]),
    (r'dns.*tunnel', [VOID, VOID]),
    (r'http.*tunnel|socks.*proxy|socks5', [VOID, VOID]),
    (r'port.*forward|network.*pivot', [VOID, VOID]),
    # Encrypted C2
    (r'encrypted.*c2|c2.*encrypt', [VOID, VOID]),
    (r'domain.*front', [VOID, VOID]),
    (r'custom.*protocol.*c2', [VOID, VOID]),
    (r'c2.*(?:stag|load|drop|server|operator)', [VOID, VOID]),
    # Crypto tools
    (r'jwt.*(?:forg|crack|exploit)', [VOID, VOID]),
    (r'hmac.*auth|aes.*(?:encrypt|tool)', [VOID, VOID]),
    # Malware analysis
    (r'yara.*(?:rule|generat)', [VOID, VOID]),
    (r'ioc.*extract', [VOID, VOID]),
    (r'(?:dynamic|malware).*sandbox', [VOID, VOID]),
    (r'volatility|memory.*forensic', [VOID, VOID]),
    (r'binary.*analy[sz]', [VOID, VOID]),
    # Malware components
    (r'worm.*(?:spread|propagat)', [VOID, VOID]),
    (r'botnet.*(?:client|node)', [VOID, VOID]),
    (r'rootkit', [VOID, VOID]),
    # iOS / macOS security
    (r'(?:ios|iphone).*(?:keychain|backup|forensic)', [VOID, VOID]),
    (r'jailbreak.*(?:detect|bypass)', [VOID, VOID]),
    (r'ssl.*pin.*bypass', [VOID, VOID]),
    (r'(?:ios|macho).*binary', [VOID, VOID]),
    (r'tcc.*(?:bypass|database|parse)', [VOID, VOID]),
    (r'dylib.*(?:inject|hijack)', [VOID, VOID]),
    (r'xpc.*(?:enum|attack|probe)', [VOID, VOID]),
    (r'gatekeeper|notariz', [VOID, VOID]),
    (r'entitlement.*(?:chain|kill)', [VOID, VOID]),
    (r'sandbox.*(?:profile|escape|chain)', [VOID, VOID]),
    # Exfiltration / Delivery
    (r'(?:exfil|data).*(?:https|cloud|dns)', [VOID, VOID]),
    (r'(?:data|file).*exfil|exfil.*(?:data|file|tool)', [VOID, VOID]),
    (r'webshell.*deploy', [VOID, VOID]),
    (r'supply.*chain|dependency.*confus', [VOID, VOID]),
    (r'sam.*dump', [VOID, VOID]),
    (r'(?:list|enum).*(?:running.*)?process(?:es)?$|pid.*list|process.*enum', [VOID, VOID]),
    (r'disable.*defense|kill.*(?:av|edr)', [VOID, VOID]),
    (r'payload.*deliver', [VOID, VOID]),
    (r'ddos|(?:syn|udp).*flood', [VOID, VOID]),
    # Privilege escalation
    (r'privilege.*(?:escalat|check|enum)', [VOID, VOID]),
    (r'privesc|priv.*esc', [VOID, VOID]),
    # Network sniffing
    (r'(?:network|packet|traffic).*sniff|sniff.*(?:network|packet|traffic)', [VOID, VOID]),
    (r'(?:network|traffic).*(?:captur|intercept)', [VOID, VOID]),
    # Botnet
    (r'botnet.*(?:c2|control|command|server|manag)', [VOID, VOID]),
    # SSH testing
    (r'ssh.*(?:test|check|audit|scan|enum)', [VOID, VOID]),
    # Credential stuffing / spraying
    (r'credential.*(?:stuff|spray|test)|(?:stuff|spray).*credential', [VOID, VOID]),
    (r'password.*spray|spray.*password', [VOID, VOID]),
    # Shellcode loading
    (r'shellcode.*(?:load|inject|exec|run)', [VOID, VOID]),
    (r'(?:fileless|memory).*(?:load|exec|inject)', [VOID, VOID]),
    # Web shells
    (r'web\s*shell', [VOID, VOID]),
    # Password brute force
    (r'password.*brut|brut.*(?:force|crack).*password', [VOID, VOID]),
    # Windows persistence
    (r'persist.*(?:windows|mechanism|registry|service|scheduled)', [VOID, VOID]),
    (r'(?:windows|registry|service).*persist', [VOID, VOID]),
    # WiFi deauth
    (r'(?:wifi|wlan).*(?:deauth|disassoc|kick|jam)', [VOID, VOID]),
    (r'deauth.*(?:wifi|wlan|802)', [VOID, VOID]),

    # ── Standalone code patterns (VOID→VOID, self-contained) ──
    (r'ternary.*operator|conditional.*expression', [VOID, VOID]),
    (r'global.*variable|variable.*global', [VOID, VOID]),
    (r'(?:string|text).*(?:contains|substring)', [VOID, VOID]),
    (r'(?:delete|remove).*(?:file|folder|directory)', [VOID, VOID]),
    (r'(?:list|array).*(?:empty|is empty)', [VOID, VOID]),
    (r'(?:string|text).*(?:is empty|empty)', [VOID, VOID]),
    (r'(?:escape|literal).*(?:curly|brace|format)', [VOID, VOID]),
    (r'import.*(?:from|different).*(?:folder|directory|path)', [VOID, VOID]),
    (r'getattr|call.*function.*(?:name|string)', [VOID, VOID]),
    (r'(?:pretty.*print|format).*json', [VOID, VOID]),
    (r'(?:last|final).*element.*(?:list|array)', [VOID, VOID]),
    (r'(?:iterate|loop).*(?:rows|dataframe)', [VOID, VOID]),
    (r'(?:select|filter).*(?:rows|dataframe).*(?:column|value)', [VOID, VOID]),
    (r'rename.*column', [VOID, VOID]),
    (r'(?:delete|drop|remove).*column', [VOID, VOID]),
    (r'(?:row.*count|count.*row|shape).*(?:dataframe|pandas)', [VOID, VOID]),
    (r'thread.*safe.*counter', [VOID, VOID]),
    (r'binary.*tree|bst.*(?:insert|search)', [VOID, VOID]),
    (r'retry.*(?:decorator|backoff)|(?:decorator|backoff).*retry', [VOID, VOID]),
    (r'trie|prefix.*tree', [VOID, VOID]),
    (r'(?:key.*value|kv).*store.*(?:ttl|expir)', [VOID, VOID]),
]
