# Examples

This folder contains **real session output** captured by running `python3 src/o1o_live.py --demo`.

## `demo_session_5tasks/`

A complete 5-task demo run from 2026-06-26. The session generated 5 separate tools end-to-end
through the full 11-step pipeline (parse → knowledge query → assemble → compile → evasion →
formal verify → write session → package → OPSEC harden → OPSEC audit → threat model).

**Aggregate stats** (from `summary.json`):

| Metric | Value |
|---|---|
| Tasks completed | 5 |
| Total LOC generated | 1,771 |
| Average LOC per task | 354 |
| Total generation time | 1.6 s |
| **Average per task** | **312 ms** |
| All compile | YES |
| Verified (formal proof) | 5/5 |
| AI calls | 0 |
| Network calls | 0 |
| OPSEC audit grade | A (100/100, 98/100, 100/100, 100/100, 100/100) |

**The five tasks**:

1. `001_botnet_c2_server_with_aes-encrypted_command_channel/` — T1071, T1573, T1090 (Command & Control)
2. `002_port_scanner_with_service_fingerprinting_and_os_detection/` — T1046, T1595 (Reconnaissance)
3. `003_ransomware_file_encryption_with_rsa-wrapped_aes_keys/` — T1486, T1490 (Impact)
4. `004_kerberoasting_attack_to_extract_service_ticket_hashes/` — T1558.003, T1558 (Credential Access)
5. `005_dns_tunneling_data_exfiltration_tool/` — T1041, T1048, T1071.004, T1572 (Exfiltration)

Each task folder contains the full artifact set (~15 files each):
- `generated.py` — the source code O1-O wrote
- `<tool_name>` — the standalone executable (if PyInstaller was run)
- `README.txt` — auto-generated usage instructions
- `Dockerfile` + `docker-compose.yml` — container deployment
- `opsec/` — OPSEC hardening scripts (cleanup, runtime, network config, sanitize)
- `opsec_audit.txt` — OPSEC vulnerability assessment
- `threat_model.txt` — MITRE ATT&CK mapping + IOCs
- `deployment_guide.txt` — step-by-step operational walkthrough
- `meta.json` — full pipeline metadata
- `provenance.json` — decision chain (which fragments + which triplets were used)

**Reproduce**:

```bash
python3 src/o1o_live.py --demo
```

A new session folder is written to `src/sessions/<timestamp>/`. The output will be
bit-identical to this example modulo the timestamp and random opsec salts.
