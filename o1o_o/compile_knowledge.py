#!/usr/bin/env python3
"""
Compile JSON triplets into .causal binary files
"""

import json
import msgpack
import zlib
from pathlib import Path

def create_causal(triplets, output_path, source_name):
    """Create .causal binary from triplets"""
    graph = {
        'triplets': triplets,
        'metadata': {
            'version': 1,
            'source': f'FORGE_bootstrap_{source_name}',
            'generator': 'claude-haiku-4-5 (via agents)'
        }
    }

    packed = msgpack.packb(graph, use_bin_type=True)
    compressed = zlib.compress(packed, level=9)

    with open(output_path, 'wb') as f:
        f.write(b'CAUSAL')
        f.write((1).to_bytes(2, 'big'))
        f.write(compressed)

    print(f"✅ {output_path.name}: {len(triplets)} triplets, {len(compressed):,} bytes")

base = Path(__file__).parent
knowledge_dir = base / "knowledge"
fragments_dir = base / "fragments"

knowledge_dir.mkdir(exist_ok=True)
fragments_dir.mkdir(exist_ok=True)

# Load and compile triplet files
triplet_files = [
    ('python_stdlib_triplets.json', 'python_stdlib.causal', 'stdlib'),
    ('python_libraries_triplets.json', 'python_libraries.causal', 'libraries'),
    ('code_patterns_triplets.json', 'code_patterns.causal', 'patterns'),
    ('error_patterns_triplets.json', 'error_patterns.causal', 'errors'),
    ('string_text_triplets.json', 'string_patterns.causal', 'strings'),
    ('data_science_triplets.json', 'data_science.causal', 'data_science'),
    ('devops_triplets.json', 'devops.causal', 'devops'),
    ('networking_triplets.json', 'networking.causal', 'networking'),
    ('database_triplets.json', 'database.causal', 'database'),
    ('testing_triplets.json', 'testing.causal', 'testing'),
    ('web_framework_triplets.json', 'web_frameworks.causal', 'web_frameworks'),
    ('cli_automation_triplets.json', 'cli_automation.causal', 'cli_automation'),
    ('security_crypto_triplets.json', 'security.causal', 'security'),
    ('bridge_triplets.json', 'bridge_intents.causal', 'bridge'),
    ('composition_triplets.json', 'composition.causal', 'composition'),
    ('file_formats_triplets.json', 'file_formats.causal', 'file_formats'),
    ('native_triplets.json', 'native.causal', 'native'),
    ('harvested_stdlib_triplets.json', 'harvested.causal', 'harvest'),
    ('offensive_security_triplets.json', 'offensive_security.causal', 'offensive'),
    ('exploit_dev_triplets.json', 'exploit_dev.causal', 'exploit_dev'),
    ('evasion_triplets.json', 'evasion.causal', 'evasion'),
    ('protocol_attacks_triplets.json', 'protocol_attacks.causal', 'protocol_attacks'),
    ('malware_analysis_triplets.json', 'malware_analysis.causal', 'malware_analysis'),
    ('wireless_rf_triplets.json', 'wireless_rf.causal', 'wireless_rf'),
    ('ad_enterprise_triplets.json', 'ad_enterprise.causal', 'ad_enterprise'),
    ('cloud_container_triplets.json', 'cloud_container.causal', 'cloud_container'),
    ('social_engineering_triplets.json', 'social_engineering.causal', 'social_engineering'),
    ('firmware_iot_triplets.json', 'firmware_iot.causal', 'firmware_iot'),
    ('forensics_ir_triplets.json', 'forensics_ir.causal', 'forensics_ir'),
    ('error_handling_triplets.json', 'error_handling.causal', 'error_handling'),
    ('problem_solution_triplets.json', 'problem_solution.causal', 'problem_solution'),
    ('bash_triplets.json', 'bash.causal', 'bash'),
    ('javascript_triplets.json', 'javascript.causal', 'javascript'),
    ('performance_triplets.json', 'performance.causal', 'performance'),
    ('composition_architectural_triplets.json', 'composition_arch.causal', 'composition_arch'),
    ('harvested_github.json', 'harvested_github.causal', 'github'),
    ('offensive_security_v2_triplets.json', 'offensive_security_v2.causal', 'offensive_v2'),
    ('dataflow_triplets.json', 'dataflow.causal', 'dataflow'),
    ('security_architecture_triplets.json', 'security_architecture.causal', 'security_arch'),
]

print("🔨 Compiling knowledge base...\n")

for json_file, causal_file, source in triplet_files:
    json_path = base / json_file
    if json_path.exists():
        with open(json_path) as f:
            triplets = json.load(f)
        create_causal(triplets, knowledge_dir / causal_file, source)
    else:
        print(f"⚠️  Missing: {json_file}")

# Create empty learned.causal
create_causal([], knowledge_dir / "learned.causal", "learned")

# Move fragment files
for frag_file in ['stdlib_fragments.json', 'library_fragments.json']:
    src = base / frag_file
    dst = fragments_dir / frag_file
    if src.exists():
        src.rename(dst)
        print(f"📦 Moved {frag_file} → fragments/")

print("\n✅ Knowledge base complete!")
print(f"\n📊 Summary:")
print(f"  Knowledge files: {len(list(knowledge_dir.glob('*.causal')))}")
print(f"  Fragment files: {len(list(fragments_dir.glob('*.json')))}")
