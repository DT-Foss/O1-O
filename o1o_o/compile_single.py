#!/usr/bin/env python3
"""Compile a single JSON triplets file to .causal binary"""

import json
import msgpack
import zlib
import sys
from pathlib import Path

if len(sys.argv) != 3:
    print("Usage: compile_single.py <input.json> <output.causal>")
    sys.exit(1)

input_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])

# Load triplets
with open(input_path) as f:
    triplets = json.load(f)

# Create .causal structure
graph = {
    'triplets': triplets,
    'metadata': {
        'version': 1,
        'source': f'FORGE_expansion_{input_path.stem}',
        'generator': 'claude-haiku-4-5 (via agents)'
    }
}

# Pack and compress
packed = msgpack.packb(graph, use_bin_type=True)
compressed = zlib.compress(packed, level=9)

# Write .causal file
with open(output_path, 'wb') as f:
    f.write(b'CAUSAL')
    f.write((1).to_bytes(2, 'big'))
    f.write(compressed)

print(f"✅ Compiled {output_path.name}: {len(triplets)} triplets, {len(compressed):,} bytes")
