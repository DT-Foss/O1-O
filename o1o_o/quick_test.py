#!/usr/bin/env python3
"""Quick test of O1-O code generation pipeline."""

import sys
from pathlib import Path

# Resolve repo root (this file lives in src/)
_HERE = Path(__file__).resolve().parent
_REPO = _HERE
sys.path.insert(0, str(_HERE))

from o1o_o.core.intent_parser import IntentParser
from o1o_o.core.knowledge_engine import KnowledgeEngine
from o1o_o.core.code_assembler import CodeAssembler

# Initialize components
knowledge_dir = _REPO / 'knowledge'
fragments_dir = _REPO / 'fragments'

knowledge = KnowledgeEngine(knowledge_dir)
parser = IntentParser(knowledge)
assembler = CodeAssembler(fragments_dir, knowledge)

# Test input
user_input = "build a script to list all files in a directory"

print(f"\nInput: {user_input}\n")

# Parse intent
intent = parser.parse(user_input)
print(f"Parsed:")
print(f"   Mode: {intent['mode']}")
print(f"   Entities: {[e['matched'] for e in intent['entities']]}")
print(f"   Params: {intent['params']}")
print(f"   Confidence: {intent['confidence']:.2f}\n")

# Query knowledge
inference_chain = knowledge.infer(intent)
print(f"Knowledge query: {len(inference_chain)} results\n")

if inference_chain:
    print("First 3 inference chains (each is a list of triplets):")
    for i, chain in enumerate(inference_chain[:3], 1):
        if isinstance(chain, list):
            # Each chain is a list of triplet dicts
            for j, t in enumerate(chain[:2], 1):
                trigger = t.get('trigger', '?')
                mechanism = t.get('mechanism', '?')
                outcome = t.get('outcome', '?')
                print(f"   {i}.{j}. {trigger} -> {mechanism} -> {outcome}")
        elif isinstance(chain, dict):
            t = chain.get('triplet', chain)
            print(f"   {i}. {t.get('trigger', '?')} -> {t.get('mechanism', '?')} -> {t.get('outcome', '?')}")

# Generate code
if inference_chain:
    print(f"\nGenerating code...\n")
    script = assembler.assemble(inference_chain, intent)
    print("=" * 60)
    print(script)
    print("=" * 60)
else:
    print("\nNo knowledge found to generate code")
