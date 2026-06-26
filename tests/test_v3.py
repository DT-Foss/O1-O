"""
V3 Verification — The Conversational Leap
Tests the incremental patching flow:
1. Build a basic scraper.
2. Add SQLite storage to the existing script.
"""

import sys
from pathlib import Path
from core.intent_parser import IntentParser
from core.knowledge_engine import KnowledgeEngine
from core.code_assembler import CodeAssembler
from core.session_memory import SessionMemory

def test_v3_sequence():
    print("🧪 Testing V3: The Conversational Leap (Patching Flow)...")
    
    ke = KnowledgeEngine(Path("knowledge"))
    ip = IntentParser(ke)
    assembler = CodeAssembler(Path("fragments"), ke)
    memory = SessionMemory()

    # Step 1: BUILD a scraper
    print("\n--- TURN 1: Initial Build ---")
    input1 = "build a scraper for example.com"
    intent1 = ip.parse(input1)
    chain1 = ke.infer(intent1)
    script1 = assembler.assemble(chain1, intent1)
    
    print("Generated Script 1 (Initial):")
    print("-" * 20)
    print(script1[:200] + "...")
    print("-" * 20)
    
    # Store in memory
    memory.add_turn(intent1, "Success", script1)
    
    # Step 2: INCREMENTAL ADD SQLite
    print("\n--- TURN 2: Incremental Patch ---")
    input2 = "now save the results to sqlite"
    intent2 = ip.parse(input2)
    intent2 = memory.resolve_references(intent2)
    
    print(f"Intent 2 Is Incremental: {intent2.get('is_incremental')}")
    
    chain2 = ke.infer(intent2)
    script2 = assembler.assemble(chain2, intent2)
    
    print("Generated Script 2 (Patched):")
    print("-" * 20)
    print(script2)
    print("-" * 20)
    
    # Validation
    has_requests = "import requests" in script2
    has_sqlite = "import sqlite3" in script2
    has_conn = "sqlite3.connect" in script2
    
    if has_requests and has_sqlite and has_conn:
        print("\n✅ PASS: Conversational Patching (Scraper + SQLite) successful.")
    else:
        print("\n❌ FAIL: Patching failed to preserve or integrate components correctly.")
        if not has_requests: print("  - Missing: requests (context lost)")
        if not has_sqlite: print("  - Missing: sqlite3 (new library missed)")
        if not has_conn: print("  - Missing: sqlite3 logic (fragment not injected)")

if __name__ == "__main__":
    test_v3_sequence()
