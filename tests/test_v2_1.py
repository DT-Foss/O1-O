"""
V2.1 Verification — Complex Cross-Domain Inference
"Build a Flask API that reads from SQLite and returns JSON"
"""

import sys
from pathlib import Path
from core.knowledge_engine import KnowledgeEngine
from core.intent_parser import IntentParser
from core.code_assembler import CodeAssembler

def test_complex_query():
    print("🧪 Testing Complex Query: 'Build a Flask API that reads from SQLite and returns JSON'")
    
    ke = KnowledgeEngine(Path("knowledge"))
    parser = IntentParser(ke)
    assembler = CodeAssembler(Path("fragments"), ke)
    
    intent = parser.parse("Build a Flask API that reads from SQLite and returns JSON")
    chain = ke.infer(intent)
    
    print(f"\n🔗 Inference Chain Length: {len(chain)}")
    for i, item in enumerate(chain[:5]):
        t = item['triplet']
        print(f"  {i+1}. {t['trigger']} --{t['mechanism']}--> {t['outcome']} (conf={t['confidence']})")

    script = assembler.assemble(chain, intent)
    lines = script.split('\n')
    
    print("\n📦 Generated Script Preview (First 30 lines):")
    print("-" * 40)
    print("\n".join(lines[:30]))
    print("-" * 40)
    
    # Check for library presence in imports
    imports = [line for line in lines if line.startswith('import ') or line.startswith('from ')]
    print(f"  Imports: {', '.join(imports)}")
    
    # Check for key modules
    has_flask = any('flask' in line.lower() for line in imports)
    has_sqlite = any('sqlite' in line.lower() for line in imports)
    has_json = any('json' in line.lower() for line in imports)
    
    if has_flask and has_sqlite:
        print("\n✅ PASS: Cross-domain integration (Flask + SQLite) detected.")
    else:
        print("\n❌ FAIL: Missing core integrations.")

if __name__ == "__main__":
    test_complex_query()
