"""
Verification Test for V4.5: Natural Selection (Empirical Knowledge Compiler)
"""

import sys
from pathlib import Path
from core.knowledge_engine import KnowledgeEngine

def test_natural_selection():
    print("🧪 Testing V4.5: Natural Selection Loop...")
    
    ke = KnowledgeEngine(Path("knowledge"))
    
    # 1. Inject Test Triplets
    good_triplet = {
        'trigger': 'requests',
        'mechanism': 'usage',
        'outcome': 'http_get',
        'confidence': 0.70
    }
    bad_triplet = {
        'trigger': 'nonexistent_lib',
        'mechanism': 'usage',
        'outcome': 'failure',
        'confidence': 0.70
    }
    
    ke.all_triplets.extend([good_triplet, bad_triplet])
    ke._build_indexes()
    
    # 2. Simulate Reward
    print("Rewarding 'requests'...")
    ke.reward_triplet('requests', 'http_get', boost=0.20)
    t_good = ke.get_triplet('requests', 'http_get')
    print(f"  Confidence: {t_good['confidence']}")
    assert t_good['confidence'] > 0.85
    
    # 3. Simulate Penalty
    print("Penalizing 'nonexistent_lib'...")
    ke.penalize_triplet('nonexistent_lib', 'failure', penalty=0.50)
    t_bad = ke.get_triplet('nonexistent_lib', 'failure')
    print(f"  Confidence: {t_bad['confidence']}")
    assert t_bad['confidence'] < 0.30
    
    # 4. Pruning
    print("Running Pruning (Natural Selection)...")
    pruned = ke.prune_knowledge(threshold=0.30)
    print(f"  Pruned {pruned} weak triplets.")
    
    # Final Checks
    assert pruned >= 1, "Failed to prune bad triplet"
    assert ke.get_triplet('requests', 'http_get') is not None
    assert ke.get_triplet('nonexistent_lib', 'failure') is None
    
    print("\n✅ V4.5 Natural Selection PASSED.")

if __name__ == "__main__":
    try:
        test_natural_selection()
    except Exception as e:
        print(f"\n❌ FAIL: {e}")
        sys.exit(1)
