#!/usr/bin/env python3
"""
Basic tests for FORGE components
"""

import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.intent_parser import IntentParser
from core.knowledge_engine import KnowledgeEngine


class MockKnowledgeEngine:
    """Mock knowledge engine for testing"""

    def get_all_entities(self):
        return ['csv', 'pdf', 'json', 'parse', 'read', 'write', 'python', 'pandas']


def test_intent_parser():
    """Test intent parser"""
    print("\n=== Testing Intent Parser ===\n")

    knowledge = MockKnowledgeEngine()
    parser = IntentParser(knowledge)

    test_cases = [
        ("build a script to parse csv files", "BUILD"),
        ("what is pandas", "CHAT"),
        ("my script has an error", "DEBUG"),
        ("teach me about json", "LEARN"),
    ]

    for text, expected_mode in test_cases:
        intent = parser.parse(text)
        print(f"Input: {text}")
        print(f"  Mode: {intent['mode']} (expected: {expected_mode})")
        print(f"  Tokens: {intent['tokens']}")
        print(f"  Entities: {len(intent['entities'])}")
        print(f"  Confidence: {intent['confidence']:.2f}")

        assert intent['mode'] == expected_mode, f"Expected {expected_mode}, got {intent['mode']}"
        print("  ✅ PASS\n")


def test_tokenization():
    """Test tokenization"""
    print("\n=== Testing Tokenization ===\n")

    knowledge = MockKnowledgeEngine()
    parser = IntentParser(knowledge)

    text = "Build a script that reads CSV files from the folder ~/data"
    tokens = parser.tokenize(text)

    print(f"Input: {text}")
    print(f"Tokens: {tokens}")

    # Should remove stopwords
    assert 'the' not in tokens
    assert 'that' not in tokens
    assert 'from' not in tokens

    # Should keep meaningful words
    assert 'build' in tokens
    assert 'script' in tokens
    assert 'csv' in tokens

    print("✅ PASS\n")


def test_parameter_extraction():
    """Test parameter extraction"""
    print("\n=== Testing Parameter Extraction ===\n")

    knowledge = MockKnowledgeEngine()
    parser = IntentParser(knowledge)

    test_cases = [
        ("parse PDF files in ~/documents", {'input_format': 'PDF'}),
        ("convert csv to json", {'output_format': 'JSON'}),
        ("read from /data/input.txt", {'input_path': '/data/input.txt'}),
    ]

    for text, expected_params in test_cases:
        intent = parser.parse(text)
        print(f"Input: {text}")
        print(f"  Params: {intent['params']}")

        for key, value in expected_params.items():
            assert key in intent['params'], f"Missing param: {key}"
            assert intent['params'][key] == value, f"Expected {value}, got {intent['params'][key]}"

        print("  ✅ PASS\n")


if __name__ == "__main__":
    print("╔═══════════════════════════════════════════════════════╗")
    print("║              FORGE BASIC TESTS                        ║")
    print("╚═══════════════════════════════════════════════════════╝")

    try:
        test_tokenization()
        test_parameter_extraction()
        test_intent_parser()

        print("\n" + "="*60)
        print("✅ ALL TESTS PASSED")
        print("="*60)

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
