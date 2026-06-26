#!/usr/bin/env python3
"""
Full test suite for FORGE — tests all 5 phases
"""

import sys
import re
import io
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.intent_parser import IntentParser
from core.knowledge_engine import KnowledgeEngine
from core.code_assembler import CodeAssembler
from core.learning import LearningLoop


def init_forge(quiet=True):
    """Initialize all FORGE components"""
    knowledge_dir = Path(__file__).parent.parent / "knowledge"
    fragments_dir = Path(__file__).parent.parent / "fragments"

    if quiet:
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()

    knowledge = KnowledgeEngine(knowledge_dir)
    parser = IntentParser(knowledge)
    assembler = CodeAssembler(fragments_dir, knowledge)
    learning = LearningLoop(knowledge)
    stats = knowledge.get_stats()

    if quiet:
        sys.stdout = old_stdout

    return knowledge, parser, assembler, learning, stats


def test_code_generation(parser, knowledge, assembler):
    """Test code generation for 6 basic scenarios (structural check)"""
    print("\n=== CODE GENERATION (6 tests) ===")

    test_cases = [
        "list all files in a directory",
        "read a CSV file and print the rows",
        "download a webpage",
        "calculate sha256 hash",
        "connect to sqlite database",
        "create a zip file",
    ]

    passed = 0
    for query in test_cases:
        intent = parser.parse(query)
        chain = knowledge.infer(intent)

        if intent['mode'] == 'BUILD' and chain:
            script = assembler.assemble(chain, intent)
            has_main = 'def main()' in script
            has_imports = 'import' in script
            ok = has_main and has_imports

            if ok:
                passed += 1
                print(f"  PASS \"{query}\"")
            else:
                print(f"  FAIL \"{query}\" (main={has_main}, imports={has_imports})")
        else:
            print(f"  FAIL \"{query}\" (mode={intent['mode']}, chain={len(chain)})")

    print(f"  Result: {passed}/6")
    assert passed >= 5, f"Code generation: {passed}/6 (need at least 5)"
    return passed


def test_functional_correctness(parser, knowledge, assembler):
    """Test that the RIGHT fragment is selected for each task.

    Each test verifies the generated code contains the correct imports
    and function calls — not just structural validity.
    """
    print("\n=== FUNCTIONAL CORRECTNESS (20 tests) ===")

    # (query, must_contain_list, must_not_contain_list)
    test_cases = [
        # Basic tasks (10)
        ("list all files in a directory", ["os"], []),
        ("read a CSV file", ["csv"], []),
        ("download a webpage", ["requests"], []),
        ("parse json from string", ["json"], []),
        ("find files matching pattern", ["glob"], []),
        ("write text to a file", ["open"], []),
        ("generate a random number", ["random"], []),
        ("compute SHA256 hash", ["hashlib"], []),
        ("sort a list of items", ["sorted"], []),
        ("get current date and time", ["datetime"], []),
        # Hard tasks (10)
        ("download a webpage and save it to file", ["requests"], ["json()"]),
        ("scan open ports on a host", ["socket"], []),
        ("compress a folder into tar.gz", ["tarfile"], []),
        ("read a CSV and convert to JSON", ["csv", "json"], []),
        ("find all Python files recursively", ["glob", "rglob", "Path"], []),
        ("hash a file with SHA256", ["hashlib"], []),
        ("create a SQLite database and insert data", ["sqlite3"], []),
        ("send an HTTP POST with JSON body", ["requests"], []),
        ("generate all permutations of a list", ["itertools", "permutations"], []),
        ("measure execution time of code", ["time", "perf_counter"], []),
    ]

    passed = 0
    for query, must_contain, must_not_contain in test_cases:
        intent = parser.parse(query)
        chains = knowledge.infer(intent, top_k=3)

        if not chains:
            print(f"  FAIL \"{query}\" -> no inference chains")
            continue

        script = assembler.assemble(chains[0], intent)

        ok = True
        for keyword in must_contain:
            if keyword not in script:
                ok = False
                break
        for bad in must_not_contain:
            if bad in script:
                ok = False
                break

        if ok:
            passed += 1
            print(f"  PASS \"{query}\"")
        else:
            imports = [l.strip() for l in script.split('\n')
                       if l.strip().startswith('import ') or l.strip().startswith('from ')]
            print(f"  FAIL \"{query}\"")
            print(f"        imports: {imports[:3]}")
            print(f"        must_contain: {must_contain}")

    print(f"  Result: {passed}/{len(test_cases)}")
    assert passed >= 18, f"Functional correctness: {passed}/{len(test_cases)} (need at least 18)"
    return passed


def test_debug_mode(parser, knowledge):
    """Test DEBUG mode detection and error analysis"""
    print("\n=== DEBUG MODE (3 tests) ===")

    debug_cases = [
        ("/debug ModuleNotFoundError: No module named pandas", "ModuleNotFoundError"),
        ("/debug FileNotFoundError: data.csv not found", "FileNotFoundError"),
        ("/debug my script crashes", None),
    ]

    passed = 0
    for query, expected_error in debug_cases:
        intent = parser.parse(query)

        if intent['mode'] != 'DEBUG':
            print(f"  FAIL \"{query[:40]}\" mode={intent['mode']} (expected DEBUG)")
            continue

        error_match = re.search(
            r'(ModuleNotFoundError|FileNotFoundError|IndexError|KeyError|'
            r'TypeError|ValueError|AttributeError)',
            intent.get('raw', '')
        )
        detected = error_match.group(1) if error_match else None
        ok = (detected == expected_error)

        if ok:
            passed += 1
            # Also check knowledge lookup works for known errors
            if detected:
                results = knowledge.query_entity(detected)
                print(f"  PASS \"{query[:40]}\" -> {detected} ({len(results)} patterns)")
            else:
                print(f"  PASS \"{query[:40]}\" -> generic complaint")
        else:
            print(f"  FAIL \"{query[:40]}\" detected={detected} (expected {expected_error})")

    print(f"  Result: {passed}/3")
    assert passed == 3, f"Debug mode: {passed}/3"
    return passed


def test_learn_mode(parser):
    """Test LEARN mode detection and parsing"""
    print("\n=== LEARN MODE (4 tests) ===")

    learn_cases = [
        ("/learn pandas can read parquet files", "LEARN", "pandas"),
        ("/learn requests uses urllib3 under the hood", "LEARN", "requests"),
        ("/teach numpy handles matrix math", "LEARN", "numpy"),
        ("teach me about json processing", "LEARN", None),  # entity-based fallback
    ]

    passed = 0
    for query, expected_mode, expected_trigger in learn_cases:
        intent = parser.parse(query)

        if intent['mode'] != expected_mode:
            print(f"  FAIL \"{query}\" mode={intent['mode']} (expected {expected_mode})")
            continue

        # Try parsing trigger/outcome
        raw = intent.get('raw', '')
        patterns = [
            r'(\w+)\s+(?:can|uses?|reads?|writes?|creates?|handles?)\s+(.+)',
            r'(\w+)\s+(?:is|works with)\s+(.+)',
            r'teach.*?(\w+)\s+(\w+)',
        ]
        trigger = None
        for pattern in patterns:
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                trigger = match.group(1).strip()
                break

        if expected_trigger:
            ok = (trigger and trigger.lower() == expected_trigger.lower())
        else:
            ok = True  # Just mode detection is enough

        if ok:
            passed += 1
            print(f"  PASS \"{query}\" -> trigger={trigger}")
        else:
            print(f"  FAIL \"{query}\" -> trigger={trigger} (expected {expected_trigger})")

    print(f"  Result: {passed}/4")
    assert passed >= 3, f"Learn mode: {passed}/4 (need at least 3)"
    return passed


def test_implicit_build(parser):
    """Test implicit BUILD detection from action verbs"""
    print("\n=== IMPLICIT BUILD (5 tests) ===")

    cases = [
        ("list all files in a directory", "BUILD"),
        ("read a CSV file", "BUILD"),
        ("download webpage from url", "BUILD"),
        ("what is pandas", "CHAT"),
        ("how does json work", "CHAT"),
    ]

    passed = 0
    for query, expected in cases:
        intent = parser.parse(query)
        ok = intent['mode'] == expected
        if ok:
            passed += 1
            print(f"  PASS \"{query}\" -> {intent['mode']}")
        else:
            print(f"  FAIL \"{query}\" -> {intent['mode']} (expected {expected})")

    print(f"  Result: {passed}/5")
    assert passed == 5, f"Implicit BUILD: {passed}/5"
    return passed


def test_inference_engine(knowledge, stats):
    """Test 3-pass inference amplification"""
    print("\n=== INFERENCE ENGINE ===")

    explicit = stats['explicit_triplets']
    inferred = stats['inferred_triplets']
    total = stats['total_triplets']
    amp = stats['amplification_pct']

    print(f"  Explicit: {explicit}")
    print(f"  Inferred: {inferred}")
    print(f"  Total: {total}")
    print(f"  Amplification: {amp}%")

    assert explicit > 1000, f"Expected >1000 explicit triplets, got {explicit}"
    assert inferred > 1000, f"Expected >1000 inferred triplets, got {inferred}"
    assert amp > 100, f"Expected >100% amplification, got {amp}%"

    print(f"  PASS (amplification={amp}%)")
    return 1


def test_output_detection(parser):
    """Test requires_output detection"""
    print("\n=== OUTPUT DETECTION (4 tests) ===")

    cases = [
        ("list all files", True),
        ("show me the data", True),
        ("create a zip file", False),
        ("find all python files", True),
    ]

    passed = 0
    for query, expected in cases:
        intent = parser.parse(query)
        ok = intent['requires_output'] == expected
        if ok:
            passed += 1
            print(f"  PASS \"{query}\" requires_output={intent['requires_output']}")
        else:
            print(f"  FAIL \"{query}\" requires_output={intent['requires_output']} (expected {expected})")

    print(f"  Result: {passed}/4")
    assert passed >= 3, f"Output detection: {passed}/4 (need at least 3)"
    return passed


def test_composition_detection(parser):
    """Test composition intent detection"""
    print("\n=== COMPOSITION DETECTION (6 tests) ===")

    cases = [
        ("download a webpage and save it to file", True),
        ("read CSV and convert to JSON", True),
        ("scan ports and save results", True),
        ("download webpage and extract emails", True),
        ("list all files in a directory", False),
        ("read a CSV file", False),
    ]

    passed = 0
    for query, expected_composition in cases:
        intent = parser.parse(query)
        ok = intent['is_composition'] == expected_composition
        if ok:
            passed += 1
            print(f"  PASS \"{query}\" is_composition={intent['is_composition']}")
        else:
            print(f"  FAIL \"{query}\" is_composition={intent['is_composition']} (expected {expected_composition})")

    print(f"  Result: {passed}/6")
    assert passed >= 5, f"Composition detection: {passed}/6 (need at least 5)"
    return passed


def test_composition_generation(parser, knowledge, assembler):
    """Test that composition queries generate multi-component code.

    Each test verifies the generated code contains imports/keywords from
    BOTH steps of the composition — not just one.
    """
    print("\n=== COMPOSITION GENERATION (10 tests) ===")

    # (query, must_contain_all, description)
    test_cases = [
        ("download a webpage and save it to file",
         ["requests", "open("],
         "download+save"),
        ("read CSV and convert to JSON",
         ["csv", "json"],
         "csv→json"),
        ("download webpage and extract emails",
         ["requests", "re"],
         "download+regex"),
        ("scrape emails from webpage",
         ["requests", "re.findall"],
         "scrape emails"),
        ("convert csv to json",
         ["csv", "json"],
         "csv→json pipeline"),
        ("hash all files in directory",
         ["hashlib", "os"],
         "hash+walk"),
        ("find duplicate files",
         ["hashlib", "os"],
         "hash+dedup"),
        ("compare two files",
         ["difflib"],
         "diff"),
        ("count words in file",
         ["open("],
         "word count"),
        ("list files by size",
         ["os"],
         "files by size"),
    ]

    passed = 0
    for query, must_contain, desc in test_cases:
        intent = parser.parse(query)
        chains = knowledge.infer(intent, top_k=3)

        if not chains:
            print(f"  FAIL \"{query}\" [{desc}] -> no inference chains")
            continue

        script = assembler.assemble(chains[0], intent)

        ok = all(kw in script for kw in must_contain)
        if ok:
            passed += 1
            print(f"  PASS \"{query}\" [{desc}]")
        else:
            missing = [kw for kw in must_contain if kw not in script]
            imports = [l.strip() for l in script.split('\n')
                       if l.strip().startswith('import ') or l.strip().startswith('from ')]
            print(f"  FAIL \"{query}\" [{desc}]")
            print(f"        missing: {missing}")
            print(f"        imports: {imports[:4]}")

    print(f"  Result: {passed}/{len(test_cases)}")
    assert passed >= 8, f"Composition generation: {passed}/{len(test_cases)} (need at least 8)"
    return passed


def test_pipeline_fragments(parser, knowledge, assembler):
    """Test that pipeline fragments are correctly selected for multi-step tasks"""
    print("\n=== PIPELINE FRAGMENTS (5 tests) ===")

    test_cases = [
        ("merge csv files", ["csv", "glob"], "merge csv"),
        ("batch rename files", ["os", "re"], "batch rename"),
        ("system information", ["platform"], "sysinfo"),
        ("monitor file changes", ["hashlib", "os"], "file monitor"),
        ("merge json files", ["json", "glob"], "merge json"),
    ]

    passed = 0
    for query, must_contain, desc in test_cases:
        intent = parser.parse(query)
        chains = knowledge.infer(intent, top_k=3)

        if not chains:
            print(f"  FAIL \"{query}\" [{desc}] -> no inference chains")
            continue

        script = assembler.assemble(chains[0], intent)
        ok = all(kw in script for kw in must_contain)
        if ok:
            passed += 1
            print(f"  PASS \"{query}\" [{desc}]")
        else:
            missing = [kw for kw in must_contain if kw not in script]
            print(f"  FAIL \"{query}\" [{desc}] missing: {missing}")

    print(f"  Result: {passed}/{len(test_cases)}")
    assert passed >= 4, f"Pipeline fragments: {passed}/{len(test_cases)} (need at least 4)"
    return passed


def test_gap_detector(knowledge, assembler):
    """Test that GapDetector finds real gaps in the knowledge base"""
    print("\n=== GAP DETECTOR (4 tests) ===")

    from core.self_improve import GapDetector
    import json

    base_dir = Path(__file__).parent.parent

    # Load bridge + composition triplets
    bridge_path = base_dir / 'bridge_triplets.json'
    comp_path = base_dir / 'composition_triplets.json'
    bridge_triplets = json.load(open(bridge_path)) if bridge_path.exists() else []
    comp_triplets = json.load(open(comp_path)) if comp_path.exists() else []

    detector = GapDetector(knowledge, assembler.fragments, bridge_triplets, comp_triplets)
    gaps = detector.detect_all()

    passed = 0

    # Test 1: Gaps are found
    has_gaps = len(gaps) > 0
    if has_gaps:
        passed += 1
        print(f"  PASS Found {len(gaps)} gaps")
    else:
        print(f"  FAIL No gaps found (should always have some)")

    # Test 2: Gaps have required fields
    valid_fields = all(
        'type' in g and 'priority' in g and 'description' in g
        for g in gaps[:20]
    )
    if valid_fields:
        passed += 1
        print(f"  PASS All gaps have type, priority, description")
    else:
        print(f"  FAIL Some gaps missing required fields")

    # Test 3: Gaps are sorted by priority descending
    priorities = [g['priority'] for g in gaps]
    is_sorted = all(priorities[i] >= priorities[i+1] for i in range(len(priorities)-1))
    if is_sorted:
        passed += 1
        print(f"  PASS Gaps sorted by priority (highest first)")
    else:
        print(f"  FAIL Gaps not sorted by priority")

    # Test 4: Gap types are known
    known_types = {'orphan_fragment', 'low_confidence', 'untested_composition', 'underconnected'}
    found_types = set(g['type'] for g in gaps)
    valid_types = found_types.issubset(known_types)
    if valid_types:
        passed += 1
        print(f"  PASS Gap types: {found_types}")
    else:
        unknown = found_types - known_types
        print(f"  FAIL Unknown gap types: {unknown}")

    print(f"  Result: {passed}/4")
    assert passed >= 3, f"Gap detector: {passed}/4 (need at least 3)"
    return passed


def test_task_generator(assembler):
    """Test that TaskGenerator produces valid natural language tasks"""
    print("\n=== TASK GENERATOR (3 tests) ===")

    from core.self_improve import TaskGenerator

    generator = TaskGenerator(assembler.fragments)
    passed = 0

    # Test 1: Generate random tasks
    random_tasks = generator.generate_random_tasks(10)
    if len(random_tasks) == 10 and all(isinstance(t, str) and len(t) > 5 for t in random_tasks):
        passed += 1
        print(f"  PASS Generated 10 random tasks")
    else:
        print(f"  FAIL Random tasks: got {len(random_tasks)}")

    # Test 2: Generate from orphan gap
    orphan_gap = {
        'type': 'orphan_fragment',
        'fragment_key': 'csv_read',
        'priority': 9,
        'description': 'test',
    }
    task = generator.generate_from_gap(orphan_gap)
    if task and isinstance(task, str) and len(task) > 3:
        passed += 1
        print(f"  PASS Orphan gap -> \"{task}\"")
    else:
        print(f"  FAIL Orphan gap -> {task}")

    # Test 3: Generate from composition gap
    comp_gap = {
        'type': 'untested_composition',
        'source': 'requests_get',
        'sink': 'json_dump',
        'wiring': {'data': 'response'},
        'priority': 7,
        'description': 'test',
    }
    task = generator.generate_from_gap(comp_gap)
    if task and isinstance(task, str) and 'and' in task:
        passed += 1
        print(f"  PASS Composition gap -> \"{task}\"")
    else:
        print(f"  FAIL Composition gap -> {task}")

    print(f"  Result: {passed}/3")
    assert passed >= 2, f"Task generator: {passed}/3 (need at least 2)"
    return passed


def test_self_improve_micro(parser, knowledge, assembler):
    """Test SelfImproveLoop with a tiny run (5 iterations, no time limit)"""
    print("\n=== SELF-IMPROVE MICRO (3 tests) ===")

    from core.self_improve import SelfImproveLoop
    from core.executor import Executor
    from core.learning import LearningLoop

    # Create a minimal mock session
    class MiniSession:
        pass

    session = MiniSession()
    session.knowledge = knowledge
    session.intent_parser = parser
    session.code_assembler = assembler
    session.executor = Executor(timeout=10)
    session.learning = LearningLoop(knowledge)
    session.knowledge_dir = str(Path(__file__).parent.parent / "knowledge")

    loop = SelfImproveLoop(session)
    passed = 0

    # Test 1: Run with tiny budget
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    stats = loop.run(max_iterations=5, time_budget_hours=0.01, verbose=False)
    sys.stdout = old_stdout

    if stats['iterations'] > 0:
        passed += 1
        print(f"  PASS Ran {stats['iterations']} iterations")
    else:
        print(f"  FAIL No iterations ran")

    # Test 2: Some tasks executed
    total_attempts = stats['successes'] + stats['failures']
    if total_attempts > 0:
        passed += 1
        print(f"  PASS {stats['successes']} ok, {stats['failures']} fail")
    else:
        print(f"  FAIL No attempts recorded")

    # Test 3: Report generates
    report = loop.get_report()
    if 'Self-Improvement Report' in report and 'Iterations' in report:
        passed += 1
        print(f"  PASS Report generated ({len(report)} chars)")
    else:
        print(f"  FAIL Report malformed")

    print(f"  Result: {passed}/3")
    assert passed >= 2, f"Self-improve micro: {passed}/3 (need at least 2)"
    return passed


if __name__ == "__main__":
    print("=" * 60)
    print("         FORGE FULL TEST SUITE")
    print("=" * 60)

    knowledge, parser, assembler, learning, stats = init_forge()
    print(f"Knowledge: {stats['total_triplets']} triplets ({stats['amplification_pct']}% amplification)")

    total_passed = 0

    try:
        total_passed += test_inference_engine(knowledge, stats)
        total_passed += test_implicit_build(parser)
        total_passed += test_output_detection(parser)
        total_passed += test_code_generation(parser, knowledge, assembler)
        total_passed += test_functional_correctness(parser, knowledge, assembler)
        total_passed += test_debug_mode(parser, knowledge)
        total_passed += test_learn_mode(parser)
        total_passed += test_composition_detection(parser)
        total_passed += test_composition_generation(parser, knowledge, assembler)
        total_passed += test_pipeline_fragments(parser, knowledge, assembler)
        total_passed += test_gap_detector(knowledge, assembler)
        total_passed += test_task_generator(assembler)
        total_passed += test_self_improve_micro(parser, knowledge, assembler)

        print("\n" + "=" * 60)
        print(f"ALL TESTS PASSED ({total_passed} test groups)")
        print("=" * 60)

    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
