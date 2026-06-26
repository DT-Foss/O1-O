"""
Moonshot Test Suite — Verify FORGE Expansion
"""

import sys
from pathlib import Path
from core.knowledge_engine import KnowledgeEngine
from core.intent_parser import IntentParser
from core.code_assembler import CodeAssembler
from core.project_generator import ProjectGenerator

def test_domains():
    print("=== Testing New Domains ===")
    knowledge = KnowledgeEngine(Path("knowledge"))
    parser = IntentParser(knowledge)
    assembler = CodeAssembler(Path("fragments"), knowledge)
    
    test_cases = [
        ("calculate moving average numpy", "numpy"),
        ("train a classifier with sklearn", "sklearn"),
        ("docker container status", "docker"),
        ("setup streamlit dashboard", "streamlit"),
        ("connect to postgres database", "psycopg2"),
        ("encrypt password with bcrypt", "bcrypt"),
    ]
    
    for query, expected in test_cases:
        intent = parser.parse(query)
        chain = knowledge.infer(intent)
        script = assembler.assemble(chain, intent)
        
        success = expected in script.lower()
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"[{status}] {query} (contains '{expected}')")

def test_project_generation():
    print("\n=== Testing Project Generation ===")
    knowledge = KnowledgeEngine(Path("knowledge"))
    parser = IntentParser(knowledge)
    assembler = CodeAssembler(Path("fragments"), knowledge)
    generator = ProjectGenerator(Path("fragments"), knowledge, assembler)
    
    test_cases = [
        ("create a flask api with user authentication", "flask_api"),
        ("make a data pipeline for data science", "data_pipeline"),
        ("build a command line tool with rich", "cli_tool"),
    ]
    
    for query, expected_type in test_cases:
        intent = parser.parse(query)
        detected = generator.detect_project_type(intent)
        
        success = detected == expected_type
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"[{status}] {query} -> {detected} (expected {expected_type})")
        
        if success:
            files = generator.generate_project(detected, intent)
            print(f"    Generated {len(files)} files: {list(files.keys())}")

if __name__ == "__main__":
    test_domains()
    test_project_generation()
