"""
Repository Indexer — Universal Persistent Memory
Scans local directories to extract causal knowledge.
"""
# Dependencies: none
# Depended by: none (leaf module)


import ast
import os
from pathlib import Path
from typing import List, Dict, Any

class RepositoryIndexer:
    """Derives triplets from existing local codebases"""

    def __init__(self, knowledge_engine):
        self.knowledge = knowledge_engine

    def index_directory(self, path: Path) -> List[Dict[str, Any]]:
        """Scan directory for Python files and extract signatures"""
        path = Path(path)
        new_triplets = []
        
        for py_file in path.rglob("*.py"):
            if '.venv' in str(py_file) or '__pycache__' in str(py_file):
                continue
                
            try:
                triplets = self._extract_from_file(py_file)
                new_triplets.extend(triplets)
            except Exception as e:
                print(f"⚠️ Failed to index {py_file}: {e}")
                
        return new_triplets

    def _extract_from_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Extract function/class signatures as triplets"""
        code = file_path.read_text()
        tree = ast.parse(code)
        triplets = []
        
        module_name = file_path.stem
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Trigger: Module, Mechanism: provides_function, Outcome: Function
                triplets.append({
                    'trigger': module_name,
                    'mechanism': 'provides_function',
                    'outcome': node.name,
                    'confidence': 0.90,
                    'source': 'repository_indexer',
                    'file': str(file_path)
                })
            elif isinstance(node, ast.ClassDef):
                # Trigger: Module, Mechanism: defines_class, Outcome: Class
                triplets.append({
                    'trigger': module_name,
                    'mechanism': 'defines_class',
                    'outcome': node.name,
                    'confidence': 0.90,
                    'source': 'repository_indexer',
                    'file': str(file_path)
                })
                
        return triplets
