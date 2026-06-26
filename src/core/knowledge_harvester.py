"""
Knowledge Harvester — Scaling FORGE to 10k+ Triplets
Extracts causal relationships from pydoc, inspect, and type hints.
"""
# Dependencies: none
# Depended by: none (leaf module)


import inspect
import importlib
import pkgutil
from typing import List, Dict, Any, Tuple

class KnowledgeHarvester:
    """Automated triplet extraction from code metadata"""

    def __init__(self):
        self.seen_entities = set()

    def harvest_module(self, module_name: str) -> List[Dict[str, Any]]:
        """Harvest enriched triplets from a module"""
        triplets = []
        from typing import Tuple # Ensure Tuple is available
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            print(f"❌ Could not import {module_name}")
            return []

        for name, obj in inspect.getmembers(module):
            if name.startswith('_'): continue
            
            if inspect.isfunction(obj):
                triplets.extend(self._make_triplet(module_name, "provides_func", name, obj))
            elif inspect.isclass(obj):
                triplets.extend(self._make_triplet(module_name, "defines_class", name, obj))
                for m_name, m_obj in inspect.getmembers(obj):
                    if m_name.startswith('_'): continue
                    if inspect.isfunction(m_obj) or inspect.ismethod(m_obj):
                        triplets.extend(self._make_triplet(name, "implements_method", m_name, m_obj))

        return triplets

    def _extract_semantics(self, doc: str, name: str) -> List[Tuple[str, str]]:
        """Extract semantic relationships from docstrings and names"""
        rels = []
        doc_lower = doc.lower()
        
        # 1. Serialization detection
        if any(w in doc_lower or w in name.lower() for w in ['serialize', 'json', 'dump', 'encode']):
            rels.append(('performs', 'serialization'))
        
        # 2. Deserialization / Inverse
        if any(w in doc_lower or w in name.lower() for w in ['deserialize', 'load', 'decode', 'parse']):
            rels.append(('performs', 'deserialization'))
            
        # 3. DB operations
        if any(w in doc_lower for w in ['database', 'sqlite', 'query', 'sql', 'execute']):
            rels.append(('interacts_with', 'database'))

        # 4. Web/HTTP
        if any(w in doc_lower for w in ['http', 'url', 'request', 'api', 'route']):
            rels.append(('provides', 'api_endpoint'))

        return rels

    def _make_triplet(self, trigger: str, mechanism: str, outcome: str, obj: Any) -> List[Dict[str, Any]]:
        """Create a list of triplets including semantic enrichment"""
        doc = inspect.getdoc(obj) or ""
        triplets = []
        
        # Base signature triplet
        confidence = 0.85
        if len(doc) > 100: confidence += 0.05
        
        base = {
            'trigger': trigger,
            'mechanism': mechanism,
            'outcome': outcome,
            'confidence': round(min(0.95, confidence), 2),
            'source': 'knowledge_harvester',
            'doc_summary': doc.split('\n')[0][:100] if doc else "No docstring"
        }
        triplets.append(base)

        # Semantic triplets
        semantics = self._extract_semantics(doc, outcome)
        for mech, res in semantics:
            triplets.append({
                'trigger': outcome,
                'mechanism': mech,
                'outcome': res,
                'confidence': 0.80,
                'source': 'semantic_harvester'
            })
            # Also bridge the module to the semantic result
            triplets.append({
                'trigger': trigger,
                'mechanism': mech,
                'outcome': res,
                'confidence': 0.75,
                'source': 'semantic_harvester'
            })

        return triplets

    def harvest_standard_library(self) -> List[Dict[str, Any]]:
        """Crawl the core Python stdlib and major 3rd party libs"""
        modules = [
            'os', 'sys', 'json', 'math', 'datetime', 're', 'shutil', 
            'itertools', 'collections', 'pathlib', 'csv', 'sqlite3',
            'hashlib', 'base64', 'zlib', 'argparse', 'logging',
            'requests', 'pandas', 'numpy', 'flask', 'sklearn', 
            'matplotlib', 'seaborn', 'pytest', 'sqlalchemy', 'cryptography'
        ]
        all_triplets = []
        for mod in modules:
            print(f"🚜 Harvesting {mod}...")
            all_triplets.extend(self.harvest_module(mod))
        return all_triplets
