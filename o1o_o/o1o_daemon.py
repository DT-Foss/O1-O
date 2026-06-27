"""
FORGE Daemon — The Causal IDE
Background service for real-time knowledge injection.
"""

import time
import sys
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from o1o_o.core.knowledge_engine import KnowledgeEngine
from o1o_o.core.repository_indexer import RepositoryIndexer

class CausalHandler(FileSystemEventHandler):
    """Handles file system events and triggers re-indexing"""
    
    def __init__(self, indexer, knowledge):
        self.indexer = indexer
        self.knowledge = knowledge
        self.last_run = 0

    def on_modified(self, event):
        if event.is_directory or not event.src_path.endswith(".py"):
            return
            
        # Debounce: avoid too many updates
        now = time.time()
        if now - self.last_run < 2:
            return
        self.last_run = now
            
        print(f"👁️  Detected change: {Path(event.src_path).name}")
        self.run_check(Path(event.src_path))

    def run_check(self, file_path: Path):
        """Analyze file for causal implications"""
        try:
            # 1. Re-index file
            new_triplets = self.indexer._extract_from_file(file_path)
            self.knowledge.load_transient_triplets(new_triplets, "daemon_live")
            
            # 2. Basic Causal Check (Example: find used libs without imports)
            code = file_path.read_text()
            self._check_implications(code)
            
        except Exception as e:
            print(f"⚠️  Daemon check failed: {e}")

    def _check_implications(self, code: str):
        """Check for missing imports or recommended patterns based on knowledge"""
        # Simple SOTA prototype logic
        for entity in self.knowledge.get_all_entities():
            if entity in code and f"import {entity}" not in code:
                # If we have a triplet saying Entity uses Library, suggest it
                triplets = self.knowledge.query_entity(entity)
                if triplets:
                    print(f"💡 Suggestion: You are using '{entity}'. Consider importing its dependencies.")

def start_daemon(path: str):
    print(f"🚀 FORGE Causal Daemon starting at {path}...")
    
    knowledge_dir = Path(path) / "knowledge"
    knowledge = KnowledgeEngine(knowledge_dir)
    indexer = RepositoryIndexer(knowledge)
    
    event_handler = CausalHandler(indexer, knowledge)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_daemon(sys.argv[1] if len(sys.argv) > 1 else ".")
