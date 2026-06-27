"""
Web Harvester — Extract causal knowledge from natural language documentation
"""
# Dependencies: none
# Depended by: domain_bootstrapper


import re
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Any

class WebHarvester:
    """Fetches and parses technical documentation to extract causal triplets"""

    CAUSAL_PATTERNS = [
        (r"use\s+(?:the\s+)?([\w\.\- ]+?)(?:\s+library)?\s+to\s+([\w\.\- ]+)", "usage"),
        (r"(?:the\s+)?([\w\.\- ]+?)\s+(?:allows|enables|supports)\s+([\w\.\- ]+)", "capability"),
        (r"(?:the\s+)?([\w\.\- ]+?)\s+(?:provides|gives|offers)\s+([\w\.\- ]+)", "feature"),
        (r"to\s+([\w\.\- ]+),?\s+(?:use|try)\s+(?:the\s+)?([\w\.\- ]+)", "usage_pre"),
        (r"(?:the\s+)?([\w\.\- ]+?)\s+is\s+used\s+for\s+([\w\.\- ]+)", "purpose"),
        (r"prevents?\s+([\w\.\- ]+),?\s+(?:use|using)\s+(?:the\s+)?([\w\.\- ]+)", "prevention"),
        (r"requires\s+([\w\.\- ]+)", "dependency"),
    ]

    def __init__(self, knowledge_engine):
        self.knowledge = knowledge_engine
        self.visited_urls = set()

    def harvest_url(self, url: str) -> int:
        """Fetch URL and extract triplets into the knowledge engine"""
        if url in self.visited_urls:
            return 0
        
        self.visited_urls.add(url)
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return 0
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Remove scripts and styles
            for script in soup(["script", "style"]):
                script.decompose()
            
            text = soup.get_text()
            triplets = self.extract_triplets(text, url)
            
            # Discovery: Find more technical documentation links
            if len(self.visited_urls) < 10: # Safety limit
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if 'docs' in href or 'readme' in href or 'guide' in href:
                        # Normalize and ensure same domain or absolute
                        if href.startswith('/'):
                            from urllib.parse import urljoin
                            href = urljoin(url, href)
                        if href.startswith('http') and href not in self.visited_urls:
                            # Proactively harvest (recursive, but shallow)
                            self.harvest_url(href)

            if triplets:
                # Inject directly into KnowledgeEngine
                self.knowledge.all_triplets.extend(triplets)
                self.knowledge._build_indexes()
                return len(triplets)
                
        except Exception as e:
            print(f"Error harvesting {url}: {e}")
            
        return 0

    def extract_triplets(self, text: str, source: str) -> List[Dict[str, Any]]:
        """Extract causal triplets from raw text using NL patterns"""
        triplets = []
        
        # Split into sentences
        sentences = re.split(r'[.!?\n]', text)
        
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence or len(sentence) < 5: continue
            
            # Debug:
            # print(f"Analysing: {sentence}")
            
            for pattern, mechanism in self.CAUSAL_PATTERNS:
                matches = list(re.finditer(pattern, sentence, re.IGNORECASE))
                if matches:
                    # print(f"  Pattern matched: {pattern}")
                    pass
                for match in matches:
                    groups = match.groups()
                    if len(groups) == 2:
                        trigger = groups[0].strip()
                        outcome = groups[1].strip()
                    else:
                        trigger = groups[0].strip()
                        outcome = mechanism # fallback
                    
                    # Clean outcomes
                    outcome = ' '.join(outcome.split()[:5])
                    
                    if len(trigger) > 2 and len(outcome) > 2:
                        # Clean trigger: strip 'parser', 'library', 'the'
                        clean_trigger = re.sub(r'\s+(?:library|parser|module|package|tool)$', '', trigger, flags=re.IGNORECASE)
                        clean_trigger = re.sub(r'^the\s+', '', clean_trigger, flags=re.IGNORECASE)
                        
                        triplets.append({
                            'trigger': clean_trigger.strip(),
                            'mechanism': mechanism,
                            'outcome': outcome.strip(),
                            'confidence': 0.70,
                            'source': f"web:{source}",
                            '_source_graph': 'web_harvested'
                        })
                        
        return triplets
