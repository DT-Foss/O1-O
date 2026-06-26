"""
Autonomous Knowledge Harvester — FORGE expands its own knowledge

When self-improvement detects unfillable gaps (no fragments/triplets for a domain),
the harvester:
1. Identifies the missing domain from intent keywords
2. Searches GitHub for top Python repos matching that domain
3. Downloads + runs ReverseForge extraction
4. Ingests new triplets into the live knowledge graph
5. Re-attempts the failed task

Rate-limited to avoid API abuse. Tracks harvested domains to prevent re-harvesting.

Storage: knowledge/harvested_domains.json (domain → timestamp + repo list)
"""
# Dependencies: reverse_forge
# Depended by: self_improve


import os
import re
import json
import time
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List, Set
from collections import defaultdict


class AutoHarvester:
    """Autonomously discover and ingest knowledge from GitHub repos."""

    # Domain keywords → GitHub search queries
    DOMAIN_SEARCH_MAP = {
        'async': 'asyncio python example',
        'asyncio': 'asyncio python tutorial',
        'websocket': 'websocket python client server',
        'graphql': 'graphql python client',
        'grpc': 'grpc python example',
        'celery': 'celery python task queue',
        'redis': 'redis python client',
        'mongodb': 'pymongo python example',
        'postgresql': 'psycopg2 python example',
        'docker': 'docker python sdk',
        'kubernetes': 'kubernetes python client',
        'terraform': 'terraform python cdktf',
        'aws': 'boto3 python aws',
        'azure': 'azure python sdk',
        'gcp': 'google cloud python',
        'kafka': 'kafka python producer consumer',
        'rabbitmq': 'pika python rabbitmq',
        'elasticsearch': 'elasticsearch python client',
        'prometheus': 'prometheus python client',
        'fastapi': 'fastapi python api',
        'django': 'django python example',
        'flask': 'flask python api',
        'sqlalchemy': 'sqlalchemy python orm',
        'pydantic': 'pydantic python validation',
        'click': 'click python cli',
        'typer': 'typer python cli',
        'pytest': 'pytest python testing',
        'mock': 'unittest mock python',
        'numpy': 'numpy python scientific',
        'pandas': 'pandas python dataframe',
        'scipy': 'scipy python scientific',
        'matplotlib': 'matplotlib python plotting',
        'seaborn': 'seaborn python visualization',
        'scikit': 'scikit-learn python ml',
        'torch': 'pytorch python deep learning',
        'tensorflow': 'tensorflow python example',
        'opencv': 'opencv python image processing',
        'pillow': 'pillow python image',
        'beautifulsoup': 'beautifulsoup python scraping',
        'scrapy': 'scrapy python spider',
        'selenium': 'selenium python browser',
        'paramiko': 'paramiko python ssh',
        'fabric': 'fabric python deployment',
        'ansible': 'ansible python automation',
        'cryptography': 'cryptography python encryption',
        'jwt': 'pyjwt python token',
        'oauth': 'oauth python authentication',
        'ldap': 'ldap python active directory',
        'smtp': 'smtp python email',
        'imap': 'imap python email',
        'ftp': 'ftp python file transfer',
    }

    # Minimum time between harvests of the same domain (seconds)
    COOLDOWN_SECONDS = 3600 * 24  # 24 hours

    # Max repos per harvest
    MAX_REPOS = 3

    # Max files per repo to analyze
    MAX_FILES_PER_REPO = 20

    def __init__(self, forge_session, storage_path: str = None):
        """
        Args:
            forge_session: ForgeSession instance
            storage_path: Path to harvested_domains.json
        """
        self.session = forge_session
        self.knowledge = forge_session.knowledge

        base_dir = Path(forge_session.knowledge_dir).parent
        if storage_path is None:
            storage_path = str(base_dir / 'knowledge' / 'harvested_domains.json')

        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

        # Load harvest history
        self.history = self._load_history()

        # Stats
        self.stats = {
            'domains_harvested': 0,
            'repos_cloned': 0,
            'files_analyzed': 0,
            'triplets_extracted': 0,
        }

    def _load_history(self) -> Dict[str, Any]:
        """Load harvest history from disk."""
        if self.storage_path.exists():
            try:
                with open(self.storage_path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {'domains': {}, 'version': 1}

    def _save_history(self):
        """Persist harvest history."""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(self.history, f, indent=2, default=str)
        except IOError:
            pass

    def identify_domain(self, task_query: str, intent: Dict[str, Any]) -> Optional[str]:
        """Identify the missing domain from a failed task.

        Args:
            task_query: The natural language task that failed
            intent: Parsed intent dict

        Returns:
            Domain keyword, or None if can't identify
        """
        tokens = set(intent.get('tokens', []))
        raw = task_query.lower()

        # Direct keyword match
        for domain in self.DOMAIN_SEARCH_MAP:
            if domain in tokens or domain in raw:
                return domain

        # Fuzzy: check if any token starts with a domain keyword
        for domain in self.DOMAIN_SEARCH_MAP:
            for token in tokens:
                if token.startswith(domain[:4]) and len(token) >= 4:
                    return domain

        return None

    def should_harvest(self, domain: str) -> bool:
        """Check if we should harvest this domain (cooldown + not already done)."""
        if domain not in self.history.get('domains', {}):
            return True

        last_harvest = self.history['domains'][domain].get('timestamp', 0)
        return (time.time() - last_harvest) > self.COOLDOWN_SECONDS

    def harvest(self, domain: str, verbose: bool = True) -> int:
        """Harvest knowledge for a specific domain.

        Returns number of new triplets ingested.
        """
        if not self.should_harvest(domain):
            if verbose:
                print(f"  🔄 Domain '{domain}' already harvested (cooldown)")
            return 0

        search_query = self.DOMAIN_SEARCH_MAP.get(domain, f'{domain} python example')

        if verbose:
            print(f"  🌐 Harvesting: {domain} (query: '{search_query}')")

        # Step 1: Search GitHub for repos
        repos = self._search_github(search_query)
        if not repos:
            if verbose:
                print(f"  ❌ No repos found for '{search_query}'")
            return 0

        # Step 2: Clone and analyze each repo
        total_triplets = 0
        cloned_repos = []

        for repo_url in repos[:self.MAX_REPOS]:
            triplets = self._harvest_repo(repo_url, verbose)
            if triplets:
                total_triplets += len(triplets)
                cloned_repos.append(repo_url)

                # Ingest into live knowledge graph
                self.knowledge.load_transient_triplets(triplets, f'harvested_{domain}')

        # Step 3: Record in history
        self.history.setdefault('domains', {})[domain] = {
            'timestamp': time.time(),
            'repos': cloned_repos,
            'triplets': total_triplets,
            'query': search_query,
        }
        self._save_history()

        self.stats['domains_harvested'] += 1
        self.stats['triplets_extracted'] += total_triplets

        if verbose:
            print(f"  ✅ Harvested {total_triplets} triplets from {len(cloned_repos)} repos")

        return total_triplets

    def _search_github(self, query: str) -> List[str]:
        """Search GitHub API for Python repos matching query.

        Returns list of clone URLs (HTTPS).
        Uses `gh` CLI if available, falls back to API.
        """
        try:
            # Try gh CLI first (handles auth automatically)
            result = subprocess.run(
                ['gh', 'search', 'repos', query,
                 '--language', 'python',
                 '--sort', 'stars',
                 '--limit', str(self.MAX_REPOS),
                 '--json', 'url'],
                capture_output=True, text=True, timeout=30,
            )

            if result.returncode == 0 and result.stdout.strip():
                repos = json.loads(result.stdout)
                return [r['url'] for r in repos if 'url' in r]
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass

        # Fallback: use GitHub search API (unauthenticated, rate-limited)
        try:
            import urllib.request
            import urllib.parse

            encoded = urllib.parse.quote(f'{query} language:python')
            url = f'https://api.github.com/search/repositories?q={encoded}&sort=stars&per_page={self.MAX_REPOS}'

            req = urllib.request.Request(url, headers={
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'FORGE-AutoHarvester/1.0',
            })

            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                return [item['html_url'] for item in data.get('items', [])[:self.MAX_REPOS]]

        except Exception:
            return []

    def _harvest_repo(self, repo_url: str, verbose: bool) -> List[Dict]:
        """Clone a repo to temp dir, run ReverseForge, return triplets."""
        tmpdir = None
        try:
            tmpdir = tempfile.mkdtemp(prefix='forge_harvest_')

            # Shallow clone (only latest commit, saves bandwidth)
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', '--single-branch', repo_url, tmpdir + '/repo'],
                capture_output=True, text=True, timeout=60,
            )

            if result.returncode != 0:
                if verbose:
                    print(f"  ⚠️ Clone failed: {repo_url}")
                return []

            self.stats['repos_cloned'] += 1
            repo_dir = Path(tmpdir) / 'repo'

            # Find Python files (skip tests, docs, venvs)
            py_files = self._find_python_files(repo_dir)
            if verbose:
                print(f"    📁 {repo_url.split('/')[-1]}: {len(py_files)} Python files")

            # Run ReverseForge on each file
            from core.reverse_forge import ReverseForge
            rf = ReverseForge(self.knowledge)

            all_triplets = []
            for py_file in py_files[:self.MAX_FILES_PER_REPO]:
                try:
                    triplets = rf.analyze_file(str(py_file))
                    all_triplets.extend(triplets)
                    self.stats['files_analyzed'] += 1
                except Exception:
                    pass

            return all_triplets

        except subprocess.TimeoutExpired:
            if verbose:
                print(f"  ⚠️ Clone timed out: {repo_url}")
            return []
        except Exception as e:
            if verbose:
                print(f"  ⚠️ Harvest error: {e}")
            return []
        finally:
            if tmpdir:
                try:
                    shutil.rmtree(tmpdir, ignore_errors=True)
                except Exception:
                    pass

    def _find_python_files(self, repo_dir: Path) -> List[Path]:
        """Find Python files, excluding tests/docs/venvs."""
        skip_dirs = {
            'test', 'tests', 'docs', 'doc', 'examples', 'example',
            'venv', 'env', '.venv', '.env', 'node_modules',
            '__pycache__', '.git', '.tox', 'build', 'dist',
            'site-packages', 'migrations',
        }

        py_files = []
        for py_file in repo_dir.rglob('*.py'):
            # Skip excluded directories
            parts = set(py_file.relative_to(repo_dir).parts)
            if parts & skip_dirs:
                continue
            # Skip very large files (>50KB)
            if py_file.stat().st_size > 50_000:
                continue
            # Skip __init__.py (usually just imports)
            if py_file.name == '__init__.py':
                continue
            py_files.append(py_file)

        # Sort by size (smaller files first — more likely to be clean examples)
        py_files.sort(key=lambda f: f.stat().st_size)
        return py_files

    def get_stats(self) -> Dict[str, Any]:
        """Return harvester statistics."""
        return {
            **self.stats,
            'domains_in_history': len(self.history.get('domains', {})),
            'known_domains': len(self.DOMAIN_SEARCH_MAP),
        }
