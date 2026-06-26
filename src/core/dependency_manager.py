"""
Dependency Manager — Track, resolve, and install Python dependencies

Features:
1. Extract imports from generated code
2. Classify: stdlib vs third-party
3. Resolve package names (cv2 → opencv-python)
4. Auto-install missing packages
5. Generate requirements.txt
6. Detect version conflicts
"""
# Dependencies: none
# Depended by: none (leaf module)


import subprocess
import sys
import importlib
import re
from typing import List, Dict, Set, Optional, Tuple


class DependencyManager:
    """Manage Python dependencies for generated code"""

    # Python stdlib modules (3.10+)
    STDLIB = {
        'abc', 'aifc', 'argparse', 'array', 'ast', 'asyncio', 'atexit',
        'base64', 'binascii', 'bisect', 'builtins', 'bz2',
        'calendar', 'cgi', 'cgitb', 'chunk', 'cmath', 'cmd', 'code',
        'codecs', 'codeop', 'collections', 'colorsys', 'compileall',
        'concurrent', 'configparser', 'contextlib', 'contextvars', 'copy',
        'copyreg', 'cProfile', 'crypt', 'csv', 'ctypes', 'curses',
        'dataclasses', 'datetime', 'dbm', 'decimal', 'difflib', 'dis',
        'distutils', 'doctest',
        'email', 'encodings', 'enum', 'errno',
        'faulthandler', 'fcntl', 'filecmp', 'fileinput', 'fnmatch',
        'fractions', 'ftplib', 'functools',
        'gc', 'getopt', 'getpass', 'gettext', 'glob', 'grp', 'gzip',
        'hashlib', 'heapq', 'hmac', 'html', 'http',
        'idlelib', 'imaplib', 'imghdr', 'imp', 'importlib', 'inspect',
        'io', 'ipaddress', 'itertools',
        'json',
        'keyword',
        'lib2to3', 'linecache', 'locale', 'logging', 'lzma',
        'mailbox', 'mailcap', 'marshal', 'math', 'mimetypes', 'mmap',
        'modulefinder', 'multiprocessing',
        'netrc', 'nis', 'nntplib', 'numbers',
        'operator', 'optparse', 'os', 'ossaudiodev',
        'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil',
        'platform', 'plistlib', 'poplib', 'posix', 'posixpath', 'pprint',
        'profile', 'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr',
        'pydoc',
        'queue', 'quopri',
        'random', 're', 'readline', 'reprlib', 'resource', 'rlcompleter',
        'runpy',
        'sched', 'secrets', 'select', 'selectors', 'shelve', 'shlex',
        'shutil', 'signal', 'site', 'smtpd', 'smtplib', 'sndhdr',
        'socket', 'socketserver', 'sqlite3', 'ssl', 'stat', 'statistics',
        'string', 'stringprep', 'struct', 'subprocess', 'sunau', 'symtable',
        'sys', 'sysconfig', 'syslog',
        'tabnanny', 'tarfile', 'telnetlib', 'tempfile', 'termios', 'test',
        'textwrap', 'threading', 'time', 'timeit', 'tkinter', 'token',
        'tokenize', 'tomllib', 'trace', 'traceback', 'tracemalloc', 'tty',
        'turtle', 'turtledemo', 'types', 'typing',
        'unicodedata', 'unittest', 'urllib', 'uu', 'uuid',
        'venv',
        'warnings', 'wave', 'weakref', 'webbrowser', 'winreg', 'winsound',
        'wsgiref',
        'xdrlib', 'xml', 'xmlrpc',
        'zipapp', 'zipfile', 'zipimport', 'zlib',
        '_thread',
    }

    # Import name → pip package name (when they differ)
    PACKAGE_MAP = {
        'PIL': 'Pillow',
        'cv2': 'opencv-python',
        'sklearn': 'scikit-learn',
        'yaml': 'pyyaml',
        'bs4': 'beautifulsoup4',
        'lxml': 'lxml',
        'dateutil': 'python-dateutil',
        'dotenv': 'python-dotenv',
        'jwt': 'PyJWT',
        'Crypto': 'pycryptodome',
        'magic': 'python-magic',
        'gi': 'PyGObject',
        'wx': 'wxPython',
        'serial': 'pyserial',
        'usb': 'pyusb',
        'daemon': 'python-daemon',
        'dns': 'dnspython',
        'paramiko': 'paramiko',
        'socks': 'PySocks',
        'nacl': 'PyNaCl',
        'attr': 'attrs',
        'msgpack': 'msgpack',
        'jellyfish': 'jellyfish',
        'rich': 'rich',
        'click': 'click',
        'flask': 'flask',
        'django': 'django',
        'fastapi': 'fastapi',
        'pydantic': 'pydantic',
        'requests': 'requests',
        'aiohttp': 'aiohttp',
        'httpx': 'httpx',
        'numpy': 'numpy',
        'pandas': 'pandas',
        'scipy': 'scipy',
        'matplotlib': 'matplotlib',
        'seaborn': 'seaborn',
        'torch': 'torch',
        'tensorflow': 'tensorflow',
        'transformers': 'transformers',
        'sqlalchemy': 'sqlalchemy',
        'psycopg2': 'psycopg2-binary',
        'pymongo': 'pymongo',
        'redis': 'redis',
        'celery': 'celery',
        'scrapy': 'scrapy',
        'scapy': 'scapy',
        'nmap': 'python-nmap',
        'shodan': 'shodan',
        'pwntools': 'pwntools',
        'angr': 'angr',
        'volatility3': 'volatility3',
        'yara': 'yara-python',
        'hypothesis': 'hypothesis',
        'pytest': 'pytest',
    }

    def __init__(self):
        self._installed_cache = None

    def extract_imports(self, code: str) -> Set[str]:
        """Extract all imported module names from code"""
        modules = set()
        for line in code.split('\n'):
            stripped = line.strip()
            if stripped.startswith('import '):
                # import os, sys → ['os', 'sys']
                parts = stripped[7:].split(',')
                for p in parts:
                    mod = p.strip().split(' as ')[0].split('.')[0]
                    if mod:
                        modules.add(mod)
            elif stripped.startswith('from '):
                match = re.match(r'from\s+(\S+)\s+import', stripped)
                if match:
                    modules.add(match.group(1).split('.')[0])
        return modules

    def classify(self, modules: Set[str]) -> Tuple[Set[str], Set[str]]:
        """Classify modules into stdlib vs third-party"""
        stdlib_mods = set()
        third_party = set()

        for mod in modules:
            if mod in self.STDLIB or mod.startswith('_'):
                stdlib_mods.add(mod)
            else:
                third_party.add(mod)

        return stdlib_mods, third_party

    def resolve_package_names(self, modules: Set[str]) -> Dict[str, str]:
        """Map import names to pip package names"""
        mapping = {}
        for mod in modules:
            if mod in self.PACKAGE_MAP:
                mapping[mod] = self.PACKAGE_MAP[mod]
            else:
                mapping[mod] = mod
        return mapping

    def check_installed(self, modules: Set[str]) -> Tuple[Set[str], Set[str]]:
        """Check which modules are installed vs missing"""
        installed = set()
        missing = set()

        for mod in modules:
            try:
                importlib.import_module(mod)
                installed.add(mod)
            except ImportError:
                missing.add(mod)

        return installed, missing

    def install_missing(self, modules: Set[str], quiet: bool = True) -> Dict[str, bool]:
        """Install missing packages via pip"""
        results = {}
        _, missing = self.check_installed(modules)
        package_names = self.resolve_package_names(missing)

        for mod, pkg in package_names.items():
            cmd = [sys.executable, '-m', 'pip', 'install']
            if quiet:
                cmd.append('-q')
            cmd.append(pkg)

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                results[mod] = result.returncode == 0
            except (subprocess.TimeoutExpired, Exception):
                results[mod] = False

        return results

    def generate_requirements(self, code: str, pin_versions: bool = False) -> str:
        """Generate requirements.txt content from code"""
        modules = self.extract_imports(code)
        _, third_party = self.classify(modules)
        packages = self.resolve_package_names(third_party)

        lines = []
        for mod in sorted(third_party):
            pkg = packages.get(mod, mod)
            if pin_versions:
                version = self._get_installed_version(pkg)
                if version:
                    lines.append(f'{pkg}=={version}')
                else:
                    lines.append(pkg)
            else:
                lines.append(pkg)

        return '\n'.join(lines)

    def _get_installed_version(self, package: str) -> Optional[str]:
        """Get installed version of a package"""
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'show', package],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                match = re.search(r'^Version:\s*(.+)$', result.stdout, re.MULTILINE)
                if match:
                    return match.group(1).strip()
        except Exception:
            pass
        return None

    def analyze_code(self, code: str) -> Dict:
        """Full dependency analysis of generated code"""
        modules = self.extract_imports(code)
        stdlib, third_party = self.classify(modules)
        installed, missing = self.check_installed(third_party)
        packages = self.resolve_package_names(third_party)

        return {
            'stdlib': sorted(stdlib),
            'third_party': sorted(third_party),
            'installed': sorted(installed),
            'missing': sorted(missing),
            'packages': packages,
            'requirements': self.generate_requirements(code),
        }
