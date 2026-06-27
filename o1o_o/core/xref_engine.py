"""Cross-Reference Engine: Call graph + data flow analysis.

Builds on CFGEngine to provide:
- Function call graph (who calls whom)
- Dangerous sink identification (memcpy, system, exec, etc.)
- Source-sink reachability (can attacker input reach a dangerous sink?)
- Import cross-referencing
- Triplet generation for FORGE knowledge base

Part of FORGE Phase M: Deep Binary Analysis.
"""
# Dependencies: cfg_engine, platform_adapter
# Depended by: decompiler

import os
import struct
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque


# ─── Dangerous Sinks ────────────────────────────────────────────────

# Functions that are dangerous if reached with attacker-controlled data
SINKS = {
    # Memory corruption
    'memory_write': [
        'memcpy', 'memmove', 'memset', 'bcopy', 'bzero',
        'strcpy', 'strncpy', 'strcat', 'strncat',
        'sprintf', 'vsprintf', 'swprintf',
        'gets', 'fgets', 'read', 'recv', 'recvfrom', 'recvmsg',
        'reallocf', 'realloc',
        '_memcpy', '_memmove', '_strcpy', '_strcat',
        'wmemcpy', 'wmemmove', 'wcscpy', 'wcscat',
    ],
    # Command execution
    'command_exec': [
        'system', 'popen', 'execve', 'execvp', 'execl', 'execlp',
        'dlopen', 'dlsym', 'posix_spawn', 'posix_spawnp',
        'fork', 'vfork', 'clone',
        'WinExec', 'ShellExecuteA', 'ShellExecuteW',
        'CreateProcessA', 'CreateProcessW',
        '_system', '_popen', '_exec',
    ],
    # Format string
    'format_string': [
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
        'syslog', 'NSLog',
        'wprintf', 'fwprintf', 'swprintf',
    ],
    # File operations
    'file_ops': [
        'fopen', 'open', 'creat', 'mktemp', 'tmpnam',
        'rename', 'unlink', 'remove', 'rmdir',
        'chmod', 'chown', 'chgrp',
        'CreateFileA', 'CreateFileW', 'DeleteFileA',
    ],
    # Memory management (potential UAF/double-free)
    'memory_mgmt': [
        'free', 'delete', 'cfree', 'realloc',
        'HeapFree', 'LocalFree', 'GlobalFree',
        'munmap', 'VirtualFree',
    ],
    # Privilege
    'privilege': [
        'setuid', 'setgid', 'seteuid', 'setegid',
        'setreuid', 'setregid', 'setresuid', 'setresgid',
        'chroot', 'pivot_root',
        'AdjustTokenPrivileges', 'ImpersonateLoggedOnUser',
    ],
    # Network
    'network': [
        'connect', 'bind', 'listen', 'accept',
        'send', 'sendto', 'sendmsg', 'write',
        'WSAConnect', 'WSASend',
    ],
}

# All sinks flattened for quick lookup
ALL_SINKS = {}
for category, funcs in SINKS.items():
    for f in funcs:
        ALL_SINKS[f] = category
        # Also match with _ prefix (macOS/iOS mangles with _)
        ALL_SINKS[f'_{f}'] = category
        ALL_SINKS[f'__{f}'] = category


# ─── Input Sources ──────────────────────────────────────────────────

# Functions that read attacker-controlled data
SOURCES = {
    'network_input': [
        'recv', 'recvfrom', 'recvmsg', 'read',
        'accept', 'WSARecv', 'WSARecvFrom',
    ],
    'file_input': [
        'fread', 'fgets', 'getline', 'getdelim',
        'fscanf', 'scanf', 'sscanf',
        'ReadFile', 'ReadFileEx',
    ],
    'env_input': [
        'getenv', 'getenv_s',
        'GetEnvironmentVariableA', 'GetEnvironmentVariableW',
    ],
    'user_input': [
        'gets', 'scanf', 'getchar', 'fgetc',
        'argv',  # Command line args
    ],
    'ipc_input': [
        'msgrcv', 'mq_receive',
        'xpc_dictionary_get_string', 'xpc_dictionary_get_data',
        'CFDictionaryGetValue',
    ],
}

ALL_SOURCES = {}
for category, funcs in SOURCES.items():
    for f in funcs:
        ALL_SOURCES[f] = category
        ALL_SOURCES[f'_{f}'] = category
        ALL_SOURCES[f'__{f}'] = category


# ─── Cross-Reference Node ──────────────────────────────────────────

class XRefNode:
    """A function in the cross-reference graph."""
    __slots__ = ('name', 'addr', 'callers', 'callees',
                 'is_sink', 'sink_category', 'is_source', 'source_category',
                 'reachable_sinks', 'reachable_from_sources')

    def __init__(self, name: str, addr: int = 0):
        self.name = name
        self.addr = addr
        self.callers: Set[str] = set()   # Functions that call this
        self.callees: Set[str] = set()   # Functions this calls
        self.is_sink = False
        self.sink_category = ''
        self.is_source = False
        self.source_category = ''
        self.reachable_sinks: Set[str] = set()  # Sinks reachable from here
        self.reachable_from_sources: Set[str] = set()  # Sources that can reach here


# ─── Cross-Reference Engine ────────────────────────────────────────

class XRefEngine:
    """Cross-reference and data flow analysis engine.

    Builds a call graph from binary analysis (CFG engine or import tables),
    identifies sources (attacker input) and sinks (dangerous operations),
    and computes reachability: can attacker data reach a dangerous sink?
    """

    def __init__(self):
        self.nodes: Dict[str, XRefNode] = {}
        self.source_sink_paths: List[Dict] = []  # Cached paths
        self._analyzed = False

    def _get_or_create(self, name: str, addr: int = 0) -> XRefNode:
        """Get existing node or create new one."""
        if name not in self.nodes:
            self.nodes[name] = XRefNode(name, addr)
        return self.nodes[name]

    # ─── Graph Construction ──────────────────────────────────────

    def add_call(self, caller: str, callee: str, caller_addr: int = 0, callee_addr: int = 0):
        """Register a function call edge."""
        c = self._get_or_create(caller, caller_addr)
        t = self._get_or_create(callee, callee_addr)
        c.callees.add(callee)
        t.callers.add(caller)

    def add_import(self, func_name: str, library: str = ''):
        """Register an imported function (potential sink/source)."""
        node = self._get_or_create(func_name)

        # Check if it's a sink
        base_name = func_name.lstrip('_')
        if base_name in ALL_SINKS:
            node.is_sink = True
            node.sink_category = ALL_SINKS[base_name]
        elif func_name in ALL_SINKS:
            node.is_sink = True
            node.sink_category = ALL_SINKS[func_name]

        # Check if it's a source
        if base_name in ALL_SOURCES:
            node.is_source = True
            node.source_category = ALL_SOURCES[base_name]
        elif func_name in ALL_SOURCES:
            node.is_source = True
            node.source_category = ALL_SOURCES[func_name]

    def build_from_cfg(self, cfg_result: dict):
        """Build cross-references from CFGEngine result."""
        if 'function_details' not in cfg_result:
            return

        for func_info in cfg_result['function_details']:
            name = func_info['name']
            addr = func_info.get('addr', 0)
            node = self._get_or_create(name, addr)

            for target in func_info.get('calls', []):
                target_name = target.get('name', f"sub_{target.get('addr', 0):x}")
                self.add_call(name, target_name, addr, target.get('addr', 0))

    def build_from_binary(self, filepath: str):
        """Build cross-references from a binary file.

        Uses platform_adapter for import analysis and cfg_engine for call graph.
        """
        # Step 1: Get imports from platform_adapter
        try:
            from o1o_o.core.platform_adapter import analyze as pa_analyze
            info = pa_analyze(filepath)
            for lib in info.libraries:
                self.add_import(lib)
        except ImportError:
            pass

        # Step 2: Get call graph from cfg_engine
        try:
            from o1o_o.core.cfg_engine import CFGEngine
            cfg = CFGEngine()
            result = cfg.analyze(filepath)

            if result and 'function_details' in result:
                for func in result['function_details']:
                    name = func['name']
                    self._get_or_create(name, func.get('addr', 0))

                    for call_target in func.get('calls', []):
                        target_name = call_target.get('name', f"sub_{call_target.get('addr', 0):x}")
                        self.add_call(name, target_name)

            # Also add string references as imports (for sink detection)
            if result and 'imports' in result:
                for imp in result['imports']:
                    self.add_import(imp)

        except (ImportError, Exception):
            pass

        # Step 3: Mark sinks and sources
        self._classify_nodes()

    def _classify_nodes(self):
        """Classify all nodes as sinks/sources based on name matching."""
        for name, node in self.nodes.items():
            base = name.lstrip('_')
            if base in ALL_SINKS:
                node.is_sink = True
                node.sink_category = ALL_SINKS[base]
            if base in ALL_SOURCES:
                node.is_source = True
                node.source_category = ALL_SOURCES[base]

    # ─── Reachability Analysis ───────────────────────────────────

    def analyze_reachability(self):
        """Compute source-to-sink reachability.

        For each source, BFS forward to find reachable sinks.
        For each sink, BFS backward to find reaching sources.
        """
        self._analyzed = True
        self.source_sink_paths = []

        # Forward analysis: from each source, find reachable sinks
        sources = [n for n in self.nodes.values() if n.is_source]
        sinks = [n for n in self.nodes.values() if n.is_sink]

        for source in sources:
            # BFS forward through call graph
            visited = set()
            queue = deque([source.name])
            parent = {source.name: None}

            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)

                node = self.nodes.get(current)
                if not node:
                    continue

                # Check if we reached a sink
                if node.is_sink and current != source.name:
                    # Reconstruct path
                    path = []
                    p = current
                    while p is not None:
                        path.append(p)
                        p = parent.get(p)
                    path.reverse()

                    self.source_sink_paths.append({
                        'source': source.name,
                        'source_category': source.source_category,
                        'sink': current,
                        'sink_category': node.sink_category,
                        'path': path,
                        'path_length': len(path),
                    })

                    source.reachable_sinks.add(current)
                    node.reachable_from_sources.add(source.name)

                # Expand forward (through callees)
                for callee in node.callees:
                    if callee not in visited:
                        queue.append(callee)
                        if callee not in parent:
                            parent[callee] = current

        # Also check: which callers of sinks might pass untrusted data?
        for sink in sinks:
            for caller in sink.callers:
                caller_node = self.nodes.get(caller)
                if caller_node:
                    caller_node.reachable_sinks.add(sink.name)

    # ─── Query Interface ─────────────────────────────────────────

    def get_sinks(self) -> List[XRefNode]:
        """Get all identified sinks."""
        return [n for n in self.nodes.values() if n.is_sink]

    def get_sources(self) -> List[XRefNode]:
        """Get all identified sources."""
        return [n for n in self.nodes.values() if n.is_source]

    def get_callers(self, func_name: str) -> List[str]:
        """Get all callers of a function."""
        node = self.nodes.get(func_name)
        return list(node.callers) if node else []

    def get_callees(self, func_name: str) -> List[str]:
        """Get all functions called by a function."""
        node = self.nodes.get(func_name)
        return list(node.callees) if node else []

    def get_paths_to_sink(self, sink_name: str) -> List[Dict]:
        """Get all source-to-sink paths that reach a specific sink."""
        if not self._analyzed:
            self.analyze_reachability()
        return [p for p in self.source_sink_paths if p['sink'] == sink_name]

    def get_paths_from_source(self, source_name: str) -> List[Dict]:
        """Get all source-to-sink paths from a specific source."""
        if not self._analyzed:
            self.analyze_reachability()
        return [p for p in self.source_sink_paths if p['source'] == source_name]

    def get_dangerous_callers(self, limit: int = 20) -> List[Dict]:
        """Get functions that call dangerous sinks, ranked by risk."""
        if not self._analyzed:
            self.analyze_reachability()

        dangerous = []
        for name, node in self.nodes.items():
            if node.reachable_sinks:
                risk_score = 0
                for sink_name in node.reachable_sinks:
                    sink = self.nodes.get(sink_name)
                    if sink:
                        cat = sink.sink_category
                        risk_score += {
                            'command_exec': 10,
                            'memory_write': 8,
                            'format_string': 7,
                            'privilege': 9,
                            'memory_mgmt': 6,
                            'file_ops': 5,
                            'network': 4,
                        }.get(cat, 3)

                dangerous.append({
                    'function': name,
                    'risk_score': risk_score,
                    'reachable_sinks': list(node.reachable_sinks),
                    'sink_categories': list(set(
                        self.nodes[s].sink_category
                        for s in node.reachable_sinks
                        if s in self.nodes
                    )),
                    'caller_count': len(node.callers),
                })

        dangerous.sort(key=lambda x: -x['risk_score'])
        return dangerous[:limit]

    # ─── Triplet Generation ──────────────────────────────────────

    def to_triplets(self) -> List[dict]:
        """Convert cross-references to causal triplets."""
        if not self._analyzed:
            self.analyze_reachability()

        triplets = []

        # Call edges
        for name, node in self.nodes.items():
            for callee in node.callees:
                triplets.append({
                    'trigger': name,
                    'mechanism': 'calls',
                    'outcome': callee,
                    'confidence': 0.95,
                })

        # Source → sink paths (high value)
        for path in self.source_sink_paths:
            triplets.append({
                'trigger': f"input_from_{path['source_category']}",
                'mechanism': f"flows_through_{path['path_length']}_hops",
                'outcome': f"reaches_{path['sink_category']}_sink_{path['sink']}",
                'confidence': 0.85,
            })

        # Dangerous caller alerts
        for name, node in self.nodes.items():
            if node.is_sink and node.callers:
                for caller in node.callers:
                    triplets.append({
                        'trigger': caller,
                        'mechanism': f'directly_calls_{node.sink_category}_sink',
                        'outcome': f'potential_{node.sink_category}_vulnerability',
                        'confidence': 0.8,
                    })

        return triplets

    # ─── Analysis Summary ────────────────────────────────────────

    def analyze(self, filepath: str) -> dict:
        """Full cross-reference analysis of a binary."""
        self.build_from_binary(filepath)
        self.analyze_reachability()

        sinks = self.get_sinks()
        sources = self.get_sources()

        # Group sinks by category
        sink_by_cat = defaultdict(list)
        for s in sinks:
            sink_by_cat[s.sink_category].append(s.name)

        source_by_cat = defaultdict(list)
        for s in sources:
            source_by_cat[s.source_category].append(s.name)

        return {
            'file': filepath,
            'total_functions': len(self.nodes),
            'total_call_edges': sum(len(n.callees) for n in self.nodes.values()),
            'sinks': {
                'total': len(sinks),
                'by_category': dict(sink_by_cat),
            },
            'sources': {
                'total': len(sources),
                'by_category': dict(source_by_cat),
            },
            'source_sink_paths': len(self.source_sink_paths),
            'paths': self.source_sink_paths[:20],
            'dangerous_callers': self.get_dangerous_callers(10),
            'triplets_generated': len(self.to_triplets()),
        }

    def format_analysis(self, result: dict) -> str:
        """Format analysis result as text."""
        lines = [
            f"XREF Analysis: {result['file']}",
            f"  Functions:    {result['total_functions']}",
            f"  Call edges:   {result['total_call_edges']}",
            f"  Sinks:        {result['sinks']['total']}",
            f"  Sources:      {result['sources']['total']}",
            f"  Src→Sink:     {result['source_sink_paths']} reachable paths",
        ]

        if result['sinks']['by_category']:
            lines.append(f"")
            lines.append(f"  Sinks by category:")
            for cat, funcs in sorted(result['sinks']['by_category'].items()):
                lines.append(f"    {cat:20s} {len(funcs):3d}  ({', '.join(funcs[:5])})")

        if result['sources']['by_category']:
            lines.append(f"")
            lines.append(f"  Sources by category:")
            for cat, funcs in sorted(result['sources']['by_category'].items()):
                lines.append(f"    {cat:20s} {len(funcs):3d}  ({', '.join(funcs[:5])})")

        if result['paths']:
            lines.append(f"")
            lines.append(f"  Source → Sink Paths:")
            for p in result['paths'][:10]:
                path_str = ' → '.join(p['path'][:5])
                if len(p['path']) > 5:
                    path_str += f" → ... ({len(p['path'])} hops)"
                lines.append(f"    [{p['source_category']}] {path_str} [{p['sink_category']}]")

        if result['dangerous_callers']:
            lines.append(f"")
            lines.append(f"  Dangerous callers (top {len(result['dangerous_callers'])}):")
            for dc in result['dangerous_callers'][:5]:
                cats = ', '.join(dc['sink_categories'][:3])
                lines.append(f"    {dc['function'][:35]:35s} risk={dc['risk_score']:3d}  "
                             f"sinks={len(dc['reachable_sinks'])}  ({cats})")

        lines.append(f"")
        lines.append(f"  {result['triplets_generated']} causal triplets generated")

        return '\n'.join(lines)
