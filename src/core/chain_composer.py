"""Chain Composer: Compose complete kill chains from FORGE fragments.

Takes a kill chain path (from KillChainGraph) and assembles the
fragments into a single operational script. Uses FORGE's existing
code assembly pipeline with kill-chain-aware ordering.

Pipeline:
  Intent → KillChainGraph → Path → ChainComposer → Operational Script

Part of FORGE Phase H: Sovereign Cyber Intelligence Platform.
"""
# Dependencies: kill_chain
# Depended by: none (leaf module)

import json
import os
import re
import textwrap
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from core.kill_chain import KillChainGraph


class ChainComposer:
    """Composes kill chain fragments into operational scripts."""

    def __init__(self, fragments_dir: str = 'fragments'):
        self.fragments_dir = fragments_dir
        self.graph = KillChainGraph()
        self._fragment_cache: Dict[str, str] = {}
        self._mechanism_map: Dict[str, str] = self.graph.ontology.get(
            'mechanism_to_fragment', {})
        self._load_all_fragments()

    def _load_all_fragments(self):
        """Load all fragment code into cache."""
        if not os.path.exists(self.fragments_dir):
            return

        for fname in os.listdir(self.fragments_dir):
            if not fname.endswith('.json'):
                continue
            path = os.path.join(self.fragments_dir, fname)
            try:
                with open(path) as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self._fragment_cache.update(data)
            except (json.JSONDecodeError, OSError):
                pass

    def compose_chain(self, intent: str,
                      max_chains: int = 5) -> List[Dict]:
        """Compose kill chains from a natural language intent.

        Args:
            intent: Natural language description
                (e.g., "remote compromise with c2 and persistence")
            max_chains: Maximum number of chains to return

        Returns:
            List of composed chain dicts, each with:
                - chain: the kill chain info (path, stages, techniques)
                - code: assembled Python script
                - fragments_used: list of fragment keys
                - att_ck: ATT&CK technique mappings
        """
        # 1. Resolve intent to kill chain parameters
        params = self.graph.resolve_intent_to_chain(intent)

        # 2. Find kill chain paths
        chains = self.graph.find_kill_chain(
            params['entry_caps'],
            params['objectives'],
            params.get('required_stages'),
            max_depth=10)

        if not chains:
            return []

        # 3. Compose code for each chain
        results = []
        seen_fragment_sets = set()

        for chain in chains[:max_chains * 3]:
            frag_key = tuple(sorted(chain['fragments']))
            if frag_key in seen_fragment_sets:
                continue
            seen_fragment_sets.add(frag_key)

            code = self._assemble_chain(chain, intent)
            if code:
                results.append({
                    'chain': chain,
                    'code': code,
                    'fragments_used': chain['fragments'],
                    'att_ck': self._get_technique_details(chain['techniques']),
                    'stages': chain['stages'],
                    'score': chain['score'],
                })

            if len(results) >= max_chains:
                break

        return results

    def _assemble_chain(self, chain: Dict, intent: str) -> Optional[str]:
        """Assemble fragment code into a single operational script.

        Handles:
        - Import deduplication
        - Function ordering (dependencies first)
        - Config section at top
        - Main orchestrator function
        - Stage-by-stage execution with mechanism_to_fragment resolution
        """
        fragments = list(chain['fragments'])

        # Also pull in mechanism-mapped fragments not already in the list
        for src, mech, dst in chain['path']:
            mapped_frag = self._mechanism_map.get(mech)
            if mapped_frag and mapped_frag not in fragments:
                if mapped_frag in self._fragment_cache:
                    fragments.append(mapped_frag)

        if not fragments:
            return None

        # Collect code from fragments
        fragment_codes = {}
        for frag_name in fragments:
            code = self._fragment_cache.get(frag_name)
            if code:
                fragment_codes[frag_name] = code

        if not fragment_codes:
            return None

        # Update chain's fragment list with resolved fragments
        chain['fragments'] = fragments

        # Build the composed script
        sections = {
            'imports': set(),
            'config': [],
            'functions': [],
            'main_calls': [],
            'func_names': [],       # ordered list of (frag_name, func_name) tuples
            'bare_code': {},        # frag_name → bare code (top-level, non-function)
        }

        for frag_name in fragments:
            code = fragment_codes.get(frag_name)
            if not code:
                continue

            self._extract_sections(frag_name, code, sections)

        return self._build_script(intent, chain, sections)

    def _extract_sections(self, frag_name: str, code: str,
                          sections: Dict):
        """Extract imports, functions, and bare code from fragment code.

        Tracks function names per fragment so the orchestrator can call them.
        Bare code (top-level statements that aren't imports/functions) is
        wrapped into a stage function for orchestration.
        """
        lines = code.split('\n')
        in_function = False
        current_func = []
        current_func_name = None
        func_indent = 0
        bare_lines = []
        frag_func_names = []

        def _flush_function():
            nonlocal in_function, current_func, current_func_name
            if current_func:
                sections['functions'].append('\n'.join(current_func))
                if current_func_name:
                    frag_func_names.append(current_func_name)
            in_function = False
            current_func = []
            current_func_name = None

        for line in lines:
            stripped = line.strip()

            # Shebang lines
            if stripped.startswith('#!'):
                continue

            # Skip empty lines and comments at top level
            if not stripped or stripped.startswith('#'):
                if in_function:
                    current_func.append(line)
                continue

            # Imports
            if not in_function and (stripped.startswith('import ') or
                                     stripped.startswith('from ')):
                sections['imports'].add(stripped)
                continue

            # Function/class definitions
            if stripped.startswith('def ') or stripped.startswith('class '):
                if in_function:
                    _flush_function()
                in_function = True
                current_func = [line]
                func_indent = len(line) - len(line.lstrip())
                # Extract function name (skip dunder methods — not callable as stages)
                m = re.match(r'def\s+(\w+)\s*\(', stripped)
                if m and not m.group(1).startswith('__'):
                    current_func_name = m.group(1)
                else:
                    current_func_name = None
                continue

            if in_function:
                line_indent = len(line) - len(line.lstrip()) if stripped else func_indent + 4
                if line_indent > func_indent or not stripped:
                    current_func.append(line)
                else:
                    _flush_function()
                    # Check if this starts a new function
                    if stripped.startswith('def ') or stripped.startswith('class '):
                        in_function = True
                        current_func = [line]
                        func_indent = len(line) - len(line.lstrip())
                        m = re.match(r'def\s+(\w+)\s*\(', stripped)
                        if m and not m.group(1).startswith('__'):
                            current_func_name = m.group(1)
                        else:
                            current_func_name = None
                    else:
                        # Top-level code outside function
                        bare_lines.append(line)
            else:
                # Top-level code (not in a function, not an import)
                # Skip global constant assignments (SBOX, etc.)
                if re.match(r'^[A-Z_]+ = ', stripped):
                    sections['functions'].append(line)
                else:
                    bare_lines.append(line)

        # Flush last function
        if in_function:
            _flush_function()

        # If fragment has NO functions, wrap all bare code into a stage function
        # If it HAS functions, bare code is the "main" invocation — also wrap it
        if bare_lines:
            # Clean bare code: remove if __name__ guards
            clean_bare = []
            skip_main = False
            for bl in bare_lines:
                bs = bl.strip()
                if bs.startswith('if __name__'):
                    skip_main = True
                    continue
                if skip_main:
                    if bs and not bs.startswith(' ') and not bs.startswith('\t'):
                        skip_main = False
                    elif bs:
                        # Dedent one level
                        clean_bare.append(bl.replace('    ', '', 1) if bl.startswith('    ') else bl)
                        continue
                    else:
                        continue
                if not skip_main:
                    clean_bare.append(bl)

            if clean_bare:
                sections['bare_code'][frag_name] = '\n'.join(clean_bare)

        # Record function names for this fragment
        if frag_func_names:
            # Store the primary (first) function as the callable for this fragment
            sections['func_names'].append((frag_name, frag_func_names[0]))
        elif bare_lines:
            # Fragment is bare code — we'll wrap it in a stage function
            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', frag_name)
            wrapper_name = f'stage_{safe_name}'
            # Build wrapper function from bare code
            indented = '\n'.join(f'    {bl}' if bl.strip() else '' for bl in clean_bare)
            wrapper = f'def {wrapper_name}(**kwargs):\n    """Auto-wrapped stage: {frag_name}"""\n{indented}\n    return {{"status": "complete", "fragment": "{frag_name}"}}'
            sections['functions'].append(wrapper)
            sections['func_names'].append((frag_name, wrapper_name))

    def _build_script(self, intent: str, chain: Dict,
                      sections: Dict) -> str:
        """Build the final composed script with LIVE orchestration.

        The orchestrator actually calls fragment functions in kill chain order,
        passing results between stages via a shared context dict.
        """
        lines = []
        num_path = len(chain['path'])
        num_stages = len(chain['stages'])

        # Header
        lines.append(f'"""FORGE Kill Chain — Auto-composed')
        lines.append(f'')
        lines.append(f'Intent: {intent}')
        lines.append(f'Stages: {" → ".join(chain["stages"])}')
        lines.append(f'Fragments: {", ".join(chain["fragments"])}')
        if chain.get('techniques'):
            tech_strs = []
            for tid in chain['techniques'][:10]:
                info = self.graph.technique_index.get(tid, {})
                name = info.get('name', tid)
                tech_strs.append(f'{tid} ({name})')
            lines.append(f'ATT&CK: {", ".join(tech_strs)}')
        lines.append(f'')
        lines.append(f'Generated by FORGE — deterministic, zero AI, fully offline.')
        lines.append(f'"""')
        lines.append('')

        # Imports — always include sys and traceback for error handling
        sections['imports'].add('import sys')
        sections['imports'].add('import traceback')

        sorted_imports = sorted(sections['imports'])
        stdlib_imports = [i for i in sorted_imports
                          if not any(i.startswith(f'import {tp}') or i.startswith(f'from {tp}')
                                     for tp in ['requests', 'flask', 'django'])]
        for imp in stdlib_imports:
            lines.append(imp)
        lines.append('')
        lines.append('')

        # Config section
        lines.append('# ' + '═' * 59)
        lines.append('# CONFIGURATION — Modify these for your operation')
        lines.append('# ' + '═' * 59)
        lines.append('')

        config_vars = self._generate_config(chain)
        for var, val in config_vars.items():
            lines.append(f'{var} = {val}')
        lines.append('')
        lines.append('')

        # Functions
        lines.append('# ' + '═' * 59)
        lines.append('# KILL CHAIN COMPONENTS')
        lines.append('# ' + '═' * 59)
        lines.append('')

        for func in sections['functions']:
            lines.append(func)
            lines.append('')
            lines.append('')

        # Build a mapping: fragment_name → callable function name
        frag_to_func = {}
        for frag_name, func_name in sections.get('func_names', []):
            frag_to_func[frag_name] = func_name

        # Main orchestrator — ACTUALLY CALLS FUNCTIONS
        lines.append('# ' + '═' * 59)
        lines.append('# KILL CHAIN ORCHESTRATOR')
        lines.append('# ' + '═' * 59)
        lines.append('')
        lines.append('def run_kill_chain(fail_fast=False):')
        stage_str = ' -> '.join(chain['stages'])
        lines.append(f'    """Execute kill chain: {stage_str}')
        lines.append(f'')
        lines.append(f'    Args:')
        lines.append(f'        fail_fast: If True, abort chain on first stage failure.')
        lines.append(f'                   If False, log error and continue to next stage.')
        lines.append(f'    """')
        lines.append(f'    print("[*] FORGE Kill Chain — {num_stages} stages, {num_path} steps")')
        frags_preview = ', '.join(chain['fragments'][:5])
        lines.append(f'    print("[*] Fragments: {frags_preview}")')
        lines.append(f'    print()')
        lines.append(f'')
        lines.append(f'    # Shared context — each stage can read/write results here')
        lines.append(f'    ctx = {{')
        # Inject config vars into context
        for var in config_vars:
            lines.append(f'        "{var.lower()}": {var},')
        lines.append(f'    }}')
        lines.append(f'    results = []')
        lines.append(f'    failed = []')
        lines.append(f'')

        # Generate a call block for each path step
        used_fragments = set()
        for i, (src, mech, dst) in enumerate(chain['path'], 1):
            stage = chain['stages'][min(i-1, num_stages - 1)]

            # Find which fragment handles this step using multiple strategies:
            step_fragment = None

            # Strategy 0: mechanism_to_fragment explicit mapping (most reliable)
            mapped = self._mechanism_map.get(mech)
            if mapped and mapped in frag_to_func:
                step_fragment = mapped
            elif mapped and mapped in self._fragment_cache:
                step_fragment = mapped

            # Strategy 1: mechanism IS the fragment name
            if not step_fragment and mech in frag_to_func:
                step_fragment = mech

            # Strategy 2: mechanism matches a fragment name (substring)
            if not step_fragment:
                for frag_name in chain['fragments']:
                    if frag_name not in used_fragments:
                        if mech in frag_name or frag_name in mech:
                            step_fragment = frag_name
                            break

            # Strategy 3: find fragment that provides dst capability
            if not step_fragment:
                for frag_name in chain['fragments']:
                    if frag_name in used_fragments:
                        continue
                    info = self.graph.fragment_index.get(frag_name, {})
                    provides = set(info.get('provides', []))
                    if dst in provides:
                        step_fragment = frag_name
                        break

            if step_fragment:
                used_fragments.add(step_fragment)

            func_name = frag_to_func.get(step_fragment) if step_fragment else None

            lines.append(f'    # ── Stage {i}/{num_path}: {stage} ──')
            lines.append(f'    print(f"[{i}/{num_path}] {stage}: {mech}")')

            if func_name:
                # Call the actual function with error handling
                lines.append(f'    try:')
                lines.append(f'        _result = {func_name}(**ctx) if _accepts_kwargs({func_name}) else {func_name}()')
                lines.append(f'        if isinstance(_result, dict):')
                lines.append(f'            ctx.update(_result)')
                lines.append(f'        results.append(("{mech}", "success", _result))')
                lines.append(f'        print(f"    [+] {mech} — OK")')
                lines.append(f'    except Exception as _e:')
                lines.append(f'        failed.append(("{mech}", str(_e)))')
                lines.append(f'        print(f"    [-] {mech} — FAILED: {{_e}}")')
                lines.append(f'        if fail_fast:')
                lines.append(f'            print("[!] Aborting: fail_fast=True")')
                lines.append(f'            return {{"success": False, "results": results, "failed": failed, "ctx": ctx}}')
            else:
                # No function found for this step — log it
                lines.append(f'    # No callable found for fragment: {step_fragment or mech}')
                lines.append(f'    print(f"    [~] {mech} — no callable (manual step)")')
                lines.append(f'    results.append(("{mech}", "skipped", None))')

            lines.append(f'')

        # Summary
        lines.append(f'    # ── Summary ──')
        lines.append(f'    print()')
        lines.append(f'    succeeded = sum(1 for _, s, _ in results if s == "success")')
        lines.append(f'    print(f"[*] Kill chain complete: {{succeeded}}/{num_path} stages succeeded")')
        lines.append(f'    if failed:')
        lines.append(f'        print(f"[!] Failed stages:")')
        lines.append(f'        for name, err in failed:')
        lines.append(f'            print(f"    {{name}}: {{err}}")')
        lines.append(f'    return {{"success": not failed, "results": results, "failed": failed, "ctx": ctx}}')
        lines.append(f'')
        lines.append(f'')

        # Helper: check if function accepts **kwargs
        lines.append('def _accepts_kwargs(fn):')
        lines.append('    """Check if a function accepts **kwargs."""')
        lines.append('    import inspect')
        lines.append('    try:')
        lines.append('        sig = inspect.signature(fn)')
        lines.append('        return any(p.kind == inspect.Parameter.VAR_KEYWORD')
        lines.append('                   for p in sig.parameters.values())')
        lines.append('    except (ValueError, TypeError):')
        lines.append('        return False')
        lines.append('')
        lines.append('')
        lines.append('if __name__ == "__main__":')
        lines.append('    result = run_kill_chain(fail_fast=False)')
        lines.append('    sys.exit(0 if result["success"] else 1)')

        return '\n'.join(lines)

    def _generate_config(self, chain: Dict) -> Dict[str, str]:
        """Generate config variables based on chain requirements."""
        config = {}

        # Collect all requirements from fragments
        all_requires = set()
        for frag_name in chain['fragments']:
            info = self.graph.fragment_index.get(frag_name, {})
            all_requires.update(info.get('requires', []))

        # Map requirements to config variables
        config_map = {
            'target_ip': ('TARGET_IP', '"10.0.0.1"'),
            'target_domain': ('TARGET_DOMAIN', '"target.local"'),
            'target_url': ('TARGET_URL', '"https://target.local"'),
            'listener_ip': ('LISTENER_IP', '"0.0.0.0"'),
            'listen_port': ('LISTEN_PORT', '4444'),
            'c2_server_ip': ('C2_SERVER', '"10.0.0.100"'),
            'dns_domain': ('DNS_DOMAIN', '"c2.example.com"'),
            'target_binary': ('TARGET_BINARY', '"/usr/sbin/target"'),
            'network_range': ('NETWORK_RANGE', '"10.0.0.0/24"'),
            'target_dir': ('TARGET_DIR', '"/tmp/target"'),
            'target_process': ('TARGET_PROCESS', '"explorer.exe"'),
            'target_pid': ('TARGET_PID', '0'),
            'target_email': ('TARGET_EMAIL', '"target@example.com"'),
            'proxy_server': ('PROXY_SERVER', '"proxy.example.com"'),
            'cdn_domain': ('CDN_DOMAIN', '"cdn.example.com"'),
            'payload': ('PAYLOAD', 'b"\\x90" * 100'),
            'payload_url': ('PAYLOAD_URL', '"https://c2.example.com/payload"'),
            'cloud_endpoint': ('CLOUD_ENDPOINT', '"https://storage.example.com"'),
            'search_query': ('SEARCH_QUERY', '"apache 2.4"'),
            'macos_access': ('MACOS_TARGET', '"localhost"'),
            'domain_access': ('DOMAIN', '"corp.local"'),
            'admin_access': ('ADMIN_USER', '"administrator"'),
            'wallet_addr': ('WALLET', '"0x0000000000000000000000000000000000000000"'),
        }

        for req in sorted(all_requires):
            if req in config_map:
                var_name, default = config_map[req]
                config[var_name] = default

        # Always include operation metadata
        config['OPERATION_NAME'] = '"forge_chain"'

        return config

    def _get_technique_details(self, technique_ids: List[str]) -> List[Dict]:
        """Get full ATT&CK technique details."""
        details = []
        for tid in technique_ids:
            info = self.graph.technique_index.get(tid, {})
            if info:
                details.append({
                    'id': tid,
                    'name': info.get('name', ''),
                    'tactic': info.get('tactic', ''),
                })
        return details

    def format_result(self, result: Dict) -> str:
        """Format a composed chain result for display."""
        lines = []
        chain = result['chain']
        lines.append(f"{'═' * 60}")
        lines.append(f"FORGE Kill Chain — Score: {result['score']}")
        lines.append(f"{'═' * 60}")
        lines.append(f"Stages: {' → '.join(result['stages'])}")
        lines.append(f"Fragments ({len(result['fragments_used'])}): "
                     f"{', '.join(result['fragments_used'])}")

        if result['att_ck']:
            lines.append(f"ATT&CK Techniques:")
            for t in result['att_ck'][:10]:
                lines.append(f"  {t['id']}: {t['name']} [{t['tactic']}]")

        lines.append(f"\nPath:")
        for src, mech, dst in chain['path']:
            lines.append(f"  {src} → [{mech}] → {dst}")

        lines.append(f"\nCode: {len(result['code'])} chars, "
                     f"{result['code'].count(chr(10))} lines")

        return '\n'.join(lines)


if __name__ == '__main__':
    composer = ChainComposer()

    # Test composition
    test_intents = [
        "remote network compromise with persistence",
        "local macOS privilege escalation to root",
        "active directory lateral movement with credential theft",
        "remote recon and service enumeration",
    ]

    for intent in test_intents:
        print(f"\n{'=' * 70}")
        print(f"Intent: {intent}")
        print(f"{'=' * 70}")

        results = composer.compose_chain(intent, max_chains=2)
        if results:
            for r in results:
                print()
                print(composer.format_result(r))
        else:
            print("  No chains found")
