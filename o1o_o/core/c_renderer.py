"""
C Renderer — Language-specific code generation for C

Maps fragment keys to C implementations and renders complete C programs.
Used for systems programming, exploit development, and low-level code.

The renderer:
1. Maps Python fragment keys to C equivalents via FRAGMENT_MAP
2. Resolves template variables ({host}, {port}, {path}, etc.)
3. Generates compilable C code with proper includes and main()
4. Provides compilation commands for the output
"""
# Dependencies: none
# Depended by: code_assembler


import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional


# Maps Python fragment keys → C fragment keys
FRAGMENT_MAP = {
    # Networking
    'socket_server': 'c_socket_server',
    'socket_client': 'c_socket_client',
    'tcp_server': 'c_socket_server',
    'tcp_client': 'c_socket_client',
    'port_scanner': 'c_port_scanner',
    'http_request': 'c_http_request',
    'reverse_shell': 'c_reverse_shell',
    'arp_spoof': 'c_arp_spoof',

    # File I/O
    'file_read': 'c_file_read',
    'file_write': 'c_file_write',
    'read_file': 'c_file_read',
    'write_file': 'c_file_write',

    # Crypto
    'sha256_hash': 'c_sha256_hash',
    'hash_file': 'c_sha256_hash',
    'xor_cipher': 'c_xor_cipher',
    'xor_encrypt': 'c_xor_cipher',

    # Systems
    'process_list': 'c_process_list',
    'list_processes': 'c_process_list',
    'keylogger': 'c_keylogger',
    'memory_scanner': 'c_memory_scanner',
    'shellcode_runner': 'c_shellcode_runner',
    'shellcode_exec': 'c_shellcode_runner',

    # Data structures
    'struct_pack': 'c_struct_pack',
    'binary_protocol': 'c_struct_pack',
    'linked_list': 'c_linked_list',
    'thread_pool': 'c_thread_pool',

    # Security demos
    'buffer_overflow': 'c_buffer_overflow_demo',
    'buffer_overflow_demo': 'c_buffer_overflow_demo',
}

# C-specific variable defaults
C_DEFAULTS = {
    'host': '127.0.0.1',
    'port': '8080',
    'path': 'data.txt',
    'data': 'test_data',
    'url': 'http://example.com',
    'interface': 'eth0',
}

# Compilation commands by platform
COMPILE_COMMANDS = {
    'default': 'gcc -o {output} {source} -Wall -Wextra',
    'threaded': 'gcc -o {output} {source} -Wall -Wextra -pthread',
    'crypto_macos': 'gcc -o {output} {source} -Wall -Wextra -framework Security',
    'network': 'gcc -o {output} {source} -Wall -Wextra',
}


class CRenderer:
    """Renders C code from fragment keys and inference chains."""

    def __init__(self, fragments_dir: Path):
        self.fragments_dir = Path(fragments_dir)
        self.c_fragments = {}
        self._load_fragments()

    def _load_fragments(self):
        """Load C fragment JSON files."""
        c_frag_path = self.fragments_dir / 'c_fragments.json'
        if c_frag_path.exists():
            with open(c_frag_path) as f:
                self.c_fragments = json.load(f)
            print(f"Loaded {len(self.c_fragments)} C fragments")

    def can_render(self, fragment_key: str) -> bool:
        """Check if a Python fragment key has a C equivalent."""
        return fragment_key in FRAGMENT_MAP or fragment_key in self.c_fragments

    def get_c_key(self, python_key: str) -> Optional[str]:
        """Map a Python fragment key to its C equivalent."""
        c_key = FRAGMENT_MAP.get(python_key)
        if c_key and c_key in self.c_fragments:
            return c_key
        if python_key in self.c_fragments:
            return python_key
        # Try prefix matching
        for py_key, c_key in FRAGMENT_MAP.items():
            if py_key in python_key and c_key in self.c_fragments:
                return c_key
        return None

    def render(self, fragment_key: str, params: Dict[str, Any] = None,
               intent: Dict[str, Any] = None) -> Optional[str]:
        """Render a C program from a fragment key.

        Returns complete, compilable C code or None if no C equivalent exists.
        """
        c_key = self.get_c_key(fragment_key)
        if not c_key:
            return None

        code = self.c_fragments[c_key]
        code = self._resolve_variables(code, params or {})
        return code

    def render_chain(self, chain: List[Dict[str, Any]], intent: Dict[str, Any] = None) -> Optional[str]:
        """Render a C program from an inference chain.

        For C, we pick the best matching fragment from the chain
        (C programs are typically monolithic, not composed like Python).
        """
        params = intent.get('params', {}) if intent else {}

        # Find the best C fragment from the chain
        for item in chain:
            triplet = item.get('triplet', item)
            outcome = triplet.get('outcome', '')

            c_key = self.get_c_key(outcome)
            if c_key:
                code = self.c_fragments[c_key]
                code = self._resolve_variables(code, params)
                return code

            # Try trigger as key
            trigger = triplet.get('trigger', '')
            c_key = self.get_c_key(trigger)
            if c_key:
                code = self.c_fragments[c_key]
                code = self._resolve_variables(code, params)
                return code

        return None

    def _resolve_variables(self, template: str, params: Dict[str, Any]) -> str:
        """Replace {variables} in C template with values."""
        result = template
        for key, default in C_DEFAULTS.items():
            value = str(params.get(key, default))
            result = result.replace(f'{{{key}}}', value)
        # Also resolve any extra params
        for key, value in params.items():
            result = result.replace(f'{{{key}}}', str(value))
        return result

    def get_compile_command(self, source_file: str, fragment_key: str = '') -> str:
        """Get the appropriate compilation command for a C fragment."""
        output = source_file.replace('.c', '')
        c_key = self.get_c_key(fragment_key) or fragment_key

        if 'thread' in c_key:
            cmd = COMPILE_COMMANDS['threaded']
        elif 'sha256' in c_key or 'crypto' in c_key:
            cmd = COMPILE_COMMANDS['crypto_macos']
        else:
            cmd = COMPILE_COMMANDS['default']

        return cmd.format(output=output, source=source_file)

    def get_available_fragments(self) -> Dict[str, List[str]]:
        """List available C fragments grouped by category."""
        categories = {
            'networking': [],
            'file_io': [],
            'crypto': [],
            'systems': [],
            'data_structures': [],
            'security': [],
        }

        for key in self.c_fragments:
            if 'socket' in key or 'http' in key or 'port' in key or 'arp' in key:
                categories['networking'].append(key)
            elif 'file' in key:
                categories['file_io'].append(key)
            elif 'sha' in key or 'xor' in key or 'cipher' in key:
                categories['crypto'].append(key)
            elif 'process' in key or 'keylog' in key or 'memory' in key or 'shellcode' in key:
                categories['systems'].append(key)
            elif 'linked' in key or 'struct' in key or 'thread' in key:
                categories['data_structures'].append(key)
            elif 'buffer' in key or 'shell' in key or 'reverse' in key:
                categories['security'].append(key)

        return {k: v for k, v in categories.items() if v}
