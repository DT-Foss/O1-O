"""
Native Engine — Direct Binary & Hardware Mastery
Handles GCC, NASM, and ELF/Mach-O manipulation.
"""
# Dependencies: none
# Depended by: none (leaf module)


import subprocess
import os
from pathlib import Path
from typing import Dict, Any, Optional, List

class NativeEngine:
    """Specialized engine for native code (C, ASM, Verilog)"""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def compile_c(self, source_code: str, module_name: str) -> Optional[Path]:
        """Compile C source to shared library"""
        source_path = self.output_dir / f"{module_name}.c"
        source_path.write_text(source_code)
        
        output_path = self.output_dir / f"{module_name}.so"
        
        # Determine platform-specific Python include paths
        try:
            python_include = subprocess.check_output(
                ["python3-config", "--includes"], text=True
            ).strip().split()
        except:
            python_include = ["-I/usr/include/python3.13"]

        cmd = ["gcc", "-shared", "-o", str(output_path), "-fPIC"] + python_include + [str(source_path)]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return output_path
        except subprocess.CalledProcessError as e:
            print(f"❌ C Compilation failed: {e.stderr.decode()}")
            return None

    def assemble_nasm(self, asm_code: str, output_name: str) -> Optional[Path]:
        """Assemble NASM x86_64 source"""
        source_path = self.output_dir / f"{output_name}.asm"
        source_path.write_text(asm_code)
        
        obj_path = self.output_dir / f"{output_name}.o"
        bin_path = self.output_dir / output_name
        
        try:
            # Assemble
            subprocess.run(["nasm", "-f", "elf64", str(source_path), "-o", str(obj_path)], check=True)
            # Link
            subprocess.run(["ld", str(obj_path), "-o", str(bin_path)], check=True)
            return bin_path
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"❌ ASM Assembly/Linking failed: {e}")
            return None

    def patch_binary(self, binary_path: str, patch_data: Dict[str, Any]) -> bool:
        """Apply patches to existing binary via LIEF (if available)"""
        try:
            import lief
            binary = lief.parse(binary_path)
            
            # Example: Rename section
            if 'rename_section' in patch_data:
                old, new = patch_data['rename_section']
                section = binary.get_section(old)
                if section:
                    section.name = new
            
            binary.write(binary_path)
            return True
        except ImportError:
            print("⚠️ LIEF not installed. Binary patching unavailable.")
            return False
        except Exception as e:
            print(f"❌ Patching failed: {e}")
            return False
