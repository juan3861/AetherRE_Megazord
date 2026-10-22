"""Reverse Engineering Graph (AetherRE) — Production angr-Powered Binary Decompiler & IR Lifter.

Provides:
  1. Real binary loading and normalized CFG generation via angr.
  2. Architecture-agnostic VEX Intermediate Representation (IR) lifting.
  3. Real structured C code generation from compiled PE / ELF binaries.
  4. Variable and calling convention recovery.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Sequence

import angr


class RealBinaryDecompiler:
    """Production binary lifter and decompiler backed by angr."""

    def __init__(self, binary_path: str | Path, *, auto_load_libs: bool = False):
        self.binary_path = Path(binary_path).resolve()
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")

        self.project = angr.Project(str(self.binary_path), auto_load_libs=auto_load_libs)
        self.cfg: Any = None
        self._analyzed = False

    def build_cfg(self, *, normalize: bool = True) -> int:
        """Constructs a normalized control flow graph for decompilation."""
        self.cfg = self.project.analyses.CFGFast(normalize=normalize)
        self._analyzed = True
        return len(self.cfg.kb.functions)

    def list_functions(self) -> list[dict[str, Any]]:
        """Returns all functions discovered by the CFG."""
        if not self._analyzed:
            self.build_cfg()

        funcs = []
        for addr, fn in self.cfg.kb.functions.items():
            funcs.append({
                "name": fn.name,
                "address": hex(addr),
                "size_bytes": fn.size,
                "is_simprocedure": fn.is_simprocedure,
                "has_return": fn.has_return,
                "num_blocks": len(fn.block_addrs_set),
            })
        return funcs

    def lift_block_to_vex(self, addr: int) -> dict[str, Any]:
        """Lifts machine code at the given address to VEX Intermediate Representation."""
        block = self.project.factory.block(addr)
        vex = block.vex
        statements = [str(st) for st in vex.statements]
        return {
            "address": hex(addr),
            "size_bytes": block.size,
            "instruction_count": block.instructions,
            "vex_statements_count": len(statements),
            "statements": statements,
            "jumpkind": str(vex.jumpkind),
        }

    def decompile_function(self, func_name_or_addr: str | int) -> dict[str, Any]:
        """Runs the angr structured C decompiler on a function."""
        if not self._analyzed:
            self.build_cfg(normalize=True)

        func = None
        if isinstance(func_name_or_addr, int):
            func = self.cfg.kb.functions.get(func_name_or_addr)
        elif isinstance(func_name_or_addr, str):
            if func_name_or_addr.startswith("0x"):
                addr = int(func_name_or_addr, 16)
                func = self.cfg.kb.functions.get(addr)
            else:
                func = self.cfg.kb.functions.function(name=func_name_or_addr)

        if not func:
            raise ValueError(f"Function {func_name_or_addr} not found in binary")

        t0 = time.perf_counter()
        dec = self.project.analyses.Decompiler(func, cfg=self.cfg.model)
        elapsed_sec = round(time.perf_counter() - t0, 3)

        c_code = dec.codegen.text if dec.codegen else ""
        return {
            "function_name": func.name,
            "address": hex(func.addr),
            "decompiled_c": c_code,
            "decompilation_time_sec": elapsed_sec,
            "has_c_output": bool(c_code),
            "c_lines_count": len(c_code.splitlines()) if c_code else 0,
        }
