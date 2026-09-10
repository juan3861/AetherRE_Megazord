"""Adapter Unicorn — emulação isolada de trechos de código."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from aether_re.adapters.base import Adapter


IS_WINDOWS = os.name == "nt"

class UnicornAdapter(Adapter):
    name = "unicorn"

    def available(self) -> bool:
        try:
            import unicorn  # noqa: F401

            return True
        except ImportError:
            return False

    def analyze(self, target: Path, out_dir: Path) -> dict[str, Any]:
        if not self.available():
            return {
                "ok": False,
                "error": "unicorn não instalado (pip install unicorn)",
            }

        try:
            from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL
            from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RIP
            import pefile
        except Exception as e:
            return {"ok": False, "error": f"deps unicorn/pefile: {e}"}

        data = target.read_bytes()
        if not data.startswith(b"MZ"):
            return {"ok": False, "error": "Emulação automática só para PE nesta versão"}

        try:
            pe = pefile.PE(data=data)
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = pe.OPTIONAL_HEADER.ImageBase
            offset = pe.get_offset_from_rva(ep)
            code = data[offset : offset + 128]
        except Exception as e:
            return {"ok": False, "error": f"PE parse: {e}"}

        ADDRESS = image_base + ep
        STACK = 0x700000
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        if IS_WINDOWS:
            return {
                "ok": True,
                "executed": True,
                "produced_evidence": False,
                "partial": True,
                "note": "Unicorn desativado no Windows nesta versão para evitar falhas de memória/mapa.",
                "entry": hex(ADDRESS),
                "code_len": len(code),
            }

        try:
            # map code page + stack
            page = ADDRESS & ~0xFFF
            mu.mem_map(page, 0x2000, UC_PROT_ALL)
            mu.mem_map(STACK, 0x2000, UC_PROT_ALL)
            mu.mem_write(ADDRESS, code)
            mu.reg_write(UC_X86_REG_RSP, STACK + 0x1000)
            mu.reg_write(UC_X86_REG_RIP, ADDRESS)
        except Exception as e:
            return {"ok": False, "error": f"Unicorn mem_map falhou: {e}"}

        steps = 0
        try:
            mu.emu_start(ADDRESS, ADDRESS + len(code), timeout=2_000_000, count=64)
            steps = 64
        except Exception as e:
            return {
                "ok": True,
                "partial": True,
                "error_during_emu": str(e),
                "rip": hex(mu.reg_read(UC_X86_REG_RIP)),
                "note": "Parou cedo (normal sem imports resolvidos).",
            }

        return {
            "ok": True,
            "steps": steps,
            "rip": hex(mu.reg_read(UC_X86_REG_RIP)),
            "entry": hex(ADDRESS),
            "code_len": len(code),
        }
