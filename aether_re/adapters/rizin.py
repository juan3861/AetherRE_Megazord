"""Adapter Rizin/radare2 — análise estática rápida (estilo Cutter CLI)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from aether_re.adapters.base import Adapter
from aether_re.engines.ghidra_parse import normalize_address


class RizinAdapter(Adapter):
    name = "rizin"

    def available(self) -> bool:
        return self._bin() is not None

    def _bin(self) -> str | None:
        # Check common installation locations first
        candidates = [
            r"C:\Program Files\Rizin\bin\rizin.exe",
            r"C:\Program Files (x86)\Rizin\bin\rizin.exe",
        ]
        for c in candidates:
            if Path(c).is_file():
                return c
        # Fallback to PATH
        return shutil.which("rizin") or shutil.which("r2")

    def _parse_functions(self, stdout: str) -> list[dict[str, Any]]:
        """Parse Rizin JSON output for functions (from aflj command)."""
        functions = []
        # Strip ANSI escape codes first
        import re
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        clean_stdout = ansi_escape.sub('', stdout)

        # The command runs: aaa; iI; iij; iEj; aflj
        # This produces multiple JSON arrays. We want the LAST one (from aflj).
        # Find all top-level JSON arrays and take the last one.
        arrays = []
        depth = 0
        start = -1
        for i, ch in enumerate(clean_stdout):
            if ch == '[':
                if depth == 0:
                    start = i
                depth += 1
            elif ch == ']':
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start != -1:
                        arrays.append(clean_stdout[start:i+1])
                        start = -1

        # The last array should be from aflj (functions)
        if not arrays:
            return functions

        json_str = arrays[-1]
        try:
            data = json.loads(json_str)
            if isinstance(data, list):
                for item in data:
                    # Rizin aflj returns offset as a decimal integer
                    addr = item.get("offset") or item.get("addr")
                    if addr is not None:
                        # Rizin returns offset as decimal integer, convert to hex
                        if isinstance(addr, int):
                            addr_hex = f"0x{addr:x}"
                        else:
                            addr_hex = normalize_address(addr)
                        functions.append({
                            "address": addr_hex,
                            "name": item.get("name", f"sub_{addr_hex.removeprefix('0x')}"),
                            "source": "rizin",
                            "confidence": 0.85,
                            "quality": 0.80,
                            "coverage": 0.90,
                            "calls": [],
                            "imports_used": [],
                            "strings_near": [],
                            "notes": f"Rizin function, size={item.get('size', 0)}",
                            "warnings": [],
                            "raw": {
                                "realsz": item.get("realsz"),
                                "size": item.get("size"),
                                "type": item.get("type"),
                                "nbbs": item.get("nbbs"),
                                "edges": item.get("edges"),
                            }
                        })
        except json.JSONDecodeError:
            pass
        return functions

    def analyze(self, target: Path, out_dir: Path) -> dict[str, Any]:
        exe = self._bin()
        if not exe:
            return {
                "ok": False,
                "executed": False,
                "produced_evidence": False,
                "error": "rizin/r2 não encontrado no PATH",
            }

        cmd = [
            exe,
            "-q",
            "-c",
            "aaa; iI; iij; iEj; aflj",
            str(target),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            report_path = out_dir / "rizin_raw.txt"
            report_path.write_text(proc.stdout or "", encoding="utf-8", errors="replace")

            functions = self._parse_functions(proc.stdout)
            produced_evidence = proc.returncode == 0 and bool(functions)

            return {
                "ok": proc.returncode == 0,
                "executed": True,
                "produced_evidence": produced_evidence,
                "partial": proc.returncode != 0 or not produced_evidence,
                "returncode": proc.returncode,
                "functions": functions,
                "report": str(report_path),
                "stdout_tail": (proc.stdout or "")[-3000:],
                "stderr_tail": (proc.stderr or "")[-1000:],
            }
        except Exception as e:
            return {
                "ok": False,
                "executed": True,
                "produced_evidence": False,
                "error": str(e),
            }
