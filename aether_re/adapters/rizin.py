"""Adapter Rizin/radare2 — análise estática rápida (estilo Cutter CLI)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from aether_re.adapters.base import Adapter


class RizinAdapter(Adapter):
    name = "rizin"

    def available(self) -> bool:
        return shutil.which("rizin") is not None or shutil.which("r2") is not None

    def _bin(self) -> str | None:
        return shutil.which("rizin") or shutil.which("r2")

    def analyze(self, target: Path, out_dir: Path) -> dict[str, Any]:
        exe = self._bin()
        if not exe:
            return {"ok": False, "error": "rizin/r2 não encontrado no PATH"}

        # iI = info, iij = imports json, iE = exports, afl = functions, pd 40 @ entry
        cmd = [
            exe,
            "-q",
            "-c",
            "aaa; iI; iij; iEj; aflj; s entry0; pd 30",
            str(target),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            report_path = out_dir / "rizin_raw.txt"
            report_path.write_text(proc.stdout or "", encoding="utf-8", errors="replace")
            return {
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "report": str(report_path),
                "stdout_tail": (proc.stdout or "")[-3000:],
                "stderr_tail": (proc.stderr or "")[-1000:],
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}
