"""Adapter angr — análise simbólica e execução simbólica."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from aether_re.adapters.base import Adapter


class AngrAdapter(Adapter):
    name = "angr"

    def available(self) -> bool:
        try:
            import angr  # noqa: F401
            return True
        except ImportError:
            return False

    def analyze(self, target: Path, out_dir: Path) -> dict[str, Any]:
        if not self.available():
            return {
                "ok": False,
                "error": "angr não instalado (pip install angr)",
            }

        try:
            import angr
            import claripy
        except Exception as e:
            return {"ok": False, "error": f"deps angr: {e}"}

        try:
            proj = angr.Project(str(target), auto_load_libs=False)
        except Exception as e:
            return {"ok": False, "error": f"angr.Project falhou: {e}"}

        results = {
            "ok": True,
            "arch": proj.arch.name,
            "entry": hex(proj.entry),
            "analysis": {},
        }

        # Executar CFG (Control Flow Graph)
        try:
            cfg = proj.analyses.CFGFast()
            funcs = cfg.functions
            results["analysis"]["functions_count"] = len(funcs)
            results["analysis"]["functions"] = [
                {"addr": hex(f), "name": f.name}
                for f in list(funcs)[:20]
            ]
        except Exception as e:
            results["analysis"]["cfg_error"] = str(e)

        # Executar bootstrap (simular entry point)
        try:
            state = proj.factory.entry_state()
            simgr = proj.factory.simulation_manager(state)
            simgr.explore(find=0x1000, avoid=[], num_find=1, timeout=5)
            results["analysis"]["simulation"] = {
                "found": len(simgr.found) > 0,
                "visited": len(simgr.visited),
            }
        except Exception as e:
            results["analysis"]["sim_error"] = str(e)

        # Salvar resultado
        report_path = out_dir / "angr_report.json"
        import json
        report_path.write_text(json.dumps(results, indent=2, default=str))
        results["report"] = str(report_path)

        return results
