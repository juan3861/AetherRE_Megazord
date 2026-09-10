"""Adapter angr — CFG e evidências estáticas de controle de fluxo."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aether_re.adapters.base import Adapter
from aether_re.engines.consensus import normalize_address


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
                "executed": False,
                "produced_evidence": False,
                "error": "angr não instalado",
            }

        try:
            import angr
        except Exception as e:
            return {
                "ok": False,
                "executed": False,
                "produced_evidence": False,
                "error": f"deps angr: {e}",
            }

        try:
            proj = angr.Project(str(target), auto_load_libs=False)
            cfg = proj.analyses.CFGFast(
                normalize=True,
                data_references=True,
                resolve_indirect_jumps=True,
            )
            functions = []
            for addr, function in sorted(cfg.functions.items()):
                calls = sorted(
                    {
                        normalize_address(callee)
                        for callee in function.transition_graph.nodes()
                        if isinstance(callee, int)
                    }
                )
                blocks = [
                    {
                        "address": normalize_address(block.addr),
                        "size": block.size,
                    }
                    for block in function.blocks
                ]
                functions.append(
                    {
                        "address": normalize_address(addr),
                        "name": function.name or f"sub_{addr:x}",
                        "source": "angr",
                        "confidence": 0.82,
                        "quality": 0.75,
                        "coverage": min(1.0, len(blocks) / 3.0 + 0.2),
                        "disassembly": function.__str__(),
                        "calls": calls,
                        "notes": "CFGFast function",
                        "warnings": [],
                        "raw": {
                            "blocks": blocks,
                            "is_simprocedure": function.is_simprocedure,
                        },
                    }
                )
            results = {
                "ok": True,
                "executed": True,
                "produced_evidence": bool(functions),
                "partial": not bool(functions),
                "arch": proj.arch.name,
                "entry": normalize_address(proj.entry),
                "functions": functions,
                "analysis": {
                    "functions_count": len(functions),
                    "cfg": "CFGFast",
                },
                "note": "CFG estática; sem execução simbólica automática do alvo.",
            }
        except Exception as e:
            results = {
                "ok": False,
                "executed": True,
                "produced_evidence": False,
                "error": f"angr CFG falhou: {e}",
            }

        report_path = out_dir / "angr_report.json"
        report_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        results["report"] = str(report_path)
        return results
