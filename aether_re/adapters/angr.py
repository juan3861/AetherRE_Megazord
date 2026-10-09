"""Adapter angr — CFG e evidências estáticas de controle de fluxo."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aether_re.adapters.base import Adapter
from aether_re.engines.consensus import normalize_address


def _call_targets(cfg: Any, function: Any, address: int) -> tuple[list[str], int]:
    """Return resolved function-call targets and unresolved callsite count.

    ``transition_graph.nodes()`` contains basic-block nodes, not callee
    functions; using it as a call list silently produced empty/incorrect
    evidence. Prefer angr's callsite API and fall back to the CFG callgraph
    when a version does not expose it. No target code is executed here.
    """
    targets: set[int] = set()
    unresolved = 0
    try:
        callsites = list(function.get_call_sites())
    except Exception:
        raw_sites = getattr(function, "callout_sites", [])
        callsites = list(raw_sites) if raw_sites else []
    for site in callsites:
        try:
            target = function.get_call_target(site)
        except Exception:
            target = None
        if hasattr(target, "addr"):
            target = target.addr
        if isinstance(target, int):
            targets.add(target)
        else:
            unresolved += 1
    if not targets:
        graph = getattr(cfg, "callgraph", None)
        if graph is None:
            manager = getattr(cfg, "functions", None)
            graph = getattr(manager, "callgraph", None)
        try:
            if graph is not None and graph.has_node(address):
                targets.update(int(item) for item in graph.successors(address) if isinstance(item, int))
        except Exception:
            pass
    return [normalize_address(item) for item in sorted(targets)], unresolved


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
                "available": False,
                "executed": False,
                "produced_evidence": False,
                "partial": False,
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

        proj = None
        try:
            proj = angr.Project(str(target), auto_load_libs=False)
            cfg = proj.analyses.CFGFast(
                normalize=True,
                data_references=True,
                resolve_indirect_jumps=True,
            )
            functions = []
            unresolved_calls = 0
            for addr, function in sorted(cfg.functions.items()):
                calls, unresolved = _call_targets(cfg, function, addr)
                unresolved_calls += unresolved
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
                        "unresolved_call_sites": unresolved,
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
                    "resolved_call_targets": sum(len(item.get("calls", [])) for item in functions),
                    "unresolved_call_sites": unresolved_calls,
                    "call_extraction": "function_callsite_api_or_cfg_callgraph",
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

        if proj is not None:
            try:
                proj.kb.rtdb.cleanup()
                results["runtime_database"] = "closed"
            except Exception as cleanup_error:
                results["runtime_database"] = "cleanup_failed"
                results["cleanup_error"] = cleanup_error.__class__.__name__
                results["partial"] = True
                results["ok"] = False

        report_path = out_dir / "angr_report.json"
        report_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        results["report"] = str(report_path)
        return results
