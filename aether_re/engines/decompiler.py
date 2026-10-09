"""Wrapper de decompilação e integração por função."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from aether_re.engines import reconstruct
from aether_re.engines.ghidra_parse import parse_decompiled_file


GHIDRA_PARTIAL_CONFIDENCE_CAP = 0.80


def ghidra_result_is_complete(ghidra_result: dict[str, Any] | None) -> bool:
    """Return true only for an explicitly complete Ghidra export contract."""
    if not isinstance(ghidra_result, dict):
        return False
    attempted = ghidra_result.get("attempted_functions")
    exported = ghidra_result.get("exported_functions")
    failed = ghidra_result.get("failed_functions")
    limit = ghidra_result.get("max_functions")
    returncode = ghidra_result.get("returncode")
    return (
        ghidra_result.get("ok") is True
        and ghidra_result.get("produced_evidence") is True
        and ghidra_result.get("partial") is False
        and ghidra_result.get("extraction_status") == "complete"
        and ghidra_result.get("truncated") is False
        and type(returncode) is int
        and returncode == 0
        and ghidra_result.get("timed_out") is False
        and ghidra_result.get("resource_exceeded") is False
        and type(attempted) is int
        and attempted > 0
        and type(exported) is int
        and exported >= 0
        and type(failed) is int
        and failed == 0
        and type(limit) is int
        and limit > 0
        and attempted == exported + failed
        and exported <= limit
    )


def mark_ghidra_functions_partial(
    functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Preserve partial function evidence while capping certainty and labeling loss."""
    marked: list[dict[str, Any]] = []
    warning = "Ghidra export is partial or lacks an explicit complete summary."
    for function in functions:
        if not isinstance(function, dict):
            continue
        item = dict(function)
        try:
            confidence = float(item.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        if not math.isfinite(confidence):
            confidence = 0.0
        item["confidence"] = min(max(confidence, 0.0), GHIDRA_PARTIAL_CONFIDENCE_CAP)
        item["partial"] = True
        warnings = item.get("warnings", [])
        if isinstance(warnings, str):
            warnings = [warnings]
        elif not isinstance(warnings, list):
            warnings = []
        item["warnings"] = list(dict.fromkeys([*warnings, warning]))
        marked.append(item)
    return marked


def _extract_ghidra_evidence(ghidra_result: dict[str, Any]) -> list[dict[str, Any]]:
    path = ghidra_result.get("decompiled_path")
    if path and Path(path).is_file():
        return parse_decompiled_file(Path(path))
    return ghidra_result.get("functions", [])


def _extract_rizin_evidence(rizin_result: dict[str, Any]) -> list[dict[str, Any]]:
    return rizin_result.get("functions", [])


def _extract_angr_evidence(angr_result: dict[str, Any]) -> list[dict[str, Any]]:
    return angr_result.get("functions", [])


def merge_decompilation_results(
    ghidra_result: dict[str, Any] | None,
    rizin_result: dict[str, Any] | None,
    native_result: dict[str, Any],
    angr_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ghidra_functions = _extract_ghidra_evidence(ghidra_result or {})
    ghidra_complete = ghidra_result_is_complete(ghidra_result)
    if ghidra_functions and not ghidra_complete:
        ghidra_functions = mark_ghidra_functions_partial(ghidra_functions)
    rizin_functions = _extract_rizin_evidence(rizin_result or {})
    angr_functions = _extract_angr_evidence(angr_result or {})
    sketches = native_result.get("function_sketches", [])
    source_counts = {
        "ghidra": len(ghidra_functions),
        "rizin": len(rizin_functions),
        "angr": len(angr_functions),
        "native": len(sketches),
    }
    functions = [
        *ghidra_functions,
        *rizin_functions,
        *angr_functions,
        *[
            {
                "address": getattr(sketch, "address", ""),
                "name": getattr(sketch, "name", "unknown"),
                "source": "native",
                "confidence": float(getattr(sketch, "confidence", 0.3)),
                "quality": 0.3,
                "coverage": 0.25,
                "notes": getattr(sketch, "notes", ""),
                "imports_used": list(getattr(sketch, "imports_used", [])),
                "strings_near": list(getattr(sketch, "strings_near", [])),
            }
            for sketch in sketches
            if getattr(sketch, "address", "") not in {"", None, "unknown", "export"}
        ],
    ]
    best_source = (
        "ghidra" if ghidra_functions and ghidra_complete
        else "rizin" if rizin_functions
        else "reconstruct"
    )
    partial_sources = ["ghidra"] if ghidra_functions and not ghidra_complete else []
    return {
        "best_source": best_source,
        "confidence": 0.95 if best_source == "ghidra" else 0.75 if best_source == "rizin" else 0.4,
        "partial": bool(partial_sources),
        "partial_sources": partial_sources,
        "text": native_result.get("pseudo_source", ""),
        "functions": functions,
        "source_counts": source_counts,
        "raw": {
            "ghidra": bool(ghidra_result and ghidra_result.get("ok")),
            "rizin": bool(rizin_result and rizin_result.get("ok")),
            "angr": bool(angr_result and angr_result.get("ok")),
            "reconstruct": bool(native_result.get("pseudo_source")),
        },
    }


def get_best_decompiler(
    ghidra_result: dict[str, Any] | None,
    rizin_result: dict[str, Any] | None,
    native_result: dict[str, Any],
    angr_result: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    merged = merge_decompilation_results(
        ghidra_result,
        rizin_result,
        native_result,
        angr_result,
    )
    return merged["best_source"], merged


def _get_confidence(source: str) -> float:
    mapping = {"ghidra": 0.95, "rizin": 0.75, "reconstruct": 0.4, "none": 0.0}
    return mapping.get(source, 0.0)
