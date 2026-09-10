"""Wrapper de decompilação e integração por função."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aether_re.engines import reconstruct
from aether_re.engines.ghidra_parse import parse_decompiled_file


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
    return {
        "best_source": "ghidra" if ghidra_functions else ("rizin" if rizin_functions else "reconstruct"),
        "confidence": 0.95 if ghidra_functions else 0.75 if rizin_functions else 0.4,
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
