"""
DECOMPILER WRAPPER — Escolhe o melhor motor de decompilação disponível.

Ordem de prioridade:
1. Ghidra (decompilação real, multi-arch)
2. Rizin (análise rápida)
3. Native Reconstruct (fallback)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aether_re.engines import reconstruct


def get_best_decompiler(
    ghidra_result: dict | None,
    rizin_result: dict | None,
    native_result: dict,
) -> tuple[str, dict]:
    """
    Retorna o melhor resultado de decompilação baseado em confiança e disponibilidade.

    Returns:
        (source_name, decomp_result)
    """
    sources: list[tuple[str, dict, float]] = []

    # 1) Ghidra
    if ghidra_result and ghidra_result.get("ok"):
        # Ghidra tem decompilação real
        decomp_text = _extract_ghidra_decomp(ghidra_result)
        if decomp_text:
            sources.append(("ghidra", {"text": decomp_text}, 0.95))

    # 2) Rizin
    if rizin_result and rizin_result.get("ok"):
        # Rizin tem disassembly, não decompilação real
        sources.append(("rizin", rizin_result, 0.75))

    # 3) Native Reconstruct
    if native_result.get("pseudo_source"):
        sources.append(("reconstruct", native_result, native_result.get("confidence", 0.4)))

    if not sources:
        return "none", {}

    # Escolher o de maior confiança
    best = max(sources, key=lambda x: x[2])
    return best[0], best[1]


def _extract_ghidra_decomp(ghidra_result: dict) -> str:
    """Extrai texto de decompilação do resultado Ghidra."""
    # GhidraAdapter pode retornar decompiled_path ou texto direto
    path = ghidra_result.get("decompiled_path")
    if path and Path(path).is_file():
        return Path(path).read_text(encoding="utf-8", errors="replace")

    # Ou texto direto no resultado
    return ghidra_result.get("decompiled", "")


def merge_decompilation_results(
    ghidra_result: dict | None,
    rizin_result: dict | None,
    native_result: dict,
) -> dict[str, Any]:
    """
    Mescla resultados de decompilação de múltiplas fontes em um único output estruturado.

    Útil para o Consensus Engine depois.
    """
    source, result = get_best_decompiler(ghidra_result, rizin_result, native_result)

    return {
        "best_source": source,
        "confidence": _get_confidence(source),
        "text": result.get("text", result.get("pseudo_source", "")),
        "raw": {
            "ghidra": ghidra_result.get("ok", False),
            "rizin": rizin_result.get("ok", False),
            "reconstruct": bool(native_result.get("pseudo_source")),
        },
    }


def _get_confidence(source: str) -> float:
    mapping = {
        "ghidra": 0.95,
        "rizin": 0.75,
        "reconstruct": 0.40,
        "none": 0.0,
    }
    return mapping.get(source, 0.0)
