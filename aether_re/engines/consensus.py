"""
CONSENSUS ENGINE — O cérebro que une resultados de múltiplos motores.
Vota no melhor resultado baseado em confiança, cobertura e redundância.

Ensemble: Ghidra + Rizin + Capstone + Reconstruct + (futuro: Binary Ninja, angr)
"""

from __future__ import annotations

from typing import Any

from aether_re.models import Finding


def weighted_vote(items: list[dict[str, Any]], weight_key: str = "confidence") -> Any:
    """Vota no item com maior confiança ponderada."""
    if not items:
        return None

    best = max(items, key=lambda x: x.get(weight_key, 0.5))
    return best


def merge_function_signatures(
    ghidra_funcs: list[dict],
    rizin_funcs: list[dict],
    reconstruct_sketches: list[dict],
) -> list[dict[str, Any]]:
    """
    Une funções de múltiplas fontes.

    Prioridade: Ghidra > Rizin > Reconstruct
    Ghidra tem decompilação real, então tem peso maior.
    """
    merged: dict[str, dict] = {}  # key = address

    # Processar Ghidra (maior prioridade)
    for func in ghidra_funcs:
        addr = func.get("address", "")
        merged[addr] = {
            "address": addr,
            "name": func.get("name", f"func_{addr}"),
            "decompiled": func.get("decompiled", ""),
            "signature": func.get("signature", ""),
            "confidence": 0.95,
            "source": "ghidra",
        }

    # Mesclar Rizin
    for func in rizin_funcs:
        addr = func.get("address", "")
        if addr in merged:
            # Já existe do Ghidra — melhorar se Rizin tem mais info
            if func.get("calls"):
                merged[addr]["rizin_calls"] = func["calls"]
        else:
            merged[addr] = {
                "address": addr,
                "name": func.get("name", f"func_{addr}"),
                "disasm": func.get("disasm", ""),
                "confidence": 0.75,
                "source": "rizin",
            }

    # Mesclar Reconstruct (menor prioridade)
    for sketch in reconstruct_sketches:
        addr = sketch.get("address", "")
        if addr in merged:
            merged[addr]["reconstruct_notes"] = sketch.get("notes", "")
        else:
            merged[addr] = {
                "address": addr,
                "name": sketch.get("name", f"func_{addr}"),
                "role": sketch.get("role", "unknown"),
                "confidence": 0.40,
                "source": "reconstruct",
            }

    return list(merged.values())


def merge_findings(
    ghidra_findings: list[Finding],
    rizin_findings: list[Finding],
    native_findings: list[Finding],
) -> list[Finding]:
    """
    Une findings de múltiplas fontes, removendo duplicatas.

    Usa título + severidade como chave de dedup.
    """
    seen: dict[str, Finding] = {}

    all_findings = [
        *native_findings,
        *(ghidra_findings or []),
        *(rizin_findings or []),
    ]

    for f in all_findings:
        key = f"{f.title}:{f.severity}"
        if key not in seen:
            seen[key] = f
        else:
            # Se já existe, manter o de maior confiança
            if f.confidence > seen[key].confidence:
                seen[key] = f

    # Ordenar por severidade: critical > high > medium > low > info
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        seen.values(),
        key=lambda x: (severity_order.get(x.severity, 5), -x.confidence)
    )

    return sorted_findings


def compute_overall_confidence(
    ghidra_available: bool,
    rizin_available: bool,
    capstone_available: bool,
    native_confidence: float,
) -> float:
    """
    Calcula confiança geral baseada em quais ferramentas estão disponíveis.

   weights:
    - Ghidra: 0.40 (decompilação real)
    - Rizin: 0.25 (análise estática)
    - Capstone: 0.15 (disasm)
    - Native: 0.20 (strings/decode)
    """
    weights = {
        "ghidra": 0.40,
        "rizin": 0.25,
        "capstone": 0.15,
        "native": 0.20,
    }

    total = 0.0
    divisor = 0.0

    if ghidra_available:
        total += weights["ghidra"]
        divisor += weights["ghidra"]

    if rizin_available:
        total += weights["rizin"]
        divisor += weights["rizin"]

    if capstone_available:
        total += weights["capstone"]
        divisor += weights["capstone"]

    # Native sempre disponível
    total += weights["native"] * native_confidence
    divisor += weights["native"]

    if divisor == 0:
        return 0.0

    return total / divisor


def build_ensemble_report(
    ghidra_result: dict | None,
    rizin_result: dict | None,
    native_result: dict,
    capstone_available: bool,
) -> dict[str, Any]:
    """
    Monta relatório ensemble final com consenso.
    """
    # Calcular confiança baseada em quais ferramentas estão disponíveis
    confidence = compute_overall_confidence(
        ghidra_available=ghidra_result.get("ok", False) if ghidra_result else False,
        rizin_available=rizin_result.get("ok", False) if rizin_result else False,
        capstone_available=capstone_available,
        native_confidence=native_result.get("confidence", 0.5),
    )

    # Fundir functions
    merged_funcs = merge_function_signatures(
        ghidra_funcs=ghidra_result.get("functions", []) if ghidra_result else [],
        rizin_funcs=rizin_result.get("functions", []) if rizin_result else [],
        reconstruct_sketches=native_result.get("function_sketches", []),
    )

    # Fundir findings
    merged_findings = merge_findings(
        ghidra_findings=[],  # GhidraAdapter já retorna findings formatados
        rizin_findings=[],
        native_findings=native_result.get("findings", []),
    )

    return {
        "confidence": confidence,
        "engines_used": _list_engines(ghidra_result, rizin_result),
        "merged_functions": merged_funcs,
        "merged_findings": merged_findings,
        "sources": {
            "ghidra": ghidra_result.get("ok", False) if ghidra_result else False,
            "rizin": rizin_result.get("ok", False) if rizin_result else False,
            "native": True,
        },
    }


def _list_engines(ghidra: dict | None, rizin: dict | None) -> list[str]:
    engines = ["triage", "structure", "strings_decode", "disasm", "reconstruct"]
    if ghidra and ghidra.get("ok"):
        engines.append("ghidra")
    if rizin and rizin.get("ok"):
        engines.append("rizin")
    return engines
