"""Consenso por função e calibração de confiança do AetherRE."""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations
from typing import Any

from aether_re.models import Finding, FunctionConsensus, FunctionEvidence


SOURCE_WEIGHTS = {
    "ghidra": 0.35,
    "rizin": 0.20,
    "angr": 0.15,
    "binaryninja": 0.20,
    "native": 0.10,
}


def normalize_address(value: object, base_addr: int = 0) -> str:
    if value is None:
        return ""
    # If already an integer, format as hex
    if isinstance(value, int):
        return f"0x{value:x}"
    raw = str(value).strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not raw:
        return ""
    try:
        # Just normalize hex format, don't adjust for base address
        # All adapter addresses are already virtual addresses
        addr = int(raw, 16)
        return f"0x{addr:x}"
    except ValueError:
        return ""


def _sets(values: list[str]) -> set[str]:
    return {str(value).strip().lower() for value in values if str(value).strip()}


def _jaccard(left: list[str], right: list[str]) -> float:
    a = _sets(left)
    b = _sets(right)
    if not a and not b:
        return 0.5
    union = a | b
    return len(a & b) / len(union) if union else 0.5


def _source_agreement(left: FunctionEvidence, right: FunctionEvidence) -> float:
    call_score = _jaccard(left.calls, right.calls)
    import_score = _jaccard(left.imports_used, right.imports_used)
    left_name = left.name.lower()
    right_name = right.name.lower()
    name_score = (
        1.0
        if left_name == right_name
        or left_name in right_name
        or right_name in left_name
        or left_name.startswith("fun_")
        or right_name.startswith("fun_")
        else 0.25
    )
    return round(0.5 * call_score + 0.2 * import_score + 0.3 * name_score, 4)


def merge_function_evidence(
    evidence_items: list[FunctionEvidence],
    successful_sources: list[str] | None = None,
    base_addr: int = 0,
) -> list[FunctionConsensus]:
    grouped: dict[str, list[FunctionEvidence]] = defaultdict(list)
    for item in evidence_items:
        address = normalize_address(item.address, base_addr)
        if address:
            grouped[address].append(item)

    # Use all possible sources from SOURCE_WEIGHTS for coverage denominator
    source_universe = set(SOURCE_WEIGHTS.keys())
    denominator = max(len(source_universe), 1)
    merged: list[FunctionConsensus] = []

    for address in sorted(grouped, key=lambda value: int(value, 16)):
        items = grouped[address]
        items.sort(
            key=lambda item: (
                -SOURCE_WEIGHTS.get(item.source, 0.1),
                -item.confidence,
                -item.quality,
            )
        )
        selected = items[0]
        total_weight = sum(SOURCE_WEIGHTS.get(item.source, 0.1) for item in items)
        weighted_confidence = sum(
            item.confidence * SOURCE_WEIGHTS.get(item.source, 0.1) for item in items
        ) / total_weight
        weighted_quality = sum(
            item.quality * SOURCE_WEIGHTS.get(item.source, 0.1) for item in items
        ) / total_weight
        agreement_values = [
            _source_agreement(left, right)
            for left, right in combinations(items, 2)
        ]
        agreement = sum(agreement_values) / len(agreement_values) if agreement_values else 1.0
        # Coverage: proportion of source_universe that contributed evidence to this function
        coverage = len({item.source for item in items}) / denominator

        score = 0.65 * weighted_confidence + 0.25 * agreement + 0.10 * coverage
        if len(items) == 1:
            score = min(score, 0.92)
        elif len(items) == 2:
            score = min(score, 0.96)
        else:
            score = min(score, 0.98)

        aliases = sorted({item.name for item in items})
        names = {item.name.lower() for item in items}
        warnings: list[str] = []
        if len(items) == 1:
            warnings.append("Função observada por apenas uma fonte; não há corroboração independente.")
        if len(names) > 1:
            warnings.append("As fontes atribuem nomes diferentes à mesma função.")
        for item in items:
            warnings.extend(f"[{item.source}] {warning}" for warning in item.warnings)

        merged.append(
            FunctionConsensus(
                address=address,
                name=selected.name,
                aliases=aliases,
                confidence=round(max(0.0, min(score, 1.0)), 4),
                evidence_quality=round(weighted_quality, 4),
                source_agreement=round(agreement, 4),
                coverage=round(coverage, 4),
                selected_source=selected.source,
                fallback_used=selected.source not in {"ghidra", "rizin", "angr"},
                pseudocode=selected.pseudocode,
                disassembly=selected.disassembly,
                calls=sorted({call for item in items for call in item.calls}),
                imports_used=sorted({imp for item in items for imp in item.imports_used}),
                strings_near=sorted({value for item in items for value in item.strings_near}),
                sources=sorted({item.source for item in items}),
                warnings=list(dict.fromkeys(warnings)),
                evidence={
                    item.source: item.to_dict()
                    for item in sorted(items, key=lambda value: value.source)
                },
            )
        )
    return merged


def compute_overall_confidence(
    merged_functions: list[FunctionConsensus],
    native_confidence: float,
    successful_sources: list[str] | None = None,
    failed_sources: list[str] | None = None,
) -> tuple[float, dict[str, Any]]:
    if merged_functions:
        function_confidence = sum(
            function.confidence * max(function.coverage, 0.1)
            for function in merged_functions
        ) / sum(max(function.coverage, 0.1) for function in merged_functions)
        average_coverage = sum(function.coverage for function in merged_functions) / len(
            merged_functions
        )
        average_quality = sum(
            function.evidence_quality * max(function.coverage, 0.1)
            for function in merged_functions
        ) / sum(max(function.coverage, 0.1) for function in merged_functions)
        structure_weight = 0.15
        function_weight = 0.70
        coverage_weight = 0.15
        overall = (
            function_weight * function_confidence
            + structure_weight * float(native_confidence)
            + coverage_weight * average_coverage
        )
    else:
        function_confidence = 0.0
        average_coverage = 0.0
        average_quality = 0.0
        overall = min(float(native_confidence), 0.65)

    successful = sorted(set(successful_sources or []))
    failed = sorted(set(failed_sources or []))
    rationale = {
        "method": "function-weighted ensemble",
        "successful_function_sources": successful,
        "unavailable_or_failed_sources": failed,
        "function_count": len(merged_functions),
        "function_confidence": round(function_confidence, 4),
        "mean_function_coverage": round(average_coverage, 4),
        "mean_evidence_quality": round(average_quality, 4),
        "native_structure_confidence": round(float(native_confidence), 4),
        "weights": {
            "functions": 0.70 if merged_functions else 0.0,
            "native_structure": 0.15 if merged_functions else 0.70,
            "coverage": 0.15 if merged_functions else 0.0,
        },
    }
    return round(max(0.0, min(overall, 1.0)), 4), rationale


def merge_findings(
    ghidra_findings: list[Finding],
    rizin_findings: list[Finding],
    native_findings: list[Finding],
) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for finding in [*native_findings, *(ghidra_findings or []), *(rizin_findings or [])]:
        key = f"{finding.title}:{finding.severity}"
        if key not in seen or finding.confidence > seen[key].confidence:
            seen[key] = finding
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(seen.values(), key=lambda item: (severity_order.get(item.severity, 5), -item.confidence))


def weighted_vote(items: list[dict[str, Any]], weight_key: str = "confidence") -> Any:
    return max(items, key=lambda item: item.get(weight_key, 0.5)) if items else None


def merge_function_signatures(
    ghidra_funcs: list[dict[str, Any]],
    rizin_funcs: list[dict[str, Any]],
    reconstruct_sketches: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    evidence: list[FunctionEvidence] = []
    for source, items in (("ghidra", ghidra_funcs), ("rizin", rizin_funcs)):
        for item in items:
            evidence.append(FunctionEvidence(**item))
    for sketch in reconstruct_sketches:
        address = normalize_address(sketch.get("address"))
        if address:
            evidence.append(
                FunctionEvidence(
                    address=address,
                    name=sketch.get("name", f"sub_{address.removeprefix('0x')}"),
                    source="native",
                    confidence=float(sketch.get("confidence", 0.3)),
                    quality=0.3,
                    coverage=0.25,
                    notes=str(sketch.get("notes", "")),
                    imports_used=list(sketch.get("imports_used", [])),
                    strings_near=list(sketch.get("strings_near", [])),
                )
            )
    return [item.to_dict() for item in merge_function_evidence(evidence, ["ghidra", "rizin"])]
