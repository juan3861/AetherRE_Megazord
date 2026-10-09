"""Correlação conservadora fonte↔binário, sempre marcada como heurística."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def _leaf(name: object) -> str:
    value = str(name or "").strip().lower()
    value = value.removeprefix("fun_").removeprefix("sub_")
    # ELF symbol version suffixes are metadata, not part of the source name.
    value = re.split(r"@@?", value, maxsplit=1)[0]
    return re.split(r"[.:$]", value)[-1]


def _build_units_for_source(source: dict[str, Any], units: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Link source metadata to declared compilation units without changing confidence."""
    candidates = [
        str(source.get("file") or ""),
        str(source.get("path") or ""),
        str(source.get("module") or ""),
    ]
    qualified = str(source.get("qualified_name") or "")
    if ":" in qualified:
        candidates.append(qualified.split(":", 1)[0])
    normalized = [item.replace("\\", "/").strip("/").lower() for item in candidates if item]
    if not normalized:
        return []
    linked: list[dict[str, Any]] = []
    for unit in units:
        raw_file = str(unit.get("file") or "").replace("\\", "/").strip("/").lower()
        if not raw_file:
            continue
        raw_name = raw_file.rsplit("/", 1)[-1]
        if any(value == raw_file or value.endswith("/" + raw_file) or value == raw_name or value.endswith("/" + raw_name) for value in normalized):
            linked.append(unit)
    return linked


def _invalid_report(errors: list[dict[str, Any]], *, source_count: int = 0, binary_count: int = 0) -> dict[str, Any]:
    return {
        "schema": "source-binary-correlation.v1",
        "status": "invalid",
        "matches": [],
        "summary": {"source_functions": source_count, "binary_functions": binary_count, "candidate": 0, "ambiguous": 0, "unmatched": 0},
        "errors": errors,
        "limitations": ["entrada inválida não é convertida em candidatos", "nome igual não prova equivalência", "validação exige símbolos, build ou trace independente"],
    }


def correlate_source_to_binary(
    source_functions: list[dict[str, Any]],
    binary_functions: list[dict[str, Any]],
    *,
    build_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Gera candidatos por símbolo; não afirma equivalência sem debug/trace."""
    if not isinstance(source_functions, list) or not isinstance(binary_functions, list):
        return _invalid_report(
            [{"code": "source_and_binary_functions_must_be_lists"}],
            source_count=len(source_functions) if isinstance(source_functions, list) else 0,
            binary_count=len(binary_functions) if isinstance(binary_functions, list) else 0,
        )
    errors: list[dict[str, Any]] = []
    for index, source in enumerate(source_functions):
        if not isinstance(source, dict):
            errors.append({"side": "source", "index": index, "code": "function_not_object"})
            continue
        if not any(isinstance(source.get(field), str) and source.get(field).strip() for field in ("qualified_name", "name")):
            errors.append({"side": "source", "index": index, "code": "function_name_missing"})
    for index, binary in enumerate(binary_functions):
        if not isinstance(binary, dict):
            errors.append({"side": "binary", "index": index, "code": "function_not_object"})
            continue
        if not isinstance(binary.get("name"), str) or not binary.get("name", "").strip():
            errors.append({"side": "binary", "index": index, "code": "function_name_missing"})
    if build_report is not None and not isinstance(build_report, dict):
        errors.append({"side": "build", "code": "build_report_must_be_object"})
    if isinstance(build_report, dict) and "compile_commands" in build_report and not isinstance(build_report.get("compile_commands"), list):
        errors.append({"side": "build", "code": "compile_commands_must_be_list"})
    if errors:
        return _invalid_report(errors, source_count=len(source_functions), binary_count=len(binary_functions))
    index: dict[str, list[dict[str, Any]]] = {}
    elf_symbols_seen: set[tuple[str, str]] = set()
    for binary in binary_functions:
        raw_name = str(binary.get("name") or "").strip().lower()
        if raw_name.startswith(("fun_", "sub_")):
            continue
        key = _leaf(raw_name)
        if key:
            source = binary.get("source") or ("elf-symbol" if "value" in binary else "")
            address = str(binary.get("address") or binary.get("value", ""))
            # .dynsym and .symtab often repeat the same ELF symbol.  They are
            # one artifact observation, not two independent candidates; retain
            # true ambiguity when addresses or producers differ.
            if source == "elf-symbol":
                identity = (key, address)
                if identity in elf_symbols_seen:
                    continue
                elf_symbols_seen.add(identity)
            index.setdefault(key, []).append(binary)
    compile_units = []
    if isinstance(build_report, dict) and isinstance(build_report.get("compile_commands"), list):
        compile_units = [item for item in build_report["compile_commands"] if isinstance(item, dict)]
    matches: list[dict[str, Any]] = []
    for source in source_functions:
        source_name = source.get("qualified_name") or source.get("name")
        key = _leaf(source_name)
        candidates = index.get(key, [])
        if len(candidates) == 1:
            status = "candidate"
        elif candidates:
            status = "ambiguous"
        else:
            status = "unmatched"
        linked_units = _build_units_for_source(source, compile_units) if compile_units else []
        matches.append({
            "source": source_name,
            "binary_candidates": [{"address": item.get("address") or item.get("value", ""), "name": item.get("name", ""), "source": item.get("source") or ("elf-symbol" if "value" in item else "")} for item in candidates],
            "status": status,
            "method": "normalized_symbol_name",
            "confidence_kind": "heuristic",
            "requires_validation": True,
            "build_link": "linked" if linked_units else ("unlinked" if build_report is not None else "not_provided"),
            "build_units": linked_units,
        })
    candidate_count = sum(item["status"] == "candidate" for item in matches)
    ambiguous_count = sum(item["status"] == "ambiguous" for item in matches)
    unmatched_count = sum(item["status"] == "unmatched" for item in matches)
    correlation_status = "insufficient_data" if not matches else "complete" if candidate_count == len(matches) else "partial"
    return {
        "schema": "source-binary-correlation.v1",
        "status": correlation_status,
        "matches": matches,
        "summary": {
            "source_functions": len(source_functions),
            "candidate": candidate_count,
            "ambiguous": ambiguous_count,
            "unmatched": unmatched_count,
            "candidate_coverage": candidate_count / len(matches) if matches else 0.0,
        },
        "limitations": ["nome igual não prova equivalência", "inlining/stripping podem gerar 1:N/N:1", "validação exige símbolos, build ou trace independente"],
        "build_provenance": {
            "supplied": build_report is not None,
            "compile_units": len(compile_units),
            "executed": False,
            "limitations": ["compile_commands é declaração estática", "vínculo por arquivo não prova que o binário foi produzido pela unidade", "flags/toolchain/debug info exigem verificação independente"],
        },
        "errors": [],
    }


def write_correlation_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
