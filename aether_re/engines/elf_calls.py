"""Static direct-call recovery for ELF x86/x86_64 artifacts.

This is deliberately a narrow observation engine.  It disassembles executable
ELF sections with Capstone, attributes direct ``call`` instructions to symbol
ranges and never loads or executes the artifact.  Indirect calls, PLT/import
edges and optimized/inlined relationships remain explicitly unresolved.
"""

from __future__ import annotations

from typing import Any


def _as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _symbol_ranges(structure: dict[str, Any], text_start: int, text_end: int) -> list[dict[str, Any]]:
    raw: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    symbols = structure.get("symbols", [])
    for item in symbols if isinstance(symbols, list) else []:
        if not isinstance(item, dict) or _as_int(item.get("type", -1)) != 2:
            continue
        name = str(item.get("name") or "").strip()
        address = _as_int(item.get("value"))
        if not name or address is None or address < text_start or address >= text_end:
            continue
        identity = (name, address)
        if identity in seen:
            continue
        seen.add(identity)
        size = _as_int(item.get("size")) or 0
        if size <= 0:
            continue
        raw.append({"name": name, "address": address, "size": size})
    raw.sort(key=lambda item: (item["address"], item["name"]))
    ranges: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        next_address = raw[index + 1]["address"] if index + 1 < len(raw) else text_end
        end = min(text_end, item["address"] + item["size"]) if item["size"] else next_address
        if end <= item["address"]:
            continue
        ranges.append({**item, "end": end})
    return ranges


def _owners(ranges: list[dict[str, Any]], address: int) -> list[dict[str, Any]]:
    return [item for item in ranges if item["address"] <= address < item["end"]]


def recover_direct_calls(data: bytes, structure: dict[str, Any]) -> dict[str, Any]:
    """Recover local direct-call observations from an ELF byte snapshot."""
    base_result = {
        "status": "not_measured",
        "method": "capstone_direct_calls",
        "relations": [],
        "instructions_disassembled": 0,
        "direct_calls": 0,
        "resolved_calls": 0,
        "unresolved_direct_calls": 0,
        "executed": False,
    }
    if not isinstance(structure, dict) or not str(structure.get("format", "")).upper().startswith("ELF"):
        return {**base_result, "status": "not_applicable", "reason": "ELF_required"}
    machine = str(structure.get("machine_name", "")).lower()
    if machine not in {"i386", "x86_64"}:
        return {**base_result, "status": "unsupported", "reason": "x86_or_x86_64_required", "machine": machine}
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OP_IMM, Cs  # type: ignore
    except ImportError:
        return {**base_result, "status": "unavailable", "reason": "capstone_unavailable"}
    raw_sections = structure.get("sections", [])
    sections = [item for item in raw_sections if isinstance(item, dict)] if isinstance(raw_sections, list) else []
    text_sections = [item for item in sections if str(item.get("name", "")).lower() == ".text"]
    if not text_sections:
        text_sections = [item for item in sections if _as_int(item.get("chars")) is not None and _as_int(item.get("chars")) & 0x4]
    if not text_sections:
        return {**base_result, "status": "not_measured", "reason": "executable_section_not_found"}
    mode = CS_MODE_64 if machine == "x86_64" else CS_MODE_32
    try:
        md = Cs(CS_ARCH_X86, mode)
    except Exception as exc:
        return {**base_result, "status": "failed", "reason": "capstone_init_failed", "error": type(exc).__name__}
    md.detail = True
    relations: list[dict[str, Any]] = []
    direct_calls = 0
    unresolved = 0
    ambiguous = 0
    instruction_count = 0
    function_range_count = 0
    try:
        for section in text_sections:
            offset = _as_int(section.get("offset"))
            section_start = _as_int(section.get("va"))
            raw_size = _as_int(section.get("raw_size"))
            if offset is None or section_start is None or raw_size is None or offset < 0 or raw_size <= 0 or offset > len(data) or raw_size > len(data) - offset:
                continue
            payload = data[offset:offset + raw_size]
            section_end = section_start + len(payload)
            ranges = _symbol_ranges(structure, section_start, section_end)
            function_range_count += len(ranges)
            for instruction in md.disasm(payload, section_start):
                instruction_count += 1
                if instruction.mnemonic != "call" or not instruction.operands:
                    continue
                direct_calls += 1
                operand = instruction.operands[0]
                if operand.type != CS_OP_IMM:
                    unresolved += 1
                    continue
                callers = _owners(ranges, instruction.address)
                callees = _owners(ranges, int(operand.imm))
                if len(callers) != 1 or len(callees) != 1:
                    unresolved += 1
                    if len(callers) > 1 or len(callees) > 1:
                        ambiguous += 1
                    continue
                caller, callee = callers[0], callees[0]
                relations.append({"caller": caller["name"], "callee": callee["name"], "callsite": hex(instruction.address), "target": hex(int(operand.imm))})
    except Exception as exc:
        return {**base_result, "status": "partial" if instruction_count else "failed", "reason": "capstone_disassembly_failed", "error": type(exc).__name__, "instructions_disassembled": instruction_count, "direct_calls": direct_calls, "resolved_calls": len(relations), "unresolved_direct_calls": unresolved, "ambiguous_calls": ambiguous, "function_ranges": function_range_count}
    unique = {(item["caller"], item["callee"]) for item in relations}
    if function_range_count == 0:
        return {
            **base_result,
            "status": "not_measured",
            "reason": "function_symbols_not_available",
            "instructions_disassembled": instruction_count,
            "direct_calls": direct_calls,
            "resolved_calls": 0,
            "unresolved_direct_calls": unresolved + len(relations),
            "ambiguous_calls": ambiguous,
            "function_ranges": 0,
            "limitations": ["símbolos de função locais são necessários para atribuir caller/callee", "stripping não é falso negativo de relação", "disassembly estático não prova alcançabilidade nem comportamento"],
        }
    return {
        **base_result,
        "status": "measured",
        "relations": relations,
        "unique_relations": [{"caller": caller, "callee": callee} for caller, callee in sorted(unique)],
        "instructions_disassembled": instruction_count,
        "direct_calls": direct_calls,
        "resolved_calls": len(relations),
        "unresolved_direct_calls": unresolved,
        "ambiguous_calls": ambiguous,
        "function_ranges": function_range_count,
        "limitations": ["somente calls diretos locais em ELF x86/x86_64", "indiretos, PLT/imports e inlining permanecem não resolvidos", "disassembly estático não prova alcançabilidade nem comportamento"],
    }
