"""Native PE/ELF structural observations normalized into canonical IR."""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from aether_re.ir import IRDocument, IREdge, IRLocation, IRNode
from aether_re.kernel_contracts import EpistemicState


def _state(structure: dict[str, Any]) -> EpistemicState:
    return EpistemicState.EXACT if structure.get("parse_status", "partial") == "complete" else EpistemicState.UNKNOWN


def normalize_native_structure(artifact_id: str, profile_id: str, structure: dict[str, Any], evidence_ref: str) -> IRDocument:
    if profile_id not in {"native-pe", "native-elf"}:
        raise ValueError("native_profile_required")
    prefix = "pe" if profile_id == "native-pe" else "elf"
    state = _state(structure)
    losses: list[str] = []
    errors = structure.get("parse_errors", [])
    for loss, flag in [("section_table", "section_table_truncated"), ("symbol_table", "symbol_table_unavailable"), ("relocations", "relocations_unavailable")]:
        if flag in errors:
            losses.append(loss)
    nodes: list[IRNode] = []
    node_index: dict[str, int] = {}
    edges: list[IREdge] = []

    def add(kind: str, name: str, space: str, value: Any, attrs: dict[str, Any] | None = None) -> IRNode:
        attributes = dict(attrs or {})
        node = IRNode(kind, name, IRLocation(space, str(value)), "structure", (evidence_ref,), state,
                      1.0 if state is EpistemicState.EXACT else 0.0, tuple(losses), attributes)
        existing_index = node_index.get(node.identity)
        if existing_index is not None:
            existing = nodes[existing_index]
            records = existing.attributes.get("source_records")
            if not isinstance(records, list):
                records = [dict(existing.attributes)]
            records = [*records, attributes]
            merged_attributes = dict(existing.attributes)
            merged_attributes["source_records"] = records
            merged_attributes["duplicate_observation_count"] = len(records)
            merged = replace(existing, attributes=merged_attributes,
                             evidence_refs=tuple(sorted(set(existing.evidence_refs + node.evidence_refs))),
                             losses=tuple(sorted(set(existing.losses + node.losses))))
            nodes[existing_index] = merged
            return merged
        node_index[node.identity] = len(nodes)
        nodes.append(node)
        return node

    for section in structure.get("sections", []):
        name = str(section.get("name", "section"))
        rva = section.get("va", section.get("vaddr", ""))
        section_node = add("section", name, f"{prefix}:rva" if prefix == "pe" else f"{prefix}:vaddr", rva, dict(section))
        raw = section.get("raw_offset")
        if raw is not None:
            file_node = add("file_region", name, f"{prefix}:file", raw, dict(section))
            edges.append(IREdge("mapped_to", section_node.identity, file_node.identity, "structure", (evidence_ref,), state,
                                1.0 if state is EpistemicState.EXACT else 0.0, tuple(losses), {}))
    for typ, kind, space, key in [("segments", "segment", f"{prefix}:vaddr", "vaddr"),
                                  ("imports", "import", f"{prefix}:symbol", None),
                                  ("exports", "export", f"{prefix}:symbol", None),
                                  ("symbols", "symbol", f"{prefix}:vaddr", "value"),
                                  ("relocations", "relocation", f"{prefix}:vaddr", "offset")]:
        for index, item in enumerate(structure.get(typ, [])):
            if isinstance(item, dict):
                name = str(item.get("name") or item.get("symbol") or f"{kind}_{index}")
                value = item.get(key, "") if key else name
                attributes = dict(item)
            else:
                name = value = str(item)
                attributes = {}
            add(kind, name, space, value, attributes)
    return IRDocument("ir.v1", artifact_id, profile_id, tuple(nodes), tuple(edges), tuple(sorted(set(losses))))


def normalize_function_evidence(document: IRDocument, items: list[Any]) -> IRDocument:
    return document
