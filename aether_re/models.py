"""Modelos de dados do pipeline Megazord."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict, fields
from typing import Any, Mapping
from aether_re.kernel_contracts import EpistemicState


@dataclass
class Finding:
    engine: str
    severity: str  # info | low | medium | high | critical
    title: str
    detail: str
    evidence: str = ""
    confidence: float = 0.5  # 0.0–1.0


@dataclass
class FunctionSketch:
    name: str
    address: str = ""
    imports_used: list[str] = field(default_factory=list)
    strings_near: list[str] = field(default_factory=list)
    notes: str = ""
    confidence: float = 0.3


@dataclass
class FunctionEvidence:
    address: str
    name: str
    source: str
    confidence: float = 0.5
    quality: float = 0.5
    coverage: float = 1.0
    pseudocode: str = ""
    disassembly: str = ""
    calls: list[str] = field(default_factory=list)
    imports_used: list[str] = field(default_factory=list)
    strings_near: list[str] = field(default_factory=list)
    notes: str = ""
    warnings: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    address_space: str = "unknown"
    evidence_refs: list[str] = field(default_factory=list)
    epistemic_state: EpistemicState = EpistemicState.UNKNOWN
    losses: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, item: Mapping[str, Any]) -> FunctionEvidence:
        """Convert adapter output while preserving unknown fields as raw evidence."""
        if not isinstance(item, Mapping):
            raise TypeError("function_evidence_mapping_required")
        allowed = {field.name for field in fields(cls)}
        values = {key: value for key, value in item.items() if key in allowed}
        extras = {key: value for key, value in item.items() if key not in allowed}
        raw = values.get("raw", {})
        if not isinstance(raw, Mapping):
            raise TypeError("function_evidence_raw_mapping_required")
        merged_raw = dict(raw)
        if extras:
            existing = merged_raw.get("adapter_extra_fields", {})
            if existing and not isinstance(existing, Mapping):
                raise TypeError("function_evidence_adapter_extra_fields_invalid")
            merged_raw["adapter_extra_fields"] = {**dict(existing), **extras}
        values["raw"] = merged_raw
        return cls(**values)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FunctionConsensus:
    address: str
    name: str
    aliases: list[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence_quality: float = 0.0
    source_agreement: float = 0.0
    coverage: float = 0.0
    selected_source: str = ""
    fallback_used: bool = False
    pseudocode: str = ""
    disassembly: str = ""
    calls: list[str] = field(default_factory=list)
    imports_used: list[str] = field(default_factory=list)
    strings_near: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    evidence: dict[str, dict[str, Any]] = field(default_factory=dict)
    address_space: str = "unknown"
    evidence_refs: list[str] = field(default_factory=list)
    epistemic_state: EpistemicState = EpistemicState.UNKNOWN
    losses: list[str] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    alternatives: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisReport:
    target: str
    target_sha256: str = ""
    target_identity: dict[str, Any] = field(default_factory=dict)
    file_type: str = "unknown"
    size_bytes: int = 0
    entropy: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    sections: list[dict[str, Any]] = field(default_factory=list)
    segments: list[dict[str, Any]] = field(default_factory=list)
    symbols: list[dict[str, Any]] = field(default_factory=list)
    relocations: list[dict[str, Any]] = field(default_factory=list)
    needed_libraries: list[str] = field(default_factory=list)
    dwarf: dict[str, Any] = field(default_factory=dict)
    strings: list[str] = field(default_factory=list)
    decoded_payloads: list[dict[str, Any]] = field(default_factory=list)
    disassembly_snippets: list[dict[str, Any]] = field(default_factory=list)
    function_sketches: list[FunctionSketch] = field(default_factory=list)
    function_evidence: list[FunctionEvidence] = field(default_factory=list)
    merged_functions: list[FunctionConsensus] = field(default_factory=list)
    pseudo_source: str = ""
    adapter_results: dict[str, Any] = field(default_factory=dict)
    overall_confidence: float = 0.0
    confidence_rationale: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    engines_used: list[str] = field(default_factory=list)
    case_id: str = ""
    intake_manifest: str = ""
    root_artifact_id: str = ""
    profile_decision: dict[str, Any] = field(default_factory=dict)
    evidence_journal: str = ""
    ir: dict[str, Any] = field(default_factory=dict)
    profile: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
