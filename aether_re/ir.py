"""Immutable, provenance-preserving normalized static-analysis IR."""
from __future__ import annotations
import hashlib, math
from dataclasses import asdict, dataclass
from typing import Any, Mapping
from aether_re.kernel_contracts import EpistemicState

@dataclass(frozen=True)
class IRLocation:
    space: str
    value: str
    module: str = ""

@dataclass(frozen=True)
class IRNode:
    kind: str; name: str; location: IRLocation; source_backend: str
    evidence_refs: tuple[str, ...]; epistemic_state: EpistemicState; confidence: float
    losses: tuple[str, ...]; attributes: Mapping[str, Any]
    @property
    def identity(self) -> str:
        payload = "\0".join((self.kind,self.location.space,self.location.value,self.location.module,self.name))
        return "irn:" + hashlib.sha256(payload.encode()).hexdigest()

@dataclass(frozen=True)
class IREdge:
    kind: str; source: str; target: str; source_backend: str
    evidence_refs: tuple[str, ...]; epistemic_state: EpistemicState; confidence: float
    losses: tuple[str, ...]; attributes: Mapping[str, Any]

@dataclass(frozen=True)
class IRDocument:
    schema: str; artifact_id: str; profile_id: str; nodes: tuple[IRNode,...]; edges: tuple[IREdge,...]; losses: tuple[str,...]

def _state(value: Any) -> EpistemicState:
    try: return value if isinstance(value, EpistemicState) else EpistemicState(value)
    except (TypeError,ValueError) as exc: raise ValueError("ir_epistemic_state_invalid") from exc

def _item(item: IRNode|IREdge) -> None:
    if not item.source_backend or not item.evidence_refs: raise ValueError("ir_evidence_refs_required")
    if not all(isinstance(x,str) and x for x in item.evidence_refs): raise ValueError("ir_evidence_refs_required")
    if not isinstance(item.confidence,(float,int)) or isinstance(item.confidence,bool) or not math.isfinite(item.confidence) or not 0 <= item.confidence <= 1: raise ValueError("ir_confidence_invalid")
    _state(item.epistemic_state)

def validate_ir(document: IRDocument) -> None:
    if not isinstance(document, IRDocument) or not document.schema or not document.artifact_id or not document.profile_id: raise ValueError("ir_document_invalid")
    ids=set()
    for node in document.nodes:
        _item(node)
        if not node.kind or not node.location.space or not node.location.value: raise ValueError("ir_node_invalid")
        if node.identity in ids: raise ValueError("ir_node_duplicate")
        ids.add(node.identity)
    for edge in document.edges:
        _item(edge)
        if edge.source not in ids or edge.target not in ids: raise ValueError("ir_edge_endpoint_missing")

def _node(node: IRNode) -> dict[str,Any]:
    return {"id":node.identity,"kind":node.kind,"name":node.name,"location":asdict(node.location),"source_backend":node.source_backend,"evidence_refs":list(node.evidence_refs),"epistemic_state":_state(node.epistemic_state).value,"confidence":node.confidence,"losses":list(node.losses),"attributes":dict(node.attributes)}
def _edge(edge: IREdge) -> dict[str,Any]:
    return {"kind":edge.kind,"source":edge.source,"target":edge.target,"source_backend":edge.source_backend,"evidence_refs":list(edge.evidence_refs),"epistemic_state":_state(edge.epistemic_state).value,"confidence":edge.confidence,"losses":list(edge.losses),"attributes":dict(edge.attributes)}
def canonical_ir_dict(document: IRDocument) -> dict[str,Any]:
    validate_ir(document)
    return {"schema":document.schema,"artifact_id":document.artifact_id,"profile_id":document.profile_id,"nodes":sorted((_node(x) for x in document.nodes),key=lambda x:x["id"]),"edges":sorted((_edge(x) for x in document.edges),key=lambda x:(x["kind"],x["source"],x["target"],x["source_backend"])),"losses":sorted(document.losses)}