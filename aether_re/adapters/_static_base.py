"""Normalizers for optional static profiles; outputs remain conservative IR."""
from __future__ import annotations
from typing import Any
from aether_re.ir import IRDocument, IREdge, IRLocation, IRNode, validate_ir
from aether_re.kernel_contracts import EpistemicState

def _state(value: Any) -> EpistemicState:
    try: return value if isinstance(value, EpistemicState) else EpistemicState(value)
    except (ValueError, TypeError) as exc: raise ValueError('adapter_payload_invalid') from exc

def doc(profile: str, artifact_id: str, evidence_refs: tuple[str, ...], payload: dict[str, Any], prefix: str, kind_map: dict[str, str], losses: tuple[str, ...] = ()) -> IRDocument:
    if not isinstance(payload, dict) or not isinstance(artifact_id, str) or not artifact_id or not isinstance(evidence_refs, tuple) or not evidence_refs or any(not isinstance(x, str) or not x for x in evidence_refs): raise ValueError('adapter_payload_invalid')
    nodes=[]; edges=[]
    try:
        for category, kind in kind_map.items():
            items=payload.get(category, [])
            if not isinstance(items, list): raise ValueError('adapter_payload_invalid')
            for index, item in enumerate(items):
                if not isinstance(item, dict): raise ValueError('adapter_payload_invalid')
                name=str(item.get('name') or item.get('id') or f'{kind}_{index}')
                loc=str(item.get('offset', item.get('index', item.get('token', index))))
                nodes.append(IRNode(kind,name,IRLocation(f'{prefix}:{item.get("space","offset")}',loc),str(item.get('source_backend','adapter')),evidence_refs,_state(item.get('epistemic_state','UNKNOWN')),float(item.get('confidence',0.0)),tuple(item.get('losses',())),dict(item)))
        by_name={item.name:item for item in nodes}
        relations=payload.get('edges', [])
        if not isinstance(relations, list): raise ValueError('adapter_payload_invalid')
        for rel in relations:
            if not isinstance(rel,dict): raise ValueError('adapter_payload_invalid')
            if str(rel.get('source')) in by_name and str(rel.get('target')) in by_name:
                edges.append(IREdge(str(rel.get('kind','references')),by_name[str(rel['source'])].identity,by_name[str(rel['target'])].identity,'adapter',evidence_refs,EpistemicState.PROBABILISTIC_INFERENCE,0.,(),dict(rel)))
        result=IRDocument('ir.v1',artifact_id,profile,tuple(nodes),tuple(edges),tuple(losses))
        validate_ir(result)
        return result
    except (TypeError, ValueError, OverflowError) as exc:
        if str(exc)=='adapter_payload_invalid': raise
        raise ValueError('adapter_payload_invalid') from exc
