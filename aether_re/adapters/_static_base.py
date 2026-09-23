"""Normalizers for optional static profiles; outputs remain conservative IR."""
from __future__ import annotations
from typing import Any
from aether_re.ir import IRDocument,IREdge,IRLocation,IRNode
from aether_re.kernel_contracts import EpistemicState
def _state(value:Any)->EpistemicState:
 try:return value if isinstance(value,EpistemicState) else EpistemicState(value)
 except (ValueError,TypeError):return EpistemicState.UNKNOWN
def doc(profile:str,artifact_id:str,evidence_refs:tuple[str,...],payload:dict[str,Any],prefix:str,kind_map:dict[str,str],losses:tuple[str,...]=())->IRDocument:
 nodes=[];edges=[]
 for category,kind in kind_map.items():
  for index,item in enumerate(payload.get(category,[]) if isinstance(payload.get(category,[]),list) else []):
   item=item if isinstance(item,dict) else {'name':str(item)};name=str(item.get('name') or item.get('id') or f'{kind}_{index}');loc=str(item.get('offset',item.get('index',item.get('token',index))))
   nodes.append(IRNode(kind,name,IRLocation(f'{prefix}:{item.get("space","offset")}',loc),str(item.get('source_backend','adapter')),evidence_refs,_state(item.get('epistemic_state','UNKNOWN')),float(item.get('confidence',0.0)),tuple(item.get('losses',())),item))
 by_name={n.name:n for n in nodes}
 for rel in payload.get('edges',[]):
  if isinstance(rel,dict) and str(rel.get('source')) in by_name and str(rel.get('target')) in by_name:edges.append(IREdge(str(rel.get('kind','references')),by_name[str(rel['source'])].identity,by_name[str(rel['target'])].identity,'adapter',evidence_refs,EpistemicState.PROBABILISTIC_INFERENCE,0.,(),dict(rel)))
 return IRDocument('ir.v1',artifact_id,profile,tuple(nodes),tuple(edges),tuple(losses))
