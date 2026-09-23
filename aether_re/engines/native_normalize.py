"""Native PE/ELF structural observations normalized into canonical IR."""
from __future__ import annotations
from typing import Any
from aether_re.ir import IRDocument,IREdge,IRLocation,IRNode
from aether_re.kernel_contracts import EpistemicState
def _state(structure:dict[str,Any])->EpistemicState:return EpistemicState.EXACT if structure.get('parse_status','partial')=='complete' else EpistemicState.UNKNOWN
def normalize_native_structure(artifact_id:str,profile_id:str,structure:dict[str,Any],evidence_ref:str)->IRDocument:
 if profile_id not in {'native-pe','native-elf'}:raise ValueError('native_profile_required')
 prefix='pe' if profile_id=='native-pe' else 'elf';state=_state(structure);losses=[]
 errors=structure.get('parse_errors',[])
 for loss,flag in [('section_table','section_table_truncated'),('symbol_table','symbol_table_unavailable'),('relocations','relocations_unavailable')]:
  if flag in errors:losses.append(loss)
 nodes=[];edges=[]
 def add(kind,name,space,value,attrs=None):
  node=IRNode(kind,name,IRLocation(space,str(value)), 'structure',(evidence_ref,),state,1.0 if state is EpistemicState.EXACT else 0.,tuple(losses),attrs or {})
  nodes.append(node);return node
 for section in structure.get('sections',[]):
  name=str(section.get('name','section'));rva=section.get('va',section.get('vaddr',''))
  a=add('section',name,f'{prefix}:rva' if prefix=='pe' else f'{prefix}:vaddr',rva,dict(section))
  raw=section.get('raw_offset')
  if raw is not None:
   b=add('file_region',name,f'{prefix}:file',raw,dict(section));edges.append(IREdge('mapped_to',a.identity,b.identity,'structure',(evidence_ref,),state,1.0 if state is EpistemicState.EXACT else 0.,tuple(losses),{}))
 for typ,kind,space,key in [('segments','segment',f'{prefix}:vaddr','vaddr'),('imports','import',f'{prefix}:symbol',None),('exports','export',f'{prefix}:symbol',None),('symbols','symbol',f'{prefix}:vaddr','value'),('relocations','relocation',f'{prefix}:vaddr','offset')]:
  for index,item in enumerate(structure.get(typ,[])):
   if isinstance(item,dict):name=str(item.get('name') or item.get('symbol') or f'{kind}_{index}');value=item.get(key,'') if key else name;attrs=dict(item)
   else:name=value=str(item);attrs={}
   add(kind,name,space,value,attrs)
 return IRDocument('ir.v1',artifact_id,profile_id,tuple(nodes),tuple(edges),tuple(sorted(set(losses))))
def normalize_function_evidence(document:IRDocument,items:list[Any])->IRDocument:return document
