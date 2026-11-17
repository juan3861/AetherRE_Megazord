"""Calibrated, conflict-preserving function consensus."""
from __future__ import annotations
from collections import defaultdict
from itertools import combinations
from typing import Any
from aether_re.kernel_contracts import EpistemicState
from aether_re.models import Finding, FunctionConsensus, FunctionEvidence
SOURCE_WEIGHTS={"ghidra":.35,"rizin":.20,"angr":.15,"binaryninja":.20,"native":.10}
def normalize_address(value:object,base_addr:int=0)->str:
 if value is None:return ""
 try:return f"0x{int(value,16) if isinstance(value,str) else int(value):x}"
 except (TypeError,ValueError):return ""
def _sets(values:list[str])->set[str]:return {str(x).strip().lower() for x in values if str(x).strip()}
def _jaccard(a:list[str],b:list[str])->float:
 left,right=_sets(a),_sets(b);return .5 if not left and not right else len(left&right)/len(left|right)
def _source_agreement(a:FunctionEvidence,b:FunctionEvidence)->float:
 name=1.0 if a.name.lower()==b.name.lower() else .25
 return round(.5*_jaccard(a.calls,b.calls)+.2*_jaccard(a.imports_used,b.imports_used)+.3*name,4)
def merge_function_evidence(evidence_items:list[FunctionEvidence],successful_sources:list[str]|None=None,base_addr:int=0,reliability:dict[str,float]|None=None)->list[FunctionConsensus]:
 groups:dict[tuple[str,str],list[FunctionEvidence]]=defaultdict(list)
 for item in evidence_items:
  addr=normalize_address(item.address,base_addr)
  if addr:groups[(item.address_space or 'unknown',addr)].append(item)
 universe=(set(successful_sources or [x.source for x in evidence_items]) if reliability is not None else set(SOURCE_WEIGHTS)) or {'native'}; rel=reliability or SOURCE_WEIGHTS; result=[]
 for (space,address),items in sorted(groups.items(),key=lambda x:(x[0][0],int(x[0][1],16))):
  def weight(x:FunctionEvidence)->float:return max(0,min(1,float(rel.get(x.source,.25))))*max(0,min(1,x.confidence))*max(0,min(1,x.quality))
  ranked=sorted(items,key=lambda x:(-weight(x),x.source,x.name)); selected=ranked[0]; weights=[weight(x) for x in items];total=sum(weights) or 1
  quality=sum(x.quality*w for x,w in zip(items,weights))/total; confidence=sum(x.confidence*w for x,w in zip(items,weights))/total
  agreements=[_source_agreement(x,y) for x,y in combinations(items,2)];agreement=sum(agreements)/len(agreements) if agreements else 0.
  coverage=len({x.source for x in items})/len(universe); score=min(.80, .65*confidence+.25*agreement+.10*coverage)
  conflicts=[]; alternatives=[]
  for field in ('name','pseudocode','disassembly'):
   values={getattr(x,field) for x in items if getattr(x,field)}
   if len(values)>1:
    conflicts.append({'field':field,'values':sorted(values),'selected':getattr(selected,field)})
    alternatives.extend({'field':field,'value':getattr(x,field),'source':x.source,'evidence_refs':list(x.evidence_refs)} for x in items if getattr(x,field)!=getattr(selected,field))
  refs=sorted({r for x in items for r in x.evidence_refs}); losses=sorted({loss for x in items for loss in x.losses})
  warnings=[]
  if len(items)==1:warnings.append('Função observada por apenas uma fonte; não há corroboração independente.')
  if conflicts:warnings.append('Conflitos de backend preservados como alternativas.')
  warnings.extend(f'[{x.source}] {w}' for x in items for w in x.warnings)
  result.append(FunctionConsensus(address=address,name=selected.name,aliases=sorted({x.name for x in items}),confidence=round(score,4),evidence_quality=round(quality,4),source_agreement=round(agreement,4),coverage=round(coverage,4),selected_source=selected.source,fallback_used=selected.source not in {'ghidra','rizin','angr'},pseudocode=selected.pseudocode,disassembly=selected.disassembly,calls=sorted({c for x in items for c in x.calls}),imports_used=sorted({v for x in items for v in x.imports_used}),strings_near=sorted({v for x in items for v in x.strings_near}),sources=sorted({x.source for x in items}),warnings=list(dict.fromkeys(warnings)),evidence={x.source:x.to_dict() for x in sorted(items,key=lambda x:x.source)},address_space=space,evidence_refs=refs,epistemic_state=EpistemicState.PROBABILISTIC_INFERENCE,losses=losses,conflicts=conflicts,alternatives=alternatives))
 return result
def compute_overall_confidence(merged_functions:list[FunctionConsensus],native_confidence:float,successful_sources:list[str]|None=None,failed_sources:list[str]|None=None)->tuple[float,dict[str,Any]]:
 if merged_functions:
  overall=sum(x.confidence for x in merged_functions)/len(merged_functions)*.7+min(1,max(0,native_confidence))*.2+sum(x.coverage for x in merged_functions)/len(merged_functions)*.1
 else: overall=min(float(native_confidence),.65)
 return round(min(1,max(0,overall)),4),{'method':'function-weighted ensemble','successful_function_sources':sorted(set(successful_sources or [])),'unavailable_or_failed_sources':sorted(set(failed_sources or [])),'function_count':len(merged_functions)}
def merge_findings(ghidra_findings:list[Finding],rizin_findings:list[Finding],native_findings:list[Finding])->list[Finding]:
 seen={}
 for x in [*native_findings,*(ghidra_findings or []),*(rizin_findings or [])]:
  key=f'{x.title}:{x.severity}'
  if key not in seen or x.confidence>seen[key].confidence:seen[key]=x
 return list(seen.values())
def weighted_vote(items:list[dict[str,Any]],weight_key:str='confidence')->Any:return max(items,key=lambda x:x.get(weight_key,.5)) if items else None
def merge_function_signatures(ghidra_funcs:list[dict[str,Any]],rizin_funcs:list[dict[str,Any]],reconstruct_sketches:list[dict[str,Any]])->list[dict[str,Any]]:
 evidence=[FunctionEvidence(**x) for group in (ghidra_funcs,rizin_funcs) for x in group]
 for x in reconstruct_sketches:
  if normalize_address(x.get('address')):evidence.append(FunctionEvidence(address=normalize_address(x['address']),name=x.get('name','unknown'),source='native',confidence=float(x.get('confidence',.3)),quality=.3,address_space='unknown'))
 return [x.to_dict() for x in merge_function_evidence(evidence,['ghidra','rizin'])]
