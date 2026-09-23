from __future__ import annotations
from aether_re.adapters._static_base import doc
def normalize_wasm(payload:dict,artifact_id:str,evidence_ref:str):
 losses=tuple(['function_names'] if not payload.get('name_section',False) else [])
 return doc('wasm',artifact_id,(evidence_ref,),payload,'wasm',{'functions':'function','imports':'import','exports':'export','custom_sections':'custom_section'},losses)
class WasmAdapter:
 name='wasm'
 def available(self):return False
