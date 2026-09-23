from __future__ import annotations
from aether_re.adapters._static_base import doc
def normalize_firmware(payload:dict,artifact_id:str,evidence_ref:str,layout:dict|None):
 if layout is None:raise ValueError('firmware_layout_required')
 if not layout.get('architecture') or not layout.get('endianness') or not isinstance(layout.get('regions'),list):raise ValueError('firmware_layout_required')
 used=[]
 for reg in layout['regions']:
  start=int(reg.get('offset',-1));size=int(reg.get('size',-1))
  if start<0 or size<0 or any(start<s+z and s<start+size for s,z in used):raise ValueError('firmware_layout_overlap')
  used.append((start,size))
 return doc('firmware',artifact_id,(evidence_ref,),{'regions':layout['regions']},'firmware',{'regions':'region'})
