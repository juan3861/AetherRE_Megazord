from __future__ import annotations
from aether_re.adapters._static_base import doc
def normalize_macho(payload:dict,artifact_id:str,evidence_ref:str):return doc('macho',artifact_id,(evidence_ref,),payload,'macho',{'slices':'slice','segments':'segment','sections':'section','symbols':'symbol','imports':'import','exports':'export'})
