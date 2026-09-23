from __future__ import annotations
from aether_re.adapters._static_base import doc
def normalize_jvm(payload:dict,artifact_id:str,evidence_ref:str):
 if payload.get('class_major_unknown'):raise ValueError('jvm_class_version_unsupported')
 return doc('jvm',artifact_id,(evidence_ref,),payload,'jvm',{'classes':'class','methods':'jvm_method','fields':'field','annotations':'annotation'})
