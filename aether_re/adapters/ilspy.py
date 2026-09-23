from __future__ import annotations
from aether_re.adapters._static_base import doc
from aether_re.ir import IRDocument,IREdge,IRNode
from aether_re.kernel_contracts import EpistemicState
def normalize_ilspy(payload:dict,artifact_id:str,evidence_ref:str)->IRDocument:
 if payload.get('schema','ilspy.v1') not in {'ilspy.v1','ilspy-json.v1'}:raise ValueError('ilspy_schema_unsupported')
 result=doc('dotnet',artifact_id,(evidence_ref,),payload,'dotnet',{'types':'type','methods':'method','fields':'field','resources':'resource'},tuple(['native_code_mapping'] if payload.get('ready_to_run') else []))
 return result
class ILSpyAdapter:
 name='ilspy'
 def available(self):return False
