"""Pinned ILSpyCmd worker for static-only .NET assembly decompilation."""
from __future__ import annotations
import hashlib, json, os, shutil
from pathlib import Path
from typing import Any
from aether_re.adapters._static_base import doc
from aether_re.adapters.base import Adapter
from aether_re.process import run_bounded
from aether_re.ir import IRDocument,IREdge,IRNode
from aether_re.kernel_contracts import EpistemicState
def normalize_ilspy(payload:dict,artifact_id:str,evidence_ref:str)->IRDocument:
 if payload.get('schema','ilspy.v1') not in {'ilspy.v1','ilspy-json.v1'}:raise ValueError('ilspy_schema_unsupported')
 result=doc('dotnet',artifact_id,(evidence_ref,),payload,'dotnet',{'types':'type','methods':'method','fields':'field','resources':'resource'},tuple(['native_code_mapping'] if payload.get('ready_to_run') else []))
 return result
class ILSpyAdapter(Adapter):
 name='ilspy'
 _DOTNET=Path(r'C:\Program Files\dotnet\dotnet.exe');_DOTNET_SHA256='c1809e1f7fc603c2096efdfbc3f98c2123a398d3dff331096fdaebc3071ac32d'
 _CMD=Path(r'E:\AetherRE_Toolchain\packages\ilspycmd-11.1.0.9782\content\tools\net10.0\any\ilspycmd.dll');_CMD_SHA256='e93cec394a6e21221db7686ca3932004382642c7d58c1308633ce6eded41b9c9'
 def __init__(self,*,dotnet:str|None=None,ilspycmd:str|None=None)->None:
  self.dotnet=Path(dotnet or os.environ.get('AETHER_DOTNET_BIN','') or self._DOTNET);self.ilspycmd=Path(ilspycmd or os.environ.get('AETHER_ILSPYCMD_DLL','') or self._CMD)
 @staticmethod
 def _hash(path:Path)->str|None:
  try:return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
  except OSError:return None
 def available(self)->bool:
  return bool(self._DOTNET_SHA256 and self._CMD_SHA256 and self._hash(self.dotnet)==self._DOTNET_SHA256 and self._hash(self.ilspycmd)==self._CMD_SHA256)
 def analyze(self,target:Path,out_dir:Path)->dict[str,Any]:
  if not self.available():return {'ok':False,'available':False,'executed':False,'produced_evidence':False,'partial':False,'error':'ilspycmd_worker_unavailable_or_hash_mismatch'}
  root=Path(out_dir)/'dotnet_static'
  if root.exists():return {'ok':False,'available':True,'executed':False,'produced_evidence':False,'partial':False,'error':'dotnet_evidence_already_exists'}
  root.mkdir(parents=True);source=root/'source';source.mkdir()
  try:
   run=run_bounded([str(self.dotnet),str(self.ilspycmd),'-p','-o',str(source),str(target)],timeout=120.,memory_limit_mb=1536,cpu_time_limit_s=120,cwd=str(root))
   files=sorted(x.relative_to(source).as_posix() for x in source.rglob('*.cs'));evidence=root/'summary.json';evidence.write_text(json.dumps({'schema':'dotnet-static-evidence.v1','target':str(target),'decompiled_files':files,'worker':run,'limitations':['decompiled C# is not original source','no assembly execution performed']},sort_keys=True,ensure_ascii=False,indent=2),encoding='utf-8')
   good=run.get('returncode')==0 and not run.get('timed_out') and bool(files)
   return {'ok':good,'available':True,'executed':True,'produced_evidence':evidence.is_file(),'partial':not good,'returncode':run.get('returncode'),'timed_out':bool(run.get('timed_out')),'decompiled_files':files,'report':str(evidence),'stderr_tail':str(run.get('stderr',''))[-2000:]}
  except (OSError,ValueError) as exc:
   shutil.rmtree(root,ignore_errors=True);return {'ok':False,'available':True,'executed':True,'produced_evidence':False,'partial':True,'error':f'ilspycmd_worker_failed:{exc.__class__.__name__}'}
