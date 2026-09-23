"""Pinned, bounded static worker invocation; no shell or target execution."""
from __future__ import annotations
import hashlib, os, re, subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from aether_re.process import run_bounded
_FORBIDDEN=re.compile(r"[|&;<>\r\n\0]|(?:^|/)\.\.(?:/|$)|^@")
@dataclass(frozen=True)
class StaticWorkerSpec:
 name:str; executable:Path; executable_sha256:str; expected_version:str; license_spdx:str; timeout_s:float; memory_mb:int; cpu_s:int; max_output_bytes:int
@dataclass(frozen=True)
class StaticWorkerProbe:
 name:str; available:bool; executable_sha256:str; version:str; license_spdx:str; errors:tuple[str,...]
def _hash(path:Path)->str:
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk)
 return h.hexdigest()
def probe_static_worker(spec:StaticWorkerSpec)->StaticWorkerProbe:
 try:
  exe=spec.executable.resolve(strict=True)
  if not exe.is_file() or _hash(exe)!=spec.executable_sha256:return StaticWorkerProbe(spec.name,False,"","",spec.license_spdx,("worker_executable_hash_mismatch",))
  value=run_bounded([str(exe),'--version'],timeout=min(spec.timeout_s,10),memory_limit_mb=spec.memory_mb,cpu_time_limit_s=spec.cpu_s,cwd=str(exe.parent))
  version=str(value.get('stdout','')).strip()
  if value.get('returncode') not in (0,None):return StaticWorkerProbe(spec.name,False,spec.executable_sha256,version,spec.license_spdx,("worker_version_failed",))
  return StaticWorkerProbe(spec.name,True,spec.executable_sha256,version,spec.license_spdx,())
 except (OSError,ValueError) as exc:return StaticWorkerProbe(spec.name,False,"","",spec.license_spdx,(str(exc),))
def run_static_worker(spec:StaticWorkerSpec,args:tuple[str,...],input_path:Path,out_dir:Path)->dict[str,Any]:
 exe=spec.executable.resolve(strict=True)
 if _hash(exe)!=spec.executable_sha256:raise ValueError('worker_executable_hash_mismatch')
 inp=input_path.resolve(strict=True); out=out_dir.resolve()
 if not inp.is_file() or inp.is_symlink():raise ValueError('worker_input_invalid')
 if out.exists():raise ValueError('worker_out_dir_must_be_new')
 if inp.parent==out or out.is_relative_to(inp.parent):raise ValueError('worker_output_location_invalid')
 if any(not isinstance(x,str) or _FORBIDDEN.search(x) for x in args):raise ValueError('worker_argument_forbidden')
 out.mkdir(parents=True); command=[str(exe),*args,str(inp)]
 value=run_bounded(command,timeout=spec.timeout_s,memory_limit_mb=spec.memory_mb,cpu_time_limit_s=spec.cpu_s,cwd=str(out))
 stdout=str(value.get('stdout',''));stderr=str(value.get('stderr',''))
 if len(stdout.encode())+len(stderr.encode())>spec.max_output_bytes:return {'schema':'static-worker-result.v1','name':spec.name,'state':'failed','ok':False,'available':True,'executed':True,'produced_evidence':False,'partial':False,'error':'worker_output_limit_exceeded','stdout':'','stderr':'','returncode':value.get('returncode')}
 state='timed_out' if value.get('timed_out') else ('failed' if value.get('returncode') else 'succeeded')
 return {'schema':'static-worker-result.v1','name':spec.name,'state':state,'ok':state=='succeeded','available':True,'executed':True,'produced_evidence':False,'partial':state=='timed_out','error':stderr,'stdout':stdout,'stderr':stderr,'returncode':value.get('returncode')}
def validate_static_worker_result(name:str,result:dict[str,Any])->dict[str,Any]:
 required={'schema','name','state','ok','available','executed','produced_evidence','partial','error','stdout','stderr','returncode'}
 if set(result)!=required or result.get('schema')!='static-worker-result.v1' or result.get('name')!=name:raise ValueError('static_worker_result_schema_invalid')
 if result['state'] not in {'unavailable','succeeded','partial','failed','timed_out'}:raise ValueError('static_worker_result_state_invalid')
 if result['state']=='succeeded' and not result['executed']:raise ValueError('static_worker_result_invalid')
 return dict(result)