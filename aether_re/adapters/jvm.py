"""Pinned static JVM/JAR decompilation; output is reconstructed source only."""
from __future__ import annotations
import hashlib, json, os, shutil, zipfile
from pathlib import Path
from typing import Any
from aether_re.adapters._static_base import doc
from aether_re.adapters.base import Adapter
from aether_re.process import run_bounded
def normalize_jvm(payload:dict,artifact_id:str,evidence_ref:str):
 if payload.get('class_major_unknown'):raise ValueError('jvm_class_version_unsupported')
 return doc('jvm',artifact_id,(evidence_ref,),payload,'jvm',{'classes':'class','methods':'jvm_method','fields':'field','annotations':'annotation'})

class JvmAdapter(Adapter):
 name='jvm'
 _JAVA=Path(r'C:\Program Files\Android\Android Studio\jbr\bin\java.exe');_JAVA_SHA256='478ab50b6ca350b71d3174c201c1e4bd93c2c255ab6e0e9ab4465a5d322260aa'
 _VINEFLOWER=Path(r'E:\AetherRE_Toolchain\packages\vineflower-1.12.0\vineflower-1.12.0.jar');_VINEFLOWER_SHA256='1dfcfe974395734fa467ce620661c7623d05ba83670de0529b1fbd63ff548b9d'
 def __init__(self,*,java:str|None=None,vineflower:str|None=None)->None:
  self.java=Path(java or os.environ.get('AETHER_JAVA_BIN','') or self._JAVA);self.vineflower=Path(vineflower or os.environ.get('AETHER_VINEFLOWER_JAR','') or self._VINEFLOWER)
 @staticmethod
 def _matches(path:Path,digest:str)->bool:
  try:return path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==digest
  except OSError:return False
 def available(self)->bool:return self._matches(self.java,self._JAVA_SHA256) and self._matches(self.vineflower,self._VINEFLOWER_SHA256)
 @staticmethod
 def _classes(target:Path)->list[dict[str,Any]]:
  try:
   with zipfile.ZipFile(target) as archive:names=sorted(x for x in archive.namelist() if x.endswith('.class') and not x.startswith('META-INF/'))
  except (OSError,zipfile.BadZipFile):return []
  return [{'name':x[:-6].replace('/','.'),'path':x,'source_backend':'jar-index','confidence':1.,'epistemic_state':'EXACT'} for x in names]
 def analyze(self,target:Path,out_dir:Path)->dict[str,Any]:
  target=Path(target)
  if not self.available():return {'ok':False,'available':False,'executed':False,'produced_evidence':False,'partial':False,'error':'jvm_workers_unavailable_or_hash_mismatch'}
  classes=self._classes(target)
  if not classes:return {'ok':False,'available':True,'executed':False,'produced_evidence':False,'partial':False,'error':'jvm_archive_missing_classes'}
  root=Path(out_dir)/'jvm_static'
  if root.exists():return {'ok':False,'available':True,'executed':False,'produced_evidence':False,'partial':False,'error':'jvm_evidence_already_exists'}
  root.mkdir(parents=True);source=root/'source';source.mkdir()
  try:
   run=run_bounded([str(self.java),'-Xms64m','-Xmx1024m','-jar',str(self.vineflower),'--silent=1',str(target),str(source)],timeout=120.,memory_limit_mb=1536,cpu_time_limit_s=120,cwd=str(root))
   decompiled=sorted(x.relative_to(source).as_posix() for x in source.rglob('*.java'))
   evidence=root/'summary.json';evidence.write_text(json.dumps({'schema':'jvm-static-evidence.v1','target':str(target),'classes':classes,'decompiled_files':decompiled,'worker':run,'limitations':['decompiled Java is not original source','no JVM execution performed']},sort_keys=True,ensure_ascii=False,indent=2),encoding='utf-8')
   good=run.get('returncode')==0 and not run.get('timed_out') and bool(decompiled)
   return {'ok':good,'available':True,'executed':True,'produced_evidence':evidence.is_file(),'partial':not good,'returncode':run.get('returncode'),'timed_out':bool(run.get('timed_out')),'classes':classes,'decompiled_files':decompiled,'report':str(evidence),'stderr_tail':str(run.get('stderr',''))[-2000:]}
  except (OSError,ValueError) as exc:
   shutil.rmtree(root,ignore_errors=True);return {'ok':False,'available':True,'executed':True,'produced_evidence':False,'partial':True,'error':f'jvm_worker_failed:{exc.__class__.__name__}'}
