"""Pinned static-only Android APK extraction worker; it never executes an APK."""
from __future__ import annotations
import hashlib, json, os, re, shutil
from pathlib import Path
from typing import Any
from aether_re.adapters._static_base import doc
from aether_re.adapters.base import Adapter
from aether_re.process import run_bounded

def normalize_android(jadx:dict,apktool:dict,artifact_id:str,evidence_refs:tuple[str,str]):
 payload={**apktool,**jadx}; payload['components']=apktool.get('components',apktool.get('manifest_components',[]));payload['native_children']=apktool.get('native_children',[])
 losses=('resource_name_conflict',) if apktool.get('resource_conflicts') else ()
 return doc('android-apk',artifact_id,evidence_refs,payload,'dex',{'components':'android_component','methods':'dex_method','resources':'resource','native_children':'native_child_artifact'},losses)

class AndroidAdapter(Adapter):
 name='android'
 _JAVA=Path(r'C:\Program Files\Android\Android Studio\jbr\bin\java.exe'); _JAVA_SHA256='478ab50b6ca350b71d3174c201c1e4bd93c2c255ab6e0e9ab4465a5d322260aa'
 _JADX=Path(r'E:\AetherRE_Toolchain\packages\jadx-1.5.6\lib\jadx-1.5.6-all.jar'); _JADX_SHA256='fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b'
 _APKTOOL=Path(r'E:\AetherRE_Toolchain\packages\apktool-3.0.3\apktool_3.0.3.jar'); _APKTOOL_SHA256='dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423'
 def __init__(self,*,java:str|None=None,jadx:str|None=None,apktool:str|None=None)->None:
  self.java=Path(java or os.environ.get('AETHER_JAVA_BIN','') or self._JAVA);self.jadx=Path(jadx or os.environ.get('AETHER_JADX_JAR','') or self._JADX);self.apktool=Path(apktool or os.environ.get('AETHER_APKTOOL_JAR','') or self._APKTOOL)
 @staticmethod
 def _matches(path:Path,digest:str)->bool:
  try:return path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==digest
  except OSError:return False
 def available(self)->bool:return self._matches(self.java,self._JAVA_SHA256) and self._matches(self.jadx,self._JADX_SHA256) and self._matches(self.apktool,self._APKTOOL_SHA256)
 @staticmethod
 def _manifest_components(path:Path)->list[dict[str,str]]:
  if not path.is_file():return []
  pattern=r'<(activity|service|receiver|provider|application)\b[^>]*(?:android:)?name="([^"]+)"'
  return [{'name':f'{kind}:{name}','kind':kind,'source_backend':'apktool','confidence':1.0,'epistemic_state':'EXACT'} for kind,name in re.findall(pattern,path.read_text(encoding='utf-8',errors='replace'))]
 @staticmethod
 def _source_summary(root:Path)->list[dict[str,Any]]:
  return [{'name':item.stem,'path':item.relative_to(root).as_posix(),'source_backend':'jadx','confidence':.7,'epistemic_state':'PROBABILISTIC_INFERENCE'} for item in sorted(root.rglob('*.java'))[:10000]] if root.is_dir() else []
 def analyze(self,target:Path,out_dir:Path)->dict[str,Any]:
  target=Path(target)
  if not self.available():return {'ok':False,'available':False,'executed':False,'produced_evidence':False,'partial':False,'error':'android_workers_unavailable_or_hash_mismatch'}
  try:
   if target.read_bytes()[:4]!=b'PK\x03\x04':return {'ok':False,'available':True,'executed':False,'produced_evidence':False,'partial':False,'error':'apk_zip_magic_missing'}
  except OSError:return {'ok':False,'available':True,'executed':False,'produced_evidence':False,'partial':False,'error':'apk_input_unreadable'}
  root=Path(out_dir)/'android_static'
  if root.exists():return {'ok':False,'available':True,'executed':False,'produced_evidence':False,'partial':False,'error':'android_evidence_already_exists'}
  jadx_out,apktool_out=root/'jadx',root/'apktool';root.mkdir(parents=True);common={'timeout':180.,'memory_limit_mb':2048,'cpu_time_limit_s':180,'cwd':str(root)}
  try:
   # Explicit JVM ceilings make the external process tree attributable to this
   # run and prevent an APK from silently consuming the host heap indefinitely.
   jadx_run=run_bounded([str(self.java),'-Xms64m','-Xmx1536m','-jar',str(self.jadx),'-d',str(jadx_out),str(target)],**common);apktool_run=run_bounded([str(self.java),'-Xms64m','-Xmx1024m','-jar',str(self.apktool),'d','-f','-o',str(apktool_out),str(target)],**common)
   methods=self._source_summary(jadx_out/'sources');components=self._manifest_components(apktool_out/'AndroidManifest.xml');evidence=root/'summary.json';evidence.write_text(json.dumps({'schema':'android-static-evidence.v1','target':str(target),'methods':methods,'components':components,'jadx':jadx_run,'apktool':apktool_run,'limitations':['decompiled Java is not original source','no APK execution performed']},sort_keys=True,ensure_ascii=False,indent=2),encoding='utf-8')
   good=jadx_run.get('returncode')==0 and apktool_run.get('returncode')==0 and not jadx_run.get('timed_out') and not apktool_run.get('timed_out')
   return {'ok':good,'available':True,'executed':True,'produced_evidence':evidence.is_file(),'partial':not good,'returncode':[jadx_run.get('returncode'),apktool_run.get('returncode')],'timed_out':bool(jadx_run.get('timed_out') or apktool_run.get('timed_out')),'components':components,'methods':methods,'report':str(evidence),'stderr_tail':(str(jadx_run.get('stderr',''))+'\n'+str(apktool_run.get('stderr','')))[-2000:]}
  except (OSError,ValueError) as exc:
   shutil.rmtree(root,ignore_errors=True);return {'ok':False,'available':True,'executed':True,'produced_evidence':False,'partial':True,'error':f'android_worker_failed:{exc.__class__.__name__}'}
