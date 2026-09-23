from __future__ import annotations
from aether_re.adapters._static_base import doc
def normalize_android(jadx:dict,apktool:dict,artifact_id:str,evidence_refs:tuple[str,str]):
 payload={**apktool,**jadx}; payload['components']=apktool.get('components',apktool.get('manifest_components',[]));payload['native_children']=apktool.get('native_children',[])
 losses=('resource_name_conflict',) if apktool.get('resource_conflicts') else ()
 return doc('android-apk',artifact_id,evidence_refs,payload,'dex',{'components':'android_component','methods':'dex_method','resources':'resource','native_children':'native_child_artifact'},losses)
class AndroidAdapter:
 name='android'
 def available(self):return False
