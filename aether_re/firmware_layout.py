"""Fail-closed qualification of raw firmware before static workers see it."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from typing import Any

def _hash(path:Path)->str:
 d=hashlib.sha256()
 with path.open('rb') as h:
  for part in iter(lambda:h.read(1<<20),b''):d.update(part)
 return d.hexdigest()

def qualify_firmware_layout(blob:Path, declaration:Path)->dict[str,Any]:
 """Validate a bound, non-overlapping layout; never infer target architecture."""
 try:
  raw=json.loads(Path(declaration).read_text(encoding='utf-8'));data=Path(blob).read_bytes()
  required={'schema','artifact_sha256','architecture','endianness','regions'}
  if not isinstance(raw,dict) or set(raw)!=required or raw.get('schema')!='firmware-layout.v1':raise ValueError('layout_schema_invalid')
  if raw['artifact_sha256']!=_hash(Path(blob)):raise ValueError('layout_artifact_hash_mismatch')
  if raw['architecture'] not in {'arm','aarch64','mips','riscv','x86','xtensa','avr'}:raise ValueError('layout_architecture_invalid')
  if raw['endianness'] not in {'little','big'}:raise ValueError('layout_endianness_invalid')
  regions=raw['regions'];used=[]
  if not isinstance(regions,list) or not regions:raise ValueError('layout_regions_invalid')
  for item in regions:
   if not isinstance(item,dict) or set(item)!={'name','offset','size','kind'} or not isinstance(item['name'],str) or not item['name'] or item['kind'] not in {'code','data','metadata','padding'}:raise ValueError('layout_regions_invalid')
   off,size=item['offset'],item['size']
   if isinstance(off,bool) or isinstance(size,bool) or not isinstance(off,int) or not isinstance(size,int) or off<0 or size<1 or off+size>len(data) or any(off<s+z and s<off+size for s,z in used):raise ValueError('layout_regions_invalid')
   used.append((off,size))
  return {'schema':'firmware-layout-qualification.v1','qualified':True,'artifact_sha256':raw['artifact_sha256'],'layout':raw,'limitations':['layout is declarative provenance, not an inferred architecture proof','no firmware execution performed']}
 except (OSError,UnicodeError,json.JSONDecodeError,ValueError) as exc:
  return {'schema':'firmware-layout-qualification.v1','qualified':False,'errors':[str(exc) or 'layout_invalid'],'limitations':['no firmware worker is authorized without a valid layout bound to exact bytes']}
