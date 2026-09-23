"""Fail-closed static profile certificate denominator."""
from __future__ import annotations
import hashlib, json, re
from typing import Any
REQUIRED_MEASUREMENTS=('entities','relations','abstention','calibration','reproducibility')
_SHA=re.compile(r'^[0-9a-f]{64}$')
_SPDX=re.compile(r'^[A-Za-z0-9][A-Za-z0-9.+-]*(?:\s+(?:OR|AND|WITH)\s+[A-Za-z0-9.+-]+)*$')
def sha256_canonical(value:Any)->str:return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
def _error(errors:list[dict[str,str]],code:str)->None:
 if not any(item['code']==code for item in errors): errors.append({'code':code})
def _measurement_valid(value:Any)->bool:
 return isinstance(value,dict) and value.get('status')=='measured' and any(key not in {'status','evidence_refs'} and item not in (None,'',[],{}) for key,item in value.items()) and isinstance(value.get('evidence_refs'),list) and bool(value['evidence_refs']) and all(isinstance(x,str) and x for x in value['evidence_refs'])
def certify_static_profile(profile_scope:dict[str,Any],corpus:dict[str,Any],workers:dict[str,Any],evaluation:dict[str,Any],baseline:dict[str,Any])->dict[str,Any]:
 errors=[]
 if not isinstance(profile_scope,dict) or profile_scope.get('schema')!='profile-scope.v1' or not isinstance(profile_scope.get('profile_id'),str) or not profile_scope['profile_id']:_error(errors,'profile_scope_invalid')
 if not isinstance(corpus,dict) or any(not isinstance(corpus.get(key),str) or not corpus[key] for key in ('development_hash','calibration_hash','blind_hash')) or len({corpus.get('development_hash'),corpus.get('calibration_hash'),corpus.get('blind_hash')})!=3:_error(errors,'sealed_corpus_invalid')
 worker_items=workers.get('workers') if isinstance(workers,dict) else None
 if not isinstance(worker_items,list) or not worker_items:_error(errors,'workers_missing')
 else:
  for worker in worker_items:
   if not isinstance(worker,dict) or not isinstance(worker.get('name'),str) or not _SHA.fullmatch(str(worker.get('executable_sha256',''))) or not isinstance(worker.get('version'),str) or not worker['version'] or not _SPDX.fullmatch(str(worker.get('license_spdx',''))) or not isinstance(worker.get('invocation'),list) or not worker['invocation']:_error(errors,'worker_pin_invalid')
 if not isinstance(evaluation,dict) or evaluation.get('oracle_independent') is not True:_error(errors,'independent_oracle_missing')
 if not isinstance(evaluation,dict) or not isinstance(evaluation.get('evidence_refs'),list) or not evaluation['evidence_refs'] or any(not isinstance(x,str) or not x for x in evaluation.get('evidence_refs',[])):_error(errors,'evaluation_evidence_missing')
 for name in REQUIRED_MEASUREMENTS:
  if not _measurement_valid(evaluation.get(name) if isinstance(evaluation,dict) else None):_error(errors,f'{name}_unmeasured')
 if not isinstance(baseline,dict) or baseline.get('regressions'):_error(errors,'critical_regression')
 return {'schema':'static-profile-certificate.v1','profile_id':profile_scope.get('profile_id','unknown') if isinstance(profile_scope,dict) else 'unknown','status':'QUITADA' if not errors else 'NAO_COMPROVADA','errors':errors,'measurements':evaluation,'worker_lock_sha256':sha256_canonical(workers if isinstance(workers,dict) else {}),'limitations':sorted(evaluation.get('limitations',[]) if isinstance(evaluation,dict) else [])}
