"""Fail-closed profile certificate denominator."""
from __future__ import annotations
import hashlib,json,re
from typing import Any
REQUIRED_MEASUREMENTS=('entities','relations','abstention','calibration','reproducibility')
def sha256_canonical(value:Any)->str:return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
def certify_static_profile(profile_scope:dict[str,Any],corpus:dict[str,Any],workers:dict[str,Any],evaluation:dict[str,Any],baseline:dict[str,Any])->dict[str,Any]:
 errors=[]
 if profile_scope.get('schema') not in {None,'profile-scope.v1'} or not profile_scope.get('profile_id'):errors.append({'code':'profile_scope_invalid'})
 if not corpus.get('blind_hash') or not corpus.get('calibration_hash') or corpus.get('blind_hash')==corpus.get('calibration_hash'):errors.append({'code':'sealed_corpus_invalid'})
 for worker in workers.get('workers',[]):
  if not re.fullmatch('[0-9a-f]{64}',str(worker.get('executable_sha256',''))) or not worker.get('license_spdx'):errors.append({'code':'worker_pin_invalid'})
 if not evaluation.get('oracle_independent'):errors.append({'code':'independent_oracle_missing'})
 for name in REQUIRED_MEASUREMENTS:
  if name not in evaluation or (name=='relations' and evaluation.get(name,{}).get('status')=='unmeasured'):errors.append({'code':f'{name}_unmeasured' if name!='relations' else 'relations_unmeasured'})
 if baseline.get('regressions'):errors.append({'code':'critical_regression'})
 return {'schema':'static-profile-certificate.v1','profile_id':profile_scope.get('profile_id','unknown'),'status':'QUITADA' if not errors else 'NAO_COMPROVADA','errors':errors,'measurements':evaluation,'worker_lock_sha256':sha256_canonical(workers),'limitations':sorted(evaluation.get('limitations',[]))}
