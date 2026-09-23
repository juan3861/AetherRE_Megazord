from aether_re.evidence_contract import validate_kernel_evidence
def test_manifest_bound_evidence():
 d='a'*64; m={'schema':'universal-intake-manifest.v1','case_id':'case-1','artifacts':[{'artifact_id':'sha256:'+d,'sha256':d}]}
 r={'schema':'kernel-evidence.v1','evidence_id':'ev-1','case_id':'case-1','artifact_id':'sha256:'+d,'artifact_sha256':d,'producer':{'name':'triage','version':'1','release':'builtin'},'method':'magic','location':{'offset':0,'length':4},'epistemic_state':'EXACT','confidence':None,'derivation_parents':['sha256:'+d],'limitations':[],'losses':[]}
 assert validate_kernel_evidence([r],manifest=m)['status']=='valid'