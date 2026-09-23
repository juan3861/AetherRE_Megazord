import pytest
from aether_re.contracts import ContractViolation, validate_worker_plan, validate_worker_result
def plan(): return validate_worker_plan({"schema":"worker-plan.v1","worker":"ghidra","worker_version":"11.4","input_artifact_id":"sha256:"+"a"*64,"command":["analyzeHeadless","<workspace>","case"],"network":False,"timeout_s":120,"memory_mb":2048,"disk_mb":4096,"processes":8})
def evidence(digest="a"*64):
    return {"schema":"kernel-evidence.v1","evidence_id":"ev-1","case_id":"case-1","artifact_id":"sha256:"+digest,"artifact_sha256":digest,"producer":{"name":"ghidra","version":"11.4","release":"test"},"method":"static","location":{"offset":0,"length":1},"epistemic_state":"EXACT","confidence":None,"derivation_parents":["sha256:"+digest],"limitations":[],"losses":[]}
def result(p, record):
    return {"schema":"worker-result.v1","worker":"ghidra","state":"succeeded","plan_sha256":p.plan_sha256,"evidence":[record],"losses":[],"stdout":"","stderr":"","returncode":0}
def test_success_requires_evidence():
    p=plan()
    with pytest.raises(ContractViolation,match='success_without_evidence'): validate_worker_result({"schema":"worker-result.v1","worker":"ghidra","state":"succeeded","plan_sha256":p.plan_sha256,"evidence":[],"losses":[],"stdout":"","stderr":"","returncode":0},plan=p,max_output_bytes=4096)
def test_plan_hash_changes():
    assert plan().plan_sha256 != validate_worker_plan({"schema":"worker-plan.v1","worker":"ghidra","worker_version":"11.4","input_artifact_id":"sha256:"+"a"*64,"command":["changed"],"network":False,"timeout_s":120,"memory_mb":2048,"disk_mb":4096,"processes":8}).plan_sha256

def test_worker_evidence_is_bound_to_planned_input_artifact():
    p=plan()
    accepted=validate_worker_result(result(p,evidence()),plan=p,max_output_bytes=4096)
    assert accepted.evidence[0]["artifact_id"] == p.input_artifact_id
    with pytest.raises(ContractViolation,match="worker_evidence_artifact_mismatch"):
        validate_worker_result(result(p,evidence("b"*64)),plan=p,max_output_bytes=4096)
