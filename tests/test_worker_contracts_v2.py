import pytest
from aether_re.contracts import ContractViolation, validate_worker_plan, validate_worker_result
def plan(): return validate_worker_plan({"schema":"worker-plan.v1","worker":"ghidra","worker_version":"11.4","input_artifact_id":"sha256:"+"a"*64,"command":["analyzeHeadless","<workspace>","case"],"network":False,"timeout_s":120,"memory_mb":2048,"disk_mb":4096,"processes":8})
def test_success_requires_evidence():
    p=plan()
    with pytest.raises(ContractViolation,match='success_without_evidence'): validate_worker_result({"schema":"worker-result.v1","worker":"ghidra","state":"succeeded","plan_sha256":p.plan_sha256,"evidence":[],"losses":[],"stdout":"","stderr":"","returncode":0},plan=p,max_output_bytes=4096)
def test_plan_hash_changes():
    assert plan().plan_sha256 != validate_worker_plan({"schema":"worker-plan.v1","worker":"ghidra","worker_version":"11.4","input_artifact_id":"sha256:"+"a"*64,"command":["changed"],"network":False,"timeout_s":120,"memory_mb":2048,"disk_mb":4096,"processes":8}).plan_sha256