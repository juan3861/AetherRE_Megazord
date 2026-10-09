import pytest
from aether_re.contracts import ContractViolation, validate_capability_envelope, validate_loss_ledger, validate_worker_plan, validate_worker_result
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

def test_capability_envelope_is_versioned_and_fail_closed():
    value={"schema":"capability-envelope.v1","profile_id":"android-apk","formats":["APK","DEX"],"architectures":["dex"],"abis":["android"],"endianness":["little"],"runtimes":["ART"],"protections":["none"],"modalities":["static"],"limits":{"max_input_bytes":1048576,"max_depth":4,"timeout_s":60}}
    envelope=validate_capability_envelope(value)
    assert envelope.profile_id == "android-apk"
    with pytest.raises(ContractViolation,match="capability_profile_invalid"):
        validate_capability_envelope({**value,"profile_id":"android"})

def test_loss_ledger_requires_classified_non_overlapping_properties():
    value={"schema":"loss-ledger.v1","artifact_id":"sha256:"+"a"*64,"transformation":"jadx-normalize","preserved":["method-signatures"],"inferred":["source-structure"],"lost":["original-identifiers"],"evidence_refs":["ev-1"]}
    ledger=validate_loss_ledger(value)
    assert ledger.lost == ("original-identifiers",)
    with pytest.raises(ContractViolation,match="loss_ledger_overlap"):
        validate_loss_ledger({**value,"lost":["method-signatures"]})
