"""Contratos versionados para estados de adapters e alegações."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


ADAPTER_STATES = {
    "unavailable", "skipped", "queued", "running", "succeeded",
    "partial", "failed", "timed_out", "cancelled",
}


@dataclass(frozen=True)
class AdapterResultContract:
    schema: str
    name: str
    state: str
    available: bool
    executed: bool
    produced_evidence: bool
    partial: bool
    error: str = ""

    def validate(self) -> None:
        if self.schema != "adapter-result.v1":
            raise ValueError("adapter_schema_mismatch")
        if self.state not in ADAPTER_STATES:
            raise ValueError(f"adapter_state_invalid:{self.state}")
        if self.state == "unavailable" and (self.available or self.executed or self.produced_evidence):
            raise ValueError("unavailable_state_inconsistent")
        if self.state == "succeeded" and (not self.executed or not self.produced_evidence or self.partial):
            raise ValueError("succeeded_state_inconsistent")
        if self.state == "timed_out" and not self.partial:
            raise ValueError("timeout_must_be_partial")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def adapter_state(result: dict[str, Any]) -> str:
    """Deriva estado terminal sem apagar os flags de capacidade/execução."""
    if not result.get("available", False):
        return "unavailable"
    if result.get("timed_out"):
        return "timed_out"
    if result.get("resource_exceeded"):
        return "failed"
    if result.get("cancelled"):
        return "cancelled"
    if result.get("ok") and result.get("executed") and result.get("produced_evidence") and not result.get("partial"):
        return "succeeded"
    if result.get("executed") and result.get("partial"):
        return "partial"
    if result.get("executed") and not result.get("ok"):
        return "failed"
    return "skipped"


def validate_adapter_result(name: str, result: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(result)
    normalized.setdefault("schema", "adapter-result.v1")
    normalized.setdefault("state", adapter_state(normalized))
    contract = AdapterResultContract(
        schema=normalized["schema"], name=name, state=normalized["state"],
        available=bool(normalized.get("available")), executed=bool(normalized.get("executed")),
        produced_evidence=bool(normalized.get("produced_evidence")), partial=bool(normalized.get("partial")),
        error=str(normalized.get("error", "")),
    )
    contract.validate()
    return normalized

# Versioned worker lifecycle contracts.  The v1 adapter API above remains untouched.
import hashlib
from dataclasses import field
from typing import Mapping, Protocol, Sequence, runtime_checkable
from .kernel_contracts import ArtifactRef, SHA256_RE, canonical_json

class ContractViolation(ValueError):
    pass

WORKER_STATES=frozenset({"succeeded","partial","failed","timed_out","oom","cancelled","malformed_output","unavailable","skipped"})
CANONICAL_PROFILE_IDS=frozenset({"native-pe","native-elf","dotnet","jvm","android-apk","wasm","macho","firmware"})

@runtime_checkable
class WorkerAdapter(Protocol):
    def probe(self) -> Mapping[str, Any]: ...
    def supports(self, profile_id: str, architecture: str) -> bool: ...
    def plan(self, artifact: ArtifactRef, profile_id: str) -> Mapping[str, Any]: ...
    def run(self, plan: "WorkerPlan") -> Mapping[str, Any]: ...
    def normalize(self, result: "WorkerResult") -> Sequence[Mapping[str, Any]]: ...
    def validate(self, result: "WorkerResult") -> None: ...
    def cleanup(self) -> None: ...

def _strict_string(value: Any, code: str) -> str:
    if not isinstance(value,str) or not value.strip(): raise ContractViolation(code)
    return value

def _strict_int(value: Any, code: str, maximum: int) -> int:
    if isinstance(value,bool) or not isinstance(value,int) or not 0<value<=maximum: raise ContractViolation(code)
    return value

@dataclass(frozen=True)
class WorkerProbe:
    schema: str; worker: str; worker_version: str; executable_sha256: str; license: str; capabilities: tuple[str,...]

@dataclass(frozen=True)
class WorkerPlan:
    schema: str; worker: str; worker_version: str; input_artifact_id: str; command: tuple[str,...]; network: bool; timeout_s: int; memory_mb: int; disk_mb: int; processes: int; plan_sha256: str
    def canonical(self) -> dict[str,Any]:
        return {"schema":self.schema,"worker":self.worker,"worker_version":self.worker_version,"input_artifact_id":self.input_artifact_id,"command":list(self.command),"network":self.network,"timeout_s":self.timeout_s,"memory_mb":self.memory_mb,"disk_mb":self.disk_mb,"processes":self.processes}

@dataclass(frozen=True)
class WorkerResult:
    schema: str; worker: str; state: str; plan_sha256: str; evidence: tuple[Mapping[str,Any],...]; losses: tuple[str,...]; stdout: str; stderr: str; returncode: int|None

@dataclass(frozen=True)
class CapabilityEnvelope:
    schema: str; profile_id: str; formats: tuple[str,...]; architectures: tuple[str,...]; abis: tuple[str,...]; endianness: tuple[str,...]; runtimes: tuple[str,...]; protections: tuple[str,...]; modalities: tuple[str,...]; limits: Mapping[str,int]

@dataclass(frozen=True)
class LossLedger:
    schema: str; artifact_id: str; transformation: str; preserved: tuple[str,...]; inferred: tuple[str,...]; lost: tuple[str,...]; evidence_refs: tuple[str,...]

def _string_list(value: Any, code: str, *, allow_empty: bool = False) -> tuple[str,...]:
    if not isinstance(value,list) or (not allow_empty and not value) or any(not isinstance(x,str) or not x.strip() for x in value):
        raise ContractViolation(code)
    items=tuple(x.strip() for x in value)
    if len(items)!=len(set(items)): raise ContractViolation(code)
    return items

def validate_capability_envelope(value: Mapping[str,Any]) -> CapabilityEnvelope:
    required={"schema","profile_id","formats","architectures","abis","endianness","runtimes","protections","modalities","limits"}
    if not isinstance(value,Mapping) or set(value)!=required or value.get("schema")!="capability-envelope.v1": raise ContractViolation("capability_envelope_schema_invalid")
    profile=value.get("profile_id")
    if profile not in CANONICAL_PROFILE_IDS: raise ContractViolation("capability_profile_invalid")
    limits=value.get("limits")
    if not isinstance(limits,Mapping) or set(limits)!={"max_input_bytes","max_depth","timeout_s"} or any(isinstance(v,bool) or not isinstance(v,int) or v<1 for v in limits.values()): raise ContractViolation("capability_limits_invalid")
    return CapabilityEnvelope("capability-envelope.v1",profile,_string_list(value.get("formats"),"capability_formats_invalid"),_string_list(value.get("architectures"),"capability_architectures_invalid"),_string_list(value.get("abis"),"capability_abis_invalid"),_string_list(value.get("endianness"),"capability_endianness_invalid"),_string_list(value.get("runtimes"),"capability_runtimes_invalid"),_string_list(value.get("protections"),"capability_protections_invalid"),_string_list(value.get("modalities"),"capability_modalities_invalid"),dict(limits))

def validate_loss_ledger(value: Mapping[str,Any]) -> LossLedger:
    required={"schema","artifact_id","transformation","preserved","inferred","lost","evidence_refs"}
    if not isinstance(value,Mapping) or set(value)!=required or value.get("schema")!="loss-ledger.v1": raise ContractViolation("loss_ledger_schema_invalid")
    artifact=value.get("artifact_id")
    if not isinstance(artifact,str) or not artifact.startswith("sha256:") or not SHA256_RE.fullmatch(artifact[7:]): raise ContractViolation("loss_ledger_artifact_invalid")
    preserved=_string_list(value.get("preserved"),"loss_ledger_properties_invalid",allow_empty=True)
    inferred=_string_list(value.get("inferred"),"loss_ledger_properties_invalid",allow_empty=True)
    lost=_string_list(value.get("lost"),"loss_ledger_properties_invalid",allow_empty=True)
    if (set(preserved)&set(inferred)) or (set(preserved)&set(lost)) or (set(inferred)&set(lost)): raise ContractViolation("loss_ledger_overlap")
    if not (preserved or inferred or lost): raise ContractViolation("loss_ledger_properties_invalid")
    return LossLedger("loss-ledger.v1",artifact,_strict_string(value.get("transformation"),"loss_ledger_transformation_invalid"),preserved,inferred,lost,_string_list(value.get("evidence_refs"),"loss_ledger_evidence_invalid"))

def validate_worker_probe(value: Mapping[str,Any]) -> WorkerProbe:
    required={"schema","worker","worker_version","executable_sha256","license","capabilities"}
    if not isinstance(value,Mapping) or set(value)!=required or value.get("schema")!="worker-probe.v1": raise ContractViolation("worker_probe_schema_invalid")
    caps=value.get("capabilities")
    if not isinstance(caps,list) or any(not isinstance(x,str) or not x for x in caps) or len(set(caps))!=len(caps): raise ContractViolation("worker_probe_capabilities_invalid")
    digest=value.get("executable_sha256")
    if not isinstance(digest,str) or not SHA256_RE.fullmatch(digest): raise ContractViolation("worker_probe_hash_invalid")
    return WorkerProbe("worker-probe.v1",_strict_string(value.get("worker"),"worker_invalid"),_strict_string(value.get("worker_version"),"worker_version_invalid"),digest,_strict_string(value.get("license"),"worker_license_invalid"),tuple(caps))

def validate_worker_plan(value: Mapping[str,Any]) -> WorkerPlan:
    required={"schema","worker","worker_version","input_artifact_id","command","network","timeout_s","memory_mb","disk_mb","processes"}
    if not isinstance(value,Mapping) or set(value) != required and set(value) != required|{"plan_sha256"} or value.get("schema")!="worker-plan.v1": raise ContractViolation("worker_plan_schema_invalid")
    artifact=value.get("input_artifact_id"); command=value.get("command")
    if not isinstance(artifact,str) or not artifact.startswith("sha256:") or not SHA256_RE.fullmatch(artifact[7:]): raise ContractViolation("worker_plan_artifact_invalid")
    if not isinstance(command,list) or not command or any(not isinstance(x,str) or not x for x in command): raise ContractViolation("worker_command_invalid")
    if value.get("network") is not False: raise ContractViolation("worker_network_forbidden")
    plan0=WorkerPlan("worker-plan.v1",_strict_string(value.get("worker"),"worker_invalid"),_strict_string(value.get("worker_version"),"worker_version_invalid"),artifact,tuple(command),False,_strict_int(value.get("timeout_s"),"worker_resource_invalid",86400),_strict_int(value.get("memory_mb"),"worker_resource_invalid",1048576),_strict_int(value.get("disk_mb"),"worker_resource_invalid",1048576),_strict_int(value.get("processes"),"worker_resource_invalid",4096),"")
    digest=hashlib.sha256(canonical_json(plan0.canonical())).hexdigest()
    if "plan_sha256" in value and value["plan_sha256"] != digest: raise ContractViolation("worker_plan_hash_invalid")
    return WorkerPlan(plan0.schema,plan0.worker,plan0.worker_version,plan0.input_artifact_id,plan0.command,plan0.network,plan0.timeout_s,plan0.memory_mb,plan0.disk_mb,plan0.processes,digest)

def validate_worker_result(value: Mapping[str,Any], *, plan: WorkerPlan, max_output_bytes: int) -> WorkerResult:
    required={"schema","worker","state","plan_sha256","evidence","losses","stdout","stderr","returncode"}
    if not isinstance(value,Mapping) or set(value)!=required or value.get("schema")!="worker-result.v1": raise ContractViolation("worker_result_schema_invalid")
    if value.get("worker") != plan.worker: raise ContractViolation("worker_mismatch")
    if value.get("plan_sha256") != plan.plan_sha256: raise ContractViolation("plan_hash_mismatch")
    if isinstance(max_output_bytes,bool) or not isinstance(max_output_bytes,int) or max_output_bytes<1: raise ContractViolation("worker_output_budget_exceeded")
    stdout,stderr=value.get("stdout"),value.get("stderr")
    if not isinstance(stdout,str) or not isinstance(stderr,str) or len(stdout.encode("utf-8"))+len(stderr.encode("utf-8"))>max_output_bytes: raise ContractViolation("worker_output_budget_exceeded")
    state=value.get("state"); evidence=value.get("evidence"); losses=value.get("losses")
    if state not in WORKER_STATES: raise ContractViolation("worker_state_invalid")
    if not isinstance(evidence,list) or not isinstance(losses,list) or any(not isinstance(x,str) or not x for x in losses): raise ContractViolation("worker_result_invalid")
    try: encoded=canonical_json({"evidence":evidence})
    except Exception as exc: raise ContractViolation("worker_evidence_invalid") from exc
    if len(encoded)>max_output_bytes: raise ContractViolation("worker_output_budget_exceeded")
    if state=="succeeded" and not evidence: raise ContractViolation("success_without_evidence")
    if evidence:
        from .evidence_contract import validate_kernel_evidence
        report=validate_kernel_evidence(evidence,manifest=None)
        if report["status"]!="valid": raise ContractViolation("worker_evidence_invalid")
        expected_artifact_id = plan.input_artifact_id
        expected_artifact_sha256 = expected_artifact_id.removeprefix("sha256:")
        for record in evidence:
            if (
                record.get("artifact_id") != expected_artifact_id
                or record.get("artifact_sha256") != expected_artifact_sha256
            ):
                raise ContractViolation("worker_evidence_artifact_mismatch")
    rc=value.get("returncode")
    if rc is not None and (isinstance(rc,bool) or not isinstance(rc,int)): raise ContractViolation("worker_returncode_invalid")
    return WorkerResult("worker-result.v1",plan.worker,state,plan.plan_sha256,tuple(evidence),tuple(losses),stdout,stderr,rc)
