"""Validação do contrato de proveniência de evidências forenses."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SCHEMA = "evidence-validation.v1"
HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
VALIDATION_STATES = {"observed", "inferred", "supported", "confirmed", "unsupported", "inconclusive", "pending"}
REQUIRED = ("evidence_id", "run_id", "input_hash", "producer", "method", "validation_status")
STRICT_REQUIRED = ("target_identity", "source_span", "raw_artifact_hash", "assumptions", "limits", "dependencies")


def _error(evidence_id: str, code: str, detail: str = "") -> dict[str, str]:
    return {"evidence_id": evidence_id, "code": code, "detail": detail}


def validate_evidence_records(
    records: list[dict[str, Any]],
    *,
    manifest: dict[str, Any] | None = None,
    strict: bool = False,
) -> dict[str, Any]:
    """Validate provenance fields without deciding semantic truth."""
    if not isinstance(records, list):
        return {
            "schema": SCHEMA,
            "status": "invalid",
            "strict": strict,
            "sample_count": 0,
            "valid_count": 0,
            "invalid_count": 0,
            "records": [],
            "errors": [_error("<input>", "records_must_be_list")],
            "limitations": ["contrato valida forma/proveniência, não verdade semântica", "nenhum registro inválido é promovido"],
        }
    errors: list[dict[str, str]] = []
    valid: list[dict[str, Any]] = []
    seen: set[str] = set()
    manifest_hashes = {str(item.get("sha256")) for item in (manifest or {}).get("files", []) if isinstance(item, dict)}
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append(_error(f"<index:{index}>", "record_not_object"))
            continue
        evidence_id = str(record.get("evidence_id", f"<index:{index}>"))
        local: list[dict[str, str]] = []
        if evidence_id in seen:
            local.append(_error(evidence_id, "duplicate_evidence_id"))
        seen.add(evidence_id)
        for field in REQUIRED:
            if field not in record or record[field] in (None, "", []):
                local.append(_error(evidence_id, "required_field_missing", field))
        if record.get("input_hash") is not None and not HASH_RE.fullmatch(str(record["input_hash"])):
            local.append(_error(evidence_id, "input_hash_invalid"))
        if record.get("validation_status") not in VALIDATION_STATES:
            local.append(_error(evidence_id, "validation_status_invalid", str(record.get("validation_status"))))
        if "supports" in record and not isinstance(record["supports"], bool):
            local.append(_error(evidence_id, "supports_must_be_boolean"))
        if strict:
            for field in STRICT_REQUIRED:
                if field not in record or record[field] in (None, ""):
                    local.append(_error(evidence_id, "strict_field_missing", field))
            if "raw_artifact_hash" in record and not HASH_RE.fullmatch(str(record["raw_artifact_hash"])):
                local.append(_error(evidence_id, "raw_artifact_hash_invalid"))
            raw_artifact_hash = record.get("raw_artifact_hash")
            if raw_artifact_hash not in (None, "") and str(raw_artifact_hash) not in manifest_hashes:
                local.append(_error(evidence_id, "raw_artifact_not_in_manifest"))
            for field in ("assumptions", "limits", "dependencies"):
                if field in record and not isinstance(record[field], list):
                    local.append(_error(evidence_id, "strict_list_required", field))
            if "target_identity" in record and not isinstance(record["target_identity"], dict):
                local.append(_error(evidence_id, "target_identity_must_be_object"))
            if "source_span" in record and not isinstance(record["source_span"], dict):
                local.append(_error(evidence_id, "source_span_must_be_object"))
        if local:
            errors.extend(local)
        else:
            valid.append(record)
    status = "invalid" if errors else "valid" if valid else "insufficient_data"
    return {
        "schema": SCHEMA,
        "status": status,
        "strict": strict,
        "sample_count": len(records),
        "valid_count": len(valid),
        "invalid_count": len(records) - len(valid),
        "records": valid,
        "errors": errors,
        "limitations": ["contrato valida forma/proveniência, não verdade semântica", "hash relativo ao manifesto não prova autenticidade sem assinatura/custódia", "campos inferidos continuam exigindo revisão"],
    }


def load_evidence_file(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    records = value.get("evidence", value) if isinstance(value, (dict, list)) else []
    return records if isinstance(records, list) else []


def write_evidence_validation(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

KERNEL_SCHEMA = "evidence-kernel-validation.v1"

def validate_kernel_evidence(records: list[dict[str, Any]], *, manifest: dict[str, Any] | None) -> dict[str, Any]:
    """Validate hostile worker envelopes without coercing their claims."""
    allowed={"schema","evidence_id","case_id","artifact_id","artifact_sha256","producer","method","location","epistemic_state","confidence","derivation_parents","limitations","losses"}
    errors=[]; valid=[]; seen=set(); manifest_artifacts={}
    if manifest is not None:
        if not isinstance(manifest,dict) or manifest.get("schema")!="universal-intake-manifest.v1":
            return {"schema":KERNEL_SCHEMA,"status":"invalid","sample_count":0,"valid_count":0,"invalid_count":0,"records":[],"errors":[_error("<manifest>","manifest_invalid")]}
        for artifact in manifest.get("artifacts",[]):
            if isinstance(artifact,dict): manifest_artifacts[artifact.get("artifact_id")]=artifact.get("sha256")
        root=manifest.get("root_artifact")
        if isinstance(root,dict): manifest_artifacts[root.get("artifact_id")]=root.get("sha256")
    if not isinstance(records,list): return {"schema":KERNEL_SCHEMA,"status":"invalid","sample_count":0,"valid_count":0,"invalid_count":0,"records":[],"errors":[_error("<input>","records_must_be_list")]}
    from .kernel_contracts import EpistemicState, SHA256_RE, canonical_json
    for index,record in enumerate(records):
        evidence_id=record.get("evidence_id",f"<index:{index}>") if isinstance(record,dict) else f"<index:{index}>"; local=[]
        if not isinstance(record,dict): errors.append(_error(str(evidence_id),"record_not_object")); continue
        if set(record)-allowed: local.append(_error(str(evidence_id),"unknown_field"))
        if set(record)!=allowed: local.append(_error(str(evidence_id),"required_field_missing"))
        if evidence_id in seen: local.append(_error(str(evidence_id),"duplicate_evidence_id"))
        seen.add(evidence_id)
        if not isinstance(evidence_id,str) or not evidence_id: local.append(_error(str(evidence_id),"evidence_id_invalid"))
        if record.get("schema")!="kernel-evidence.v1": local.append(_error(str(evidence_id),"schema_invalid"))
        if manifest is not None and record.get("case_id") != manifest.get("case_id"): local.append(_error(str(evidence_id),"case_manifest_mismatch"))
        aid,digest=record.get("artifact_id"),record.get("artifact_sha256")
        if not isinstance(aid,str) or not isinstance(digest,str) or not SHA256_RE.fullmatch(digest) or aid != "sha256:"+digest: local.append(_error(str(evidence_id),"artifact_invalid"))
        elif manifest is not None and manifest_artifacts.get(aid)!=digest: local.append(_error(str(evidence_id),"artifact_manifest_mismatch"))
        producer=record.get("producer")
        if not isinstance(producer,dict) or set(producer)!={"name","version","release"} or any(not isinstance(x,str) or not x for x in producer.values()): local.append(_error(str(evidence_id),"producer_invalid"))
        if not isinstance(record.get("method"),str) or not record["method"]: local.append(_error(str(evidence_id),"method_invalid"))
        location=record.get("location")
        if not isinstance(location,dict) or set(location)!={"offset","length"} or any(isinstance(location.get(k),bool) or not isinstance(location.get(k),int) or location[k]<0 for k in ("offset","length")): local.append(_error(str(evidence_id),"location_invalid"))
        parents=record.get("derivation_parents")
        if not isinstance(parents,list) or not parents or any(not isinstance(x,str) or not x.startswith("sha256:") for x in parents) or len(parents)!=len(set(parents)): local.append(_error(str(evidence_id),"derivation_parent_missing"))
        for field in ("limitations","losses"):
            v=record.get(field)
            if not isinstance(v,list) or any(not isinstance(x,str) or not x for x in v): local.append(_error(str(evidence_id),f"{field}_invalid"))
        try: state=EpistemicState(record.get("epistemic_state"))
        except (TypeError,ValueError): local.append(_error(str(evidence_id),"epistemic_state_invalid")); state=None
        confidence=record.get("confidence")
        if state is EpistemicState.PROBABILISTIC_INFERENCE:
            if isinstance(confidence,bool) or not isinstance(confidence,(int,float)) or not 0<=confidence<=1: local.append(_error(str(evidence_id),"confidence_invalid"))
        elif confidence is not None: local.append(_error(str(evidence_id),"confidence_forbidden"))
        try:
            if len(canonical_json(record))>1024*1024: local.append(_error(str(evidence_id),"record_budget_exceeded"))
        except Exception: local.append(_error(str(evidence_id),"record_encoding_invalid"))
        if local: errors.extend(local)
        else: valid.append(record)
    return {"schema":KERNEL_SCHEMA,"status":"invalid" if errors else "valid" if valid else "insufficient_data","sample_count":len(records),"valid_count":len(valid),"invalid_count":len(records)-len(valid),"records":valid,"errors":errors}
