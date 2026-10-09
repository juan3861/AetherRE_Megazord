"""Verificador de alegações: IDs válidos não bastam sem suporte explícito."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aether_re.evidence_contract import validate_evidence_records
from aether_re.profile_scope import validate_claim_scope, validate_profile_scope


_SUPPORTING_STATES = {"observed", "supported", "confirmed"}


def _explicit_support(record: dict[str, Any]) -> bool:
    """Only explicit support in a non-negative validation state can support a claim."""
    if record.get("supports") is not True:
        return False
    state = record.get("validation_status")
    return state is None or state in _SUPPORTING_STATES


def validate_claims(
    claims: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    *,
    strict_evidence: bool = False,
    evidence_manifest: dict[str, Any] | None = None,
    profile_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    profile_report = validate_profile_scope(profile_scope) if profile_scope is not None else None
    if profile_report is not None and profile_report.get("status") != "valid":
        errors.append({"code": "profile_scope_invalid", "detail": f"{len(profile_report.get('errors', []))} profile error(s)"})
    if not isinstance(claims, list) or not isinstance(evidence, list):
        return {"schema": "claim-validation.v1", "strict_evidence": strict_evidence, "evidence_contract": None, "claims": [], "errors": [{"code": "claims_and_evidence_must_be_lists"}], "summary": {"total": 0, "supported": 0, "inconclusive": 0, "unsupported": 0}, "status": "invalid", "limitations": ["validar ID não prova que o conteúdo sustenta a frase", "modelo não pode promover alegação sem evidência"]}
    contract = validate_evidence_records(evidence, manifest=evidence_manifest, strict=True) if strict_evidence else None
    # In strict mode, a provenance contract failure is itself a validation
    # failure.  Merely embedding an invalid contract while leaving the claim
    # report ``complete`` would let downstream consumers accidentally treat an
    # untraceable run as clean (especially when no claim references the bad
    # record).  Keep the detailed contract errors nested, but surface a stable
    # top-level error/status for fail-closed automation.
    if strict_evidence and contract and contract.get("status") == "invalid":
        errors.append(
            {
                "code": "evidence_contract_invalid",
                "detail": f"{len(contract.get('errors', []))} provenance error(s)",
            }
        )
    invalid_ids = {str(item.get("evidence_id")) for item in (contract or {}).get("errors", []) if item.get("evidence_id")}
    catalog: dict[str, dict[str, Any]] = {}
    duplicate_ids: set[str] = set()
    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            errors.append({"index": index, "code": "evidence_not_object"})
            continue
        evidence_id = str(item.get("evidence_id", "")).strip()
        if not evidence_id:
            errors.append({"index": index, "code": "evidence_id_missing"})
            continue
        if evidence_id in catalog:
            duplicate_ids.add(evidence_id)
            errors.append({"index": index, "evidence_id": evidence_id, "code": "duplicate_evidence_id"})
            continue
        catalog[evidence_id] = item
    for evidence_id in duplicate_ids:
        catalog.pop(evidence_id, None)
    results: list[dict[str, Any]] = []
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            errors.append({"index": index, "code": "claim_not_object"})
            results.append({"statement": "", "verdict": "unsupported", "evidence_ids": [], "missing_evidence_ids": [], "counterevidence_ids": [], "review_required": True})
            continue
        raw_ids = claim.get("evidence_ids", [])
        if not isinstance(raw_ids, list):
            errors.append({"index": index, "code": "claim_evidence_ids_must_be_list"})
            raw_ids = []
        ids = [str(item) for item in raw_ids]
        if len(ids) != len(set(ids)):
            errors.append({"index": index, "code": "claim_evidence_ids_duplicated"})
            ids = list(dict.fromkeys(ids))
        statement = claim.get("statement", "")
        if not isinstance(statement, str) or not statement.strip():
            errors.append({"index": index, "code": "claim_statement_missing"})
        missing = [item for item in ids if item not in catalog]
        unsupported = [item for item in ids if item in catalog and (not _explicit_support(catalog[item]) or item in invalid_ids)]
        state = str(claim.get("state", "proposed"))
        if state not in {"proposed", "observed", "inferred", "supported", "confirmed", "unsupported", "inconclusive", "pending"}:
            errors.append({"index": index, "code": "claim_state_invalid", "state": state})
        counter_ids = claim.get("counterevidence_ids", [])
        if not isinstance(counter_ids, list):
            errors.append({"index": index, "code": "counterevidence_ids_must_be_list"})
            counter_ids = []
        counter_ids = [str(item) for item in counter_ids]
        scope_errors = []
        if profile_report is not None:
            if profile_report.get("status") == "valid":
                scope_errors = validate_claim_scope(claim, profile_report["scope"])
            else:
                scope_errors = [{"code": "profile_scope_invalid"}]
            for scope_error in scope_errors:
                errors.append({"index": index, **scope_error})
        counter_missing = [item for item in counter_ids if item not in catalog]
        counter_supported = [item for item in counter_ids if item in catalog and _explicit_support(catalog[item])]
        if missing or unsupported or counter_supported or scope_errors or not isinstance(statement, str) or not statement.strip():
            verdict = "unsupported"
        elif not ids and state == "confirmed":
            verdict = "unsupported"
        elif counter_missing:
            verdict = "inconclusive"
        elif ids and all(_explicit_support(catalog[item]) for item in ids):
            verdict = "supported"
        else:
            verdict = "inconclusive"
        results.append({"statement": statement if isinstance(statement, str) else "", "verdict": verdict, "evidence_ids": ids, "missing_evidence_ids": missing, "counterevidence_ids": counter_ids, "scope_errors": scope_errors, "review_required": verdict != "supported"})
    return {
        "schema": "claim-validation.v1",
        "strict_evidence": strict_evidence,
        "evidence_contract": contract,
        "profile_scope": profile_report,
        "claims": results,
        "errors": errors,
        "status": "invalid" if errors else "complete",
        "summary": {"total": len(results), "supported": sum(item["verdict"] == "supported" for item in results), "inconclusive": sum(item["verdict"] == "inconclusive" for item in results), "unsupported": sum(item["verdict"] == "unsupported" for item in results)},
        "limitations": ["validar ID não prova que o conteúdo sustenta a frase", "revisão humana/causal continua necessária para achados críticos", "modelo não pode promover alegação sem evidência"]
    }


def write_claim_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
