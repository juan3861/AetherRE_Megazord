"""Fail-closed profile scope for forensic claims.

A profile bounds languages, formats and architectures before evaluation.  It
prevents a measured profile from being marketed as universal coverage.
"""

from __future__ import annotations

from typing import Any

SCHEMA = "profile-scope.v1"
_LIST_FIELDS = ("languages", "formats", "architectures", "toolchain", "exclusions")

def _list_field(scope: dict[str, Any], field: str, errors: list[dict[str, Any]], *, required: bool = True) -> list[str]:
    value = scope.get(field)
    if not isinstance(value, list) or (required and not value) or any(not isinstance(item, str) or not item.strip() for item in value):
        errors.append({"code": "profile_scope_list_invalid", "field": field})
        return []
    normalized = [item.strip() for item in value]
    if len(normalized) != len(set(normalized)):
        errors.append({"code": "profile_scope_list_duplicate", "field": field})
    return normalized

def validate_profile_scope(scope: Any) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    if not isinstance(scope, dict):
        return {"schema": SCHEMA, "status": "invalid", "scope": {}, "errors": [{"code": "profile_scope_must_be_object"}], "limitations": ["perfil delimitado não é cobertura universal"]}
    profile_id = scope.get("profile_id")
    if not isinstance(profile_id, str) or not profile_id.strip():
        errors.append({"code": "profile_id_missing"})
        profile_id = ""
    else:
        profile_id = profile_id.strip()
    normalized: dict[str, Any] = {"profile_id": profile_id}
    for field in _LIST_FIELDS:
        normalized[field] = _list_field(scope, field, errors, required=field != "exclusions")
    frozen_at = scope.get("frozen_at")
    if not isinstance(frozen_at, str) or not frozen_at.strip():
        errors.append({"code": "profile_frozen_at_missing"})
        frozen_at = ""
    normalized["frozen_at"] = frozen_at.strip() if isinstance(frozen_at, str) else ""
    universal = scope.get("universal", False)
    if universal is not False:
        errors.append({"code": "universal_profile_forbidden"})
    normalized["universal"] = False
    return {"schema": SCHEMA, "status": "invalid" if errors else "valid", "scope": normalized, "errors": errors, "limitations": ["escopo mede somente os itens declarados", "exclusões não são resultados negativos", "perfil válido não prova equivalência semântica ou ausência universal de falhas"]}

def validate_claim_scope(claim: Any, profile_scope: dict[str, Any]) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    if not isinstance(claim, dict):
        return [{"code": "claim_scope_claim_not_object"}]
    scope_id = claim.get("scope_id")
    if not isinstance(scope_id, str) or not scope_id.strip():
        errors.append({"code": "claim_scope_missing"})
    elif scope_id.strip() != profile_scope.get("profile_id"):
        errors.append({"code": "claim_scope_mismatch", "expected": profile_scope.get("profile_id"), "received": scope_id.strip()})
    if claim.get("universal") is True:
        errors.append({"code": "universal_claim_forbidden"})
    elif "universal" in claim and not isinstance(claim.get("universal"), bool):
        errors.append({"code": "claim_universal_must_be_boolean"})
    return errors
