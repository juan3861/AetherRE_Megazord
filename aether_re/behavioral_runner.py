"""Fail-closed reconstruction candidate and guest-observation orchestration."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Mapping

from aether_re.dynamic_lab_contracts import DynamicLabHandoff
from aether_re.differential import compare_observations
from aether_re.kernel_contracts import ContractError

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CANDIDATE_SCHEMA = "reconstruction-candidate.v1"
_CASE_SCHEMA = "behavior-cases.v1"
_RUN_SCHEMA = "behavioral-run.v1"
_RESULT_SCHEMA = "guest-pair-result.v1"
_STATUSES = {"candidate", "pseudo_source_only", "unsupported", "partial"}
_MAX_CASES = 10_000


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json_loads(data: str) -> Any:
    """Decode JSON while refusing duplicate object keys and non-finite numbers."""
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique_pairs, parse_constant=lambda _x: (_ for _ in ()).throw(ValueError("non_finite_json")))


def _error(code: str, **details: Any) -> dict[str, Any]:
    return {"code": code, **details}


def _within(root: Path, raw_path: Any) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("artifact_path_invalid")
    # Manifest paths are portable POSIX-relative paths; reject drive roots and traversal.
    posix, windows = PurePosixPath(raw_path), PureWindowsPath(raw_path)
    if posix.is_absolute() or windows.is_absolute() or windows.drive or ".." in posix.parts or ".." in windows.parts:
        raise ValueError("artifact_path_escape")
    path = (root / Path(*posix.parts)).resolve(strict=True)
    resolved_root = root.resolve(strict=True)
    if path != resolved_root and resolved_root not in path.parents:
        raise ValueError("artifact_path_escape")
    if not path.is_file():
        raise ValueError("artifact_not_file")
    return path


def _read_bounded_artifact(path: Path, max_bytes: int, name: str) -> bytes:
    """Read no more than the artifact's declared budget plus one sentinel byte."""
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{name}_size_exceeded")
    return data


def _artifact(root: Path, value: Any, name: str, max_bytes: int) -> tuple[bytes, dict[str, str]]:
    if not isinstance(value, Mapping) or set(value) != {"path", "sha256"}:
        raise ValueError(f"{name}_descriptor_invalid")
    expected = value.get("sha256")
    if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
        raise ValueError(f"{name}_sha256_invalid")
    path = _within(root, value.get("path"))
    data = _read_bounded_artifact(path, max_bytes, name)
    actual = _digest(data)
    if actual != expected:
        raise ValueError("artifact_hash_mismatch")
    return data, {"path": str(value["path"]), "sha256": actual}


def _case_rows(raw: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    if not isinstance(raw, dict) or set(raw) != {"schema", "cases"} or raw.get("schema") != _CASE_SCHEMA or not isinstance(raw.get("cases"), list):
        return [], [_error("case_manifest_invalid")]
    cases = raw["cases"]
    if not cases or len(cases) > _MAX_CASES:
        return [], [_error("case_count_invalid", count=len(cases), max=_MAX_CASES)]
    seen_ids: set[str] = set()
    seen_inputs: set[bytes] = set()
    valid: list[dict[str, Any]] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != {"case_id", "input"}:
            errors.append(_error("case_shape_invalid", index=index))
            continue
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            errors.append(_error("case_id_invalid", index=index))
            continue
        try:
            canonical_input = _canonical(case["input"])
        except (TypeError, ValueError):
            errors.append(_error("case_input_not_canonical_json", index=index))
            continue
        if case_id in seen_ids:
            errors.append(_error("duplicate_case_id", case_id=case_id))
        if canonical_input in seen_inputs:
            errors.append(_error("duplicate_input", case_id=case_id))
        seen_ids.add(case_id)
        seen_inputs.add(canonical_input)
        valid.append({"case_id": case_id, "input": case["input"], "input_sha256": _digest(canonical_input)})
    return valid, errors


def validate_candidate(candidate: Any, artifact_root: str | Path, *, case_manifest_path: str | Path | None = None) -> dict[str, Any]:
    """Validate typed candidate provenance and all bound local artifact hashes."""
    errors: list[dict[str, Any]] = []
    hashes: dict[str, str] = {}
    if not isinstance(candidate, dict):
        return {"schema": "reconstruction-candidate-validation.v1", "status": "invalid", "errors": [_error("candidate_must_be_object")], "hashes": hashes}
    if set(candidate) != {"schema", "status", "original", "candidate", "toolchain", "reconstruction_evidence", "input_manifest"} or candidate.get("schema") != _CANDIDATE_SCHEMA:
        errors.append(_error("candidate_schema_invalid"))
    if candidate.get("status") not in _STATUSES:
        errors.append(_error("candidate_status_invalid"))
    root = Path(artifact_root)
    descriptors = (("original_source", candidate.get("original", {}).get("source") if isinstance(candidate.get("original"), dict) else None, 16 * 1024 * 1024),
                   ("original_binary", candidate.get("original", {}).get("binary") if isinstance(candidate.get("original"), dict) else None, 128 * 1024 * 1024),
                   ("candidate_source", candidate.get("candidate", {}).get("source") if isinstance(candidate.get("candidate"), dict) else None, 16 * 1024 * 1024),
                   ("candidate_binary", candidate.get("candidate", {}).get("binary") if isinstance(candidate.get("candidate"), dict) else None, 128 * 1024 * 1024),
                   ("toolchain", candidate.get("toolchain"), 8 * 1024 * 1024),
                   ("reconstruction_evidence", candidate.get("reconstruction_evidence"), 8 * 1024 * 1024),
                   ("input_manifest", candidate.get("input_manifest"), 4 * 1024 * 1024))
    loaded: dict[str, bytes] = {}
    for name, descriptor, budget in descriptors:
        try:
            data, entry = _artifact(root, descriptor, name, budget)
            loaded[name] = data
            hashes[name] = entry["sha256"]
        except (OSError, ValueError) as exc:
            errors.append(_error(str(exc) if str(exc).startswith(("artifact_", "original_", "candidate_", "toolchain_", "input_")) else "artifact_unreadable", artifact=name))
    input_path: Path | None = None
    if isinstance(candidate.get("input_manifest"), dict) and isinstance(candidate["input_manifest"].get("path"), str):
        try:
            input_path = _within(root, candidate["input_manifest"]["path"])
            if case_manifest_path is not None and input_path != Path(case_manifest_path).resolve(strict=True):
                errors.append(_error("case_manifest_path_mismatch"))
        except (OSError, ValueError) as exc:
            errors.append(_error(str(exc) if str(exc).startswith("artifact_") else "input_manifest_unreadable"))
    candidate_source = loaded.get("candidate_source", b"")
    if candidate.get("status") == "candidate" and (b"pseudo_source_only" in candidate_source.lower() or b"pseudo-fonte reconstruida" in candidate_source.lower()):
        errors.append(_error("candidate_pseudo_source_marked"))
    case_data: dict[str, Any] | None = None
    if "input_manifest" in loaded:
        try:
            case_data = strict_json_loads(loaded["input_manifest"].decode("utf-8"))
        except (UnicodeError, ValueError, json.JSONDecodeError):
            errors.append(_error("case_manifest_unreadable"))
    cases, case_errors = _case_rows(case_data)
    errors.extend(case_errors)
    if errors:
        return {"schema": "reconstruction-candidate-validation.v1", "status": "invalid", "candidate_status": candidate.get("status"), "errors": errors, "hashes": hashes}
    manifest_hash = _digest(_canonical(candidate))
    return {"schema": "reconstruction-candidate-validation.v1", "status": "verified", "candidate_status": candidate["status"], "manifest_sha256": manifest_hash, "hashes": hashes, "cases": cases, "case_manifest_sha256": hashes["input_manifest"]}


def _validate_output(value: Any, *, max_output_bytes: int) -> tuple[dict[str, Any] | None, str | None]:
    fields = {"stdout", "stderr", "exit_code", "exception", "timeout", "effects"}
    if not isinstance(value, dict) or set(value) != fields:
        return None, "guest_observation_shape_invalid"
    for field in ("stdout", "stderr"):
        if not isinstance(value[field], str) or len(value[field].encode("utf-8")) > max_output_bytes:
            return None, "guest_output_invalid_or_over_budget"
    code = value["exit_code"]
    if code is not None and (isinstance(code, bool) or not isinstance(code, int)):
        return None, "guest_exit_code_invalid"
    if not isinstance(value["timeout"], bool):
        return None, "guest_timeout_flag_invalid"
    if value["exception"] is not None and not isinstance(value["exception"], dict):
        return None, "guest_exception_invalid"
    try:
        exception_size = 0 if value["exception"] is None else len(_canonical(value["exception"]))
    except (TypeError, ValueError):
        return None, "guest_exception_invalid"
    if exception_size > max_output_bytes:
        return None, "guest_exception_over_budget"
    effects = value["effects"]
    if not isinstance(effects, dict) or set(effects) != {"status", "events"} or effects.get("status") not in {"observed", "unknown"} or not isinstance(effects.get("events"), list):
        return None, "guest_effects_invalid"
    try:
        effect_size = len(_canonical(effects))
    except (TypeError, ValueError):
        return None, "guest_effects_invalid"
    if effect_size > max_output_bytes:
        return None, "guest_effects_over_budget"
    return {"stdout": value["stdout"], "stderr": value["stderr"], "exit_code": code, "timeout": value["timeout"]}, None


def run_behavioral_cases(
    *, candidate: dict[str, Any], artifact_root: str | Path, case_manifest_path: str | Path,
    signed_handoff: dict[str, Any], guest_executor: Callable[[dict[str, Any]], dict[str, Any]] | None,
    verify_attestation: Callable[[dict[str, Any]], bool] | None, timeout_s: int, max_output_bytes: int = 65536,
) -> dict[str, Any]:
    """Request pairwise guest observations. Never starts a target on this host.

    ``guest_executor`` must be a qualified VM transport. Both the handoff and
    every returned pair envelope must pass the caller's cryptographic verifier.
    """
    errors: list[dict[str, Any]] = []
    validation = validate_candidate(candidate, artifact_root, case_manifest_path=case_manifest_path)
    if validation["status"] != "verified":
        return {"schema": _RUN_SCHEMA, "status": "invalid", "original": [], "candidate": [], "errors": validation["errors"], "limitations": ["nenhum alvo foi executado"]}
    if validation["candidate_status"] != "candidate":
        return {"schema": _RUN_SCHEMA, "status": "refused", "original": [], "candidate": [], "errors": [_error("candidate_not_executable", candidate_status=validation["candidate_status"])], "limitations": ["pseudo-source não é um executável reconstruído", "nenhum alvo foi executado"]}
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, int) or not 1 <= timeout_s <= 3600:
        return {"schema": _RUN_SCHEMA, "status": "invalid", "original": [], "candidate": [], "errors": [_error("timeout_budget_invalid")], "limitations": ["nenhum alvo foi executado"]}
    if isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int) or not 1 <= max_output_bytes <= 1_048_576:
        return {"schema": _RUN_SCHEMA, "status": "invalid", "original": [], "candidate": [], "errors": [_error("output_budget_invalid")], "limitations": ["nenhum alvo foi executado"]}
    if not callable(verify_attestation):
        return {"schema": _RUN_SCHEMA, "status": "refused", "original": [], "candidate": [], "errors": [_error("attestation_verifier_required")], "limitations": ["nenhum alvo foi executado"]}
    if not callable(guest_executor):
        return {"schema": _RUN_SCHEMA, "status": "refused", "original": [], "candidate": [], "errors": [_error("guest_executor_required")], "limitations": ["nenhum alvo foi executado"]}
    if not isinstance(signed_handoff, dict) or set(signed_handoff) != {"payload", "signature"}:
        return {"schema": _RUN_SCHEMA, "status": "invalid", "original": [], "candidate": [], "errors": [_error("handoff_envelope_invalid")], "limitations": ["nenhum alvo foi executado"]}
    try:
        handoff = DynamicLabHandoff.from_dict(signed_handoff["payload"])
    except (ContractError, TypeError, ValueError):
        return {"schema": _RUN_SCHEMA, "status": "invalid", "original": [], "candidate": [], "errors": [_error("handoff_contract_invalid")], "limitations": ["nenhum alvo foi executado"]}
    try:
        handoff_verified = verify_attestation(signed_handoff)
    except Exception:
        handoff_verified = False
    if handoff_verified is not True:
        return {"schema": _RUN_SCHEMA, "status": "refused", "original": [], "candidate": [], "errors": [_error("handoff_attestation_invalid")], "limitations": ["nenhum alvo foi executado"]}

    root = Path(artifact_root).resolve(strict=True)
    try:
        original_binary = _read_bounded_artifact(
            _within(root, candidate["original"]["binary"]["path"]),
            128 * 1024 * 1024,
            "original_binary",
        )
        candidate_binary = _read_bounded_artifact(
            _within(root, candidate["candidate"]["binary"]["path"]),
            128 * 1024 * 1024,
            "candidate_binary",
        )
    except (OSError, ValueError):
        return {"schema": _RUN_SCHEMA, "status": "invalid", "original": [], "candidate": [], "errors": [_error("execution_artifact_unreadable")], "limitations": ["nenhum alvo foi executado"]}
    for artifact_name, data in (("original_binary", original_binary), ("candidate_binary", candidate_binary)):
        if _digest(data) != validation["hashes"].get(artifact_name):
            return {"schema": _RUN_SCHEMA, "status": "invalid", "original": [], "candidate": [], "errors": [_error("execution_artifact_hash_changed", artifact=artifact_name)], "limitations": ["nenhum alvo foi executado"]}
    original_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    result_envelopes: list[dict[str, Any]] = []
    cases = validation["cases"]
    for case in cases:
        request = {
            "schema": "guest-pair-request.v1", "run_lease": handoff.run_lease.to_dict(),
            "case_index": len(result_envelopes), "case_total": len(cases),
            "candidate_manifest_sha256": validation["manifest_sha256"],
            "case": {"case_id": case["case_id"], "input": case["input"]},
            "input_sha256": case["input_sha256"], "input_manifest_sha256": validation["case_manifest_sha256"],
            "original_binary": original_binary, "candidate_binary": candidate_binary,
            "original_binary_sha256": validation["hashes"]["original_binary"],
            "candidate_binary_sha256": validation["hashes"]["candidate_binary"],
            "timeout_s": timeout_s, "max_output_bytes": max_output_bytes,
            "network_enabled": False, "execution_environment": "vm",
        }
        try:
            envelope = guest_executor(request)
        except TimeoutError:
            errors.append(_error("guest_executor_timeout", case_id=case["case_id"]))
            break
        except Exception as exc:
            errors.append(_error("guest_executor_error", case_id=case["case_id"], detail=type(exc).__name__))
            break
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            errors.append(_error("guest_result_envelope_invalid", case_id=case["case_id"]))
            break
        try:
            verified = verify_attestation(envelope)
        except Exception:
            verified = False
        if verified is not True:
            errors.append(_error("guest_result_attestation_invalid", case_id=case["case_id"]))
            break
        payload = envelope.get("payload")
        required = {"schema", "run_id", "guest_id", "nonce", "case_id", "case_index", "case_total", "input", "input_sha256", "input_manifest_sha256", "candidate_manifest_sha256", "original_binary_sha256", "candidate_binary_sha256", "timeout_s", "max_output_bytes", "original", "candidate"}
        if not isinstance(payload, dict) or set(payload) != required or payload.get("schema") != _RESULT_SCHEMA:
            errors.append(_error("guest_result_schema_invalid", case_id=case["case_id"]))
            break
        lease = handoff.run_lease
        if any(isinstance(payload[field], bool) or not isinstance(payload[field], int) for field in ("case_index", "case_total", "timeout_s", "max_output_bytes")) or (payload["run_id"], payload["guest_id"], payload["nonce"], payload["case_id"], payload["case_index"], payload["case_total"], payload["input_sha256"], payload["input_manifest_sha256"], payload["candidate_manifest_sha256"], payload["original_binary_sha256"], payload["candidate_binary_sha256"], payload["timeout_s"], payload["max_output_bytes"]) != (lease.run_id, lease.guest_id, lease.nonce, case["case_id"], len(result_envelopes), len(cases), case["input_sha256"], validation["case_manifest_sha256"], validation["manifest_sha256"], validation["hashes"]["original_binary"], validation["hashes"]["candidate_binary"], timeout_s, max_output_bytes):
            errors.append(_error("guest_case_identity_mismatch", case_id=case["case_id"]))
            break
        try:
            if _canonical(payload["input"]) != _canonical(case["input"]):
                errors.append(_error("guest_input_mismatch", case_id=case["case_id"]))
                break
        except (TypeError, ValueError):
            errors.append(_error("guest_input_invalid", case_id=case["case_id"]))
            break
        original_output, original_error = _validate_output(payload["original"], max_output_bytes=max_output_bytes)
        candidate_output, candidate_error = _validate_output(payload["candidate"], max_output_bytes=max_output_bytes)
        if original_error or candidate_error:
            errors.append(_error(original_error or candidate_error or "guest_output_invalid", case_id=case["case_id"]))
            break
        original_rows.append({"case_id": case["case_id"], "input": case["input"], "output": original_output, "effects": payload["original"]["effects"], "exception": payload["original"]["exception"]})
        candidate_rows.append({"case_id": case["case_id"], "input": case["input"], "output": candidate_output, "effects": payload["candidate"]["effects"], "exception": payload["candidate"]["exception"]})
        result_envelopes.append(envelope)
    if errors:
        return {"schema": _RUN_SCHEMA, "status": "invalid", "original": [], "candidate": [], "guest_result_envelopes": result_envelopes, "errors": errors, "limitations": ["nenhum resultado parcial é comparado; a execução/atestado precisa ser repetida"]}
    comparison = compare_observations(original_rows, candidate_rows)
    return {
        "schema": _RUN_SCHEMA, "status": "complete", "run_id": handoff.run_lease.run_id,
        "guest_id": handoff.run_lease.guest_id, "nonce": handoff.run_lease.nonce,
        "signed_handoff": signed_handoff, "guest_result_envelopes": result_envelopes,
        "candidate_hashes": {"original_binary_sha256": validation["hashes"]["original_binary"], "candidate_binary_sha256": validation["hashes"]["candidate_binary"], "candidate_manifest_sha256": validation["manifest_sha256"], "input_manifest_sha256": validation["case_manifest_sha256"]},
        "execution_policy": {"timeout_s": timeout_s, "max_output_bytes": max_output_bytes, "network_enabled": False, "execution_environment": "vm"},
        "case_manifest": [{"case_id": item["case_id"], "input": item["input"]} for item in cases],
        "summary": {"cases": len(cases), "observed": len(result_envelopes), "failed": 0},
        "original": original_rows, "candidate": candidate_rows, "comparison": comparison,
        "errors": [], "limitations": ["execução delegada a provedor de guest; este módulo não executa alvos no host", "efeitos ausentes não são convertidos em lista vazia; desconhecidos permanecem desconhecidos", "equivalência vale apenas para as entradas observadas"],
    }


def verify_signed_document(envelope: Any, trust_map: Any) -> bool:
    """Verify an Ed25519 envelope against an out-of-band public-key trust map."""
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"} or not isinstance(envelope.get("signature"), dict):
        return False
    signature = envelope["signature"]
    if set(signature) != {"key_id", "algorithm", "signature_b64"} or signature.get("algorithm") != "Ed25519":
        return False
    if not isinstance(trust_map, dict) or set(trust_map) != {"schema", "keys"} or trust_map.get("schema") != "aetherre-trust-map.v1" or not isinstance(trust_map.get("keys"), list):
        return False
    keys = [item for item in trust_map["keys"] if isinstance(item, dict) and item.get("key_id") == signature.get("key_id")]
    if len(keys) != 1 or set(keys[0]) != {"key_id", "algorithm", "public_key_b64", "active"} or keys[0].get("algorithm") != "Ed25519" or keys[0].get("active") is not True:
        return False
    if not isinstance(signature.get("signature_b64"), str) or not isinstance(keys[0].get("public_key_b64"), str):
        return False
    try:
        public_key_bytes = base64.b64decode(keys[0]["public_key_b64"], validate=True)
        signature_bytes = base64.b64decode(signature["signature_b64"], validate=True)
        payload_bytes = _canonical(envelope["payload"])
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature_bytes, payload_bytes)
    except Exception:
        return False
    return True


def compare_signed_behavioral_run(document: Any, trust_map: Any) -> dict[str, Any]:
    """Recompute comparison exclusively from signed and independently verified guest rows."""
    errors: list[dict[str, Any]] = []
    if not isinstance(document, dict) or document.get("schema") != _RUN_SCHEMA or document.get("status") != "complete":
        return {"schema": "behavioral-comparison.v1", "status": "invalid", "summary": {}, "mismatches": [], "errors": [_error("observations_not_verified")], "limitations": ["somente relatórios completos e assinados são comparados"]}
    handoff_envelope = document.get("signed_handoff")
    if not verify_signed_document(handoff_envelope, trust_map):
        errors.append(_error("handoff_attestation_invalid"))
    try:
        handoff = DynamicLabHandoff.from_dict(handoff_envelope["payload"])
    except (TypeError, ValueError, KeyError, ContractError):
        handoff = None
        errors.append(_error("handoff_contract_invalid"))
    manifest = document.get("case_manifest")
    cases, case_errors = _case_rows({"schema": _CASE_SCHEMA, "cases": manifest} if isinstance(manifest, list) else None)
    errors.extend(case_errors)
    envelopes = document.get("guest_result_envelopes")
    if not isinstance(envelopes, list) or len(envelopes) != len(cases):
        errors.append(_error("guest_observation_denominator_mismatch", expected=len(cases), observed=len(envelopes) if isinstance(envelopes, list) else 0))
        envelopes = []
    original_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    if handoff is not None:
        lease = handoff.run_lease
        for index, (case, envelope) in enumerate(zip(cases, envelopes)):
            if not verify_signed_document(envelope, trust_map):
                errors.append(_error("guest_result_attestation_invalid", index=index))
                continue
            payload = envelope.get("payload") if isinstance(envelope, dict) else None
            required = {"schema", "run_id", "guest_id", "nonce", "case_id", "case_index", "case_total", "input", "input_sha256", "input_manifest_sha256", "candidate_manifest_sha256", "original_binary_sha256", "candidate_binary_sha256", "timeout_s", "max_output_bytes", "original", "candidate"}
            if not isinstance(payload, dict) or set(payload) != required or payload.get("schema") != _RESULT_SCHEMA:
                errors.append(_error("guest_result_schema_invalid", index=index))
                continue
            hashes = document.get("candidate_hashes")
            policy = document.get("execution_policy")
            if not isinstance(hashes, dict) or not isinstance(policy, dict) or any(isinstance(payload[field], bool) or not isinstance(payload[field], int) for field in ("case_index", "case_total", "timeout_s", "max_output_bytes")) or (payload.get("run_id"), payload.get("guest_id"), payload.get("nonce"), payload.get("case_id"), payload.get("case_index"), payload.get("case_total"), payload.get("input_sha256"), payload.get("input_manifest_sha256"), payload.get("candidate_manifest_sha256"), payload.get("original_binary_sha256"), payload.get("candidate_binary_sha256"), payload.get("timeout_s"), payload.get("max_output_bytes")) != (lease.run_id, lease.guest_id, lease.nonce, case["case_id"], index, len(cases), case["input_sha256"], hashes.get("input_manifest_sha256"), hashes.get("candidate_manifest_sha256"), hashes.get("original_binary_sha256"), hashes.get("candidate_binary_sha256"), policy.get("timeout_s"), policy.get("max_output_bytes")):
                errors.append(_error("guest_case_identity_mismatch", index=index))
                continue
            if _canonical(payload.get("input")) != _canonical(case["input"]):
                errors.append(_error("guest_input_mismatch", index=index))
                continue
            budget = policy.get("max_output_bytes")
            if isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= 1_048_576:
                errors.append(_error("execution_policy_invalid"))
                continue
            original_output, original_error = _validate_output(payload.get("original"), max_output_bytes=budget)
            candidate_output, candidate_error = _validate_output(payload.get("candidate"), max_output_bytes=budget)
            if original_error or candidate_error:
                errors.append(_error(original_error or candidate_error or "guest_output_invalid", index=index))
                continue
            original_rows.append({"case_id": case["case_id"], "input": case["input"], "output": original_output, "effects": payload["original"]["effects"], "exception": payload["original"]["exception"]})
            candidate_rows.append({"case_id": case["case_id"], "input": case["input"], "output": candidate_output, "effects": payload["candidate"]["effects"], "exception": payload["candidate"]["exception"]})
    if errors or len(original_rows) != len(cases) or len(candidate_rows) != len(cases):
        return {"schema": "behavioral-comparison.v1", "status": "invalid", "summary": {"cases": len(cases), "verified": len(original_rows)}, "mismatches": [], "errors": errors or [_error("guest_observation_missing")], "limitations": ["nenhum subconjunto parcial é apresentado como comparação válida"]}
    comparison = compare_observations(original_rows, candidate_rows)
    return {"schema": "behavioral-comparison.v1", "status": comparison["status"], "summary": comparison["summary"], "matched": comparison["matched"], "mismatches": comparison["mismatches"], "confidence_kind": "empirical_observation", "verification": {"handoff_signature": "verified", "guest_result_signatures": len(envelopes), "trust_map_schema": "aetherre-trust-map.v1"}, "errors": [], "limitations": comparison["limitations"]}
