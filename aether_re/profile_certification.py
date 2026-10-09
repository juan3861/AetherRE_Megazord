"""Material, fail-closed certification for static analysis profiles."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


REQUIRED_MEASUREMENTS = (
    "entities", "relations", "abstention", "calibration", "reproducibility",
)
_SHA = re.compile(r"^[0-9a-f]{64}$")
_SPDX = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.+-]*(?:\s+(?:OR|AND|WITH)\s+[A-Za-z0-9.+-]+)*$"
)
_REPARSE_POINT = 0x400


def sha256_canonical(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _error(errors: list[dict[str, str]], code: str) -> None:
    if not any(item["code"] == code for item in errors):
        errors.append({"code": code})


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _is_reparse_point(path: Path) -> bool:
    try:
        return bool(getattr(path.lstat(), "st_file_attributes", 0) & _REPARSE_POINT)
    except OSError:
        return False


def _material_path(root: Path, ref: Any) -> tuple[Path | None, str | None]:
    if not isinstance(ref, str) or not ref or "\x00" in ref:
        return None, "evidence_ref_unsafe"
    posix_ref, windows_ref = PurePosixPath(ref), PureWindowsPath(ref)
    candidate_ref = Path(ref)
    if (
        posix_ref.is_absolute() or windows_ref.is_absolute() or windows_ref.drive
        or ".." in posix_ref.parts or ".." in windows_ref.parts
    ):
        return None, "evidence_ref_unsafe"
    candidate = root.joinpath(candidate_ref)
    cursor = root
    for part in candidate_ref.parts:
        cursor = cursor / part
        if cursor.is_symlink() or _is_reparse_point(cursor):
            return None, "evidence_ref_symlink"
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (FileNotFoundError, OSError):
        return None, "evidence_ref_missing"
    except ValueError:
        return None, "evidence_ref_unsafe"
    if not resolved.is_file():
        return None, "evidence_ref_missing"
    return resolved, None


def _close(left: float, right: float) -> bool:
    return math.isclose(left, right, rel_tol=1e-9, abs_tol=1e-12)


def _common_measurement(value: Any, metric_type: str) -> bool:
    return (
        isinstance(value, dict)
        and value.get("status") == "measured"
        and value.get("metric_type") == metric_type
        and isinstance(value.get("denominator"), int)
        and not isinstance(value.get("denominator"), bool)
        and value["denominator"] > 0
        and isinstance(value.get("thresholds"), dict)
        and bool(value["thresholds"])
        and isinstance(value.get("evidence_refs"), list)
        and bool(value["evidence_refs"])
        and all(isinstance(ref, str) and ref for ref in value["evidence_refs"])
    )


def _validate_measurement(name: str, value: Any) -> tuple[bool, bool]:
    """Return (shape_and_arithmetic_valid, thresholds_passed)."""
    if name in {"entities", "relations"}:
        if not _common_measurement(value, "classification"):
            return False, False
        counts = [value.get(key) for key in ("true_positive", "false_positive", "false_negative")]
        precision, recall = value.get("precision"), value.get("recall")
        thresholds = value["thresholds"]
        if (
            any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in counts)
            or not all(_is_number(item) and 0 <= item <= 1 for item in (precision, recall))
            or set(thresholds) != {"min_precision", "min_recall"}
            or not all(_is_number(item) and 0 <= item <= 1 for item in thresholds.values())
            or sum(counts) > value["denominator"]
        ):
            return False, False
        tp, fp, fn = counts
        expected_precision = tp / (tp + fp) if tp + fp else 0.0
        expected_recall = tp / (tp + fn) if tp + fn else 0.0
        if not (_close(float(precision), expected_precision) and _close(float(recall), expected_recall)):
            return False, False
        return True, precision >= thresholds["min_precision"] and recall >= thresholds["min_recall"]

    if name == "abstention":
        if not _common_measurement(value, "abstention"):
            return False, False
        abstained, rate, thresholds = value.get("abstained"), value.get("rate"), value["thresholds"]
        if (
            not isinstance(abstained, int) or isinstance(abstained, bool)
            or not 0 <= abstained <= value["denominator"]
            or not _is_number(rate) or not 0 <= rate <= 1
            or set(thresholds) != {"max_rate"}
            or not _is_number(thresholds["max_rate"]) or not 0 <= thresholds["max_rate"] <= 1
            or not _close(float(rate), abstained / value["denominator"])
        ):
            return False, False
        return True, rate <= thresholds["max_rate"]

    if name == "calibration":
        if not _common_measurement(value, "calibration"):
            return False, False
        brier, ece, thresholds = value.get("brier_score"), value.get("ece"), value["thresholds"]
        if (
            not all(_is_number(item) and 0 <= item <= 1 for item in (brier, ece))
            or set(thresholds) != {"max_brier_score", "max_ece"}
            or not all(_is_number(item) and 0 <= item <= 1 for item in thresholds.values())
        ):
            return False, False
        return True, brier <= thresholds["max_brier_score"] and ece <= thresholds["max_ece"]

    if name == "reproducibility":
        if not _common_measurement(value, "reproducibility"):
            return False, False
        matching, rate, thresholds = value.get("matching_runs"), value.get("rate"), value["thresholds"]
        if (
            not isinstance(matching, int) or isinstance(matching, bool)
            or not 0 <= matching <= value["denominator"]
            or not _is_number(rate) or not 0 <= rate <= 1
            or set(thresholds) != {"min_rate", "min_runs"}
            or not _is_number(thresholds["min_rate"]) or not 0 <= thresholds["min_rate"] <= 1
            or not isinstance(thresholds["min_runs"], int) or isinstance(thresholds["min_runs"], bool)
            or thresholds["min_runs"] <= 0
            or not _close(float(rate), matching / value["denominator"])
        ):
            return False, False
        return True, rate >= thresholds["min_rate"] and value["denominator"] >= thresholds["min_runs"]
    return False, False


def _load_external_trust_map(
    value: Any, root: Path | None,
) -> tuple[dict[str, Any] | None, str | None]:
    if value is None:
        return None, "external_oracle_trust_map_missing"
    if isinstance(value, Mapping):
        return dict(value), None
    if not isinstance(value, (str, os.PathLike)):
        return None, "external_oracle_trust_map_invalid"
    source = Path(value)
    try:
        if source.is_symlink() or _is_reparse_point(source):
            return None, "external_oracle_trust_map_invalid"
        source = source.resolve(strict=True)
        if not source.is_file():
            return None, "external_oracle_trust_map_invalid"
        if root is not None:
            try:
                source.relative_to(root)
            except ValueError:
                pass
            else:
                return None, "external_oracle_trust_map_not_external"
        repository_root = Path(__file__).resolve().parents[1]
        try:
            source.relative_to(repository_root)
        except ValueError:
            pass
        else:
            return None, "external_oracle_trust_map_not_external"
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "external_oracle_trust_map_invalid"
    return document if isinstance(document, dict) else None, (
        None if isinstance(document, dict) else "external_oracle_trust_map_invalid"
    )


def _trusted_oracle_key(
    trust_map: Any, key_id: Any, owner: Any, producer: Any,
) -> tuple[Ed25519PublicKey | None, str | None]:
    if (
        not isinstance(trust_map, dict)
        or trust_map.get("schema") != "profile-oracle-trust-map.v1"
        or set(trust_map) != {"schema", "keys"}
        or not isinstance(trust_map.get("keys"), list)
    ):
        return None, "external_oracle_trust_map_invalid"
    matches = [
        item for item in trust_map["keys"]
        if isinstance(item, dict) and item.get("key_id") == key_id
    ]
    if len(matches) != 1:
        return None, "independent_oracle_signer_untrusted"
    item = matches[0]
    if (
        set(item) != {
            "key_id", "algorithm", "public_key_b64",
            "oracle_owner_identity", "active",
        }
        or item.get("algorithm") != "Ed25519"
        or item.get("active") is not True
        or not isinstance(owner, str) or not owner
        or not isinstance(producer, str) or not producer
        or item.get("oracle_owner_identity") != owner
        or owner == producer
    ):
        return None, "independent_oracle_signer_invalid"
    try:
        public_bytes = base64.b64decode(item["public_key_b64"], validate=True)
        if len(public_bytes) != 32:
            raise ValueError
        return Ed25519PublicKey.from_public_bytes(public_bytes), None
    except (binascii.Error, TypeError, ValueError):
        return None, "external_oracle_trust_map_invalid"


def _verify_oracle_envelope(
    envelope: Any, trust_map: Any, profile_id: str, blind_hash: Any,
) -> str | None:
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"schema", "payload", "signature"}
        or envelope.get("schema") != "signed-oracle-independence-attestation.v1"
        or not isinstance(envelope.get("payload"), dict)
        or not isinstance(envelope.get("signature"), dict)
    ):
        return "independent_oracle_attestation_invalid"
    payload, signature = envelope["payload"], envelope["signature"]
    if (
        set(payload) != {
            "schema", "profile_id", "producer_identity",
            "oracle_owner_identity", "blind_corpus_sha256",
            "sealed_before_evaluation", "oracle_access",
        }
        or payload.get("schema") != "oracle-independence-claim.v1"
        or payload.get("profile_id") != profile_id
        or payload.get("blind_corpus_sha256") != blind_hash
        or payload.get("sealed_before_evaluation") is not True
        or payload.get("oracle_access") != "withheld_until_evaluation_complete"
        or set(signature) != {"key_id", "algorithm", "signature_b64"}
        or signature.get("algorithm") != "Ed25519"
    ):
        return "independent_oracle_attestation_invalid"
    key, key_error = _trusted_oracle_key(
        trust_map, signature.get("key_id"), payload.get("oracle_owner_identity"),
        payload.get("producer_identity"),
    )
    if key_error:
        return key_error
    try:
        signature_bytes = base64.b64decode(signature["signature_b64"], validate=True)
        if len(signature_bytes) != 64:
            raise ValueError
        key.verify(signature_bytes, json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8"))
    except (binascii.Error, InvalidSignature, TypeError, ValueError):
        return "independent_oracle_signature_invalid"
    return None


def certify_static_profile(
    profile_scope: dict[str, Any],
    corpus: dict[str, Any],
    workers: dict[str, Any],
    evaluation: dict[str, Any],
    baseline: dict[str, Any],
    evidence_root: str | os.PathLike[str] | None = None,
    external_trust_map: Mapping[str, Any] | str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Recalculate a profile certificate from evidence bytes below one root.

    The legacy five-argument form deliberately remains fail-closed. Producer
    declarations are inputs to verification, never proof by themselves.
    """
    errors: list[dict[str, str]] = []
    verified: set[Path] = set()
    root: Path | None = None
    if evidence_root is None:
        _error(errors, "profile_evidence_root_missing")
        # Compatibility marker consumed by the original declaration-bypass
        # regression.  It remains true specifically for the legacy API.
        _error(errors, "profile_evidence_verification_unavailable")
    else:
        try:
            root = Path(evidence_root).resolve(strict=True)
        except (OSError, TypeError, ValueError):
            _error(errors, "profile_evidence_root_invalid")
        else:
            if not root.is_dir() or root.is_symlink() or _is_reparse_point(root):
                _error(errors, "profile_evidence_root_invalid")

    profile_id = profile_scope.get("profile_id", "unknown") if isinstance(profile_scope, dict) else "unknown"
    if (
        not isinstance(profile_scope, dict)
        or profile_scope.get("schema") != "profile-scope.v1"
        or not isinstance(profile_scope.get("profile_id"), str)
        or not profile_scope["profile_id"]
    ):
        _error(errors, "profile_scope_invalid")

    corpus_valid = isinstance(corpus, dict)
    corpus_hashes: list[str] = []
    if corpus_valid:
        for split in ("development", "calibration", "blind"):
            digest, ref = corpus.get(f"{split}_hash"), corpus.get(f"{split}_ref")
            if not isinstance(digest, str) or not _SHA.fullmatch(digest) or not isinstance(ref, str):
                corpus_valid = False
                continue
            corpus_hashes.append(digest)
            if root is not None:
                path, path_error = _material_path(root, ref)
                if path_error:
                    _error(errors, path_error)
                elif path is not None:
                    verified.add(path)
                    if _sha256_file(path) != digest:
                        _error(errors, "corpus_hash_mismatch")
        if len(set(corpus_hashes)) != 3:
            corpus_valid = False
    if not corpus_valid:
        _error(errors, "sealed_corpus_invalid")

    worker_items = workers.get("workers") if isinstance(workers, dict) else None
    if not isinstance(worker_items, list) or not worker_items:
        _error(errors, "workers_missing")
    else:
        for worker in worker_items:
            valid = (
                isinstance(worker, dict)
                and isinstance(worker.get("name"), str) and bool(worker["name"])
                and isinstance(worker.get("executable_ref"), str) and bool(worker["executable_ref"])
                and bool(_SHA.fullmatch(str(worker.get("executable_sha256", ""))))
                and isinstance(worker.get("version"), str) and bool(worker["version"])
                and bool(_SPDX.fullmatch(str(worker.get("license_spdx", ""))))
                and isinstance(worker.get("invocation"), list) and bool(worker["invocation"])
                and all(isinstance(arg, str) and arg for arg in worker["invocation"])
            )
            if not valid:
                _error(errors, "worker_pin_invalid")
                continue
            if root is not None:
                path, path_error = _material_path(root, worker["executable_ref"])
                if path_error:
                    _error(errors, path_error)
                elif path is not None:
                    verified.add(path)
                    if _sha256_file(path) != worker["executable_sha256"]:
                        _error(errors, "worker_executable_hash_mismatch")

    artifact_map: dict[str, str] = {}
    if isinstance(evaluation, dict) and isinstance(evaluation.get("artifacts"), list):
        for artifact in evaluation["artifacts"]:
            if (
                not isinstance(artifact, dict)
                or not isinstance(artifact.get("ref"), str)
                or not _SHA.fullmatch(str(artifact.get("sha256", "")))
                or artifact["ref"] in artifact_map
            ):
                _error(errors, "evidence_artifact_declaration_invalid")
                continue
            artifact_map[artifact["ref"]] = artifact["sha256"]
            if root is not None:
                path, path_error = _material_path(root, artifact["ref"])
                if path_error:
                    _error(errors, path_error)
                elif path is not None:
                    verified.add(path)
                    if _sha256_file(path) != artifact["sha256"]:
                        _error(errors, "evidence_hash_mismatch")
    else:
        _error(errors, "evidence_artifacts_missing")

    all_evidence_refs: list[Any] = []
    if isinstance(evaluation, dict):
        refs = evaluation.get("evidence_refs")
        if not isinstance(refs, list) or not refs:
            _error(errors, "evaluation_evidence_missing")
        else:
            all_evidence_refs.extend(refs)
        for name in REQUIRED_MEASUREMENTS:
            value = evaluation.get(name)
            valid, passed = _validate_measurement(name, value)
            if not valid:
                _error(errors, f"{name}_measurement_invalid")
                _error(errors, f"{name}_unmeasured")
            elif not passed:
                _error(errors, f"{name}_threshold_failed")
            if isinstance(value, dict) and isinstance(value.get("evidence_refs"), list):
                all_evidence_refs.extend(value["evidence_refs"])
    else:
        _error(errors, "evaluation_invalid")

    for ref in all_evidence_refs:
        if root is not None:
            _, path_error = _material_path(root, ref)
            if path_error:
                _error(errors, path_error)
        if ref not in artifact_map:
            _error(errors, "evidence_ref_unbound")

    limitations = evaluation.get("limitations") if isinstance(evaluation, dict) else None
    if (
        not isinstance(limitations, list) or not limitations
        or any(not isinstance(item, str) or not item.strip() for item in limitations)
    ):
        _error(errors, "limitations_missing")
        limitations = []

    trust_map, trust_error = _load_external_trust_map(external_trust_map, root)
    if trust_error:
        _error(errors, trust_error)
    attestation = evaluation.get("oracle_attestation") if isinstance(evaluation, dict) else None
    if not isinstance(attestation, dict) or not _SHA.fullmatch(str(attestation.get("sha256", ""))):
        _error(errors, "independent_oracle_attestation_missing")
    elif root is not None:
        oracle_path, path_error = _material_path(root, attestation.get("ref"))
        if path_error:
            _error(errors, path_error)
        elif oracle_path is not None:
            verified.add(oracle_path)
            if _sha256_file(oracle_path) != attestation["sha256"]:
                _error(errors, "independent_oracle_attestation_hash_mismatch")
            else:
                try:
                    oracle_doc = json.loads(oracle_path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError):
                    _error(errors, "independent_oracle_attestation_invalid")
                else:
                    oracle_error = _verify_oracle_envelope(
                        oracle_doc, trust_map, profile_id,
                        corpus.get("blind_hash") if isinstance(corpus, dict) else None,
                    )
                    if oracle_error:
                        _error(errors, oracle_error)
    if not isinstance(evaluation, dict) or evaluation.get("oracle_independent") is not True:
        _error(errors, "independent_oracle_missing")

    if (
        not isinstance(baseline, dict)
        or not isinstance(baseline.get("regressions"), list)
        or baseline["regressions"]
    ):
        _error(errors, "critical_regression")

    return {
        "schema": "static-profile-certificate.v2",
        "profile_id": profile_id,
        "status": "QUITADA" if not errors else "NAO_COMPROVADA",
        "errors": errors,
        "measurements": evaluation if isinstance(evaluation, dict) else {},
        "worker_lock_sha256": sha256_canonical(workers if isinstance(workers, dict) else {}),
        "limitations": sorted(limitations),
        "verified_artifact_count": len(verified),
    }
