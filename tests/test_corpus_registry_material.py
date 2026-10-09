import hashlib
import json
from base64 import b64encode
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aether_re.corpus_registry as corpus_registry_module
from aether_re.corpus_registry import validate_corpus_registry


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry(
    artifact_id: str,
    path: str,
    payload: bytes,
    *,
    profile_id: str,
    split: str,
    family: str,
    project: str,
) -> dict:
    return {
        "artifact_id": artifact_id,
        "path": path,
        "sha256": _sha256(payload),
        "size": len(payload),
        "origin": "https://example.invalid/public-corpus",
        "license": "MIT",
        "authorization": "public-licensed",
        "profile_id": profile_id,
        "split": split,
        "family": family,
        "project": project,
    }


def _write_registry(path: Path, entries: list[dict]) -> Path:
    path.write_text(
        json.dumps({"schema": "corpus-registry.v1", "entries": entries}),
        encoding="utf-8",
    )
    return path


def _material_registry(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "corpus"
    root.mkdir()
    payloads = {
        "dev.bin": b"development-real-bytes",
        "cal.bin": b"calibration-real-bytes",
        "blind.bin": b"blind-real-bytes",
    }
    for name, payload in payloads.items():
        (root / name).write_bytes(payload)
    registry = _write_registry(
        tmp_path / "registry.json",
        [
            _entry("dev-1", "dev.bin", payloads["dev.bin"], profile_id="native-pe", split="development", family="dev-family", project="dev-project"),
            _entry("cal-1", "cal.bin", payloads["cal.bin"], profile_id="jvm", split="calibration", family="cal-family", project="cal-project"),
            _entry("blind-1", "blind.bin", payloads["blind.bin"], profile_id="wasm", split="blind", family="blind-family", project="blind-project"),
        ],
    )
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps({"schema": "blind-oracle.v1", "entries": [{"artifact_id": "blind-1", "expected": {"functions": 2}}]}),
        encoding="utf-8",
    )
    return root, registry, oracle


def _canonical_sha256(document: dict) -> str:
    encoded = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _external_attestation(tmp_path: Path, root: Path, registry: Path, oracle: Path) -> tuple[Path, Path]:
    unsigned = validate_corpus_registry(registry, root, blind_oracle_path=oracle)
    assert unsigned["material_integrity"]["status"] == "verified"
    assert unsigned["status"] == "NAO_COMPROVADA"
    private = Ed25519PrivateKey.generate()
    owner = "independent-auditor"
    attested = {
        "schema": "blind-oracle-attestation.v1",
        "owner": owner,
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "oracle_schema": "blind-oracle.v1",
        "oracle_sha256": _canonical_sha256(json.loads(oracle.read_text(encoding="utf-8"))),
        "corpus_lock_sha256": unsigned["lock_sha256"],
        "algorithm": "ed25519",
    }
    signature = private.sign(json.dumps(attested, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    attestation = tmp_path / "attestation.json"
    attestation.write_text(json.dumps({**attested, "signature": b64encode(signature).decode("ascii")}), encoding="utf-8")
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    trust = tmp_path / "external-trust-map.json"
    trust.write_text(json.dumps({"schema": "oracle-trust-map.v1", "owners": {owner: {"ed25519_public_key": public}}}), encoding="utf-8")
    return attestation, trust


def _fake_repository_root(path: Path) -> Path:
    path.mkdir()
    (path / ".git").mkdir()
    (path / "megazord.py").write_text("# test repository marker\n", encoding="utf-8")
    package = path / "aether_re"
    package.mkdir()
    (package / "corpus_registry.py").write_text("# test package marker\n", encoding="utf-8")
    return path


def test_validates_real_material_and_emits_reproducible_lock_without_oracle(tmp_path: Path):
    root, registry, oracle = _material_registry(tmp_path)
    attestation, trust = _external_attestation(tmp_path, root, registry, oracle)

    first = validate_corpus_registry(registry, root, blind_oracle_path=oracle, blind_attestation_path=attestation, trust_map_path=trust)
    second = validate_corpus_registry(registry, root, blind_oracle_path=oracle, blind_attestation_path=attestation, trust_map_path=trust)

    assert first["schema"] == "corpus-validation-report.v1"
    assert first["status"] == "QUITADA"
    assert first["counts"] == {"development": 1, "calibration": 1, "blind": 1}
    assert first["lock_sha256"] == second["lock_sha256"]
    assert len(first["lock_sha256"]) == 64
    serialized = json.dumps(first, sort_keys=True)
    assert "expected" not in serialized
    assert str(oracle) not in serialized
    assert first["blind_oracle"] == {"status": "verified", "entry_count": 1}
    assert first["independent_attestation"] == {"status": "verified", "owner": "independent-auditor"}
    assert first["material_integrity"]["status"] == "verified"


def test_unsigned_or_self_declared_oracle_never_promotes_material_integrity(tmp_path: Path):
    root, registry, oracle = _material_registry(tmp_path)

    unsigned = validate_corpus_registry(registry, root, blind_oracle_path=oracle)

    assert unsigned["material_integrity"] == {"status": "verified", "entry_count": 3}
    assert unsigned["lock_sha256"] is not None
    assert unsigned["blind_oracle"] == {"status": "verified", "entry_count": 1}
    assert unsigned["independent_attestation"]["status"] == "not_verified"
    assert unsigned["status"] == "NAO_COMPROVADA"
    assert "oracle_attestation_required" in {error["code"] for error in unsigned["errors"]}


def test_invalid_signature_or_untrusted_owner_fails_closed(tmp_path: Path):
    root, registry, oracle = _material_registry(tmp_path)
    attestation, trust = _external_attestation(tmp_path, root, registry, oracle)
    document = json.loads(attestation.read_text(encoding="utf-8"))
    document["owner"] = "producer-controlled"
    attestation.write_text(json.dumps(document), encoding="utf-8")

    report = validate_corpus_registry(
        registry,
        root,
        blind_oracle_path=oracle,
        blind_attestation_path=attestation,
        trust_map_path=trust,
    )

    codes = {error["code"] for error in report["errors"]}
    assert {"oracle_attestation_owner_untrusted", "oracle_attestation_signature_invalid"} <= codes
    assert report["status"] == "NAO_COMPROVADA"
    assert report["material_integrity"]["status"] == "verified"


def test_attestation_is_bound_to_oracle_schema_hash_date_and_corpus_lock(tmp_path: Path):
    root, registry, oracle = _material_registry(tmp_path)
    attestation, trust = _external_attestation(tmp_path, root, registry, oracle)
    document = json.loads(attestation.read_text(encoding="utf-8"))
    document["issued_at"] = "not-a-date"
    document["oracle_schema"] = "blind-oracle.v0"
    document["oracle_sha256"] = "0" * 64
    document["corpus_lock_sha256"] = "1" * 64
    attestation.write_text(json.dumps(document), encoding="utf-8")

    report = validate_corpus_registry(
        registry,
        root,
        blind_oracle_path=oracle,
        blind_attestation_path=attestation,
        trust_map_path=trust,
    )

    codes = {error["code"] for error in report["errors"]}
    assert {"oracle_attestation_date_invalid", "oracle_attestation_oracle_schema_mismatch", "oracle_attestation_oracle_hash_mismatch", "oracle_attestation_corpus_lock_mismatch"} <= codes
    assert report["status"] == "NAO_COMPROVADA"


def test_oracle_and_trust_anchor_must_remain_outside_execution_corpus(tmp_path: Path):
    root, registry, oracle = _material_registry(tmp_path)
    attestation, trust = _external_attestation(tmp_path, root, registry, oracle)
    embedded_oracle = root / "oracle.json"
    embedded_oracle.write_bytes(oracle.read_bytes())
    embedded_trust = root / "trust.json"
    embedded_trust.write_bytes(trust.read_bytes())

    report = validate_corpus_registry(
        registry,
        root,
        blind_oracle_path=embedded_oracle,
        blind_attestation_path=attestation,
        trust_map_path=embedded_trust,
    )

    codes = {error["code"] for error in report["errors"]}
    assert {"blind_oracle_not_separate", "oracle_trust_map_not_external"} <= codes
    assert report["status"] == "NAO_COMPROVADA"


def test_trust_map_inside_repository_but_outside_corpus_is_rejected(tmp_path: Path, monkeypatch):
    root, registry, oracle = _material_registry(tmp_path)
    repository_root = _fake_repository_root(tmp_path / "repository")
    monkeypatch.setattr(corpus_registry_module, "_discover_repository_root", lambda: repository_root)
    attestation, external_trust = _external_attestation(tmp_path, root, registry, oracle)
    in_repository = repository_root / "trust-map.json"
    in_repository.write_bytes(external_trust.read_bytes())

    report = validate_corpus_registry(
        registry,
        root,
        blind_oracle_path=oracle,
        blind_attestation_path=attestation,
        trust_map_path=in_repository,
    )

    assert "oracle_trust_map_not_external" in {error["code"] for error in report["errors"]}
    assert report["status"] == "NAO_COMPROVADA"
    assert report["independent_attestation"]["status"] != "verified"


def test_trust_map_outside_repository_and_corpus_remains_accepted(tmp_path: Path, monkeypatch):
    root, registry, oracle = _material_registry(tmp_path)
    repository_root = _fake_repository_root(tmp_path / "repository")
    monkeypatch.setattr(corpus_registry_module, "_discover_repository_root", lambda: repository_root)
    attestation, external_trust = _external_attestation(tmp_path, root, registry, oracle)

    report = validate_corpus_registry(
        registry,
        root,
        blind_oracle_path=oracle,
        blind_attestation_path=attestation,
        trust_map_path=external_trust,
    )

    assert report["status"] == "QUITADA"
    assert report["independent_attestation"] == {"status": "verified", "owner": "independent-auditor"}
    assert "trust-map path location does not prove signer identity, governance, or reviewer independence" in report["limitations"]


def test_trust_map_fails_closed_when_repository_root_is_unavailable(tmp_path: Path, monkeypatch):
    root, registry, oracle = _material_registry(tmp_path)
    monkeypatch.setattr(corpus_registry_module, "_discover_repository_root", lambda: None)
    attestation, trust = _external_attestation(tmp_path, root, registry, oracle)

    report = validate_corpus_registry(
        registry,
        root,
        blind_oracle_path=oracle,
        blind_attestation_path=attestation,
        trust_map_path=trust,
    )

    assert "oracle_trust_map_repository_root_unavailable" in {error["code"] for error in report["errors"]}
    assert report["status"] == "NAO_COMPROVADA"
    assert report["independent_attestation"]["status"] != "verified"


def test_trust_map_symlink_to_repository_file_is_rejected(tmp_path: Path, monkeypatch):
    root, registry, oracle = _material_registry(tmp_path)
    repository_root = _fake_repository_root(tmp_path / "repository")
    monkeypatch.setattr(corpus_registry_module, "_discover_repository_root", lambda: repository_root)
    attestation, external_trust = _external_attestation(tmp_path, root, registry, oracle)
    repository_trust = repository_root / "trust-map.json"
    repository_trust.write_bytes(external_trust.read_bytes())
    external_alias = tmp_path / "trust-map-alias.json"
    try:
        external_alias.symlink_to(repository_trust)
    except OSError as exc:
        pytest.skip(f"filesystem symlinks are unavailable: {type(exc).__name__}")

    report = validate_corpus_registry(
        registry,
        root,
        blind_oracle_path=oracle,
        blind_attestation_path=attestation,
        trust_map_path=external_alias,
    )

    assert "oracle_trust_map_not_external" in {error["code"] for error in report["errors"]}
    assert report["status"] == "NAO_COMPROVADA"


def test_trust_map_hardlink_alias_is_rejected_when_supported(tmp_path: Path, monkeypatch):
    root, registry, oracle = _material_registry(tmp_path)
    repository_root = _fake_repository_root(tmp_path / "repository")
    monkeypatch.setattr(corpus_registry_module, "_discover_repository_root", lambda: repository_root)
    attestation, external_trust = _external_attestation(tmp_path, root, registry, oracle)
    repository_trust = repository_root / "trust-map.json"
    repository_trust.write_bytes(external_trust.read_bytes())
    external_alias = tmp_path / "external-hardlink-trust-map.json"
    try:
        external_alias.hardlink_to(repository_trust)
    except (AttributeError, OSError) as exc:
        pytest.skip(f"filesystem hard links are unavailable: {type(exc).__name__}")

    report = validate_corpus_registry(
        registry,
        root,
        blind_oracle_path=oracle,
        blind_attestation_path=attestation,
        trust_map_path=external_alias,
    )

    assert "oracle_trust_map_not_external" in {error["code"] for error in report["errors"]}
    assert report["status"] == "NAO_COMPROVADA"


def test_fails_closed_when_material_hash_or_size_does_not_match(tmp_path: Path):
    root, registry, oracle = _material_registry(tmp_path)
    (root / "cal.bin").write_bytes(b"tampered")

    report = validate_corpus_registry(registry, root, blind_oracle_path=oracle)

    assert report["status"] == "NAO_COMPROVADA"
    assert {error["code"] for error in report["errors"]} >= {"size_mismatch", "sha256_mismatch"}
    assert report["lock_sha256"] is None


def test_rejects_traversal_and_symlink_even_when_target_exists(tmp_path: Path):
    root, registry, oracle = _material_registry(tmp_path)
    document = json.loads(registry.read_text(encoding="utf-8"))
    document["entries"][0]["path"] = "../oracle.json"
    registry.write_text(json.dumps(document), encoding="utf-8")

    traversal = validate_corpus_registry(registry, root, blind_oracle_path=oracle)
    assert "path_outside_root" in {error["code"] for error in traversal["errors"]}

    external = tmp_path / "external.bin"
    external.write_bytes(b"external")
    link = root / "link.bin"
    try:
        link.symlink_to(external)
    except OSError:
        return
    document["entries"][0].update(path="link.bin", sha256=_sha256(b"external"), size=8)
    registry.write_text(json.dumps(document), encoding="utf-8")
    symlink = validate_corpus_registry(registry, root, blind_oracle_path=oracle)
    assert "symlink_forbidden" in {error["code"] for error in symlink["errors"]}


def test_rejects_duplicate_hash_and_family_or_project_overlap_between_splits(tmp_path: Path):
    root, registry, oracle = _material_registry(tmp_path)
    document = json.loads(registry.read_text(encoding="utf-8"))
    document["entries"][1]["sha256"] = document["entries"][0]["sha256"]
    document["entries"][1]["family"] = document["entries"][0]["family"]
    document["entries"][2]["project"] = document["entries"][0]["project"]
    registry.write_text(json.dumps(document), encoding="utf-8")

    report = validate_corpus_registry(registry, root, blind_oracle_path=oracle)

    codes = {error["code"] for error in report["errors"]}
    assert {"duplicate_sha256", "family_split_overlap", "project_split_overlap"} <= codes
    assert report["status"] == "NAO_COMPROVADA"


def test_requires_versioned_schema_metadata_canonical_profile_and_all_splits(tmp_path: Path):
    root, registry, oracle = _material_registry(tmp_path)
    document = json.loads(registry.read_text(encoding="utf-8"))
    document["schema"] = "corpus-registry.v0"
    document["entries"][0]["profile_id"] = "source-tree"
    document["entries"][0]["origin"] = ""
    document["entries"][1].pop("license")
    document["entries"][2]["authorization"] = ""
    document["entries"][2]["split"] = "holdout"
    registry.write_text(json.dumps(document), encoding="utf-8")

    report = validate_corpus_registry(registry, root, blind_oracle_path=oracle)

    codes = {error["code"] for error in report["errors"]}
    assert {"schema_mismatch", "profile_id_invalid", "origin_invalid", "license_invalid", "authorization_invalid", "split_invalid", "split_missing"} <= codes
    assert report["status"] == "NAO_COMPROVADA"


def test_blind_oracle_must_be_separate_complete_and_reference_only_blind_ids(tmp_path: Path):
    root, registry, oracle = _material_registry(tmp_path)
    document = json.loads(registry.read_text(encoding="utf-8"))
    document["entries"][2]["oracle"] = {"expected": "leaked"}
    registry.write_text(json.dumps(document), encoding="utf-8")
    oracle.write_text(
        json.dumps({"schema": "blind-oracle.v1", "entries": [{"artifact_id": "dev-1", "expected": "wrong-split"}]}),
        encoding="utf-8",
    )

    report = validate_corpus_registry(registry, root, blind_oracle_path=oracle)

    codes = {error["code"] for error in report["errors"]}
    assert {"oracle_exposed_in_registry", "blind_oracle_missing_entry", "blind_oracle_nonblind_entry"} <= codes
    assert report["blind_oracle"]["status"] == "invalid"
    assert "entries" not in report["blind_oracle"]

