from argparse import Namespace
import json
from pathlib import Path

from aether_re.claims import validate_claims
from aether_re.profile_scope import validate_claim_scope, validate_profile_scope
from megazord import cmd_claims_validate


def _scope():
    return {
        "profile_id": "python-cpp-pe-elf-x86_64",
        "languages": ["python", "c", "cpp"],
        "formats": ["source", "PE", "ELF"],
        "architectures": ["x86_64"],
        "toolchain": ["CPython 3.13", "MSVC/GCC declared"],
        "frozen_at": "2026-09-18T00:00:00Z",
        "exclusions": ["Go", "JS/TS", "other architectures"],
        "universal": False,
    }


def test_profile_scope_requires_frozen_bounded_fields():
    report = validate_profile_scope(_scope())
    assert report["status"] == "valid"
    assert report["scope"]["universal"] is False
    assert validate_profile_scope({"profile_id": "x", "universal": True})["status"] == "invalid"


def test_profile_scope_rejects_duplicates_and_missing_lists():
    scope = _scope()
    scope["languages"] = ["python", "python"]
    scope["architectures"] = []
    report = validate_profile_scope(scope)
    assert report["status"] == "invalid"
    assert {item["code"] for item in report["errors"]} >= {"profile_scope_list_duplicate", "profile_scope_list_invalid"}


def test_claim_scope_rejects_universal_and_mismatch():
    scope = validate_profile_scope(_scope())["scope"]
    assert any(item["code"] == "universal_claim_forbidden" for item in validate_claim_scope({"scope_id": scope["profile_id"], "universal": True}, scope))
    assert any(item["code"] == "claim_scope_mismatch" for item in validate_claim_scope({"scope_id": "other"}, scope))


def test_claim_validation_requires_scope_when_profile_is_supplied():
    report = validate_claims(
        [{"statement": "measured in profile", "state": "confirmed", "evidence_ids": ["e1"]}],
        [{"evidence_id": "e1", "supports": True}],
        profile_scope=_scope(),
    )
    assert report["status"] == "invalid"
    assert report["claims"][0]["verdict"] == "unsupported"
    assert any(item["code"] == "claim_scope_missing" for item in report["claims"][0]["scope_errors"])


def test_claim_validation_accepts_scoped_supported_claim():
    scope = _scope()
    report = validate_claims(
        [{"statement": "measured in declared profile", "state": "confirmed", "scope_id": scope["profile_id"], "evidence_ids": ["e1"]}],
        [{"evidence_id": "e1", "supports": True}],
        profile_scope=scope,
    )
    assert report["status"] == "complete"
    assert report["summary"]["supported"] == 1
    assert report["profile_scope"]["status"] == "valid"


def test_claims_cli_profile_scope_rejects_universal(tmp_path: Path):
    claims = tmp_path / "claims.json"; evidence = tmp_path / "evidence.json"; scope = tmp_path / "scope.json"; out = tmp_path / "report.json"
    claims.write_text(json.dumps([{"statement": "universal", "state": "confirmed", "scope_id": "python-cpp-pe-elf-x86_64", "universal": True, "evidence_ids": ["e1"]}]), encoding="utf-8")
    evidence.write_text(json.dumps([{"evidence_id": "e1", "supports": True}]), encoding="utf-8")
    scope.write_text(json.dumps(_scope()), encoding="utf-8")
    code = cmd_claims_validate(Namespace(claims=str(claims), evidence=str(evidence), out=str(out), strict_evidence=False, manifest=None, profile_scope=str(scope)))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert any(item["code"] == "universal_claim_forbidden" for item in report["claims"][0]["scope_errors"])
