import json
from argparse import Namespace

from aether_re.evidence_contract import validate_evidence_records
from megazord import cmd_evidence_validate


def _record(**extra):
    value = {
        "evidence_id": "ev-1",
        "run_id": "run-1",
        "input_hash": "a" * 64,
        "producer": {"name": "native", "version": "1"},
        "method": "static-test",
        "validation_status": "observed",
        "supports": True,
    }
    value.update(extra)
    return value


def test_evidence_contract_accepts_observation_and_rejects_duplicates():
    report = validate_evidence_records([_record(), _record(evidence_id="ev-1")])
    assert report["status"] == "invalid"
    assert any(item["code"] == "duplicate_evidence_id" for item in report["errors"])


def test_strict_evidence_requires_provenance_and_manifest_binding():
    record = _record(
        target_identity={"format": "PE"},
        source_span={"module": "main.c", "line": 4},
        raw_artifact_hash="b" * 64,
        assumptions=[],
        limits=["static"],
        dependencies=[],
    )
    report = validate_evidence_records(record and [record], strict=True, manifest={"files": [{"sha256": "c" * 64}]})
    assert report["status"] == "invalid"
    assert any(item["code"] == "raw_artifact_not_in_manifest" for item in report["errors"])
    valid = validate_evidence_records([record], strict=True, manifest={"files": [{"sha256": "b" * 64}]})
    assert valid["status"] == "valid"


def test_strict_evidence_rejects_unbound_raw_artifact_without_manifest_entries():
    record = _record(
        target_identity={"format": "PE"},
        source_span={"module": "main.c", "line": 4},
        raw_artifact_hash="b" * 64,
        assumptions=[],
        limits=["static"],
        dependencies=[],
    )

    for manifest in (None, {"files": []}):
        report = validate_evidence_records([record], strict=True, manifest=manifest)
        assert report["status"] == "invalid"
        assert any(item["code"] == "raw_artifact_not_in_manifest" for item in report["errors"])


def test_non_strict_evidence_remains_usable_without_manifest_binding():
    record = _record(raw_artifact_hash="b" * 64)

    report = validate_evidence_records([record], manifest=None)

    assert report["status"] == "valid"


def test_evidence_contract_rejects_non_list_records():
    report = validate_evidence_records({})  # type: ignore[arg-type]
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "records_must_be_list"


def test_evidence_cli_rejects_unreadable_input_without_traceback(tmp_path):
    source = tmp_path / "evidence.json"
    out = tmp_path / "report.json"
    source.write_text("{", encoding="utf-8")
    code = cmd_evidence_validate(Namespace(input=str(source), manifest=None, out=str(out), strict=False))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "input_unreadable"
