import hashlib
import json
from argparse import Namespace

from aether_re.phase_gates import PHASE_IDS, evaluate_phase_gates, write_phase_gate_report
from megazord import cmd_phase_gates


def _evidence(root, *, content=b"gate-fixture\n", name="evidence.log"):
    path = root / name
    path.write_bytes(content)
    return {"path": name, "sha256": hashlib.sha256(content).hexdigest()}


def _phase(root, evidence, phase_id, **overrides):
    row = {
        "phase_id": phase_id,
        "implementation": True,
        "integration": True,
        "reviewed": True,
        "tests": {"passed": 1, "failed": 0, "skipped": 0},
        "evidence": [evidence],
    }
    row.update(overrides)
    return row


def test_phase_gate_requires_explicit_evidence_and_can_pass_all_declared_phases(tmp_path):
    evidence = _evidence(tmp_path)
    report = evaluate_phase_gates({"phases": [_phase(tmp_path, evidence, phase_id) for phase_id in PHASE_IDS]}, root=tmp_path)
    assert report["status"] == "complete"
    assert report["gate_passed"] is True
    assert report["summary"]["quitada"] == 13
    assert all(row["status"] == "QUITADA" for row in report["phases"])
    assert next(row for row in report["phases"] if row["phase_id"] == "F09")["gate_id"] == "G09"


def test_phase_gate_accepts_gate_id_alias_but_rejects_mismatch(tmp_path):
    evidence = _evidence(tmp_path)
    report = evaluate_phase_gates({"phases": [_phase(tmp_path, evidence, "G09")]}, root=tmp_path)
    row = next(item for item in report["phases"] if item["phase_id"] == "F09")
    assert row["gate_id"] == "G09"
    assert not any(item["code"] == "gate_id_mismatch" for item in report["errors"])

    mismatch = evaluate_phase_gates({"phases": [_phase(tmp_path, evidence, "F09", gate_id="G08")]}, root=tmp_path)
    assert any(item["code"] == "gate_id_mismatch" for item in mismatch["errors"])


def test_phase_gate_missing_phase_is_not_comprovada_and_blocks_gate(tmp_path):
    evidence = _evidence(tmp_path)
    report = evaluate_phase_gates({"phases": [_phase(tmp_path, evidence, "F09")]}, root=tmp_path)
    assert report["status"] == "partial"
    assert report["gate_passed"] is False
    assert report["summary"]["nao_comprovada"] == 12
    assert any(item["code"] == "phase_missing" and item["phase_id"] == "F00" for item in report["errors"])


def test_phase_gate_rejects_declared_quitada_overclaim_and_failed_tests(tmp_path):
    evidence = _evidence(tmp_path)
    report = evaluate_phase_gates(
        {"phases": [_phase(tmp_path, evidence, "F09", status="QUITADA", reviewed=False, tests={"passed": 2, "failed": 1, "skipped": 0})]},
        root=tmp_path,
    )
    row = next(item for item in report["phases"] if item["phase_id"] == "F09")
    codes = {item["code"] for item in report["errors"]}
    assert row["status"] == "NÃO QUITADA"
    assert "declared_status_overclaim" in codes
    assert "phase_missing" in codes


def test_phase_gate_rejects_hash_tampering_and_path_escape(tmp_path):
    evidence = _evidence(tmp_path, content=b"original\n")
    (tmp_path / "evidence.log").write_bytes(b"tampered\n")
    bad = _phase(tmp_path, evidence, "F09")
    bad["evidence"].append({"path": "../outside", "sha256": "a" * 64})
    report = evaluate_phase_gates({"phases": [bad]}, root=tmp_path)
    codes = {item["code"] for item in report["errors"]}
    assert "evidence_hash_mismatch" in codes
    assert "evidence_path_escape" in codes
    assert next(item for item in report["phases"] if item["phase_id"] == "F09")["status"] == "NÃO COMPROVADA"


def test_phase_gate_rejects_bad_shape_and_budget_without_coercion(tmp_path):
    report = evaluate_phase_gates([{"phase_id": "F09", "implementation": 1, "integration": True, "reviewed": True, "tests": {"passed": True, "failed": 0, "skipped": 0}, "evidence": []}], root=tmp_path)
    codes = {item["code"] for item in report["errors"]}
    assert {"phase_boolean_invalid", "test_count_invalid", "evidence_empty", "phase_missing"} <= codes
    assert evaluate_phase_gates([], root=tmp_path, max_evidence=True)["errors"][0]["code"] == "max_evidence_invalid"


def test_phase_gate_cli_fail_closed_and_materializes_report(tmp_path):
    out = tmp_path / "invalid.json"
    code = cmd_phase_gates(Namespace(input=str(tmp_path / "missing.json"), root=str(tmp_path), out=str(out), max_evidence=100))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "input_unreadable"

    scalar = tmp_path / "scalar.json"
    scalar.write_text("[]", encoding="utf-8")
    scalar_out = tmp_path / "scalar-report.json"
    code = cmd_phase_gates(Namespace(input=str(scalar), root=str(tmp_path), out=str(scalar_out), max_evidence=100))
    report = json.loads(scalar_out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["summary"]["nao_comprovada"] == 13


def test_phase_gate_writer_is_deterministic_json(tmp_path):
    report = evaluate_phase_gates([], root=tmp_path)
    out = tmp_path / "gate.json"
    write_phase_gate_report(report, out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == "phase-gate-report.v1"
