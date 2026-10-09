import hashlib
import json
from pathlib import Path

from megazord import main


def _evidence(root: Path, gate: str) -> str:
    artifact = root / "proof" / f"{gate}.bin"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    payload = f"proof:{gate}".encode()
    artifact.write_bytes(payload)
    evidence = {
        "schema": "gate-evidence.v1", "gate": gate, "status": "QUITADA",
        "gate_passed": True, "integrity_errors": [], "blocking_gates": [],
        "artifacts": [{"path": f"proof/{gate}.bin", "sha256": hashlib.sha256(payload).hexdigest()}],
    }
    evidence_path = root / "gates" / f"{gate}.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    return str(evidence_path.relative_to(root))


def test_release_build_cli_emits_real_manifest_from_material_gate_evidence(tmp_path, monkeypatch):
    paths = [_evidence(tmp_path, f"F{index:02d}") for index in range(13)]
    toolchain = tmp_path / "toolchain-lock.json"
    corpus = tmp_path / "corpus-lock.json"
    toolchain.write_bytes(b"material toolchain lock")
    corpus.write_bytes(b"material corpus lock")
    report = tmp_path / "report.json"

    monkeypatch.setattr("sys.argv", ["megazord", "release-build", "--release-root", str(tmp_path),
        "--commit", "a" * 40, "--toolchain-lock", str(toolchain), "--corpus-lock", str(corpus),
        "--gate-evidence", *paths, "--manifest-out", "release-manifest.json", "--out", str(report)])
    assert main() == 0

    result = json.loads(report.read_text(encoding="utf-8"))
    manifest = json.loads((tmp_path / "release-manifest.json").read_text(encoding="utf-8"))
    assert result["manifest_built"] is True
    assert manifest["schema"] == "release-manifest.v1"
    assert len(manifest["gates"]) == 13


def test_release_build_cli_stays_blocked_when_only_gate_status_strings_exist(tmp_path, monkeypatch):
    phases = tmp_path / "phases.json"
    report = tmp_path / "report.json"
    phases.write_text(json.dumps({"schema": "phase-gate-report.v1", "phases": [
        {"phase_id": f"F{index:02d}", "status": "QUITADA"} for index in range(13)
    ]}), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["megazord", "release-build", "--phase-report", str(phases), "--out", str(report)])

    assert main() == 3
    result = json.loads(report.read_text(encoding="utf-8"))
    assert result["manifest_built"] is False
    assert result["status"] == "blocked"
