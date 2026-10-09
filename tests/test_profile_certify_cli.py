import json
from pathlib import Path

from megazord import main


def _write(path: Path, value: object) -> str:
    path.write_text(json.dumps(value), encoding="utf-8")
    return str(path)


def test_profile_certify_cli_recalculates_and_fails_closed(tmp_path: Path, monkeypatch) -> None:
    scope = _write(tmp_path / "scope.json", {"schema": "profile-scope.v1", "profile_id": "wasm"})
    corpus = _write(tmp_path / "corpus.json", {"development_hash": "a", "calibration_hash": "b", "blind_hash": "c"})
    workers = _write(tmp_path / "workers.json", {"workers": []})
    evaluation = _write(tmp_path / "evaluation.json", {"oracle_independent": False})
    baseline = _write(tmp_path / "baseline.json", {"regressions": []})
    out = tmp_path / "certificate.json"
    monkeypatch.setattr("sys.argv", ["megazord", "profile-certify", "--profile-scope", scope, "--corpus", corpus, "--workers", workers, "--evaluation", evaluation, "--baseline", baseline, "--out", str(out)])
    assert main() == 3
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["status"] == "NAO_COMPROVADA"
    assert {row["code"] for row in report["errors"]} >= {"workers_missing", "independent_oracle_missing"}


def test_profile_certify_cli_rejects_unreadable_input(tmp_path: Path, monkeypatch) -> None:
    out = tmp_path / "certificate.json"
    monkeypatch.setattr("sys.argv", ["megazord", "profile-certify", "--profile-scope", str(tmp_path / "missing.json"), "--corpus", "x", "--workers", "x", "--evaluation", "x", "--baseline", "x", "--out", str(out)])
    assert main() == 3
    assert json.loads(out.read_text(encoding="utf-8"))["errors"][0]["code"] == "certification_input_unreadable"


def test_profile_certify_cli_passes_external_evidence_root_and_trust_map(tmp_path: Path, monkeypatch) -> None:
    scope = _write(tmp_path / "scope.json", {"schema": "profile-scope.v1", "profile_id": "wasm"})
    corpus = _write(tmp_path / "corpus.json", {})
    workers = _write(tmp_path / "workers.json", {})
    evaluation = _write(tmp_path / "evaluation.json", {})
    baseline = _write(tmp_path / "baseline.json", {})
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    external = tmp_path.parent / "external-trust-map.json"
    external.write_text("{}", encoding="utf-8")
    out = tmp_path / "certificate.json"
    seen = {}

    def capture(**kwargs):
        seen.update(kwargs)
        return {"schema": "static-profile-certificate.v1", "profile_id": "wasm", "status": "NAO_COMPROVADA", "errors": [], "limitations": []}

    monkeypatch.setattr("megazord.certify_static_profile", capture)
    monkeypatch.setattr("sys.argv", ["megazord", "profile-certify", "--profile-scope", scope,
        "--corpus", corpus, "--workers", workers, "--evaluation", evaluation, "--baseline", baseline,
        "--evidence-root", str(evidence_root), "--trust-map", str(external), "--out", str(out)])
    assert main() == 3
    assert seen["evidence_root"] == str(evidence_root)
    assert seen["external_trust_map"] == str(external)
