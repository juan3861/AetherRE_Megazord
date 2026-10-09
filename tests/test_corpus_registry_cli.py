import json
from pathlib import Path

from megazord import main


def test_corpus_registry_cli_forwards_external_oracle_attestation_and_trust_map(tmp_path: Path, monkeypatch) -> None:
    registry = tmp_path / "registry.json"
    oracle = tmp_path.parent / "blind-oracle.json"
    attestation = tmp_path.parent / "attestation.json"
    trust_map = tmp_path.parent / "trust-map.json"
    root = tmp_path / "corpus"
    root.mkdir()
    for path in (registry, oracle, attestation, trust_map):
        path.write_text("{}", encoding="utf-8")
    out = tmp_path / "validation.json"
    seen = {}

    def capture(registry_path, corpus_root, **kwargs):
        seen.update(registry_path=registry_path, corpus_root=corpus_root, **kwargs)
        return {"status": "NAO_COMPROVADA", "entry_count": 0, "errors": [], "limitations": []}

    monkeypatch.setattr("megazord.validate_corpus_registry", capture)
    monkeypatch.setattr("sys.argv", ["megazord", "corpus-registry-validate", "--registry", str(registry),
        "--root", str(root), "--blind-oracle", str(oracle), "--blind-attestation", str(attestation),
        "--trust-map", str(trust_map), "--out", str(out)])

    assert main() == 3
    assert seen == {
        "registry_path": str(registry), "corpus_root": str(root),
        "blind_oracle_path": str(oracle), "blind_attestation_path": str(attestation),
        "trust_map_path": str(trust_map),
    }
    assert json.loads(out.read_text(encoding="utf-8"))["status"] == "NAO_COMPROVADA"
