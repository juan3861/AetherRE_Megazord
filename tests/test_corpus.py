import json
from pathlib import Path

import pytest

from tools.bootstrap_corpus import generate_corpus


def test_bootstrap_corpus_has_known_oracles_and_family_split(tmp_path: Path):
    manifest = generate_corpus(tmp_path / "corpus")
    assert manifest["count"] == 20
    assert {item["language"] for item in manifest["projects"]} == {"python", "c"}
    assert {item["split"] for item in manifest["projects"]} == {"development", "calibration", "holdout"}
    families_by_split = {
        split: {item["family"] for item in manifest["projects"] if item["split"] == split}
        for split in {item["split"] for item in manifest["projects"]}
    }
    assert not (families_by_split["development"] & families_by_split["holdout"])
    for item in manifest["projects"]:
        source = tmp_path / "corpus" / item["source"]
        oracle = tmp_path / "corpus" / item["oracle"]
        assert source.is_file() and oracle.is_file()
        oracle_data = json.loads(oracle.read_text(encoding="utf-8"))
        assert oracle_data["family"] == item["family"]
        source_text = source.read_text(encoding="utf-8")
        assert all(symbol in source_text for symbol in oracle_data["expected_symbols"])


def test_bootstrap_corpus_refuses_overwrite(tmp_path: Path):
    out = tmp_path / "corpus"
    generate_corpus(out)
    with pytest.raises(FileExistsError):
        generate_corpus(out)
