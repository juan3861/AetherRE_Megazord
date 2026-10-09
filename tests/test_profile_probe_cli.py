import json
from pathlib import Path

from megazord import main


def test_profile_probe_identifies_wasm_and_writes_envelope(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "sample.wasm"
    target.write_bytes(b"\0asm\x01\0\0\0")
    out = tmp_path / "probe.json"
    monkeypatch.setattr("sys.argv", ["megazord", "profile-probe", str(target), "--out", str(out)])
    assert main() == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["status"] == "identified"
    assert report["matches"][0]["profile_id"] == "wasm"
    assert report["matches"][0]["capability_envelope"]["static_only"] is True


def test_profile_probe_rejects_unknown_input(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "unknown.bin"
    target.write_bytes(b"not-a-known-format")
    monkeypatch.setattr("sys.argv", ["megazord", "profile-probe", str(target)])
    assert main() == 2
