from pathlib import Path

from aether_re.pipeline import run_megazord


def test_real_run_publishes_explicit_binary_identity(tmp_path: Path):
    fixture = Path(__file__).resolve().parents[1] / "samples" / "fixtures" / "notepad_reference.exe"
    report = run_megazord(fixture, out_dir=tmp_path / "run", use_adapters=False, deep=False)
    assert report.target_identity["architecture"] == "x86_64"
    assert report.target_identity["module"] == fixture.name
    assert report.target_identity["sha256"] == report.target_sha256
