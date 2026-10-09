from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from aether_re.build_link import link_build_artifact


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path):
    source = tmp_path / "src" / "main.c"
    source.parent.mkdir()
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    binary = tmp_path / "build" / "app.elf"
    binary.parent.mkdir()
    binary.write_bytes(b"ELF-observation")
    build = {
        "schema": "build-audit.v1",
        "root": str(tmp_path),
        "compile_commands": [{
            "file": "src/main.c",
            "directory": str(tmp_path),
            "output": str(binary),
            "compiler": "gcc",
            "source_sha256": _sha(source),
            "executed": False,
        }],
    }
    report = {"target_sha256": _sha(binary)}
    return source, binary, build, report


def test_build_link_requires_declared_output_and_hashes(tmp_path: Path):
    source, binary, build, report = _fixture(tmp_path)
    linked = link_build_artifact(build, binary, binary_report=report)
    assert linked["status"] == "linked"
    assert linked["proof"]["source_hashes_match"] is True
    assert linked["equivalence_proven"] is False
    assert linked["executed"] is False
    assert linked["matches"][0]["compiler"] == "gcc"


def test_build_link_rejects_changed_source_hash(tmp_path: Path):
    source, binary, build, report = _fixture(tmp_path)
    source.write_text("int main(void) { return 1; }\n", encoding="utf-8")
    partial = link_build_artifact(build, binary, binary_report=report)
    assert partial["status"] == "partial"
    assert partial["matches"][0]["source_hash_match"] is False


def test_build_link_is_explicitly_unmatched_without_output_declaration(tmp_path: Path):
    source, binary, build, report = _fixture(tmp_path)
    build["compile_commands"][0].pop("output")
    unmatched = link_build_artifact(build, binary, binary_report=report)
    assert unmatched["status"] == "unmatched"
    assert unmatched["reason"] == "declared_output_not_found"


def test_build_link_cli_writes_hash_bound_report(tmp_path: Path):
    source, binary, build, report = _fixture(tmp_path)
    build_path = tmp_path / "build-audit.json"
    binary_report_path = tmp_path / "binary-report.json"
    out = tmp_path / "link.json"
    build_path.write_text(json.dumps(build), encoding="utf-8")
    binary_report_path.write_text(json.dumps(report), encoding="utf-8")
    command = [sys.executable, str(Path(__file__).parents[1] / "megazord.py"), "build-link", "--build-report", str(build_path), "--binary", str(binary), "--binary-report", str(binary_report_path), "--out", str(out)]
    completed = subprocess.run(command, cwd=str(Path(__file__).parents[1]), capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["status"] == "linked"
    assert data["binary_sha256"] == _sha(binary)
