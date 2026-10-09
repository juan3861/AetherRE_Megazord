import json
import hashlib

from aether_re.build_audit import audit_build, write_build_report


def test_build_audit_collects_provenance_candidates_without_running_tools(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\nproject(demo)\nadd_executable(demo src/main.cpp)\nset(CMAKE_CXX_FLAGS \"-O2 -g\")\n",
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    report = audit_build(root)
    assert report["schema"] == "build-audit.v1"
    assert report["status"] == "observed"
    assert "cmake" in report["build_systems"]
    assert "cmake" in report["tools"]
    assert "-O2" in report["flags"]
    assert "src/main.cpp" in report["source_candidates"]
    assert all(item["confidence"] == "candidate" for item in report["observations"])
    out = tmp_path / "build.json"
    write_build_report(report, out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == report["schema"]


def test_build_audit_reports_absence_without_failure_or_execution(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    report = audit_build(root)
    assert report["status"] == "not_found"
    assert report["files"] == []
    assert report["tools"] == []


def test_build_audit_parses_compile_commands_as_unexecuted_provenance(tmp_path):
    root = tmp_path / "project"
    source = root / "src" / "main.c"
    source.parent.mkdir(parents=True)
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (root / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": "src/main.c",
                    "command": "clang -Iinclude -O2 -g -c src/main.c -o main.o",
                }
            ]
        ),
        encoding="utf-8",
    )
    report = audit_build(root)
    assert report["status"] == "observed"
    assert report["compile_commands"]
    unit = report["compile_commands"][0]
    assert unit["compiler"] == "clang"
    assert unit["file"] == "src/main.c"
    assert unit["source_scope"] == "within_root"
    assert unit["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert unit["executed"] is False
    assert "-O2" in unit["flags"]
    assert "clang" in report["tools"]
    assert "main.o" in report["output_candidates"]
    assert any(item["method"] == "compile_commands" for item in report["observations"])


def test_build_audit_keeps_malformed_compile_database_explicit(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "compile_commands.json").write_text("{not-json", encoding="utf-8")
    report = audit_build(root)
    assert report["status"] == "partial"
    assert report["compile_commands"] == []
    assert any(issue["code"] == "compile_commands_invalid_json" for issue in report["issues"])
