from argparse import Namespace
import json
import pytest
from pathlib import Path

from aether_re.c_source import analyze_c_family_project, write_c_source_report
from megazord import cmd_c_source_analyze


def test_c_family_reader_collects_candidates_without_execution(tmp_path):
    root = tmp_path / "cproj"
    (root / "src").mkdir(parents=True)
    (root / "include").mkdir()
    (root / "src" / "main.c").write_text(
        '#include "api.h"\n#define LIMIT 4\nstatic int add(int a, int b) { return helper(a) + b; }\nint helper(int x) { return x * LIMIT; }\n',
        encoding="utf-8",
    )
    (root / "include" / "api.h").write_text("int add(int, int);\n", encoding="utf-8")
    report = analyze_c_family_project(root)
    assert report["schema"] == "c-family-source-analysis.v1"
    assert {item["name"] for item in report["functions"]} == {"add", "helper"}
    assert report["includes"][0]["target"] == '"api.h"'
    assert any(item["name"] == "LIMIT" for item in report["macros"])
    assert any(item["callee"] == "helper" and not item["resolved"] for item in report["calls"])
    assert "heurístico" in report["limitations"][0]
    assert any(edge["kind"] == "includes" and edge["resolved"] is True for edge in report["graph"]["edges"])
    assert any(edge["kind"] == "calls" and edge["target"] == "helper" and edge["resolved"] is True for edge in report["graph"]["edges"])
    out = tmp_path / "report.json"
    write_c_source_report(report, out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == report["schema"]


def test_c_family_reader_does_not_misclassify_type_names_as_calls(tmp_path):
    source = tmp_path / "callback.c"
    source.write_text("int callback(int (*fn)(int), int value) { return fn(value); }\n", encoding="utf-8")
    report = analyze_c_family_project(tmp_path)
    assert [item["callee"] for item in report["calls"]] == ["fn"]


def test_c_source_cli_rejects_missing_root_without_traceback(tmp_path):
    out = tmp_path / "invalid-c-source.json"
    code = cmd_c_source_analyze(Namespace(root=str(tmp_path / "missing"), out=str(out)))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["errors"][0]["kind"] == "input_invalid"


def test_c_source_skips_symlinked_source_with_explicit_error(tmp_path):
    real = tmp_path / "real.c"
    real.write_text("int safe(void) { return 1; }\n", encoding="utf-8")
    linked = tmp_path / "linked.c"
    try:
        linked.symlink_to(real)
    except OSError:
        pytest.skip("symlink capability unavailable")
    report = analyze_c_family_project(tmp_path)
    assert not any(item["path"] == "linked.c" for item in report["modules"])
    assert any(item["kind"] == "symlink_skipped" and item["path"] == "linked.c" for item in report["errors"])


def test_c_source_budget_abstains_before_large_read(tmp_path):
    (tmp_path / "large.c").write_text("int main(void) { return 0; }\n" * 10, encoding="utf-8")
    report = analyze_c_family_project(tmp_path, max_file_bytes=16)
    assert report["modules"] == []
    assert report["errors"][0]["kind"] == "max_file_bytes_exceeded"
    assert report["summary"]["bytes_read"] == 0
    assert report["summary"]["candidates"] == 1


def test_c_family_reader_binds_compile_commands_without_execution(tmp_path):
    (tmp_path / "src").mkdir()
    source = tmp_path / "src" / "main.c"
    source.write_text("#include \"api.h\"\nint run(int value) { return value + 1; }\n", encoding="utf-8")
    (tmp_path / "src" / "api.h").write_text("int run(int);\n", encoding="utf-8")
    (tmp_path / "compile_commands.json").write_text(json.dumps([{
        "directory": str(tmp_path),
        "file": "src/main.c",
        "arguments": ["clang", "-Isrc", "-DMODE=1", "-c", "src/main.c"],
    }]), encoding="utf-8")
    report = analyze_c_family_project(tmp_path)
    assert report["compile_context"]["status"] == "available"
    assert report["compile_context"]["matched_entries"] == 1
    unit = next(item for item in report["modules"] if item["path"] == "src/main.c")["compile_unit"]
    assert unit["compiler"] == "clang"
    assert unit["include_dirs"] == ["src"]
    assert unit["defines"] == ["MODE=1"]
    assert unit["arguments"][-1] == "src/main.c"
    assert unit["entry_sha256"]
    assert report["compile_context"]["executed"] is False


def test_c_family_reader_rejects_compile_command_path_escape(tmp_path):
    (tmp_path / "main.c").write_text("int run(void) { return 1; }\n", encoding="utf-8")
    outside = tmp_path.parent / "outside.c"
    outside.write_text("int outside(void) { return 0; }\n", encoding="utf-8")
    (tmp_path / "compile_commands.json").write_text(json.dumps([{
        "directory": str(tmp_path), "file": str(outside), "command": "clang -c outside.c"
    }]), encoding="utf-8")
    report = analyze_c_family_project(tmp_path)
    assert report["compile_context"]["status"] == "partial"
    assert any(error["code"] == "compile_command_path_escape" for error in report["compile_context"]["errors"])
    assert report["compile_context"]["matched_entries"] == 0


def test_c_family_reader_reports_malformed_compile_commands_without_execution(tmp_path):
    (tmp_path / "main.c").write_text("int run(void) { return 1; }\n", encoding="utf-8")
    (tmp_path / "compile_commands.json").write_text("{malformed", encoding="utf-8")
    report = analyze_c_family_project(tmp_path)
    assert report["compile_context"]["status"] == "invalid"
    assert report["compile_context"]["executed"] is False
    assert report["modules"]


def test_c_family_reader_accepts_juliet_style_brace_on_following_line(tmp_path):
    source = tmp_path / "juliet.c"
    source.write_text(
        "void declared(void);\n"
        "void external_bad(void)\n"
        "{\n"
        "    helper();\n"
        "}\n"
        "static int helper(void)\n"
        "{\n"
        "    return 1;\n"
        "}\n",
        encoding="utf-8",
    )
    report = analyze_c_family_project(tmp_path)
    names = {item["name"] for item in report["functions"]}
    assert names == {"external_bad", "helper"}
    definition = next(item for item in report["functions"] if item["name"] == "external_bad")
    assert definition["line"] == 2
    assert definition["body_line"] == 3
    assert any(item["caller"].endswith(":external_bad") and item["callee"] == "helper" for item in report["calls"])
def test_c_family_reader_supports_declared_source_scope(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_text("int main(void) { return helper(); }\n", encoding="utf-8")
    (tmp_path / "src" / "support.c").write_text("int helper(void) { return 1; }\nint unrelated(void) { return 2; }\n", encoding="utf-8")
    report = analyze_c_family_project(tmp_path, source_files=["src/main.c"])
    assert report["analysis_scope"] == {"mode": "declared_source_files", "files": ["src/main.c"]}
    assert {item["name"] for item in report["functions"]} == {"main"}
    assert [item["path"] for item in report["modules"]] == ["src/main.c"]
