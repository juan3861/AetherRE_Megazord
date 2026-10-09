import json
from argparse import Namespace

from aether_re.correlation import correlate_source_to_binary
from megazord import cmd_correlate


def test_correlation_preserves_ambiguous_and_unmatched_candidates():
    report = correlate_source_to_binary(
        [{"qualified_name": "pkg.main"}, {"qualified_name": "pkg.missing"}, {"qualified_name": "other.main"}],
        [
            {"address": "0x1000", "name": "main", "source": "symbols"},
            {"address": "0x2000", "name": "main", "source": "debug"},
        ],
    )
    assert report["schema"] == "source-binary-correlation.v1"
    assert report["status"] == "partial"
    assert [item["status"] for item in report["matches"]] == ["ambiguous", "unmatched", "ambiguous"]
    assert all(item["confidence_kind"] == "heuristic" for item in report["matches"])
    assert report["summary"]["candidate_coverage"] == 0.0


def test_correlation_accepts_elf_symbol_records_without_promoting_them():
    report = correlate_source_to_binary(
        [{"qualified_name": "pkg.main"}],
        [{"name": "main", "value": "0x401000"}],
    )
    match = report["matches"][0]
    assert match["status"] == "candidate"
    assert match["binary_candidates"] == [{"address": "0x401000", "name": "main", "source": "elf-symbol"}]
    assert match["requires_validation"] is True


def test_correlation_strips_elf_symbol_version_suffix():
    report = correlate_source_to_binary(
        [{"qualified_name": "pkg.__cxa_finalize"}],
        [{"name": "__cxa_finalize@@GLIBC_2.2.5", "value": "0x1000"}],
    )
    assert report["matches"][0]["status"] == "candidate"


def test_correlation_deduplicates_repeated_elf_symbol_tables():
    report = correlate_source_to_binary(
        [{"qualified_name": "pkg.main"}],
        [
            {"name": "main", "value": "0x401000"},
            {"name": "main", "value": "0x401000"},
        ],
    )
    assert report["matches"][0]["status"] == "candidate"
    assert len(report["matches"][0]["binary_candidates"]) == 1


def test_correlation_attaches_declared_build_unit_without_promoting_match():
    report = correlate_source_to_binary(
        [{"qualified_name": "src/main.c:main", "module": "src/main.c"}],
        [{"name": "main", "value": "0x401000"}],
        build_report={
            "schema": "build-audit.v1",
            "compile_commands": [
                {
                    "file": "src/main.c",
                    "compiler": "clang",
                    "flags": ["-O2"],
                    "executed": False,
                }
            ],
        },
    )
    match = report["matches"][0]
    assert match["status"] == "candidate"
    assert match["build_link"] == "linked"
    assert match["build_units"][0]["compiler"] == "clang"
    assert match["requires_validation"] is True
    assert report["build_provenance"] == {
        "supplied": True,
        "compile_units": 1,
        "executed": False,
        "limitations": [
            "compile_commands é declaração estática",
            "vínculo por arquivo não prova que o binário foi produzido pela unidade",
            "flags/toolchain/debug info exigem verificação independente",
        ],
    }


def test_correlation_rejects_malformed_records_without_dropping_them():
    report = correlate_source_to_binary([{"qualified_name": "pkg.main"}, "bad"], [{"name": "main"}, {"address": "0x20"}])
    assert report["status"] == "invalid"
    codes = {item["code"] for item in report["errors"]}
    assert {"function_not_object", "function_name_missing"} <= codes


def test_correlation_cli_rejects_unreadable_input_without_traceback(tmp_path):
    source = tmp_path / "source.json"
    binary = tmp_path / "binary.json"
    out = tmp_path / "correlation.json"
    source.write_text("{", encoding="utf-8")
    binary.write_text(json.dumps({"functions": []}), encoding="utf-8")
    code = cmd_correlate(Namespace(source_report=str(source), binary_report=str(binary), build_report=None, out=str(out)))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "input_unreadable"


def test_correlation_cli_rejects_scalar_reports_without_traceback(tmp_path):
    source = tmp_path / "source.json"
    binary = tmp_path / "binary.json"
    out = tmp_path / "correlation.json"
    source.write_text(json.dumps([]), encoding="utf-8")
    binary.write_text(json.dumps([]), encoding="utf-8")
    code = cmd_correlate(Namespace(source_report=str(source), binary_report=str(binary), build_report=None, out=str(out)))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "input_shape_invalid"
