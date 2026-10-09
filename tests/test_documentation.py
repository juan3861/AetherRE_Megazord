import hashlib
import json
from argparse import Namespace

from aether_re.documentation import audit_documentation, write_documentation_report
from megazord import cmd_documentation_audit


def test_documentation_audit_extracts_structure_without_executing_code(tmp_path):
    (tmp_path / "README.md").write_text(
        "# Project\n\nSee [guide](docs/guide.md) and [external](https://example.invalid/x).\n\n```powershell\nWrite-Error 'must not run'\n```\n",
        encoding="utf-8",
    )
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("## Guide\n\n[home](../README.md)\n", encoding="utf-8")
    report = audit_documentation(tmp_path)
    assert report["status"] == "complete"
    assert report["summary"]["documents"] == 2
    assert report["summary"]["local_resolved"] == 2
    assert report["summary"]["external_links"] == 1
    assert report["documents"][0]["headings"][0]["text"] == "Project"
    assert report["documents"][0]["fences"][0]["language"] == "powershell"


def test_documentation_audit_marks_broken_and_unsafe_links_partial(tmp_path):
    (tmp_path / "README.md").write_text("[missing](missing.md) [escape](../outside.md) [drive](C:/secret.txt)\n", encoding="utf-8")
    report = audit_documentation(tmp_path)
    assert report["status"] == "partial"
    assert report["summary"]["local_unresolved"] == 1
    assert report["summary"]["unsafe_links"] == 2
    codes = {item["code"] for item in report["issues"]}
    assert {"local_reference_unresolved", "unsafe_reference"} <= codes


def test_documentation_audit_malformed_ipv6_url_is_unsafe_not_exception(tmp_path):
    (tmp_path / "README.md").write_text("[bad](http://[broken)\n", encoding="utf-8")
    report = audit_documentation(tmp_path)
    assert report["status"] == "partial"
    assert report["summary"]["unsafe_links"] == 1
    assert report["references"][0]["status"] == "unsafe"


def test_documentation_audit_preserves_external_links_without_fetching(tmp_path):
    (tmp_path / "README.md").write_text("See https://example.invalid/a and mailto:user@example.invalid\n", encoding="utf-8")
    report = audit_documentation(tmp_path)
    assert report["status"] == "complete"
    assert report["summary"]["external_links"] == 1
    assert all(item["status"] != "unsafe" for item in report["references"])


def test_documentation_audit_rejects_limits_and_missing_root(tmp_path):
    invalid = audit_documentation(tmp_path / "missing")
    assert invalid["status"] == "invalid"
    assert invalid["errors"][0]["code"] == "root_missing"
    limited = audit_documentation(tmp_path, max_files=True)
    assert limited["errors"][0]["code"] == "limits_invalid"


def test_documentation_audit_detects_truncation_and_symlink_without_reading_target(tmp_path):
    (tmp_path / "README.md").write_text("# root\n", encoding="utf-8")
    (tmp_path / "large.md").write_text("x" * 100, encoding="utf-8")
    outside = tmp_path.parent / "outside-doc.md"
    outside.write_text("# outside\n", encoding="utf-8")
    link = tmp_path / "linked.md"
    try:
        link.symlink_to(outside)
    except OSError:
        link = None
    report = audit_documentation(tmp_path, max_file_bytes=20)
    assert report["status"] == "partial"
    assert report["summary"]["truncated"] is True
    assert any(item["reason"] == "max_file_bytes" for item in report["skipped"])
    if link is not None:
        assert any(item["code"] == "symlink_document_skipped" for item in report["issues"])
    outside.unlink(missing_ok=True)


def test_documentation_audit_cli_materializes_report(tmp_path):
    (tmp_path / "README.md").write_text("# ok\n", encoding="utf-8")
    out = tmp_path / "docs.json"
    code = cmd_documentation_audit(Namespace(root=str(tmp_path), out=str(out), max_files=100, max_bytes=100000, max_file_bytes=1000))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 0
    assert report["status"] == "complete"
    assert report["summary"]["documents"] == 1


def test_documentation_report_writer_is_stable(tmp_path):
    report = audit_documentation(tmp_path)
    out = tmp_path / "report.json"
    write_documentation_report(report, out)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["root_digest"] == hashlib.sha256(b"").hexdigest()
