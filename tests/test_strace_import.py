import hashlib
import json
import subprocess
import sys
from pathlib import Path

from aether_re.strace_import import parse_strace_text


def test_strace_import_normalizes_real_syscalls_and_provenance():
    raw = (
        "1234 1700000000.000001 openat(AT_FDCWD, \"/tmp/input\", O_RDONLY) = 3 <0.000010>\n"
        "1234 1700000000.000002 read(3, \"x\", 1) = 1 <0.000002>\n"
    )

    report = parse_strace_text(
        raw,
        target_sha256="a" * 64,
        run_id="qualification-1",
        source_sha256="b" * 64,
    )

    assert report["status"] == "complete"
    assert report["summary"] == {"received": 2, "accepted": 2, "issues": 0}
    assert report["events"][0] == {
        "seq": 0,
        "timestamp_ns": 1_700_000_000_000_001_000,
        "thread_id": "1234",
        "process_id": "1234",
        "event": "openat",
        "module": "linux.syscall",
        "payload": {
            "arguments": 'AT_FDCWD, "/tmp/input", O_RDONLY',
            "result": "3",
            "duration_seconds": "0.000010",
            "source_line": 1,
        },
    }
    assert report["trace_metadata"]["target_sha256"] == "a" * 64
    assert report["trace_metadata"]["source_sha256"] == "b" * 64
    assert "does not prove target identity" in " ".join(report["limitations"])


def test_strace_import_marks_unparsed_lines_partial_without_leaking_trace_text():
    report = parse_strace_text(
        "this may contain a secret command argument\n"
        "1234 1700000000.000001 openat(AT_FDCWD, \"/tmp/x\", O_RDONLY) = 3 <0.000001>\n",
        target_sha256="a" * 64,
        run_id="qualification-2",
        source_sha256="b" * 64,
    )

    assert report["status"] == "partial"
    assert report["summary"]["accepted"] == 1
    assert report["issues"] == [{"line": 1, "kind": "unparsed_strace_line"}]
    assert "secret" not in str(report)


def test_strace_import_rejects_invalid_target_hash_and_event_budget():
    raw = "1234 1700000000.000001 openat(AT_FDCWD, \"/tmp/x\", O_RDONLY) = 3 <0.000001>\n"

    invalid = parse_strace_text(raw, target_sha256="bad", run_id="qualification-3", source_sha256="b" * 64)
    assert invalid["status"] == "invalid"
    assert any(issue["kind"] == "target_hash_invalid" for issue in invalid["issues"])

    bounded = parse_strace_text(
        raw + raw,
        target_sha256="a" * 64,
        run_id="qualification-4",
        source_sha256="b" * 64,
        max_events=1,
    )
    assert bounded["status"] == "partial"
    assert bounded["summary"]["received"] == 2
    assert any(issue["kind"] == "event_budget_exceeded" for issue in bounded["issues"])


def test_trace_import_strace_cli_binds_raw_file_hash_and_writes_report(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    raw = tmp_path / "trace.txt"
    out = tmp_path / "normalized.json"
    raw.write_text(
        "1234 1700000000.000001 openat(AT_FDCWD, \"/tmp/x\", O_RDONLY) = 3 <0.000001>\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(root / "megazord.py"),
            "trace-import-strace",
            "--input",
            str(raw),
            "--target-sha256",
            "a" * 64,
            "--run-id",
            "qualification-cli",
            "--isolation",
            "hyperv-private-vswitch",
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["status"] == "complete"
    assert report["trace_metadata"]["target_sha256"] == "a" * 64
    assert report["parser"]["source_sha256"] == hashlib.sha256(raw.read_bytes()).hexdigest()


def test_trace_import_strace_cli_fails_closed_for_missing_input(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    out = tmp_path / "rejected.json"
    result = subprocess.run(
        [
            sys.executable,
            str(root / "megazord.py"),
            "trace-import-strace",
            "--input",
            str(tmp_path / "absent.txt"),
            "--target-sha256",
            "a" * 64,
            "--run-id",
            "qualification-missing",
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert json.loads(out.read_text(encoding="utf-8"))["issues"] == [{"kind": "source_unreadable"}]
