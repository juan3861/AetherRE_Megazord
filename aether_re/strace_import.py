"""Fail-closed normalization of Linux strace text into dynamic-trace.v1."""

from __future__ import annotations

import hashlib
import re
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from pathlib import Path
from typing import Any

from .trace import validate_trace_document


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_LINE_RE = re.compile(
    r"^(?:(?:\[pid\s+(?P<wrapped_pid>\d+)\]\s+)|(?P<pid>\d+)\s+)?"
    r"(?P<timestamp>\d{9,}(?:\.\d+)?)\s+(?P<body>.+)$"
)
_CALL_RE = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<arguments>.*)\)\s*="
    r"\s*(?P<result>.*?)\s*(?:<(?P<duration>\d+(?:\.\d+)?)>)?"
)
_KNOWN_NON_EVENT_RE = re.compile(
    r"^(?:\+\+\+ (?:exited|killed by) .+ \+\+\+|"
    r"--- [A-Z0-9]+ .+ ---|strace: Process \d+ (?:attached|detached))$"
)


def _invalid(issue: str, *, source_sha256: str | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "dynamic-trace.v1",
        "events": [],
        "issues": [{"kind": issue}],
        "status": "invalid",
        "summary": {"received": 0, "accepted": 0, "issues": 1},
        "limitations": [
            "parser does not establish causal completeness or prove VM isolation",
            "raw trace and collector provenance must be verified independently",
        ],
    }
    if source_sha256 is not None:
        report["trace_metadata"] = {"source_sha256": source_sha256}
    return report


def parse_strace_text(
    text: str,
    *,
    target_sha256: str,
    run_id: str,
    source_sha256: str,
    isolation: str = "unverified",
    max_events: int = 100_000,
    max_bytes: int = 50 * 1024 * 1024,
) -> dict[str, Any]:
    """Parse timestamped syscall rows without treating raw trace as attestation.

    Expected input is Linux strace output collected with ``-ttt`` and a single
    output file. Unknown rows are counted by line number (their contents are
    intentionally not copied into the normalized report). The caller remains
    responsible for binding this parse to the raw file hash and the VM run.
    """
    if not isinstance(text, str):
        return _invalid("strace_text_invalid")
    if not isinstance(target_sha256, str) or not _SHA256_RE.fullmatch(target_sha256):
        return _invalid("target_hash_invalid", source_sha256=source_sha256 if isinstance(source_sha256, str) else None)
    if not isinstance(source_sha256, str) or not _SHA256_RE.fullmatch(source_sha256):
        return _invalid("source_hash_invalid")
    if not isinstance(run_id, str) or not run_id.strip():
        return _invalid("run_id_invalid", source_sha256=source_sha256)
    if not isinstance(isolation, str) or not isolation.strip():
        return _invalid("isolation_invalid", source_sha256=source_sha256)
    if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
        return _invalid("max_events_invalid", source_sha256=source_sha256)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        return _invalid("max_bytes_invalid", source_sha256=source_sha256)

    encoded_size = len(text.encode("utf-8", errors="surrogatepass"))
    if encoded_size > max_bytes:
        return _invalid("input_byte_budget_exceeded", source_sha256=source_sha256)

    events: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    non_event_lines = 0
    received_syscalls = 0

    for line_number, line in enumerate(text.splitlines(), start=1):
        row = line.strip()
        if not row:
            continue
        match = _LINE_RE.fullmatch(row)
        if match is None:
            if _KNOWN_NON_EVENT_RE.fullmatch(row):
                non_event_lines += 1
            else:
                issues.append({"line": line_number, "kind": "unparsed_strace_line"})
            continue

        call = _CALL_RE.fullmatch(match.group("body"))
        if call is None:
            # A syscall split over unfinished/resumed lines is not silently
            # reconstructed: this version reports partial evidence instead.
            issues.append({"line": line_number, "kind": "unparsed_strace_call"})
            continue
        received_syscalls += 1
        if len(events) >= max_events:
            continue
        try:
            timestamp_ns = int(
                (Decimal(match.group("timestamp")) * Decimal(1_000_000_000)).to_integral_value(
                    rounding=ROUND_HALF_EVEN
                )
            )
        except (InvalidOperation, ValueError, OverflowError):
            issues.append({"line": line_number, "kind": "timestamp_invalid"})
            continue
        pid = match.group("wrapped_pid") or match.group("pid") or "unknown"
        duration = call.group("duration")
        result = call.group("result").strip()
        if duration is not None and result.endswith(f"<{duration}>"):
            result = result[: -(len(duration) + 2)].rstrip()
        events.append(
            {
                "seq": len(events),
                "timestamp_ns": timestamp_ns,
                "thread_id": pid,
                "process_id": pid,
                "event": call.group("name"),
                "module": "linux.syscall",
                "payload": {
                    "arguments": call.group("arguments"),
                    "result": result,
                    "duration_seconds": duration,
                    "source_line": line_number,
                },
            }
        )

    if received_syscalls > max_events:
        issues.append(
            {"kind": "event_budget_exceeded", "received": received_syscalls, "max": max_events}
        )
    if not events:
        issues.append({"kind": "no_syscall_events"})

    report = validate_trace_document(
        {
            "schema": "dynamic-trace.v1",
            "target_sha256": target_sha256,
            "run_id": run_id,
            "collector": "strace -f -ttt normalized by RE_Megazord",
            "isolation": isolation,
            "source": "linux-strace-text",
            "events": events,
        },
        max_events=max_events,
    )
    report["issues"].extend(issues)
    report["summary"]["received"] = received_syscalls
    report["summary"]["issues"] = len(report["issues"])
    report["summary"]["accepted"] = len(report["events"])
    report["parser"] = {
        "name": "aether_re.strace_import",
        "version": 1,
        "source_sha256": source_sha256,
        "source_bytes": encoded_size,
        "known_non_event_lines": non_event_lines,
        "unparsed_lines": sum(issue["kind"].startswith("unparsed_strace") for issue in issues),
    }
    report.setdefault("trace_metadata", {})["source_sha256"] = source_sha256
    report["limitations"] = [
        "normalization preserves syscall rows but does not establish causal completeness",
        "strace filtering, ptrace effects, lost events, and process coverage must be assessed separately",
        "the parser alone does not prove target identity, execution, VM isolation, or rollback",
    ]
    if report["status"] != "invalid" and (issues or not events):
        report["status"] = "partial" if events else "insufficient_data"
    return report


def parse_strace_file(
    path: Path,
    *,
    target_sha256: str,
    run_id: str,
    isolation: str = "unverified",
    max_events: int = 100_000,
    max_bytes: int = 50 * 1024 * 1024,
) -> dict[str, Any]:
    """Read and hash the raw source before parsing; unreadable files fail closed."""
    try:
        raw = path.read_bytes()
    except (FileNotFoundError, OSError):
        return _invalid("source_unreadable")
    source_sha256 = hashlib.sha256(raw).hexdigest()
    if len(raw) > max_bytes:
        return _invalid("input_byte_budget_exceeded", source_sha256=source_sha256)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _invalid("source_encoding_invalid", source_sha256=source_sha256)
    return parse_strace_text(
        text,
        target_sha256=target_sha256,
        run_id=run_id,
        source_sha256=source_sha256,
        isolation=isolation,
        max_events=max_events,
        max_bytes=max_bytes,
    )
