"""Bounded, deterministic orchestration for offline F02/F11 validation cases."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any, Sequence


SCHEMA = "validation-campaign.v1"
ALLOWED_CATEGORIES = frozenset({
    "journal_truncation", "commit_crash", "concurrency", "disk_full",
    "timeout", "cancellation", "recovery", "tamper", "parser_bomb",
    "archive_traversal", "prompt_injection", "citation_tamper",
    "oversized_output", "schema_confusion", "unicode_control", "cli_encoding",
})
_SECRET = re.compile(r"(?i)(token|password|secret|api[_-]?key)\s*[=:]\s*([^\s]+)")


@dataclass(frozen=True)
class CampaignCase:
    case_id: str
    category: str
    command: tuple[str, ...]
    expected_exit: int
    expected_codes: tuple[str, ...]
    timeout_s: int


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _tail(data: bytes, limit: int = 4096) -> str:
    text = data.decode("utf-8", errors="replace")
    text = _SECRET.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    return text[-limit:]


def _kill_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       capture_output=True, check=False)
    else:
        try:
            os.killpg(process.pid, 9)
        except ProcessLookupError:
            pass
    try:
        process.kill()
    except OSError:
        pass


def _validate(cases: Sequence[CampaignCase], *, max_cases: int) -> None:
    if not 1 <= max_cases <= 500:
        raise ValueError("max_cases_out_of_range")
    if not cases or len(cases) > max_cases:
        raise ValueError("case_count_out_of_range")
    ids: set[str] = set()
    for case in cases:
        if not isinstance(case, CampaignCase):
            raise ValueError("invalid_case")
        if not case.case_id or case.case_id in ids:
            raise ValueError("duplicate_or_empty_case_id")
        ids.add(case.case_id)
        if case.category not in ALLOWED_CATEGORIES:
            raise ValueError("invalid_category")
        if type(case.command) is not tuple or not case.command or not all(
                isinstance(item, str) and item and "\x00" not in item for item in case.command):
            raise ValueError("invalid_command")
        if not isinstance(case.expected_exit, int) or not case.expected_codes or not all(
                isinstance(code, str) and code for code in case.expected_codes):
            raise ValueError("invalid_expectation")
        if not isinstance(case.timeout_s, int) or not 1 <= case.timeout_s <= 3600:
            raise ValueError("invalid_timeout")


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush(); os.fsync(handle.fileno())
        os.replace(raw, path)
    except BaseException:
        try: os.unlink(raw)
        except FileNotFoundError: pass
        raise


def run_validation_campaign(cases: Sequence[CampaignCase], *, root: Path,
                            output: Path, max_cases: int = 500) -> dict[str, Any]:
    """Execute commands without a shell and fail closed on every mismatch."""
    root = Path(root).resolve()
    output = Path(output).resolve()
    if not root.is_dir():
        raise ValueError("root_not_directory")
    if not _inside(output, root):
        raise ValueError("output_outside_root")
    _validate(cases, max_cases=max_cases)
    rows: list[dict[str, Any]] = []
    for case in cases:
        started = time.monotonic()
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        proc = subprocess.Popen(case.command, cwd=root, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                shell=False, creationflags=flags, env=env,
                                start_new_session=(os.name != "nt"))
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=case.timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree(proc)
            stdout, stderr = proc.communicate()
        combined = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
        matched = [code for code in case.expected_codes if code in combined]
        unavailable = "CAPABILITY_UNAVAILABLE" in combined
        passed = not timed_out and proc.returncode == case.expected_exit and len(matched) == len(case.expected_codes)
        state = "partial" if unavailable and not timed_out else ("passed" if passed else "failed")
        rows.append({
            "case_id": case.case_id, "category": case.category, "status": state,
            "outcome_code": "timeout" if timed_out else ("capability_unavailable" if unavailable else ("matched" if passed else "expectation_mismatch")),
            "expected_exit": case.expected_exit, "exit_code": proc.returncode,
            "expected_codes": list(case.expected_codes), "matched_codes": matched,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "stdout_tail": _tail(stdout), "stderr_tail": _tail(stderr),
            "evidence_hashes": [],
        })
    failed = sum(row["status"] == "failed" for row in rows)
    partial = sum(row["status"] == "partial" for row in rows)
    status = "failed" if failed else ("partial" if partial else "passed")
    report = {
        "schema": SCHEMA, "status": status, "root": str(root),
        "cases": rows,
        "summary": {"total": len(rows), "passed": sum(r["status"] == "passed" for r in rows),
                    "failed": failed, "partial": partial,
                    "categories": sorted({r["category"] for r in rows})},
        "execution": {"shell": False, "target_execution": False, "network_required": False},
    }
    _atomic_json(output, report)
    return report
