"""Capture a deterministic, scope-clean RE_Megazord program baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any, Iterator


SCHEMA = "program-baseline.v1"
EXCLUDED_DIR_NAMES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".superpowers",
        "__pycache__",
        "htmlcov",
        "ghidra_12.1.2_public",
        "node_modules",
        "output",
    }
)
EXCLUDED_RELATIVE_DIRS = frozenset({"samples/generated"})


def safe_iter_files(root: Path) -> Iterator[Path]:
    """Yield regular files deterministically without following directory links."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("baseline_root_must_be_regular_directory")
    excluded_names = {name.casefold() for name in EXCLUDED_DIR_NAMES}
    excluded_relative_dirs = {
        relative.casefold() for relative in EXCLUDED_RELATIVE_DIRS
    }
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(current)
        dirs[:] = [
            name
            for name in sorted(dirs)
            if name.casefold() not in excluded_names
            and not _is_excluded_relative_dir(
                (parent / name).relative_to(root).as_posix(),
                excluded_relative_dirs,
            )
            and not (parent / name).is_symlink()
            and not (
                hasattr(parent / name, "is_junction")
                and (parent / name).is_junction()
            )
        ]
        for name in sorted(files):
            path = parent / name
            if path.is_file() and not path.is_symlink():
                yield path


def _is_excluded_relative_dir(path: str, excluded_relative_dirs: set[str]) -> bool:
    """Return whether a normalized directory is an excluded path or descendant."""
    normalized = path.casefold().strip("/")
    return any(
        normalized == excluded or normalized.startswith(excluded + "/")
        for excluded in excluded_relative_dirs
    )


def _stat_signature(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def hash_file_stable(path: Path) -> tuple[str, int]:
    """Hash one file and fail closed when it changes while being read."""
    path = Path(path)
    before = _stat_signature(path)
    digest = hashlib.sha256()
    bytes_read = 0
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            bytes_read += len(chunk)
    after = _stat_signature(path)
    if before != after or bytes_read != before[2]:
        raise ValueError(f"baseline_file_changed_during_hash:{path}")
    return digest.hexdigest(), bytes_read


def _read_file_stable_bytes(path: Path) -> bytes:
    """Read one immutable byte snapshot or fail if the file changes/replaces."""
    path = Path(path)
    before = _stat_signature(path)
    with path.open("rb") as handle:
        opened_before = os.fstat(handle.fileno())
        payload = handle.read()
        opened_after = os.fstat(handle.fileno())
    after = _stat_signature(path)
    opened_before_signature = (
        opened_before.st_dev,
        opened_before.st_ino,
        opened_before.st_size,
        opened_before.st_mtime_ns,
    )
    opened_after_signature = (
        opened_after.st_dev,
        opened_after.st_ino,
        opened_after.st_size,
        opened_after.st_mtime_ns,
    )
    if (
        before != opened_before_signature
        or opened_before_signature != opened_after_signature
        or opened_after_signature != after
        or len(payload) != before[2]
    ):
        raise ValueError(f"baseline_file_changed_during_read:{path}")
    return payload


def sha256_file(path: Path) -> str:
    """Return a stable SHA-256 digest for one regular baseline file."""
    return hash_file_stable(path)[0]


def _canonical_json_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _capture_git_status(root: Path) -> dict[str, Any]:
    """Capture Git porcelain v1 without making Git availability a precondition."""
    empty_digest = hashlib.sha256(b"").hexdigest()
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
            check=False,
            capture_output=True,
        )
    except OSError:
        return {
            "available": False,
            "reason": "git_unavailable",
            "returncode": None,
            "sha256": empty_digest,
            "status_porcelain_v1": [],
        }
    if completed.returncode != 0:
        return {
            "available": False,
            "reason": "git_status_failed",
            "returncode": completed.returncode,
            "sha256": hashlib.sha256(completed.stdout).hexdigest(),
            "status_porcelain_v1": [],
        }
    return {
        "available": True,
        "returncode": 0,
        "sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "status_porcelain_v1": completed.stdout.decode("utf-8", "surrogateescape").splitlines(),
    }


def _junit_summary(root: ElementTree.Element) -> dict[str, int]:
    """Return a strict normalized JUnit summary from a testsuite(s) document."""
    local_name = root.tag.rsplit("}", 1)[-1]
    if local_name not in {"testsuite", "testsuites"}:
        raise ValueError("baseline_junit_invalid_root")

    def attribute(element: ElementTree.Element, name: str) -> int | None:
        value = element.get(name)
        if value is None:
            return None
        try:
            parsed = int(value)
        except ValueError as error:
            raise ValueError(f"baseline_junit_invalid_{name}") from error
        if parsed < 0:
            raise ValueError(f"baseline_junit_invalid_{name}")
        return parsed

    def children_named(element: ElementTree.Element, name: str) -> list[ElementTree.Element]:
        return [child for child in element if child.tag.rsplit("}", 1)[-1] == name]

    def suite_value(suite: ElementTree.Element, name: str) -> int:
        declared = attribute(suite, name)
        if declared:
            return declared
        child_suites = children_named(suite, "testsuite")
        if child_suites:
            return sum(suite_value(child, name) for child in child_suites)
        cases = children_named(suite, "testcase")
        if name == "tests":
            return len(cases)
        outcome = {"errors": "error", "failures": "failure", "skipped": "skipped"}[name]
        return sum(bool(children_named(case, outcome)) for case in cases)

    result: dict[str, int] = {}
    for name in ("errors", "failures", "skipped", "tests"):
        declared = attribute(root, name)
        if declared:
            result[name] = declared
            continue
        if local_name == "testsuite":
            result[name] = suite_value(root, name)
        else:
            result[name] = sum(
                suite_value(suite, name) for suite in children_named(root, "testsuite")
            )
    return result


def _capture_junit(junit_path: Path | None) -> dict[str, Any]:
    """Link a supplied JUnit file by stable hash and normalized summary."""
    if junit_path is None:
        return {"provided": False}
    path = Path(junit_path).resolve()
    if path.is_symlink() or not path.is_file():
        raise ValueError("baseline_junit_must_be_regular_file")
    payload = _read_file_stable_bytes(path)
    digest = hashlib.sha256(payload).hexdigest()
    size = len(payload)
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as error:
        raise ValueError("baseline_junit_invalid_xml") from error
    return {
        "path": str(path),
        "provided": True,
        "sha256": digest,
        "size": size,
        "summary": _junit_summary(root),
    }


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Durably replace a JSON report after writing it beside its destination."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def capture_program_baseline(
    root: Path, output: Path, junit_path: Path | None = None
) -> dict[str, Any]:
    """Hash the RE project while explicitly removing Rotor artifacts from scope."""
    root = Path(root).resolve()
    output = Path(output).resolve()
    included: list[dict[str, Any]] = []
    excluded: list[str] = []
    for path in safe_iter_files(root):
        if path.resolve() == output:
            continue
        relative = path.relative_to(root).as_posix()
        if "rotor" in relative.casefold():
            excluded.append(relative)
            continue
        digest, size = hash_file_stable(path)
        included.append({"path": relative, "sha256": digest, "size": size})
    files = sorted(included, key=lambda row: row["path"])
    report = {
        "schema": SCHEMA,
        "scope": {
            "included_count": len(included),
            "excluded": sorted(excluded),
        },
        "files": files,
        "git": _capture_git_status(root),
        "inventory": {"file_count": len(files), "sha256": _canonical_json_sha256(files)},
        "junit": _capture_junit(junit_path),
    }
    atomic_write_json(output, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--junit", type=Path)
    arguments = parser.parse_args()
    report = capture_program_baseline(arguments.root, arguments.output, arguments.junit)
    print(
        json.dumps(
            {
                "schema": report["schema"],
                "included_count": report["scope"]["included_count"],
                "excluded_count": len(report["scope"]["excluded"]),
                "output": str(arguments.output.resolve()),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
