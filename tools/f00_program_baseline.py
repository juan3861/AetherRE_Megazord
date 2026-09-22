"""Capture a deterministic, scope-clean RE_Megazord program baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterator


SCHEMA = "program-baseline.v1"
EXCLUDED_DIRS = frozenset(
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
        "samples/generated",
    }
)


def safe_iter_files(root: Path) -> Iterator[Path]:
    """Yield regular files deterministically without following directory links."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("baseline_root_must_be_regular_directory")
    excluded_names = {name.casefold() for name in EXCLUDED_DIRS if "/" not in name}
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(current)
        dirs[:] = [
            name
            for name in sorted(dirs)
            if name.casefold() not in excluded_names
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


def sha256_file(path: Path) -> str:
    """Hash a file in bounded chunks."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def capture_program_baseline(root: Path, output: Path) -> dict[str, Any]:
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
        included.append(
            {
                "path": relative,
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
        )
    report = {
        "schema": SCHEMA,
        "scope": {
            "included_count": len(included),
            "excluded": sorted(excluded),
        },
        "files": sorted(included, key=lambda row: row["path"]),
    }
    atomic_write_json(output, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    report = capture_program_baseline(arguments.root, arguments.output)
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
