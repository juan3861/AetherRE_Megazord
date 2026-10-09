"""Fail-closed integrity checks for an unqualified Ghidra distribution candidate.

This module records material provenance only. It deliberately cannot qualify a
worker, certify a profile, or promote a release gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


GHIDRA_12_1_4_SHA256 = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
GHIDRA_12_1_4_SIZE = 569_649_598
REPARSE_POINT = 0x400
MAX_MANIFEST_FILES = 50_000
MAX_MANIFEST_BYTES = 20 * 1024**3


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def _load_json_strict(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            Path(path).read_text(encoding="utf-8"), object_pairs_hook=_reject_pairs
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid_json:{Path(path)}") from exc
    if not isinstance(value, dict):
        raise ValueError("json_object_required")
    return value


def _require_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise ValueError(f"{label}_keys_invalid:missing={missing}:extra={extra}")


def validate_candidate_boundary(candidate: dict[str, Any]) -> bool:
    """Reject declarations that try to self-promote an unqualified candidate."""
    qualification = candidate.get("qualification")
    if not isinstance(qualification, dict):
        raise ValueError("candidate_self_promotion_rejected")
    _require_keys(
        qualification,
        {"classification", "worker_eligible", "worker_qualified", "independent_review", "gate_passed", "blockers"},
        "qualification",
    )
    expected = {
        "classification": "candidate-not-qualified",
        "worker_eligible": False,
        "worker_qualified": False,
        "independent_review": None,
        "gate_passed": False,
    }
    if any(qualification.get(key) != value for key, value in expected.items()):
        raise ValueError("candidate_self_promotion_rejected")
    blockers = qualification.get("blockers")
    if (
        not isinstance(blockers, list)
        or not blockers
        or any(not isinstance(item, str) or not item.strip() for item in blockers)
    ):
        raise ValueError("candidate_blockers_required")
    return True


def _safe_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("unsafe_manifest_path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("unsafe_manifest_path")
    if any(":" in part or part.endswith((".", " ")) for part in path.parts):
        raise ValueError("unsafe_manifest_path")
    return path.as_posix()


def _reject_reparse_chain(path: Path) -> None:
    current = Path(path).absolute()
    chain = [*reversed(current.parents), current]
    for item in chain:
        try:
            info = item.lstat()
        except FileNotFoundError as exc:
            raise ValueError(f"path_missing:{item}") from exc
        if stat.S_ISLNK(info.st_mode) or (getattr(info, "st_file_attributes", 0) & REPARSE_POINT):
            raise ValueError(f"reparse_path_rejected:{item}")


def _resolved_under(path: Path | str, root: Path | str) -> Path:
    try:
        raw = Path(path)
    except (TypeError, ValueError) as exc:
        raise ValueError("path_value_invalid") from exc
    if not raw.is_absolute() or ".." in raw.parts:
        raise ValueError("absolute_path_without_traversal_required")
    _reject_reparse_chain(raw)
    resolved = raw.resolve(strict=True)
    allowed = Path(root).resolve(strict=True)
    _reject_reparse_chain(allowed)
    try:
        resolved.relative_to(allowed)
    except ValueError as exc:
        # Windows paths are case-insensitive even when tests run on a case-sensitive host.
        common = os.path.commonpath([os.path.normcase(str(resolved)), os.path.normcase(str(allowed))])
        if os.path.normcase(common) != os.path.normcase(str(allowed)):
            raise ValueError("path_outside_allowed_root") from exc
    return resolved


def _hash_file(path: Path) -> tuple[int, str]:
    h = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
            size += len(chunk)
    return size, h.hexdigest()


def _tree_rows(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_bytes = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or stat.S_ISLNK(info.st_mode) or (
                    getattr(info, "st_file_attributes", 0) & REPARSE_POINT
                ):
                    raise ValueError(f"reparse_entry_rejected:{path}")
                relative = path.relative_to(root).as_posix()
                relative = _safe_relative_path(relative)
                folded = relative.casefold()
                if folded in seen:
                    raise ValueError(f"case_insensitive_path_collision:{relative}")
                seen.add(folded)
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ValueError(f"non_regular_entry_rejected:{relative}")
                size, digest = _hash_file(path)
                after = path.stat()
                if size != info.st_size or after.st_size != info.st_size or after.st_mtime_ns != info.st_mtime_ns:
                    raise ValueError(f"file_changed_while_hashing:{relative}")
                rows.append({"path": relative, "size": size, "sha256": digest})
                total_bytes += size
                if len(rows) > MAX_MANIFEST_FILES or total_bytes > MAX_MANIFEST_BYTES:
                    raise ValueError("manifest_tree_limit_exceeded")
    rows.sort(key=lambda row: row["path"])
    return rows


def _tree_digest(rows: list[dict[str, Any]]) -> str:
    canonical = json.dumps(
        rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify_file_manifest(
    root: Path | str,
    manifest_path: Path | str,
    expected_manifest_sha256: str,
    *,
    expected_schema: str = "distribution-files.v1",
) -> dict[str, Any]:
    """Rehash a complete directory tree and compare it with a material manifest."""
    raw_root = Path(root)
    _reject_reparse_chain(raw_root)
    root_path = raw_root.resolve(strict=True)
    if not root_path.is_dir():
        raise ValueError("manifest_root_must_be_directory")
    _reject_reparse_chain(root_path)
    manifest_file = Path(manifest_path)
    if not manifest_file.is_file():
        raise ValueError("manifest_file_missing")
    _reject_reparse_chain(manifest_file)
    manifest_size, manifest_digest = _hash_file(manifest_file)
    del manifest_size
    if not isinstance(expected_manifest_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_manifest_sha256
    ):
        raise ValueError("expected_manifest_sha256_invalid")
    if manifest_digest != expected_manifest_sha256:
        raise ValueError("manifest_digest_mismatch")
    manifest = _load_json_strict(manifest_file)
    _require_keys(
        manifest,
        {"schema", "root", "file_count", "total_bytes", "tree_sha256", "files"},
        "manifest",
    )
    if manifest["schema"] != expected_schema:
        raise ValueError("manifest_schema_mismatch")
    if not isinstance(manifest["root"], str):
        raise ValueError("manifest_root_invalid")
    if Path(manifest["root"]).resolve(strict=True) != root_path:
        raise ValueError("manifest_root_mismatch")
    if (
        type(manifest["file_count"]) is not int
        or manifest["file_count"] < 0
        or type(manifest["total_bytes"]) is not int
        or manifest["total_bytes"] < 0
        or not isinstance(manifest["tree_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", manifest["tree_sha256"])
    ):
        raise ValueError("manifest_counts_invalid")
    if not isinstance(manifest["files"], list):
        raise ValueError("manifest_files_list_required")
    declared: dict[str, dict[str, Any]] = {}
    for row in manifest["files"]:
        if not isinstance(row, dict):
            raise ValueError("manifest_file_row_invalid")
        _require_keys(row, {"path", "size", "sha256"}, "manifest_file")
        relative = _safe_relative_path(row["path"])
        folded = relative.casefold()
        if folded in declared:
            raise ValueError(f"duplicate_manifest_path:{relative}")
        if (
            not isinstance(row["size"], int)
            or isinstance(row["size"], bool)
            or row["size"] < 0
        or not isinstance(row["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
        ):
            raise ValueError("manifest_file_row_invalid")
        declared[folded] = {"path": relative, "size": row["size"], "sha256": row["sha256"]}
    actual_rows = _tree_rows(root_path)
    actual = {row["path"].casefold(): row for row in actual_rows}
    if actual != declared:
        raise ValueError("file_set_mismatch_or_content_hash_mismatch")
    actual_total = sum(row["size"] for row in actual_rows)
    actual_tree_digest = _tree_digest(actual_rows)
    if (
        manifest["file_count"] != len(actual_rows)
        or manifest["total_bytes"] != actual_total
        or manifest["tree_sha256"] != actual_tree_digest
    ):
        raise ValueError("tree_mismatch")
    return {
        "verified": True,
        "file_count": len(actual_rows),
        "total_bytes": actual_total,
        "tree_sha256": actual_tree_digest,
        "manifest_sha256": manifest_digest,
    }


def _require_exact_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label}_object_required")
    _require_keys(value, fields, label)
    return value


def verify_ghidra_candidate(
    candidate_path: Path | str,
    *,
    toolchain_root: Path | str,
    evidence_root: Path | str,
    runtime_root: Path | str,
) -> dict[str, Any]:
    """Verify current bytes for Ghidra 12.1.4; never qualifies or promotes it."""
    candidate_file = Path(candidate_path)
    _reject_reparse_chain(candidate_file)
    candidate = _load_json_strict(candidate_file)
    _require_keys(candidate, {"schema", "acquisition", "distribution", "runtime", "qualification"}, "candidate")
    if candidate["schema"] != "ghidra-distribution-candidate.v1":
        raise ValueError("candidate_schema_mismatch")
    validate_candidate_boundary(candidate)
    acquisition = _require_exact_fields(
        candidate["acquisition"],
        {"repository", "tag", "asset", "official_release_url", "archive_path", "expected_size", "expected_sha256", "observed_size", "observed_sha256", "integrity"},
        "acquisition",
    )
    distribution = _require_exact_fields(
        candidate["distribution"],
        {"root", "version", "java_minimum", "file_manifest", "file_manifest_sha256", "tree_sha256", "file_count", "total_bytes", "license_entry", "integrity"},
        "distribution",
    )
    runtime = _require_exact_fields(
        candidate["runtime"],
        {"root", "java_executable", "java_sha256", "runtime_manifest", "runtime_manifest_sha256", "tree_sha256", "file_count", "total_bytes", "java_version_output", "network_isolation"},
        "runtime",
    )
    if (
        acquisition["repository"] != "NationalSecurityAgency/ghidra"
        or acquisition["tag"] != "Ghidra_12.1.4_build"
        or acquisition["asset"] != "ghidra_12.1.4_PUBLIC_20260921.zip"
        or acquisition["official_release_url"] != "https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build"
        or acquisition["expected_size"] != GHIDRA_12_1_4_SIZE
        or acquisition["expected_sha256"] != GHIDRA_12_1_4_SHA256
        or acquisition["integrity"] != "verified_against_official_release_digest"
    ):
        raise ValueError("official_acquisition_identity_mismatch")
    if runtime["network_isolation"] != "not_proven":
        raise ValueError("network_isolation_overclaim_rejected")

    archive = _resolved_under(acquisition["archive_path"], toolchain_root)
    archive_size, archive_hash = _hash_file(archive)
    if archive_size != GHIDRA_12_1_4_SIZE or archive_hash != GHIDRA_12_1_4_SHA256:
        raise ValueError("official_archive_hash_or_size_mismatch")
    if acquisition["observed_size"] != archive_size or acquisition["observed_sha256"] != archive_hash:
        raise ValueError("candidate_archive_observation_mismatch")

    dist_root = _resolved_under(distribution["root"], toolchain_root)
    dist_manifest = _resolved_under(distribution["file_manifest"], evidence_root)
    dist_result = verify_file_manifest(
        dist_root, dist_manifest, distribution["file_manifest_sha256"], expected_schema="distribution-files.v1"
    )
    if (
        distribution["tree_sha256"] != dist_result["tree_sha256"]
        or distribution["file_count"] != dist_result["file_count"]
        or distribution["total_bytes"] != dist_result["total_bytes"]
    ):
        raise ValueError("distribution_observation_mismatch")
    properties = (dist_root / "Ghidra" / "application.properties").read_text(encoding="utf-8")
    if not re.search(r"(?m)^application\.version=12\.1\.4$", properties):
        raise ValueError("ghidra_version_mismatch")
    minimum = re.search(r"(?m)^application\.java\.min=(\d+)$", properties)
    if not minimum or minimum.group(1) != str(distribution["java_minimum"]):
        raise ValueError("ghidra_java_minimum_mismatch")
    license_entry = _resolved_under(distribution["license_entry"], dist_root)
    if not license_entry.is_file():
        raise ValueError("distribution_license_file_missing")

    runtime_dir = _resolved_under(runtime["root"], runtime_root)
    expected_runtime_root = Path(runtime_root).resolve(strict=True)
    if runtime_dir != expected_runtime_root:
        raise ValueError("runtime_root_mismatch")
    runtime_manifest = _resolved_under(runtime["runtime_manifest"], evidence_root)
    runtime_result = verify_file_manifest(
        runtime_dir, runtime_manifest, runtime["runtime_manifest_sha256"], expected_schema="runtime-files.v1"
    )
    if (
        runtime["tree_sha256"] != runtime_result["tree_sha256"]
        or runtime["file_count"] != runtime_result["file_count"]
        or runtime["total_bytes"] != runtime_result["total_bytes"]
    ):
        raise ValueError("runtime_observation_mismatch")
    java = _resolved_under(runtime["java_executable"], runtime_dir)
    if java != (runtime_dir / "bin" / "java.exe"):
        raise ValueError("runtime_java_path_mismatch")
    _, java_hash = _hash_file(java)
    if java_hash != runtime["java_sha256"]:
        raise ValueError("runtime_java_hash_mismatch")
    probe = subprocess.run(
        [str(java), "-version"],
        shell=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    version_text = (probe.stderr or probe.stdout).strip()
    if probe.returncode != 0 or not re.search(r'openjdk version "21(?:\.|\\")', version_text):
        raise ValueError("runtime_java_21_preflight_failed")
    if version_text != runtime["java_version_output"].strip():
        raise ValueError("runtime_java_version_observation_mismatch")

    return {
        "schema": "ghidra-candidate-verification.v1",
        "integrity_status": "verified",
        "archive_sha256": archive_hash,
        "distribution_tree_sha256": dist_result["tree_sha256"],
        "runtime_tree_sha256": runtime_result["tree_sha256"],
        "direct_java_preflight_ok": True,
        "worker_eligible": False,
        "worker_qualified": False,
        "gate_passed": False,
        "classification": "candidate-not-qualified",
        "blockers": list(candidate["qualification"]["blockers"]),
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Ghidra candidate integrity without qualifying its worker.")
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--toolchain-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_ghidra_candidate(
            args.candidate,
            toolchain_root=args.toolchain_root,
            evidence_root=args.evidence_root,
            runtime_root=args.runtime_root,
        )
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, ensure_ascii=False))
        return 3
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
