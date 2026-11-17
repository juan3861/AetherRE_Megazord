"""Pinned, bounded reuse of REA for static JavaScript/Electron analysis.

The adapter keeps REA's graph as an independent evidence artifact. It does not
claim to merge incompatible graph identities or to prove runtime equivalence.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from aether_re import __version__
from aether_re.contracts import validate_adapter_result
from aether_re.evidence import _path_has_link, create_verified_snapshot, sha256_file
from aether_re.process import run_bounded
from aether_re.project_audit import analyze_project
from aether_re.project_snapshot import create_project_snapshot


LOCK_SCHEMA = "rea-static-workers-lock.v1"
RESULT_SCHEMA = "rea-federated-report.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_LOCK_BYTES = 1024 * 1024
_MIB = 1024 * 1024
_LOCK_WORKER_FIELDS = {
    "name", "version", "official_url", "git_head", "license_spdx",
    "candidate_root", "package_relative_path", "package_tree_sha256",
    "package_files", "package_bytes", "dependencies_relative_path",
    "dependencies_tree_sha256", "dependencies_files", "dependencies_bytes",
    "tarball_relative_path", "tarball_sha256", "package_lock_relative_path",
    "package_lock_sha256", "signature_audit_relative_path",
    "signature_audit_sha256", "candidate_manifest_relative_path",
    "candidate_manifest_sha256", "node_executable", "node_version",
    "node_sha256", "capabilities", "limits",
}
_LIMIT_FIELDS = {
    "cpu_seconds", "memory_bytes", "wall_seconds", "output_bytes",
    "node_heap_mb", "analysis_timeout_ms", "max_files", "max_total_bytes",
    "max_file_bytes", "max_worker_files", "max_worker_bytes",
}
_REQUIRED_REA_FIELDS = {
    "input_path", "format", "root_artifact_sha256", "inventory_manifest_id",
    "inventory_graph_sha256", "integrity_contradictions", "graph", "summary",
    "statistics", "limitations", "semantic_graph",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _load_json(path: Path, *, max_bytes: int = _MAX_LOCK_BYTES) -> Any:
    if _path_has_link(path) or not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError("json_file_invalid")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)


def _default_lock_path() -> Path:
    return Path(__file__).resolve().parents[1] / "tools" / "rea_static_workers.lock.json"


def load_rea_worker_lock(path: Path | None = None) -> dict[str, Any]:
    """Load a strict lock for this separately versioned Node worker family."""
    raw = _load_json(Path(path) if path is not None else _default_lock_path())
    if not isinstance(raw, dict) or set(raw) != {"schema", "worker"} or raw.get("schema") != LOCK_SCHEMA:
        raise ValueError("rea_lock_schema_invalid")
    worker = raw.get("worker")
    if not isinstance(worker, dict) or set(worker) != _LOCK_WORKER_FIELDS:
        raise ValueError("rea_worker_schema_invalid")
    for name in ("package_tree_sha256", "dependencies_tree_sha256", "tarball_sha256", "package_lock_sha256", "signature_audit_sha256", "candidate_manifest_sha256", "node_sha256"):
        if not isinstance(worker.get(name), str) or not _SHA256_RE.fullmatch(worker[name]):
            raise ValueError(f"rea_worker_hash_invalid:{name}")
    if worker.get("name") != "rea-agents-static-js-electron" or worker.get("version") != "6.4.0":
        raise ValueError("rea_worker_identity_invalid")
    if worker.get("license_spdx") != "MIT" or not str(worker.get("official_url", "")).startswith("https://registry.npmjs.org/"):
        raise ValueError("rea_worker_provenance_invalid")
    if not isinstance(worker.get("capabilities"), list) or worker["capabilities"] != ["javascript", "electron-static"]:
        raise ValueError("rea_worker_capability_invalid")
    limits = worker.get("limits")
    if not isinstance(limits, dict) or set(limits) != _LIMIT_FIELDS:
        raise ValueError("rea_worker_limits_invalid")
    for name, value in limits.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"rea_worker_limit_invalid:{name}")
    for name in ("package_files", "package_bytes", "dependencies_files", "dependencies_bytes"):
        value = worker.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"rea_worker_count_invalid:{name}")
    for name in ("candidate_root", "package_relative_path", "dependencies_relative_path", "tarball_relative_path", "package_lock_relative_path", "signature_audit_relative_path", "candidate_manifest_relative_path", "node_executable", "node_version", "git_head"):
        value = worker.get(name)
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            raise ValueError(f"rea_worker_value_invalid:{name}")
    return worker


def _is_link_or_reparse(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except OSError:
        return True


def _directory_tree_sha256(root: Path, *, max_files: int, max_bytes: int) -> tuple[str, int, int]:
    """Hash regular files by sorted relative path, length, and content digest."""
    root = Path(root).absolute()
    if _path_has_link(root) or not root.is_dir():
        raise ValueError("worker_tree_root_invalid")
    files: list[tuple[str, int, Path]] = []
    total = 0
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        parent = Path(current)
        dirs.sort()
        names.sort()
        for name in list(dirs):
            path = parent / name
            if _is_link_or_reparse(path):
                raise ValueError("worker_tree_link_rejected")
        for name in names:
            path = parent / name
            if _is_link_or_reparse(path) or not path.is_file():
                raise ValueError("worker_tree_nonregular_file")
            info = path.stat(follow_symlinks=False)
            if info.st_nlink > 1:
                raise ValueError("worker_tree_hardlink_rejected")
            relative = path.relative_to(root).as_posix()
            files.append((relative, info.st_size, path))
            total += info.st_size
            if len(files) > max_files or total > max_bytes:
                raise ValueError("worker_tree_budget_exceeded")

    def hash_file(item: tuple[str, int, Path]) -> tuple[str, int, str]:
        relative, expected_size, path = item
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            if before.st_size != expected_size or before.st_nlink > 1:
                raise ValueError("worker_tree_changed_during_hash")
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
            after = os.fstat(handle.fileno())
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise ValueError("worker_tree_changed_during_hash")
        return relative, expected_size, digest

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(hash_file, files))
    digest = hashlib.sha256()
    for relative, size, file_hash in sorted(rows):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0F\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_hash.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest(), len(rows), total


def _candidate_provenance_matches(candidate: Any, worker: dict[str, Any]) -> bool:
    """Compare immutable package identity while accepting SHA hex casing."""
    return (
        isinstance(candidate, dict)
        and candidate.get("gitHead") == worker.get("git_head")
        and isinstance(candidate.get("download_sha256"), str)
        and candidate["download_sha256"].casefold() == str(worker.get("tarball_sha256", "")).casefold()
        and candidate.get("sri_match") is True
    )


_VERIFIED_WORKER_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}


def verify_rea_worker(lock_path: Path | None = None, *, force_recheck: bool = False) -> dict[str, Any]:
    """Rehash the package, installed dependency closure, runtime, and receipts."""
    resolved_lock = Path(lock_path) if lock_path is not None else _default_lock_path()
    candidate_root_env = os.environ.get("AETHER_REA_CANDIDATE_ROOT")
    node_env = os.environ.get("AETHER_REA_NODE")

    lock_stat: tuple[int, int] | None = None
    if resolved_lock.is_file():
        try:
            st = resolved_lock.stat()
            lock_stat = (st.st_mtime_ns, st.st_size)
        except OSError:
            lock_stat = None

    cache_key = (str(resolved_lock.resolve()), lock_stat, candidate_root_env, node_env)
    if not force_recheck and lock_stat is not None and cache_key in _VERIFIED_WORKER_CACHE:
        return dict(_VERIFIED_WORKER_CACHE[cache_key])

    issues: list[str] = []
    try:
        worker = load_rea_worker_lock(lock_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return {"schema": "rea-worker-verification.v1", "verified": False, "issues": [str(exc) if isinstance(exc, ValueError) else "rea_lock_unreadable"]}
    candidate_root = Path(os.environ.get("AETHER_REA_CANDIDATE_ROOT", worker["candidate_root"])).absolute()
    node = Path(os.environ.get("AETHER_REA_NODE", worker["node_executable"])).absolute()
    package_root = candidate_root / worker["package_relative_path"]
    dependencies_root = candidate_root / worker["dependencies_relative_path"]
    checks = [
        (candidate_root / worker["tarball_relative_path"], worker["tarball_sha256"], "tarball_hash_mismatch"),
        (candidate_root / worker["package_lock_relative_path"], worker["package_lock_sha256"], "package_lock_hash_mismatch"),
        (candidate_root / worker["signature_audit_relative_path"], worker["signature_audit_sha256"], "signature_audit_hash_mismatch"),
        (candidate_root / worker["candidate_manifest_relative_path"], worker["candidate_manifest_sha256"], "candidate_manifest_hash_mismatch"),
        (node, worker["node_sha256"], "node_runtime_hash_mismatch"),
    ]
    for path, expected, code in checks:
        try:
            if _path_has_link(path) or not path.is_file() or sha256_file(path) != expected:
                issues.append(code)
        except OSError:
            issues.append(code)
    try:
        package_hash, package_files, package_bytes = _directory_tree_sha256(
            package_root,
            max_files=worker["limits"]["max_worker_files"],
            max_bytes=worker["limits"]["max_worker_bytes"],
        )
        if (package_hash, package_files, package_bytes) != (worker["package_tree_sha256"], worker["package_files"], worker["package_bytes"]):
            issues.append("package_tree_mismatch")
    except (OSError, ValueError):
        issues.append("package_tree_invalid")
    try:
        dependencies_hash, dependencies_files, dependencies_bytes = _directory_tree_sha256(
            dependencies_root,
            max_files=worker["limits"]["max_worker_files"],
            max_bytes=worker["limits"]["max_worker_bytes"],
        )
        if (dependencies_hash, dependencies_files, dependencies_bytes) != (worker["dependencies_tree_sha256"], worker["dependencies_files"], worker["dependencies_bytes"]):
            issues.append("dependencies_tree_mismatch")
    except (OSError, ValueError):
        issues.append("dependencies_tree_invalid")
    try:
        package_metadata = _load_json(package_root / "package.json")
        candidate_manifest = _load_json(candidate_root / worker["candidate_manifest_relative_path"])
        signature_audit = _load_json(candidate_root / worker["signature_audit_relative_path"])
        candidate = candidate_manifest.get("candidate") if isinstance(candidate_manifest, dict) else None
        verification = candidate_manifest.get("verification") if isinstance(candidate_manifest, dict) else None
        if not isinstance(package_metadata, dict) or (package_metadata.get("name"), package_metadata.get("version"), package_metadata.get("license")) != ("rea-agents", worker["version"], worker["license_spdx"]):
            issues.append("package_metadata_mismatch")
        if not _candidate_provenance_matches(candidate, worker):
            issues.append("candidate_provenance_mismatch")
        if not isinstance(verification, dict) or verification.get("npm_audit_signatures_exit") != 0 or verification.get("invalid_signatures") != 0 or verification.get("missing_signatures") != 0 or verification.get("package_scripts") != "disabled via --ignore-scripts":
            issues.append("signature_audit_not_clean")
        if not isinstance(signature_audit, dict) or signature_audit.get("invalid") != [] or signature_audit.get("missing") != []:
            issues.append("signature_audit_content_invalid")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        issues.append("package_provenance_invalid")
    if os.name != "nt":
        issues.append("windows_worker_runtime_required")
    else:
        try:
            version_probe = run_bounded(
                [node, "--version"], timeout=5, memory_limit_mb=128,
                cpu_time_limit_s=5, output_limit_bytes=1024,
                require_process_tree=True, shell=False,
            )
            observed_version = version_probe.get("stdout", "").strip()
            if version_probe.get("returncode") != 0 or observed_version != worker["node_version"] or version_probe.get("resource_exceeded") or not version_probe.get("process_tree_contained"):
                issues.append("node_runtime_probe_failed")
        except (OSError, ValueError, TypeError):
            issues.append("node_runtime_probe_failed")
    entrypoint = package_root / "scripts" / "rea.mjs"
    paths = {"node": str(node), "package_root": str(package_root), "entrypoint": str(entrypoint)}
    if _path_has_link(entrypoint) or not entrypoint.is_file():
        issues.append("worker_entrypoint_missing")

    result = {
        "schema": "rea-worker-verification.v1",
        "verified": not issues,
        "issues": sorted(set(issues)),
        "worker": worker,
        "paths": paths,
    }
    if not issues and lock_stat is not None:
        _VERIFIED_WORKER_CACHE[cache_key] = dict(result)
    return result


def _canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _write_json(path: Path, value: Any) -> str:
    payload = _canonical_json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(payload)
    return hashlib.sha256(payload).hexdigest()


def _valid_rea_result(value: Any, expected_input: Path) -> tuple[bool, str]:
    if not isinstance(value, dict) or not _REQUIRED_REA_FIELDS.issubset(value):
        return False, "rea_result_schema_invalid"
    if value.get("error"):
        return False, "rea_reported_analysis_error"
    if not isinstance(value.get("input_path"), str) or Path(value["input_path"]).absolute() != expected_input.absolute():
        return False, "rea_input_path_mismatch"
    if value.get("format") not in {"directory", "asar"} or not isinstance(value.get("root_artifact_sha256"), str) or not _SHA256_RE.fullmatch(value["root_artifact_sha256"]):
        return False, "rea_result_identity_invalid"
    if not isinstance(value.get("integrity_contradictions"), list) or not isinstance(value.get("limitations"), list) or any(not isinstance(item, str) for item in value["limitations"]):
        return False, "rea_result_evidence_invalid"
    if not isinstance(value.get("graph"), dict) or not isinstance(value.get("semantic_graph"), dict) or not isinstance(value.get("summary"), dict) or not isinstance(value.get("statistics"), dict):
        return False, "rea_result_graph_invalid"
    stats = value["statistics"]
    parse_failures = stats.get("parse_failures")
    if isinstance(parse_failures, bool) or not isinstance(parse_failures, int) or parse_failures < 0:
        return False, "rea_result_statistics_invalid"
    return True, ""


def _valid_rea_evidence_envelope(value: Any, expected_input: Path) -> tuple[bool, str]:
    """Validate REA's shipped Evidence wrapper and bind it to its normalized report."""
    required = {
        "evidence_id", "subject", "provider", "predicate_type", "operation",
        "parameters", "normalized_result", "confidence", "authority",
        "limitations", "locations", "evidence_links",
    }
    if not isinstance(value, dict) or not required.issubset(value):
        return False, "rea_evidence_envelope_schema_invalid"
    if not isinstance(value.get("evidence_id"), str) or not re.fullmatch(r"ev_[0-9a-f]{64}", value["evidence_id"]):
        return False, "rea_evidence_id_invalid"
    if value.get("predicate_type") != "rea.javascript-application-analysis" or value.get("operation") != "analyze_javascript_application":
        return False, "rea_evidence_operation_invalid"
    provider = value.get("provider")
    if not isinstance(provider, dict) or provider.get("id") != "rea-javascript-application" or not isinstance(provider.get("version"), str):
        return False, "rea_evidence_provider_invalid"
    parameters = value.get("parameters")
    if not isinstance(parameters, dict) or parameters.get("integrity_policy") != "fail":
        return False, "rea_evidence_policy_invalid"
    subject = value.get("subject")
    subject_digest = subject.get("digest") if isinstance(subject, dict) else None
    normalized = value.get("normalized_result")
    valid, error = _valid_rea_result(normalized, expected_input)
    if not valid:
        return False, error
    if (
        not isinstance(subject_digest, dict)
        or subject_digest.get("sha256") != normalized.get("root_artifact_sha256")
        or subject.get("format") != normalized.get("format")
    ):
        return False, "rea_evidence_subject_mismatch"
    if not all(isinstance(value.get(name), list) for name in ("limitations", "locations", "evidence_links")):
        return False, "rea_evidence_collections_invalid"
    if any(not isinstance(item, str) for item in value["limitations"]):
        return False, "rea_evidence_limitations_invalid"
    return True, ""


def _normalized_artifact_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048 or "\x00" in value or "\\" in value or ":" in value:
        raise ValueError("artifact_correspondence_relative_path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or PureWindowsPath(value).is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("artifact_correspondence_relative_path_invalid")
    return path.as_posix()


def _artifact_identity(value: Any) -> tuple[str, str, int]:
    if not isinstance(value, dict):
        raise ValueError("artifact_correspondence_file_record_invalid")
    path = _normalized_artifact_path(value.get("path"))
    digest = value.get("sha256")
    size = value.get("size")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise ValueError("artifact_correspondence_file_hash_invalid")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ValueError("artifact_correspondence_file_size_invalid")
    return path, digest.casefold(), size


def _explicit_rea_node_file_references(node: Any) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]]]:
    """Return only graph-node references with explicit path and content digest."""
    if not isinstance(node, dict):
        return [], []
    identity = node.get("identity") if isinstance(node.get("identity"), dict) else {}
    identity_digest = identity.get("artifact_sha256") or identity.get("sha256")
    refs: set[tuple[str, str]] = set()
    digest_conflicts: set[tuple[str, str, str]] = set()
    observations = node.get("observations", [])
    if isinstance(observations, list):
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            evidence = observation.get("evidence") if isinstance(observation.get("evidence"), dict) else {}
            artifact = evidence.get("artifact") if isinstance(evidence.get("artifact"), dict) else {}
            location = evidence.get("location") if isinstance(evidence.get("location"), dict) else {}
            location_value = location.get("value") if isinstance(location.get("value"), dict) else {}
            path_value = location_value.get("source") or location_value.get("path")
            evidence_digest = artifact.get("sha256")
            if (
                isinstance(path_value, str)
                and isinstance(identity_digest, str)
                and isinstance(evidence_digest, str)
                and re.fullmatch(r"[0-9a-fA-F]{64}", identity_digest)
                and re.fullmatch(r"[0-9a-fA-F]{64}", evidence_digest)
                and identity_digest.casefold() != evidence_digest.casefold()
            ):
                digest_conflicts.add((_normalized_artifact_path(path_value), identity_digest.casefold(), evidence_digest.casefold()))
                continue
            digest = evidence_digest or identity_digest
            if isinstance(path_value, str) and isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                refs.add((_normalized_artifact_path(path_value), digest.casefold()))
    if not refs and not digest_conflicts:
        path_value = identity.get("module_path") or identity.get("path")
        if isinstance(path_value, str) and isinstance(identity_digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", identity_digest):
            refs.add((_normalized_artifact_path(path_value), identity_digest.casefold()))
    return sorted(refs), sorted(digest_conflicts)


def build_artifact_correspondence(snapshot_manifest: Any, rea_result: Any, project_report: Any) -> dict[str, Any]:
    """Link tool outputs only when they identify the same captured file bytes.

    The output is a provenance bridge, not semantic graph reconciliation.
    Missing or conflicting references stay visible and never become a match.
    """
    if isinstance(snapshot_manifest, dict) and snapshot_manifest.get("schema") == "rea-input-snapshot.v1":
        if not isinstance(rea_result, dict) or not isinstance(project_report, dict):
            raise ValueError("artifact_correspondence_engine_report_invalid")
        source_name, digest, size = _artifact_identity({
            "path": snapshot_manifest.get("source_name"),
            "sha256": snapshot_manifest.get("sha256"),
            "size": snapshot_manifest.get("size_bytes"),
        })
        rea_root = rea_result.get("root_artifact_sha256")
        rea_root_matches = (
            rea_result.get("format") == "asar"
            and isinstance(rea_root, str)
            and bool(re.fullmatch(r"[0-9a-fA-F]{64}", rea_root))
            and rea_root.casefold() == digest
        )
        conflicts = [] if rea_root_matches else [{"engine": "rea", "path": source_name, "reason": "root_artifact_identity_mismatch"}]
        return {
            "schema": "artifact-correspondence.v1",
            "status": "not_applicable_asar" if rea_root_matches else "partial",
            "basis": ["normalized_relative_path", "sha256", "byte_length"],
            "relation_semantics": "same_input_bytes_only",
            "semantic_graph_merge": "not_attempted",
            "files": [
                {
                    "path": source_name,
                    "sha256": digest,
                    "size": size,
                    "aetherre": {"inventory_match": False, "source_module": False, "languages": []},
                    "rea": {"root_artifact_match": rea_root_matches, "graph_node_ids": [], "graph_kinds": []},
                    "exact_identity_across_engines": False,
                }
            ],
            "unmatched_rea_references": [],
            "conflicts": conflicts,
            "summary": {
                "snapshot_files": 1,
                "aetherre_inventory_matches": 0,
                "aetherre_source_modules": 0,
                "rea_graph_files": 1 if rea_root_matches else 0,
                "files_with_exact_engine_identity": 0,
                "unmatched_rea_references": 0,
                "conflicts": len(conflicts),
            },
            "limitations": [
                "ASAR input is analyzed by REA only; AetherRE project_audit is not applicable to packed ASAR containers.",
                "No semantic graph nodes, edges, behavior, source recovery, or equivalence are merged or inferred.",
            ],
        }
    if (
        not isinstance(snapshot_manifest, dict)
        or snapshot_manifest.get("schema") != "project-snapshot.v1"
        or snapshot_manifest.get("scope") != "complete"
        or not isinstance(snapshot_manifest.get("files"), list)
        or snapshot_manifest.get("skipped", []) != []
    ):
        raise ValueError("artifact_correspondence_snapshot_invalid")
    rows: dict[str, dict[str, Any]] = {}
    folded_paths: set[str] = set()
    for record in snapshot_manifest["files"]:
        path, digest, size = _artifact_identity(record)
        if path.casefold() in folded_paths or path in rows:
            raise ValueError("artifact_correspondence_snapshot_duplicate_path")
        folded_paths.add(path.casefold())
        rows[path] = {
            "path": path,
            "sha256": digest,
            "size": size,
            "aetherre": {"inventory_match": False, "source_module": False, "languages": []},
            "rea": {"graph_node_ids": [], "graph_kinds": []},
        }
    if not isinstance(rea_result, dict) or not isinstance(project_report, dict):
        raise ValueError("artifact_correspondence_engine_report_invalid")

    conflicts: list[dict[str, str]] = []
    aether_inventory = project_report.get("inventory", {})
    inventory_files = aether_inventory.get("files", []) if isinstance(aether_inventory, dict) else []
    if not isinstance(inventory_files, list):
        raise ValueError("artifact_correspondence_aether_inventory_invalid")
    seen_aether: set[str] = set()
    for record in inventory_files:
        path, digest, size = _artifact_identity(record)
        if path.casefold() in seen_aether:
            raise ValueError("artifact_correspondence_aether_duplicate_path")
        seen_aether.add(path.casefold())
        snapshot = rows.get(path)
        if snapshot is None or (snapshot["sha256"], snapshot["size"]) != (digest, size):
            conflicts.append({"engine": "aetherre", "path": path, "reason": "snapshot_identity_mismatch"})
            continue
        snapshot["aetherre"]["inventory_match"] = True

    source_root = project_report.get("source", {})
    language_profiles = source_root.get("language_profiles", {}) if isinstance(source_root, dict) else {}
    if language_profiles is None:
        language_profiles = {}
    if not isinstance(language_profiles, dict):
        raise ValueError("artifact_correspondence_aether_profiles_invalid")
    profiles = language_profiles.get("profiles", {})
    if profiles is None:
        profiles = {}
    if not isinstance(profiles, dict):
        raise ValueError("artifact_correspondence_aether_profiles_invalid")
    for language, profile in profiles.items():
        modules = profile.get("modules", []) if isinstance(profile, dict) else []
        if not isinstance(modules, list):
            raise ValueError("artifact_correspondence_aether_modules_invalid")
        for module in modules:
            path, digest, size = _artifact_identity(module)
            snapshot = rows.get(path)
            if snapshot is None or (snapshot["sha256"], snapshot["size"]) != (digest, size):
                conflicts.append({"engine": "aetherre", "path": path, "reason": "source_module_identity_mismatch"})
                continue
            snapshot["aetherre"]["source_module"] = True
            snapshot["aetherre"]["languages"].append(str(language))

    graph = rea_result.get("graph", {})
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else None
    if not isinstance(nodes, list):
        raise ValueError("artifact_correspondence_rea_graph_invalid")
    unmatched_rea: list[dict[str, str]] = []
    seen_node_ids: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict):
            raise ValueError("artifact_correspondence_rea_node_invalid")
        node_id, kind = node.get("node_id"), node.get("kind")
        if not isinstance(node_id, str) or not node_id or not isinstance(kind, str) or not kind:
            raise ValueError("artifact_correspondence_rea_node_identity_invalid")
        if node_id in seen_node_ids:
            raise ValueError("artifact_correspondence_rea_duplicate_node_id")
        seen_node_ids.add(node_id)
        references, digest_conflicts = _explicit_rea_node_file_references(node)
        for path, identity_digest, observation_digest in digest_conflicts:
            unmatched_rea.append({
                "node_id": node_id,
                "path": path,
                "reason": "identity_digest_conflict",
                "identity_sha256": identity_digest,
                "observation_sha256": observation_digest,
            })
        for path, digest in references:
            snapshot = rows.get(path)
            if snapshot is None or snapshot["sha256"] != digest:
                unmatched_rea.append({"node_id": node_id, "path": path, "reason": "no_exact_snapshot_identity"})
                continue
            snapshot["rea"]["graph_node_ids"].append(node_id)
            snapshot["rea"]["graph_kinds"].append(kind)

    files = []
    for path in sorted(rows):
        row = rows[path]
        row["aetherre"]["languages"] = sorted(set(row["aetherre"]["languages"]))
        row["rea"]["graph_node_ids"] = sorted(set(row["rea"]["graph_node_ids"]))
        row["rea"]["graph_kinds"] = sorted(set(row["rea"]["graph_kinds"]))
        row["exact_identity_across_engines"] = bool(
            row["aetherre"]["inventory_match"] and row["rea"]["graph_node_ids"]
        )
        files.append(row)
    matched = sum(file["exact_identity_across_engines"] for file in files)
    return {
        "schema": "artifact-correspondence.v1",
        "status": "exact_identity_only" if matched and not conflicts else "partial",
        "basis": ["normalized_relative_path", "sha256", "byte_length"],
        "relation_semantics": "same_input_bytes_only",
        "semantic_graph_merge": "not_attempted",
        "files": files,
        "unmatched_rea_references": sorted(unmatched_rea, key=lambda item: (item["path"], item["node_id"])),
        "conflicts": sorted(conflicts, key=lambda item: (item["engine"], item["path"], item["reason"])),
        "summary": {
            "snapshot_files": len(files),
            "aetherre_inventory_matches": sum(file["aetherre"]["inventory_match"] for file in files),
            "aetherre_source_modules": sum(file["aetherre"]["source_module"] for file in files),
            "rea_graph_files": sum(bool(file["rea"]["graph_node_ids"]) for file in files),
            "files_with_exact_engine_identity": matched,
            "unmatched_rea_references": len(unmatched_rea),
            "conflicts": len(conflicts),
        },
        "limitations": [
            "A match proves only that engines refer to the same captured bytes at the same relative path and size.",
            "No semantic graph nodes, edges, behavior, source recovery, or equivalence are merged or inferred.",
            "Unmatched engine references do not prove a feature or relationship is absent.",
        ],
    }


class ReaStaticJavaScriptAdapter:
    """Analyze an authorized JavaScript/Electron directory or ASAR statically."""

    name = "rea-agents-static-js-electron"

    def __init__(self, lock_path: Path | None = None) -> None:
        self.lock_path = Path(lock_path) if lock_path is not None else _default_lock_path()

    def available(self) -> bool:
        return bool(verify_rea_worker(self.lock_path).get("verified"))

    def analyze(self, target: Path, out_dir: Path) -> dict[str, Any]:
        target, out_dir = Path(target).absolute(), Path(out_dir).absolute()
        verification = verify_rea_worker(self.lock_path)
        if not verification.get("verified"):
            issue = (verification.get("issues") or ["rea_worker_not_verified"])[0]
            return validate_adapter_result(self.name, {
                "available": False, "executed": False, "produced_evidence": False,
                "partial": False, "ok": False, "error": issue,
            })
        worker = verification["worker"]
        paths = verification["paths"]
        if _path_has_link(target) or not target.exists() or (not target.is_dir() and (not target.is_file() or target.suffix.casefold() != ".asar")):
            return self._input_failure("rea_input_invalid")
        if target.is_dir() and out_dir.is_relative_to(target):
            return self._input_failure("rea_output_inside_input")
        if out_dir.exists() or out_dir.is_symlink() or _path_has_link(out_dir.parent):
            return self._input_failure("rea_output_must_be_new_and_unlinked")
        limits = worker["limits"]
        if target.is_file():
            try:
                info = target.stat(follow_symlinks=False)
            except OSError:
                return self._input_failure("rea_input_unreadable")
            if info.st_nlink > 1 or info.st_size > limits["max_total_bytes"]:
                return self._input_failure("rea_input_file_budget_exceeded")
        try:
            out_dir.parent.mkdir(parents=True, exist_ok=True)
            if _path_has_link(out_dir.parent):
                return self._input_failure("rea_output_parent_link_rejected")
            out_dir.mkdir()
            snapshot_root = out_dir / "input_snapshot"
            if target.is_dir():
                snapshot = create_project_snapshot(
                    target, snapshot_root,
                    max_files=limits["max_files"],
                    max_bytes=limits["max_total_bytes"],
                    max_file_bytes=limits["max_file_bytes"],
                    immutable=True,
                )
                input_path = snapshot_root / "files"
                input_format = "directory"
                snapshot_manifest = snapshot_root / "manifest.json"
                snapshot_scope = snapshot.get("scope", "partial")
                snapshot_digest = snapshot.get("root_digest")
                snapshot_manifest_sha256 = snapshot.get("manifest_sha256")
            else:
                snapshot_root.mkdir()
                input_path = snapshot_root / target.name
                input_digest = sha256_file(target)
                copied_digest = create_verified_snapshot(
                    target, input_path,
                    expected_sha256=input_digest,
                    max_bytes=limits["max_total_bytes"],
                )
                snapshot_manifest = snapshot_root / "manifest.json"
                snapshot_manifest_payload = {
                    "schema": "rea-input-snapshot.v1",
                    "source_name": target.name,
                    "sha256": copied_digest,
                    "size_bytes": input_path.stat().st_size,
                    "immutable": False,
                    "limitations": ["ASAR input is copied and hash-verified locally; this is not external custody or WORM"],
                }
                snapshot_manifest_sha256 = _write_json(snapshot_manifest, snapshot_manifest_payload)
                snapshot_scope, snapshot_digest, input_format = "complete", copied_digest, "asar"

            limits_dir = out_dir / ".rea-tmp"
            limits_dir.mkdir()
            env = _minimal_worker_environment(Path(paths["node"]), limits_dir)
            command = [
                paths["node"], paths["entrypoint"], "analyze-javascript-application",
                str(input_path), "--json", "--artifact-format", input_format,
                "--integrity-policy", "fail", "--max-heap-mb", str(limits["node_heap_mb"]),
                "--analysis-timeout-ms", str(limits["analysis_timeout_ms"]),
            ]
            process = run_bounded(
                command,
                timeout=limits["wall_seconds"],
                memory_limit_mb=limits["memory_bytes"] // _MIB,
                cpu_time_limit_s=limits["cpu_seconds"],
                output_limit_bytes=limits["output_bytes"],
                require_process_tree=True,
                cwd=paths["package_root"], env=env, shell=False,
            )
            stdout = str(process.get("stdout", ""))
            stderr = str(process.get("stderr", ""))
            (out_dir / "rea-progress.log").write_text(stderr, encoding="utf-8", errors="replace")
            if process.get("resource_exceeded") or process.get("timed_out") or process.get("returncode") != 0 or not process.get("capture_complete", False):
                partial_path = out_dir / "rea-result.partial.txt"
                partial_path.write_text(stdout, encoding="utf-8", errors="replace")
                error = "rea_output_limit_exceeded" if process.get("output_limit_exceeded") else "rea_worker_timeout" if process.get("timed_out") else "rea_worker_resource_exceeded" if process.get("resource_exceeded") else "rea_worker_failed"
                return validate_adapter_result(self.name, {
                    "available": True, "executed": True, "produced_evidence": False,
                    "partial": True, "ok": False, "error": error,
                    "timed_out": bool(process.get("timed_out")),
                    "resource_exceeded": bool(process.get("resource_exceeded")),
                    "output_limit_exceeded": bool(process.get("output_limit_exceeded")),
                    "output_bytes": process.get("output_bytes", 0),
                    "partial_output_path": str(partial_path),
                    "process_tree_contained": bool(process.get("process_tree_contained")),
                })
            try:
                rea_data = json.loads(stdout, object_pairs_hook=_reject_duplicate_keys)
            except (json.JSONDecodeError, ValueError):
                partial_path = out_dir / "rea-result.partial.txt"
                partial_path.write_text(stdout, encoding="utf-8", errors="replace")
                return validate_adapter_result(self.name, {
                    "available": True, "executed": True, "produced_evidence": False,
                    "partial": True, "ok": False, "error": "rea_json_output_invalid",
                    "partial_output_path": str(partial_path),
                    "process_tree_contained": bool(process.get("process_tree_contained")),
                })
            rea_envelope: dict[str, Any] | None = None
            if isinstance(rea_data, dict) and "normalized_result" in rea_data:
                valid, error = _valid_rea_evidence_envelope(rea_data, input_path)
                if not valid:
                    partial_path = out_dir / "rea-result.partial.txt"
                    partial_path.write_text(stdout, encoding="utf-8", errors="replace")
                    return validate_adapter_result(self.name, {
                        "available": True, "executed": True, "produced_evidence": False,
                        "partial": True, "ok": False, "error": error,
                        "partial_output_path": str(partial_path),
                        "process_tree_contained": bool(process.get("process_tree_contained")),
                    })
                rea_envelope = rea_data
                rea_data = rea_envelope["normalized_result"]
            valid, error = _valid_rea_result(rea_data, input_path)
            if not valid:
                partial_path = out_dir / "rea-result.partial.txt"
                partial_path.write_text(stdout, encoding="utf-8", errors="replace")
                return validate_adapter_result(self.name, {
                    "available": True, "executed": True, "produced_evidence": False,
                    "partial": True, "ok": False, "error": error,
                    "partial_output_path": str(partial_path),
                    "process_tree_contained": bool(process.get("process_tree_contained")),
                })
            raw_result_path = out_dir / "rea-result.json"
            raw_bytes = _canonical_json_bytes(rea_data) if rea_envelope is not None else stdout.encode("utf-8")
            raw_result_path.write_bytes(raw_bytes)
            raw_result_sha256 = hashlib.sha256(raw_bytes).hexdigest()
            envelope_path: Path | None = None
            envelope_sha256: str | None = None
            envelope_bytes = b""
            if rea_envelope is not None:
                envelope_path = out_dir / "rea-evidence-envelope.json"
                envelope_bytes = stdout.encode("utf-8")
                envelope_path.write_bytes(envelope_bytes)
                envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
            project_path: Path | None = None
            project_report: dict[str, Any] | None = None
            if input_format == "directory":
                try:
                    project_report = analyze_project(input_path)
                except Exception as exc:
                    project_report = {"schema": "project-audit.v1", "status": "invalid", "errors": [{"code": "aetherre_project_audit_error", "detail": type(exc).__name__}], "summary": {}}
                project_path = out_dir / "aetherre-project-audit.json"
                project_digest = _write_json(project_path, project_report)
            else:
                project_digest = None
            artifacts = [
                {"path": raw_result_path.name, "role": "normalized_rea_analysis" if rea_envelope is not None else "raw_rea_analysis", "sha256": raw_result_sha256, "bytes": len(raw_bytes)},
                {"path": snapshot_manifest.relative_to(out_dir).as_posix(), "role": "input_snapshot_manifest", "sha256": snapshot_manifest_sha256, "bytes": snapshot_manifest.stat().st_size},
            ]
            if envelope_path is not None:
                artifacts.append({"path": envelope_path.name, "role": "raw_rea_evidence_envelope", "sha256": envelope_sha256, "bytes": len(envelope_bytes)})
            if project_path is not None:
                artifacts.append({"path": project_path.name, "role": "aetherre_project_audit", "sha256": project_digest, "bytes": project_path.stat().st_size})
            progress_path = out_dir / "rea-progress.log"
            if progress_path.stat().st_size:
                artifacts.append({"path": progress_path.name, "role": "rea_progress_log", "sha256": sha256_file(progress_path), "bytes": progress_path.stat().st_size})
            worker_provenance = {
                "name": worker["name"], "version": worker["version"],
                "official_url": worker["official_url"], "git_head": worker["git_head"],
                "license_spdx": worker["license_spdx"],
                "tarball_sha256": worker["tarball_sha256"],
                "package_tree_sha256": worker["package_tree_sha256"],
                "dependencies_tree_sha256": worker["dependencies_tree_sha256"],
                "node_version": worker["node_version"], "node_sha256": worker["node_sha256"],
            }
            rea_stats = rea_data["statistics"]
            project_status = project_report.get("status") if project_report else "not_applicable_asar"
            process_contained = process.get("process_tree_contained") is True
            complete = (
                snapshot_scope == "complete"
                and rea_stats.get("parse_failures") == 0
                and not rea_data.get("integrity_contradictions")
                and process_contained
                and (project_status in {"complete", "not_applicable_asar"})
            )
            report = {
                "schema": RESULT_SCHEMA,
                "status": "complete" if complete else "partial",
                "created_by": {"name": "AetherRE Megazord", "version": __version__},
                "input": {
                    "source_path": str(target), "source_format": input_format,
                    "snapshot_scope": snapshot_scope,
                    "snapshot_root_digest": snapshot_digest,
                    "snapshot_manifest_sha256": snapshot_manifest_sha256,
                },
                "workers": {
                    "rea": worker_provenance,
                    "aetherre_project_audit": {
                        "name": "AetherRE project_audit", "version": __version__,
                        "status": project_status,
                        "report_sha256": project_digest,
                    },
                },
                "rea_summary": {
                    "root_artifact_sha256": rea_data["root_artifact_sha256"],
                    "inventory_manifest_id": rea_data["inventory_manifest_id"],
                    "inventory_graph_sha256": rea_data["inventory_graph_sha256"],
                    "summary": rea_data["summary"], "statistics": rea_stats,
                    "limitations": rea_data["limitations"],
                },
                "cross_engine_correlation": {
                    "status": "not_attempted",
                    "reason": "semantic engine graph identities are not merged; the artifact correspondence below links only exact input-byte identities",
                },
                "artifact_correspondence": build_artifact_correspondence(
                    json.loads(snapshot_manifest.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys),
                    rea_data,
                    project_report or {},
                ),
                "evidence_catalog": [
                    {"engine": "rea-agents", "artifact_path": envelope_path.name if envelope_path else raw_result_path.name, "artifact_sha256": envelope_sha256 if envelope_path else raw_result_sha256, "graph_field": "normalized_result.graph" if envelope_path else "graph", "semantic_graph_field": "normalized_result.semantic_graph" if envelope_path else "semantic_graph"},
                    *([{"engine": "aetherre", "artifact_path": project_path.name, "artifact_sha256": project_digest, "graph_field": "source"}] if project_path else []),
                ],
                "artifacts": artifacts,
                "loss_ledger": [
                    {"property": "source tool outputs", "handling": "exact REA Evidence envelope, normalized REA report, and AetherRE project audit preserved as separate artifacts", "loss": "none introduced by the federation wrapper"},
                    {"property": "cross-engine graph identity", "handling": "not merged; correlation deliberately not attempted", "loss": "cross-engine edges are not available"},
                    {"property": "runtime behavior and semantic equivalence", "handling": "not inferred from static analysis", "loss": "unknown; requires separate authorized dynamic evidence"},
                    {"property": "directory snapshot exclusions", "handling": "listed by input_snapshot/manifest.json", "loss": "any skipped input prevents complete status"},
                ],
                "limitations": [
                    "Static JavaScript/Electron analysis only; the analyzed application was not executed.",
                    "A readable reconstruction or source map does not prove recovery of original source or behavioral equivalence.",
                    "The wrapper federates evidence but does not claim a canonical merged graph or a profile certificate.",
                ],
                "run": {
                    "returncode": process.get("returncode"),
                    "timed_out": bool(process.get("timed_out")),
                    "resource_exceeded": bool(process.get("resource_exceeded")),
                    "output_limit_exceeded": bool(process.get("output_limit_exceeded")),
                    "output_bytes": process.get("output_bytes", 0),
                    "captured_output_bytes": process.get("captured_output_bytes", 0),
                    "process_tree_contained": process_contained,
                    "limits": limits,
                },
            }
            report_path = out_dir / "rea-federated-report.v1.json"
            report_sha256 = _write_json(report_path, report)
            result = {
                "available": True, "executed": True, "produced_evidence": True,
                "partial": not complete, "ok": complete,
                "evidence_path": str(report_path), "evidence_sha256": report_sha256,
                "report_status": report["status"], "artifact_count": len(artifacts),
                "root_artifact_sha256": rea_data["root_artifact_sha256"],
                "process_tree_contained": process_contained,
            }
            return validate_adapter_result(self.name, result)
        except (OSError, ValueError, RuntimeError, TypeError) as exc:
            return validate_adapter_result(self.name, {
                "available": True, "executed": False, "produced_evidence": False,
                "partial": False, "ok": False,
                "error": str(exc) if isinstance(exc, ValueError) and re.fullmatch(r"[a-z0-9_:\-.]{1,128}", str(exc)) else f"rea_analysis_error:{type(exc).__name__}",
            })

    def _input_failure(self, error: str) -> dict[str, Any]:
        return validate_adapter_result(self.name, {
            "available": True, "executed": False, "produced_evidence": False,
            "partial": False, "ok": False, "state": "failed", "error": error,
        })


def _minimal_worker_environment(node: Path, temporary_root: Path) -> dict[str, str]:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    path = os.pathsep.join((str(node.parent), os.path.join(system_root, "System32"), system_root))
    return {
        "PATH": path,
        "SystemRoot": system_root,
        "WINDIR": system_root,
        "TEMP": str(temporary_root),
        "TMP": str(temporary_root),
        "NO_COLOR": "1",
        "CI": "1",
    }
