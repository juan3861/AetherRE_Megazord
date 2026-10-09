"""Validação controlada de receitas do corpus, sem executar os binários gerados."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from aether_re.process import run_bounded
from aether_re.evidence import _path_has_link


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_path(root: Path, relative: object) -> Path | None:
    if not isinstance(relative, str):
        return None
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    raw = root / candidate
    if _path_has_link(raw):
        return None
    path = raw.resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return None
    return path


def validate_auxiliary_artifacts(item: dict[str, Any], root: Path, project_id: str) -> list[dict[str, Any]]:
    """Validate declared non-primary corpus files before scoring/building.

    Omission still means an unmeasured file, not a closed-world proof; callers
    must not infer that documentation/tests/config are authenticated unless
    explicitly listed here.
    """
    artifacts = item.get("artifacts")
    if artifacts is None:
        return []
    if not isinstance(artifacts, list) or len(artifacts) > 1000:
        return [{"code": "artifacts_invalid", "id": project_id}]
    errors: list[dict[str, Any]] = []
    seen: set[str] = set()
    primary = {str(item.get("source")), str(item.get("oracle"))}
    for entry in artifacts:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            errors.append({"code": "artifact_invalid", "id": project_id})
            continue
        relative = entry["path"]
        candidate = Path(relative)
        if relative in seen or relative in primary:
            errors.append({"code": "artifact_duplicate", "id": project_id, "path": relative})
            continue
        seen.add(relative)
        if not candidate.parts or candidate.parts[0] != project_id:
            errors.append({"code": "artifact_scope_invalid", "id": project_id, "path": relative})
            continue
        path = _safe_path(root, relative)
        if path is None or not path.is_file():
            errors.append({"code": "artifact_path_invalid", "id": project_id, "path": relative})
            continue
        digest = entry.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            errors.append({"code": "artifact_hash_invalid", "id": project_id, "path": relative})
            continue
        if path.stat().st_size > 16 * 1024 * 1024 or _sha256(path) != digest:
            errors.append({"code": "artifact_hash_mismatch", "id": project_id, "path": relative})
    return errors


def _validate_manifest(manifest: object, root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """Validate corpus identity before allowing any build worker to run."""
    errors: list[dict[str, Any]] = []
    projects = manifest.get("projects", []) if isinstance(manifest, dict) else []
    if not isinstance(projects, list):
        errors.append({"code": "projects_invalid", "detail": "list_required"})
        return [], errors, {}
    if not isinstance(manifest, dict) or manifest.get("schema") != "re-megazord-corpus.v1":
        errors.append({"code": "schema_invalid", "detail": "re-megazord-corpus.v1_required"})
    seen_ids: set[str] = set()
    families: dict[str, list[dict[str, Any]]] = {}
    valid: list[dict[str, Any]] = []
    for item in projects:
        if not isinstance(item, dict):
            errors.append({"code": "project_invalid", "detail": "object_required"})
            continue
        project_id = str(item.get("id", "<missing>"))
        local_errors: list[dict[str, Any]] = []
        if not project_id or project_id in {".", ".."} or Path(project_id).name != project_id or not re.fullmatch(r"[A-Za-z0-9_.-]+", project_id):
            local_errors.append({"code": "project_id_invalid", "id": project_id})
        if project_id in seen_ids:
            local_errors.append({"code": "duplicate_id", "id": project_id})
        seen_ids.add(project_id)
        if item.get("language") not in {"python", "c"}:
            local_errors.append({"code": "language_unsupported", "id": project_id})
        build_kind = item.get("build_kind", "executable")
        if build_kind not in {"executable", "shared_library"} or (item.get("language") != "c" and "build_kind" in item):
            local_errors.append({"code": "build_kind_invalid", "id": project_id})
        if not item.get("family") or item.get("split") not in {"development", "calibration", "holdout"}:
            local_errors.append({"code": "identity_invalid", "id": project_id})
        authorization = item.get("authorization")
        if authorization not in {"owned_synthetic", "external_authorized", "local_authorized"}:
            local_errors.append({"code": "authorization_missing", "id": project_id})
        elif authorization in {"external_authorized", "local_authorized"}:
            provenance = item.get("provenance")
            prefix = "local" if authorization == "local_authorized" else "external"
            if not isinstance(provenance, dict):
                local_errors.append({"code": f"{prefix}_provenance_missing", "id": project_id})
            else:
                required_provenance = ("origin", "license", "authorization_ref", "oracle_method")
                missing = [field for field in required_provenance if not isinstance(provenance.get(field), str) or not provenance.get(field).strip()]
                if missing:
                    local_errors.append({"code": f"{prefix}_provenance_incomplete", "id": project_id, "fields": missing})
                if provenance.get("oracle_independent") is not True:
                    local_errors.append({"code": f"{prefix}_oracle_independence_unasserted", "id": project_id})
                oracle_artifact = _safe_path(root, provenance.get("oracle_artifact"))
                artifact_hash = provenance.get("oracle_artifact_sha256")
                if oracle_artifact is None or not oracle_artifact.is_file():
                    local_errors.append({"code": f"{prefix}_oracle_artifact_missing", "id": project_id})
                elif oracle_artifact.is_relative_to(root / project_id):
                    local_errors.append({"code": f"{prefix}_oracle_not_separate", "id": project_id})
                elif not isinstance(artifact_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", artifact_hash) or _sha256(oracle_artifact) != artifact_hash:
                    local_errors.append({"code": f"{prefix}_oracle_artifact_hash_mismatch", "id": project_id})
                if authorization == "local_authorized":
                    auth_artifact = _safe_path(root, provenance.get("authorization_artifact"))
                    auth_hash = provenance.get("authorization_artifact_sha256")
                    if auth_artifact is None or not auth_artifact.is_file():
                        local_errors.append({"code": "local_authorization_artifact_missing", "id": project_id})
                    elif auth_artifact.is_relative_to(root / project_id):
                        local_errors.append({"code": "local_authorization_not_separate", "id": project_id})
                    elif not isinstance(auth_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", auth_hash) or _sha256(auth_artifact) != auth_hash:
                        local_errors.append({"code": "local_authorization_artifact_hash_mismatch", "id": project_id})
        source = _safe_path(root, item.get("source"))
        oracle = _safe_path(root, item.get("oracle"))
        if source is None or not source.is_file():
            local_errors.append({"code": "source_invalid", "id": project_id})
        if oracle is None or not oracle.is_file():
            local_errors.append({"code": "oracle_invalid", "id": project_id})
        if source and source.is_file() and item.get("source_sha256") != _sha256(source):
            local_errors.append({"code": "source_hash_mismatch", "id": project_id})
        if oracle and oracle.is_file():
            if item.get("oracle_sha256") != _sha256(oracle):
                local_errors.append({"code": "oracle_hash_mismatch", "id": project_id})
            try:
                oracle_data = json.loads(oracle.read_text(encoding="utf-8"))
                if not isinstance(oracle_data, dict) or oracle_data.get("oracle_schema") != "re-megazord-oracle.v1" or oracle_data.get("family") != item.get("family") or oracle_data.get("language") != item.get("language"):
                    local_errors.append({"code": "oracle_identity_mismatch", "id": project_id})
            except (OSError, UnicodeError, json.JSONDecodeError):
                local_errors.append({"code": "oracle_json_invalid", "id": project_id})
        local_errors.extend(validate_auxiliary_artifacts(item, root, project_id))
        if local_errors:
            errors.extend(local_errors)
        else:
            valid.append(item)
        families.setdefault(str(item.get("family")), []).append({"id": project_id, "split": item.get("split"), "errors": local_errors})
    for family, entries in families.items():
        splits = {str(item["split"]) for item in entries}
        if len(splits) > 1:
            errors.append({"code": "family_split_leak", "family": family, "splits": sorted(splits)})
    return valid, errors, families


def validate_corpus_builds(manifest_path: Path, *, python_executable: str | None = None) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    root = manifest_path.parent
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {"schema": "corpus-build-validation.v1", "manifest": str(manifest_path), "status": "invalid", "results": [], "manifest_errors": [{"code": "manifest_unreadable", "detail": type(exc).__name__}], "limits": ["Python usa py_compile somente", "build nativo requer worker explícito", "binários gerados nunca são executados"]}
    manifest_sha256 = _sha256(manifest_path)
    valid_projects, manifest_errors, families = _validate_manifest(manifest, root)
    valid_by_id = {str(item["id"]): item for item in valid_projects}
    results: list[dict[str, Any]] = []
    py = python_executable or sys.executable
    projects = manifest.get("projects", []) if isinstance(manifest, dict) else []
    for item in projects if isinstance(projects, list) else []:
        if not isinstance(item, dict):
            results.append({"id": "<invalid>", "status": "invalid", "reason": "project_object_required"})
            continue
        project_id = str(item.get("id", "<missing>"))
        if project_id not in valid_by_id:
            results.append({"id": project_id, "language": item.get("language"), "status": "invalid", "reason": "manifest_validation_failed"})
            continue
        project_dir = root / project_id
        source = _safe_path(root, item["source"])
        if source is None:
            results.append({"id": project_id, "language": item.get("language"), "status": "invalid", "reason": "source_path_invalid"})
            continue
        result: dict[str, Any] = {"id": item["id"], "language": item["language"], "source_sha256": _sha256(source)}
        if item["language"] == "python":
            python_files = [source]
            for artifact in item.get("artifacts", []):
                if Path(artifact["path"]).suffix == ".py":
                    python_files.append(_safe_path(root, artifact["path"]))
            compile_results = []
            for path in python_files:
                proc = run_bounded([py, "-m", "py_compile", str(path)], timeout=30, cwd=str(project_dir))
                compile_results.append({"path": str(path), "returncode": proc["returncode"], "timed_out": proc["timed_out"], "stderr_tail": proc["stderr"][-500:]})
            failed = [entry for entry in compile_results if entry["returncode"] != 0 or entry["timed_out"]]
            result.update({"status": "failed" if failed else "succeeded", "returncode": compile_results[0]["returncode"], "timed_out": any(entry["timed_out"] for entry in compile_results), "stderr_tail": compile_results[0]["stderr_tail"], "compiled_files": len(compile_results), "compile_failures": failed})
        else:
            compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
            result.update({"status": "unavailable" if not compiler else "queued", "reason": "compiler_not_found" if not compiler else "native_build_requires_explicit_worker", "compiler": compiler})
        results.append(result)
    status = "invalid" if manifest_errors else "complete" if results and all(item["status"] == "succeeded" for item in results) else "partial"
    return {"schema": "corpus-build-validation.v1", "manifest": str(manifest_path), "status": status, "results": results, "manifest_errors": manifest_errors, "family_index": families, "authorization_profiles": ["owned_synthetic", "external_authorized", "local_authorized"], "limits": ["Python usa py_compile somente", "build C permanece unavailable/queued conforme compiler descoberto", "binários gerados nunca são executados", "manifesto, hashes, autorização, oracle e split são validados antes do worker", "external_authorized/local_authorized exigem provenance declarada; declaração não substitui auditoria independente"]}


def write_build_validation(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _wsl_path(path: Path) -> str:
    """Map a Windows path into WSL without invoking a shell or following links."""
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").lower()
    if os.name == "nt" and drive:
        return "/mnt/" + drive + resolved.as_posix()[2:]
    return resolved.as_posix()


def build_c_corpus_wsl(
    manifest_path: Path,
    output_dir: Path,
    *,
    timeout: float = 60.0,
    memory_limit_mb: int = 1024,
    opt_level: str = "-O0",
    debug: bool = True,
    strip: bool = False,
) -> dict[str, Any]:
    """Build owned C fixtures in an explicitly selected WSL worker.

    The worker is opt-in and compiles only manifest entries authorized as
    ``owned_synthetic``. Generated binaries are never executed; they are read
    back only for hash and static ELF identity. The function is deliberately
    separate from :func:`validate_corpus_builds`, whose default remains
    non-building on Windows.
    """
    manifest_path = manifest_path.resolve()
    if opt_level not in {"-O0", "-O1", "-O2", "-O3", "-Os"}:
        return {"schema": "corpus-native-build.v1", "status": "invalid", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [{"code": "optimization_invalid", "detail": opt_level}], "executed_targets": False}
    root = manifest_path.parent
    output_candidate = Path(output_dir)
    output_is_symlink = output_candidate.is_symlink()
    output_dir = output_candidate.resolve()
    if output_dir == root or output_dir.is_relative_to(root) or output_is_symlink:
        return {
            "schema": "corpus-native-build.v1",
            "status": "invalid",
            "manifest": str(manifest_path),
            "output_dir": str(output_dir),
            "results": [],
            "issues": [{"code": "output_inside_corpus", "detail": "separate_output_required"}],
            "executed_targets": False,
        }
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {"schema": "corpus-native-build.v1", "status": "invalid", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [{"code": "manifest_unreadable", "detail": type(exc).__name__}], "executed_targets": False}
    manifest_sha256 = _sha256(manifest_path)
    valid_projects, manifest_errors, families = _validate_manifest(manifest, root)
    if manifest_errors:
        return {"schema": "corpus-native-build.v1", "status": "invalid", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": manifest_errors, "family_index": families, "executed_targets": False}
    projects = [item for item in valid_projects if item.get("language") == "c"]
    if not projects:
        return {"schema": "corpus-native-build.v1", "status": "not_applicable", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [], "family_index": families, "executed_targets": False}
    wsl = shutil.which("wsl.exe") or shutil.which("wsl")
    if not wsl:
        return {"schema": "corpus-native-build.v1", "status": "unavailable", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [{"id": item["id"], "language": "c", "status": "unavailable", "reason": "wsl_not_found"} for item in projects], "issues": [], "family_index": families, "executed_targets": False}
    probe = run_bounded([wsl, "-e", "gcc", "--version"], timeout=min(15.0, timeout))
    version_lines = (probe.get("stdout") or probe.get("stderr") or "").splitlines()
    compiler_version = version_lines[0][:300] if version_lines else "unknown (gcc probe returned no text)"
    if probe.get("returncode") != 0 or probe.get("timed_out"): 
        return {"schema": "corpus-native-build.v1", "status": "unavailable", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [{"id": item["id"], "language": "c", "status": "unavailable", "reason": "wsl_gcc_unavailable"} for item in projects], "issues": [], "compiler": "gcc", "compiler_version": compiler_version, "executed_targets": False}
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    compile_commands: list[dict[str, Any]] = []
    for item in projects:
        project_id = str(item.get("id", ""))
        if not project_id or project_id in {".", ".."} or Path(project_id).name != project_id or not re.fullmatch(r"[A-Za-z0-9_.-]+", project_id):
            results.append({"id": project_id or "<missing>", "language": "c", "status": "invalid", "reason": "project_id_invalid"})
            continue
        source = _safe_path(root, item.get("source"))
        if source is None or not source.is_file() or source.is_symlink():
            results.append({"id": item["id"], "language": "c", "status": "invalid", "reason": "source_invalid"})
            continue
        build_kind = item.get("build_kind", "executable")
        output_path = output_dir / f"{project_id}{'.so' if build_kind == 'shared_library' else '.elf'}"
        command = ["gcc", "-std=c11", opt_level]
        if debug:
            command.append("-g")
        if strip:
            command.append("-s")
        command.extend(["-fno-inline", "-fno-omit-frame-pointer"])
        command.extend(["-fPIC", "-shared"] if build_kind == "shared_library" else ["-fno-pie", "-no-pie"])
        command.extend(["-Wl,--build-id=none", "-o", _wsl_path(output_path), _wsl_path(source)])
        proc = run_bounded([wsl, "-e", *command], timeout=timeout, memory_limit_mb=memory_limit_mb)
        result: dict[str, Any] = {"id": item["id"], "language": "c", "build_kind": build_kind, "source": item["source"], "source_sha256": _sha256(source), "command": command, "profile": {"opt_level": opt_level, "debug": debug, "strip": strip}, "compiler": "gcc", "compiler_version": compiler_version, "executed_target": False, "returncode": proc.get("returncode"), "timed_out": proc.get("timed_out", False), "resource_exceeded": proc.get("resource_exceeded", False), "stderr_tail": str(proc.get("stderr", ""))[-500:]}
        if proc.get("returncode") == 0 and not proc.get("timed_out") and output_path.is_file():
            from aether_re.engines.pe_elf import run_structure

            binary = output_path.read_bytes()
            structure = run_structure(binary)
            result.update({"status": "succeeded", "output": str(output_path), "output_sha256": _sha256(output_path), "format": structure.get("format"), "architecture": structure.get("machine_name", "unknown"), "symbols": len(structure.get("symbols", []))})
        else:
            result.update({"status": "failed", "output": str(output_path)})
        results.append(result)
        compile_commands.append({"directory": _wsl_path(root), "file": _wsl_path(source), "arguments": command})
    (output_dir / "compile_commands.json").write_text(json.dumps(compile_commands, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    succeeded = sum(item.get("status") == "succeeded" for item in results)
    status = "complete" if succeeded == len(projects) else "partial"
    return {"schema": "corpus-native-build.v1", "status": status, "manifest": str(manifest_path), "manifest_sha256": manifest_sha256, "output_dir": str(output_dir), "compiler": "gcc", "compiler_version": compiler_version, "profile": {"opt_level": opt_level, "debug": debug, "strip": strip}, "results": results, "family_index": families, "compile_commands": str(output_dir / "compile_commands.json"), "executed_targets": False, "limits": ["worker explícito WSL/gcc", "somente projetos owned_synthetic", "binários gerados nunca são executados", "hash e identidade ELF são leitura estática posterior"]}


def build_c_corpus_msvc(
    manifest_path: Path,
    output_dir: Path,
    *,
    compiler_path: Path,
    vcvarsall_path: Path,
    support_dir: Path,
    timeout: float = 120.0,
    memory_limit_mb: int = 2048,
    opt_level: str = "-O0",
    debug: bool = True,
    allow_external_authorized: bool = False,
) -> dict[str, Any]:
    """Build authorized C fixtures with an explicit, non-executing MSVC worker.

    A temporary batch file is used only to provision ``vcvarsall`` because
    Python's Windows argv quoting cannot safely carry nested batch paths with
    spaces. The batch file is bounded, deleted after each call, and never
    receives untrusted shell fragments; generated PE files are only hashed and
    parsed structurally, never loaded or executed.
    """
    schema = "corpus-native-build.v1"
    manifest_path = Path(manifest_path).resolve()
    output_candidate = Path(output_dir)
    output_is_symlink = output_candidate.is_symlink()
    output_dir = output_candidate.resolve()
    if output_dir == manifest_path.parent or output_dir.is_relative_to(manifest_path.parent) or output_is_symlink:
        return {"schema": schema, "status": "invalid", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [{"code": "output_inside_corpus", "detail": "separate_output_required"}], "executed_targets": False}
    if opt_level not in {"-O0", "-O1", "-O2", "-O3", "-Os"}:
        return {"schema": schema, "status": "invalid", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [{"code": "optimization_invalid", "detail": opt_level}], "executed_targets": False}
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < float(timeout) <= 86400:
        return {"schema": schema, "status": "invalid", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [{"code": "timeout_invalid"}], "executed_targets": False}
    if not isinstance(memory_limit_mb, int) or isinstance(memory_limit_mb, bool) or memory_limit_mb < 128:
        return {"schema": schema, "status": "invalid", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [{"code": "memory_limit_invalid"}], "executed_targets": False}

    def _regular(path: Path) -> bool:
        try:
            return path.is_file() and not path.is_symlink() and not _path_has_link(path)
        except OSError:
            return False

    compiler_path = Path(compiler_path).resolve()
    vcvarsall_path = Path(vcvarsall_path).resolve()
    support_dir = Path(support_dir).resolve()
    if not _regular(compiler_path):
        return {"schema": schema, "status": "unavailable", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [{"code": "compiler_invalid", "path": str(compiler_path)}], "executed_targets": False}
    if not _regular(vcvarsall_path):
        return {"schema": schema, "status": "unavailable", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [{"code": "vcvarsall_invalid", "path": str(vcvarsall_path)}], "executed_targets": False}
    support_files = [support_dir / "std_testcase.h", support_dir / "std_testcase_io.h", support_dir / "io.c", support_dir / "std_thread.c"]
    if not support_dir.is_dir() or any(not _regular(item) for item in support_files):
        return {"schema": schema, "status": "unavailable", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [{"code": "juliet_support_invalid", "path": str(support_dir)}], "executed_targets": False}
    unsafe = re.compile(r'[\r\n"&|<>^%]')
    if any(unsafe.search(str(path)) for path in (manifest_path, output_dir, compiler_path, vcvarsall_path, support_dir)):
        return {"schema": schema, "status": "invalid", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [{"code": "path_characters_invalid"}], "executed_targets": False}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {"schema": schema, "status": "invalid", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [{"code": "manifest_unreadable", "detail": type(exc).__name__}], "executed_targets": False}
    manifest_sha256 = _sha256(manifest_path)
    valid_projects, manifest_errors, families = _validate_manifest(manifest, manifest_path.parent)
    if manifest_errors:
        return {"schema": schema, "status": "invalid", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": manifest_errors, "family_index": families, "executed_targets": False}
    projects = [item for item in valid_projects if item.get("language") == "c"]
    if not projects:
        return {"schema": schema, "status": "not_applicable", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [], "family_index": families, "executed_targets": False}
    external = [item for item in projects if item.get("authorization") in {"external_authorized", "local_authorized"}]
    if external and not allow_external_authorized:
        results = []
        issues = []
        for item in external:
            authorization = item.get("authorization")
            code = f"{authorization}_requires_explicit_flag"
            results.append({"id": item["id"], "status": "rejected", "reason": code, "executed_target": False})
            issues.append({"code": code, "count": 1})
        return {"schema": schema, "status": "rejected", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": results, "issues": issues, "family_index": families, "executed_targets": False}
    comspec = os.environ.get("ComSpec") or shutil.which("cmd.exe")
    if not comspec or unsafe.search(str(comspec)):
        return {"schema": schema, "status": "unavailable", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [{"id": item["id"], "status": "unavailable", "reason": "cmd_not_found", "executed_target": False} for item in projects], "issues": [], "family_index": families, "executed_targets": False}
    batch_root = Path(tempfile.gettempdir()).resolve()
    if _path_has_link(batch_root) or unsafe.search(str(batch_root)):
        return {"schema": schema, "status": "unavailable", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [], "issues": [{"code": "batch_temp_path_invalid", "path": str(batch_root)}], "executed_targets": False}
    batch_root.mkdir(parents=True, exist_ok=True)
    opt_flag = {"-O0": "/Od", "-O1": "/O1", "-O2": "/O2", "-O3": "/O2", "-Os": "/O1"}[opt_level]
    base_args = ["/nologo", "/TC", "/std:c11", opt_flag, "/W3", "/EHsc", "/DINCLUDEMAIN", f'/I"{support_dir}"']
    if debug:
        base_args.append("/Zi")

    def _run_batch(cl_args: list[str], budget: float) -> dict[str, Any]:
        script_path: Path | None = None
        try:
            handle = tempfile.NamedTemporaryFile(prefix="re-megazord-msvc-", suffix=".bat", dir=batch_root, delete=False)
            script_path = Path(handle.name)
            compiler_line = f'"{compiler_path}" ' + " ".join(cl_args)
            payload = "\r\n".join(("@echo off", f'call "{vcvarsall_path}" x64 >nul', "if errorlevel 1 exit /b %errorlevel%", compiler_line, "exit /b %errorlevel%", ""))
            handle.write(payload.encode("utf-8"))
            handle.close()
            return run_bounded([comspec, "/d", "/c", str(script_path)], timeout=budget, memory_limit_mb=memory_limit_mb)
        finally:
            if script_path is not None:
                try:
                    script_path.unlink(missing_ok=True)
                except OSError:
                    pass

    probe = _run_batch(["/Bv"], min(15.0, float(timeout)))
    version_lines = [line.strip() for line in (probe.get("stdout", "") + "\n" + probe.get("stderr", "")).splitlines() if line.strip()]
    compiler_version = next((line for line in version_lines if "Compiler" in line or "Vers" in line), version_lines[0] if version_lines else "unknown")[:300]
    if probe.get("timed_out") or compiler_version == "unknown":
        return {"schema": schema, "status": "unavailable", "manifest": str(manifest_path), "output_dir": str(output_dir), "results": [{"id": item["id"], "status": "unavailable", "reason": "msvc_probe_failed", "executed_target": False} for item in projects], "issues": [{"code": "msvc_probe_failed", "detail": compiler_version}], "compiler": str(compiler_path), "compiler_version": compiler_version, "executed_targets": False}
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    compile_commands: list[dict[str, Any]] = []
    for item in projects:
        project_id = str(item.get("id", ""))
        source = _safe_path(manifest_path.parent, item.get("source"))
        if not project_id or Path(project_id).name != project_id or not re.fullmatch(r"[A-Za-z0-9_.-]+", project_id) or source is None or not _regular(source) or unsafe.search(str(source)):
            results.append({"id": project_id or "<missing>", "language": "c", "status": "invalid", "reason": "source_invalid", "executed_target": False})
            continue
        # A fixture may declare its complete translation-unit set and extra
        # include roots in the manifest. Resolve every path beneath the
        # immutable corpus root and reject links/missing files before invoking
        # cl.exe; legacy manifests retain the historical support-file default.
        declared_sources = item.get("build_sources")
        build_sources: list[Path] = []
        if declared_sources is None:
            build_sources = [source, support_files[2], support_files[3]]
        elif isinstance(declared_sources, list) and declared_sources:
            for raw_path in declared_sources:
                resolved = _safe_path(manifest_path.parent, raw_path)
                if resolved is None or not _regular(resolved) or unsafe.search(str(resolved)):
                    build_sources = []
                    break
                build_sources.append(resolved)
            if not build_sources or build_sources[0] != source:
                build_sources = []
        if not build_sources:
            results.append({"id": project_id, "language": "c", "status": "invalid", "reason": "build_sources_invalid", "executed_target": False})
            continue
        include_dirs: list[Path] = [support_dir]
        declared_includes = item.get("include_dirs", [])
        if not isinstance(declared_includes, list):
            results.append({"id": project_id, "language": "c", "status": "invalid", "reason": "include_dirs_invalid", "executed_target": False})
            continue
        for raw_dir in declared_includes:
            resolved_dir = _safe_path(manifest_path.parent, raw_dir)
            if resolved_dir is None or not resolved_dir.is_dir() or _path_has_link(resolved_dir) or unsafe.search(str(resolved_dir)):
                include_dirs = []
                break
            include_dirs.append(resolved_dir)
        if not include_dirs:
            results.append({"id": project_id, "language": "c", "status": "invalid", "reason": "include_dirs_invalid", "executed_target": False})
            continue
        output_path = output_dir / f"{project_id}.exe"
        include_args = [f'/I"{include_dir}"' for include_dir in include_dirs]
        cl_args = [*base_args, *include_args[1:], f'/Fe:"{output_path}"', *(str(path) for path in build_sources)]
        command = ["cl.exe", *cl_args]
        proc = _run_batch(cl_args, float(timeout))
        def _display_path(path: Path) -> str:
            return str(path.relative_to(manifest_path.parent)) if path.is_relative_to(manifest_path.parent) else str(path)

        result: dict[str, Any] = {"id": item["id"], "language": "c", "authorization": item.get("authorization"), "build_kind": item.get("build_kind", "executable"), "source": item["source"], "source_sha256": _sha256(source), "build_sources": [_display_path(path) for path in build_sources], "build_sources_sha256": {_display_path(path): _sha256(path) for path in build_sources}, "include_dirs": [_display_path(path) for path in include_dirs], "command": command, "worker": "msvc", "compiler": str(compiler_path), "compiler_version": compiler_version, "profile": {"opt_level": opt_level, "debug": debug, "include_main": True}, "executed_target": False, "returncode": proc.get("returncode"), "timed_out": proc.get("timed_out", False), "resource_exceeded": proc.get("resource_exceeded", False), "stderr_tail": str(proc.get("stderr", ""))[-1000:]}
        if proc.get("returncode") == 0 and not proc.get("timed_out") and output_path.is_file() and not output_path.is_symlink():
            from aether_re.engines.pe_elf import run_structure
            structure = run_structure(output_path.read_bytes())
            pdb_path = output_path.with_suffix(".pdb")
            pdb_ok = pdb_path.is_file() and not pdb_path.is_symlink() and not _path_has_link(pdb_path)
            result.update({"status": "succeeded", "output": str(output_path), "output_sha256": _sha256(output_path), "format": structure.get("format"), "architecture": structure.get("machine_name", "unknown"), "symbols": len(structure.get("symbols", [])), "pdb": str(pdb_path), "pdb_exists": pdb_ok, "pdb_sha256": _sha256(pdb_path) if pdb_ok else ""})
        else:
            result.update({"status": "failed", "output": str(output_path)})
        results.append(result)
        compile_commands.append({"directory": str(manifest_path.parent), "file": str(source), "sources": [str(path) for path in build_sources], "arguments": command, "worker": "msvc", "vcvarsall": str(vcvarsall_path)})
    compile_commands_path = output_dir / "compile_commands.json"
    compile_commands_path.write_text(json.dumps(compile_commands, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    succeeded = sum(item.get("status") == "succeeded" for item in results)
    status = "complete" if succeeded == len(projects) else "partial"
    return {"schema": schema, "status": status, "manifest": str(manifest_path), "manifest_sha256": manifest_sha256, "output_dir": str(output_dir), "compiler": str(compiler_path), "compiler_version": compiler_version, "profile": {"opt_level": opt_level, "debug": debug, "include_main": True}, "results": results, "family_index": families, "compile_commands": str(compile_commands_path), "executed_targets": False, "limits": ["worker explícito Windows/MSVC", "external_authorized exige flag explícita", "binários PE gerados nunca são executados", "hash e identidade PE são leitura estática posterior"]}



