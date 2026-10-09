"""Avaliação de leitores estáticos contra oracles do corpus, sem executar alvos."""

from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path
from typing import Any

from aether_re.c_source import analyze_c_family_project
from aether_re.source import analyze_python_project
from aether_re.engines.dwarf import analyze_dwarf
from aether_re.engines.elf_calls import recover_direct_calls
from aether_re.engines.pe_elf import run_structure
from aether_re.corpus import _safe_path, validate_auxiliary_artifacts
from aether_re.pdb_dia import extract_pdb_symbols
from aether_re.pe_debug import parse_pe_codeview


SCHEMA = "corpus-source-evaluation.v1"


def _leaf(value: object) -> str:
    return str(value or "").split(".")[-1].split(":")[-1].lower()


def _candidate_function_names(structure: dict[str, Any]) -> set[str]:
    """Return material, defined function symbols for precision scoring.

    ELF symbol tables also contain undefined imports, objects, file markers,
    and zero-sized linker/runtime stubs. Counting those as candidate source
    functions inflates false positives without measuring reconstruction.
    """
    symbols = structure.get("symbols", []) if isinstance(structure, dict) else []
    if not isinstance(symbols, list):
        return set()
    if not str(structure.get("format", "")).upper().startswith("ELF"):
        return {_leaf(item.get("name")) for item in symbols if isinstance(item, dict) and item.get("name")}
    names: set[str] = set()
    for item in symbols:
        if not isinstance(item, dict):
            continue
        try:
            symbol_type = int(str(item.get("type", -1)), 0)
            size = int(str(item.get("size", 0)), 0)
            section_index = int(str(item.get("section_index", 0)), 0)
        except ValueError:
            continue
        if symbol_type == 2 and size > 0 and section_index not in {0, 0xFFF1}:
            name = _leaf(item.get("name"))
            if name:
                names.add(name)
    return names


def _pdb_function_names_for_sources(pdb_report: dict[str, Any], sources: list[str], *, external_only: bool = False) -> set[str]:
    """Select PDB functions attributed by DIA to declared source files.

    The filter is based only on debug source provenance, never on oracle names.
    Raw PDB symbols remain reported separately so this scoped metric cannot hide
    linker/CRT noise.
    """
    declared = {
        str(value).replace("\\", "/").strip("/").casefold()
        for value in sources
        if isinstance(value, str) and value.strip()
    }
    names: set[str] = set()
    for symbol in pdb_report.get("symbols", []):
        if not isinstance(symbol, dict) or not isinstance(symbol.get("name"), str):
            continue
        if external_only and symbol.get("is_static") is not False:
            continue
        source_file = str(symbol.get("source_file") or "").replace("\\", "/").strip("/").casefold()
        if not source_file:
            continue
        if any(source_file == value or source_file.endswith("/" + value) for value in declared):
            name = _leaf(symbol["name"])
            if name:
                names.add(name)
    return names


def _scores(expected: set[str], observed: set[str]) -> dict[str, Any]:
    tp = len(expected & observed)
    fp = len(observed - expected)
    fn = len(expected - observed)
    if not expected and not observed:
        return {"expected": 0, "observed": 0, "true_positive": 0, "false_positive": 0, "false_negative": 0, "precision": 1.0, "recall": 1.0, "f1": 1.0}
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"expected": len(expected), "observed": len(observed), "true_positive": tp, "false_positive": fp, "false_negative": fn, "precision": precision, "recall": recall, "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0}


def _relation_key(caller: object, callee: object) -> tuple[str, str]:
    return (_leaf(caller), _leaf(callee))


def _measured_relation_scores(expected: set[tuple[str, str]], observation: dict[str, Any]) -> dict[str, Any]:
    """Keep numeric `observed` from the score separate from relation samples."""
    observed = {_relation_key(value.get("caller"), value.get("callee")) for value in observation.get("unique_relations", []) if isinstance(value, dict)}
    return {"status": "measured", "method": observation.get("method"), **_scores(expected, observed),
            "observed_relations": sorted([list(value) for value in observed]),
            "direct_calls": observation.get("direct_calls", 0), "resolved_calls": observation.get("resolved_calls", 0),
            "unresolved_direct_calls": observation.get("unresolved_direct_calls", 0),
            "ambiguous_calls": observation.get("ambiguous_calls", 0), "limitations": observation.get("limitations", [])}


def evaluate_corpus_source(manifest_path: Path) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    root = manifest_path.parent
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {"schema": SCHEMA, "status": "invalid", "manifest": str(manifest_path), "projects": [], "errors": [{"code": "manifest_unreadable", "detail": type(exc).__name__}]}
    if not isinstance(manifest, dict) or manifest.get("schema") != "re-megazord-corpus.v1" or not isinstance(manifest.get("projects"), list):
        return {"schema": SCHEMA, "status": "invalid", "manifest": str(manifest_path), "projects": [], "errors": [{"code": "manifest_invalid", "detail": "re-megazord-corpus.v1_and_projects_list_required"}]}
    projects: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for item in manifest["projects"]:
        if not isinstance(item, dict):
            errors.append({"code": "project_invalid"})
            continue
        project_id = str(item.get("id", "<missing>"))
        if project_id in seen_ids:
            errors.append({"code": "duplicate_project_id", "id": project_id})
            continue
        seen_ids.add(project_id)
        if item.get("language") not in {"python", "c"}:
            errors.append({"code": "language_unsupported", "id": project_id})
            continue
        artifact_errors = validate_auxiliary_artifacts(item, root, project_id)
        if artifact_errors:
            errors.extend(artifact_errors)
            continue
        project_dir = (root / project_id).resolve()
        source_path = _safe_file(root, item.get("source"))
        oracle_path = _safe_file(root, item.get("oracle"))
        try:
            project_dir.relative_to(root)
        except ValueError:
            errors.append({"code": "path_escape", "id": project_id})
            continue
        if source_path is None or not source_path.is_file():
            errors.append({"code": "source_invalid", "id": project_id})
            continue
        if oracle_path is None or not oracle_path.is_file():
            errors.append({"code": "oracle_invalid", "id": project_id})
            continue
        try:
            oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            errors.append({"code": "oracle_invalid", "id": project_id, "detail": type(exc).__name__})
            continue
        actual_source_hash = _file_sha256(source_path)
        declared_source_hash = item.get("source_sha256")
        if not isinstance(declared_source_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", declared_source_hash):
            errors.append({"code": "source_hash_missing_or_invalid", "id": project_id})
            continue
        if actual_source_hash != declared_source_hash:
            errors.append({"code": "source_hash_mismatch", "id": project_id})
            continue
        actual_oracle_hash = _file_sha256(oracle_path)
        declared_oracle_hash = item.get("oracle_sha256")
        if not isinstance(declared_oracle_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", declared_oracle_hash):
            errors.append({"code": "oracle_hash_missing_or_invalid", "id": project_id})
            continue
        if actual_oracle_hash != declared_oracle_hash:
            errors.append({"code": "oracle_hash_mismatch", "id": project_id})
            continue
        if not isinstance(oracle, dict) or oracle.get("oracle_schema") != "re-megazord-oracle.v1" or oracle.get("family") != item.get("family") or oracle.get("language") != item.get("language"):
            errors.append({"code": "oracle_identity_mismatch", "id": project_id})
            continue
        analysis = analyze_python_project(project_dir) if item.get("language") == "python" else analyze_c_family_project(project_dir)
        observed_symbols = {_leaf(value.get("name")) for value in analysis.get("functions", []) if isinstance(value, dict)}
        expected_symbols = {_leaf(value) for value in oracle.get("expected_symbols", []) if isinstance(value, str)}
        # Candidate calls include unresolved/external/module-level noise.  The
        # primary metric uses only graph edges that the reader resolved to a
        # unique local function; candidates remain published for audit.
        candidate_relations = {_relation_key(value.get("caller"), value.get("callee")) for value in analysis.get("calls", []) if isinstance(value, dict)}
        resolved_relations = {_relation_key(edge.get("source"), edge.get("resolved_to") or edge.get("target")) for edge in analysis.get("graph", {}).get("edges", []) if isinstance(edge, dict) and edge.get("kind") == "calls" and edge.get("resolved") is True and str(edge.get("source", "")).startswith("function:") and not str(edge.get("source", "")).endswith(".<module>")}
        expected_relations = {_relation_key(value[0], value[1]) for value in oracle.get("expected_relations", []) if isinstance(value, list) and len(value) == 2}
        projects.append({"id": project_id, "family": item.get("family"), "language": item.get("language"), "split": item.get("split"), "source_sha256": actual_source_hash, "oracle_sha256": actual_oracle_hash, "symbols": _scores(expected_symbols, observed_symbols), "relations": _scores(expected_relations, resolved_relations), "relation_candidates": _scores(expected_relations, candidate_relations), "analysis_errors": analysis.get("errors", []), "compile_context": analysis.get("compile_context", {})})
    grouped: dict[str, dict[str, Any]] = {}
    for project in projects:
        key = f"{project['split']}:{project['language']}"
        grouped.setdefault(key, {"projects": 0, "symbol_precision": [], "symbol_recall": [], "relation_precision": [], "relation_recall": [], "relation_candidate_precision": [], "relation_candidate_recall": []})
        bucket = grouped[key]
        bucket["projects"] += 1
        bucket["symbol_precision"].append(project["symbols"]["precision"])
        bucket["symbol_recall"].append(project["symbols"]["recall"])
        bucket["relation_precision"].append(project["relations"]["precision"])
        bucket["relation_recall"].append(project["relations"]["recall"])
        bucket["relation_candidate_precision"].append(project["relation_candidates"]["precision"])
        bucket["relation_candidate_recall"].append(project["relation_candidates"]["recall"])
    for bucket in grouped.values():
        for key in ("symbol_precision", "symbol_recall", "relation_precision", "relation_recall", "relation_candidate_precision", "relation_candidate_recall"):
            values = bucket[key]
            bucket[key] = sum(values) / len(values) if values else 0.0
    oracle_provenance = str(manifest.get("provenance") or "owned_synthetic_generated_with_source; não independente do gerador")
    return {"schema": SCHEMA, "status": "invalid" if errors else "complete", "manifest": str(manifest_path), "projects": projects, "groups": grouped, "errors": errors, "oracle_provenance": oracle_provenance, "limitations": ["relation_precision/recall usam somente arestas calls resolvidas para função local única", "relation_candidate_* preserva chamadas não resolvidas e ruído externo para auditoria", "scores medem leitor de fonte, não binário nem comportamento", "proveniência declarada precisa de auditoria independente; não é autenticidade automática", "médias por projeto não substituem IC/holdout independente", "nenhum build ou alvo foi executado"]}


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_file(root: Path, relative: object) -> Path | None:
    """Resolve a manifest-relative regular file without following links."""
    return _safe_path(root, relative)


def evaluate_corpus_binaries(
    manifest_path: Path,
    build_report_path: Path,
    *,
    measure_relations: bool = False,
    dia_helper: Path | None = None,
    dia_dll: Path | None = None,
    pdb_timeout: float = 90.0,
    pdb_max_symbols: int = 50_000,
) -> dict[str, Any]:
    """Evaluate statically-built C fixtures against the declared oracle.

    The build worker must have been invoked explicitly beforehand. This
    evaluator verifies output hashes, reads ELF/DWARF metadata and never loads
    or executes a generated binary. Direct local-call measurement is opt-in;
    relation/behavioral equivalence otherwise remains explicitly unmeasured.
    """
    manifest_path = manifest_path.resolve()
    build_report_path = build_report_path.resolve()
    root = manifest_path.parent
    pdb_requested = dia_helper is not None or dia_dll is not None
    if pdb_requested and (dia_helper is None or dia_dll is None):
        return {"schema": "corpus-binary-evaluation.v1", "status": "invalid", "manifest": str(manifest_path), "build_report": str(build_report_path), "projects": [], "errors": [{"code": "pdb_dia_configuration_incomplete", "detail": "dia_helper_and_dia_dll_required_together"}], "executed_targets": False, "pdb_reader": {"status": "invalid"}}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        build_report = json.loads(build_report_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {"schema": "corpus-binary-evaluation.v1", "status": "invalid", "manifest": str(manifest_path), "build_report": str(build_report_path), "projects": [], "errors": [{"code": "input_unreadable", "detail": type(exc).__name__}], "executed_targets": False}
    if not isinstance(manifest, dict) or not isinstance(manifest.get("projects"), list):
        return {"schema": "corpus-binary-evaluation.v1", "status": "invalid", "manifest": str(manifest_path), "build_report": str(build_report_path), "projects": [], "errors": [{"code": "manifest_invalid", "detail": "projects_list_required"}], "executed_targets": False}
    # A repeated manifest ID would score the same physical artifact twice and
    # inflate apparent sample size, even if build results themselves are
    # unique. Reject it before reading any binary.
    errors: list[dict[str, Any]] = []
    seen_manifest_ids: set[str] = set()
    duplicate_manifest_ids: set[str] = set()
    for item in manifest["projects"]:
        if not isinstance(item, dict) or item.get("language") != "c":
            continue
        project_id = str(item.get("id", "<missing>"))
        artifact_errors = validate_auxiliary_artifacts(item, root, project_id)
        if artifact_errors:
            errors.extend(artifact_errors)
            continue
        if project_id in seen_manifest_ids:
            duplicate_manifest_ids.add(project_id)
        seen_manifest_ids.add(project_id)
    if duplicate_manifest_ids:
        return {"schema": "corpus-binary-evaluation.v1", "status": "invalid", "manifest": str(manifest_path), "build_report": str(build_report_path), "projects": [], "errors": [{"code": "duplicate_manifest_project_id", "id": project_id} for project_id in sorted(duplicate_manifest_ids)], "executed_targets": False}
    if errors:
        return {"schema": "corpus-binary-evaluation.v1", "status": "invalid", "manifest": str(manifest_path), "build_report": str(build_report_path), "projects": [], "errors": errors, "executed_targets": False}
    if not isinstance(build_report, dict) or build_report.get("schema") != "corpus-native-build.v1":
        return {"schema": "corpus-binary-evaluation.v1", "status": "invalid", "manifest": str(manifest_path), "build_report": str(build_report_path), "projects": [], "errors": [{"code": "build_report_invalid", "detail": "corpus-native-build.v1_required"}], "executed_targets": False}
    declared_manifest_hash = build_report.get("manifest_sha256")
    if not declared_manifest_hash:
        return {"schema": "corpus-binary-evaluation.v1", "status": "invalid", "manifest": str(manifest_path), "build_report": str(build_report_path), "projects": [], "errors": [{"code": "manifest_provenance_missing"}], "executed_targets": False}
    if _file_sha256(manifest_path) != str(declared_manifest_hash):
        return {"schema": "corpus-binary-evaluation.v1", "status": "invalid", "manifest": str(manifest_path), "build_report": str(build_report_path), "projects": [], "errors": [{"code": "manifest_hash_mismatch"}], "executed_targets": False}
    output_root_raw = Path(str(build_report.get("output_dir") or ""))
    if not str(build_report.get("output_dir") or "") or not output_root_raw.is_absolute() or output_root_raw.is_symlink():
        return {"schema": "corpus-binary-evaluation.v1", "status": "invalid", "manifest": str(manifest_path), "build_report": str(build_report_path), "projects": [], "errors": [{"code": "output_root_invalid"}], "executed_targets": False}
    output_root = output_root_raw.resolve()
    if not output_root.is_dir():
        return {"schema": "corpus-binary-evaluation.v1", "status": "invalid", "manifest": str(manifest_path), "build_report": str(build_report_path), "projects": [], "errors": [{"code": "output_root_invalid"}], "executed_targets": False}
    raw_results = build_report.get("results")
    if not isinstance(raw_results, list):
        return {"schema": "corpus-binary-evaluation.v1", "status": "invalid", "manifest": str(manifest_path), "build_report": str(build_report_path), "projects": [], "errors": [{"code": "build_results_invalid", "detail": "results_list_required"}], "executed_targets": False}
    duplicate_results = []
    result_ids: set[str] = set()
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        result_id = str(item.get("id", "<missing>"))
        if result_id in result_ids:
            duplicate_results.append(result_id)
        result_ids.add(result_id)
    if duplicate_results:
        return {"schema": "corpus-binary-evaluation.v1", "status": "invalid", "manifest": str(manifest_path), "build_report": str(build_report_path), "projects": [], "errors": [{"code": "duplicate_build_result_id", "id": item} for item in sorted(set(duplicate_results))], "executed_targets": False}
    by_id = {str(item.get("id")): item for item in raw_results if isinstance(item, dict)}
    projects: list[dict[str, Any]] = []
    for item in manifest["projects"]:
        if not isinstance(item, dict) or item.get("language") != "c":
            continue
        project_id = str(item.get("id", "<missing>"))
        source_path = _safe_file(root, item.get("source"))
        oracle_path = _safe_file(root, item.get("oracle"))
        try:
            if source_path is None or not source_path.is_file():
                raise ValueError("source_invalid")
            if oracle_path is None or not oracle_path.is_file():
                raise ValueError("oracle_invalid")
            oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
        except (ValueError, FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            code = str(exc) if str(exc) in {"source_invalid", "oracle_invalid"} else "oracle_invalid"
            errors.append({"code": code, "id": project_id, "detail": type(exc).__name__})
            continue
        declared_oracle_hash = item.get("oracle_sha256")
        if declared_oracle_hash and _file_sha256(oracle_path) != str(declared_oracle_hash):
            errors.append({"code": "oracle_hash_mismatch", "id": project_id})
            continue
        build = by_id.get(project_id)
        if not build or build.get("status") != "succeeded":
            errors.append({"code": "binary_unavailable", "id": project_id, "detail": str((build or {}).get("status", "missing"))})
            continue
        declared_kind = item.get("build_kind", "executable")
        observed_kind = build.get("build_kind", "executable")
        if declared_kind not in {"executable", "shared_library"} or observed_kind != declared_kind:
            errors.append({"code": "build_kind_mismatch", "id": project_id, "declared": declared_kind, "observed": observed_kind})
            continue
        output_raw = Path(str(build.get("output", "")))
        if not str(build.get("output", "")) or not output_raw.is_absolute() or output_raw.is_symlink():
            errors.append({"code": "binary_path_invalid", "id": project_id})
            continue
        output = output_raw.resolve()
        try:
            output.relative_to(output_root)
        except ValueError:
            errors.append({"code": "binary_path_escape", "id": project_id})
            continue
        if not output.is_file() or output.is_symlink():
            errors.append({"code": "binary_missing", "id": project_id})
            continue
        digest = _file_sha256(output)
        if digest != str(build.get("output_sha256", "")):
            errors.append({"code": "binary_hash_mismatch", "id": project_id})
            continue
        declared_source_hash = build.get("source_sha256")
        if not declared_source_hash:
            errors.append({"code": "source_provenance_missing", "id": project_id})
            continue
        actual_source_hash = _file_sha256(source_path)
        if actual_source_hash != str(declared_source_hash):
            errors.append({"code": "source_hash_mismatch", "id": project_id})
            continue
        manifest_source_hash = item.get("source_sha256")
        if manifest_source_hash and actual_source_hash != str(manifest_source_hash):
            errors.append({"code": "manifest_source_hash_mismatch", "id": project_id})
            continue
        pdb_report: dict[str, Any] = {"status": "not_requested", "count": 0, "symbols": [], "executed_target": False}
        if pdb_requested:
            pdb_raw = Path(str(build.get("pdb") or output.with_suffix(".pdb")))
            if not pdb_raw.is_absolute() or pdb_raw.is_symlink():
                errors.append({"code": "pdb_path_invalid", "id": project_id})
                continue
            pdb_path = pdb_raw.resolve()
            try:
                pdb_path.relative_to(output_root)
            except ValueError:
                errors.append({"code": "pdb_path_escape", "id": project_id})
                continue
            declared_pdb_hash = str(build.get("pdb_sha256") or "")
            if not pdb_path.is_file() or pdb_path.is_symlink():
                pdb_report = {"status": "unavailable", "code": "pdb_missing", "pdb": str(pdb_path), "count": 0, "symbols": [], "executed_target": False}
                errors.append({"code": "pdb_missing", "id": project_id})
                continue
            actual_pdb_hash = _file_sha256(pdb_path)
            if declared_pdb_hash and actual_pdb_hash != declared_pdb_hash:
                errors.append({"code": "pdb_hash_mismatch", "id": project_id})
                continue
            pdb_report = extract_pdb_symbols(pdb_path, helper_path=Path(dia_helper), dia_dll=Path(dia_dll), timeout=pdb_timeout, max_symbols=pdb_max_symbols)
            if pdb_report.get("status") != "complete":
                errors.append({"code": "pdb_reader_failed", "id": project_id, "detail": pdb_report.get("code", "unknown")})
                continue
        raw = output.read_bytes()
        structure = run_structure(raw)
        codeview = parse_pe_codeview(raw) if str(structure.get("format", "")).upper().startswith("PE") else {"schema": "re-megazord-pe-codeview.v1", "status": "not_applicable", "records": []}
        pdb_binding: dict[str, Any] = {"status": "not_requested", "codeview_records": len(codeview.get("records", [])), "executed_target": False}
        if pdb_requested and pdb_report.get("status") == "complete":
            records = codeview.get("records", []) if codeview.get("status") == "complete" else []
            pdb_guid = str(pdb_report.get("guid") or "").upper()
            pdb_age = int(pdb_report.get("age") or 0)
            name_match = False
            guid_match = False
            age_match = False
            for record in records:
                if not isinstance(record, dict):
                    continue
                guid_match = guid_match or str(record.get("guid") or "").upper() == pdb_guid and bool(pdb_guid)
                age_match = age_match or int(record.get("age") or 0) == pdb_age
                record_name = Path(str(record.get("pdb_name") or "")).name.lower()
                name_match = name_match or record_name == pdb_path.name.lower()
            if guid_match and age_match and name_match:
                binding_status = "matched"
            else:
                binding_status = "mismatch"
                errors.append({"code": "pdb_codeview_binding_mismatch", "id": project_id, "guid_match": guid_match, "age_match": age_match, "name_match": name_match})
            pdb_binding = {"status": binding_status, "codeview_records": len(records), "guid_match": guid_match, "age_match": age_match, "name_match": name_match, "pdb_guid": pdb_guid, "pdb_age": pdb_age, "executed_target": False}
        dwarf = analyze_dwarf(output) if str(structure.get("format", "")).upper().startswith("ELF") else {"status": "not_applicable", "executed": False}
        structural_names = _candidate_function_names(structure)
        dwarf_names = {_leaf(value.get("name")) for value in dwarf.get("functions", []) if isinstance(value, dict)}
        # Prefer debug-function observations for the primary metric when
        # present; dynamic/CRT symbols remain visible as a noisy companion.
        observed_names = dwarf_names or structural_names
        expected_names = {_leaf(value) for value in oracle.get("expected_symbols", []) if isinstance(value, str)}
        expected_relations = {_relation_key(value[0], value[1]) for value in oracle.get("expected_relations", []) if isinstance(value, list) and len(value) == 2}
        pdb_names = {_leaf(value.get("name")) for value in pdb_report.get("symbols", []) if isinstance(value, dict) and isinstance(value.get("name"), str)}
        pdb_score = ({"status": "complete", **_scores(expected_names, pdb_names)} if pdb_report.get("status") == "complete" else {"status": pdb_report.get("status", "not_requested"), "expected": len(expected_names), "observed": 0})
        pdb_capabilities = set(pdb_report.get("capabilities", [])) if isinstance(pdb_report.get("capabilities"), list) else set()
        source_scope_available = {"source_file", "is_static"}.issubset(pdb_capabilities)
        primary_pdb_names = _pdb_function_names_for_sources(pdb_report, [str(item.get("source") or "")], external_only=True) if source_scope_available else set()
        primary_pdb_score = ({"status": "complete", "scope": "dia_source_file_matches_manifest_primary_source_and_is_static_false", **_scores(expected_names, primary_pdb_names)} if pdb_report.get("status") == "complete" and source_scope_available else {"status": "not_measured" if pdb_report.get("status") == "complete" else pdb_report.get("status", "not_requested"), "reason": "dia_source_and_static_capabilities_required" if pdb_report.get("status") == "complete" else "pdb_unavailable", "expected": len(expected_names), "observed": 0})
        relation_observation = recover_direct_calls(raw, structure) if measure_relations else {"status": "not_measured", "reason": "opt_in_required", "executed": False}
        if relation_observation.get("status") == "measured":
            relations = _measured_relation_scores(expected_relations, relation_observation)
        else:
            relations = {"status": "not_measured", "expected": len(expected_relations), "reason": relation_observation.get("reason", "static structural evaluator does not infer call equivalence"), "method": relation_observation.get("method"), "ambiguous_calls": relation_observation.get("ambiguous_calls", 0), "executed": False}
        projects.append({"id": project_id, "family": item.get("family"), "language": "c", "split": item.get("split"), "build_kind": declared_kind, "binary": str(output), "binary_sha256": digest, "format": structure.get("format"), "architecture": structure.get("machine_name", "unknown"), "symbols": _scores(expected_names, observed_names), "symbol_candidates": _scores(expected_names, structural_names), "pdb": pdb_report, "pdb_symbols": pdb_score, "pdb_primary_source_symbols": primary_pdb_score, "pdb_binding": pdb_binding, "codeview": codeview, "relations": relations, "dwarf": dwarf, "executed": False})
    grouped: dict[str, dict[str, Any]] = {}
    for project in projects:
        key = f"{project['split']}:{project['language']}"
        grouped.setdefault(key, {"projects": 0, "symbol_precision": [], "symbol_recall": [], "symbol_candidate_precision": [], "symbol_candidate_recall": [], "pdb_symbol_precision": [], "pdb_symbol_recall": [], "pdb_primary_source_precision": [], "pdb_primary_source_recall": [], "pdb_projects": 0, "relations": "not_measured"})
        bucket = grouped[key]
        bucket["projects"] += 1
        bucket["symbol_precision"].append(project["symbols"]["precision"])
        bucket["symbol_recall"].append(project["symbols"]["recall"])
        bucket["symbol_candidate_precision"].append(project["symbol_candidates"]["precision"])
        bucket["symbol_candidate_recall"].append(project["symbol_candidates"]["recall"])
        if project["pdb_symbols"].get("status") == "complete":
            bucket["pdb_projects"] += 1
            bucket["pdb_symbol_precision"].append(project["pdb_symbols"]["precision"])
            bucket["pdb_symbol_recall"].append(project["pdb_symbols"]["recall"])
            if project["pdb_primary_source_symbols"].get("status") == "complete":
                bucket["pdb_primary_source_precision"].append(project["pdb_primary_source_symbols"]["precision"])
                bucket["pdb_primary_source_recall"].append(project["pdb_primary_source_symbols"]["recall"])
        if project["relations"].get("status") == "measured":
            bucket.setdefault("relation_precision", []).append(project["relations"]["precision"])
            bucket.setdefault("relation_recall", []).append(project["relations"]["recall"])
            bucket["relations"] = "measured"
    for bucket in grouped.values():
        bucket["symbol_precision"] = sum(bucket["symbol_precision"]) / len(bucket["symbol_precision"]) if bucket["symbol_precision"] else 0.0
        bucket["symbol_recall"] = sum(bucket["symbol_recall"]) / len(bucket["symbol_recall"]) if bucket["symbol_recall"] else 0.0
        bucket["symbol_candidate_precision"] = sum(bucket["symbol_candidate_precision"]) / len(bucket["symbol_candidate_precision"]) if bucket["symbol_candidate_precision"] else 0.0
        bucket["symbol_candidate_recall"] = sum(bucket["symbol_candidate_recall"]) / len(bucket["symbol_candidate_recall"]) if bucket["symbol_candidate_recall"] else 0.0
        bucket["pdb_symbol_precision"] = sum(bucket["pdb_symbol_precision"]) / len(bucket["pdb_symbol_precision"]) if bucket["pdb_symbol_precision"] else 0.0
        bucket["pdb_symbol_recall"] = sum(bucket["pdb_symbol_recall"]) / len(bucket["pdb_symbol_recall"]) if bucket["pdb_symbol_recall"] else 0.0
        bucket["pdb_primary_source_precision"] = sum(bucket["pdb_primary_source_precision"]) / len(bucket["pdb_primary_source_precision"]) if bucket["pdb_primary_source_precision"] else 0.0
        bucket["pdb_primary_source_recall"] = sum(bucket["pdb_primary_source_recall"]) / len(bucket["pdb_primary_source_recall"]) if bucket["pdb_primary_source_recall"] else 0.0
        if "relation_precision" in bucket:
            bucket["relation_precision"] = sum(bucket["relation_precision"]) / len(bucket["relation_precision"]) if bucket["relation_precision"] else 0.0
            bucket["relation_recall"] = sum(bucket["relation_recall"]) / len(bucket["relation_recall"]) if bucket["relation_recall"] else 0.0
    limitations = ["símbolos/DWARF/PDB confirmam observações de nomes, não equivalência semântica", "compiler/build foi executado somente no worker explícito; evaluator não executa binários", "médias sintéticas não substituem corpus independente ou IC"]
    if measure_relations:
        limitations.append("calls medidos somente quando Capstone e símbolos locais permitem atribuição; indiretos/PLT/inlining permanecem não resolvidos")
    else:
        limitations.append("relações de chamada e comportamento não medidos")
    oracle_provenance = str(manifest.get("provenance") or "owned_synthetic_generated_with_source; não independente do gerador")
    limitations.append("proveniência declarada no manifesto não comprova autoria independente")
    if pdb_requested:
        limitations.append("PDB foi lido por helper DIA explícito e vinculado ao CodeView RSDS quando possível; pdb_symbols preserva todo o ruído bruto, enquanto pdb_primary_source_symbols filtra apenas pela proveniência source_file do DIA, nunca pelo oracle")
    else:
        limitations.append("PDB/DIA não solicitado; symbols=0/unknown no parser estrutural PE não significam ausência de símbolos")
    return {"schema": "corpus-binary-evaluation.v1", "status": "complete" if projects and not errors else "partial" if projects else "invalid", "manifest": str(manifest_path), "manifest_sha256": str(declared_manifest_hash), "build_report": str(build_report_path), "projects": projects, "groups": grouped, "errors": errors, "oracle_provenance": oracle_provenance, "executed_targets": False, "measure_relations": measure_relations, "pdb_reader": {"status": "enabled" if pdb_requested else "not_requested", "helper": str(dia_helper) if dia_helper else "", "dia_dll": str(dia_dll) if dia_dll else ""}, "limitations": limitations}


def write_corpus_evaluation(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
