"""Orquestra inventário, fonte e build em uma única leitura estática."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aether_re.build_audit import audit_build
from aether_re.c_source import analyze_c_family_project
from aether_re.dependency_audit import audit_python_dependencies
from aether_re.project_inventory import inventory_project
from aether_re.project_dependencies import audit_project_dependencies
from aether_re.risk_audit import audit_source_risks
from aether_re.source import analyze_python_project
from aether_re.documentation import audit_documentation
from aether_re.evidence import _path_has_link
from aether_re.language_profiles import analyze_language_profiles


SCHEMA = "project-audit.v1"


def analyze_project(root: Path) -> dict[str, Any]:
    """Return a static project map; adapters/builders are never invoked."""
    try:
        root = Path(root)
        if _path_has_link(root):
            return {"schema": SCHEMA, "status": "invalid", "root": str(root), "inventory": {}, "source": {}, "build": {}, "dependencies": {}, "documentation": {}, "errors": [{"code": "root_symlink_not_allowed"}], "limitations": ["raiz symlink não autorizada", "orquestração estática; nenhum import, build, instalador ou alvo foi executado"]}
        root = root.resolve()
    except (TypeError, ValueError, OSError, RuntimeError) as exc:
        return {
            "schema": SCHEMA,
            "status": "invalid",
            "root": repr(root),
            "inventory": {},
            "source": {},
            "build": {},
            "dependencies": {},
            "documentation": {},
            "errors": [{"code": "root_invalid", "detail": type(exc).__name__}],
            "limitations": ["raiz inválida", "orquestração estática; nenhum import, build, instalador ou alvo foi executado"],
        }
    try:
        inventory = inventory_project(root)
    except Exception as exc:
        inventory = {"status": "invalid", "root": str(root), "errors": [{"code": "inventory_error", "detail": type(exc).__name__}]}
    if inventory.get("status") == "invalid":
        inventory_errors = inventory.get("errors") or inventory.get("issues") or [{"code": "inventory_invalid"}]
        return {"schema": SCHEMA, "status": "invalid", "root": str(root), "inventory": inventory, "source": {}, "build": {}, "dependencies": {}, "documentation": {}, "errors": inventory_errors, "limitations": ["raiz inválida", "orquestração estática; nenhum import, build, instalador ou alvo foi executado"]}
    language_counts = inventory.get("summary", {}).get("languages", {})
    errors: list[dict[str, Any]] = []
    if not isinstance(language_counts, dict):
        errors.append({"code": "inventory_summary_invalid", "detail": "languages_map_required"})
        language_counts = {}
    source: dict[str, Any] = {}
    analyzed_languages: set[str] = set()
    if language_counts.get("python"):
        try:
            python_report = analyze_python_project(root)
        except Exception as exc:
            python_report = {"modules": [], "functions": [], "calls": [], "errors": [{"kind": "source_analysis_error", "detail": type(exc).__name__}]}
            errors.append({"code": "python_source_analysis_error", "detail": type(exc).__name__})
        if isinstance(python_report, dict) and (python_report.get("modules") or python_report.get("errors")):
            source["python"] = python_report
            analyzed_languages.add("python")
            try:
                source["python_dependencies"] = audit_python_dependencies(root, source_report=python_report)
            except Exception as exc:
                source["python_dependencies"] = {"status": "invalid", "errors": [{"code": "dependency_analysis_error", "detail": type(exc).__name__}], "summary": {}}
                errors.append({"code": "python_dependency_analysis_error", "detail": type(exc).__name__})
            source["python_risks"] = audit_source_risks(source["python"])
    if any(language_counts.get(name) for name in ("c", "c-header", "cpp", "cpp-header")):
        try:
            c_report = analyze_c_family_project(root)
        except Exception as exc:
            c_report = {"modules": [], "functions": [], "calls": [], "errors": [{"kind": "c_source_analysis_error", "detail": type(exc).__name__}]}
            errors.append({"code": "c_source_analysis_error", "detail": type(exc).__name__})
        if isinstance(c_report, dict) and (c_report.get("modules") or c_report.get("errors")):
            source["c_family"] = c_report
            analyzed_languages.update(str(item.get("language")) for item in c_report.get("modules", []))
    if any(language_counts.get(name) for name in ("go", "javascript", "typescript")):
        try:
            profile_report = analyze_language_profiles(root)
        except Exception as exc:
            profile_report = {"profiles": {}, "errors": [{"kind": "language_profile_error", "detail": type(exc).__name__}], "status": "invalid"}
            errors.append({"code": "language_profile_analysis_error", "detail": type(exc).__name__})
        if isinstance(profile_report, dict) and (profile_report.get("profiles") or profile_report.get("errors")):
            source["language_profiles"] = profile_report
            analyzed_languages.update(str(name) for name in profile_report.get("profiles", {}))
    inventory_languages = set(str(item) for item in language_counts)
    excluded_languages = sorted(inventory_languages - analyzed_languages)
    try:
        build = audit_build(root)
    except Exception as exc:
        build = {"status": "invalid", "errors": [{"code": "build_audit_error", "detail": type(exc).__name__}]}
        errors.append({"code": "build_audit_error", "detail": type(exc).__name__})
    try:
        dependencies = audit_project_dependencies(root)
    except Exception as exc:
        dependencies = {"status": "invalid", "errors": [{"code": "dependency_audit_error", "detail": type(exc).__name__}]}
        errors.append({"code": "dependency_audit_error", "detail": type(exc).__name__})
    try:
        documentation = audit_documentation(root)
    except Exception as exc:
        documentation = {"status": "invalid", "errors": [{"code": "documentation_audit_error", "detail": type(exc).__name__}], "summary": {}}
        errors.append({"code": "documentation_audit_error", "detail": type(exc).__name__})
    skipped_inventory = inventory.get("skipped", [])
    skipped_count = len(skipped_inventory) if isinstance(skipped_inventory, list) else 0
    nested_partial = inventory.get("status") != "complete" or skipped_count > 0 or build.get("status") not in {"observed", "not_found"} or dependencies.get("status") not in {"observed", "not_found"} or documentation.get("status") not in {"complete", "not_found"} or bool(excluded_languages)
    for report in source.values():
        if isinstance(report, dict) and (report.get("errors") or report.get("status") in {"invalid", "partial"}):
            nested_partial = True
    # Two observations detect ordinary edits during a multi-reader audit.
    # This is not an immutable snapshot: a file can change and change back,
    # and excluded paths are outside the digest's scope.
    try:
        post_inventory = inventory_project(root)
        post_digest = post_inventory.get("root_digest")
        same_skips = post_inventory.get("skipped") == inventory.get("skipped")
        consistency = "stable_observed" if post_digest == inventory.get("root_digest") and same_skips and post_inventory.get("status") != "invalid" else "changed_during_analysis"
    except Exception as exc:
        post_digest = None
        consistency = "unverified"
        errors.append({"code": "post_inventory_error", "detail": type(exc).__name__})
    if consistency != "stable_observed":
        nested_partial = True
    status = "invalid" if errors else "partial" if nested_partial or not source else "complete"
    limitations = [
        "orquestração estática; nenhum import, build, instalador ou alvo foi executado",
        "componentes ausentes ou excluídos pelo budget permanecem fora do escopo",
        "classificações e correlações não equivalem a compreensão semântica completa",
        "duas leituras de inventário não constituem snapshot imutável nem detectam mudança e reversão entre leituras",
    ]
    return {
        "schema": SCHEMA,
        "status": status,
        "root": str(root),
        "root_digest": inventory.get("root_digest"),
        "post_root_digest": post_digest,
        "consistency": consistency,
        "inventory": inventory,
        "source": source,
        "build": build,
        "dependencies": dependencies,
        "documentation": documentation,
        "errors": errors,
        "scope": {"inventory_languages": sorted(inventory_languages), "analyzed_languages": sorted(analyzed_languages), "excluded_languages": excluded_languages, "skipped_inventory_paths": skipped_count, "full_project_covered": not nested_partial and not errors, "exclusion_reason": "diretório fora do escopo estático ou sem parser habilitado"},
        "summary": {
            "languages": sorted(analyzed_languages),
            "modules": sum(len(report.get("modules", [])) for report in source.values() if isinstance(report, dict)),
            "functions": sum(len(report.get("functions", [])) for report in source.values() if isinstance(report, dict)),
            "risk_indicators": len(source.get("python_risks", {}).get("indicators", [])),
        },
        "limitations": limitations,
    }


def write_project_audit(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
