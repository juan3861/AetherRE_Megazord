"""Inventário estático de dependências declaradas versus imports observados."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from aether_re.source import analyze_python_project


_REQ_NAME = re.compile(r"^[A-Za-z0-9_.-]+")


def _norm(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _requirements(root: Path, errors: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for filename in ("requirements.txt", "requirements-dev.txt"):
        path = root / filename
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, UnicodeError) as exc:
            if errors is not None:
                errors.append({"code": "requirements_read_error", "file": filename, "detail": type(exc).__name__})
            continue
        for line_no, raw in enumerate(lines, 1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "git+", "http:" , "https:")):
                continue
            match = _REQ_NAME.match(line)
            if match:
                entries.append({"name": match.group(0), "file": filename, "line": str(line_no), "spec": line})
    return entries


def audit_python_dependencies(root: Path, *, source_report: dict[str, Any] | None = None) -> dict[str, Any]:
    schema = "python-dependency-audit.v1"
    errors: list[dict[str, Any]] = []
    try:
        root = Path(root).resolve()
    except (TypeError, ValueError, OSError, RuntimeError) as exc:
        return {"schema": schema, "status": "invalid", "root": repr(root), "requirements_files": [], "dependencies": [], "errors": [{"code": "root_invalid", "detail": type(exc).__name__}], "summary": {"declared": 0, "imported": 0, "declared_not_observed": 0, "import_not_declared": 0}, "limitations": ["presença de import não prova execução/alcançabilidade", "nomes de distribuição podem diferir do módulo importado", "requirements dinâmicos/pyproject ainda não são resolvidos"]}
    try:
        root_exists = root.is_dir()
    except (OSError, RuntimeError):
        root_exists = False
    if not root_exists:
        return {"schema": schema, "status": "invalid", "root": str(root), "requirements_files": [], "dependencies": [], "errors": [{"code": "root_missing", "detail": "directory_required"}], "summary": {"declared": 0, "imported": 0, "declared_not_observed": 0, "import_not_declared": 0}, "limitations": ["presença de import não prova execução/alcançabilidade", "nomes de distribuição podem diferir do módulo importado", "requirements dinâmicos/pyproject ainda não são resolvidos"]}
    if source_report is None:
        try:
            source = analyze_python_project(root)
        except Exception as exc:
            source = {"modules": [], "imports": [], "errors": [{"kind": "source_analysis_error", "detail": type(exc).__name__}]}
            errors.append({"code": "source_analysis_error", "detail": type(exc).__name__})
    else:
        source = source_report
        if not isinstance(source, dict) or source.get("root") != str(root):
            errors.append({"code": "source_report_root_mismatch"})
            source = {"modules": [], "imports": [], "errors": [{"kind": "source_report_root_mismatch"}]}
    if not isinstance(source, dict):
        source = {"modules": [], "imports": [], "errors": [{"kind": "source_report_invalid"}]}
        errors.append({"code": "source_report_invalid"})
    declared = _requirements(root, errors)
    declared_map = {_norm(item["name"]): item for item in declared}
    modules = source.get("modules", [])
    imports = source.get("imports", [])
    if not isinstance(modules, list) or not isinstance(imports, list):
        errors.append({"code": "source_report_shape_invalid"})
        modules = modules if isinstance(modules, list) else []
        imports = imports if isinstance(imports, list) else []
    local_modules = {_norm(item["module"].split(".", 1)[0]) for item in modules if isinstance(item, dict) and isinstance(item.get("module"), str)}
    stdlib = {_norm(name) for name in getattr(sys, "stdlib_module_names", set())}
    observed: dict[str, list[dict[str, Any]]] = {}
    for item in imports:
        if not isinstance(item, dict):
            errors.append({"code": "import_record_invalid"})
            continue
        module = str(item.get("module", ""))
        top = module.lstrip(".").split(".", 1)[0]
        if not top:
            continue
        observed.setdefault(_norm(top), []).append(item)
    names = sorted(set(declared_map) | set(observed))
    rows: list[dict[str, Any]] = []
    for name in names:
        is_stdlib = name in stdlib
        is_local = name in local_modules
        rows.append({
            "normalized": name,
            "declared": name in declared_map,
            "declaration": declared_map.get(name),
            "imported": name in observed,
            "imports": observed.get(name, []),
            "stdlib": is_stdlib,
            "local": is_local,
            "state": "declared_and_imported" if name in declared_map and name in observed else "declared_not_observed" if name in declared_map else "import_not_declared",
        })
    source_errors = source.get("errors", [])
    if not isinstance(source_errors, list):
        errors.append({"code": "source_errors_shape_invalid"})
        source_errors = []
    return {
        "schema": schema,
        "status": "invalid" if errors else "partial" if source_errors else "complete",
        "root": str(root),
        "requirements_files": sorted({item["file"] for item in declared}),
        "dependencies": rows,
        "errors": errors,
        "summary": {
            "declared": len(declared),
            "imported": sum(1 for name in observed if name not in stdlib and name not in local_modules),
            "declared_not_observed": sum(1 for row in rows if row["state"] == "declared_not_observed"),
            "import_not_declared": sum(1 for row in rows if row["state"] == "import_not_declared" and not row["stdlib"] and not row["local"]),
        },
        "limitations": ["presença de import não prova execução/alcançabilidade", "nomes de distribuição podem diferir do módulo importado", "requirements dinâmicos/pyproject ainda não são resolvidos"],
    }


def write_dependency_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
