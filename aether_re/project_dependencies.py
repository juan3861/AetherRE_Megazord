"""Inventário multi-ecossistema de dependências declaradas e observadas."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from aether_re.safe_walk import iter_files_pruned

try:
    import tomllib
except ImportError:  # pragma: no cover - Python 3.10 fallback explícito
    tomllib = None  # type: ignore[assignment]


SCHEMA = "project-dependency-audit.v1"
EXCLUDED_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "vendor", "third_party", "tools", "output", "build", "dist", "target", "corpus", "samples"}
REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(.*)$")
GO_REQUIRE_RE = re.compile(r"^\s*([^\s]+)\s+([^\s]+)")
PY_IMPORT_RE = re.compile(r"^\s*(?:from\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)|import\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*))")
JS_IMPORT_RE = re.compile(r"(?:from\s*[\"']([^\"']+)[\"']|require\(\s*[\"']([^\"']+)[\"']\s*\))")
GO_IMPORT_RE = re.compile(r"^\s*[\"']([^\"']+)[\"']\s*$")
C_INCLUDE_RE = re.compile(r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]")


def _top(name: str) -> str:
    value = name.strip().split("/", 1)[0]
    return value.split(".", 1)[0] if value else value


def _read_toml(path: Path, errors: list[dict[str, str]]) -> dict[str, Any]:
    if tomllib is None:
        errors.append({"code": "toml_parser_missing", "path": path.name})
        return {}
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, UnicodeError, ValueError) as exc:
        errors.append({"code": "manifest_parse_error", "path": path.name, "detail": type(exc).__name__})
        return {}
    return value if isinstance(value, dict) else {}


def audit_project_dependencies(root: Path) -> dict[str, Any]:
    try:
        root = Path(root).resolve()
    except (TypeError, ValueError, OSError, RuntimeError) as exc:
        return {
            "schema": SCHEMA,
            "status": "invalid",
            "root": repr(root),
            "declared": [],
            "observed": [],
            "dependencies": [],
            "errors": [{"code": "root_invalid", "detail": type(exc).__name__}],
            "limitations": ["não executa código"],
        }
    declared: list[dict[str, Any]] = []
    observed: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    files: list[str] = []
    try:
        root_exists = root.is_dir()
    except (OSError, RuntimeError):
        root_exists = False
    if not root_exists:
        return {"schema": SCHEMA, "status": "invalid", "root": str(root), "declared": [], "observed": [], "dependencies": [], "errors": [{"code": "root_missing"}], "limitations": ["não executa código"]}

    def add_declared(ecosystem: str, name: str, spec: Any, path: Path, section: str = "") -> None:
        if not name:
            return
        declared.append({"ecosystem": ecosystem, "name": name, "normalized": _top(name).lower().replace("-", "_"), "spec": str(spec), "path": path.relative_to(root).as_posix(), "section": section, "confidence": "declared"})

    req_files = sorted(path for path in root.glob("requirements*.txt") if path.is_file())
    for path in req_files:
        files.append(path.relative_to(root).as_posix())
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, UnicodeError) as exc:
            errors.append({"code": "manifest_read_error", "path": path.relative_to(root).as_posix(), "detail": type(exc).__name__})
            continue
        for line_no, raw in enumerate(lines, 1):
            text = raw.split("#", 1)[0].strip()
            if not text or text.startswith(("-", "git+", "http:", "https:")):
                continue
            match = REQ_RE.match(text)
            if match:
                add_declared("python", match.group(1), match.group(2), path, f"line:{line_no}")
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        files.append("pyproject.toml")
        data = _read_toml(pyproject, errors)
        project = data.get("project", {}) if isinstance(data.get("project"), dict) else {}
        for spec in project.get("dependencies", []) if isinstance(project.get("dependencies"), list) else []:
            match = REQ_RE.match(str(spec))
            if match:
                add_declared("python", match.group(1), match.group(2), pyproject, "project.dependencies")
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for section, values in optional.items():
                for spec in values if isinstance(values, list) else []:
                    match = REQ_RE.match(str(spec))
                    if match:
                        add_declared("python", match.group(1), match.group(2), pyproject, f"optional:{section}")
    package = root / "package.json"
    if package.is_file():
        files.append("package.json")
        try:
            data = json.loads(package.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            errors.append({"code": "manifest_parse_error", "path": "package.json", "detail": type(exc).__name__})
            data = {}
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            values = data.get(section, {}) if isinstance(data, dict) else {}
            for name, spec in values.items() if isinstance(values, dict) else []:
                add_declared("node", str(name), spec, package, section)
    cargo = root / "Cargo.toml"
    if cargo.is_file():
        files.append("Cargo.toml")
        data = _read_toml(cargo, errors)
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            values = data.get(section, {})
            for name, spec in values.items() if isinstance(values, dict) else []:
                add_declared("rust", str(name), spec, cargo, section)
    gomod = root / "go.mod"
    if gomod.is_file():
        files.append("go.mod")
        in_block = False
        try:
            go_lines = gomod.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, UnicodeError) as exc:
            errors.append({"code": "manifest_read_error", "path": "go.mod", "detail": type(exc).__name__})
            go_lines = []
        for line in go_lines:
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_block = True
                continue
            if in_block and stripped == ")":
                in_block = False
                continue
            if stripped.startswith("require "):
                stripped = stripped[len("require "):]
            if in_block or line.strip().startswith("require "):
                match = GO_REQUIRE_RE.match(stripped)
                if match:
                    add_declared("go", match.group(1), match.group(2), gomod, "require")
    vcpkg = root / "vcpkg.json"
    if vcpkg.is_file():
        files.append("vcpkg.json")
        try:
            data = json.loads(vcpkg.read_text(encoding="utf-8"))
            values = data.get("dependencies", []) if isinstance(data, dict) else []
            for item in values if isinstance(values, list) else []:
                if isinstance(item, str):
                    name = item
                elif isinstance(item, dict):
                    name = str(item.get("name", ""))
                else:
                    errors.append({"code": "manifest_invalid_dependency", "path": "vcpkg.json", "detail": "dependency_name_required"})
                    continue
                add_declared("vcpkg", name, "", vcpkg, "dependencies")
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            errors.append({"code": "manifest_parse_error", "path": "vcpkg.json", "detail": type(exc).__name__})

    stdlib = {name.lower().replace("-", "_") for name in getattr(sys, "stdlib_module_names", set())}
    try:
        candidate_paths = iter_files_pruned(root, EXCLUDED_DIRS)
    except (OSError, RuntimeError) as exc:
        errors.append({"code": "walk_error", "detail": type(exc).__name__})
        candidate_paths = []
    for path in candidate_paths:
        if not path.is_file() or path.is_symlink() or {part.lower() for part in path.relative_to(root).parts} & EXCLUDED_DIRS:
            continue
        rel = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        if suffix not in {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if suffix == ".py":
            for line_no, line in enumerate(lines, 1):
                match = PY_IMPORT_RE.match(line)
                if match:
                    name = match.group(1) or match.group(2)
                    observed.append({"ecosystem": "python", "name": name, "normalized": _top(name).lower().replace("-", "_"), "path": rel, "line": line_no, "stdlib": _top(name).lower().replace("-", "_") in stdlib, "method": "static_import", "confidence": "observed"})
        elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
            for line_no, line in enumerate(lines, 1):
                for match in JS_IMPORT_RE.finditer(line):
                    name = match.group(1) or match.group(2)
                    if not name.startswith("."):
                        observed.append({"ecosystem": "node", "name": name, "normalized": _top(name).lower().replace("-", "_"), "path": rel, "line": line_no, "method": "static_import", "confidence": "observed"})
        elif suffix == ".go":
            in_import = False
            for line_no, line in enumerate(lines, 1):
                if line.strip().startswith("import ("):
                    in_import = True
                    continue
                if in_import and line.strip() == ")":
                    in_import = False
                    continue
                if in_import:
                    match = GO_IMPORT_RE.match(line.strip())
                    if match:
                        name = match.group(1)
                        observed.append({"ecosystem": "go", "name": name, "normalized": name.lower(), "path": rel, "line": line_no, "method": "static_import", "confidence": "observed"})
        elif suffix in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}:
            for line_no, line in enumerate(lines, 1):
                match = C_INCLUDE_RE.match(line)
                if match:
                    name = match.group(1)
                    observed.append({"ecosystem": "c", "name": name, "normalized": _top(name).lower(), "path": rel, "line": line_no, "method": "static_include", "confidence": "observed"})
    declared_keys = {(item["ecosystem"], item["normalized"]) for item in declared}
    observed_keys = {(item["ecosystem"], item["normalized"]) for item in observed}
    names = sorted(declared_keys | observed_keys)
    dependencies = [{"ecosystem": ecosystem, "normalized": name, "declared": (ecosystem, name) in declared_keys, "observed": (ecosystem, name) in observed_keys, "declarations": [item for item in declared if item["ecosystem"] == ecosystem and item["normalized"] == name], "observations": [item for item in observed if item["ecosystem"] == ecosystem and item["normalized"] == name], "state": "declared_and_observed" if (ecosystem, name) in declared_keys and (ecosystem, name) in observed_keys else "declared_not_observed" if (ecosystem, name) in declared_keys else "observed_not_declared"} for ecosystem, name in names]
    return {"schema": SCHEMA, "status": "invalid" if errors else "observed" if files or observed else "not_found", "root": str(root), "manifest_files": sorted(set(files)), "declared": declared, "observed": observed, "dependencies": dependencies, "errors": errors, "summary": {"declared": len(declared), "observed": len(observed), "declared_not_observed": sum(item["state"] == "declared_not_observed" for item in dependencies), "observed_not_declared": sum(item["state"] == "observed_not_declared" for item in dependencies)}, "limitations": ["mapeamento distribuição→módulo é heurístico", "include/import observado não prova execução/alcançabilidade", "lockfiles transitivos e versões efetivas ainda não são resolvidos", "nenhum instalador ou código foi executado"]}


def write_project_dependency_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
