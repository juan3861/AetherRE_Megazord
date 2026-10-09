"""Bounded lexical profiles for Go, JavaScript and TypeScript.

This reader opens regular source files only.  It never imports, builds,
installs, or executes material from the project under examination.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from aether_re.safe_walk import iter_files_pruned


SCHEMA = "static-language-profiles.v1"
EXTENSIONS = {".go": "go", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript"}
DEFAULT_EXCLUDES = {".git", "__pycache__", "vendor", "generated", ".venv", "venv", "tools", "output", "corpus", "samples", "build", "dist", "node_modules"}
GO_IMPORT_RE = re.compile(r'^\s*import\s+(?:[A-Za-z_]\w*\s+)?(?P<target>"[^"\r\n]+")\s*$')
JS_IMPORT_RE = re.compile(r'\b(?:import|export)\s+(?:[^;\r\n]*?\s+from\s+)?["\'](?P<target>[^"\'\r\n]+)["\']')
JS_REQUIRE_RE = re.compile(r'\brequire\s*\(\s*["\'](?P<target>[^"\'\r\n]+)["\']\s*\)')
GO_DECL_RE = re.compile(r'^\s*(?:func|type|var|const)\s+(?P<name>[A-Za-z_]\w*)')
JS_DECL_RE = re.compile(r'^\s*(?:export\s+)?(?:async\s+)?(?:function|class|interface|type|const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)')


def _imports(language: str, text: str, path: str) -> list[dict[str, Any]]:
    """Return syntactic import candidates, never resolved dependencies."""
    found: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        patterns = (GO_IMPORT_RE,) if language == "go" else (JS_IMPORT_RE, JS_REQUIRE_RE)
        for pattern in patterns:
            for match in pattern.finditer(line):
                found.append({"source": path, "target": match.group("target"), "line": line_number, "resolution": "lexical_unresolved"})
    return found


def _declarations(language: str, text: str, path: str) -> list[dict[str, Any]]:
    pattern = GO_DECL_RE if language == "go" else JS_DECL_RE
    return [
        {"source": path, "name": match.group("name"), "line": line_number, "kind": "lexical_declaration"}
        for line_number, line in enumerate(text.splitlines(), start=1)
        if (match := pattern.match(line))
    ]


def analyze_language_profiles(
    root: Path,
    *,
    max_files: int = 5000,
    max_total_bytes: int = 64 * 1024 * 1024,
    max_file_bytes: int = 4 * 1024 * 1024,
) -> dict[str, Any]:
    """Collect bounded lexical facts for supported non-Python language files."""
    root = Path(root)
    if root.is_symlink():
        raise ValueError("root_symlink_not_allowed")
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in (max_files, max_total_bytes, max_file_bytes)):
        raise ValueError("source_limits_invalid")

    profiles: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    total_bytes = 0
    candidates = 0
    for path in iter_files_pruned(root, DEFAULT_EXCLUDES):
        language = EXTENSIONS.get(path.suffix.lower())
        if language is None:
            continue
        candidates += 1
        if candidates > max_files:
            errors.append({"kind": "max_files_exceeded", "limit": max_files})
            break
        try:
            if path.is_symlink():
                errors.append({"path": path.relative_to(root).as_posix(), "kind": "symlink_skipped"})
                continue
            size = path.stat().st_size
            relative = path.relative_to(root).as_posix()
            if size > max_file_bytes:
                errors.append({"path": relative, "kind": "max_file_bytes_exceeded", "limit": max_file_bytes})
                continue
            raw = path.read_bytes()
            if total_bytes + len(raw) > max_total_bytes:
                errors.append({"path": relative, "kind": "max_total_bytes_exceeded", "limit": max_total_bytes})
                break
        except (OSError, ValueError) as exc:
            errors.append({"path": str(path), "kind": "read_error", "detail": type(exc).__name__})
            continue
        total_bytes += len(raw)
        text = raw.decode("utf-8", errors="replace")
        profile = profiles.setdefault(language, {"modules": [], "imports": [], "declarations": [], "executed": False})
        profile["modules"].append({"path": relative, "language": language, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)})
        profile["imports"].extend(_imports(language, text, relative))
        profile["declarations"].extend(_declarations(language, text, relative))

    for profile in profiles.values():
        for key in ("modules", "imports", "declarations"):
            profile[key].sort(key=lambda item: tuple(str(item.get(field, "")) for field in ("path", "source", "line", "name", "target")))
    return {
        "schema": SCHEMA,
        "analysis_kind": "lexical_heuristic",
        "root": str(root),
        "profiles": profiles,
        "errors": errors,
        "executed": False,
        "limits": {"max_files": max_files, "max_total_bytes": max_total_bytes, "max_file_bytes": max_file_bytes},
        "summary": {"candidates": candidates, "bytes_read": total_bytes, "languages": sorted(profiles)},
        "limitations": [
            "perfis lexicais não provam equivalência semântica, tipos, fluxo de dados ou comportamento",
            "imports e declarações são candidatos sintáticos não resolvidos",
            "nenhum import, build, instalador ou alvo foi executado",
        ],
    }
