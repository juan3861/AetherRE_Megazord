"""Inventário estático, determinístico e limitado de um projeto.

O inventário é deliberadamente agnóstico de linguagem: coleta arquivos,
classifica sinais de fonte/build/dependência/documentação/testes e calcula
hashes sem importar módulos, executar scripts ou seguir symlinks.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from aether_re.safe_walk import should_exclude_dir
from aether_re.evidence import _path_has_link


SCHEMA = "project-inventory.v1"
DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "vendor",
        "third_party",
        "tools",
        "output",
        "build",
        "dist",
        "target",
    }
)

SOURCE_LANGUAGES = {
    ".py": "python",
    ".pyi": "python",
    ".c": "c",
    ".h": "c-header",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp-header",
    ".hh": "cpp-header",
    ".rs": "rust",
    ".go": "go",
    ".java": "java",
    ".cs": "csharp",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".asm": "assembly",
    ".s": "assembly",
}
BINARY_SUFFIXES = frozenset({".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".pyd", ".class", ".jar", ".wasm"})
DOC_SUFFIXES = frozenset({".md", ".rst", ".adoc", ".textile", ".txt"})
BUILD_NAMES = frozenset(
    {
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "requirements-dev.txt",
        "pipfile",
        "pipfile.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "cmakelists.txt",
        "makefile",
        "meson.build",
        "cargo.toml",
        "cargo.lock",
        "go.mod",
        "go.sum",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "tox.ini",
        "noxfile.py",
        "justfile",
    }
)
CONFIG_SUFFIXES = frozenset({".toml", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".json", ".properties", ".env"})


def _category(path: Path) -> tuple[str, str | None]:
    name = path.name.lower()
    suffix = path.suffix.lower()
    parts = {part.lower() for part in path.parts}
    if name in BUILD_NAMES or name.startswith("requirements") and suffix in {".txt", ".in"}:
        return "build_or_dependency", None
    if "test" in parts or name.startswith(("test_", "test-")) or ".test." in name:
        language = SOURCE_LANGUAGES.get(suffix)
        return "test", language
    if suffix in SOURCE_LANGUAGES:
        return "source", SOURCE_LANGUAGES[suffix]
    if suffix in BINARY_SUFFIXES:
        return "binary", None
    if suffix in DOC_SUFFIXES or name.startswith(("readme", "changelog", "license", "copying")):
        return "documentation", None
    if suffix in CONFIG_SUFFIXES:
        return "configuration", None
    return "other", None


def _iter_files(root: Path, excluded_dirs: frozenset[str]) -> Iterable[tuple[Path, str | None]]:
    """Yield regular files and symlink skips in deterministic order."""
    for current, dirs, files in __import__("os").walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for dirname in sorted(dirs):
            candidate = current_path / dirname
            if candidate.is_symlink() or (hasattr(candidate, "is_junction") and candidate.is_junction()):
                yield candidate, "symlink_directory"
            elif should_exclude_dir(dirname, excluded_dirs):
                yield candidate, "excluded_directory"
            else:
                kept_dirs.append(dirname)
        dirs[:] = kept_dirs
        for filename in sorted(files):
            path = current_path / filename
            if path.is_symlink():
                yield path, "symlink_file"
            else:
                yield path, None


def inventory_project(
    root: Path,
    *,
    max_files: int = 5000,
    max_bytes: int = 512 * 1024 * 1024,
    max_file_bytes: int = 16 * 1024 * 1024,
) -> dict[str, Any]:
    """Return a bounded inventory; limits are part of the report and status."""
    root = Path(root)
    if _path_has_link(root):
        return {
            "schema": SCHEMA,
            "status": "invalid",
            "root": str(root),
            "files": [],
            "skipped": [],
            "issues": [{"code": "root_symlink_not_allowed"}],
            "limits": {"max_files": max_files, "max_bytes": max_bytes, "max_file_bytes": max_file_bytes},
        }
    root = root.resolve()
    issues: list[dict[str, str]] = []
    skipped: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    if not root.is_dir():
        return {
            "schema": SCHEMA,
            "status": "invalid",
            "root": str(root),
            "files": [],
            "skipped": [],
            "issues": [{"code": "root_missing", "detail": "directory_required"}],
            "limits": {"max_files": max_files, "max_bytes": max_bytes, "max_file_bytes": max_file_bytes},
        }
    if max_files < 1 or max_bytes < 0 or max_file_bytes < 0:
        issues.append({"code": "invalid_limits", "detail": "limits_must_be_nonnegative_and_max_files_positive"})

    total_bytes = 0
    truncated = False
    for path, skip_reason in _iter_files(root, DEFAULT_EXCLUDED_DIRS):
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            skipped.append({"path": str(path), "reason": "path_escape"})
            truncated = True
            continue
        if skip_reason:
            skipped.append({"path": relative, "reason": skip_reason})
            continue
        if len(files) >= max_files:
            skipped.append({"path": relative, "reason": "max_files"})
            truncated = True
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            skipped.append({"path": relative, "reason": f"stat_error:{type(exc).__name__}"})
            truncated = True
            continue
        if size > max_file_bytes:
            skipped.append({"path": relative, "size": size, "reason": "max_file_bytes"})
            truncated = True
            continue
        if total_bytes + size > max_bytes:
            skipped.append({"path": relative, "size": size, "reason": "max_bytes"})
            truncated = True
            continue
        try:
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            category, language = _category(Path(relative))
        except (OSError, ValueError) as exc:
            skipped.append({"path": relative, "reason": f"read_error:{type(exc).__name__}"})
            truncated = True
            continue
        files.append({"path": relative, "size": size, "sha256": digest.hexdigest(), "category": category, "language": language})
        total_bytes += size

    files.sort(key=lambda item: item["path"])
    root_digest = hashlib.sha256()
    for item in files:
        root_digest.update(f"{item['path']}\0{item['size']}\0{item['sha256']}\0{item['category']}\n".encode("utf-8"))
    counts: dict[str, int] = {}
    languages: dict[str, int] = {}
    for item in files:
        counts[item["category"]] = counts.get(item["category"], 0) + 1
        if item["language"]:
            languages[item["language"]] = languages.get(item["language"], 0) + 1
    return {
        "schema": SCHEMA,
        "status": "partial" if truncated or issues else "complete",
        "root": str(root),
        "root_digest": root_digest.hexdigest(),
        "files": files,
        "skipped": skipped,
        "issues": issues,
        "summary": {"files": len(files), "bytes": total_bytes, "categories": counts, "languages": languages},
        "limits": {"max_files": max_files, "max_bytes": max_bytes, "max_file_bytes": max_file_bytes},
        "limitations": ["hashes representam o instante da leitura", "arquivos excluídos ou acima do budget não foram analisados", "classificação por extensão/nome é heurística", "não executa código nem resolve semântica"],
    }


def write_inventory_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
