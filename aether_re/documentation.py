"""Auditoria estática de documentação e referências locais.

Documentação é evidência contextual, não ground truth. Este leitor coleta
headings, links e fences de texto sem seguir URLs, importar código ou executar
comandos encontrados em exemplos. Referências locais são resolvidas apenas
dentro da raiz autorizada e ficam separadas de links externos.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from aether_re.safe_walk import should_exclude_dir
from aether_re.evidence import _path_has_link


SCHEMA = "documentation-audit.v1"
DEFAULT_EXCLUDES = frozenset({".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "venv", "env", "node_modules", "vendor", "third_party", "tools", "output", "build", "dist", "target", "corpus"})
DOC_SUFFIXES = frozenset({".md", ".markdown", ".rst", ".adoc", ".asciidoc", ".txt", ".textile"})
DOC_NAMES = frozenset({"readme", "changelog", "history", "license", "copying", "notice", "contributing", "security", "code_of_conduct"})
_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
_MARKDOWN_LINK_RE = re.compile(r"!?(?P<label>\[[^\]]*\])\((?P<target><[^>]*>|[^)\s]+)(?:\s+[^)]*)?\)")
_REFERENCE_LINK_RE = re.compile(r"^\s*\[[^\]]+\]:\s*(?P<target><[^>]*>|\S+)")
_HTML_LINK_RE = re.compile(r"<a\b[^>]*\bhref\s*=\s*(?:\"(?P<double>[^\"]+)\"|'(?P<single>[^']+)'|(?P<bare>[^\s>]+))", re.IGNORECASE)
_FENCE_RE = re.compile(r"^\s*(```+|~~~+)\s*([^\s]*)")
_URL_RE = re.compile(r"(?<![\w\"'=])(https?://[^\s)<>\"']+)", re.IGNORECASE)


def _invalid(errors: list[dict[str, Any]], *, root: str = "") -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "invalid",
        "root": root,
        "documents": [],
        "references": [],
        "skipped": [],
        "issues": [],
        "errors": errors,
        "summary": {"documents": 0, "bytes": 0, "headings": 0, "links": 0, "external_links": 0, "local_resolved": 0, "local_unresolved": 0, "unsafe_links": 0, "truncated": False},
        "limitations": ["não executa comandos ou código encontrado em documentação", "links externos não são consultados", "documentação não é ground truth sem corroborar implementação"],
    }


def _is_document(path: Path) -> bool:
    return path.suffix.lower() in DOC_SUFFIXES or path.suffix == "" and path.name.lower() in DOC_NAMES


def _hash_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _has_symlink_component(path: Path, root: Path) -> bool:
    try:
        current = root
        for part in path.relative_to(root).parts:
            current = current / part
            if current.is_symlink():
                return True
    except (ValueError, OSError):
        return True
    return False


def _target_kind(target: str) -> str:
    try:
        parsed = urlsplit(target)
    except ValueError:
        # Malformed URL syntax is untrusted document data, not a scan crash.
        return "unsafe"
    if parsed.scheme.lower() in {"http", "https", "mailto", "ftp"}:
        return "external"
    if parsed.scheme or target.startswith("//"):
        return "unsafe"
    if not parsed.path and parsed.fragment:
        return "anchor"
    return "local"


def _resolve_reference(source: Path, target: str, root: Path) -> tuple[str, str | None]:
    """Return (status, resolved relative path) without touching external URLs."""
    cleaned = target.strip()
    if cleaned.startswith("<") and cleaned.endswith(">"):
        cleaned = cleaned[1:-1]
    kind = _target_kind(cleaned)
    if kind == "external":
        return "external", None
    if kind == "unsafe":
        return "unsafe", None
    parsed = urlsplit(cleaned)
    if kind == "anchor":
        return "anchor", None
    decoded = unquote(parsed.path)
    if not decoded:
        return "anchor" if parsed.fragment else "empty", None
    candidate_text = decoded.replace("\\", "/")
    candidate = Path(candidate_text)
    if candidate.is_absolute() or ":" in candidate_text.split("/")[0]:
        return "unsafe", None
    lexical_candidate = Path(os.path.abspath(str(source.parent / candidate)))
    try:
        resolved = lexical_candidate.resolve()
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return "unsafe", None
    if _has_symlink_component(lexical_candidate, root):
        return "unsafe", None
    if resolved.is_file():
        return "resolved", resolved.relative_to(root).as_posix()
    if resolved.is_dir():
        for index_name in ("README.md", "README.rst", "index.md", "index.rst"):
            index_path = resolved / index_name
            if index_path.is_file() and not _has_symlink_component(index_path, root):
                return "resolved", index_path.relative_to(root).as_posix()
    return "unresolved", None


def audit_documentation(
    root: Path,
    *,
    max_files: int = 2_000,
    max_bytes: int = 64 * 1024 * 1024,
    max_file_bytes: int = 4 * 1024 * 1024,
    excludes: set[str] | None = None,
) -> dict[str, Any]:
    """Read documentation metadata and resolve local references conservatively."""
    try:
        candidate_root = Path(root)
    except (TypeError, ValueError):
        return _invalid([{"code": "root_invalid", "detail": "path_required"}])
    if _path_has_link(candidate_root):
        return _invalid([{"code": "root_symlink_not_allowed"}], root=str(candidate_root))
    try:
        resolved_root = candidate_root.resolve()
    except (OSError, RuntimeError) as exc:
        return _invalid([{"code": "root_invalid", "detail": type(exc).__name__}], root=str(candidate_root))
    if not resolved_root.is_dir():
        return _invalid([{"code": "root_missing", "detail": "directory_required"}], root=str(resolved_root))
    limits = (max_files, max_bytes, max_file_bytes)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in limits) or max_files < 1 or max_bytes < 0 or max_file_bytes < 0:
        return _invalid([{"code": "limits_invalid", "detail": "max_files_positive_and_byte_limits_nonnegative"}], root=str(resolved_root))
    excluded = {str(item).lower() for item in (DEFAULT_EXCLUDES | (excludes or set()))}
    documents: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    total_bytes = 0
    truncated = False
    for current, dirs, files in os.walk(resolved_root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for dirname in sorted(dirs):
            child = current_path / dirname
            if should_exclude_dir(dirname, excluded):
                skipped.append({"path": child.relative_to(resolved_root).as_posix(), "reason": "excluded_directory"})
            elif child.is_symlink() or (hasattr(child, "is_junction") and child.is_junction()):
                skipped.append({"path": child.relative_to(resolved_root).as_posix(), "reason": "symlink_directory"})
                issues.append({"code": "symlink_directory_skipped", "path": child.relative_to(resolved_root).as_posix()})
            else:
                kept_dirs.append(dirname)
        dirs[:] = kept_dirs
        for filename in sorted(files):
            path = current_path / filename
            if not _is_document(path):
                continue
            relative = path.relative_to(resolved_root).as_posix()
            if path.is_symlink():
                skipped.append({"path": relative, "reason": "symlink_file"})
                issues.append({"code": "symlink_document_skipped", "path": relative})
                continue
            if len(documents) >= max_files:
                skipped.append({"path": relative, "reason": "max_files"})
                truncated = True
                continue
            try:
                size = path.stat().st_size
            except OSError as exc:
                errors.append({"code": "stat_error", "path": relative, "detail": type(exc).__name__})
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
                payload = path.read_bytes()
                text = payload.decode("utf-8-sig", errors="replace")
            except OSError as exc:
                errors.append({"code": "read_error", "path": relative, "detail": type(exc).__name__})
                continue
            lines = text.splitlines()
            headings: list[dict[str, Any]] = []
            fences: list[dict[str, Any]] = []
            link_targets: list[tuple[int, str, str]] = []
            in_fence = False
            for line_no, line in enumerate(lines, start=1):
                heading = _HEADING_RE.match(line)
                if heading and not in_fence:
                    headings.append({"level": len(heading.group(1)), "text": heading.group(2), "line": line_no})
                fence = _FENCE_RE.match(line)
                if fence:
                    in_fence = not in_fence
                    if in_fence:
                        fences.append({"language": fence.group(2) or None, "line": line_no})
                if not in_fence:
                    for match in _MARKDOWN_LINK_RE.finditer(line):
                        link_targets.append((line_no, match.group("target"), "markdown"))
                    reference = _REFERENCE_LINK_RE.match(line)
                    if reference:
                        link_targets.append((line_no, reference.group("target"), "reference_definition"))
                    for match in _HTML_LINK_RE.finditer(line):
                        link_targets.append((line_no, match.group("double") or match.group("single") or match.group("bare"), "html"))
                    for match in _URL_RE.finditer(line):
                        link_targets.append((line_no, match.group(1), "url"))
            # A Markdown URL is also matched by the bare-URL detector; count
            # one reference per line/target so link metrics cannot be inflated
            # by overlapping extractors.
            seen_links: set[tuple[int, str]] = set()
            document_links: list[dict[str, Any]] = []
            for line_no, target, kind in link_targets:
                key = (line_no, target)
                if key in seen_links:
                    continue
                seen_links.add(key)
                status, resolved = _resolve_reference(path, target, resolved_root)
                item = {"source": relative, "line": line_no, "target": target, "kind": kind, "status": status}
                if resolved:
                    item["resolved_path"] = resolved
                references.append(item)
                document_links.append({"line": line_no, "target": target, "kind": kind, "status": status, **({"resolved_path": resolved} if resolved else {})})
                if status in {"unresolved", "unsafe"}:
                    issues.append({"code": "local_reference_unresolved" if status == "unresolved" else "unsafe_reference", "source": relative, "line": line_no, "target": target})
            documents.append({"path": relative, "sha256": _hash_bytes(payload), "size": size, "headings": headings, "fences": fences, "links": document_links})
            total_bytes += size
    documents.sort(key=lambda item: item["path"])
    references.sort(key=lambda item: (item["source"], item["line"], item["target"], item["kind"]))
    root_digest = hashlib.sha256()
    for item in documents:
        root_digest.update(f"{item['path']}\0{item['size']}\0{item['sha256']}\n".encode("utf-8"))
    summary = {
        "documents": len(documents),
        "bytes": total_bytes,
        "headings": sum(len(item["headings"]) for item in documents),
        "links": len(references),
        "external_links": sum(item["status"] == "external" for item in references),
        "local_resolved": sum(item["status"] == "resolved" for item in references),
        "local_unresolved": sum(item["status"] == "unresolved" for item in references),
        "unsafe_links": sum(item["status"] == "unsafe" for item in references),
        "truncated": truncated,
    }
    status = "invalid" if errors else "partial" if truncated or issues or summary["local_unresolved"] else "complete" if documents else "not_found"
    return {
        "schema": SCHEMA,
        "status": status,
        "root": str(resolved_root),
        "root_digest": root_digest.hexdigest(),
        "documents": documents,
        "references": references,
        "skipped": skipped,
        "issues": issues,
        "errors": errors,
        "summary": summary,
        "limits": {"max_files": max_files, "max_bytes": max_bytes, "max_file_bytes": max_file_bytes},
        "limitations": ["não executa comandos ou código encontrado em documentação", "links externos não são consultados", "documentação não é ground truth sem corroborar implementação", "headings/links são extraídos por heurísticas de texto"],
    }


def write_documentation_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
