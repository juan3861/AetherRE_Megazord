"""Leitura estática e conservadora de projetos Python (sem executar imports)."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from aether_re.safe_walk import iter_files_pruned


SCHEMA = "python-source-analysis.v1"
DEFAULT_EXCLUDES = {".git", "__pycache__", "vendor", "generated", ".venv", "venv", "tools", "output", "corpus", "samples"}


def _call_name(node: ast.AST) -> tuple[str, str]:
    if isinstance(node, ast.Name):
        return node.id, "name"
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts)), "attribute"
    return "<dynamic>", "dynamic"


def _resolve_import_target(item: dict[str, Any]) -> tuple[str, list[str]]:
    """Resolve a relative import to local module candidates without importing."""
    raw = str(item.get("module") or "")
    if not raw.startswith("."):
        return raw, [raw]
    level = len(raw) - len(raw.lstrip("."))
    suffix = raw[level:]
    source = Path(str(item.get("source") or "")).with_suffix("")
    source_module = ".".join(source.parts)
    if source_module.endswith(".__init__"):
        source_module = source_module.removesuffix(".__init__")
    parts = source_module.split(".") if source_module else []
    if level > len(parts):
        return "", []
    base = parts[:-level]
    target = ".".join([*base, suffix] if suffix else base)
    candidates = [target] if target else []
    name = str(item.get("name") or "")
    if name and target:
        candidates.append(f"{target}.{name}")
    return target, candidates


class _ModuleVisitor(ast.NodeVisitor):
    def __init__(self, module: str):
        self.module = module
        self.scope: list[str] = []
        self.conditional_depth = 0
        self.functions: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []
        self.dynamic_imports: list[dict[str, Any]] = []

    def _qualified(self, name: str) -> str:
        return ".".join([self.module, *self.scope, name])

    def _current_scope(self) -> str:
        """Return the enclosing module/class/function without duplicating it."""
        return ".".join([self.module, *self.scope]) if self.scope else f"{self.module}.<module>"

    def visit_If(self, node: ast.If) -> None:
        self.conditional_depth += 1
        for child in node.body:
            self.visit(child)
        for child in node.orelse:
            self.visit(child)
        self.conditional_depth -= 1

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append({"module": alias.name, "name": alias.asname, "conditional": self.conditional_depth > 0, "line": node.lineno})

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = "." * node.level + (node.module or "")
        for alias in node.names:
            self.imports.append({"module": base, "name": alias.name, "asname": alias.asname, "conditional": self.conditional_depth > 0, "line": node.lineno})

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualified = self._qualified(node.name)
        self.functions.append(
            {
                "name": node.name,
                "qualified_name": qualified,
                "module": self.module,
                "line": node.lineno,
                "end_line": getattr(node, "end_lineno", node.lineno),
                "async": isinstance(node, ast.AsyncFunctionDef),
                "decorators": [ast.unparse(item) for item in node.decorator_list],
            }
        )
        self.scope.append(node.name)
        for child in node.body:
            self.visit(child)
        self.scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        for child in node.body:
            self.visit(child)
        self.scope.pop()

    def visit_Call(self, node: ast.Call) -> None:
        callee, kind = _call_name(node.func)
        caller = self._current_scope()
        self.calls.append({"caller": caller, "callee": callee, "kind": kind, "line": node.lineno})
        if callee in {"__import__", "importlib.import_module", "import_module"}:
            self.dynamic_imports.append({"caller": caller, "callee": callee, "line": node.lineno, "reason": "runtime_import_expression"})
        self.generic_visit(node)


def analyze_python_project(
    root: Path, *, excludes: set[str] | None = None,
    max_files: int = 5000, max_total_bytes: int = 64 * 1024 * 1024,
    max_file_bytes: int = 4 * 1024 * 1024,
) -> dict[str, Any]:
    """Analisa arquivos Python sem importar/executar o projeto."""
    root = Path(root)
    if root.is_symlink():
        raise ValueError("root_symlink_not_allowed")
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in (max_files, max_total_bytes, max_file_bytes)):
        raise ValueError("source_limits_invalid")
    excluded = DEFAULT_EXCLUDES | (excludes or set())
    modules: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    imports: list[dict[str, Any]] = []
    dynamic_imports: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    candidate_files = 0
    total_bytes = 0
    for path in iter_files_pruned(root, excluded):
        if path.suffix.lower() != ".py":
            continue
        candidate_files += 1
        if candidate_files > max_files:
            errors.append({"kind": "max_files_exceeded", "limit": max_files})
            break
        try:
            relative_path = path.relative_to(root)
        except ValueError:
            errors.append({"path": str(path), "kind": "path_escape"})
            continue
        relative_parts = set(relative_path.parts)
        if relative_parts & excluded:
            continue
        if path.is_symlink():
            errors.append({"path": relative_path.as_posix(), "kind": "symlink_skipped", "message": "regular_source_required"})
            continue
        relative = relative_path.with_suffix("")
        module = ".".join(relative.parts)
        if module.endswith(".__init__"):
            module = module.removesuffix(".__init__")
        try:
            size = path.stat().st_size
            if size > max_file_bytes:
                errors.append({"path": relative_path.as_posix(), "kind": "max_file_bytes_exceeded", "size": size, "limit": max_file_bytes})
                continue
            with path.open("rb") as handle:
                raw = handle.read(max_file_bytes + 1)
            if len(raw) > max_file_bytes:
                errors.append({"path": relative_path.as_posix(), "kind": "max_file_bytes_exceeded", "size": len(raw), "limit": max_file_bytes})
                continue
            if total_bytes + len(raw) > max_total_bytes:
                errors.append({"path": relative_path.as_posix(), "kind": "max_total_bytes_exceeded", "limit": max_total_bytes})
                break
            source = raw.decode("utf-8", errors="replace")
            size = len(raw)
            digest = hashlib.sha256(raw).hexdigest()
            total_bytes += size
        except OSError as exc:
            errors.append({"path": relative_path.as_posix(), "kind": "read_error", "message": type(exc).__name__})
            continue
        modules.append({"module": module, "path": relative_path.as_posix(), "sha256": digest, "size": size})
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            errors.append({"path": relative_path.as_posix(), "line": exc.lineno, "message": exc.msg, "kind": "syntax_error"})
            continue
        visitor = _ModuleVisitor(module)
        visitor.visit(tree)
        functions.extend(visitor.functions)
        calls.extend([{**item, "source": relative_path.as_posix()} for item in visitor.calls])
        imports.extend([{**item, "source": relative_path.as_posix()} for item in visitor.imports])
        dynamic_imports.extend([{**item, "source": relative_path.as_posix()} for item in visitor.dynamic_imports])
    nodes = [
        {"id": f"module:{item['module']}", "kind": "module", "path": item["path"]}
        for item in modules
    ] + [
        {"id": f"function:{item['qualified_name']}", "kind": "function", "module": item["module"], "line": item["line"]}
        for item in functions
    ]
    module_names = {str(item["module"]) for item in modules}
    function_names: dict[str, list[str]] = {}
    for item in functions:
        function_names.setdefault(str(item["name"]), []).append(str(item["qualified_name"]))
    edges = []
    for item in imports:
        raw_target = str(item["module"])
        target, candidates = _resolve_import_target(item)
        matches = [name for candidate in candidates for name in module_names if name == candidate or name.startswith(candidate + ".")]
        resolved = len(set(matches)) == 1
        edge = {"kind": "imports", "source": f"module:{item['source'][:-3].replace('/', '.').removesuffix('.__init__')}", "target": raw_target, "resolved": resolved, "resolution": "relative_local_module" if raw_target.startswith(".") and resolved else ("local_module_prefix" if resolved else "unresolved"), "conditional": item["conditional"]}
        if target:
            edge["resolved_module"] = target
        if resolved:
            edge["resolved_to"] = sorted(set(matches))[0]
        edges.append(edge)
    for item in calls:
        candidates = function_names.get(str(item["callee"]), [])
        resolved = len(candidates) == 1 and item["kind"] in {"name", "attribute"}
        edges.append({"kind": "calls", "source": f"function:{item['caller']}", "target": item["callee"], "resolved": resolved, "resolved_to": candidates[0] if resolved else None, "resolution": "unique_local_function" if resolved else item["kind"], "line": item["line"]})
    return {
        "schema": SCHEMA,
        "root": str(root),
        "modules": modules,
        "functions": functions,
        "calls": calls,
        "imports": imports,
        "dynamic_imports": dynamic_imports,
        "graph": {"schema": "source-graph.v1", "nodes": nodes, "edges": edges},
        "errors": errors,
        "limits": {"max_files": max_files, "max_total_bytes": max_total_bytes, "max_file_bytes": max_file_bytes},
        "summary": {"candidates": candidate_files, "bytes_read": total_bytes},
        "limitations": ["AST estático; reflexão/import dinâmico permanecem incertos", "não prova código morto nem alcançabilidade", "nenhum módulo foi executado"],
    }


def write_source_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
