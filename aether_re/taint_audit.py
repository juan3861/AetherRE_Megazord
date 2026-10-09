"""Fluxo de dados intraprocedural conservador para Python."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from aether_re.source import DEFAULT_EXCLUDES, _call_name
from aether_re.safe_walk import iter_files_pruned


SOURCES = {"input", "os.getenv", "os.environ.get", "request.args.get", "request.form.get"}
SINKS = {"eval", "exec", "os.system", "subprocess.call", "subprocess.run", "subprocess.Popen", "pickle.loads", "pickle.load"}


def _names(node: ast.AST) -> set[str]:
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)}


class _FlowVisitor(ast.NodeVisitor):
    def __init__(self, source: str, path: str):
        self.source = source
        self.path = path
        self.function = "<module>"
        self.tainted: dict[str, dict[str, Any]] = {}
        self.flows: list[dict[str, Any]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous = self.function
        self.function = node.name
        self.tainted = {}
        for child in node.body:
            self.visit(child)
        self.function = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        flow = self._flow_in(node.value)
        if flow:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted[target.id] = flow
        self.generic_visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            flow = self._flow_in(node.value)
            if flow and isinstance(node.target, ast.Name):
                self.tainted[node.target.id] = flow
            self.generic_visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        callee, _ = _call_name(node.func)
        if callee in SINKS:
            flow = self._flow_in(node)
            if flow:
                self.flows.append({
                    "source": self.path,
                    "source_line": flow["line"],
                    "source_kind": flow["kind"],
                    "sink": callee,
                    "sink_line": node.lineno,
                    "function": self.function,
                    "state": "static_flow",
                    "reachable": "unknown",
                    "confidence_kind": "heuristic",
                    "requires_validation": True,
                })
        self.generic_visit(node)

    def _flow_in(self, node: ast.AST) -> dict[str, Any] | None:
        for call in (item for item in ast.walk(node) if isinstance(item, ast.Call)):
            callee, _ = _call_name(call.func)
            if callee in SOURCES:
                return {"line": call.lineno, "kind": callee}
        for name in _names(node):
            if name in self.tainted:
                return self.tainted[name]
        return None


def audit_python_taint(root: Path) -> dict[str, Any]:
    schema = "python-taint-audit.v1"
    try:
        root = Path(root).resolve()
    except (TypeError, ValueError, OSError, RuntimeError) as exc:
        return {
            "schema": schema,
            "status": "invalid",
            "root": repr(root),
            "flows": [],
            "parse_errors": [],
            "errors": [{"code": "root_invalid", "detail": type(exc).__name__}],
            "summary": {"flows": 0, "parse_errors": 0, "read_errors": 0},
            "limitations": ["intraprocedural e ordem simples de assignments", "não modela aliases/containers/interproceduralidade", "reachable permanece unknown"],
        }
    try:
        root_exists = root.is_dir()
    except (OSError, RuntimeError):
        root_exists = False
    if not root_exists:
        return {
            "schema": schema,
            "status": "invalid",
            "root": str(root),
            "flows": [],
            "parse_errors": [],
            "errors": [{"code": "root_missing", "detail": "directory_required"}],
            "summary": {"flows": 0, "parse_errors": 0, "read_errors": 0},
            "limitations": ["intraprocedural e ordem simples de assignments", "não modela aliases/containers/interproceduralidade", "reachable permanece unknown"],
        }
    flows: list[dict[str, Any]] = []
    parse_errors: list[dict[str, Any]] = []
    read_errors: list[dict[str, Any]] = []
    try:
        paths = (path for path in iter_files_pruned(root, DEFAULT_EXCLUDES) if path.suffix.lower() == ".py")
    except (OSError, RuntimeError) as exc:
        return {
            "schema": schema,
            "status": "invalid",
            "root": str(root),
            "flows": [],
            "parse_errors": [],
            "errors": [{"code": "walk_error", "detail": type(exc).__name__}],
            "summary": {"flows": 0, "parse_errors": 0, "read_errors": 0},
            "limitations": ["intraprocedural e ordem simples de assignments", "não modela aliases/containers/interproceduralidade", "reachable permanece unknown"],
        }
    for path in paths:
        try:
            relative = path.relative_to(root)
        except ValueError:
            read_errors.append({"source": str(path), "code": "path_escape"})
            continue
        if path.is_symlink() or set(relative.parts) & DEFAULT_EXCLUDES:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        except SyntaxError as exc:
            parse_errors.append({"source": relative.as_posix(), "line": exc.lineno, "kind": "syntax_error"})
            continue
        except (OSError, UnicodeError) as exc:
            read_errors.append({"source": relative.as_posix(), "kind": "read_error", "detail": type(exc).__name__})
            continue
        visitor = _FlowVisitor(str(root), relative.as_posix())
        visitor.visit(tree)
        flows.extend(visitor.flows)
    return {
        "schema": schema,
        "status": "invalid" if read_errors else "partial" if parse_errors else "complete",
        "root": str(root),
        "flows": flows,
        "parse_errors": parse_errors,
        "errors": read_errors,
        "summary": {"flows": len(flows), "parse_errors": len(parse_errors), "read_errors": len(read_errors)},
        "limitations": ["intraprocedural e ordem simples de assignments", "não modela aliases/containers/interproceduralidade", "reachable permanece unknown"],
    }
