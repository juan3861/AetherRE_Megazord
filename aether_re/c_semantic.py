"""Optional static C AST adapter backed by pycparser.

The adapter is intentionally capability-scoped.  It removes preprocessor lines
and supplies declarations for common libc symbols, so it is *not* a substitute
for Clang with the project's real compile flags.  Parse status and limitations
are always returned; no source is compiled or executed.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "c-semantic-ast-analysis.v1"

_PREFIX = """
typedef unsigned long size_t;
typedef unsigned long uintptr_t;
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
typedef int FILE;
typedef int SOCKET;
typedef unsigned long DWORD;
typedef void * HANDLE;
typedef struct { int dummy; } WSADATA;
struct sockaddr { int dummy; };
struct sockaddr_in { int sin_family; struct { int s_addr; } sin_addr; int sin_port; };
typedef int bool;
typedef int wchar_t;
FILE *stdin;
void printLine(char *);
void printHexCharLine(char);
void printIntLine(int);
void printLongLongLine(long long);
void printFloatLine(float);
void printDoubleLine(double);
void printBytesLine(void *, int);
void srand(unsigned);
int time(int *);
void *malloc(unsigned long);
void free(void *);
int memcpy(void *, const void *, unsigned long);
int memset(void *, int, unsigned long);
int fscanf(FILE *, const char *, ...);
int printf(const char *, ...);
int sprintf(char *, const char *, ...);
"""


def _preprocess_for_ast(text: str) -> str:
    """Remove directives/comments while preserving line structure."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", " ", text)
    # Remove a complete preprocessor continuation as a unit.  We do not try
    # to evaluate conditionals; that limitation is surfaced in the report.
    text = re.sub(r"^[ \t]*#(?:[^\n\\]|\\[^\n]*\n)*[^\n]*$", "", text, flags=re.MULTILINE)
    return _PREFIX + "\n" + text


class _Collector:
    def __init__(self, c_ast: Any):
        self.c_ast = c_ast
        self.functions: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None

    def visit(self, node: Any) -> None:
        method = getattr(self, f"visit_{type(node).__name__}", self.generic_visit)
        method(node)

    def generic_visit(self, node: Any) -> None:
        for _, child in node.children():
            self.visit(child)

    def visit_FuncDef(self, node: Any) -> None:
        coord = getattr(node, "coord", None)
        item = {"name": str(node.decl.name), "line": getattr(coord, "line", None), "semantic": True}
        self.functions.append(item)
        previous = self._current
        self._current = item
        self.visit(node.body)
        self._current = previous

    def visit_FuncCall(self, node: Any) -> None:
        if self._current is not None and isinstance(node.name, self.c_ast.ID):
            coord = getattr(node, "coord", None)
            self.calls.append({"caller": self._current["name"], "callee": str(node.name.name), "line": getattr(coord, "line", None), "semantic": True})
        self.generic_visit(node)


def analyze_c_ast_files(files: Iterable[Path]) -> dict[str, Any]:
    """Parse bounded C files and return AST-derived functions/direct calls."""
    try:
        from pycparser import c_ast, c_parser
    except ImportError:
        return {"schema": SCHEMA, "status": "unavailable", "capability": "pycparser", "files": [], "functions": [], "calls": [], "errors": [{"code": "pycparser_unavailable"}], "executed": False}
    records: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for raw in files:
        path = Path(raw)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = c_parser.CParser().parse(_preprocess_for_ast(text), filename=str(path))
            collector = _Collector(c_ast)
            collector.visit(tree)
            for function in collector.functions:
                functions.append({"file": str(path), **function})
            for call in collector.calls:
                calls.append({"file": str(path), **call})
            records.append({"path": str(path), "status": "parsed", "function_count": len(collector.functions), "call_count": len(collector.calls)})
        except Exception as exc:
            records.append({"path": str(path), "status": "parse_failed", "error": type(exc).__name__})
            errors.append({"path": str(path), "code": "c_ast_parse_failed", "detail": str(exc)[:500]})
    defined = {str(item["name"]) for item in functions}
    edges = []
    for call in calls:
        edges.append({"kind": "calls", "source": f"function:{call['caller']}", "target": call["callee"], "resolved": call["callee"] in defined, "semantic": True, "line": call.get("line")})
    status = "complete" if records and not errors else "partial" if records else "invalid"
    return {"schema": SCHEMA, "status": status, "capability": "pycparser_without_real_preprocessor", "files": records, "functions": functions, "calls": calls, "graph": {"schema": "c-semantic-ast-graph.v1", "edges": edges}, "errors": errors, "executed": False, "limitations": ["preprocessor directives are removed rather than evaluated", "real compile_commands flags and headers are not applied", "this is AST syntax/structure evidence, not behavior or semantic equivalence", "optional adapter does not replace Clang or a real build"]}
