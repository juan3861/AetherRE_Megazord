"""Leitor estático conservador para C/C++ sem compilar nem executar o projeto."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Any

from aether_re.safe_walk import iter_files_pruned


SCHEMA = "c-family-source-analysis.v1"
DEFAULT_EXCLUDES = {".git", "__pycache__", "vendor", "generated", ".venv", "venv", "tools", "output", "corpus", "samples", "build", "dist"}
EXTENSIONS = {".c": "c", ".h": "c-header", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp-header", ".hh": "cpp-header"}
CONTROL_NAMES = {"if", "for", "while", "switch", "catch", "sizeof", "return", "_Static_assert"}
TYPE_NAMES = {"void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "bool", "size_t"}

# Intencionalmente não tenta modelar tipos, macros ou gramática completa. O
# padrão apenas gera candidatos revisáveis, nunca funções semanticamente provadas.
FUNCTION_RE = re.compile(
    r"^\s*(?P<prefix>(?:(?:static|extern|inline|const|volatile|unsigned|signed|long|short|struct\s+\w+|enum\s+\w+|class\s+\w+)\s+)*[A-Za-z_][\w:*&<>\s,]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;{}()]*(?:\([^()]*\)[^;{}()]*)*)\)\s*(?P<open>\{)?(?P<trailing>.*)$"
)
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
INCLUDE_RE = re.compile(r"^\s*#\s*include\s*([<\"][^>\"]+[>\"])\s*$")
DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)")



def _load_compile_commands(root: Path, *, max_entries: int, max_bytes: int) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Read compile_commands as provenance only; never invoke its commands."""
    path = root / "compile_commands.json"
    context: dict[str, Any] = {
        "schema": "compile-commands-context.v1", "path": "compile_commands.json",
        "status": "absent", "entries": [], "errors": [], "matched_entries": 0,
        "unmatched_entries": 0, "executed": False,
    }
    if not path.exists():
        return context, {}
    if path.is_symlink() or not path.is_file():
        context.update({"status": "invalid"})
        context["errors"].append({"code": "compile_commands_not_regular_file"})
        return context, {}
    try:
        if path.stat().st_size > max_bytes:
            raise ValueError("compile_commands_size_exceeded")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        context.update({"status": "invalid"})
        context["errors"].append({"code": "compile_commands_invalid", "detail": type(exc).__name__})
        return context, {}
    if not isinstance(data, list) or len(data) > max_entries:
        context.update({"status": "invalid"})
        context["errors"].append({"code": "compile_commands_shape_invalid", "limit": max_entries})
        return context, {}
    units: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(data):
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            context["errors"].append({"code": "compile_command_entry_invalid", "index": index})
            continue
        directory = entry.get("directory", ".")
        base = Path(directory)
        if not base.is_absolute():
            base = root / base
        file_path = Path(entry["file"])
        resolved = (file_path if file_path.is_absolute() else base / file_path).resolve()
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError:
            context["errors"].append({"code": "compile_command_path_escape", "index": index})
            continue
        current = root
        linked = False
        for component in Path(relative).parts:
            current = current / component
            if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
                linked = True
                break
        if linked:
            context["errors"].append({"code": "compile_command_symlink_path", "index": index, "source": relative})
            continue
        arguments = entry.get("arguments")
        if isinstance(arguments, list) and all(isinstance(value, str) for value in arguments):
            args = list(arguments)
        elif isinstance(entry.get("command"), str):
            try:
                args = shlex.split(entry["command"], posix=False)
            except ValueError:
                context["errors"].append({"code": "compile_command_arguments_invalid", "index": index})
                continue
        else:
            context["errors"].append({"code": "compile_command_arguments_missing", "index": index})
            continue
        if relative in units:
            context["errors"].append({"code": "compile_command_duplicate_source", "source": relative})
            continue
        include_dirs: list[str] = []
        defines: list[str] = []
        for arg_index, arg in enumerate(args):
            if arg in {"-I", "/I"} and arg_index + 1 < len(args):
                include_dirs.append(args[arg_index + 1])
            elif arg.startswith(("-I", "/I")) and len(arg) > 2:
                include_dirs.append(arg[2:])
            elif arg.startswith(("-D", "/D")) and len(arg) > 2:
                defines.append(arg[2:])
        unit = {
            "source": relative, "directory": str(base), "arguments": args,
            "compiler": args[0] if args else "", "include_dirs": include_dirs,
            "defines": defines, "language": EXTENSIONS.get(Path(relative).suffix.lower(), "unknown"),
            "entry_sha256": hashlib.sha256(json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(),
        }
        units[relative] = unit
        context["entries"].append(unit)
    context["status"] = "partial" if context["errors"] else "available"
    return context, units

def _end_line(lines: list[str], start: int) -> int:
    """Approximate brace extent; unmatched braces are explicitly flagged later."""
    depth = 0
    seen = False
    for index in range(start - 1, len(lines)):
        depth += lines[index].count("{") - lines[index].count("}")
        if "{" in lines[index]:
            seen = True
        if seen and depth <= 0:
            return index + 1
    return len(lines)


def _function_open_line(lines: list[str], line_no: int, match: re.Match[str]) -> int | None:
    """Return the body line for a conservative function-definition candidate.

    Juliet and several real-world C codebases put the opening brace on the
    following line. The reader only accepts a nearby literal opening brace,
    so declarations/prototypes remain excluded.
    """
    if match.group("open"):
        return line_no
    for index in range(line_no, min(len(lines), line_no + 4)):
        candidate = lines[index].strip()
        if not candidate or candidate.startswith(("//", "/*", "*", "*/")):
            continue
        if candidate.startswith("{"):
            return index + 1
        break
    return None


def analyze_c_family_project(
    root: Path, *, excludes: set[str] | None = None,
    max_files: int = 5000, max_total_bytes: int = 64 * 1024 * 1024,
    max_file_bytes: int = 4 * 1024 * 1024,
    source_files: list[str] | set[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Collect files, candidate functions, includes, macros and calls."""
    root = Path(root)
    if root.is_symlink():
        raise ValueError("root_symlink_not_allowed")
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in (max_files, max_total_bytes, max_file_bytes)):
        raise ValueError("source_limits_invalid")
    excluded = {item.lower() for item in DEFAULT_EXCLUDES | (excludes or set())}
    if source_files is None:
        scoped_files: set[str] | None = None
    else:
        if not isinstance(source_files, (list, set, tuple)) or not all(isinstance(value, str) for value in source_files):
            raise ValueError("source_scope_invalid")
        scoped_files = set()
        for value in source_files:
            candidate = Path(value)
            if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
                raise ValueError("source_scope_invalid")
            resolved = (root / candidate).resolve()
            if not resolved.is_relative_to(root) or resolved.is_symlink() or not resolved.is_file():
                raise ValueError("source_scope_file_invalid")
            scoped_files.add(resolved.relative_to(root).as_posix())
    compile_context, compile_units = _load_compile_commands(root, max_entries=max_files, max_bytes=max_file_bytes * 4)
    modules: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    includes: list[dict[str, Any]] = []
    macros: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    candidate_files = 0
    total_bytes = 0
    for path in iter_files_pruned(root, excluded):
        if not path.is_file() or path.suffix.lower() not in EXTENSIONS:
            continue
        relative = path.relative_to(root)
        rel = relative.as_posix()
        if scoped_files is not None and rel not in scoped_files:
            continue
        candidate_files += 1
        if candidate_files > max_files:
            errors.append({"kind": "max_files_exceeded", "limit": max_files})
            break
        if {part.lower() for part in relative.parts} & excluded:
            continue
        if path.is_symlink():
            errors.append({"path": rel, "kind": "symlink_skipped", "message": "regular_source_required"})
            continue
        language = EXTENSIONS[path.suffix.lower()]
        try:
            size = path.stat().st_size
            if size > max_file_bytes:
                errors.append({"path": rel, "kind": "max_file_bytes_exceeded", "size": size, "limit": max_file_bytes})
                continue
            with path.open("rb") as handle:
                raw = handle.read(max_file_bytes + 1)
            if len(raw) > max_file_bytes:
                errors.append({"path": rel, "kind": "max_file_bytes_exceeded", "size": len(raw), "limit": max_file_bytes})
                continue
            if total_bytes + len(raw) > max_total_bytes:
                errors.append({"path": rel, "kind": "max_total_bytes_exceeded", "limit": max_total_bytes})
                break
            text = raw.decode("utf-8", errors="replace")
            lines = text.splitlines()
            size = len(raw)
            total_bytes += size
        except OSError as exc:
            errors.append({"path": rel, "kind": "read_error", "message": type(exc).__name__})
            continue
        modules.append({"module": rel, "path": rel, "language": language, "sha256": hashlib.sha256(raw).hexdigest(), "size": size, "compile_unit": compile_units.get(rel)})
        current_functions: list[dict[str, Any]] = []
        conditional_depth = 0
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#if") or stripped.startswith("#ifdef") or stripped.startswith("#ifndef"):
                conditional_depth += 1
            inc = INCLUDE_RE.match(line)
            if inc:
                includes.append({"source": rel, "target": inc.group(1), "line": line_no, "conditional": conditional_depth > 0})
            define = DEFINE_RE.match(line)
            if define:
                macros.append({"source": rel, "name": define.group(1), "line": line_no, "conditional": conditional_depth > 0})
            match = FUNCTION_RE.match(line)
            if match:
                name = match.group("name")
                body_line = _function_open_line(lines, line_no, match)
                if name not in CONTROL_NAMES and not stripped.startswith("#") and body_line is not None:
                    end_line = _end_line(lines, body_line)
                    item = {"name": name, "qualified_name": f"{rel}:{name}", "module": rel, "line": line_no, "body_line": body_line, "end_line": end_line, "language": language, "arguments": match.group("args").strip(), "heuristic": True, "conditional": conditional_depth > 0}
                    functions.append(item)
                    current_functions.append(item)
            if stripped.startswith("#endif"):
                conditional_depth = max(0, conditional_depth - 1)
            caller = next((item for item in reversed(current_functions) if item["line"] <= line_no <= item["end_line"]), None)
            for call in CALL_RE.finditer(line):
                callee = call.group(1)
                if callee in CONTROL_NAMES or callee in TYPE_NAMES or (caller and callee == caller["name"] and line_no == caller["line"]):
                    continue
                calls.append({"source": rel, "caller": caller["qualified_name"] if caller else f"{rel}:<global>", "callee": callee, "line": line_no, "resolution": "name", "resolved": False})
    compile_context["matched_entries"] = sum(1 for item in modules if item.get("compile_unit") is not None)
    compile_context["unmatched_entries"] = max(0, len(compile_units) - compile_context["matched_entries"])
    nodes = [{"id": f"module:{item['module']}", "kind": "module", "path": item["path"], "language": item["language"]} for item in modules]
    nodes.extend({"id": f"function:{item['qualified_name']}", "kind": "function", "module": item["module"], "line": item["line"], "heuristic": True} for item in functions)
    module_paths = {str(item["path"]) for item in modules}
    function_names: dict[str, list[str]] = {}
    for item in functions:
        function_names.setdefault(str(item["name"]), []).append(str(item["qualified_name"]))
    edges = []
    for item in includes:
        target = str(item["target"]).strip('<>"')
        matches = [path for path in module_paths if path == target or path.endswith("/" + target) or Path(path).name == target]
        edges.append({"kind": "includes", "source": f"module:{item['source']}", "target": item["target"], "resolved": len(matches) == 1, "resolved_to": f"module:{matches[0]}" if len(matches) == 1 else None, "conditional": item["conditional"], "line": item["line"]})
    for item in calls:
        candidates = function_names.get(str(item["callee"]), [])
        resolved = len(candidates) == 1
        edges.append({"kind": "calls", "source": f"function:{item['caller']}" if item["caller"] != f"{item['source']}:<global>" else f"module:{item['source']}", "target": item["callee"], "resolved": resolved, "resolved_to": candidates[0] if resolved else None, "resolution": "unique_local_function" if resolved else "name", "line": item["line"]})
    return {
        "schema": SCHEMA,
        "root": str(root),
        "modules": modules,
        "functions": functions,
        "calls": calls,
        "includes": includes,
        "macros": macros,
        "graph": {"schema": "source-graph.v1", "nodes": nodes, "edges": edges},
        "compile_context": compile_context,
        "errors": errors,
        "limits": {"max_files": max_files, "max_total_bytes": max_total_bytes, "max_file_bytes": max_file_bytes},
        "analysis_scope": {"mode": "declared_source_files" if scoped_files is not None else "all_supported_files", "files": sorted(scoped_files) if scoped_files is not None else None},
        "summary": {"candidates": candidate_files, "bytes_read": total_bytes},
        "limitations": ["parser lexical/heurístico; não expande macros nem valida gramática", "compile_commands é somente proveniência; flags não são aplicadas e nenhum compilador é invocado", "tipos, overloads, ponteiros de função e callbacks permanecem incertos", "calls/includes são candidatos não resolvidos", "nenhum compilador ou alvo foi executado"],
    }


def write_c_source_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

