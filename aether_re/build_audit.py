"""Auditoria estática de receitas e pistas de build, sem compilar o projeto."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Any

from aether_re.safe_walk import iter_files_pruned


SCHEMA = "build-audit.v1"
EXCLUDED_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "vendor", "third_party", "tools", "output", "build", "dist", "target"}
BUILD_NAME_RE = re.compile(r"^(pyproject\.toml|setup(?:\.cfg|\.py)?|requirements[^/]*\.(?:txt|in)|pipfile(?:\.lock)?|package(?:-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|cmakelists\.txt|compile_commands\.json|makefile(?:\..*)?|meson\.build|cargo\.(?:toml|lock)|go\.(?:mod|sum)|pom\.xml|build\.gradle(?:\.kts)?|dockerfile(?:\..*)?|tox\.ini|noxfile\.py|justfile)$", re.I)
BUILD_SUFFIXES = {".sln", ".vcxproj", ".csproj", ".xcodeproj", ".gradle"}
TOOL_RE = re.compile(r"\b(gcc|g\+\+|clang(?:\+\+|-cl)?|cl(?:\.exe)?|cmake|make|ninja|msbuild|cargo|rustc|go|javac|dotnet|mvn|gradle)\b", re.I)
FLAG_RE = re.compile(r"(?<![A-Za-z0-9])(?:-[A-Za-z][A-Za-z0-9_+.-]*|/[A-Za-z][A-Za-z0-9_+.-]*)")
OUTPUT_RE = re.compile(r"(?:-o\s+|/Fe:?\s*|OUTPUT(?:_NAME)?\s+|add_executable\s*\(\s*)([^\s)]+)", re.I)
SOURCE_TOKEN_RE = re.compile(r"\b[^\s,;()]+\.(?:c|cc|cpp|cxx|h|hpp|rs|go|java|cs|py|js|ts)\b", re.I)


def _clean_token(value: str) -> str:
    """Remove JSON/shell punctuation around a statically captured token."""
    return value.strip("\"'`\t\r\n,;)]}>")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _build_system(name: str) -> str:
    lower = name.lower()
    if lower.startswith("cmake"):
        return "cmake"
    if lower == "compile_commands.json":
        return "compilation-database"
    if lower.startswith("makefile"):
        return "make"
    if lower.startswith("cargo."):
        return "cargo"
    if lower.startswith("go."):
        return "go"
    if lower.startswith(("package", "yarn", "pnpm")):
        return "node"
    if lower.startswith(("pyproject", "setup", "requirements", "pipfile", "tox", "nox")):
        return "python"
    if lower.startswith(("pom", "build.gradle", "gradle")):
        return "jvm"
    if lower.startswith(("dockerfile", "docker-compose")):
        return "container"
    if lower.endswith((".sln", ".vcxproj", ".csproj")):
        return "msbuild"
    if lower.endswith(".xcodeproj"):
        return "xcode"
    if lower == "meson.build":
        return "meson"
    return "unknown"


def _command_tokens(entry: dict[str, Any]) -> list[str]:
    arguments = entry.get("arguments")
    if isinstance(arguments, list) and all(isinstance(item, str) for item in arguments):
        return list(arguments)
    command = entry.get("command")
    if isinstance(command, str):
        try:
            return shlex.split(command, posix=False)
        except ValueError:
            return command.split()
    return []


def _compile_commands_observations(
    path: Path,
    root: Path,
    text: str,
    *,
    max_entries: int = 2000,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Read a compilation database as declarations; never invokes a compiler."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], [{"code": "compile_commands_invalid_json", "path": path.relative_to(root).as_posix(), "detail": str(exc)}]
    if not isinstance(document, list):
        return [], [{"code": "compile_commands_invalid_shape", "path": path.relative_to(root).as_posix(), "detail": "array_required"}]
    issues: list[dict[str, str]] = []
    units: list[dict[str, Any]] = []
    for index, raw_entry in enumerate(document):
        if index >= max_entries:
            issues.append({"code": "compile_commands_max_entries", "path": path.relative_to(root).as_posix(), "detail": str(max_entries)})
            break
        if not isinstance(raw_entry, dict):
            issues.append({"code": "compile_commands_invalid_entry", "path": path.relative_to(root).as_posix(), "detail": f"index={index}"})
            continue
        directory = raw_entry.get("directory")
        source = raw_entry.get("file")
        tokens = _command_tokens(raw_entry)
        if not isinstance(source, str) or not source:
            issues.append({"code": "compile_commands_missing_file", "path": path.relative_to(root).as_posix(), "detail": f"index={index}"})
            continue
        working_dir = Path(directory) if isinstance(directory, str) and directory else root
        if not working_dir.is_absolute():
            working_dir = root / working_dir
        source_path = Path(source)
        if not source_path.is_absolute():
            source_path = working_dir / source_path
        source_path = source_path.resolve()
        try:
            source_rel = source_path.relative_to(root).as_posix()
            source_scope = "within_root"
            source_sha256 = _sha256(source_path) if source_path.is_file() and not source_path.is_symlink() else None
        except ValueError:
            source_rel = str(source_path)
            source_scope = "outside_root"
            source_sha256 = None
        compiler = Path(tokens[0].strip('"\'')).name if tokens else None
        flags: list[str] = []
        output: str | None = None
        skip_next = False
        for token in tokens[1:]:
            if skip_next:
                skip_next = False
                continue
            if token in {"-o", "/Fe", "/Fe:", "/Fo", "/Fo:"}:
                skip_next = True
                continue
            if token.startswith(("/Fe", "/Fo")) and len(token) > 3:
                output = token.split(":", 1)[-1]
                continue
            if token.startswith(("-", "/")):
                flags.append(token)
        units.append(
            {
                "index": index,
                "file": source_rel,
                "source_scope": source_scope,
                "source_sha256": source_sha256,
                "directory": str(working_dir),
                "compiler": compiler,
                "arguments": tokens,
                "flags": flags,
                "output": output,
                "executed": False,
                "confidence": "declared",
                "provenance": path.relative_to(root).as_posix(),
            }
        )
    return units, issues


def audit_build(root: Path, *, max_files: int = 200, max_file_bytes: int = 4 * 1024 * 1024) -> dict[str, Any]:
    """Collect build metadata as observations; never invokes a build tool."""
    root = root.resolve()
    if not root.is_dir():
        return {"schema": SCHEMA, "status": "invalid", "root": str(root), "files": [], "compile_commands": [], "observations": [], "issues": [{"code": "root_missing", "detail": "directory_required"}], "limitations": ["não compila nem executa scripts de build"]}
    files: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    systems: set[str] = set()
    tools: set[str] = set()
    flags: set[str] = set()
    outputs: set[str] = set()
    source_tokens: set[str] = set()
    compile_units: list[dict[str, Any]] = []
    for path in iter_files_pruned(root, EXCLUDED_DIRS):
        if not path.is_file() or path.is_symlink():
            continue
        rel_path = path.relative_to(root)
        if {part.lower() for part in rel_path.parts} & EXCLUDED_DIRS:
            continue
        name = path.name
        if not BUILD_NAME_RE.match(name) and path.suffix.lower() not in BUILD_SUFFIXES:
            continue
        if len(files) >= max_files:
            skipped.append({"path": rel_path.as_posix(), "reason": "max_files"})
            continue
        try:
            size = path.stat().st_size
            if size > max_file_bytes:
                skipped.append({"path": rel_path.as_posix(), "reason": "max_file_bytes"})
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            digest = _sha256(path)
        except OSError as exc:
            issues.append({"code": "read_error", "path": rel_path.as_posix(), "detail": type(exc).__name__})
            continue
        system = _build_system(name)
        systems.add(system)
        files.append({"path": rel_path.as_posix(), "size": size, "sha256": digest, "build_system": system})
        if name.lower() == "compile_commands.json":
            units, database_issues = _compile_commands_observations(path, root, text)
            compile_units.extend(units)
            issues.extend(database_issues)
            for unit in units:
                if unit.get("compiler"):
                    tools.add(str(unit["compiler"]).lower())
                    observations.append({"kind": "tool", "value": unit["compiler"], "path": rel_path.as_posix(), "method": "compile_commands", "confidence": "candidate"})
                for flag in unit.get("flags", []):
                    flags.add(flag)
                    observations.append({"kind": "flag", "value": flag, "path": rel_path.as_posix(), "method": "compile_commands", "confidence": "candidate"})
                if unit.get("output"):
                    clean_output = _clean_token(str(unit["output"]))
                    outputs.add(clean_output)
                    observations.append({"kind": "output_candidate", "value": clean_output, "path": rel_path.as_posix(), "method": "compile_commands", "confidence": "candidate"})
        # O nome da receita sugere um toolchain, mas não prova que o executável
        # esteja instalado; por isso a lista continua sendo apenas candidata.
        if system not in {"unknown", "container"}:
            tools.add(system)
            observations.append({"kind": "tool", "value": system, "path": rel_path.as_posix(), "method": "build_file_name", "confidence": "candidate"})
        for match in TOOL_RE.finditer(text):
            tools.add(match.group(1).lower())
            observations.append({"kind": "tool", "value": match.group(1), "path": rel_path.as_posix(), "method": "static_token", "confidence": "candidate"})
        for match in FLAG_RE.finditer(text):
            value = match.group(0)
            if value.lower() in {"-o", "/o"}:
                continue
            flags.add(value)
            observations.append({"kind": "flag", "value": value, "path": rel_path.as_posix(), "method": "static_token", "confidence": "candidate"})
        for match in OUTPUT_RE.finditer(text):
            clean_output = _clean_token(match.group(1))
            outputs.add(clean_output)
            observations.append({"kind": "output_candidate", "value": clean_output, "path": rel_path.as_posix(), "method": "static_pattern", "confidence": "candidate"})
        for match in SOURCE_TOKEN_RE.finditer(text):
            source_tokens.add(match.group(0))
    files.sort(key=lambda item: item["path"])
    observations.sort(key=lambda item: (item["path"], item["kind"], str(item["value"])))
    return {
        "schema": SCHEMA,
        "status": "partial" if skipped or issues else ("observed" if files else "not_found"),
        "root": str(root),
        "files": files,
        "skipped": skipped,
        "issues": issues,
        "build_systems": sorted(systems - {"unknown"}),
        "tools": sorted(tools),
        "flags": sorted(flags),
        "output_candidates": sorted(outputs),
        "source_candidates": sorted(source_tokens),
        "compile_commands": compile_units,
        "observations": observations,
        "limitations": ["observações são candidatos textuais, não prova de execução", "compile_commands registra declarações do build, não comprova que compilador/flags foram usados", "flags podem estar condicionais ou mortas", "não resolve toolchain, ambiente, dependências transitivas ou alcançabilidade", "nenhum build/install/script foi executado"],
    }


def write_build_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
