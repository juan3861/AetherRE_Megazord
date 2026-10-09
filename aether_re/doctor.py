"""Diagnóstico de capacidades sem instalar ferramentas ou executar alvos."""

from __future__ import annotations

import os
import importlib.metadata
import importlib.util
import shutil
import sys
from pathlib import Path
from typing import Any

from aether_re.process import run_bounded


KNOWN_PATHS = {
    "python": [sys.executable, r"C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe", r"C:\Users\juanp\AppData\Local\Programs\Python\Python311\python.exe"],
    "java": [r"C:\Program Files\Android\Android Studio\jbr\bin\java.exe"],
    "clang": [r"C:\Program Files\LLVM\bin\clang.exe"],
    "rizin": [r"C:\Program Files\Rizin\bin\rizin.exe"],
}


def _find(name: str) -> str | None:
    for candidate in [shutil.which(name), *KNOWN_PATHS.get(name, [])]:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate).resolve())
    return None


def diagnose_tools() -> dict[str, Any]:
    tools = {}
    for name, commands in {"python": ["--version"], "java": ["-version"], "clang": ["--version"], "rizin": ["-v"]}.items():
        path = _find(name)
        result: dict[str, Any] = {"available": bool(path), "path": path, "version": None}
        if path:
            try:
                proc = run_bounded([path, *commands], timeout=3)
                result["version"] = (proc["stdout"] or proc["stderr"]).splitlines()[0][:200] if proc["returncode"] == 0 else None
                result["version_probe_returncode"] = proc["returncode"]
                result["version_probe_timed_out"] = proc["timed_out"]
            except OSError as exc:
                result["version_probe_error"] = str(exc)
        tools[name] = result
    ghidra_home = Path(os.environ.get("GHIDRA_HOME", r"D:\AetherRE_Megazord\tools\ghidra_12.1.2_PUBLIC"))
    tools["ghidra"] = {"available": any(ghidra_home.rglob(name) for name in ("analyzeHeadless.bat", "analyzeHeadless")) if ghidra_home.is_dir() else False, "path": str(ghidra_home) if ghidra_home.is_dir() else None}
    modules: dict[str, Any] = {}
    for module, distribution in {"pefile": "pefile", "capstone": "capstone", "unicorn": "unicorn", "frida": "frida", "angr": "angr", "binaryninja": "binaryninja", "elftools": "pyelftools"}.items():
        try:
            present = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            present = False
        version = None
        if present:
            try:
                version = importlib.metadata.version(distribution)
            except importlib.metadata.PackageNotFoundError:
                version = None
        modules[module] = {"available": present, "distribution": distribution, "version": version}
    return {"schema": "megazord-doctor.v1", "tools": tools, "python_modules": modules, "platform": {"python": sys.version.split()[0], "os": os.name}, "limitations": ["presença e --version/find_spec não provam integração/análise", "não instala dependências", "não executa alvo"], "status": "ok"}
