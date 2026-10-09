"""Leitura opcional e explícita de símbolos PDB via DIA SDK no Windows.

O módulo não executa o binário analisado. Ele chama somente um helper DIA
fornecido pelo operador, registra hashes dos componentes e falha fechado se
helper/DLL/PDB não puderem ser verificados.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from aether_re.process import run_bounded

SCHEMA = "re-megazord-dia-symbols.v1"
_MAX_OUTPUT = 64 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink()
    except OSError:
        return False


def _unavailable(code: str, *, pdb_path: Path, helper_path: Path, dia_dll: Path, detail: str = "") -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "unavailable",
        "code": code,
        "pdb": str(pdb_path),
        "helper": str(helper_path),
        "dia_dll": str(dia_dll),
        "detail": detail,
        "symbols": [],
        "count": 0,
        "truncated": False,
        "executed_target": False,
    }


def extract_pdb_symbols(
    pdb_path: Path,
    *,
    helper_path: Path,
    dia_dll: Path,
    timeout: float = 90.0,
    max_symbols: int = 50_000,
    memory_limit_mb: int = 512,
) -> dict[str, Any]:
    """Extract function symbols from one PDB using an explicit DIA helper.

    The helper is treated as an analysis tool, never as the target. Its JSON
    output is bounded and authenticated by the helper/DIA/PDB hashes.
    """
    pdb_path = Path(pdb_path).resolve()
    helper_path = Path(helper_path).resolve()
    dia_dll = Path(dia_dll).resolve()
    if os.name != "nt":
        return _unavailable("windows_required", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    if not _regular(pdb_path):
        return _unavailable("pdb_invalid", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    if not _regular(helper_path):
        return _unavailable("helper_invalid", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    if not _regular(dia_dll):
        return _unavailable("dia_dll_invalid", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    if isinstance(max_symbols, bool) or not isinstance(max_symbols, int) or not 1 <= max_symbols <= 1_000_000:
        return _unavailable("max_symbols_invalid", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    try:
        proc = run_bounded(
            [helper_path, dia_dll, pdb_path, str(max_symbols)],
            timeout=float(timeout),
            memory_limit_mb=memory_limit_mb,
        )
    except (OSError, ValueError) as exc:
        return _unavailable("helper_spawn_failed", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll, detail=type(exc).__name__)
    stdout = str(proc.get("stdout") or "")
    if len(stdout.encode("utf-8", errors="replace")) > _MAX_OUTPUT:
        return _unavailable("helper_output_too_large", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    if proc.get("timed_out"):
        return _unavailable("helper_timeout", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    if proc.get("resource_exceeded"):
        return _unavailable("helper_resource_exceeded", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    try:
        raw = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        return _unavailable("helper_json_invalid", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll, detail=str(proc.get("stderr") or "")[-400:])
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA or raw.get("status") != "complete":
        return _unavailable("helper_report_invalid", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll, detail=str(raw.get("code", "unknown")) if isinstance(raw, dict) else "not_object")
    symbols = raw.get("symbols")
    if not isinstance(symbols, list) or any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in symbols):
        return _unavailable("helper_symbols_invalid", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    return {
        **raw,
        "pdb": str(pdb_path),
        "pdb_sha256": _sha256(pdb_path),
        "helper": str(helper_path),
        "helper_sha256": _sha256(helper_path),
        "dia_dll": str(dia_dll),
        "dia_dll_sha256": _sha256(dia_dll),
        "returncode": proc.get("returncode"),
        "stderr_tail": str(proc.get("stderr") or "")[-400:],
        "executed_target": False,
    }


def write_pdb_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
