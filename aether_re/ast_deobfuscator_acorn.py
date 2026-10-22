"""Reverse Engineering Graph (AetherRE) — Acorn-Powered ESTree AST Deobfuscator.

Executes true JavaScript Abstract Syntax Tree (AST) deobfuscation using Acorn,
preventing regex syntax corruption, properly handling nested braces, and preserving
string literals and regular expressions without guesswork.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
WORKER_SCRIPT = WORKSPACE_ROOT / "tools" / "acorn_ast_worker.cjs"


def deobfuscate_with_acorn_ast(
    input_file: Path | str,
    output_file: Path | str | None = None,
) -> dict[str, Any]:
    """Runs the Acorn AST worker on a JavaScript module."""
    in_path = Path(input_file).resolve()
    if not in_path.exists():
        raise FileNotFoundError(f"Source file not found: {in_path}")

    cmd = ["node", str(WORKER_SCRIPT), str(in_path)]
    if output_file:
        out_path = Path(output_file).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        cmd.append(str(out_path))

    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    try:
        data = json.loads(res.stdout.strip())
        return data
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid output from acorn worker: {res.stdout}") from exc


def deobfuscate_code_snippet_ast(code: str) -> dict[str, Any]:
    """Deobfuscates an in-memory JS snippet via temp file and Acorn AST."""
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as tf:
        tf.write(code)
        temp_in = Path(tf.name)

    temp_out = temp_in.with_suffix(".deobf.js")
    try:
        res = deobfuscate_with_acorn_ast(temp_in, temp_out)
        res["deobfuscated_code"] = temp_out.read_text(encoding="utf-8")
        return res
    finally:
        temp_in.unlink(missing_ok=True)
        temp_out.unlink(missing_ok=True)
