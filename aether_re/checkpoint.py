"""Checkpoints atômicos e idempotentes para retomada de uma análise."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def write_checkpoint(path: Path, state: dict[str, Any]) -> None:
    """Publica um checkpoint completo sem deixar JSON parcialmente gravado."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(state, handle, indent=2, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def read_checkpoint(path: Path) -> dict[str, Any] | None:
    """Lê checkpoint válido; JSON truncado é tratado como ausente, não executado."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None
