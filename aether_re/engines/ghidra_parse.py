"""Parse Ghidra decompilation exports into function-level evidence."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from aether_re.models import FunctionEvidence


MARKER_RE = re.compile(
    r"/\*\s*(?P<name>[^@\s]+)\s*@\s*(?P<address>(?:0x)?[0-9A-Fa-f]+)\s*\*/"
)
CALL_RE = re.compile(r"\b([A-Za-z_][\w:]*|FUN_[0-9A-Fa-f]+)\s*\(")
STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')
WARNING_RE = re.compile(r"WARNING:\s*(.+)")


def normalize_address(value: object) -> str:
    raw = str(value or "").strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not raw:
        return ""
    try:
        return f"0x{int(raw, 16):x}"
    except ValueError:
        return f"0x{raw.lstrip('0') or '0'}"


def _safe_name(name: str, address: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if cleaned:
        return cleaned[:128]
    return f"sub_{address.removeprefix('0x')}"


def parse_decompiled_text(text: str) -> list[FunctionEvidence]:
    matches = list(MARKER_RE.finditer(text))
    functions: list[FunctionEvidence] = []
    for index, marker in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        pseudocode = text[marker.end() : end].strip()
        address = normalize_address(marker.group("address"))
        name = _safe_name(marker.group("name"), address)
        calls = sorted(
            {
                call
                for call in CALL_RE.findall(pseudocode)
                if call != name and not call.startswith(("if", "for", "while", "switch", "return"))
            }
        )
        warnings = [warning.group(1).strip() for warning in WARNING_RE.finditer(pseudocode)]
        strings = [value.group(0)[:160] for value in STRING_RE.finditer(pseudocode)][:30]
        functions.append(
            FunctionEvidence(
                address=address,
                name=name,
                source="ghidra",
                confidence=0.95 if pseudocode else 0.5,
                quality=0.95 if pseudocode else 0.4,
                coverage=1.0 if pseudocode else 0.3,
                pseudocode=pseudocode,
                calls=calls,
                strings_near=strings,
                notes="Ghidra headless decompilation",
                warnings=warnings,
                raw={"segment_length": len(pseudocode)},
            )
        )
    return functions


def parse_decompiled_file(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return [function.to_dict() for function in parse_decompiled_text(text)]


def write_function_index(functions: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(functions, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
