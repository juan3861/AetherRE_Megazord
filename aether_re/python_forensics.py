"""AetherRE Megazord — Python Bytecode (.pyc) & PyInstaller CArchive Forensics (GEAR-08).

Pure-static, zero-execution analyzer inspired by pyinstxtractor and python-xdis:
- .pyc header parsing (magic -> Python 3.8..3.14 version, timestamp vs PEP 552 hash-based)
- Recursive CodeType inspection (functions, co_names, string constants, disassembled opcodes)
- PyInstaller CArchive (MEI\\x0c\\x0b\\x0a\\x0b\\x0e) cookie & full Table of Contents (TOC) extraction
"""

from __future__ import annotations

import dis
import marshal
import struct
import zlib
from pathlib import Path
from typing import Any

SCHEMA = "re-megazord-python-forensics.v1"
MAX_PY_BYTES = 256 * 1024 * 1024

# Common CPython 3.8..3.14 magic numbers (little-endian uint16)
_PYC_MAGICS = {
    3413: "3.8",
    3425: "3.9",
    3439: "3.10",
    3495: "3.11",
    3531: "3.12",
    3571: "3.13",
    3627: "3.14",
}

_PYINST_COOKIE_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"


def _walk_code_object(code_obj: Any, *, max_depth: int = 12, max_nodes: int = 1000) -> dict[str, Any]:
    functions: list[dict[str, Any]] = []
    names: set[str] = set()
    strings: list[str] = []
    seen_strings: set[str] = set()

    def _visit(obj: Any, depth: int) -> None:
        if depth > max_depth or len(functions) >= max_nodes:
            return
        if not hasattr(obj, "co_code"):
            return
        insns_count = 0
        try:
            insns_count = sum(1 for _ in dis.get_instructions(obj))
        except Exception:
            pass
        functions.append({
            "name": getattr(obj, "co_name", "<unknown>"),
            "qualname": getattr(obj, "co_qualname", getattr(obj, "co_name", "<unknown>")),
            "filename": getattr(obj, "co_filename", ""),
            "firstlineno": int(getattr(obj, "co_firstlineno", 0)),
            "argcount": int(getattr(obj, "co_argcount", 0)),
            "varnames": list(getattr(obj, "co_varnames", ()))[:64],
            "instruction_count": insns_count,
        })
        for n in getattr(obj, "co_names", ()):
            if isinstance(n, str):
                names.add(n)
        for c in getattr(obj, "co_consts", ()):
            if hasattr(c, "co_code"):
                _visit(c, depth + 1)
            elif isinstance(c, str) and c and c not in seen_strings and len(strings) < 500:
                seen_strings.add(c)
                strings.append(c[:256])

    _visit(code_obj, 0)
    return {
        "total_code_objects": len(functions),
        "code_objects": functions,
        "referenced_names": sorted(names)[:500],
        "string_constants": strings,
    }


def analyze_pyc(data: bytes) -> dict[str, Any]:
    """Parse a .pyc file header and walk its marshaled code object without executing it."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 16:
        return {"schema": SCHEMA, "kind": "pyc", "status": "invalid", "code": "pyc_too_small"}
    blob = bytes(data)
    magic_num, tail = struct.unpack_from("<HH", blob, 0)
    if tail != 0x0A0D:
        return {"schema": SCHEMA, "kind": "pyc", "status": "invalid", "code": "not_pyc_magic"}

    bitfield = struct.unpack_from("<I", blob, 4)[0]
    py_ver = _PYC_MAGICS.get(magic_num, f"unknown_{magic_num}")
    hash_based = bool(bitfield & 0x1)

    try:
        code_obj = marshal.loads(blob[16:])
    except Exception as exc:
        return {
            "schema": SCHEMA,
            "kind": "pyc",
            "status": "marshal_error",
            "python_version": py_ver,
            "magic_number": magic_num,
            "hash_based": hash_based,
            "error": str(exc),
        }

    walked = _walk_code_object(code_obj)
    return {
        "schema": SCHEMA,
        "kind": "pyc",
        "status": "complete",
        "python_version": py_ver,
        "magic_number": magic_num,
        "hash_based": hash_based,
        **walked,
    }


def analyze_pyinstaller_carchive(data: bytes) -> dict[str, Any]:
    """Detect and parse PyInstaller CArchive cookie and complete Table of Contents (TOC)."""
    if not isinstance(data, (bytes, bytearray)):
        return {"schema": SCHEMA, "kind": "pyinstaller", "status": "invalid", "code": "bytes_required"}
    blob = bytes(data)
    if len(blob) > MAX_PY_BYTES:
        return {"schema": SCHEMA, "kind": "pyinstaller", "status": "invalid", "code": "input_too_large"}

    cookie_idx = blob.rfind(_PYINST_COOKIE_MAGIC)
    if cookie_idx == -1:
        return {"schema": SCHEMA, "kind": "pyinstaller", "status": "not_pyinstaller", "entries": []}

    # Try v2.1+ cookie (88 bytes: magic(8) + pkg_len(4) + toc_off(4) + toc_len(4) + pyver(4) + pylibname(64))
    # or v2.0 cookie (24 bytes: magic(8) + pkg_len(4) + toc_off(4) + toc_len(4) + pyver(4))
    if cookie_idx + 88 <= len(blob):
        pkg_len, toc_off, toc_len, pyver = struct.unpack_from(">IIII", blob, cookie_idx + 8)
        pylib = blob[cookie_idx + 24:cookie_idx + 88].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        cookie_size = 88
    elif cookie_idx + 24 <= len(blob):
        pkg_len, toc_off, toc_len, pyver = struct.unpack_from(">IIII", blob, cookie_idx + 8)
        pylib = None
        cookie_size = 24
    else:
        return {"schema": SCHEMA, "kind": "pyinstaller", "status": "invalid_cookie", "entries": []}

    overlay_start = (cookie_idx + cookie_size) - pkg_len
    toc_start = overlay_start + toc_off
    toc_end = toc_start + toc_len
    if overlay_start < 0 or toc_start < 0 or toc_end > len(blob) or toc_len > 32 * 1024 * 1024:
        return {"schema": SCHEMA, "kind": "pyinstaller", "status": "invalid_toc_bounds", "entries": []}

    entries: list[dict[str, Any]] = []
    pos = toc_start
    while pos + 18 <= toc_end and len(entries) < 20000:
        entry_size, entry_pos, cmpr_len, uncmpr_len, cmpr_flag, typecd = struct.unpack_from(">IIIIBB", blob, pos)
        if entry_size < 18 or pos + entry_size > toc_end:
            break
        name = blob[pos + 18:pos + entry_size].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        entries.append({
            "name": name,
            "offset": overlay_start + entry_pos,
            "compressed_size": cmpr_len,
            "uncompressed_size": uncmpr_len,
            "compressed": bool(cmpr_flag),
            "typecode": chr(typecd) if 32 <= typecd < 127 else hex(typecd),
        })
        pos += entry_size

    return {
        "schema": SCHEMA,
        "kind": "pyinstaller",
        "status": "complete",
        "python_version_code": pyver,
        "pylib_name": pylib,
        "pkg_length": pkg_len,
        "total_entries": len(entries),
        "entries": entries,
    }


def scan_file_python_artifact(target: str | Path) -> dict[str, Any]:
    path = Path(target)
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")
    if path.stat().st_size > MAX_PY_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "file_too_large", "target": str(path)}
    blob = path.read_bytes()
    if len(blob) >= 16 and blob[2:4] == b"\r\n":
        report = analyze_pyc(blob)
    else:
        report = analyze_pyinstaller_carchive(blob)
    report["target"] = str(path)
    return report
