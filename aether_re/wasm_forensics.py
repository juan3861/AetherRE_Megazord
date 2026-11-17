"""Pure-Python WebAssembly (WASM) Binary & Capability Forensics (GEAR-18).

Parses WebAssembly binary modules (\\x00asm v1) offline without external WABT binaries:
  1. Validates WASM magic and version header.
  2. Traverses all 13 standard section types using LEB128 decoding.
  3. Extracts Import table (module, field, kind) and Export table (name, kind, index).
  4. Extracts Custom section names (e.g., 'name', 'producers', '.debug_info').
  5. Extracts printable strings from linear memory Data segments.
  6. Identifies WASI system call capabilities and compiler runtime profiles (Rust/Go/Emscripten).
"""

from __future__ import annotations

import re
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WASM_MAGIC = b"\x00asm"
WASM_VERSION_1 = b"\x01\x00\x00\x00"

SECTION_NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "datacount",
}

IMPORT_EXPORT_KINDS = {
    0: "func",
    1: "table",
    2: "mem",
    3: "global",
}


@dataclass
class WasmForensicsReport:
    file_path: str
    is_wasm: bool
    version: int = 0
    file_size: int = 0
    sections: List[Dict[str, Any]] = field(default_factory=list)
    custom_sections: List[str] = field(default_factory=list)
    imports: List[Dict[str, str]] = field(default_factory=list)
    exports: List[Dict[str, Any]] = field(default_factory=list)
    internal_function_count: int = 0
    code_bytes_total: int = 0
    data_strings: List[str] = field(default_factory=list)
    wasi_capabilities: List[str] = field(default_factory=list)
    runtime_hint: str = "unknown"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _read_uleb128(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 35:
            break
    return result, pos


def _read_wasm_string(data: bytes, pos: int) -> Tuple[str, int]:
    str_len, pos = _read_uleb128(data, pos)
    end = min(pos + str_len, len(data))
    s = data[pos:end].decode("utf-8", errors="replace")
    return s, end


def _skip_limits(data: bytes, pos: int) -> int:
    if pos >= len(data):
        return pos
    flags = data[pos]
    pos += 1
    _, pos = _read_uleb128(data, pos)  # initial
    if flags & 0x01:
        _, pos = _read_uleb128(data, pos)  # maximum
    return pos


def analyze_wasm_bytes(data: bytes, file_path: str = "") -> WasmForensicsReport:
    """Parses a WebAssembly binary module and extracts sections, imports, exports, and strings."""
    report = WasmForensicsReport(
        file_path=file_path,
        is_wasm=len(data) >= 8 and data[:4] == WASM_MAGIC,
        file_size=len(data),
    )

    if not report.is_wasm:
        report.error = "File does not start with \\x00asm magic."
        return report

    report.version = struct.unpack_from("<I", data, 4)[0]
    pos = 8
    n = len(data)

    while pos < n:
        sec_id = data[pos]
        pos += 1
        sec_size, pos = _read_uleb128(data, pos)
        sec_end = min(pos + sec_size, n)
        sec_name = SECTION_NAMES.get(sec_id, f"unknown_{sec_id}")

        report.sections.append(
            {
                "id": sec_id,
                "name": sec_name,
                "offset": pos,
                "size": sec_size,
            }
        )

        sec_buf = data[pos:sec_end]

        try:
            if sec_id == 0 and sec_buf:
                # Custom section: starts with name
                cname, _ = _read_wasm_string(sec_buf, 0)
                if cname:
                    report.custom_sections.append(cname)

            elif sec_id == 2 and sec_buf:
                # Import section
                count, spos = _read_uleb128(sec_buf, 0)
                for _ in range(min(count, 2000)):
                    if spos >= len(sec_buf):
                        break
                    mod_name, spos = _read_wasm_string(sec_buf, spos)
                    field_name, spos = _read_wasm_string(sec_buf, spos)
                    if spos >= len(sec_buf):
                        break
                    kind_id = sec_buf[spos]
                    spos += 1
                    kind_str = IMPORT_EXPORT_KINDS.get(kind_id, f"kind_{kind_id}")
                    if kind_id == 0:  # func type index
                        _, spos = _read_uleb128(sec_buf, spos)
                    elif kind_id == 1:  # tabletype: elemtype + limits
                        spos += 1
                        spos = _skip_limits(sec_buf, spos)
                    elif kind_id == 2:  # memtype: limits
                        spos = _skip_limits(sec_buf, spos)
                    elif kind_id == 3:  # globaltype: valtype + mut
                        spos += 2

                    report.imports.append(
                        {"module": mod_name, "field": field_name, "kind": kind_str}
                    )
                    if "wasi" in mod_name.lower() and field_name not in report.wasi_capabilities:
                        report.wasi_capabilities.append(field_name)

            elif sec_id == 3 and sec_buf:
                # Function section: vector of type indices
                count, _ = _read_uleb128(sec_buf, 0)
                report.internal_function_count = count

            elif sec_id == 7 and sec_buf:
                # Export section
                count, spos = _read_uleb128(sec_buf, 0)
                for _ in range(min(count, 2000)):
                    if spos >= len(sec_buf):
                        break
                    exp_name, spos = _read_wasm_string(sec_buf, spos)
                    if spos >= len(sec_buf):
                        break
                    kind_id = sec_buf[spos]
                    spos += 1
                    idx, spos = _read_uleb128(sec_buf, spos)
                    report.exports.append(
                        {
                            "name": exp_name,
                            "kind": IMPORT_EXPORT_KINDS.get(kind_id, f"kind_{kind_id}"),
                            "index": idx,
                        }
                    )

            elif sec_id == 10 and sec_buf:
                # Code section
                report.code_bytes_total += len(sec_buf)

            elif sec_id == 11 and sec_buf:
                # Data section: extract printable strings
                for match in re.finditer(rb"[ -~]{5,120}", sec_buf):
                    s = match.group(0).decode("ascii", errors="replace").strip()
                    if s and s not in report.data_strings and len(report.data_strings) < 100:
                        report.data_strings.append(s)
        except Exception:
            pass

        pos = sec_end

    # Infer runtime hint
    mod_names = {imp["module"] for imp in report.imports}
    if any("wasi" in m for m in mod_names):
        report.runtime_hint = "wasi"
    elif "go" in mod_names or "gojs" in mod_names:
        report.runtime_hint = "golang-wasm"
    elif "env" in mod_names or "wbg" in mod_names:
        report.runtime_hint = "emscripten-or-wasm-bindgen"
    else:
        report.runtime_hint = "standalone-wasm"

    return report


def scan_file_wasm(file_path: str | Path) -> WasmForensicsReport:
    """Reads a .wasm file from disk and runs offline WASM forensics."""
    p = Path(file_path)
    if not p.is_file():
        return WasmForensicsReport(
            file_path=str(p),
            is_wasm=False,
            error=f"File not found: {p}",
        )
    try:
        return analyze_wasm_bytes(p.read_bytes(), str(p))
    except Exception as exc:
        return WasmForensicsReport(
            file_path=str(p),
            is_wasm=False,
            error=f"Read error: {exc}",
        )
