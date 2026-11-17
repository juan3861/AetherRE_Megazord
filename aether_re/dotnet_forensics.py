"""AetherRE Megazord — .NET / CLR Metadata Stream (BSJB, #Strings, #US) Forensics (GEAR-12).

Pure-static, zero-execution analyzer inspired by dnlib & dotnetfile:
- Locates and parses CLR Metadata Root (BSJB magic 0x424A5342) without external .NET runtime
- Extracts CLR runtime version string and metadata stream directory (#~, #Strings, #US, #GUID, #Blob)
- Extracts UTF-8 identifiers from #Strings and UTF-16LE user literals from #US (User Strings)
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

SCHEMA = "re-megazord-dotnet-forensics.v1"
MAX_DOTNET_BYTES = 256 * 1024 * 1024
_BSJB_MAGIC = 0x424A5342


def _read_compressed_uint(buf: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(buf):
        return 0, pos
    b0 = buf[pos]
    if (b0 & 0x80) == 0:
        return b0, pos + 1
    if (b0 & 0xC0) == 0x80 and pos + 1 < len(buf):
        return ((b0 & 0x3F) << 8) | buf[pos + 1], pos + 2
    if (b0 & 0xE0) == 0xC0 and pos + 3 < len(buf):
        return (
            ((b0 & 0x1F) << 24) | (buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3],
            pos + 4,
        )
    return 0, pos + 1


def analyze_dotnet_metadata(data: bytes) -> dict[str, Any]:
    """Parse CLR BSJB metadata header and extract #Strings and #US streams."""
    if not isinstance(data, (bytes, bytearray)):
        return {"schema": SCHEMA, "status": "invalid", "code": "bytes_required"}
    blob = bytes(data)
    if len(blob) > MAX_DOTNET_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "input_too_large"}
    if len(blob) < 32:
        return {"schema": SCHEMA, "status": "invalid", "code": "too_small"}

    bsjb_off = blob.find(b"BSJB")
    if bsjb_off == -1 or bsjb_off + 20 > len(blob):
        return {"schema": SCHEMA, "status": "not_dotnet", "is_dotnet": False, "streams": []}

    sig, major, minor, _, ver_len = struct.unpack_from("<IHHII", blob, bsjb_off)
    if sig != _BSJB_MAGIC or ver_len > 256 or bsjb_off + 16 + ver_len + 4 > len(blob):
        return {"schema": SCHEMA, "status": "invalid_bsjb_header", "is_dotnet": False, "streams": []}

    runtime_version = blob[bsjb_off + 16:bsjb_off + 16 + ver_len].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    flags_pos = bsjb_off + 16 + ver_len
    _, num_streams = struct.unpack_from("<HH", blob, flags_pos)
    if num_streams > 32:
        return {"schema": SCHEMA, "status": "invalid_stream_count", "is_dotnet": True, "streams": []}

    pos = flags_pos + 4
    streams: list[dict[str, Any]] = []
    strings_list: list[str] = []
    user_strings: list[str] = []

    for _ in range(num_streams):
        if pos + 8 > len(blob):
            break
        s_off, s_size = struct.unpack_from("<II", blob, pos)
        pos += 8
        name_end = blob.find(b"\x00", pos, min(len(blob), pos + 32))
        if name_end == -1:
            break
        s_name = blob[pos:name_end].decode("utf-8", errors="replace")
        # Padded to 4-byte boundary
        name_len_padded = ((name_end - pos + 1) + 3) & ~3
        pos += name_len_padded

        abs_start = bsjb_off + s_off
        abs_end = min(len(blob), abs_start + s_size)
        streams.append({"name": s_name, "offset": abs_start, "size": s_size})

        if abs_start < abs_end and s_size <= 16 * 1024 * 1024:
            s_data = blob[abs_start:abs_end]
            if s_name == "#Strings":
                for item in s_data.split(b"\x00"):
                    if item:
                        txt = item.decode("utf-8", errors="replace")
                        strings_list.append(txt[:256])
                        if len(strings_list) >= 2000:
                            break
            elif s_name == "#US":
                u_pos = 1  # skip initial 0x00 byte
                while u_pos < len(s_data) and len(user_strings) < 1000:
                    byte_len, next_pos = _read_compressed_uint(s_data, u_pos)
                    if byte_len == 0 or next_pos + byte_len > len(s_data):
                        u_pos = max(u_pos + 1, next_pos)
                        continue
                    raw_str = s_data[next_pos:next_pos + byte_len - (1 if byte_len % 2 == 1 else 0)]
                    try:
                        decoded = raw_str.decode("utf-16-le", errors="replace")
                        if decoded:
                            user_strings.append(decoded[:256])
                    except Exception:
                        pass
                    u_pos = next_pos + byte_len

    return {
        "schema": SCHEMA,
        "status": "complete",
        "is_dotnet": True,
        "clr_version": f"{major}.{minor}",
        "runtime_version": runtime_version,
        "total_streams": len(streams),
        "streams": streams,
        "total_strings": len(strings_list),
        "strings": strings_list,
        "total_user_strings": len(user_strings),
        "user_strings": user_strings,
    }


def scan_file_dotnet(target: str | Path) -> dict[str, Any]:
    path = Path(target)
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")
    if path.stat().st_size > MAX_DOTNET_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "file_too_large", "target": str(path)}
    report = analyze_dotnet_metadata(path.read_bytes())
    report["target"] = str(path)
    return report
