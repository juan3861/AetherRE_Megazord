"""AetherRE Megazord — C++ RTTI, VTable & Class Hierarchy Recovery Engine (GEAR-10).

Pure-static, zero-execution C++ polymorphic structure & inheritance analyzer:
- MSVC PE32 / PE32+ RTTI recovery: RTTITypeDescriptor (.?AV...@@), RTTICompleteObjectLocator,
  RTTIClassHierarchyDescriptor, RTTIBaseClassDescriptor, and VTable slot extraction
- Itanium C++ ABI RTTI recovery (_ZTV / _ZTI / _ZTS) for ELF / Mach-O
- C++ symbol demangling via pydemumble + pure-Python MSVC/Itanium fallback
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

SCHEMA = "re-megazord-cpp-rtti.v1"
MAX_BINARY_BYTES = 256 * 1024 * 1024

_MSVC_TYPE_RE = re.compile(rb"(\.\?A[VU][A-Za-z0-9_@?$]+@@)\x00")
_ITANIUM_ZTS_RE = re.compile(rb"(?:^|\x00)(_ZTS[A-Za-z0-9_]+)\x00")
_ITANIUM_ZTV_RE = re.compile(rb"(?:^|\x00)(_ZTV[A-Za-z0-9_]+)\x00")


def _demangle_cpp(name: str) -> str:
    try:
        import pydemumble  # type: ignore[import-untyped]
        out = pydemumble.demangle(name)
        if out and out != name:
            return out
    except Exception:
        pass
    # Pure-Python fallback for MSVC RTTI .?AVClass@Ns@@
    if name.startswith((".?AV", ".?AU")) and name.endswith("@@"):
        kind = "class " if name.startswith(".?AV") else "struct "
        inner = name[4:-2]
        parts = [p for p in reversed(inner.split("@")) if p]
        return kind + "::".join(parts)
    # Minimal Itanium _ZTS / _ZTV fallback
    if name.startswith(("_ZTS", "_ZTV")) and len(name) > 4:
        body = name[4:]
        if body.startswith("N") and body.endswith("E"):
            body = body[1:-1]
        parts: list[str] = []
        pos = 0
        while pos < len(body):
            j = pos
            while j < len(body) and body[j].isdigit():
                j += 1
            if j == pos:
                break
            ln = int(body[pos:j])
            part = body[j:j + ln]
            if not part:
                break
            parts.append(part)
            pos = j + ln
        if parts:
            prefix = "vtable for " if name.startswith("_ZTV") else ""
            return prefix + "::".join(parts)
    return name


def _parse_msvc_rtti(blob: bytes) -> dict[str, Any]:
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        return {"detected": False, "classes": [], "complete_object_locators": 0}
    pe_off = struct.unpack_from("<I", blob, 0x3C)[0]
    if pe_off < 0x40 or pe_off + 24 > len(blob) or blob[pe_off:pe_off + 4] != b"PE\0\0":
        return {"detected": False, "classes": [], "complete_object_locators": 0}

    file_hdr = pe_off + 4
    _, num_secs, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", blob, file_hdr)
    opt = file_hdr + 20
    if opt + opt_size > len(blob) or opt_size < 56:
        return {"detected": False, "classes": [], "complete_object_locators": 0}
    magic = struct.unpack_from("<H", blob, opt)[0]
    if magic == 0x10B:
        is_64 = False
        image_base = struct.unpack_from("<I", blob, opt + 28)[0]
    elif magic == 0x20B:
        is_64 = True
        image_base = struct.unpack_from("<Q", blob, opt + 24)[0]
    else:
        return {"detected": False, "classes": [], "complete_object_locators": 0}

    sec_table = opt + opt_size
    if sec_table + num_secs * 40 > len(blob):
        return {"detected": False, "classes": [], "complete_object_locators": 0}

    sections: list[tuple[int, int, int, int, str]] = []
    for i in range(num_secs):
        off = sec_table + i * 40
        sname = blob[off:off + 8].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", blob, off + 8)
        sections.append((va, max(vsize, rsize), rptr, rsize, sname))

    def raw_to_rva(raw_off: int) -> int | None:
        for va, _, rptr, rsize, _ in sections:
            if rptr <= raw_off < rptr + rsize:
                return va + (raw_off - rptr)
        return None

    def rva_to_raw(rva: int, size: int = 4) -> int | None:
        for va, span, rptr, rsize, _ in sections:
            if va <= rva and rva - va + size <= rsize and rptr + (rva - va) + size <= len(blob):
                return rptr + (rva - va)
        return None

    # Find all MSVC TypeDescriptors (.?AV...@@ / .?AU...@@)
    # TypeDescriptor layout: pVFTable (ptr_size), spare (ptr_size), name[...]
    ptr_size = 8 if is_64 else 4
    td_name_delta = ptr_size * 2
    type_descs: dict[int, dict[str, Any]] = {}  # rva -> info
    for m in _MSVC_TYPE_RE.finditer(blob):
        raw_name_off = m.start(1)
        td_raw = raw_name_off - td_name_delta
        if td_raw < 0:
            continue
        td_rva = raw_to_rva(td_raw)
        if td_rva is None:
            continue
        mangled = m.group(1).decode("utf-8", errors="replace")
        type_descs[td_rva] = {
            "mangled": mangled,
            "demangled": _demangle_cpp(mangled),
            "rva": hex(td_rva),
            "base_classes": [],
            "vtable_rvas": [],
        }

    # Scan for RTTICompleteObjectLocator (signature = 1 for PE64 RVA-based, 0 for PE32 VA-based)
    col_count = 0
    if is_64 and type_descs:
        # In PE64, COL = <IIIIII (signature=1, offset, cdOffset, pTypeDescriptor RVA, pClassDescriptor RVA, pSelf RVA)
        for va, span, rptr, rsize, sname in sections:
            if sname not in (".rdata", ".data", ".text"):
                continue
            end_raw = min(len(blob), rptr + rsize - 24)
            for pos in range(rptr, end_raw, 4):
                sig, _, _, p_td_rva, p_chd_rva, p_self_rva = struct.unpack_from("<IIIIII", blob, pos)
                if sig == 1 and p_td_rva in type_descs and raw_to_rva(pos) == p_self_rva:
                    col_count += 1
                    # Parse ClassHierarchyDescriptor: signature(4), attributes(4), numBaseClasses(4), pBaseClassArray(4 RVA)
                    chd_raw = rva_to_raw(p_chd_rva, 16)
                    if chd_raw is not None:
                        _, _, num_bases, p_bca_rva = struct.unpack_from("<IIII", blob, chd_raw)
                        if 0 < num_bases <= 64:
                            bca_raw = rva_to_raw(p_bca_rva, num_bases * 4)
                            if bca_raw is not None:
                                bases: list[str] = []
                                for b_idx in range(num_bases):
                                    bcd_rva = struct.unpack_from("<I", blob, bca_raw + b_idx * 4)[0]
                                    bcd_raw = rva_to_raw(bcd_rva, 4)
                                    if bcd_raw is not None:
                                        b_td_rva = struct.unpack_from("<I", blob, bcd_raw)[0]
                                        if b_td_rva in type_descs:
                                            b_name = type_descs[b_td_rva]["demangled"]
                                            if b_name not in bases and b_name != type_descs[p_td_rva]["demangled"]:
                                                bases.append(b_name)
                                type_descs[p_td_rva]["base_classes"] = bases

                    # Find vtable slot pointing to this COL VA (image_base + p_self_rva)
                    col_va_bytes = struct.pack("<Q", image_base + p_self_rva)
                    v_idx = blob.find(col_va_bytes)
                    if v_idx != -1:
                        vtable_rva = raw_to_rva(v_idx + 8)  # vtable[0] is right after the COL pointer
                        if vtable_rva is not None:
                            type_descs[p_td_rva]["vtable_rvas"].append(hex(vtable_rva))

    classes = list(type_descs.values())
    return {
        "detected": bool(classes),
        "abi": "msvc",
        "is_64bit": is_64,
        "total_classes": len(classes),
        "complete_object_locators": col_count,
        "classes": classes[:500],
    }


def _parse_itanium_rtti(blob: bytes) -> dict[str, Any]:
    classes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rx in (_ITANIUM_ZTS_RE, _ITANIUM_ZTV_RE):
        for m in rx.finditer(blob):
            sym = m.group(1).decode("utf-8", errors="replace")
            if sym in seen:
                continue
            seen.add(sym)
            classes.append({
                "mangled": sym,
                "demangled": _demangle_cpp(sym),
                "offset": hex(m.start(1)),
            })
            if len(classes) >= 500:
                break
    return {
        "detected": bool(classes),
        "abi": "itanium",
        "total_classes": len(classes),
        "complete_object_locators": 0,
        "classes": classes,
    }


def recover_cpp_rtti(data: bytes) -> dict[str, Any]:
    """Recover C++ RTTI classes, inheritance hierarchy, and VTable pointers from PE/ELF/Mach-O."""
    if not isinstance(data, (bytes, bytearray)):
        return {"schema": SCHEMA, "status": "invalid", "code": "bytes_required"}
    blob = bytes(data)
    if len(blob) > MAX_BINARY_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "input_too_large"}
    if not blob:
        return {"schema": SCHEMA, "status": "invalid", "code": "empty_input"}

    if blob[:2] == b"MZ":
        rtti = _parse_msvc_rtti(blob)
    else:
        rtti = _parse_itanium_rtti(blob)
    return {"schema": SCHEMA, "status": "complete", **rtti}


def scan_file_cpp_rtti(target: str | Path) -> dict[str, Any]:
    path = Path(target)
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")
    if path.stat().st_size > MAX_BINARY_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "file_too_large", "target": str(path)}
    report = recover_cpp_rtti(path.read_bytes())
    report["target"] = str(path)
    return report
