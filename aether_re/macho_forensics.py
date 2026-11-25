"""AetherRE Megazord — Deep Mach-O, CodeSignature, Entitlements & ObjC/Swift Forensics (GEAR-05).

Pure-static, zero-execution parser for Mach-O 32/64 & Fat/Universal binaries:
- CPU type, filetype, PIE/NX flags, segments, sections, dylibs, UUID, LC_MAIN entrypoint
- LC_CODE_SIGNATURE SuperBlob parsing (CodeDirectory cdhash/identifier/team_id, Entitlements XML, CMS)
- Symbol table (.symtab) & Objective-C / Swift symbol extraction
"""

from __future__ import annotations

import hashlib
import re
import struct
from pathlib import Path
from typing import Any

SCHEMA = "re-megazord-macho-forensics.v1"
MAX_MACHO_BYTES = 256 * 1024 * 1024

_MH_MAGIC = 0xFEEDFACE
_MH_CIGAM = 0xCEFAEDFE
_MH_MAGIC_64 = 0xFEEDFACF
_MH_CIGAM_64 = 0xCFFAEDFE
_FAT_MAGIC = 0xCAFEBABE
_FAT_CIGAM = 0xBEBAFECA

_LC_REQ_DYLD = 0x80000000
_LC_SEGMENT = 0x1
_LC_SYMTAB = 0x2
_LC_UUID = 0x1B
_LC_LOAD_DYLIB = 0xC
_LC_LOAD_WEAK_DYLIB = 0x18 | _LC_REQ_DYLD
_LC_SEGMENT_64 = 0x19
_LC_CODE_SIGNATURE = 0x1D
_LC_ENCRYPTION_INFO_64 = 0x2C
_LC_MAIN = 0x28 | _LC_REQ_DYLD
_LC_BUILD_VERSION = 0x32

_CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
_CSMAGIC_CODEDIRECTORY = 0xFADE0C02
_CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
_CSMAGIC_BLOBWRAPPER = 0xFADE0B01

_CPU_TYPES = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
}

_FILE_TYPES = {
    1: "MH_OBJECT",
    2: "MH_EXECUTE",
    6: "MH_DYLIB",
    8: "MH_BUNDLE",
}


def _cstr(buf: bytes, offset: int, limit: int = 256) -> str:
    if offset < 0 or offset >= len(buf):
        return ""
    end = buf.find(b"\x00", offset, min(len(buf), offset + limit))
    if end == -1:
        end = min(len(buf), offset + limit)
    return buf[offset:end].decode("utf-8", errors="replace")


def _parse_code_signature(blob: bytes, cs_off: int, cs_size: int) -> dict[str, Any]:
    if cs_off <= 0 or cs_size < 12 or cs_off + cs_size > len(blob):
        return {"present": False}
    sub = blob[cs_off:cs_off + cs_size]
    magic, length, count = struct.unpack_from(">III", sub, 0)
    if magic != _CSMAGIC_EMBEDDED_SIGNATURE or count > 64 or 12 + count * 8 > len(sub):
        return {"present": True, "valid_superblob": False}

    result: dict[str, Any] = {
        "present": True,
        "valid_superblob": True,
        "superblob_length": length,
        "code_directory": None,
        "entitlements_xml": None,
        "entitlement_keys": [],
        "cms_signature_bytes": 0,
    }
    for i in range(count):
        slot_type, slot_off = struct.unpack_from(">II", sub, 12 + i * 8)
        if slot_off + 8 > len(sub):
            continue
        b_magic, b_len = struct.unpack_from(">II", sub, slot_off)
        if b_len < 8 or slot_off + b_len > len(sub):
            continue
        b_data = sub[slot_off:slot_off + b_len]

        if b_magic == _CSMAGIC_CODEDIRECTORY and b_len >= 44:
            # CodeDirectory header (big-endian)
            version, flags, hash_off, ident_off, n_special, n_code, code_limit, hash_size, hash_type = struct.unpack_from(
                ">IIIIIIIBB", b_data, 8
            )
            ident = _cstr(b_data, ident_off)
            team_id = None
            if version >= 0x20200 and b_len >= 52:
                team_off = struct.unpack_from(">I", b_data, 48)[0]
                if 0 < team_off < b_len:
                    team_id = _cstr(b_data, team_off)
            result["code_directory"] = {
                "version": hex(version),
                "flags": hex(flags),
                "adhoc": bool(flags & 0x2),
                "hardened_runtime": bool(flags & 0x10000),
                "identifier": ident,
                "team_id": team_id,
                "cdhash_sha256": hashlib.sha256(b_data).hexdigest()[:40],
            }
        elif b_magic == _CSMAGIC_EMBEDDED_ENTITLEMENTS:
            xml_text = b_data[8:].decode("utf-8", errors="replace").strip("\x00")
            keys = re.findall(r"<key>([^<]+)</key>", xml_text)
            result["entitlements_xml"] = xml_text[:16384]
            result["entitlement_keys"] = keys
        elif b_magic == _CSMAGIC_BLOBWRAPPER:
            result["cms_signature_bytes"] = b_len - 8
    return result


def _va_to_file_offset(va: int, segments: list[dict[str, Any]], base_offset: int) -> int | None:
    for seg in segments:
        sva = int(seg["vmaddr"], 16)
        vsz = int(seg.get("vmsize", 0) or 0)
        foff = int(seg.get("fileoff", 0) or 0)
        if sva <= va < sva + vsz:
            return base_offset + foff + (va - sva)
    return None


def _extract_objc_swift_metadata(
    blob: bytes,
    base_offset: int,
    endian: str,
    is_64: bool,
    segments: list[dict[str, Any]],
    sections: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parses structured Objective-C classes (`__objc_classlist`) and Swift 5 descriptors (`__swift5_types`)."""
    objc_structured: list[dict[str, Any]] = []
    swift_descriptors: list[dict[str, Any]] = []
    ptr_fmt = f"{endian}{'Q' if is_64 else 'I'}"

    sec_by_name = {s["section"]: s for s in sections}
    cls_sec = sec_by_name.get("__objc_classlist")
    if cls_sec and is_64 and cls_sec["size"] >= 8:
        abs_off = base_offset + int(cls_sec["offset"])
        n_ptrs = min(cls_sec["size"] // 8, 256)
        for idx in range(n_ptrs):
            if abs_off + (idx + 1) * 8 > len(blob):
                break
            cls_va = struct.unpack_from(ptr_fmt, blob, abs_off + idx * 8)[0] & 0x0000FFFFFFFFFFFF
            cls_off = _va_to_file_offset(cls_va, segments, base_offset)
            if cls_off is None or cls_off + 40 > len(blob):
                continue
            ro_va = struct.unpack_from(ptr_fmt, blob, cls_off + 32)[0] & 0x00007FFFFFFFFFF8
            ro_off = _va_to_file_offset(ro_va, segments, base_offset)
            if ro_off is None or ro_off + 40 > len(blob):
                continue
            name_va, methods_va = struct.unpack_from(f"{endian}QQ", blob, ro_off + 24)
            name_off = _va_to_file_offset(name_va & 0x0000FFFFFFFFFFFF, segments, base_offset)
            cls_name = _cstr(blob, name_off, 128) if name_off is not None else ""
            if cls_name:
                m_cnt = 0
                if methods_va:
                    moff = _va_to_file_offset(methods_va & 0x0000FFFFFFFFFFFF, segments, base_offset)
                    if moff is not None and moff + 8 <= len(blob):
                        _, m_cnt = struct.unpack_from(f"{endian}II", blob, moff)
                objc_structured.append({"class_name": cls_name, "vmaddr": hex(cls_va), "method_count": min(int(m_cnt), 4096)})

    sw_sec = sec_by_name.get("__swift5_types")
    if sw_sec and sw_sec["size"] >= 4:
        abs_off = base_offset + int(sw_sec["offset"])
        s_va = int(sw_sec["addr"], 16)
        n_ents = min(sw_sec["size"] // 4, 256)
        kind_names = {16: "class", 17: "struct", 18: "enum"}
        for idx in range(n_ents):
            if abs_off + (idx + 1) * 4 > len(blob):
                break
            rel32 = struct.unpack_from(f"{endian}i", blob, abs_off + idx * 4)[0]
            desc_va = s_va + idx * 4 + rel32
            desc_off = _va_to_file_offset(desc_va, segments, base_offset)
            if desc_off is None or desc_off + 16 > len(blob):
                continue
            flags, _parent_rel, name_rel = struct.unpack_from(f"{endian}Iii", blob, desc_off)
            kind_id = flags & 0x1F
            name_off = desc_off + 8 + name_rel
            if 0 <= name_off < len(blob):
                t_name = _cstr(blob, name_off, 128)
                if t_name:
                    swift_descriptors.append({
                        "name": t_name,
                        "kind": kind_names.get(kind_id, f"kind_{kind_id}"),
                        "vmaddr": hex(desc_va),
                    })
    return objc_structured, swift_descriptors


def _parse_single_macho(blob: bytes, base_offset: int = 0) -> dict[str, Any]:
    if base_offset + 28 > len(blob):
        return {"status": "invalid", "code": "macho_header_truncated"}
    magic = struct.unpack_from("<I", blob, base_offset)[0]
    if magic == _MH_MAGIC_64:
        endian, is_64, hdr_size = "<", True, 32
    elif magic == _MH_CIGAM_64:
        endian, is_64, hdr_size = ">", True, 32
    elif magic == _MH_MAGIC:
        endian, is_64, hdr_size = "<", False, 28
    elif magic == _MH_CIGAM:
        endian, is_64, hdr_size = ">", False, 28
    else:
        return {"status": "invalid", "code": "not_macho_magic"}

    if base_offset + hdr_size > len(blob):
        return {"status": "invalid", "code": "macho_header_truncated"}

    _, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
        f"{endian}IIIIIII", blob, base_offset
    )

    segments: list[dict[str, Any]] = []
    sections: list[dict[str, Any]] = []
    dylibs: list[str] = []
    uuid_hex: str | None = None
    entryoff: int | None = None
    code_sig: dict[str, Any] = {"present": False}
    encrypted = False
    symbols: list[str] = []
    objc_classes: list[str] = []
    objc_methods: list[str] = []
    swift_symbols: list[str] = []

    cursor = base_offset + hdr_size
    cmd_end = min(len(blob), cursor + sizeofcmds)
    for _ in range(min(ncmds, 2048)):
        if cursor + 8 > cmd_end:
            break
        cmd, cmdsize = struct.unpack_from(f"{endian}II", blob, cursor)
        if cmdsize < 8 or cursor + cmdsize > cmd_end:
            break

        if cmd == _LC_SEGMENT_64 and cmdsize >= 72:
            segname = blob[cursor + 8:cursor + 24].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _ = struct.unpack_from(
                f"{endian}QQQQIIII", blob, cursor + 24
            )
            segments.append({"name": segname, "vmaddr": hex(vmaddr), "vmsize": vmsize, "fileoff": fileoff, "filesize": filesize})
            sec_cur = cursor + 72
            for _ in range(min(nsects, 512)):
                if sec_cur + 80 > cursor + cmdsize:
                    break
                sectname = blob[sec_cur:sec_cur + 16].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                s_seg = blob[sec_cur + 16:sec_cur + 32].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                s_addr, s_size, s_off = struct.unpack_from(f"{endian}QQI", blob, sec_cur + 32)
                sections.append({"segment": s_seg, "section": sectname, "addr": hex(s_addr), "size": s_size, "offset": s_off})
                if sectname in ("__objc_classname", "__objc_methname") and s_size > 0:
                    abs_off = base_offset + s_off
                    if abs_off + s_size <= len(blob):
                        items = [x.decode("utf-8", errors="replace") for x in blob[abs_off:abs_off + min(s_size, 1024 * 1024)].split(b"\x00") if x]
                        if sectname == "__objc_classname":
                            objc_classes.extend(items[:500])
                        else:
                            objc_methods.extend(items[:500])
                sec_cur += 80

        elif cmd == _LC_SEGMENT and cmdsize >= 56:
            segname = blob[cursor + 8:cursor + 24].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(f"{endian}IIII", blob, cursor + 24)
            segments.append({"name": segname, "vmaddr": hex(vmaddr), "vmsize": vmsize, "fileoff": fileoff, "filesize": filesize})

        elif cmd in (_LC_LOAD_DYLIB, _LC_LOAD_WEAK_DYLIB) and cmdsize >= 24:
            str_off = struct.unpack_from(f"{endian}I", blob, cursor + 8)[0]
            if 8 <= str_off < cmdsize:
                dylibs.append(_cstr(blob, cursor + str_off, cmdsize - str_off))

        elif cmd == _LC_UUID and cmdsize >= 24:
            uuid_hex = blob[cursor + 8:cursor + 24].hex()

        elif cmd == _LC_MAIN and cmdsize >= 24:
            entryoff = struct.unpack_from(f"{endian}Q", blob, cursor + 8)[0]

        elif cmd == _LC_ENCRYPTION_INFO_64 and cmdsize >= 24:
            _, _, cryptid = struct.unpack_from(f"{endian}III", blob, cursor + 8)
            encrypted = cryptid != 0

        elif cmd == _LC_CODE_SIGNATURE and cmdsize >= 16:
            dataoff, datasize = struct.unpack_from(f"{endian}II", blob, cursor + 8)
            code_sig = _parse_code_signature(blob, base_offset + dataoff, datasize)

        elif cmd == _LC_SYMTAB and cmdsize >= 24:
            symoff, nsyms, stroff, strsize = struct.unpack_from(f"{endian}IIII", blob, cursor + 8)
            nlist_size = 16 if is_64 else 12
            if base_offset + symoff + nsyms * nlist_size <= len(blob) and base_offset + stroff + strsize <= len(blob):
                strtab = blob[base_offset + stroff:base_offset + stroff + strsize]
                for idx in range(min(nsyms, 5000)):
                    n_strx = struct.unpack_from(f"{endian}I", blob, base_offset + symoff + idx * nlist_size)[0]
                    if n_strx < len(strtab):
                        sname = _cstr(strtab, n_strx, 256)
                        if sname:
                            symbols.append(sname)
                            if sname.startswith(("_$s", "_$S", "$s", "$S")):
                                swift_symbols.append(sname)

        cursor += cmdsize

    objc_structured, swift_descriptors = _extract_objc_swift_metadata(blob, base_offset, endian, is_64, segments, sections)
    return {
        "status": "complete",
        "is_64bit": is_64,
        "cpu_type": _CPU_TYPES.get(cputype, hex(cputype)),
        "file_type": _FILE_TYPES.get(filetype, hex(filetype)),
        "mitigations": {
            "pie": bool(flags & 0x200000),
            "no_heap_execution": bool(flags & 0x1000000),
            "allow_stack_execution": bool(flags & 0x20000),
        },
        "uuid": uuid_hex,
        "entry_offset": hex(entryoff) if entryoff is not None else None,
        "encrypted_binary": encrypted,
        "segments": segments,
        "total_sections": len(sections),
        "sections": sections,
        "dylibs": dylibs,
        "total_symbols": len(symbols),
        "symbols": symbols[:500],
        "objc_classes": objc_classes,
        "objc_methods": objc_methods,
        "objc_structured_classes": objc_structured,
        "swift_symbols": swift_symbols[:200],
        "swift_type_descriptors": swift_descriptors,
        "code_signature": code_sig,
    }


def analyze_macho(data: bytes) -> dict[str, Any]:
    """Analyze Mach-O (thin or universal fat) binary bytes."""
    if not isinstance(data, (bytes, bytearray)):
        return {"schema": SCHEMA, "status": "invalid", "code": "bytes_required"}
    blob = bytes(data)
    if len(blob) > MAX_MACHO_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "input_too_large"}
    if len(blob) < 16:
        return {"schema": SCHEMA, "status": "invalid", "code": "too_small"}

    be_magic = struct.unpack_from(">I", blob, 0)[0]
    if be_magic == _FAT_MAGIC:
        nfat = struct.unpack_from(">I", blob, 4)[0]
        # Disambiguate Fat Mach-O vs Java .class (major version 45..100)
        if 45 <= (nfat & 0xFFFF) <= 100 and (nfat >> 16) <= 10:
            return {"schema": SCHEMA, "status": "invalid", "code": "java_class_not_macho"}
        if nfat == 0 or nfat > 32 or 8 + nfat * 20 > len(blob):
            return {"schema": SCHEMA, "status": "invalid", "code": "invalid_fat_header"}
        slices = []
        for i in range(nfat):
            cputype, _, offset, size, _ = struct.unpack_from(">IIIII", blob, 8 + i * 20)
            if offset + size > len(blob):
                slices.append({"status": "invalid", "code": "slice_oob", "cpu_type": _CPU_TYPES.get(cputype, hex(cputype))})
            else:
                slices.append(_parse_single_macho(blob, offset))
        return {"schema": SCHEMA, "status": "complete", "is_universal_fat": True, "slices": slices}

    single = _parse_single_macho(blob, 0)
    if single.get("status") != "complete":
        return {"schema": SCHEMA, **single}
    return {"schema": SCHEMA, "status": "complete", "is_universal_fat": False, "slices": [single]}


def scan_file_macho(target: str | Path) -> dict[str, Any]:
    path = Path(target)
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")
    if path.stat().st_size > MAX_MACHO_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "file_too_large", "target": str(path)}
    report = analyze_macho(path.read_bytes())
    report["target"] = str(path)
    return report
