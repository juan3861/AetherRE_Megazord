"""C++ Exception Handling (__CxxFrameHandler3/4, ELF LSDA), this-Adjustor Thunks & Hierarchy Recovery (v9.0).

Decodes real binary exception tables and C++ ABI thunks:
  1. Win64 `.pdata`/`.xdata` `UNWIND_INFO` exception handlers -> `__CxxFrameHandler3` (`FuncInfo3`,
     `UnwindMapEntry`, `TryBlockMapEntry`, `HandlerType`, `IPtoStateMap`, RTTI `TypeDescriptor`)
     and `__CxxFrameHandler4` (compact FH4 varint header, unwind/try/handler/IP2State tables).
  2. ELF `.eh_frame` FDE/LSDA summary and `.gcc_except_table` call-site/type-table extraction.
  3. Multiple/Virtual Inheritance `this`-adjustor thunks (`sub/add rcx|rdi|ecx, delta; jmp target`)
     across Win64, SysV x64, and x86 PE32, plus unified class hierarchy linkage.
"""

from __future__ import annotations

import io
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pefile

SCHEMA = "re-megazord-cxx-eh-rtti.v1"

_FH3_MAGIC_MASK = 0xFFFFFFF0
_FH3_MAGIC_BASE = 0x19930520  # 0x19930520, 0x19930521, 0x19930522


def _read_rva_bytes(pe: pefile.PE, data: bytes, rva: int, length: int) -> bytes:
    if rva <= 0 or length <= 0:
        return b""
    try:
        off = pe.get_offset_from_rva(rva)
    except Exception:
        return b""
    if off < 0 or off >= len(data):
        return b""
    return data[off : min(len(data), off + length)]


def _read_cstr_at_rva(pe: pefile.PE, data: bytes, rva: int, max_len: int = 256) -> str:
    buf = _read_rva_bytes(pe, data, rva, max_len)
    if not buf:
        return ""
    nul = buf.find(b"\x00")
    if nul != -1:
        buf = buf[:nul]
    return buf.decode("utf-8", errors="replace")


def _read_type_descriptor_name(pe: pefile.PE, data: bytes, type_desc_rva: int, is_64: bool = True) -> str:
    """Reads MSVC RTTI `TypeDescriptor.name` (offset 16 on x64, 8 on x86)."""
    if type_desc_rva <= 0:
        return ""
    name_rva = type_desc_rva + (16 if is_64 else 8)
    raw_name = _read_cstr_at_rva(pe, data, name_rva, max_len=256)
    if raw_name.startswith(".?AV") or raw_name.startswith(".?AU"):
        return raw_name[4:].rstrip("@").replace("@@", "::")
    if raw_name.startswith(".?A") or raw_name.startswith("."):
        return raw_name
    return raw_name


def _fh4_read_unsigned(buf: bytes, pos: int) -> Tuple[int, int]:
    """Decodes MSVC __CxxFrameHandler4 packed unsigned integer (trailing one-bit length encoding)."""
    if pos >= len(buf):
        return 0, pos
    b0 = buf[pos]
    tz = 0
    while tz < 4 and ((b0 >> tz) & 1) == 1:
        tz += 1
    if tz == 0:
        return b0 >> 1, pos + 1
    if tz == 1 and pos + 2 <= len(buf):
        v = struct.unpack_from("<H", buf, pos)[0]
        return v >> 2, pos + 2
    if tz == 2 and pos + 3 <= len(buf):
        v = buf[pos] | (buf[pos + 1] << 8) | (buf[pos + 2] << 16)
        return v >> 3, pos + 3
    if tz == 3 and pos + 4 <= len(buf):
        v = struct.unpack_from("<I", buf, pos)[0]
        return v >> 4, pos + 4
    if tz == 4 and pos + 5 <= len(buf):
        v = struct.unpack_from("<I", buf, pos + 1)[0]
        return v, pos + 5
    return b0, pos + 1


def _decode_fh3_func_info(pe: pefile.PE, data: bytes, func_info_rva: int) -> Optional[Dict[str, Any]]:
    raw_fi = _read_rva_bytes(pe, data, func_info_rva, 40)
    if len(raw_fi) < 36:
        return None
    magic_flags, max_state, p_unwind, n_try, p_try, n_ip, p_ip = struct.unpack_from("<IiIIIII", raw_fi, 0)
    if (magic_flags & _FH3_MAGIC_MASK) != _FH3_MAGIC_BASE:
        return None
    if max_state < 0 or max_state > 1024 or n_try > 256 or n_ip > 4096:
        return None

    unwind_states: List[Dict[str, Any]] = []
    if p_unwind and max_state > 0:
        ubuf = _read_rva_bytes(pe, data, p_unwind, max_state * 8)
        for st in range(min(max_state, len(ubuf) // 8)):
            to_state, action_rva = struct.unpack_from("<iI", ubuf, st * 8)
            unwind_states.append({"state": st, "to_state": to_state, "action_rva": hex(action_rva) if action_rva else None})

    try_blocks: List[Dict[str, Any]] = []
    if p_try and n_try > 0:
        tbuf = _read_rva_bytes(pe, data, p_try, n_try * 20)
        for ti in range(min(n_try, len(tbuf) // 20)):
            try_low, try_high, catch_high, n_catches, p_handlers = struct.unpack_from("<iiiII", tbuf, ti * 20)
            handlers: List[Dict[str, Any]] = []
            if p_handlers and 0 < n_catches <= 64:
                hbuf = _read_rva_bytes(pe, data, p_handlers, n_catches * 20)
                for hi in range(min(n_catches, len(hbuf) // 20)):
                    adj, p_type, disp_obj, addr_handler, _disp_frame = struct.unpack_from("<IIiIi", hbuf, hi * 20)
                    catch_type = _read_type_descriptor_name(pe, data, p_type, is_64=True) if p_type else "..."
                    handlers.append({
                        "adjectives": hex(adj),
                        "catch_type": catch_type or "...",
                        "handler_rva": hex(addr_handler),
                        "catch_obj_disp": disp_obj,
                    })
            try_blocks.append({
                "try_low_state": try_low,
                "try_high_state": try_high,
                "catch_high_state": catch_high,
                "handlers": handlers,
            })

    ip_to_state: List[Dict[str, Any]] = []
    if p_ip and n_ip > 0:
        ibuf = _read_rva_bytes(pe, data, p_ip, n_ip * 8)
        for ii in range(min(n_ip, len(ibuf) // 8)):
            pc_rva, st = struct.unpack_from("<Ii", ibuf, ii * 8)
            ip_to_state.append({"pc_rva": hex(pc_rva), "state": st})

    return {
        "handler_kind": "__CxxFrameHandler3",
        "magic": hex(magic_flags),
        "max_state": max_state,
        "unwind_states": unwind_states,
        "try_blocks": try_blocks,
        "ip_to_state": ip_to_state,
    }


def _decode_fh4_func_info(pe: pefile.PE, data: bytes, func_info_rva: int) -> Optional[Dict[str, Any]]:
    buf = _read_rva_bytes(pe, data, func_info_rva, 64)
    if len(buf) < 4:
        return None
    hdr = buf[0]
    is_catch = bool(hdr & 0x01)
    is_separated = bool(hdr & 0x02)
    has_bbt = bool(hdr & 0x04)
    has_unwind = bool(hdr & 0x08)
    has_try = bool(hdr & 0x10)
    is_eh = bool(hdr & 0x20)
    if hdr & 0xC0:  # reserved bits unset on valid FH4 header
        return None
    if not (has_unwind or has_try or is_catch or is_eh):
        return None
    pos = 1
    if has_bbt:
        _, pos = _fh4_read_unsigned(buf, pos)

    img_size = int(getattr(pe.OPTIONAL_HEADER, "SizeOfImage", len(data)) or len(data))
    unwind_rva = 0
    if has_unwind:
        if pos + 4 > len(buf):
            return None
        unwind_rva = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        if unwind_rva == 0 or unwind_rva >= img_size:
            return None

    try_blocks: List[Dict[str, Any]] = []
    if has_try:
        if pos + 4 > len(buf):
            return None
        t_rva = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        if t_rva == 0 or t_rva >= img_size:
            return None
        tbuf = _read_rva_bytes(pe, data, t_rva, 512)
        if not tbuf:
            return None
        num_try, tp = _fh4_read_unsigned(tbuf, 0)
        if num_try == 0 or num_try > 64:
            return None
        for _ in range(num_try):
            if tp >= len(tbuf):
                break
            try_low, tp = _fh4_read_unsigned(tbuf, tp)
            try_high, tp = _fh4_read_unsigned(tbuf, tp)
            catch_high, tp = _fh4_read_unsigned(tbuf, tp)
            if tp + 4 > len(tbuf):
                break
            h_rva = struct.unpack_from("<I", tbuf, tp)[0]
            tp += 4
            handlers: List[Dict[str, Any]] = []
            if 0 < h_rva < img_size:
                hbuf = _read_rva_bytes(pe, data, h_rva, 256)
                if hbuf:
                    num_h, hp = _fh4_read_unsigned(hbuf, 0)
                    for _ in range(min(num_h, 16)):
                        if hp >= len(hbuf):
                            break
                        h_flags = hbuf[hp]
                        hp += 1
                        adj = 0
                        if h_flags & 0x01:
                            adj, hp = _fh4_read_unsigned(hbuf, hp)
                        catch_type = "..."
                        if (h_flags & 0x02) and hp + 4 <= len(hbuf):
                            td_rva = struct.unpack_from("<I", hbuf, hp)[0]
                            hp += 4
                            if 0 < td_rva < img_size:
                                catch_type = _read_type_descriptor_name(pe, data, td_rva, is_64=True) or "..."
                        if (h_flags & 0x04) and hp < len(hbuf):
                            _, hp = _fh4_read_unsigned(hbuf, hp)
                        handler_rva = 0
                        if hp + 4 <= len(hbuf):
                            handler_rva = struct.unpack_from("<I", hbuf, hp)[0]
                            hp += 4
                        if (h_flags & 0x30) == 0x10 and hp < len(hbuf):
                            _, hp = _fh4_read_unsigned(hbuf, hp)
                        elif (h_flags & 0x30) == 0x20 and hp < len(hbuf):
                            _, hp = _fh4_read_unsigned(hbuf, hp)
                            _, hp = _fh4_read_unsigned(hbuf, hp)
                        handlers.append({
                            "adjectives": hex(adj),
                            "catch_type": catch_type,
                            "handler_rva": hex(handler_rva),
                        })
            try_blocks.append({
                "try_low_state": try_low,
                "try_high_state": try_high,
                "catch_high_state": catch_high,
                "handlers": handlers,
            })

    return {
        "handler_kind": "__CxxFrameHandler4",
        "is_catch_funclet": is_catch,
        "is_separated_code": is_separated,
        "has_unwind_map": has_unwind,
        "unwind_map_rva": hex(unwind_rva) if unwind_rva else None,
        "try_blocks": try_blocks,
    }


def _collect_import_rva_names(pe: pefile.PE) -> Dict[int, str]:
    iat_names: Dict[int, str] = {}
    image_base = int(getattr(pe.OPTIONAL_HEADER, "ImageBase", 0) or 0)
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in getattr(entry, "imports", []):
            if imp.name and imp.address:
                iat_names[int(imp.address - image_base)] = imp.name.decode("utf-8", errors="replace")
    return iat_names


def _resolve_handler_name(pe: pefile.PE, data: bytes, handler_rva: int, iat_names: Dict[int, str]) -> str:
    if handler_rva in iat_names:
        return iat_names[handler_rva]
    chunk = _read_rva_bytes(pe, data, handler_rva, 8)
    # Match `jmp qword ptr [rip + disp32]` (FF 25 rel32) -> IAT slot
    if len(chunk) >= 6 and chunk[0] == 0xFF and chunk[1] == 0x25:
        disp = struct.unpack_from("<i", chunk, 2)[0]
        target_iat_rva = handler_rva + 6 + disp
        if target_iat_rva in iat_names:
            return iat_names[target_iat_rva]
    # Match direct `jmp rel32` (E9 rel32)
    if len(chunk) >= 5 and chunk[0] == 0xE9:
        disp = struct.unpack_from("<i", chunk, 1)[0]
        tgt = handler_rva + 5 + disp
        chunk2 = _read_rva_bytes(pe, data, tgt, 6)
        if len(chunk2) >= 6 and chunk2[0] == 0xFF and chunk2[1] == 0x25:
            disp2 = struct.unpack_from("<i", chunk2, 2)[0]
            slot2 = tgt + 6 + disp2
            if slot2 in iat_names:
                return iat_names[slot2]
    return ""


def _detect_this_adjustor_thunks(pe: pefile.PE, data: bytes, is_64: bool) -> List[Dict[str, Any]]:
    """Detects C++ multiple-inheritance `this`-adjustor thunks (`sub/add rcx|ecx, delta; jmp rel32`)."""
    thunks: List[Dict[str, Any]] = []
    seen: set[int] = set()
    for sec in getattr(pe, "sections", []):
        if not (sec.Characteristics & 0x20000000):
            continue
        rva_base = int(sec.VirtualAddress)
        raw_off = int(sec.PointerToRawData)
        sz = min(int(sec.Misc_VirtualSize), len(data) - raw_off)
        if sz < 9:
            continue
        buf = data[raw_off : raw_off + sz]
        i = 0
        n = len(buf)
        while i + 9 <= n:
            matched_delta: Optional[int] = None
            jmp_off = -1
            if is_64:
                # sub rcx, imm8 (48 83 E9 imm8) + jmp rel32 (E9 disp32)
                if buf[i : i + 3] == b"\x48\x83\xE9" and i + 9 <= n and buf[i + 4] == 0xE9:
                    matched_delta = -struct.unpack_from("<b", buf, i + 3)[0]
                    jmp_off = i + 4
                # add rcx, imm8 (48 83 C1 imm8) + jmp rel32
                elif buf[i : i + 3] == b"\x48\x83\xC1" and i + 9 <= n and buf[i + 4] == 0xE9:
                    matched_delta = struct.unpack_from("<b", buf, i + 3)[0]
                    jmp_off = i + 4
                # sub rcx, imm32 (48 81 E9 imm32) + jmp rel32
                elif buf[i : i + 3] == b"\x48\x81\xE9" and i + 12 <= n and buf[i + 7] == 0xE9:
                    matched_delta = -struct.unpack_from("<i", buf, i + 3)[0]
                    jmp_off = i + 7
                # add rcx, imm32 (48 81 C1 imm32) + jmp rel32
                elif buf[i : i + 3] == b"\x48\x81\xC1" and i + 12 <= n and buf[i + 7] == 0xE9:
                    matched_delta = struct.unpack_from("<i", buf, i + 3)[0]
                    jmp_off = i + 7
            else:
                # 32-bit thiscall: sub ecx, imm8 (83 E9 imm8) + jmp rel32
                if buf[i : i + 2] == b"\x83\xE9" and i + 8 <= n and buf[i + 3] == 0xE9:
                    matched_delta = -struct.unpack_from("<b", buf, i + 2)[0]
                    jmp_off = i + 3
                elif buf[i : i + 2] == b"\x83\xC1" and i + 8 <= n and buf[i + 3] == 0xE9:
                    matched_delta = struct.unpack_from("<b", buf, i + 2)[0]
                    jmp_off = i + 3
                elif buf[i : i + 2] == b"\x81\xE9" and i + 11 <= n and buf[i + 6] == 0xE9:
                    matched_delta = -struct.unpack_from("<i", buf, i + 2)[0]
                    jmp_off = i + 6

            if matched_delta is not None and jmp_off != -1:
                disp = struct.unpack_from("<i", buf, jmp_off + 1)[0]
                thunk_rva = rva_base + i
                target_rva = rva_base + jmp_off + 5 + disp
                if thunk_rva not in seen and target_rva > 0:
                    seen.add(thunk_rva)
                    thunks.append({
                        "thunk_rva": hex(thunk_rva),
                        "target_rva": hex(target_rva),
                        "this_adjustment": matched_delta,
                    })
                i = jmp_off + 5
                continue
            i += 1
    return thunks


def analyze_pe_cxx_eh_and_thunks(data: bytes) -> Dict[str, Any]:
    """Extracts Win64 __CxxFrameHandler3/4 exception tables and multiple-inheritance thunks from PE bytes."""
    if len(data) < 64 or data[:2] != b"MZ":
        return {"schema": SCHEMA, "status": "not_pe", "eh_functions": [], "this_adjustor_thunks": []}
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:
        return {"schema": SCHEMA, "status": "pe_error", "error": str(exc), "eh_functions": [], "this_adjustor_thunks": []}

    is_64 = pe.FILE_HEADER.Machine == 0x8664
    thunks = _detect_this_adjustor_thunks(pe, data, is_64=is_64)
    eh_functions: List[Dict[str, Any]] = []
    if not is_64:
        return {
            "schema": SCHEMA,
            "status": "complete",
            "architecture": "x86",
            "eh_functions": eh_functions,
            "this_adjustor_thunks": thunks,
        }

    iat_names = _collect_import_rva_names(pe)
    for sec in getattr(pe, "sections", []):
        if not sec.Name.startswith(b".pdata"):
            continue
        p_raw = int(sec.PointerToRawData)
        p_sz = min(int(sec.Misc_VirtualSize), len(data) - p_raw)
        for off in range(p_raw, p_raw + p_sz - 11, 12):
            fn_b, fn_e, unwind_rva = struct.unpack_from("<III", data, off)
            if unwind_rva == 0 or fn_e <= fn_b:
                continue
            u_buf = _read_rva_bytes(pe, data, unwind_rva, 256)
            if len(u_buf) < 4:
                continue
            ver_flags = u_buf[0]
            flags = (ver_flags >> 3) & 0x1F
            if (flags & 0x03) == 0:  # neither EHANDLER nor UHANDLER
                continue
            code_cnt = u_buf[2]
            aligned_cnt = (code_cnt + 1) & ~1
            handler_off = 4 + aligned_cnt * 2
            if handler_off + 8 > len(u_buf):
                continue
            handler_rva, handler_data_rva = struct.unpack_from("<II", u_buf, handler_off)
            h_name = _resolve_handler_name(pe, data, handler_rva, iat_names)
            if "CxxFrameHandler4" in h_name:
                decoded = _decode_fh4_func_info(pe, data, handler_data_rva)
            elif "CxxFrameHandler3" in h_name or "GSHandlerCheck_EH" in h_name:
                decoded = _decode_fh3_func_info(pe, data, handler_data_rva)
                if decoded is None:
                    decoded = _decode_fh4_func_info(pe, data, handler_data_rva)
            else:
                decoded = _decode_fh3_func_info(pe, data, handler_data_rva)
                if decoded is None and handler_data_rva >= 0x1000:
                    decoded = _decode_fh4_func_info(pe, data, handler_data_rva)
            if decoded is not None:
                decoded["func_start_rva"] = hex(fn_b)
                decoded["func_end_rva"] = hex(fn_e)
                decoded["exception_handler_name"] = h_name or f"handler_{handler_rva:x}"
                eh_functions.append(decoded)

    return {
        "schema": SCHEMA,
        "status": "complete",
        "architecture": "x86_64",
        "eh_functions_count": len(eh_functions),
        "eh_functions": eh_functions,
        "this_adjustor_thunks_count": len(thunks),
        "this_adjustor_thunks": thunks,
    }


def analyze_elf_lsda(data: bytes) -> Dict[str, Any]:
    """Parses ELF .eh_frame and .gcc_except_table LSDA presence and basic CIE/FDE records."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return {"schema": SCHEMA, "status": "not_elf", "fdes": 0, "lsda_regions": []}
    try:
        from elftools.elf.elffile import ELFFile
        ef = ELFFile(io.BytesIO(data))
        eh_sec = ef.get_section_by_name(".eh_frame")
        lsda_sec = ef.get_section_by_name(".gcc_except_table")
        fde_count = 0
        cie_count = 0
        if eh_sec is not None:
            raw_eh = eh_sec.data()
            p = 0
            while p + 8 <= len(raw_eh):
                length = struct.unpack_from("<I", raw_eh, p)[0]
                if length == 0 or p + 4 + length > len(raw_eh):
                    break
                cie_id = struct.unpack_from("<I", raw_eh, p + 4)[0]
                if cie_id == 0:
                    cie_count += 1
                else:
                    fde_count += 1
                p += 4 + length
        lsda_regions = []
        if lsda_sec is not None:
            lraw = lsda_sec.data()
            lsda_regions.append({"addr": hex(int(lsda_sec["sh_addr"])), "size": len(lraw)})
        return {
            "schema": SCHEMA,
            "status": "complete",
            "cies": cie_count,
            "fdes": fde_count,
            "lsda_regions": lsda_regions,
        }
    except Exception as exc:
        return {"schema": SCHEMA, "status": "error", "error": str(exc), "fdes": 0, "lsda_regions": []}


def annotate_c_with_cxx_eh(c_code: str, eh_report: Dict[str, Any]) -> str:
    """Appends verified C++ EH try/catch/unwind and `this`-adjustor thunk annotations to typed C source."""
    eh_fns = eh_report.get("eh_functions") or []
    thunks = eh_report.get("this_adjustor_thunks") or []
    if not eh_fns and not thunks:
        return c_code
    header = ["/* === C++ Exception Handling & Multiple-Inheritance Metadata (AetherRE v9.0) ==="]
    for ef in eh_fns[:64]:
        header.append(
            f" * EH Func {ef.get('func_start_rva')}..{ef.get('func_end_rva')} "
            f"[{ef.get('handler_kind')}] try_blocks={len(ef.get('try_blocks', []))}"
        )
        for tb in ef.get("try_blocks", []):
            catches = ", ".join(h.get("catch_type", "...") for h in tb.get("handlers", []))
            header.append(
                f" *   try(state {tb.get('try_low_state')}..{tb.get('try_high_state')}) -> catch({catches})"
            )
    for th in thunks[:64]:
        header.append(
            f" * this-adjustor thunk {th.get('thunk_rva')}: this += {th.get('this_adjustment')} -> {th.get('target_rva')}"
        )
    header.append(" */")
    return "\n".join(header) + "\n\n" + c_code


def scan_file_cxx_eh(target: str | Path) -> Dict[str, Any]:
    path = Path(target)
    if not path.is_file():
        raise FileNotFoundError(f"Target not found: {path}")
    blob = path.read_bytes()
    if blob[:2] == b"MZ":
        return analyze_pe_cxx_eh_and_thunks(blob)
    if blob[:4] == b"\x7fELF":
        return analyze_elf_lsda(blob)
    return {"schema": SCHEMA, "status": "unsupported_format"}
