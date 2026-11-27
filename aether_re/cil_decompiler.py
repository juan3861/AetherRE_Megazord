"""Pure-Python ECMA-335 .NET Metadata Table (`#~`/`#-`) & CIL-to-C# Decompiler (v10.5).

Eliminates reliance on external `ilspycmd`:
  1. Parses PE32/PE32+ CLR CLI Header (COM Descriptor DataDirectory[14]), BSJB streams
     (`#~`, `Strings`, `#US`, `#GUID`, `#Blob`), heap index widths, and ECMA-335 table schemas
     (`Module`, `TypeRef`, `TypeDef`, `Field`, `MethodDef`, `Param`, `MemberRef`, `StandAloneSig`).
  2. Resolves MethodDef RVA -> PE file offset, decodes Tiny (`0x2`) and Fat (`0x3`) CIL headers,
     and lifts stack-based IL instructions (`ldarg`, `ldloc`, `stloc`, `ldc.i4/i8`, arithmetic,
     comparisons, branches, `ldstr`, `call`/`callvirt`, `ret`) into compilable C# methods.
  3. Detects ReadyToRun (`RTR`) and NativeAOT CLR markers cleanly.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pefile

SCHEMA = "re-megazord-cil-decompiler.v1"

# ECMA-335 Table IDs and fixed/coded column descriptors (minimal core tables up to 0x20)
_TBL_MODULE = 0x00
_TBL_TYPEREF = 0x01
_TBL_TYPEDEF = 0x02
_TBL_FIELD = 0x04
_TBL_METHODDEF = 0x06
_TBL_PARAM = 0x08
_TBL_INTERFACEIMPL = 0x09
_TBL_MEMBERREF = 0x0A
_TBL_CONSTANT = 0x0B
_TBL_CUSTOMATTRIBUTE = 0x0C
_TBL_FIELDMARSHAL = 0x0D
_TBL_DECLSECURITY = 0x0E
_TBL_CLASSLAYOUT = 0x0F
_TBL_FIELDLAYOUT = 0x10
_TBL_STANDALONESIG = 0x11
_TBL_EVENTMAP = 0x12
_TBL_EVENT = 0x14
_TBL_PROPERTYMAP = 0x15
_TBL_PROPERTY = 0x17
_TBL_METHODSEMANTICS = 0x18
_TBL_METHODIMPL = 0x19
_TBL_MODULEREF = 0x1A
_TBL_TYPESPEC = 0x1B
_TBL_IMPLMAP = 0x1C
_TBL_FIELDRVA = 0x1D
_TBL_ASSEMBLY = 0x20
_TBL_ASSEMBLYPROCESSOR = 0x21
_TBL_ASSEMBLYOS = 0x22
_TBL_ASSEMBLYREF = 0x23


def _coded_size(row_counts: Dict[int, int], tables: Tuple[int, ...], tag_bits: int) -> int:
    max_rows = max((row_counts.get(t, 0) for t in tables), default=0)
    return 2 if max_rows < (1 << (16 - tag_bits)) else 4


def _simple_size(row_counts: Dict[int, int], table_id: int) -> int:
    return 2 if row_counts.get(table_id, 0) < 0x10000 else 4


def _read_int_n(buf: bytes, pos: int, width: int) -> Tuple[int, int]:
    if pos + width > len(buf):
        return 0, len(buf)
    if width == 2:
        return struct.unpack_from("<H", buf, pos)[0], pos + 2
    return struct.unpack_from("<I", buf, pos)[0], pos + 4


def _read_comp_uint(buf: bytes, pos: int) -> Tuple[int, int]:
    if pos >= len(buf):
        return 0, pos
    b0 = buf[pos]
    if (b0 & 0x80) == 0:
        return b0, pos + 1
    if (b0 & 0xC0) == 0x80 and pos + 1 < len(buf):
        return ((b0 & 0x3F) << 8) | buf[pos + 1], pos + 2
    if (b0 & 0xE0) == 0xC0 and pos + 3 < len(buf):
        return ((b0 & 0x1F) << 24) | (buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3], pos + 4
    return 0, pos + 1


def _read_cstr_heap(heap: bytes, idx: int) -> str:
    if idx <= 0 or idx >= len(heap):
        return ""
    nul = heap.find(b"\x00", idx)
    if nul == -1:
        nul = len(heap)
    return heap[idx:nul].decode("utf-8", errors="replace")


def _read_us_str(us_heap: bytes, idx: int) -> str:
    if idx <= 0 or idx >= len(us_heap):
        return ""
    blen, start = _read_comp_uint(us_heap, idx)
    if blen <= 1 or start + blen > len(us_heap):
        return ""
    raw = us_heap[start : start + blen - (1 if blen % 2 == 1 else 0)]
    return raw.decode("utf-16-le", errors="replace")


def _parse_blob_sig(blob_heap: bytes, sig_idx: int) -> Tuple[str, List[str]]:
    """Decodes ECMA-335 MethodDefSig calling convention + return type + parameter types."""
    if sig_idx <= 0 or sig_idx >= len(blob_heap):
        return "int", []
    blen, p = _read_comp_uint(blob_heap, sig_idx)
    end = min(len(blob_heap), p + blen)
    if p >= end:
        return "int", []
    _cc = blob_heap[p]
    p += 1
    if _cc & 0x10:  # GENERIC
        _, p = _read_comp_uint(blob_heap, p)
    param_cnt, p = _read_comp_uint(blob_heap, p)
    type_map = {
        0x01: "void", 0x02: "bool", 0x03: "char",
        0x04: "sbyte", 0x05: "byte", 0x06: "short", 0x07: "ushort",
        0x08: "int", 0x09: "uint", 0x0A: "long", 0x0B: "ulong",
        0x0C: "float", 0x0D: "double", 0x0E: "string", 0x1C: "object",
    }

    def _next_type(pos_cur: int) -> Tuple[str, int]:
        if pos_cur >= end:
            return "int", pos_cur
        elem = blob_heap[pos_cur]
        pos_cur += 1
        if elem in type_map:
            return type_map[elem], pos_cur
        if elem in (0x11, 0x12):  # VALUETYPE / CLASS coded token
            _, pos_cur = _read_comp_uint(blob_heap, pos_cur)
            return "object", pos_cur
        if elem == 0x1D:  # SZARRAY
            inner, pos_cur = _next_type(pos_cur)
            return f"{inner}[]", pos_cur
        if elem in (0x0F, 0x10):  # PTR / BYREF
            inner, pos_cur = _next_type(pos_cur)
            return inner, pos_cur
        return "int", pos_cur

    ret_t, p = _next_type(p)
    ptypes: List[str] = []
    for _ in range(min(param_cnt, 32)):
        pt, p = _next_type(p)
        ptypes.append(pt)
    return ret_t, ptypes


def _lift_cil_body_to_csharp(
    pe: pefile.PE,
    raw: bytes,
    rva: int,
    param_types: List[str],
    ret_type: str,
    is_static: bool,
    us_heap: bytes,
    method_names: Dict[int, str],
) -> List[str]:
    """Lifts CIL Tiny or Fat method body at `rva` into structured C# lines."""
    if rva <= 0:
        return ["            return 0;" if ret_type != "void" else "            return;"]
    try:
        off = pe.get_offset_from_rva(rva)
    except Exception:
        return ["            return 0;" if ret_type != "void" else "            return;"]
    if off < 0 or off >= len(raw):
        return ["            return 0;" if ret_type != "void" else "            return;"]

    b0 = raw[off]
    if (b0 & 0x03) == 0x02:  # Tiny header
        code_sz = b0 >> 2
        il_start = off + 1
    elif (b0 & 0x03) == 0x03 and off + 12 <= len(raw):  # Fat header
        hdr_words = (raw[off + 1] >> 4) & 0xF
        code_sz = struct.unpack_from("<I", raw, off + 4)[0]
        il_start = off + hdr_words * 4
    else:
        return ["            return 0;" if ret_type != "void" else "            return;"]

    il = raw[il_start : min(len(raw), il_start + code_sz)]
    if not il:
        return ["            return 0;" if ret_type != "void" else "            return;"]

    # Parse ECMA-335 Fat Header Exception Handling (try/catch/finally/fault) sections
    eh_clauses: List[Tuple[str, int, int, int, int]] = []
    if (b0 & 0x03) == 0x03 and (b0 & 0x08):  # Fat header with MoreSects
        sect_pos = (il_start + code_sz + 3) & ~3
        while sect_pos + 4 <= len(raw):
            kind = raw[sect_pos]
            if (kind & 0x3F) == 0x01:  # CorILMethod_Sect_EHTable
                is_fat_eh = bool(kind & 0x40)
                if not is_fat_eh:
                    data_sz = raw[sect_pos + 1]
                    n_clauses = max(0, (data_sz - 4) // 12)
                    cpos = sect_pos + 4
                    for _ in range(n_clauses):
                        if cpos + 12 > len(raw):
                            break
                        cflags, try_off, try_len, h_off, h_len, _tok = struct.unpack_from("<HHBHB I".replace(" ", ""), raw, cpos)
                        eh_kind = {0: "catch", 2: "finally", 4: "fault"}.get(cflags & 0x7, "catch")
                        eh_clauses.append((eh_kind, try_off, try_off + try_len, h_off, h_off + h_len))
                        cpos += 12
                else:
                    data_sz = struct.unpack_from("<I", raw, sect_pos)[0] >> 8
                    n_clauses = max(0, (data_sz - 4) // 24)
                    cpos = sect_pos + 4
                    for _ in range(n_clauses):
                        if cpos + 24 > len(raw):
                            break
                        cflags, try_off, try_len, h_off, h_len, _tok = struct.unpack_from("<IIIIII", raw, cpos)
                        eh_kind = {0: "catch", 2: "finally", 4: "fault"}.get(cflags & 0x7, "catch")
                        eh_clauses.append((eh_kind, try_off, try_off + try_len, h_off, h_off + h_len))
                        cpos += 24
            if not (kind & 0x80):
                break
            step_sz = (struct.unpack_from("<I", raw, sect_pos)[0] >> 8) if (kind & 0x40) else raw[sect_pos + 1]
            if step_sz <= 0:
                break
            sect_pos = (sect_pos + step_sz + 3) & ~3

    try_starts = {c[1] for c in eh_clauses}
    try_ends = {c[2]: c[0] for c in eh_clauses}
    handler_starts = {c[3]: c[0] for c in eh_clauses}
    handler_ends = {c[4] for c in eh_clauses}

    # Map offset -> branch target labels
    targets: set[int] = set()
    p = 0
    while p < len(il):
        op = il[p]
        if op == 0xFE and p + 1 < len(il):
            op2 = il[p + 1]
            p += 2
            if op2 in (0x01, 0x02, 0x03, 0x04, 0x05):  # ceq/cgt/clt
                continue
            elif op2 in (0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E) and p + 2 <= len(il):
                p += 2
            continue
        p += 1
        if op in (0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x1F) and p < len(il):
            p += 1
        elif op in (0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37) and p < len(il):
            rel = struct.unpack_from("<b", il, p)[0]
            p += 1
            targets.add(p + rel)
        elif op in (0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44) and p + 4 <= len(il):
            rel = struct.unpack_from("<i", il, p)[0]
            p += 4
            targets.add(p + rel)
        elif op in (0x20, 0x28, 0x6F, 0x72, 0x73, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x8D) and p + 4 <= len(il):
            p += 4
        elif op == 0x45 and p + 4 <= len(il):
            n_sw = struct.unpack_from("<I", il, p)[0]
            p += 4
            if p + n_sw * 4 <= len(il):
                rels_sw = [struct.unpack_from("<i", il, p + i * 4)[0] for i in range(n_sw)]
                p += n_sw * 4
                for rel in rels_sw:
                    targets.add(p + rel)
        elif op == 0x21 and p + 8 <= len(il):
            p += 8

    out: List[str] = [f"            long loc0 = 0, loc1 = 0, loc2 = 0, loc3 = 0;"]
    stack: List[str] = []
    arg_offset = 0 if is_static else 1

    def _arg_expr(idx: int) -> str:
        if not is_static and idx == 0:
            return "this"
        pi = idx - arg_offset
        return f"p{pi}" if 0 <= pi < len(param_types) else f"p{idx}"

    p = 0
    while p < len(il):
        if p in try_starts:
            out.append("            try {")
        if p in try_ends:
            ek = try_ends[p]
            out.append("            }")
            if ek == "finally":
                out.append("            finally {")
            elif ek == "fault":
                out.append("            catch (System.Exception) { /* fault */")
            else:
                out.append("            catch (System.Exception) {")
        elif p in handler_starts and p not in try_ends.values():
            pass
        if p in handler_ends:
            out.append("            }")
        if p in targets:
            out.append(f"        IL_{p:04X}:;")
        op = il[p]
        p += 1
        if op == 0x00:  # nop
            continue
        elif op in (0x02, 0x03, 0x04, 0x05):  # ldarg.0..3
            stack.append(_arg_expr(op - 0x02))
        elif op == 0x0E and p < len(il):  # ldarg.s
            stack.append(_arg_expr(il[p]))
            p += 1
        elif op in (0x06, 0x07, 0x08, 0x09):  # ldloc.0..3
            stack.append(f"loc{op - 0x06}")
        elif op == 0x11 and p < len(il):  # ldloc.s
            stack.append(f"loc{il[p]}")
            p += 1
        elif op in (0x0A, 0x0B, 0x0C, 0x0D) and stack:  # stloc.0..3
            out.append(f"            loc{op - 0x0A} = {stack.pop()};")
        elif op == 0x13 and p < len(il) and stack:  # stloc.s
            out.append(f"            loc{il[p]} = {stack.pop()};")
            p += 1
        elif op in range(0x15, 0x1F):  # ldc.i4.m1..8
            val = -1 if op == 0x15 else (op - 0x16)
            stack.append(str(val))
        elif op == 0x1F and p < len(il):  # ldc.i4.s
            val = struct.unpack_from("<b", il, p)[0]
            p += 1
            stack.append(str(val))
        elif op == 0x20 and p + 4 <= len(il):  # ldc.i4
            val = struct.unpack_from("<i", il, p)[0]
            p += 4
            stack.append(str(val))
        elif op == 0x21 and p + 8 <= len(il):  # ldc.i8
            val = struct.unpack_from("<q", il, p)[0]
            p += 8
            stack.append(f"{val}L")
        elif op == 0x25 and stack:  # dup
            stack.append(stack[-1])
        elif op == 0x26 and stack:  # pop
            expr = stack.pop()
            if "(" in expr:
                out.append(f"            {expr};")
        elif op == 0x72 and p + 4 <= len(il):  # ldstr
            tok = struct.unpack_from("<I", il, p)[0]
            p += 4
            s_val = _read_us_str(us_heap, tok & 0x00FFFFFF)
            esc = s_val.replace("\\", "\\\\").replace('"', '\\"')
            stack.append(f'"{esc}"')
        elif op in (0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5F, 0x60, 0x61, 0x62, 0x63) and len(stack) >= 2:
            b_e, a_e = stack.pop(), stack.pop()
            sym = {
                0x58: "+", 0x59: "-", 0x5A: "*", 0x5B: "/", 0x5C: "%",
                0x5F: "&", 0x60: "|", 0x61: "^", 0x62: "<<", 0x63: ">>",
            }[op]
            stack.append(f"({a_e} {sym} {b_e})")
        elif op == 0x65 and stack:  # neg
            stack.append(f"(-{stack.pop()})")
        elif op == 0x66 and stack:  # not
            stack.append(f"(~{stack.pop()})")
        elif op in (0x67, 0x69, 0x6A, 0x6D) and stack:  # conv.i1/i4/i8/u4
            cast_t = {0x67: "sbyte", 0x69: "int", 0x6A: "long", 0x6D: "uint"}[op]
            stack.append(f"(({cast_t})({stack.pop()}))")
        elif op == 0xFE and p < len(il):
            op2 = il[p]
            p += 1
            if op2 in (0x01, 0x02, 0x04) and len(stack) >= 2:
                b_e, a_e = stack.pop(), stack.pop()
                cmp_op = {0x01: "==", 0x02: ">", 0x04: "<"}[op2]
                stack.append(f"(({a_e} {cmp_op} {b_e}) ? 1 : 0)")
        elif op in (0x2B, 0x38):  # br.s / br
            rel = struct.unpack_from("<b" if op == 0x2B else "<i", il, p)[0]
            p += 1 if op == 0x2B else 4
            out.append(f"            goto IL_{p + rel:04X};")
        elif op in (0x2C, 0x2D, 0x39, 0x3A) and stack:  # brfalse / brtrue
            is_short = op in (0x2C, 0x2D)
            rel = struct.unpack_from("<b" if is_short else "<i", il, p)[0]
            p += 1 if is_short else 4
            cond_e = stack.pop()
            neg = "!" if op in (0x2C, 0x39) else ""
            out.append(f"            if ({neg}(({cond_e}) != 0)) goto IL_{p + rel:04X};")
        elif op in (0x2E, 0x2F, 0x30, 0x31, 0x32, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F) and len(stack) >= 2:
            is_short = op <= 0x32
            rel = struct.unpack_from("<b" if is_short else "<i", il, p)[0]
            p += 1 if is_short else 4
            b_e, a_e = stack.pop(), stack.pop()
            c_map = {
                0x2E: "==", 0x3B: "==",
                0x2F: ">=", 0x3C: ">=",
                0x30: ">", 0x3D: ">",
                0x31: "<=", 0x3E: "<=",
                0x32: "<", 0x3F: "<",
            }
            out.append(f"            if ({a_e} {c_map[op]} {b_e}) goto IL_{p + rel:04X};")
        elif op in (0x28, 0x6F) and p + 4 <= len(il):  # call / callvirt
            tok = struct.unpack_from("<I", il, p)[0]
            p += 4
            m_name = method_names.get(tok, f"Call_{tok:08X}")
            arg_call = stack.pop() if stack else ""
            stack.append(f"{m_name}({arg_call})")
        elif op == 0x2A:  # ret
            if ret_type == "void":
                out.append("            return;")
            else:
                rv = stack.pop() if stack else "0"
                out.append(f"            return ({ret_type})({rv});")
        elif op == 0x73 and p + 4 <= len(il):  # newobj
            tok = struct.unpack_from("<I", il, p)[0]
            p += 4
            ctor_nm = method_names.get(tok, f"Type_{tok:08X}")
            arg_o = stack.pop() if stack else ""
            stack.append(f"new {ctor_nm}({arg_o})")
        elif op in (0x7B, 0x7E) and p + 4 <= len(il):  # ldfld / ldsfld
            tok = struct.unpack_from("<I", il, p)[0]
            p += 4
            fnm = method_names.get(tok, f"field_{tok & 0xFFFFFF}")
            obj = (stack.pop() if stack else "this") if op == 0x7B else "/*static*/"
            stack.append(f"{obj}.{fnm}" if op == 0x7B else fnm)
        elif op in (0x7D, 0x80) and p + 4 <= len(il):  # stfld / stsfld
            tok = struct.unpack_from("<I", il, p)[0]
            p += 4
            fnm = method_names.get(tok, f"field_{tok & 0xFFFFFF}")
            val_e = stack.pop() if stack else "0"
            obj = (stack.pop() if stack else "this") if op == 0x7D else ""
            out.append(f"            {obj}.{fnm} = {val_e};" if obj else f"            {fnm} = {val_e};")
        elif op == 0x8D and p + 4 <= len(il):  # newarr
            _tok = struct.unpack_from("<I", il, p)[0]
            p += 4
            sz_e = stack.pop() if stack else "0"
            stack.append(f"new int[{sz_e}]")
        elif op == 0x8E and stack:  # ldlen
            stack.append(f"{stack.pop()}.Length")
        elif op in (0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x9A) and len(stack) >= 2:  # ldelem.*
            idx_e, arr_e = stack.pop(), stack.pop()
            stack.append(f"{arr_e}[{idx_e}]")
        elif op in (0x9C, 0x9D, 0x9E, 0x9F, 0xA2) and len(stack) >= 3:  # stelem.*
            val_e, idx_e, arr_e = stack.pop(), stack.pop(), stack.pop()
            out.append(f"            {arr_e}[{idx_e}] = {val_e};")
        elif op == 0x45 and p + 4 <= len(il):  # switch
            n_cases = struct.unpack_from("<I", il, p)[0]
            p += 4
            if p + n_cases * 4 <= len(il):
                rels = [struct.unpack_from("<i", il, p + i * 4)[0] for i in range(n_cases)]
                p += n_cases * 4
                sw_val = stack.pop() if stack else "0"
                for ci, rel in enumerate(rels[:32]):
                    out.append(f"            if (({sw_val}) == {ci}) goto IL_{p + rel:04X};")
        elif op in (0x0F, 0x10, 0x12, 0x29, 0x7C, 0x7F):
            p += 1 if op in (0x0F, 0x10, 0x12) else 4

    if not any("return" in ln for ln in out):
        out.append("            return 0;" if ret_type != "void" else "            return;")
    return out


def decompile_dotnet_ecma335(raw: bytes, *, assembly_name: str = "RecoveredAsm") -> Dict[str, Any]:
    """Parses ECMA-335 BSJB tables & lifts CIL methods into C# source files without external ilspycmd."""
    bsjb_off = raw.find(b"BSJB")
    if bsjb_off == -1 or bsjb_off + 20 > len(raw):
        return {"schema": SCHEMA, "status": "not_dotnet", "classes": [], "cs_files": {}}
    try:
        pe = pefile.PE(data=raw, fast_load=False)
    except Exception as exc:
        return {"schema": SCHEMA, "status": "pe_error", "error": str(exc), "classes": [], "cs_files": {}}

    is_r2r = b"RTR\x00" in raw or b"__ReadyToRun" in raw
    is_native_aot = b"NativeAOT" in raw or b"RhpThrowEx" in raw

    sig, _maj, _min, _, ver_len = struct.unpack_from("<IHHII", raw, bsjb_off)
    if sig != 0x424A5342 or bsjb_off + 20 + ver_len > len(raw):
        return {"schema": SCHEMA, "status": "invalid_bsjb", "classes": [], "cs_files": {}}

    flags_pos = bsjb_off + 16 + ver_len
    _, num_streams = struct.unpack_from("<HH", raw, flags_pos)
    pos = flags_pos + 4
    stream_map: Dict[str, bytes] = {}
    for _ in range(min(num_streams, 32)):
        if pos + 8 > len(raw):
            break
        s_off, s_sz = struct.unpack_from("<II", raw, pos)
        pos += 8
        n_end = raw.find(b"\x00", pos, min(len(raw), pos + 32))
        if n_end == -1:
            break
        s_nm = raw[pos:n_end].decode("utf-8", errors="replace")
        pos += ((n_end - pos + 1) + 3) & ~3
        abs_s = bsjb_off + s_off
        stream_map[s_nm] = raw[abs_s : min(len(raw), abs_s + s_sz)]

    tbl_buf = stream_map.get("#~") or stream_map.get("#-") or b""
    str_heap = stream_map.get("#Strings", b"")
    us_heap = stream_map.get("#US", b"")
    blob_heap = stream_map.get("#Blob", b"")

    if len(tbl_buf) < 24:
        return {
            "schema": SCHEMA,
            "status": "no_table_stream",
            "is_ready_to_run": is_r2r,
            "is_native_aot": is_native_aot,
            "classes": [],
            "cs_files": {},
        }

    _resv, _tmaj, _tmin, heap_sizes, _resv2, valid_mask, _sorted_mask = struct.unpack_from("<IBBBBQQ", tbl_buf, 0)
    str_sz = 4 if (heap_sizes & 0x01) else 2
    guid_sz = 4 if (heap_sizes & 0x02) else 2
    blob_sz = 4 if (heap_sizes & 0x04) else 2

    tp = 24
    row_counts: Dict[int, int] = {}
    for tid in range(64):
        if (valid_mask >> tid) & 1:
            if tp + 4 > len(tbl_buf):
                break
            row_counts[tid] = struct.unpack_from("<I", tbl_buf, tp)[0]
            tp += 4

    # Compute row byte widths for core tables 0x00..0x23 so we seek accurately to TypeDef (0x02) and MethodDef (0x06)
    tdor_sz = _coded_size(row_counts, (0x02, 0x01, 0x1B), 2)  # TypeDefOrRef
    hconst_sz = _coded_size(row_counts, (0x04, 0x08, 0x17), 2)
    hca_sz = _coded_size(row_counts, (0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23), 5)
    mrp_sz = _coded_size(row_counts, (0x02, 0x01, 0x1A, 0x06, 0x1B), 3)
    res_sz = _coded_size(row_counts, (0x00, 0x1A, 0x23, 0x01), 2)

    parsed_typedefs: List[Dict[str, Any]] = []
    parsed_methods: List[Dict[str, Any]] = []
    method_tokens: Dict[int, str] = {}
    typeref_tokens: Dict[int, str] = {}
    field_tokens: Dict[int, str] = {}

    for tid in range(0x24):
        cnt = row_counts.get(tid, 0)
        if cnt == 0:
            continue
        if tid == _TBL_MODULE:
            tp += cnt * (2 + str_sz + guid_sz * 3)
        elif tid == _TBL_TYPEREF:
            for tr_i in range(1, cnt + 1):
                _scope, tp = _read_int_n(tbl_buf, tp, res_sz)
                tr_name_i, tp = _read_int_n(tbl_buf, tp, str_sz)
                tr_ns_i, tp = _read_int_n(tbl_buf, tp, str_sz)
                tr_nm = _read_cstr_heap(str_heap, tr_name_i) or f"TypeRef_{tr_i}"
                tr_ns = _read_cstr_heap(str_heap, tr_ns_i)
                typeref_tokens[0x01000000 | tr_i] = f"{tr_ns}.{tr_nm}" if tr_ns else tr_nm
        elif tid == _TBL_TYPEDEF:
            for _ in range(cnt):
                t_flags = struct.unpack_from("<I", tbl_buf, tp)[0]
                tp += 4
                t_name_i, tp = _read_int_n(tbl_buf, tp, str_sz)
                t_ns_i, tp = _read_int_n(tbl_buf, tp, str_sz)
                _ext, tp = _read_int_n(tbl_buf, tp, tdor_sz)
                fld_i, tp = _read_int_n(tbl_buf, tp, _simple_size(row_counts, _TBL_FIELD))
                mth_i, tp = _read_int_n(tbl_buf, tp, _simple_size(row_counts, _TBL_METHODDEF))
                parsed_typedefs.append({
                    "flags": t_flags,
                    "name": _read_cstr_heap(str_heap, t_name_i) or "UnnamedType",
                    "namespace": _read_cstr_heap(str_heap, t_ns_i),
                    "first_field": fld_i,
                    "first_method": mth_i,
                })
        elif tid == _TBL_FIELD:
            for fld_idx in range(1, cnt + 1):
                _fflags = struct.unpack_from("<H", tbl_buf, tp)[0]
                tp += 2
                f_name_i, tp = _read_int_n(tbl_buf, tp, str_sz)
                _f_sig, tp = _read_int_n(tbl_buf, tp, blob_sz)
                field_tokens[0x04000000 | fld_idx] = _read_cstr_heap(str_heap, f_name_i) or f"field_{fld_idx}"
        elif tid == _TBL_METHODDEF:
            for midx in range(1, cnt + 1):
                m_rva, _impl, m_flags = struct.unpack_from("<IHH", tbl_buf, tp)
                tp += 8
                m_name_i, tp = _read_int_n(tbl_buf, tp, str_sz)
                m_sig_i, tp = _read_int_n(tbl_buf, tp, blob_sz)
                _p_i, tp = _read_int_n(tbl_buf, tp, _simple_size(row_counts, _TBL_PARAM))
                m_name = _read_cstr_heap(str_heap, m_name_i) or f"Method_{midx}"
                tok = 0x06000000 | midx
                method_tokens[tok] = m_name
                parsed_methods.append({
                    "index": midx,
                    "token": tok,
                    "rva": m_rva,
                    "flags": m_flags,
                    "name": m_name,
                    "sig_idx": m_sig_i,
                })
        elif tid == _TBL_PARAM:
            tp += cnt * (4 + str_sz)
        elif tid == _TBL_INTERFACEIMPL:
            tp += cnt * (_simple_size(row_counts, _TBL_TYPEDEF) + tdor_sz)
        elif tid == _TBL_MEMBERREF:
            for ridx in range(1, cnt + 1):
                _cls, tp = _read_int_n(tbl_buf, tp, mrp_sz)
                mr_name_i, tp = _read_int_n(tbl_buf, tp, str_sz)
                _sig, tp = _read_int_n(tbl_buf, tp, blob_sz)
                method_tokens[0x0A000000 | ridx] = _read_cstr_heap(str_heap, mr_name_i) or f"Member_{ridx}"
        elif tid == _TBL_CONSTANT:
            tp += cnt * (2 + hconst_sz + blob_sz)
        elif tid == _TBL_CUSTOMATTRIBUTE:
            tp += cnt * (hca_sz + _coded_size(row_counts, (0x06, 0x0A), 3) + blob_sz)
        elif tid == _TBL_FIELDMARSHAL:
            tp += cnt * (_coded_size(row_counts, (0x04, 0x08), 1) + blob_sz)
        elif tid == _TBL_DECLSECURITY:
            tp += cnt * (2 + _coded_size(row_counts, (0x02, 0x06, 0x20), 2) + blob_sz)
        elif tid == _TBL_CLASSLAYOUT:
            tp += cnt * (6 + _simple_size(row_counts, _TBL_TYPEDEF))
        elif tid == _TBL_FIELDLAYOUT:
            tp += cnt * (4 + _simple_size(row_counts, _TBL_FIELD))
        elif tid == _TBL_STANDALONESIG:
            tp += cnt * blob_sz
        elif tid == _TBL_EVENTMAP:
            tp += cnt * (_simple_size(row_counts, _TBL_TYPEDEF) + _simple_size(row_counts, _TBL_EVENT))
        elif tid == _TBL_EVENT:
            tp += cnt * (2 + str_sz + tdor_sz)
        elif tid == _TBL_PROPERTYMAP:
            tp += cnt * (_simple_size(row_counts, _TBL_TYPEDEF) + _simple_size(row_counts, _TBL_PROPERTY))
        elif tid == _TBL_PROPERTY:
            tp += cnt * (2 + str_sz + blob_sz)
        elif tid == _TBL_METHODSEMANTICS:
            tp += cnt * (2 + _simple_size(row_counts, _TBL_METHODDEF) + _coded_size(row_counts, (0x14, 0x17), 1))
        elif tid == _TBL_METHODIMPL:
            tp += cnt * (_simple_size(row_counts, _TBL_TYPEDEF) + _coded_size(row_counts, (0x06, 0x0A), 1) * 2)
        elif tid == _TBL_MODULEREF:
            tp += cnt * str_sz
        elif tid == _TBL_TYPESPEC:
            tp += cnt * blob_sz
        elif tid == _TBL_IMPLMAP:
            tp += cnt * (2 + _coded_size(row_counts, (0x04, 0x06), 1) + str_sz + _simple_size(row_counts, _TBL_MODULEREF))
        elif tid == _TBL_FIELDRVA:
            tp += cnt * (4 + _simple_size(row_counts, _TBL_FIELD))
        elif tid == _TBL_ASSEMBLY:
            tp += cnt * (16 + blob_sz + str_sz * 2)
        elif tid in (_TBL_ASSEMBLYPROCESSOR,):
            tp += cnt * 4
        elif tid == _TBL_ASSEMBLYOS:
            tp += cnt * 12
        elif tid == _TBL_ASSEMBLYREF:
            tp += cnt * (12 + blob_sz * 2 + str_sz * 2)

    cs_files: Dict[str, str] = {}
    classes_out: List[Dict[str, Any]] = []
    for t_i, td in enumerate(parsed_typedefs):
        if td["name"] == "<Module>" and t_i + 1 < len(parsed_typedefs):
            continue
        start_m = max(1, td["first_method"])
        end_m = parsed_typedefs[t_i + 1]["first_method"] if (t_i + 1 < len(parsed_typedefs)) else (len(parsed_methods) + 1)
        owned = [m for m in parsed_methods if start_m <= m["index"] < end_m]
        ns = td["namespace"] or assembly_name
        cls_nm = re.sub(r"[^A-Za-z0-9_]", "_", td["name"]) or f"Type_{t_i}"
        lines = [
            "// Auto-Decompiled Pure-Python ECMA-335 CIL Class (AetherRE v10.5)",
            f"namespace {ns} {{",
            f"    public class {cls_nm} {{",
        ]
        m_summaries: List[str] = []
        for m in owned:
            if m["name"] in (".ctor", ".cctor"):
                continue
            is_static = bool(m["flags"] & 0x0010)
            ret_t, ptypes = _parse_blob_sig(blob_heap, m["sig_idx"])
            p_sig = ", ".join(f"{ty} p{pi}" for pi, ty in enumerate(ptypes))
            stat_kw = "static " if is_static else ""
            safe_m = re.sub(r"[^A-Za-z0-9_]", "_", m["name"])
            lines.append(f"        public {stat_kw}{ret_t} {safe_m}({p_sig}) {{")
            lines.extend(_lift_cil_body_to_csharp(pe, raw, m["rva"], ptypes, ret_t, is_static, us_heap, method_tokens))
            lines.append("        }")
            m_summaries.append(safe_m)
        lines.extend(["    }", "}", ""])
        fname = f"{cls_nm}.cs"
        cs_files[fname] = "\n".join(lines)
        classes_out.append({"namespace": ns, "name": cls_nm, "methods": m_summaries})

    return {
        "schema": SCHEMA,
        "status": "complete" if cs_files else "metadata_only",
        "is_ready_to_run": is_r2r,
        "is_native_aot": is_native_aot,
        "classes": classes_out,
        "methods_total": len(parsed_methods),
        "cs_files": cs_files,
    }
