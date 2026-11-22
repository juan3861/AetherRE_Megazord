"""Win64 PE64 Exception Handling (.pdata / .xdata UNWIND_INFO) Decoder (v6.2.0).

Decodes Win64 RUNTIME_FUNCTION entries and UNWIND_INFO structures to extract:
  - Prologue size and exact fixed stack frame allocation size (bytes)
  - Saved non-volatile general-purpose and XMM registers
  - Frame pointer register (e.g., RBP) and scaled FrameOffset
  - Structured Exception Handler (EHANDLER / UHANDLER) RVAs and CHAININFO links
"""
from __future__ import annotations

import struct
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_WIN64_REG_NAMES: Tuple[str, ...] = (
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)

UNW_FLAG_NHANDLER = 0x0
UNW_FLAG_EHANDLER = 0x1
UNW_FLAG_UHANDLER = 0x2
UNW_FLAG_CHAININFO = 0x4


@dataclass
class Win64UnwindRecord:
    begin_rva: int
    end_rva: int
    unwind_info_rva: int
    version: int
    flags: int
    has_ehandler: bool
    has_uhandler: bool
    is_chained: bool
    prolog_size: int
    frame_register: Optional[str]
    frame_offset_bytes: int
    stack_frame_bytes: int
    saved_nonvol_regs: List[str] = field(default_factory=list)
    saved_xmm_regs: List[str] = field(default_factory=list)
    exception_handler_rva: Optional[int] = None
    chained_begin_rva: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _decode_single_unwind_info(
    pe: Any,
    pe_data: bytes,
    begin_rva: int,
    end_rva: int,
    ui_rva: int,
) -> Optional[Win64UnwindRecord]:
    try:
        off = pe.get_offset_from_rva(ui_rva)
    except Exception:
        return None
    if off < 0 or off + 4 > len(pe_data):
        return None

    b0, prolog_size, code_count, b3 = struct.unpack_from("<BBBB", pe_data, off)
    version = b0 & 0x7
    if version not in (1, 2):
        return None
    flags = (b0 >> 3) & 0x1F
    frame_reg_idx = b3 & 0xF
    frame_off_scaled = ((b3 >> 4) & 0xF) * 16
    frame_reg = _WIN64_REG_NAMES[frame_reg_idx] if 1 <= frame_reg_idx < len(_WIN64_REG_NAMES) else None

    saved_nonvol: List[str] = []
    saved_xmm: List[str] = []
    stack_bytes = 0
    cursor = off + 4
    idx = 0
    while idx < code_count and cursor + 2 <= len(pe_data):
        _code_off, op_and_info = struct.unpack_from("<BB", pe_data, cursor)
        unwind_op = op_and_info & 0xF
        op_info = (op_and_info >> 4) & 0xF
        slots_consumed = 1

        if unwind_op == 0:  # UWOP_PUSH_NONVOL
            if op_info < len(_WIN64_REG_NAMES):
                saved_nonvol.append(_WIN64_REG_NAMES[op_info])
            stack_bytes += 8
        elif unwind_op == 1:  # UWOP_ALLOC_LARGE
            if op_info == 0 and cursor + 4 <= len(pe_data):
                sz_qwords = struct.unpack_from("<H", pe_data, cursor + 2)[0]
                stack_bytes += sz_qwords * 8
                slots_consumed = 2
            elif op_info == 1 and cursor + 6 <= len(pe_data):
                stack_bytes += struct.unpack_from("<I", pe_data, cursor + 2)[0]
                slots_consumed = 3
        elif unwind_op == 2:  # UWOP_ALLOC_SMALL
            stack_bytes += (op_info * 8) + 8
        elif unwind_op == 3:  # UWOP_SET_FPREG
            pass
        elif unwind_op == 4:  # UWOP_SAVE_NONVOL
            if op_info < len(_WIN64_REG_NAMES):
                saved_nonvol.append(_WIN64_REG_NAMES[op_info])
            slots_consumed = 2
        elif unwind_op == 5:  # UWOP_SAVE_NONVOL_FAR
            if op_info < len(_WIN64_REG_NAMES):
                saved_nonvol.append(_WIN64_REG_NAMES[op_info])
            slots_consumed = 3
        elif unwind_op == 6:  # UWOP_EPILOG (v2)
            pass
        elif unwind_op == 8:  # UWOP_SAVE_XMM128
            saved_xmm.append(f"xmm{op_info}")
            slots_consumed = 2
        elif unwind_op == 9:  # UWOP_SAVE_XMM128_FAR
            saved_xmm.append(f"xmm{op_info}")
            slots_consumed = 3
        elif unwind_op == 10:  # UWOP_PUSH_MACHFRAME
            stack_bytes += 48 if op_info else 40

        idx += slots_consumed
        cursor += slots_consumed * 2

    # Trailer (Exception Handler RVA or Chained RUNTIME_FUNCTION) is 4-byte aligned after UNWIND_CODE array
    aligned_count = code_count + (code_count & 1)
    trailer_off = off + 4 + (aligned_count * 2)

    has_ehandler = bool(flags & UNW_FLAG_EHANDLER)
    has_uhandler = bool(flags & UNW_FLAG_UHANDLER)
    is_chained = bool(flags & UNW_FLAG_CHAININFO)
    eh_rva: Optional[int] = None
    chained_begin: Optional[int] = None

    if is_chained and trailer_off + 12 <= len(pe_data):
        chained_begin = struct.unpack_from("<I", pe_data, trailer_off)[0]
    elif (has_ehandler or has_uhandler) and trailer_off + 4 <= len(pe_data):
        cand_eh = struct.unpack_from("<I", pe_data, trailer_off)[0]
        if cand_eh > 0:
            eh_rva = cand_eh

    # Deduplicate register order cleanly while preserving first-seen order
    dedup_nonvol = list(dict.fromkeys(saved_nonvol))
    dedup_xmm = list(dict.fromkeys(saved_xmm))

    return Win64UnwindRecord(
        begin_rva=begin_rva,
        end_rva=end_rva,
        unwind_info_rva=ui_rva,
        version=version,
        flags=flags,
        has_ehandler=has_ehandler,
        has_uhandler=has_uhandler,
        is_chained=is_chained,
        prolog_size=prolog_size,
        frame_register=frame_reg,
        frame_offset_bytes=frame_off_scaled,
        stack_frame_bytes=stack_bytes,
        saved_nonvol_regs=dedup_nonvol,
        saved_xmm_regs=dedup_xmm,
        exception_handler_rva=eh_rva,
        chained_begin_rva=chained_begin,
    )


def parse_win64_unwind_table(pe: Any, pe_data: bytes) -> Dict[str, Any]:
    """Parses PE64 .pdata + .xdata tables into structured per-function unwind/SEH records."""
    records_by_rva: Dict[int, Win64UnwindRecord] = {}
    ehandler_rvas: List[int] = []
    if pe is None or not pe_data:
        return {"records_by_rva": {}, "total_functions": 0, "ehandlers_count": 0, "ehandler_rvas": []}

    for sec in getattr(pe, "sections", []):
        if not sec.Name.startswith(b".pdata"):
            continue
        p_raw = int(sec.PointerToRawData)
        p_sz = min(int(sec.Misc_VirtualSize), len(pe_data) - p_raw)
        for off in range(p_raw, p_raw + p_sz - 11, 12):
            fn_b, fn_e, ui_rva = struct.unpack_from("<III", pe_data, off)
            if fn_b == 0 or fn_e <= fn_b or ui_rva == 0:
                continue
            rec = _decode_single_unwind_info(pe, pe_data, fn_b, fn_e, ui_rva)
            if rec is not None:
                records_by_rva[fn_b] = rec
                if rec.exception_handler_rva is not None:
                    ehandler_rvas.append(fn_b)

    return {
        "records_by_rva": records_by_rva,
        "total_functions": len(records_by_rva),
        "ehandlers_count": len(ehandler_rvas),
        "ehandler_rvas": sorted(set(ehandler_rvas)),
    }
