"""End-to-end multi-architecture tests: ELF64 (AArch64 & SysV x86_64) + PE64 ARM64 (v6.2.0)."""

from __future__ import annotations

import ctypes
import struct
from pathlib import Path
from typing import List, Tuple

from aether_re.project_reconstructor import (
    compile_llvm_twin_project,
    compile_reconstructed_project,
    reconstruct_project,
)


def _build_elf64_so(e_machine: int, funcs: List[Tuple[str, bytes]]) -> bytes:
    """Builds a minimal valid ELF64 shared object (ET_DYN) parseable by pyelftools."""
    ehdr_size = 64
    text_vaddr = 0x1000
    text_off = 0x1000

    text_chunks: List[bytes] = []
    sym_defs: List[Tuple[str, int, int]] = []
    cur_off = 0
    for nm, code in funcs:
        sym_defs.append((nm, text_vaddr + cur_off, len(code)))
        text_chunks.append(code)
        cur_off += len(code)
    text_bytes = b"".join(text_chunks)

    strtab = bytearray(b"\x00")
    syms = bytearray(b"\x00" * 24)  # STN_UNDEF
    for nm, va, sz in sym_defs:
        nm_off = len(strtab)
        strtab.extend(nm.encode("ascii") + b"\x00")
        # st_name(I), st_info(B)=(STB_GLOBAL<<4 | STT_FUNC)=0x12, st_other(B)=0, st_shndx(H)=1, st_value(Q), st_size(Q)
        syms.extend(struct.pack("<IBBHQQ", nm_off, 0x12, 0, 1, va, sz))

    shstrtab = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    sh_name_text = shstrtab.index(b".text")
    sh_name_sym = shstrtab.index(b".symtab")
    sh_name_str = shstrtab.index(b".strtab")
    sh_name_shstr = shstrtab.index(b".shstrtab")

    sym_off = text_off + len(text_bytes)
    str_off = sym_off + len(syms)
    shstr_off = str_off + len(strtab)
    shdr_off = (shstr_off + len(shstrtab) + 7) & ~7

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,  # ELF64 little-endian
        3,              # ET_DYN
        e_machine,      # EM_X86_64=62, EM_AARCH64=183
        1,              # EV_CURRENT
        text_vaddr,     # e_entry
        0,              # e_phoff
        shdr_off,       # e_shoff
        0,              # e_flags
        ehdr_size,      # e_ehsize
        56,             # e_phentsize
        0,              # e_phnum
        64,             # e_shentsize
        5,              # e_shnum (NULL, .text, .symtab, .strtab, .shstrtab)
        4,              # e_shstrndx
    )

    sh_null = b"\x00" * 64
    sh_text = struct.pack("<IIQQQQIIQQ", sh_name_text, 1, 0x6, text_vaddr, text_off, len(text_bytes), 0, 0, 16, 0)
    sh_sym = struct.pack("<IIQQQQIIQQ", sh_name_sym, 2, 0, 0, sym_off, len(syms), 3, 1, 8, 24)
    sh_str = struct.pack("<IIQQQQIIQQ", sh_name_str, 3, 0, 0, str_off, len(strtab), 0, 0, 1, 0)
    sh_shstr = struct.pack("<IIQQQQIIQQ", sh_name_shstr, 3, 0, 0, shstr_off, len(shstrtab), 0, 0, 1, 0)

    buf = bytearray(shdr_off + 5 * 64)
    buf[0:64] = ehdr
    buf[text_off : text_off + len(text_bytes)] = text_bytes
    buf[sym_off : sym_off + len(syms)] = syms
    buf[str_off : str_off + len(strtab)] = strtab
    buf[shstr_off : shstr_off + len(shstrtab)] = shstrtab
    buf[shdr_off : shdr_off + 320] = sh_null + sh_text + sh_sym + sh_str + sh_shstr
    return bytes(buf)


def _build_pe64_arm64(func_name: str, code: bytes) -> bytes:
    """Builds a minimal valid PE64 ARM64 (Machine=0xAA64) DLL with one exported function."""
    dos_hdr = bytearray(0x80)
    dos_hdr[0:2] = b"MZ"
    struct.pack_into("<I", dos_hdr, 0x3C, 0x80)

    # PE signature + COFF header (20B) + Optional header PE32+ (240B) + 2 Section headers (80B)
    coff = struct.pack("<HHIIIHH", 0xAA64, 2, 0, 0, 0, 240, 0x2022)
    opt = bytearray(240)
    struct.pack_into("<HBB", opt, 0, 0x020B, 14, 0)  # PE32+ magic
    struct.pack_into("<I", opt, 16, 0x1000)          # AddressOfEntryPoint
    struct.pack_into("<QII", opt, 24, 0x180000000, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", opt, 40, 10, 0, 0, 0, 10, 0)
    struct.pack_into("<II", opt, 56, 0x3000, 0x400)  # SizeOfImage, SizeOfHeaders
    struct.pack_into("<HH", opt, 68, 3, 0)           # Subsystem=CUI
    struct.pack_into("<QQQQII", opt, 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    struct.pack_into("<II", opt, 112, 0x2000, 128)   # Export Directory RVA & Size

    sec_text = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", len(code), 0x1000, 0x200, 0x400, 0, 0, 0, 0, 0x60000020)
    sec_edata = struct.pack("<8sIIIIIIHHI", b".edata\x00\x00", 128, 0x2000, 0x200, 0x600, 0, 0, 0, 0, 0x40000040)

    buf = bytearray(0x800)
    buf[0:0x80] = dos_hdr
    buf[0x80:0x84] = b"PE\x00\x00"
    buf[0x84:0x98] = coff
    buf[0x98:0x188] = opt
    buf[0x188:0x1B0] = sec_text
    buf[0x1B0:0x1D8] = sec_edata
    buf[0x400 : 0x400 + len(code)] = code

    # Export directory at RVA 0x2000 (file 0x600)
    # struct IMAGE_EXPORT_DIRECTORY (40 bytes): Name@0x2034, Base=1, NumberOfFunctions=1, NumberOfNames=1,
    # AddressOfFunctions@0x2028, AddressOfNames@0x202C, AddressOfNameOrdinals@0x2030
    fn_b = func_name.encode("ascii") + b"\x00"
    dll_b = b"arm64_test.dll\x00"
    struct.pack_into("<IIHHIIIIIII", buf, 0x600, 0, 0, 0, 0, 0x2040, 1, 1, 1, 0x2028, 0x202C, 0x2030)
    struct.pack_into("<I", buf, 0x628, 0x1000)       # EAT[0] -> 0x1000
    struct.pack_into("<I", buf, 0x62C, 0x2050)       # ENPT[0] -> func_name
    struct.pack_into("<H", buf, 0x630, 0)            # Ordinal[0] -> 0
    buf[0x640 : 0x640 + len(dll_b)] = dll_b
    buf[0x650 : 0x650 + len(fn_b)] = fn_b
    return bytes(buf)


_ARM64_SUM_TO_N = b"".join(
    struct.pack("<I", w)
    for w in (0xD2800009, 0xD280000A, 0xEB00015F, 0x5400008A, 0x8B0A0129, 0x9100054A, 0x17FFFFFC, 0xAA0903E0, 0xD65F03C0)
)
_X64_SYSV_SUM_MUL = bytes.fromhex("488d0437480fafc2c3")


def test_elf64_aarch64_cross_recompilation_and_live_execution(tmp_path: Path) -> None:
    elf_path = tmp_path / "libarm64_sum.so"
    elf_path.write_bytes(_build_elf64_so(183, [("sum_to_n", _ARM64_SUM_TO_N)]))

    out_dir = tmp_path / "out_arm64"
    rep = reconstruct_project(elf_path, out_dir)
    assert rep.status == "complete"
    assert rep.architecture == "elf_aarch64"
    assert rep.total_exports_reconstructed == 1
    assert rep.overall_congruence_pct == 100.0
    assert rep.ctree_structured_functions == 1
    assert rep.llvm_ir_verified is True
    assert rep.llvm_coff_obj_bytes > 0

    lnk = compile_llvm_twin_project(out_dir)
    assert lnk["compiled"] is True
    dll = ctypes.CDLL(str(lnk["dll_path"]))
    dll.sum_to_n.argtypes = [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64]
    dll.sum_to_n.restype = ctypes.c_int64
    assert dll.sum_to_n(10, 0, 0, 0) == 45
    assert dll.sum_to_n(100, 0, 0, 0) == 4950

    msvc_res = compile_reconstructed_project(out_dir, "reconstructed_msvc_from_arm64.dll")
    assert msvc_res["compiled"] is True


def test_elf64_x86_64_sysv_cross_recompilation(tmp_path: Path) -> None:
    elf_path = tmp_path / "libsysv_x64.so"
    elf_path.write_bytes(_build_elf64_so(62, [("sum_pair_mul", _X64_SYSV_SUM_MUL)]))

    out_dir = tmp_path / "out_sysv"
    rep = reconstruct_project(elf_path, out_dir)
    assert rep.status == "complete"
    assert rep.architecture == "elf_x86_64"
    assert rep.overall_congruence_pct == 100.0
    assert rep.llvm_ir_verified is True

    lnk = compile_llvm_twin_project(out_dir)
    assert lnk["compiled"] is True
    dll = ctypes.CDLL(str(lnk["dll_path"]))
    dll.sum_pair_mul.argtypes = [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64]
    dll.sum_pair_mul.restype = ctypes.c_int64
    assert dll.sum_pair_mul(10, 20, 5, 0) == 150


def test_pe64_arm64_native_reconstruction(tmp_path: Path) -> None:
    pe_path = tmp_path / "arm64_sum.dll"
    pe_path.write_bytes(_build_pe64_arm64("sum_to_n", _ARM64_SUM_TO_N))

    out_dir = tmp_path / "out_pe_arm64"
    rep = reconstruct_project(pe_path, out_dir)
    assert rep.status == "complete"
    assert rep.architecture == "pe_aarch64"
    assert rep.overall_congruence_pct == 100.0
    assert rep.llvm_ir_verified is True
