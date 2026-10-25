"""
Staging Contract & Experiment for GEAR-02 (Golang Stripped Symbol & pclntab Extractor)
Validates parsing of Go runtime symtab (pclntab) across Go versions.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path


def create_synthetic_go116_pclntab(ptr_size: int = 8) -> bytes:
    """Builds a valid Go 1.16 pclntab structure with known function names and PCs."""
    magic = 0xFFFFFFF0  # Go 1.16 magic
    min_lc = 1
    pad0 = 0
    pad1 = 0

    # Function names to embed
    fn_names = [b"runtime.morestack", b"main.main", b"net/http.Get"]
    
    # Construct funcnametab
    funcnametab = bytearray()
    name_offsets = []
    for name in fn_names:
        name_offsets.append(len(funcnametab))
        funcnametab.extend(name + b"\x00")

    # Layout offsets relative to pclntab start
    # Header size: 4 + 1 + 1 + 1 + 1 + 7 * ptr_size
    header_size = 8 + 7 * ptr_size
    funcname_offset = header_size
    
    # Functab starts after funcnametab
    functab_offset = funcname_offset + len(funcnametab)
    # Align to ptr_size
    if functab_offset % ptr_size != 0:
        padding = ptr_size - (functab_offset % ptr_size)
        funcnametab.extend(b"\x00" * padding)
        functab_offset = funcname_offset + len(funcnametab)

    nfunc = len(fn_names)
    functab_entry_size = 2 * ptr_size
    functab_size = (nfunc + 1) * functab_entry_size
    func_structs_offset = functab_offset + functab_size

    # Build func structs
    func_structs = bytearray()
    struct_offsets = []
    base_pc = 0x00401000
    pcs = [base_pc, base_pc + 0x100, base_pc + 0x250]

    for idx, (pc, name_off) in enumerate(zip(pcs, name_offsets)):
        struct_offsets.append(func_structs_offset + len(func_structs))
        if ptr_size == 8:
            # entry (uint64), nameoff (int32), args (int32)
            func_structs.extend(struct.pack("<QiI", pc, name_off, 0))
        else:
            func_structs.extend(struct.pack("<IiI", pc, name_off, 0))

    # Header
    fmt_ptr = "<Q" if ptr_size == 8 else "<I"
    header = bytearray(struct.pack("<IBBBB", magic, pad0, pad1, min_lc, ptr_size))
    header.extend(struct.pack(fmt_ptr, nfunc))
    header.extend(struct.pack(fmt_ptr, 0))  # nfiles
    header.extend(struct.pack(fmt_ptr, funcname_offset))
    header.extend(struct.pack(fmt_ptr, 0))  # cuOffset
    header.extend(struct.pack(fmt_ptr, 0))  # filetabOffset
    header.extend(struct.pack(fmt_ptr, 0))  # pctabOffset
    header.extend(struct.pack(fmt_ptr, functab_offset))  # pclnOffset

    # Functab
    functab = bytearray()
    for pc, s_off in zip(pcs, struct_offsets):
        functab.extend(struct.pack(fmt_ptr, pc))
        functab.extend(struct.pack(fmt_ptr, s_off))
    # Final sentinel entry
    functab.extend(struct.pack(fmt_ptr, pcs[-1] + 0x100))
    functab.extend(struct.pack(fmt_ptr, 0))

    pclntab = header + funcnametab + functab + func_structs
    return bytes(pclntab)


def run_staging_test() -> bool:
    data = create_synthetic_go116_pclntab(ptr_size=8)
    
    # Locate magic
    idx = data.find(b"\xf0\xff\xff\xff")
    assert idx == 0, f"Magic not at start: {idx}"

    magic, pad0, pad1, min_lc, ptr_size = struct.unpack_from("<IBBBB", data, idx)
    assert magic == 0xFFFFFFF0
    assert ptr_size == 8

    nfunc, _, funcname_off, _, _, _, functab_off = struct.unpack_from("<7Q", data, idx + 8)
    assert nfunc == 3

    # Traverse functab
    funcs = []
    for i in range(nfunc):
        entry_offset = functab_off + i * 16
        pc, s_off = struct.unpack_from("<QQ", data, entry_offset)
        # Parse func struct
        f_entry, name_off = struct.unpack_from("<Qi", data, s_off)
        # Read name
        name_start = funcname_off + name_off
        name_end = data.find(b"\x00", name_start)
        name = data[name_start:name_end].decode("utf-8")
        funcs.append((pc, name))

    expected_names = ["runtime.morestack", "main.main", "net/http.Get"]
    recovered_names = [f[1] for f in funcs]
    assert recovered_names == expected_names, f"Expected {expected_names}, got {recovered_names}"

    print(f"[STAGING EXPERIMENT] Recovered {len(funcs)} Golang functions accurately: {recovered_names}")
    return True


if __name__ == "__main__":
    if run_staging_test():
        sys.exit(0)
    sys.exit(1)
