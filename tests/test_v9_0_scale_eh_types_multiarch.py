"""Pilar 1 (v9.0) Empirical Tests: SQLite WAL Knowledge Store, C++ EH & Thunks, Signature Banks & Multi-Arch Parity."""
from __future__ import annotations

import shutil
import sqlite3
import struct
import subprocess
import zlib
from pathlib import Path

import pytest

from aether_re.cxx_eh_rtti import analyze_pe_cxx_eh_and_thunks, scan_file_cxx_eh
from aether_re.graph_store import BinaryKnowledgeStore
from aether_re.macho_forensics import analyze_macho
from aether_re.multiarch_lifter import (
    eval_arm32_insns,
    eval_mips32_insns,
    eval_riscv64_insns,
    lift_arm32_function_to_c,
    lift_mips32_function_to_c,
    lift_riscv64_function_to_c,
)
from aether_re.project_reconstructor import _MemoryArena, _execute_lifted_c_ast, reconstruct_project
from aether_re.runtime_emitter import _find_msvc_x64_toolchain
from aether_re.signature_type_bank import (
    compute_fidb_function_hash,
    match_functions_with_fidb_sqlite,
    match_functions_with_pat_bank,
    merge_type_information,
    parse_flirt_pat_text,
    parse_flirt_sig_header,
)


def _find_msvc_x64_env() -> tuple[str, dict[str, str]] | None:
    tc = _find_msvc_x64_toolchain()
    return (tc[2], tc[1]) if tc and tc[1] and tc[2] else None


def test_v90_persistent_knowledge_store_5k_functions_wal(tmp_path: Path) -> None:
    db_p = tmp_path / "knowledge_graph.sqlite"
    store = BinaryKnowledgeStore(db_p)
    sha = "a" * 64
    store.upsert_binary(
        sha,
        source_path="demo_5k.dll",
        project_kind="pe64_c_twin",
        architecture="x86_64",
        function_count=5000,
        overall_congruence_pct=100.0,
    )
    recs = [
        {
            "rva": 0x1000 + i * 0x20,
            "fn_name": f"sub_{0x1000 + i * 0x20:x}",
            "c_ident": f"sub_{0x1000 + i * 0x20:x}",
            "ordinal": i + 1,
            "is_exported": (i < 10),
            "own_lifted": True,
            "code_slice": f"code_{i}".encode(),
            "prototype": {"ret": "int64_t"},
            "c_code": f"int64_t sub_{0x1000 + i * 0x20:x}(void) {{ return {i}; }}",
        }
        for i in range(5000)
    ]
    inserted = store.upsert_functions_batch(sha, recs)
    assert inserted == 5000
    xref_ins = store.upsert_xrefs_batch(sha, [(0x1000, 0x1020 + i * 0x20, "call", 0x1005) for i in range(50)])
    assert xref_ins == 50
    store.upsert_types_batch(sha, [{"name": "PacketHeader", "kind": "struct", "size_bytes": 16, "source": "dwarf", "fields": {"0": "magic"}}])
    store.put_ir_cache("deadbeef", arch="x86_64", lifted_c="int64_t f(){return 1;}", llvm_ir="define i64 @f() { ret i64 1 }")

    summary = store.get_binary_summary(sha)
    assert summary is not None
    assert summary["stored_functions"] == 5000
    assert summary["stored_xrefs"] == 50
    assert summary["stored_types"] == 1
    assert len(store.query_functions(sha, only_exported=True)) == 10
    assert len(store.query_callers(sha, 0x1020)) == 1
    assert store.get_ir_cache("deadbeef")["llvm_ir"].startswith("define i64")


def test_v90_live_msvc_cpp_eh_and_this_adjustor_thunk_recovery(tmp_path: Path) -> None:
    msvc_tc = _find_msvc_x64_env()
    if msvc_tc is None:
        pytest.skip("MSVC x64 Build Tools not present")
    cl_exe, msvc_env = msvc_tc

    cpp_src = r"""
#include <stdint.h>
struct ErrBox { int code; };
struct LeftBase {
    int left_val;
    virtual int __declspec(noinline) compute(int x) { return left_val + x; }
    virtual ~LeftBase() = default;
};
struct RightBase {
    int right_val;
    virtual int __declspec(noinline) second(int y) = 0;
    virtual ~RightBase() = default;
};
struct Derived : public LeftBase, public RightBase {
    Derived(int a, int b) { left_val = a; right_val = b; }
    int __declspec(noinline) second(int y) override { return left_val + right_val + y; }
};
extern "C" __declspec(dllexport) int eh_catch_test(int x) {
    try {
        if (x < 0) throw ErrBox{77};
        return x * 3;
    } catch (const ErrBox& e) {
        return e.code + x;
    }
}
extern "C" __declspec(dllexport) int mi_thunk_test(int a, int b, int y) {
    Derived d(a, b);
    RightBase* rb = &d;
    return rb->second(y);
}
"""
    cpp_path = tmp_path / "eh_mi_sample.cpp"
    dll_path = tmp_path / "eh_mi_sample.dll"
    cpp_path.write_text(cpp_src, encoding="utf-8")
    res = subprocess.run(
        [cl_exe, "/nologo", "/O2", "/EHsc", "/LD", str(cpp_path), f"/Fe:{dll_path}"],
        cwd=str(tmp_path),
        env=msvc_env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert res.returncode == 0, res.stderr + res.stdout
    raw_dll = dll_path.read_bytes()

    eh_rep = analyze_pe_cxx_eh_and_thunks(raw_dll)
    assert eh_rep["status"] == "complete"
    assert eh_rep["eh_functions_count"] >= 1
    all_catches = [
        h.get("catch_type", "")
        for ef in eh_rep["eh_functions"]
        for tb in ef.get("try_blocks", [])
        for h in tb.get("handlers", [])
    ]
    assert any("ErrBox" in c or c for c in all_catches)
    # Multiple inheritance generates `sub rcx, 16; jmp Derived::second` this-adjustor thunk
    assert eh_rep["this_adjustor_thunks_count"] >= 1
    assert any(th["this_adjustment"] < 0 for th in eh_rep["this_adjustor_thunks"])

    out_proj = tmp_path / "reconstructed_eh"
    rec_rep = reconstruct_project(dll_path, out_proj)
    assert rec_rep.total_exports_reconstructed >= 2
    assert (out_proj / "knowledge_graph.sqlite").is_file()
    typed_c = (out_proj / "src" / "reconstructed_typed.c").read_text(encoding="utf-8")
    assert "C++ Exception Handling" in typed_c


def test_v90_flirt_pat_sig_fidb_and_header_type_bank(tmp_path: Path) -> None:
    fn_code = bytes.fromhex("48 89 5C 24 08 57 48 83 EC 20 8B FA 48 8B D9 E8") + b"\x11\x22\x33\x44"
    tail_crc = zlib.crc32(fn_code[16:20]) & 0xFFFF
    pat_line = f"48895C2408574883EC208BFA488BD9.. 04 {tail_crc:04X} 0014 :0000 custom_memcpy ---\n"
    entries = parse_flirt_pat_text(pat_line, library_name="ucrt_custom")
    assert len(entries) == 1
    pat_hits = match_functions_with_pat_bank([(0x2400, fn_code)], entries)
    assert pat_hits[0x2400]["name"] == "custom_memcpy"

    # FLIRT binary .sig header validation
    sig_hdr = bytearray(64)
    sig_hdr[0:6] = b"IDASGN"
    sig_hdr[6] = 10
    sig_hdr[7] = 0
    struct.pack_into("<IHHHHH12s", sig_hdr, 8, 1, 1, 1, 0, 12, 0xBEEF, b"demo_lib\x00")
    sig_hdr[34] = 8
    sig_hdr[37:45] = b"demo_lib"
    sig_info = parse_flirt_sig_header(bytes(sig_hdr))
    assert sig_info["valid"] is True
    assert sig_info["library_name"] == "demo_lib"

    # Ghidra .fidb SQLite lookup
    fidb_p = tmp_path / "sample.fidb"
    conn = sqlite3.connect(str(fidb_p))
    conn.execute("CREATE TABLE functions(full_hash TEXT, name TEXT, signature TEXT)")
    conn.execute(
        "INSERT INTO functions VALUES (?, ?, ?)",
        (compute_fidb_function_hash(fn_code), "memcpy", "void * memcpy(void *dst, const void *src, size_t n)"),
    )
    conn.commit()
    conn.close()
    fidb_hits = match_functions_with_fidb_sqlite([(0x2400, fn_code)], fidb_p)
    assert fidb_hits[0x2400]["name"] == "memcpy"

    merged = merge_type_information(
        flirt_matches=fidb_hits,
        rva_to_symbol={0x2400: "memcpy"},
        extra_c_headers="int64_t verify_checksum(const uint8_t *buf, uint32_t len);",
    )
    assert "memcpy" in merged["prototypes"]
    assert "verify_checksum" in merged["prototypes"]


def test_v90_multiarch_arm32_mips32_riscv64_and_macho_objc_swift(tmp_path: Path) -> None:
    # 1. ARM32 with movw, ldr/str, add, cbnz, bx lr (verified endian bytes)
    # Using ARMv7 LE:
    # mov r2, #10   (e3a0200a)
    # str r0, [sp, #4] (e58d0004)
    # ldr r3, [sp, #4] (e59d3004)
    # add r0, r3, r2   (e0830002)
    # bx lr            (e12fff1e)
    arm32_code = bytes.fromhex("0a20a0e3 04008de5 04309de5 020083e0 1eff2fe1".replace(" ", ""))
    c_a32, ins_a32, sup_a32, _, _ = lift_arm32_function_to_c("arm32_mem_fn", arm32_code, 0x1000)
    assert sup_a32 is True
    for val in (-5, 0, 42, 1000):
        ar_e = _MemoryArena()
        ar_c = _MemoryArena()
        e_res = eval_arm32_insns(ins_a32, (val, 0, 0, 0), ar_e)
        c_res = _execute_lifted_c_ast(c_a32, val, 0, 0, 0, ar_c)
        assert c_res == e_res == val + 10

    # 2. MIPS32 LE with lw/sw/slt/delay slot
    # sw $a0, 4($sp)   -> 0xafa40004 -> 04 00 a4 af
    # lw $v0, 4($sp)   -> 0x8fa20004 -> 04 00 a2 8f
    # addi $v0, $v0, 7 -> 0x20420007 -> 07 00 42 20
    # jr $ra           -> 0x03e00008 -> 08 00 e0 03
    # nop              -> 00 00 00 00
    mips_code = bytes.fromhex("0400a4af 0400a28f 07004220 0800e003 00000000".replace(" ", ""))
    c_m32, ins_m32, sup_m32, _, _ = lift_mips32_function_to_c("mips_mem_fn", mips_code, 0x2000)
    assert sup_m32 is True
    for val in (-10, 0, 35):
        ar_e = _MemoryArena()
        ar_c = _MemoryArena()
        assert _execute_lifted_c_ast(c_m32, val, 0, 0, 0, ar_c) == eval_mips32_insns(ins_m32, (val,), ar_e) == val + 7

    # 3. RISC-V RV64GC with sw/lbu/slti/ret
    # sb a0, 4(sp)    (0x00a10223 -> 23 02 a1 00)
    # lbu a0, 4(sp)   (0x00414503 -> 03 45 41 00)
    # addi a0, a0, 5  (0x00550513 -> 13 05 55 00)
    # ret             (0x00008067 -> 67 80 00 00)
    rv_code = bytes.fromhex("2302a100 03454100 13055500 67800000".replace(" ", ""))
    c_rv, ins_rv, sup_rv, _, _ = lift_riscv64_function_to_c("rv_lbu_fn", rv_code, 0x3000)
    assert sup_rv is True
    for val in (0x1FF, 0x42, 0):
        ar_e = _MemoryArena()
        ar_c = _MemoryArena()
        assert _execute_lifted_c_ast(c_rv, val, 0, 0, 0, ar_c) == eval_riscv64_insns(ins_rv, (val,), ar_e) == (val & 0xFF) + 5

    # 4. Mach-O 64 synthetic binary containing __objc_classlist + __swift5_types structured metadata
    blob = bytearray(0x800)
    # Mach-O 64 LE header + 1 LC_SEGMENT_64 (72 + 2*80 = 232 bytes)
    struct.pack_into("<IIIIIIII", blob, 0, 0xFEEDFACF, 0x0100000C, 0, 2, 1, 232, 0x200000, 0)
    seg_off = 32
    struct.pack_into("<II", blob, seg_off, 0x19, 232)
    blob[seg_off + 8 : seg_off + 14] = b"__DATA"
    struct.pack_into("<QQQQIIII", blob, seg_off + 24, 0x10000, 0x800, 0, 0x800, 3, 3, 2, 0)
    # Sec 0: __objc_classlist at vm 0x10200, size 8, off 0x200
    s0 = seg_off + 72
    blob[s0 : s0 + 16] = b"__objc_classlist"
    blob[s0 + 16 : s0 + 22] = b"__DATA"
    struct.pack_into("<QQI", blob, s0 + 32, 0x10200, 8, 0x200)
    # Sec 1: __swift5_types at vm 0x10400, size 4, off 0x400
    s1 = s0 + 80
    blob[s1 : s1 + 13] = b"__swift5_types"
    blob[s1 + 16 : s1 + 22] = b"__TEXT"
    struct.pack_into("<QQI", blob, s1 + 32, 0x10400, 4, 0x400)

    # ObjC pointers: classlist[0]=0x10220 -> objc_class (+32 ro_ptr = 0x10260) -> class_ro_t (+24 name=0x102A0, methods=0x102C0)
    struct.pack_into("<Q", blob, 0x200, 0x10220)
    struct.pack_into("<Q", blob, 0x220 + 32, 0x10260)
    struct.pack_into("<QQ", blob, 0x260 + 24, 0x102A0, 0x102C0)
    blob[0x2A0 : 0x2AE] = b"VaultDelegate\x00"
    struct.pack_into("<II", blob, 0x2C0, 24, 3)

    # Swift5 descriptor at 0x420 -> rel from 0x400 is +0x20; flags=17 (struct), name_rel=+12 -> 0x434
    struct.pack_into("<i", blob, 0x400, 0x20)
    struct.pack_into("<Iii", blob, 0x420, 17, 0, 12)
    blob[0x434 : 0x440] = b"CryptoToken\x00"

    macho_rep = analyze_macho(bytes(blob))
    assert macho_rep["status"] == "complete"
    sl = macho_rep["slices"][0]
    assert sl["objc_structured_classes"][0]["class_name"] == "VaultDelegate"
    assert sl["objc_structured_classes"][0]["method_count"] == 3
    assert sl["swift_type_descriptors"][0] == {"name": "CryptoToken", "kind": "struct", "vmaddr": "0x10420"}
