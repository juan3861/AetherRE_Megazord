"""Unit and ground-truth tests for Phase III LLVM IR Backend, O3 PassManager, COFF .obj & MCJIT."""

from __future__ import annotations

import ctypes
from pathlib import Path

from aether_re.llvm_backend import MCJITSession, compile_project_to_llvm_ir
from aether_re.project_reconstructor import (
    _MemoryArena,
    _bits_to_f64,
    _execute_lifted_c_ast,
    _f64_to_bits,
    compile_llvm_twin_project,
    reconstruct_project,
)


def test_llvm_ir_lowering_o3_coff_and_mcjit_scalar_and_float(tmp_path: Path) -> None:
    fn_sum = "\n".join([
        "int64_t sum_and_tzcnt(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {",
        "    int64_t rax = 0, rbx = 0, rbp = 0, rsi = 0, rdi = 0;",
        "    int64_t r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "L_1000: ; /* entry */",
        "    rax = 0;",
        "    rbx = 0;",
        "L_1010: ; /* loop */",
        "    cmp_lhs = rbx; cmp_rhs = rcx;",
        "    if (cmp_lhs >= cmp_rhs) goto L_1030;",
        "    rax = (int64_t)((rax) + (rbx));",
        "    rbx = (int64_t)((rbx) + 1);",
        "    if (1) goto L_1010;",
        "L_1030: ; /* exit */",
        "    r10 = aether_tzcnt64(rdx);",
        "    rax = (int64_t)((rax) + (r10));",
        "    return rax;",
        "}",
    ])

    fn_fp = "\n".join([
        "double calc_f64(double xmm0_arg, int64_t rdx, int64_t r8, int64_t r9) {",
        "    int64_t rcx = 0;",
        "    int64_t rax = 0, rbx = 0, rbp = 0, rsi = 0, rdi = 0;",
        "    int64_t r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "    int64_t xmm0 = 0, xmm0_hi = 0, xmm1 = 0, xmm1_hi = 0;",
        "    xmm0 = aether_f64_to_bits(xmm0_arg);",
        "L_2000: ; /* entry */",
        "    xmm1 = aether_i32_to_f64(rdx);",
        "    xmm0 = aether_f64_add(xmm0, xmm1);",
        "    xmm0 = aether_f64_mul(xmm0, xmm1);",
        "    return aether_bits_to_f64(xmm0);",
        "}",
    ])

    records = [
        {"c_ident": "sum_and_tzcnt", "c_code": fn_sum, "returns_double": False, "takes_double_arg0": False, "takes_double_arg1": False},
        {"c_ident": "calc_f64", "c_code": fn_fp, "returns_double": True, "takes_double_arg0": True, "takes_double_arg1": False},
    ]
    res = compile_project_to_llvm_ir(records, tmp_path / "ir")
    assert res["llvm_ir_verified"] is True
    assert res["llvm_o3_functions"] == 2
    assert res["coff_obj_bytes"] > 0
    assert Path(res["raw_ll_path"]).is_file()
    assert Path(res["o3_ll_path"]).is_file()
    assert Path(res["obj_path"]).is_file()
    # Real LLVM O3 mem2reg eliminates allocas on scalar functions
    assert "phi i64" in res["o3_ir_text"]

    sess = MCJITSession(res["o3_ir_text"], res["fn_sigs"])
    try:
        for n, mask, expected in [(5, 8, 10 + 3), (10, 16, 45 + 4), (0, 1, 0)]:
            a_mc = _MemoryArena()
            a_c = _MemoryArena()
            mc_out = sess.invoke("sum_and_tzcnt", n, mask, 0, 0, mem_arena=a_mc)
            c_out = _execute_lifted_c_ast(fn_sum, n, mask, 0, 0, mem_arena=a_c)
            assert mc_out == c_out == expected

        x_bits = _f64_to_bits(3.5)
        mc_fp = sess.invoke("calc_f64", 0, 4, 0, 0, xmm0_bits=x_bits)
        c_fp = _execute_lifted_c_ast(fn_fp, 0, 4, 0, 0, xmm0_bits=x_bits)
        assert abs(_bits_to_f64(mc_fp) - 30.0) < 1e-9
        assert mc_fp == c_fp
    finally:
        sess.close()


def test_reconstruct_project_llvm_o3_mcjit_on_lz4_and_cjson(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    lz_dll = repo_root / "external_test_repos" / "lz4" / "lz4.dll"
    if lz_dll.is_file():
        rep = reconstruct_project(lz_dll, tmp_path / "lz4_llvm")
        assert rep.llvm_ir_verified is True
        assert rep.llvm_o3_functions >= 44
        assert rep.llvm_coff_obj_bytes > 0
        o3_text = (tmp_path / "lz4_llvm" / "ir" / "reconstructed_project_o3.ll").read_text(encoding="utf-8")
        fn_sigs = {
            (f["c_symbol"] or f["name"]): (bool(f.get("returns_double")), bool(f.get("takes_double_arg0")), False)
            for f in rep.functions
        }
        sess = MCJITSession(o3_text, fn_sigs)
        try:
            a = _MemoryArena()
            assert sess.invoke("LZ4_compressBound", 100, 0, 0, 0, mem_arena=a) == 116
            assert sess.invoke("LZ4_compressBound", 4096, 0, 0, 0, mem_arena=a) == 4128
            assert sess.invoke("LZ4_versionNumber", 0, 0, 0, 0, mem_arena=a) >= 10900
        finally:
            sess.close()


def test_llvm_o3_linked_dll_live_execution(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    lz_dll = repo_root / "external_test_repos" / "lz4" / "lz4.dll"
    if lz_dll.is_file():
        proj_dir = tmp_path / "lz4_linked"
        rep = reconstruct_project(lz_dll, proj_dir)
        assert "src/llvm_runtime_shim.c" in rep.generated_files
        assert "src/reconstructed_typed.c" in rep.generated_files
        assert rep.flirt_cfg_matches >= 6
        assert (proj_dir / "src" / "reconstructed_typed.c").is_file()

        link_res = compile_llvm_twin_project(proj_dir)
        if link_res["compiled"]:
            llvm_dll = ctypes.CDLL(str(link_res["dll_path"]))
            assert llvm_dll.LZ4_versionNumber() >= 10900
            assert llvm_dll.LZ4_compressBound(100) == 116
            payload = b"AetherRE LLVM O3 native linked COFF test payload! " * 4
            bound = llvm_dll.LZ4_compressBound(len(payload))
            comp_buf = ctypes.create_string_buffer(bound)
            dec_buf = ctypes.create_string_buffer(len(payload))
            csz = llvm_dll.LZ4_compress_default(payload, comp_buf, len(payload), bound)
            assert csz > 0
            dsz = llvm_dll.LZ4_decompress_safe(comp_buf.raw[:csz], dec_buf, csz, len(payload))
            assert dsz == len(payload)
            assert dec_buf.raw[:dsz] == payload
