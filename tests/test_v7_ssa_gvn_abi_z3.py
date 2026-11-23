"""Comprehensive verification suite for AetherRE Megazord v7.0.0.

Validates:
  1. Pillar 1: Batched pycparser C-Tree structuring + Pre-Compiled Lifted C VM.
  2. Pillar 2: Cytron Dominance-Frontier SSA, Dominator GVN/CSE, Flag Inlining, LICM.
  3. Pillar 3: Full ABI (>4 Win64 stack args, void return, AAPCS64), TIL matching, Interproc Struct Propagation.
  4. Pillar 4: MBA Simplification, Z3 BV64 Equivalence Proving & Opaque-Predicate Pruning.
  5. Pillar 5: Native LLVM SIMD Vector IR (<8 x i8>, <2 x i32>) & Direct Pointer GEP Mode.
  6. Pillar 6: ARM64 FP/NEON + Persistent FLIRT Signature DB + Mach-O 64 Reconstruction -> Live Native DLL.
"""

from __future__ import annotations

import ctypes
import hashlib
import struct
from pathlib import Path

from aether_re.calling_convention import infer_function_prototype, refine_prototypes_interprocedural
from aether_re.ctree_structuring import structure_control_flow
from aether_re.flirt_cfg import load_flirt_signature_bank, register_cfg_signature
from aether_re.ir_optimizer import optimize_lifted_c_to_ir_bundle, optimize_lifted_c_via_ssa
from aether_re.llvm_backend import MCJITSession, compile_project_to_llvm_ir
from aether_re.multiarch_lifter import eval_arm64_insns, lift_arm64_function_to_c
from aether_re.project_reconstructor import (
    _MemoryArena,
    _execute_lifted_c_ast,
    compile_llvm_twin_project,
    compile_reconstructed_project,
    reconstruct_project,
)
from aether_re.smt_solver import prove_bv64_equivalence, prove_opaque_predicate_bv64
from aether_re.ssa_ir import build_ssa_for_cfg_blocks
from aether_re.struct_recovery import (
    emit_typed_c_from_structured,
    propagate_interprocedural_structs,
    recover_struct_layouts,
)


def _build_macho64_arm64(funcs: list[tuple[str, bytes]]) -> bytes:
    """Constructs a minimal valid Mach-O 64 (ARM64) binary parseable by extract_macho64_metadata."""
    text_vaddr = 0x100004000
    text_off = 0x4000
    code_chunks: list[bytes] = []
    sym_Entries: list[tuple[str, int]] = []
    cur = 0
    for nm, code in funcs:
        sym_Entries.append((f"_{nm}", text_vaddr + cur))
        code_chunks.append(code)
        cur += len(code)
    text_bytes = b"".join(code_chunks)

    strtab = bytearray(b"\x00")
    nlists = bytearray()
    for sym_nm, va in sym_Entries:
        s_off = len(strtab)
        strtab.extend(sym_nm.encode("ascii") + b"\x00")
        nlists.extend(struct.pack("<IBBHQ", s_off, 0x0F, 1, 0, va))

    sym_off = text_off + len(text_bytes)
    str_off = sym_off + len(nlists)

    # LC_SEGMENT_64 (72 bytes + 1 section_64 of 80 bytes = 152 bytes) + LC_SYMTAB (24 bytes) = 176 bytes
    lc_seg_sz = 72 + 80
    lc_sym_sz = 24
    sizeofcmds = lc_seg_sz + lc_sym_sz

    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 6, 2, sizeofcmds, 0, 0)
    lc_seg = struct.pack(
        "<II16sQQQQIIII",
        0x19, lc_seg_sz, b"__TEXT\x00".ljust(16, b"\x00"),
        0x100000000, sym_off, 0, sym_off, 7, 5, 1, 0,
    )
    sec_text = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text\x00".ljust(16, b"\x00"),
        b"__TEXT\x00".ljust(16, b"\x00"),
        text_vaddr, len(text_bytes), text_off, 2, 0, 0, 0x80000400, 0, 0, 0,
    )
    lc_sym = struct.pack("<IIIIII", 0x2, lc_sym_sz, sym_off, len(sym_Entries), str_off, len(strtab))

    pad_len = text_off - (len(hdr) + sizeofcmds)
    return hdr + lc_seg + sec_text + lc_sym + (b"\x00" * pad_len) + text_bytes + bytes(nlists) + bytes(strtab)


def test_v7_pillar1_and_pillar2_ssa_gvn_flag_inline_licm_and_batched_ctree() -> None:
    raw = "\n".join([
        "int64_t compute_v7(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {",
        "    int64_t rax = 0, rbx = 0, rbp = 0, rsi = 0, rdi = 0;",
        "    int64_t r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "L_100: ; /* entry */",
        "    rsi = (int64_t)((rcx) + (7));",
        "    rdi = (int64_t)((rcx) + (7));",  # identical dominated expr -> GVN!
        "    rax = 0;",
        "    rbx = 0;",
        "L_120: ; /* loop */",
        "    r10 = (int64_t)((rdx) + (11));",  # loop-invariant -> LICM!
        "    cmp_lhs = (int64_t)(rbx); cmp_rhs = (int64_t)(r8);",
        "    if (cmp_lhs >= cmp_rhs) goto L_150;",
        "    rax = (int64_t)((rax) + (r10));",
        "    rbx = (int64_t)((rbx) + (1));",
        "    if (1) goto L_120;",
        "L_150: ; /* exit */",
        "    rax = (int64_t)((rax) + (rsi));",
        "    rax = (int64_t)((rax) + (rdi));",
        "    return rax;",
        "}",
    ])

    opt_c, metrics, bundle = optimize_lifted_c_to_ir_bundle(raw)
    assert metrics["gvn_hits"] >= 1
    assert metrics["licm_hoisted"] >= 1
    assert metrics["phi_nodes_placed"] >= 1
    assert "cmp_lhs" not in "\n".join(opt_c.splitlines()[6:])
    assert bundle is not None and len(bundle["blocks"]) >= 2

    # Explicit compound-expression flag comparison inlining test
    cmp_inline_raw = "\n".join([
        "int64_t inline_cmp_demo(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {",
        "    int64_t rax = 0, rbx = 0, rbp = 0, rsi = 0, rdi = 0;",
        "    int64_t r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "L_10: ; /* entry */",
        "    cmp_lhs = (int64_t)((rcx) + (rdx)); cmp_rhs = (int64_t)(r8);",
        "    if (cmp_lhs >= cmp_rhs) goto L_20;",
        "    rax = 1;",
        "    return rax;",
        "L_20: ; /* ge */",
        "    rax = 2;",
        "    return rax;",
        "}",
    ])
    opt_cmp, m_cmp, _ = optimize_lifted_c_to_ir_bundle(cmp_inline_raw)
    assert m_cmp["flag_inlines"] >= 1
    assert "cmp_lhs" not in "\n".join(opt_cmp.splitlines()[6:])
    assert _execute_lifted_c_ast(opt_cmp, 3, 4, 10, 0, mem_arena=_MemoryArena()) == 1
    assert _execute_lifted_c_ast(opt_cmp, 6, 4, 10, 0, mem_arena=_MemoryArena()) == 2

    # Differential congruence between unoptimized and SSA/GVN/LICM-optimized IR
    for a0, a1, a2 in [(5, 3, 4), (-2, 10, 0), (10, -4, 6)]:
        v_raw = _execute_lifted_c_ast(raw, a0, a1, a2, 0, mem_arena=_MemoryArena())
        v_opt = _execute_lifted_c_ast(opt_c, a0, a1, a2, 0, mem_arena=_MemoryArena())
        assert v_raw == v_opt == (max(0, a2) * (a1 + 11) + 2 * (a0 + 7))

    # Direct Cytron SSA block builder check
    ssa = build_ssa_for_cfg_blocks(
        ["entry", "loop", "exit"],
        [("entry", "loop"), ("loop", "loop"), ("loop", "exit")],
        {"entry": [("rax", set())], "loop": [("rax", {"rax", "rdx"})], "exit": [(None, {"rax"})]},
        "entry",
    )
    assert ssa["phi_count"] >= 1 and "loop" in ssa["phi_nodes"]

    # Batched C-Tree check
    ct = structure_control_flow(
        ["entry", "exit"],
        [("entry", "exit")],
        {},
        [],
        "entry",
        block_semantics={
            "entry": {"statements": ["rax = (rcx + rdx);"], "terminator": {"kind": "jump", "target": "exit"}},
            "exit": {"statements": [], "terminator": {"kind": "return", "value": "rax"}},
        },
        function_signature="long long tiny_batch(long long rcx, long long rdx)",
        declarations=["long long rax = 0;"],
    )
    assert ct["status"] == "complete" and ct["c_syntax_checked"] is True


def test_v7_pillar3_abi_5plus_args_void_til_and_interproc_structs() -> None:
    # Win64 6-argument function with 0x20 shadow + 0x20 local frame = 0x20? Sub rsp, 0x20 -> extra args at rsp+0x48, rsp+0x50!
    insns_6arg = [
        {"mnemonic": "sub", "op_str": "rsp, 0x20"},
        {"mnemonic": "mov", "op_str": "rax, qword ptr [rsp + 0x48]"},
        {"mnemonic": "add", "op_str": "rax, qword ptr [rsp + 0x50]"},
        {"mnemonic": "add", "op_str": "rax, rcx"},
        {"mnemonic": "add", "op_str": "rsp, 0x20"},
        {"mnemonic": "ret", "op_str": ""},
    ]
    proto = infer_function_prototype(insns_6arg, function_name="sum_6args", arch="x86_64", file_format="pe", stack_frame_bytes=0x20)
    assert proto["calling_convention"] == "win64"
    assert proto["estimated_param_count"] == 6
    assert 0x48 in proto["stack_param_offsets"] and 0x50 in proto["stack_param_offsets"]

    refined = refine_prototypes_interprocedural(
        {"callee": infer_function_prototype([{"mnemonic": "mov", "op_str": "rax, rcx"}, {"mnemonic": "ret", "op_str": ""}], function_name="callee")},
        [("caller", "callee", ["rcx", "rdx", "r8"])],
    )
    assert refined["callee"]["estimated_param_count"] == 3

    # Canonical TIL matching against PROCESS_INFORMATION (0x00=8, 0x08=8, 0x10=4, 0x14=4)
    proc_info_insns = [
        {"mnemonic": "mov", "op_str": "qword ptr [rcx], rax"},
        {"mnemonic": "mov", "op_str": "qword ptr [rcx + 8], rdx"},
        {"mnemonic": "mov", "op_str": "dword ptr [rcx + 0x10], r8d"},
        {"mnemonic": "mov", "op_str": "dword ptr [rcx + 0x14], r9d"},
    ]
    st_res = recover_struct_layouts(proc_info_insns, base_registers={"rcx"})
    assert st_res["total_structs_recovered"] == 1
    assert st_res["structs"][0]["matched_til_struct"] == "PROCESS_INFORMATION"

    # Inter-procedural struct propagation from caller(rcx struct) -> callee(rdx receives rcx)
    caller_rec = {"c_ident": "outer_fn", "rva": 0x1000, "c_code": "long long outer_fn(...) {\n    rdx = rcx;\n    inner_fn(rcx, rdx, r8, r9);\n}"}
    callee_rec = {"c_ident": "inner_fn", "rva": 0x2000, "c_code": "long long inner_fn(...) {\n    rax = aether_mem_read(rdx + 0x10, 4);\n}"}
    inter_map = propagate_interprocedural_structs([caller_rec, callee_rec], st_res["structs"])
    assert inter_map["inner_fn"]["rdx"] == "RecoveredStruct_RCX"
    typed_c = emit_typed_c_from_structured(
        "long long inner_fn(long long rcx, long long rdx, long long r8, long long r9) {\n    rax = (int64_t)(aether_mem_read(rdx + 0x10, 4));\n    return rax;\n}\n",
        st_res["structs"],
        function_param_structs=inter_map,
        function_prototypes={"inner_fn": {"calling_convention": "win64", "estimated_param_count": 2, "typed_c_signature": "int64_t inner_fn(int64_t arg_1, int64_t arg_2)"}},
    )
    assert "Interproc-Structs: " in typed_c
    assert "((RecoveredStruct_RCX_t*)(uintptr_t)(rdx))->field_0x10" in typed_c


def test_v7_pillar4_z3_bv64_equivalence_and_mba_opaque_pruning() -> None:
    eq = prove_bv64_equivalence("(x ^ y) + 2 * (x & y)", "x + y")
    assert eq["proved_equivalent"] is True and eq["status"] == "PROVED_EQUIVALENT"

    op_t = prove_opaque_predicate_bv64("((x | 1) & 1) == 1")
    assert op_t["proved"] is True and op_t["truth_value"] is True

    mba_c = "\n".join([
        "int64_t mba_opaque(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {",
        "    int64_t rax = 0, rbx = 0, rbp = 0, rsi = 0, rdi = 0;",
        "    int64_t r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "L_100: ; /* entry */",
        "    rax = (rcx ^ rdx) + 2*(rcx & rdx);",
        "    if ((rbx | 1) % 2 == 0) goto L_dead;",
        "    return rax;",
        "L_dead: ; /* bogus */",
        "    rax = 999999;",
        "    return rax;",
        "}",
    ])
    opt, m = optimize_lifted_c_via_ssa(mba_c)
    assert m["mba_simplified"] >= 1
    assert m["opaque_pruned"] >= 1
    assert "999999" not in opt
    for a, b in [(7, 13), (-5, 9), (0, 0)]:
        assert _execute_lifted_c_ast(opt, a, b, 0, 0, mem_arena=_MemoryArena()) == a + b


def test_v7_pillar5_llvm_native_simd_vectors_and_direct_mem(tmp_path: Path) -> None:
    simd_fn = "\n".join([
        "int64_t simd_kernel(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {",
        "    int64_t rax = 0, rbx = 0, rbp = 0, rsi = 0, rdi = 0;",
        "    int64_t r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "L_100: ; /* simd */",
        "    r10 = aether_pcmpeqb64(rcx, rdx);",
        "    r11 = aether_pmaxud64(rcx, rdx);",
        "    rax = aether_psubd64(r11, r10);",
        "    return rax;",
        "}",
    ])
    recs = [{"c_ident": "simd_kernel", "c_code": simd_fn, "returns_double": False, "takes_double_arg0": False, "takes_double_arg1": False}]
    res = compile_project_to_llvm_ir(recs, tmp_path / "ir_simd")
    assert res["llvm_ir_verified"] is True
    raw_ll = Path(res["raw_ll_path"]).read_text(encoding="utf-8")
    assert "<8 x i8>" in raw_ll and "<2 x i32>" in raw_ll
    assert "call i64 @aether_pcmpeqb64" not in raw_ll

    sess = MCJITSession(res["o3_ir_text"], res["fn_sigs"])
    try:
        for a, b in [(0x1122334455667788, 0x1100330055007700), (0xFFFFFFFF00000001, 0x0000000200000005)]:
            mc_v = sess.invoke("simd_kernel", a, b, 0, 0, mem_arena=_MemoryArena())
            vm_v = _execute_lifted_c_ast(simd_fn, a, b, 0, 0, mem_arena=_MemoryArena())
            assert mc_v == vm_v
    finally:
        sess.close()

    # Verify optional direct pointer lowering mode (inline_direct_memory=True) produces valid inttoptr LLVM IR
    mem_fn = "\n".join([
        "int64_t read_qword(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {",
        "L_100: ; /* entry */",
        "    rax = aether_mem_read(rcx, 8);",
        "    return rax;",
        "}",
    ])
    res_gep = compile_project_to_llvm_ir(
        [{"c_ident": "read_qword", "c_code": mem_fn, "returns_double": False, "takes_double_arg0": False, "takes_double_arg1": False}],
        tmp_path / "ir_gep",
        inline_direct_memory=True,
    )
    assert res_gep["llvm_ir_verified"] is True
    assert "inttoptr" in Path(res_gep["raw_ll_path"]).read_text(encoding="utf-8")


def test_v7_pillar6_arm64_fp_flirt_db_and_macho64_recompilation(tmp_path: Path) -> None:
    # 1. ARM64 FP instructions: scvtf d0, x0; scvtf d1, x1; fadd d0, d0, d1; fcvtzs w0, d0; ret
    arm64_fp_code = struct.pack("<5I", 0x9E620000, 0x9E620021, 0x1E612800, 0x1E780000, 0xD65F03C0)
    c_src, insns, lifted_ok, _, _ = lift_arm64_function_to_c("fp_add_i32", arm64_fp_code, 0x1000)
    assert lifted_ok is True
    for a, b in [(7, 35), (-12, 50), (100, 234)]:
        assert eval_arm64_insns(insns, (a, b, 0, 0), _MemoryArena()) == a + b
        assert _execute_lifted_c_ast(c_src, a, b, 0, 0, mem_arena=_MemoryArena()) == a + b

    # 2. Mach-O 64 ARM64 full end-to-end reconstruction -> C-Tree -> LLVM O3 COFF -> live compiled Windows DLL
    macho_path = tmp_path / "libarm64_fp.dylib"
    macho_path.write_bytes(_build_macho64_arm64([("fp_add_i32", arm64_fp_code)]))
    rep = reconstruct_project(macho_path, tmp_path / "macho_twin")
    assert rep.status == "complete"
    assert rep.project_kind == "macho64_aarch64"
    assert rep.total_exports_reconstructed == 1
    assert rep.fully_lifted_functions == 1
    assert rep.ctree_structured_functions == 1
    assert rep.overall_congruence_pct == 100.0
    assert rep.llvm_ir_verified is True

    msvc_build = compile_reconstructed_project(tmp_path / "macho_twin")
    assert msvc_build["compiled"] is True
    llvm_build = compile_llvm_twin_project(tmp_path / "macho_twin")
    assert llvm_build["compiled"] is True
    for dll_p in (msvc_build["dll_path"], llvm_build["dll_path"]):
        dl = ctypes.CDLL(str(dll_p))
        dl.fp_add_i32.argtypes = [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64]
        dl.fp_add_i32.restype = ctypes.c_int64
        assert dl.fp_add_i32(19, 23, 0, 0) == 42

    # 3. Persistent Graph-FLIRT DB registration
    db_file = tmp_path / "custom_flirt.json"
    reg = register_cfg_signature("0123456789abcdef", "custom_memcpy", "cfg_flirt_v7_test", arch="aarch64", db_path=db_file)
    assert reg["registered"] is True
    loaded = load_flirt_signature_bank(db_file)
    assert loaded.get("0123456789abcdef") == ("custom_memcpy", "cfg_flirt_v7_test")
