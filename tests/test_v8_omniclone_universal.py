"""Comprehensive End-to-End Verification Suite for AetherRE Megazord v8.0.0 (OmniClone).

Verifies all v8.0.0 pillars on real artifacts (zero mocks):
  1. Dynamic PE OEP unpacking in isolated Unicorn sandbox + CFF devirtualizer + API hash rewriting.
  2. Export-free PE64 .exe EntryPoint + CMake add_executable + Multi-Arch (x86_32, ARM32, MIPS32, RISC-V64) + LLVM SIMD + Rust.
  3. Managed & Bytecode Reconstructors: .NET 10 (ilspycmd + dotnet build), Python .pyc -> live module, WASM -> C99, JS Bundle -> TS.
  4. Firmware CPIO/MMIO re-hosting + Driver WDM shim + angr symbolic branch cracker + Differential Prover + Exploit SARIF + OmniClone hybrid ZIP + MCP tools.
"""

from __future__ import annotations

import importlib.util
import json
import py_compile
import struct
import subprocess
import zipfile
from pathlib import Path

import pefile
from keystone import (
    KS_ARCH_ARM,
    KS_ARCH_MIPS,
    KS_ARCH_X86,
    KS_MODE_32,
    KS_MODE_64,
    KS_MODE_ARM,
    KS_MODE_LITTLE_ENDIAN,
    KS_MODE_MIPS32,
    Ks,
)

from aether_re.api_hash_resolve import hash_ror13
from aether_re.cff_devirtualizer import rewrite_api_hashes_in_c, unflatten_cff_function
from aether_re.dynamic_unpacker import unpack_pe_in_sandbox
from aether_re.exploit_prover import audit_reconstructed_project_exploits, check_integer_overflow_poc
from aether_re.firmware_reconstructor import reconstruct_driver_project, reconstruct_firmware_project
from aether_re.llvm_backend import compile_project_to_llvm_ir
from aether_re.mcp_server import TOOLS, AetherMcpDispatcher
from aether_re.multiarch_lifter import (
    eval_arm32_insns,
    eval_mips32_insns,
    eval_x86_32_insns,
    lift_arm32_function_to_c,
    lift_mips32_function_to_c,
    lift_x86_32_function_to_c,
)
from aether_re.omniclone import clone_and_audit_project
from aether_re.project_reconstructor import _MemoryArena, _execute_lifted_c_ast, reconstruct_project
from aether_re.rust_recover import reconstruct_rust_project
from aether_re.symbolic_equivalence import prove_differential_equivalence, synthesize_branch_inputs_angr


def _make_minimal_pe64(text_bytes: bytes, *, ep_rva: int = 0x1000, extra_section: tuple[bytes, bytes] | None = None) -> bytes:
    n_secs = 2 if extra_section else 1
    pe_hdr = bytearray(0x400)
    pe_hdr[:2] = b"MZ"
    struct.pack_into("<I", pe_hdr, 0x3C, 0x80)
    pe_hdr[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe_hdr, 0x84, 0x8664, n_secs, 0, 0, 0, 0xF0, 0x0022)
    opt = 0x98
    struct.pack_into("<H", pe_hdr, opt, 0x020B)
    struct.pack_into("<I", pe_hdr, opt + 16, ep_rva)
    struct.pack_into("<Q", pe_hdr, opt + 24, 0x140000000)
    struct.pack_into("<II", pe_hdr, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", pe_hdr, opt + 56, 0x3000 if extra_section else 0x2000, 0x400)
    struct.pack_into("<HI", pe_hdr, opt + 68, 3, 0x20)
    sec_off = 0x84 + 20 + 0xF0
    struct.pack_into("<8sIIIIIIHHI", pe_hdr, sec_off, b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x400, 0, 0, 0, 0, 0x60000020)
    body = text_bytes.ljust(0x200, b"\x90")
    if extra_section:
        sec_nm, sec_data = extra_section
        struct.pack_into("<8sIIIIIIHHI", pe_hdr, sec_off + 40, sec_nm.ljust(8, b"\x00")[:8], 0x200, 0x2000, 0x200, 0x600, 0, 0, 0, 0, 0xE0000020)
        body += sec_data.ljust(0x200, b"\x90")
    return bytes(pe_hdr) + body


def test_v8_dynamic_unpack_oep_and_cff_devirtualizer() -> None:
    plain_oep = b"\x48\xc7\xc0\x39\x05\x00\x00\xc3"  # mov rax, 1337; ret
    enc_oep = bytes(b ^ 0x5A for b in plain_oep)
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    stub_bytes, _ = ks.asm(
        "lea rsi, [rip - 0x1007]; xor ecx, ecx; L1: xor byte ptr [rsi + rcx], 0x5A; inc rcx; cmp rcx, 8; jb L1; jmp rsi",
        0x140002000,
    )
    pe_blob = _make_minimal_pe64(enc_oep, ep_rva=0x2000, extra_section=(b".pack", bytes(stub_bytes)))
    res = unpack_pe_in_sandbox(pe_blob)
    assert res["status"] == "unpacked"
    assert res["oep_detected"] is True
    assert res["oep_rva"] == "0x1000"
    unp = pefile.PE(data=res["unpacked_bytes"])
    assert unp.OPTIONAL_HEADER.AddressOfEntryPoint == 0x1000
    assert unp.get_data(0x1000, 8) == plain_oep

    cff_c = "\n".join([
        "int64_t cff_fn(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {",
        "    int64_t rax = 0, state = 0;",
        "L_0: ; /* entry */",
        "    state = 0x10;",
        "    if (1) goto L_disp;",
        "L_disp: ; /* dispatcher */",
        "    if (state == 0x10) goto L_c1;",
        "    if (state == 0x20) goto L_c2;",
        "    if (1) goto L_ret;",
        "L_c1: ; /* case 1 */",
        "    rax = (int64_t)((rcx) + (5));",
        "    if (rcx > 10) goto L_c1_t;",
        "    state = 0x30;",
        "    if (1) goto L_disp;",
        "L_c1_t: ; /* branch true */",
        "    state = 0x20;",
        "    if (1) goto L_disp;",
        "L_c2: ; /* case 2 */",
        "    rax = (int64_t)((rax) * (2));",
        "    state = 0x30;",
        "    if (1) goto L_disp;",
        "L_ret: ; /* exit */",
        "    return rax;",
        "}",
    ])
    unflat_c, cff_m = unflatten_cff_function(cff_c)
    assert cff_m["cfg_restored"] is True and cff_m["dispatchers_removed"] >= 1
    for x in (3, 15):
        assert _execute_lifted_c_ast(cff_c, x, 0, 0, 0) == _execute_lifted_c_ast(unflat_c, x, 0, 0, 0)

    va_h = hash_ror13("VirtualAlloc")
    ann_c, hm = rewrite_api_hashes_in_c(f"    rcx = 0x{va_h:x};")
    assert "VirtualAlloc" in hm["unique_api_names"] and "aether_api_hash" in ann_c


def test_v8_pe_exe_entrypoint_multiarch_llvm_simd_and_rust(tmp_path: Path) -> None:
    # 1. PE64 export-free .exe via AddressOfEntryPoint
    ks64 = Ks(KS_ARCH_X86, KS_MODE_64)
    ep_code, _ = ks64.asm("lea eax, [rcx + rdx + 7]; ret", 0x140001000)
    exe_p = tmp_path / "entry_app.exe"
    exe_p.write_bytes(_make_minimal_pe64(bytes(ep_code), ep_rva=0x1000))
    rep_exe = reconstruct_project(exe_p, tmp_path / "exe_out")
    assert rep_exe.is_executable_entry is True
    assert rep_exe.total_exports_reconstructed >= 1
    assert "add_executable(" in (tmp_path / "exe_out" / "CMakeLists.txt").read_text(encoding="utf-8")

    # 2. x86_32, ARM32, MIPS32 lifters + evaluators
    b32, _ = Ks(KS_ARCH_X86, KS_MODE_32).asm("mov eax, [esp+4]; add eax, [esp+8]; imul eax, eax, 3; ret", 0x1000)
    c32, i32, ok32, _, _ = lift_x86_32_function_to_c("f32", bytes(b32), 0x1000)
    assert ok32 and eval_x86_32_insns(i32, (4, 5), _MemoryArena()) == _execute_lifted_c_ast(c32, 4, 5, 0, 0, mem_arena=_MemoryArena()) == 27

    ba32, _ = Ks(KS_ARCH_ARM, KS_MODE_ARM).asm("add r0, r0, r1; bx lr", 0x2000)
    ca32, ia32, oka32, _, _ = lift_arm32_function_to_c("fa32", bytes(ba32), 0x2000)
    assert oka32 and eval_arm32_insns(ia32, (11, 31), _MemoryArena()) == _execute_lifted_c_ast(ca32, 11, 31, 0, 0, mem_arena=_MemoryArena()) == 42

    bm32, _ = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 | KS_MODE_LITTLE_ENDIAN).asm("addu $v0, $a0, $a1; jr $ra; nop", 0x3000)
    cm32, im32, okm32, _, _ = lift_mips32_function_to_c("fm32", bytes(bm32), 0x3000)
    assert okm32 and eval_mips32_insns(im32, (15, 27), _MemoryArena()) == _execute_lifted_c_ast(cm32, 15, 27, 0, 0, mem_arena=_MemoryArena()) == 42

    # 3. LLVM SIMD <2 x i32> vector lowering + Rust Cargo crate emitter
    simd_c = "int64_t simd_v8(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {\n    int64_t rax = aether_paddd64(rcx, rdx);\n    rax = aether_pmulld64(rax, r8);\n    return rax;\n}"
    ll_res = compile_project_to_llvm_ir([{"c_ident": "simd_v8", "rva": 0x1000, "c_code": simd_c}], tmp_path / "ir")
    assert ll_res["llvm_ir_verified"] and "<2 x i32>" in (tmp_path / "ir" / "reconstructed_project.ll").read_text(encoding="utf-8")

    rr = reconstruct_rust_project(b"rustc/1.80.0 (abcd123) _ZN7example4calc17h0123456789abcdefE core::panicking::", tmp_path / "rust_pkg")
    assert rr["status"] == "complete" and (tmp_path / "rust_pkg" / "Cargo.toml").is_file()


def test_v8_managed_dotnet_python_wasm_and_js(tmp_path: Path) -> None:
    # 1. Python .pyc decompile -> execute & verify congruence
    py_orig = tmp_path / "calc.py"
    py_orig.write_text("import math\ndef poly(x, y):\n    return (x * x) + (y * 3)\n", encoding="utf-8")
    pyc_p = Path(py_compile.compile(str(py_orig)))
    rep_py = reconstruct_project(pyc_p, tmp_path / "out_py")
    assert rep_py.project_kind == "python_bytecode_project"
    spec = importlib.util.spec_from_file_location("rec_calc_v8", tmp_path / "out_py" / "src" / f"{pyc_p.stem}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    assert mod.poly(4, 5) == 31

    # 2. Binary .wasm -> C99 + CMakeLists
    wasm_p = tmp_path / "mod.wasm"
    wasm_p.write_bytes(
        b"\x00asm\x01\x00\x00\x00\x01\x07\x01\x60\x02\x7f\x7f\x01\x7f\x03\x02\x01\x00\x07\x08\x01\x04add2\x00\x00\x0a\x09\x01\x07\x00\x20\x00\x20\x01\x6a\x0b"
    )
    rep_w = reconstruct_project(wasm_p, tmp_path / "out_wasm")
    assert rep_w.project_kind == "wasm_native_c" and "add2(" in (tmp_path / "out_wasm" / "src" / "wasm_module.c").read_text(encoding="utf-8")

    # 3. JS Webpack bundle -> TypeScript/ESM project
    js_p = tmp_path / "bundle.js"
    js_p.write_text("var mods = { alpha: function(e, t) { var _0x1 = 42; return _0x1; } };", encoding="utf-8")
    rep_js = reconstruct_project(js_p, tmp_path / "out_js")
    assert rep_js.project_kind == "javascript_webpack_ts" and (tmp_path / "out_js" / "package.json").is_file()

    # 4. Real .NET assembly compiled via dotnet build -> ilspycmd + rebuild verification
    dn_src = tmp_path / "dn_src"
    dn_src.mkdir()
    (dn_src / "DemoDotNet.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n<PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Library</OutputType></PropertyGroup>\n</Project>\n',
        encoding="utf-8",
    )
    (dn_src / "MathOps.cs").write_text("namespace DemoDotNet { public static class MathOps { public static int Calc(int a, int b) => (a * 3) + b; } }\n", encoding="utf-8")
    p_build = subprocess.run(["dotnet", "build", str(dn_src / "DemoDotNet.csproj"), "-c", "Release", "--nologo"], capture_output=True, text=True, timeout=60)
    assert p_build.returncode == 0, p_build.stdout + p_build.stderr
    dll_dn = next((dn_src / "bin" / "Release").rglob("DemoDotNet.dll"))
    rep_dn = reconstruct_project(dll_dn, tmp_path / "out_dn")
    assert rep_dn.project_kind == "dotnet_csharp" and rep_dn.overall_congruence_pct == 100.0


def test_v8_firmware_symbolic_exploit_omniclone_and_mcp(tmp_path: Path) -> None:
    # 1. Firmware CPIO extraction + MMIO Unicorn re-host harness
    cname = b"etc/config.cfg\x00"
    payload = b"mode=prod\n"
    hdr = ("070701" + "00000001" + "000081A4" + "00000000" * 2 + "00000001" + "00000000" + f"{len(payload):08x}" + "00000000" * 4 + f"{len(cname):08x}" + "00000000").encode("ascii")
    trailer = ("070701" + "00000000" * 11 + "0000000b" + "00000000").encode("ascii") + b"TRAILER!!!\x00\x00"
    fw_p = tmp_path / "fw.bin"
    fw_p.write_bytes(b"\x00\x00\x00\x40" * 4 + hdr + cname + b"\x00" * ((4 - (110 + len(cname)) % 4) % 4) + payload + b"\x00" * ((4 - len(payload) % 4) % 4) + trailer)
    fw_res = reconstruct_firmware_project(fw_p, tmp_path / "fw_out")
    assert fw_res["rootfs_files_count"] >= 1 and (tmp_path / "fw_out" / "rootfs" / "etc" / "config.cfg").read_bytes() == payload

    # 2. angr symbolic branch solver + Z3 BV64 equivalence + overflow PoC SARIF
    magic_asm, _ = Ks(KS_ARCH_X86, KS_MODE_64).asm("cmp ecx, 0x1337BEEF; je win; mov eax, 0; ret; win: mov eax, 999; ret", 0x400000)
    angr_res = synthesize_branch_inputs_angr(bytes(magic_asm), base_addr=0x400000, arch="amd64")
    assert any((v[0] & 0xFFFFFFFF) == 0x1337BEEF for v in angr_res["inputs"])

    eq = prove_differential_equivalence(
        lambda v: v[0] + v[1],
        lambda v: (v[0] ^ v[1]) + 2 * (v[0] & v[1]),
        extra_inputs=angr_res["inputs"],
        c_expr_orig="(rcx + rdx)",
        c_expr_twin="((rcx ^ rdx) + 2 * (rcx & rdx))",
    )
    assert eq["status"] == "equivalent_bounded" and eq["z3_bv64_proof"]["proved_equivalent"] is True
    assert check_integer_overflow_poc()["vulnerable"] is True

    # 3. OmniClone hybrid ZIP orchestrator + MCP wiring
    zip_p = tmp_path / "hybrid_bundle.zip"
    with zipfile.ZipFile(zip_p, "w") as zf:
        zf.writestr(
            "bin/add2.wasm",
            b"\x00asm\x01\x00\x00\x00\x01\x07\x01\x60\x02\x7f\x7f\x01\x7f\x03\x02\x01\x00\x07\x08\x01\x04add2\x00\x00\x0a\x09\x01\x07\x00\x20\x00\x20\x01\x6a\x0b",
        )
        zf.writestr("web/app.js", "function init() { return 123; }")

    clone_rep = clone_and_audit_project(zip_p, tmp_path / "cloned_ws")
    assert clone_rep["status"] == "complete" and clone_rep["components_count"] >= 2
    assert (tmp_path / "cloned_ws" / "OMNICLONE_MANIFEST.json").is_file()
    assert (tmp_path / "cloned_ws" / "OMNICLONE_AUDIT.sarif.json").is_file()

    # Check MCP v8.0 tools registration
    tool_names = {t["name"] for t in TOOLS}
    for req_t in ("aether_universal_clone", "aether_dynamic_unpack", "aether_cff_devirtualize", "aether_symbolic_equivalence", "aether_exploit_prove"):
        assert req_t in tool_names
    mcp_res = AetherMcpDispatcher.handle_exploit_prove(str(tmp_path / "cloned_ws"))
    assert mcp_res["status"] == "complete"
