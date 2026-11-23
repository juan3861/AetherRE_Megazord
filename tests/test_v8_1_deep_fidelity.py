"""Deep Cross-Ecosystem Empirical Verification Suite for AetherRE Megazord v8.1.0.

Verifies live roundtrip compilation & execution without mocks across:
  1. JVM .jar / .class -> lifted .java -> javac recompile -> java CLI execution equivalence.
  2. WebAssembly (if/else + intra-module call) -> C99 -> MSVC DLL -> ctypes live execution.
  3. Export-free PE64 .exe -> C -> MSVC compile_reconstructed_executable -> live .exe exit code.
  4. Python 3.x conditional .pyc -> structured if/else decompilation -> live execution.
  5. SquashFS v4 zlib-compressed metadata parser + PE32 (0x014c) + angr behavioral cases generator.
"""

from __future__ import annotations

import ctypes
import importlib.util
import py_compile
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path

from keystone import KS_ARCH_X86, KS_MODE_32, KS_MODE_64, Ks

from aether_re.behavioral_runner import generate_differential_cases_from_symbolic
from aether_re.firmware_reconstructor import _parse_squashfs_v4
from aether_re.project_reconstructor import reconstruct_project
from aether_re.runtime_emitter import compile_reconstructed_executable, compile_reconstructed_project


def test_v81_jvm_jar_roundtrip_javac_and_java_exec(tmp_path: Path) -> None:
    orig_dir = tmp_path / "orig_java"
    orig_dir.mkdir()
    src_java = orig_dir / "CalcOps.java"
    src_java.write_text(
        "\n".join([
            "public class CalcOps {",
            "    public static int compute(int a, int b) {",
            "        return (a * 7) + (b - 3);",
            "    }",
            "}",
        ]),
        encoding="utf-8",
    )
    cls_orig = tmp_path / "orig_cls"
    cls_orig.mkdir()
    p_jc = subprocess.run(["javac", "-d", str(cls_orig), str(src_java)], capture_output=True, text=True, timeout=30)
    assert p_jc.returncode == 0, p_jc.stderr

    jar_path = tmp_path / "calcops.jar"
    with zipfile.ZipFile(jar_path, "w") as zf:
        zf.write(cls_orig / "CalcOps.class", arcname="CalcOps.class")

    rec_dir = tmp_path / "rec_java_proj"
    rep = reconstruct_project(jar_path, rec_dir)
    assert rep.project_kind == "android_dex_java"
    rec_cls_dir = rec_dir / "build" / "classes"
    assert (rec_cls_dir / "CalcOps.class").is_file()

    # Execute a Java runner against reconstructed CalcOps.class!
    runner_src = tmp_path / "Runner.java"
    runner_src.write_text(
        'public class Runner { public static void main(String[] args) { System.out.println(CalcOps.compute(6, 10)); } }\n',
        encoding="utf-8",
    )
    p_rjc = subprocess.run(
        ["javac", "-cp", str(rec_cls_dir), "-d", str(rec_cls_dir), str(runner_src)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert p_rjc.returncode == 0, p_rjc.stderr
    p_run = subprocess.run(
        ["java", "-cp", str(rec_cls_dir), "Runner"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert p_run.returncode == 0 and p_run.stdout.strip() == "49"  # 6*7 + (10-3) = 49


def test_v81_wasm_branch_call_to_native_dll_exec(tmp_path: Path) -> None:
    # WASM with 2 functions:
    # func 0: helper(a, b) = a * b
    # func 1 ("compute_max_prod"): if (a > b) return helper(a, b) + 1 else return helper(a, b) - 1
    body_f0 = bytes([0x00, 0x20, 0x00, 0x20, 0x01, 0x6C, 0x0B])
    body_f1 = bytes([
        0x00,
        0x20, 0x00, 0x20, 0x01, 0x4A,  # local.get 0; local.get 1; i32.gt_s
        0x04, 0x7F,                    # if (result i32)
        0x20, 0x00, 0x20, 0x01, 0x10, 0x00,  # call 0
        0x41, 0x01, 0x6A,              # i32.const 1; i32.add
        0x0F,                          # return
        0x05,                          # else
        0x20, 0x00, 0x20, 0x01, 0x10, 0x00,  # call 0
        0x41, 0x01, 0x6B,              # i32.const 1; i32.sub
        0x0F,                          # return
        0x0B,                          # end if
        0x41, 0x00,                    # fallback i32.const 0
        0x0B,                          # end func
    ])

    def _sec(sid: int, payload: bytes) -> bytes:
        return bytes([sid, len(payload)]) + payload

    wasm_bin = (
        b"\x00asm\x01\x00\x00\x00"
        + _sec(1, bytes([0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F]))  # type 0: (i32,i32)->i32
        + _sec(3, bytes([0x02, 0x00, 0x00]))                          # 2 funcs of type 0
        + _sec(7, b"\x01\x10compute_max_prod\x00\x01")                # export func 1
        + _sec(10, bytes([0x02, len(body_f0)]) + body_f0 + bytes([len(body_f1)]) + body_f1)
    )
    wasm_p = tmp_path / "logic.wasm"
    wasm_p.write_bytes(wasm_bin)

    out_w = tmp_path / "wasm_proj"
    rep = reconstruct_project(wasm_p, out_w)
    assert rep.project_kind == "wasm_native_c"

    comp = compile_reconstructed_project(
        out_w,
        output_dll_name="wasm_twin.dll",
        source_rel="src/wasm_module.c",
    )
    assert comp["compiled"] is True, comp

    dll = ctypes.CDLL(comp["dll_path"])
    dll.compute_max_prod.argtypes = [ctypes.c_int64, ctypes.c_int64]
    dll.compute_max_prod.restype = ctypes.c_int64
    assert dll.compute_max_prod(5, 3) == 16  # 5 > 3 => 5*3 + 1 = 16
    assert dll.compute_max_prod(3, 5) == 14  # 3 <= 5 => 3*5 - 1 = 14


def test_v81_pe_exe_compile_and_execute_live(tmp_path: Path) -> None:
    ks64 = Ks(KS_ARCH_X86, KS_MODE_64)
    ep_bytes, _ = ks64.asm("mov eax, 42; ret", 0x140001000)
    pe_hdr = bytearray(0x400)
    pe_hdr[:2] = b"MZ"
    struct.pack_into("<I", pe_hdr, 0x3C, 0x80)
    pe_hdr[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe_hdr, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
    opt = 0x98
    struct.pack_into("<H", pe_hdr, opt, 0x020B)
    struct.pack_into("<I", pe_hdr, opt + 16, 0x1000)
    struct.pack_into("<Q", pe_hdr, opt + 24, 0x140000000)
    struct.pack_into("<II", pe_hdr, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", pe_hdr, opt + 56, 0x2000, 0x400)
    struct.pack_into("<HI", pe_hdr, opt + 68, 3, 0x20)
    struct.pack_into("<8sIIIIIIHHI", pe_hdr, 0x188, b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x400, 0, 0, 0, 0, 0x60000020)

    exe_orig = tmp_path / "answer42.exe"
    exe_orig.write_bytes(bytes(pe_hdr) + bytes(ep_bytes).ljust(0x200, b"\x90"))

    out_exe_proj = tmp_path / "exe_proj"
    rep = reconstruct_project(exe_orig, out_exe_proj)
    assert rep.is_executable_entry is True and rep.overall_congruence_pct == 100.0

    build_res = compile_reconstructed_executable(out_exe_proj)
    assert build_res["compiled"] is True, build_res
    run_res = subprocess.run([build_res["exe_path"]], capture_output=True, timeout=15)
    assert run_res.returncode == 42


def test_v81_python_conditional_squashfs_pe32_and_symbolic_cases(tmp_path: Path) -> None:
    # 1. Conditional Python .pyc decompilation
    py_f = tmp_path / "cond_ops.py"
    py_f.write_text("def pick_max(a, b):\n    if a > b:\n        return a + 10\n    return b\n", encoding="utf-8")
    pyc_f = Path(py_compile.compile(str(py_f)))
    rep_py = reconstruct_project(pyc_f, tmp_path / "py_cond")
    assert rep_py.project_kind == "python_bytecode_project"
    spec = importlib.util.spec_from_file_location("cond_rec", tmp_path / "py_cond" / "src" / f"{pyc_f.stem}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    assert mod.pick_max(10, 3) == 20 and mod.pick_max(2, 9) == 9

    # 2. Pure-Python SquashFS v4 zlib-compressed metadata extraction
    dir_meta = zlib.compress(b"bin/busybox\x00etc/shadow\x00")
    dir_blk = struct.pack("<H", len(dir_meta)) + dir_meta
    sq_off = 0
    dir_tbl_off = 96
    sq_hdr = struct.pack(
        "<IIIIIHHHHHHQQQQQQQQ",
        0x73717368, 12, 0, 131072, 0, 1, 17, 0, 1, 4, 0, 0, 96 + len(dir_blk), 0, 0, 96, dir_tbl_off, 0, 0,
    )
    sq_info = _parse_squashfs_v4(sq_hdr + dir_blk, tmp_path)
    assert sq_info["found"] is True and sq_info["compression"] == "gzip/zlib"
    assert "bin/busybox" in sq_info["dir_entries_hints"]

    # 3. Full PE32 (0x014C) export-based project reconstruction
    ks32 = Ks(KS_ARCH_X86, KS_MODE_32)
    fn32, _ = ks32.asm("mov eax, [esp+4]; add eax, [esp+8]; ret", 0x401000)
    pe32 = bytearray(0x600)
    pe32[:2] = b"MZ"
    struct.pack_into("<I", pe32, 0x3C, 0x80)
    pe32[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe32, 0x84, 0x014C, 1, 0, 0, 0, 0xE0, 0x2102)
    opt32 = 0x98
    struct.pack_into("<H", pe32, opt32, 0x010B)
    struct.pack_into("<I", pe32, opt32 + 16, 0x1000)
    struct.pack_into("<III", pe32, opt32 + 28, 0x400000, 0x1000, 0x200)
    struct.pack_into("<II", pe32, opt32 + 56, 0x2000, 0x400)
    struct.pack_into("<HI", pe32, opt32 + 68, 3, 0x10)
    # Export table at RVA 0x1100 (file off 0x500): IMAGE_EXPORT_DIRECTORY (40B) + addr(4B) + name_ptr(4B) + ord(2B) + name("add32\0")
    exp_rva = 0x1100
    exp_off = 0x500
    struct.pack_into("<II", pe32, opt32 + 96, exp_rva, 64)  # DATA_DIRECTORY[0] = Export
    struct.pack_into("<8sIIIIIIHHI", pe32, 0x84 + 20 + 0xE0, b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x400, 0, 0, 0, 0, 0x60000020)
    pe32[0x400 : 0x400 + len(fn32)] = bytes(fn32)
    # Export dir at 0x500: NumberOfFunctions=1, NumberOfNames=1, AddressOfFunctions=0x1128, AddressOfNames=0x112C, AddressOfNameOrdinals=0x1130
    struct.pack_into("<IIHHIIIIIII", pe32, exp_off, 0, 0, 0, 0, 0x1132, 1, 1, 1, 0x1128, 0x112C, 0x1130)
    struct.pack_into("<IIH", pe32, exp_off + 0x28, 0x1000, 0x113C, 0)
    pe32[exp_off + 0x32 : exp_off + 0x3C] = b"demo32.dll"
    pe32[exp_off + 0x3C : exp_off + 0x42] = b"add32\x00"

    pe32_p = tmp_path / "demo32.dll"
    pe32_p.write_bytes(bytes(pe32))
    rep32 = reconstruct_project(pe32_p, tmp_path / "out_pe32")
    assert rep32.project_kind == "pe_x86_32_c" and rep32.total_exports_reconstructed == 1
    assert rep32.overall_congruence_pct == 100.0

    # 4. Symbolic differential case generation
    b_sym, _ = Ks(KS_ARCH_X86, KS_MODE_64).asm("cmp ecx, 0x4242; je hit; xor eax, eax; ret; hit: mov eax, 1; ret", 0x400000)
    sym_cases = generate_differential_cases_from_symbolic(bytes(b_sym), max_cases=16)
    assert sym_cases["schema"] == "behavior-cases.v1" and len(sym_cases["cases"]) >= 2
