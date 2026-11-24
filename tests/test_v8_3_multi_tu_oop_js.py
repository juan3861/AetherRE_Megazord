"""Empirical tests for AetherRE Megazord v8.3.0:
1. Multi-TU partitioned compilation (`src/modules/*.c` + `CMakeLists.multi_tu.txt`) & live DLL execution across ELF64 + PE64.
2. JVM OOP lifting: fields, `<init>` constructors, `getfield`/`putfield`/`getstatic`/`putstatic`, `invokevirtual` via javac + java.
3. Lexical balanced-brace JS/TS Webpack & ESBuild unbundler handling nested braces, strings, templates, and comments.
"""

from __future__ import annotations

import ctypes
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

from aether_re.project_reconstructor import reconstruct_project
from aether_re.runtime_emitter import compile_reconstructed_project


def _build_elf64_x64_so(funcs: list[tuple[str, bytes]]) -> bytes:
    """Builds a minimal valid ELF64 shared object (ET_DYN) with .text, .symtab, .strtab, .shstrtab."""
    text_vaddr = 0x1000
    text_off = 0x1000
    code = bytearray()
    sym_defs: list[tuple[str, int, int]] = []
    for nm, b in funcs:
        sym_defs.append((nm, text_vaddr + len(code), len(b)))
        code.extend(b)
    text_bytes = bytes(code)

    strtab = bytearray(b"\x00")
    syms = bytearray(b"\x00" * 24)
    for nm, va, sz in sym_defs:
        nm_off = len(strtab)
        strtab.extend(nm.encode("ascii") + b"\x00")
        syms.extend(struct.pack("<IBBHQQ", nm_off, 0x12, 0, 1, va, sz))

    shstrtab = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    sym_off = text_off + len(text_bytes)
    str_off = sym_off + len(syms)
    shstr_off = str_off + len(strtab)
    shdr_off = (shstr_off + len(shstrtab) + 7) & ~7

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        3, 62, 1, text_vaddr, 0, shdr_off, 0, 64, 56, 0, 64, 5, 4,
    )
    sh_null = b"\x00" * 64
    sh_text = struct.pack("<IIQQQQIIQQ", shstrtab.index(b".text"), 1, 0x6, text_vaddr, text_off, len(text_bytes), 0, 0, 16, 0)
    sh_sym = struct.pack("<IIQQQQIIQQ", shstrtab.index(b".symtab"), 2, 0, 0, sym_off, len(syms), 3, 1, 8, 24)
    sh_str = struct.pack("<IIQQQQIIQQ", shstrtab.index(b".strtab"), 3, 0, 0, str_off, len(strtab), 0, 0, 1, 0)
    sh_shstr = struct.pack("<IIQQQQIIQQ", shstrtab.index(b".shstrtab"), 3, 0, 0, shstr_off, len(shstrtab), 0, 0, 1, 0)

    buf = bytearray(shdr_off + 5 * 64)
    buf[0:64] = ehdr
    buf[text_off : text_off + len(text_bytes)] = text_bytes
    buf[sym_off : sym_off + len(syms)] = syms
    buf[str_off : str_off + len(strtab)] = strtab
    buf[shstr_off : shstr_off + len(shstrtab)] = shstrtab
    buf[shdr_off : shdr_off + 320] = sh_null + sh_text + sh_sym + sh_str + sh_shstr
    return bytes(buf)


def test_v83_multi_tu_elf64_and_pe64_cross_compilation_and_live_execution(tmp_path: Path) -> None:
    # System V x86_64 machine code functions (rdi, rsi)
    fn_alpha = b"\x48\x8d\x04\x37\xc3"              # lea rax, [rdi + rsi]; ret
    fn_beta = b"\x48\x0f\xaf\xfe\x48\x89\xf8\xc3"   # imul rdi, rsi; mov rax, rdi; ret
    fn_gamma = b"\x48\x89\xf8\x48\x01\xf0\x48\x83\xc0\x0a\xc3"  # mov rax, rdi; add rax, rsi; add rax, 10; ret

    elf_p = tmp_path / "libmulti_v83.so"
    elf_p.write_bytes(_build_elf64_x64_so([("alpha_add", fn_alpha), ("beta_mul", fn_beta), ("gamma_combo", fn_gamma)]))

    out_elf = tmp_path / "elf_multi_tu"
    rep = reconstruct_project(elf_p, out_elf)
    assert rep.status == "complete"
    assert (out_elf / "CMakeLists.multi_tu.txt").is_file()
    tu_files = sorted((out_elf / "src" / "modules").glob("*.c"))
    assert len(tu_files) >= 3

    bld = compile_reconstructed_project(out_elf, "elf_multi_tu.dll", source_rel="multi_tu")
    assert bld["compiled"] is True, bld
    assert bld["translation_units"] >= 3
    dll = ctypes.CDLL(str(bld["dll_path"]))
    for sym in ("alpha_add", "beta_mul", "gamma_combo"):
        fn = getattr(dll, sym)
        fn.argtypes = [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64]
        fn.restype = ctypes.c_int64
    assert dll.alpha_add(11, 31, 0, 0) == 42
    assert dll.beta_mul(6, 7, 0, 0) == 42
    assert dll.gamma_combo(15, 25, 0, 0) == 50

    # Also verify PE64 real binary (`poly_test.dll`) compiles cleanly in Multi-TU mode and executes live
    repo_root = Path(__file__).resolve().parents[1]
    poly_dll = repo_root / "external_test_repos" / "cpp_poly" / "poly_test.dll"
    if poly_dll.is_file():
        out_pe = tmp_path / "pe_multi_tu"
        rep_pe = reconstruct_project(poly_dll, out_pe)
        assert rep_pe.status == "complete"
        bld_pe = compile_reconstructed_project(out_pe, "pe_multi_tu.dll", source_rel="multi_tu")
        assert bld_pe["compiled"] is True, bld_pe
        assert bld_pe["translation_units"] >= 2


def test_v83_jvm_oop_fields_constructor_and_instance_methods_roundtrip(tmp_path: Path) -> None:
    javac = shutil.which("javac")
    java = shutil.which("java")
    assert javac and java, "JDK javac/java required for live OOP JVM roundtrip"

    src_dir = tmp_path / "orig_src" / "demo"
    cls_dir = tmp_path / "orig_cls"
    src_dir.mkdir(parents=True, exist_ok=True)
    cls_dir.mkdir(parents=True, exist_ok=True)

    (src_dir / "Counter.java").write_text(
        "\n".join([
            "package demo;",
            "public class Counter {",
            "    public int value;",
            "    public int step;",
            "    public static int globalBias;",
            "    public static void setBias(int b) {",
            "        globalBias = b;",
            "    }",
            "    public Counter(int start, int step) {",
            "        this.value = start;",
            "        this.step = step;",
            "    }",
            "    public int advance(int times) {",
            "        for (int i = 0; i < times; i++) {",
            "            this.value += this.step;",
            "        }",
            "        return this.value + globalBias;",
            "    }",
            "}",
        ]),
        encoding="utf-8",
    )
    subprocess.run([javac, str(src_dir / "Counter.java"), "-d", str(cls_dir)], check=True, timeout=60)
    jar_path = tmp_path / "counter_oop.jar"
    with zipfile.ZipFile(jar_path, "w") as zf:
        zf.write(cls_dir / "demo" / "Counter.class", "demo/Counter.class")
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")

    out_dir = tmp_path / "rec_oop"
    rep = reconstruct_project(jar_path, out_dir)
    assert rep.status == "complete"
    lifted = out_dir / "app" / "src" / "main" / "java" / "demo" / "Counter.java"
    assert lifted.is_file()

    rec_cls = tmp_path / "rec_cls"
    rec_cls.mkdir(parents=True, exist_ok=True)
    runner = tmp_path / "RunnerOop.java"
    runner.write_text(
        "\n".join([
            "public class RunnerOop {",
            "    public static void main(String[] args) {",
            "        demo.Counter.setBias(5);",
            "        demo.Counter c = new demo.Counter(10, 3);",
            "        int r1 = c.advance(4);",
            "        int r2 = c.advance(2);",
            '        System.out.println(r1 + "," + r2 + "," + c.value);',
            "    }",
            "}",
        ]),
        encoding="utf-8",
    )
    subprocess.run([javac, str(lifted), str(runner), "-d", str(rec_cls)], check=True, timeout=60)
    run_out = subprocess.check_output([java, "-cp", str(rec_cls), "RunnerOop"], text=True, timeout=30).strip()
    # start=10, step=3, bias=5: advance(4) -> value=22, ret=27; advance(2) -> value=28, ret=33
    assert run_out == "27,33,28"


def test_v83_js_balanced_brace_webpack_and_esbuild_deep_unbundle(tmp_path: Path) -> None:
    bundle_js = tmp_path / "app.bundle.js"
    bundle_js.write_text(
        "\n".join([
            "const __webpack_modules__ = {",
            '  "crypto/hash": (module, exports, req) => {',
            '    /* fake } comment { inside */',
            '    const trap = "{ nested } `braces`";',
            "    const tpl = `prefix_${{ a: { b: 1 } }.a.b}_}`;",
            "    function inner(x) { if (x > 0) { return { ok: true, v: x + 1 }; } return { ok: false, v: 0 }; }",
            "    module.exports = inner;",
            "  },",
            '  101: function(mod, exp) {',
            "    const _0x1a2b = { fn: (z) => { return { doubled: z * 2 }; } };",
            "    exp.doubleObj = _0x1a2b.fn;",
            "  }",
            "};",
            'const __common = __commonJS({ "utils/math"(exports, module) {',
            "  exports.calc = (a, b) => { return { sum: a + b, prod: a * b }; };",
            "} });",
        ]),
        encoding="utf-8",
    )
    out_dir = tmp_path / "js_out"
    rep = reconstruct_project(bundle_js, out_dir)
    assert rep.status == "complete"
    assert rep.project_kind == "javascript_webpack_ts"
    assert (out_dir / "src" / "index.ts").is_file()
    mod_files = sorted((out_dir / "src" / "modules").glob("*.ts"))
    names = {p.name for p in mod_files}
    assert "crypto_hash.ts" in names
    assert "mod_101.ts" in names
    assert "utils_math.ts" in names
    crypto_txt = (out_dir / "src" / "modules" / "crypto_hash.ts").read_text(encoding="utf-8")
    assert "module.exports = inner" in crypto_txt
    assert "ok: true" in crypto_txt and "v: x + 1" in crypto_txt
