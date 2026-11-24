"""Empirical tests for AetherRE Megazord v8.4.0:
1. Shared Multi-TU .data/.rdata runtime state (`mod_runtime_shared.c` + `AETHER_MULTI_TU_DECL`) on real `lz4.dll` & `tinyexpr.dll`.
2. JVM multi-class inheritance (`extends`), interfaces (`implements`, `invokeinterface`), `super(...)` & cross-class `new` via javac + java.
3. Live Node.js ESM execution parity (`verify_reconstructed_js_bundle` + `loadBundleModule`) across interdependent Webpack modules.
"""

from __future__ import annotations

import ctypes
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

from aether_re.managed_reconstructors import verify_reconstructed_js_bundle
from aether_re.project_reconstructor import reconstruct_project
from aether_re.runtime_emitter import compile_reconstructed_project


def test_v84_multi_tu_shared_data_rdata_state_lz4_and_tinyexpr_live_dll(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    lz_dll = repo_root / "external_test_repos" / "lz4" / "lz4.dll"
    te_dll = repo_root / "external_test_repos" / "tinyexpr" / "tinyexpr.dll"
    assert lz_dll.is_file() and te_dll.is_file()

    # 1. Multi-TU compilation and live execution of lz4.dll
    lz_out = tmp_path / "lz4_multi_tu"
    rep_lz = reconstruct_project(lz_dll, lz_out)
    assert rep_lz.status == "complete"
    assert (lz_out / "src" / "modules" / "mod_runtime_shared.c").is_file()
    bld_lz = compile_reconstructed_project(lz_out, "lz4_mtu.dll", source_rel="multi_tu")
    assert bld_lz["compiled"] is True, bld_lz
    assert bld_lz["translation_units"] >= 3
    dlz = ctypes.CDLL(str(bld_lz["dll_path"]))
    dlz.LZ4_compressBound.argtypes = [ctypes.c_int]
    dlz.LZ4_compressBound.restype = ctypes.c_int
    dlz.LZ4_compress_default.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    dlz.LZ4_compress_default.restype = ctypes.c_int
    dlz.LZ4_decompress_safe.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    dlz.LZ4_decompress_safe.restype = ctypes.c_int
    payload = b"AetherRE v8.4 Multi-TU Shared State Compression Parity Check! " * 4
    bound = dlz.LZ4_compressBound(len(payload))
    comp = ctypes.create_string_buffer(bound)
    dec = ctypes.create_string_buffer(len(payload))
    csz = dlz.LZ4_compress_default(payload, comp, len(payload), bound)
    assert csz > 0
    dsz = dlz.LZ4_decompress_safe(comp.raw[:csz], dec, csz, len(payload))
    assert dsz == len(payload) and dec.raw[:dsz] == payload

    # 2. Multi-TU compilation and live execution of tinyexpr.dll (.rdata DIR64 relocations across TUs)
    te_out = tmp_path / "te_multi_tu"
    rep_te = reconstruct_project(te_dll, te_out)
    assert rep_te.status == "complete"
    assert (te_out / "src" / "modules" / "mod_runtime_shared.c").is_file()
    bld_te = compile_reconstructed_project(te_out, "te_mtu.dll", source_rel="multi_tu")
    assert bld_te["compiled"] is True, bld_te
    dte = ctypes.CDLL(str(bld_te["dll_path"]))
    dte.te_interp.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    dte.te_interp.restype = ctypes.c_double
    err = ctypes.c_int(0)
    val = dte.te_interp(b"sqrt(144) + pow(2, 5) + 3", ctypes.byref(err))
    assert abs(val - 47.0) < 1e-6


def test_v84_jvm_multiclass_interface_inheritance_and_polymorphism_roundtrip(tmp_path: Path) -> None:
    javac = shutil.which("javac")
    java = shutil.which("java")
    assert javac and java, "JDK javac/java required for polymorphic JVM test"

    src_dir = tmp_path / "orig_src" / "demo"
    cls_dir = tmp_path / "orig_cls"
    src_dir.mkdir(parents=True, exist_ok=True)
    cls_dir.mkdir(parents=True, exist_ok=True)

    (src_dir / "Scorer.java").write_text(
        "package demo;\npublic interface Scorer {\n    int score(int x);\n}\n",
        encoding="utf-8",
    )
    (src_dir / "BaseEngine.java").write_text(
        "\n".join([
            "package demo;",
            "public class BaseEngine implements Scorer {",
            "    public int bias;",
            "    public BaseEngine(int b) { this.bias = b; }",
            "    public int score(int x) { return x + this.bias; }",
            "}",
        ]),
        encoding="utf-8",
    )
    (src_dir / "BoostEngine.java").write_text(
        "\n".join([
            "package demo;",
            "public class BoostEngine extends BaseEngine {",
            "    public int mult;",
            "    public BoostEngine(int b, int m) { super(b); this.mult = m; }",
            "    @Override public int score(int x) { return (x * this.mult) + this.bias; }",
            "}",
        ]),
        encoding="utf-8",
    )
    (src_dir / "Dispatcher.java").write_text(
        "\n".join([
            "package demo;",
            "public class Dispatcher {",
            "    public static int runAll(int b, int x) {",
            "        Scorer s = new BoostEngine(b, 3);",
            "        return s.score(x);",
            "    }",
            "}",
        ]),
        encoding="utf-8",
    )
    subprocess.run(
        [
            javac,
            str(src_dir / "Scorer.java"),
            str(src_dir / "BaseEngine.java"),
            str(src_dir / "BoostEngine.java"),
            str(src_dir / "Dispatcher.java"),
            "-d",
            str(cls_dir),
        ],
        check=True,
        timeout=60,
    )
    jar_path = tmp_path / "poly_jvm.jar"
    with zipfile.ZipFile(jar_path, "w") as zf:
        for nm in ("Scorer.class", "BaseEngine.class", "BoostEngine.class", "Dispatcher.class"):
            zf.write(cls_dir / "demo" / nm, f"demo/{nm}")
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")

    out_dir = tmp_path / "rec_poly_jvm"
    rep = reconstruct_project(jar_path, out_dir)
    assert rep.status == "complete"
    java_root = out_dir / "app" / "src" / "main" / "java" / "demo"
    for nm in ("Scorer.java", "BaseEngine.java", "BoostEngine.java", "Dispatcher.java"):
        assert (java_root / nm).is_file()

    assert "interface Scorer" in (java_root / "Scorer.java").read_text(encoding="utf-8")
    assert "implements demo.Scorer" in (java_root / "BaseEngine.java").read_text(encoding="utf-8")
    assert "extends demo.BaseEngine" in (java_root / "BoostEngine.java").read_text(encoding="utf-8")

    rec_cls = tmp_path / "rec_cls"
    rec_cls.mkdir(parents=True, exist_ok=True)
    runner = tmp_path / "RunnerPoly.java"
    runner.write_text(
        'public class RunnerPoly { public static void main(String[] a) { System.out.println(demo.Dispatcher.runAll(10, 5) + "," + (new demo.BaseEngine(4)).score(6)); } }\n',
        encoding="utf-8",
    )
    subprocess.run(
        [
            javac,
            str(java_root / "Scorer.java"),
            str(java_root / "BaseEngine.java"),
            str(java_root / "BoostEngine.java"),
            str(java_root / "Dispatcher.java"),
            str(runner),
            "-d",
            str(rec_cls),
        ],
        check=True,
        timeout=60,
    )
    out = subprocess.check_output([java, "-cp", str(rec_cls), "RunnerPoly"], text=True, timeout=30).strip()
    assert out == "25,10"


def test_v84_js_bundle_live_node_esm_execution_parity(tmp_path: Path) -> None:
    node_bin = shutil.which("node")
    assert node_bin, "Node.js required for live ESM execution check"

    bundle_js = tmp_path / "webpack_live.js"
    bundle_js.write_text(
        "\n".join([
            "var __modules = {",
            '  "math/core": function(module, exports, req) {',
            "    exports.scale = function(x) { return { val: (x * 3) + 4 }; };",
            "  },",
            '  "app/main": (module, exports, req) => {',
            '    const core = req("math/core");',
            "    module.exports = function(n) { return core.scale(n).val; };",
            "  }",
            "};",
        ]),
        encoding="utf-8",
    )
    out_dir = tmp_path / "js_live_out"
    rep = reconstruct_project(bundle_js, out_dir)
    assert rep.status == "complete"
    ver = verify_reconstructed_js_bundle(out_dir)
    assert ver["verified"] is True, ver
    assert "app/main" in ver["modules_loaded"] and "math/core" in ver["modules_loaded"]

    loader_uri = (out_dir / "src" / "runtime_loader.mjs").resolve().as_uri()
    out_node = subprocess.check_output(
        [
            node_bin,
            "--input-type=module",
            "-e",
            f'import {{ loadBundleModule }} from {json.dumps(loader_uri)}; const fn = loadBundleModule("app/main"); console.log(fn(7));',
        ],
        text=True,
        timeout=30,
    ).strip()
    assert out_node == "25"
