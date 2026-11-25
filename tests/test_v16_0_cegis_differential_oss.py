from __future__ import annotations

from pathlib import Path
import subprocess

from aether_re.differential_certifier import certify_differential_parity
from aether_re.mcp_server import AetherMcpDispatcher, TOOLS
from aether_re.runtime_emitter import _find_msvc_x64_toolchain, compile_reconstructed_project


def test_v160_cegis_differential_certifier_auto_repairs_width_and_bias_defects(tmp_path: Path) -> None:
    orig_c = tmp_path / "orig.c"
    orig_c.write_text(
        """
        #include <stdint.h>
        __declspec(dllexport) int64_t fn_signed32(int64_t a, int64_t b, int64_t c, int64_t d) {
            uint32_t x = (uint32_t)a * 16777619u ^ 0x80000001u;
            return (int64_t)(int32_t)x;
        }
        __declspec(dllexport) int64_t fn_bias(int64_t a, int64_t b, int64_t c, int64_t d) {
            return (a * 7LL) + (b * 3LL) + 42LL;
        }
        """,
        encoding="utf-8",
    )
    orig_dll = tmp_path / "orig.dll"
    _, env, cl_exe, _ = _find_msvc_x64_toolchain()
    subprocess.run([cl_exe, "/nologo", "/LD", "/O2", str(orig_c), f"/Fe:{orig_dll}"], cwd=str(tmp_path), env=env, check=True, capture_output=True)

    proj = tmp_path / "flawed_twin"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "exports.def").write_text("EXPORTS\n    fn_signed32\n    fn_bias\n", encoding="utf-8")
    # Intentional defects: zero-extended uint32_t in fn_signed32 + missing +42 in fn_bias
    (proj / "src" / "reconstructed_project.c").write_text(
        """
        #include <stdint.h>
        int64_t fn_signed32(int64_t a, int64_t b, int64_t c, int64_t d) {
            uint32_t x = (uint32_t)a * 16777619u ^ 0x80000001u;
            return (int64_t)x;
        }
        int64_t fn_bias(int64_t a, int64_t b, int64_t c, int64_t d) {
            return (a * 7LL) + (b * 3LL);
        }
        """,
        encoding="utf-8",
    )
    comp = compile_reconstructed_project(proj)
    assert comp["compiled"] is True

    cert = certify_differential_parity(
        orig_dll,
        proj,
        ["fn_signed32", "fn_bias"],
        auto_repair=True,
        output_cert_path=tmp_path / "cert.json",
    )
    assert cert["divergences_before_repair"] > 0
    assert len(cert["cegis_repairs_applied"]) == 2
    assert cert["divergences_after_repair"] == 0
    assert cert["differential_parity_pct"] == 100.0
    assert cert["certified_100pct"] is True
    assert (tmp_path / "cert.json").is_file()


def test_v160_mcp_new_tools_and_external_oss_parity_benchmark(tmp_path: Path) -> None:
    names = {t["name"] for t in TOOLS}
    assert {
        "aether_behavioral_flirt",
        "aether_cpp_class_recover",
        "aether_backend_twin",
        "aether_forensic_container",
        "aether_differential_certify",
    }.issubset(names)

    bt = AetherMcpDispatcher.handle_backend_twin(str(tmp_path / "bt_out"))
    assert bt["routes_count"] >= 1

    from tools.benchmark_external_oss_and_dfir_parity import run_external_benchmark

    rep = run_external_benchmark(work_dir=tmp_path / "ext_bench")
    assert rep["status"] == "PASS" and rep["differential_parity_pct"] == 100.0
