"""
Empirical test script for AetherMind Strict Auditor.
Validates end-to-end functionality of megazord CLI and MCP server tools.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    python_exe = sys.executable
    megazord_py = Path("D:/AetherRE_Megazord/megazord.py")
    sample_dmp = Path("D:/AetherRE_Megazord/engineering_evidence/live_audited_process.dmp")
    sample_js = Path("D:/AetherRE_Megazord/engineering_evidence/acorn_verified_cli.js")

    assert megazord_py.exists(), f"megazord.py not found: {megazord_py}"
    assert sample_dmp.exists(), f"sample_dmp not found: {sample_dmp}"
    assert sample_js.exists(), f"sample_js not found: {sample_js}"

    # 1. Test CLI minidump-audit
    print("[TEST 1/3] CLI minidump-audit...")
    proc_dmp = subprocess.run(
        [python_exe, str(megazord_py), "minidump-audit", str(sample_dmp)],
        capture_output=True,
        text=True,
        check=True,
    )
    dmp_data = json.loads(proc_dmp.stdout)
    assert dmp_data.get("status") == "CLEAN"
    assert dmp_data.get("modules_count", 0) > 50
    assert dmp_data.get("memory_regions_count", 0) > 500
    print(f" -> CLI minidump-audit verified: {dmp_data['modules_count']} modules, {dmp_data['memory_regions_count']} memory regions.")

    # 2. Test CLI webcrack
    print("[TEST 2/3] CLI webcrack...")
    proc_wc = subprocess.run(
        [python_exe, str(megazord_py), "webcrack", str(sample_js)],
        capture_output=True,
        text=True,
        check=True,
    )
    wc_data = json.loads(proc_wc.stdout)
    assert wc_data.get("success") is True
    assert wc_data.get("deobfuscated_size", 0) > 0
    print(f" -> CLI webcrack verified: {wc_data['deobfuscated_size']} bytes deobfuscated in {wc_data['elapsed_ms']}ms.")

    # 3. Test MCP Server Dispatcher
    print("[TEST 3/3] MCP Server Dispatcher...")
    sys.path.insert(0, "D:/AetherRE_Megazord")
    from aether_re.mcp_server import AetherMcpDispatcher, TOOLS

    tool_names = {t["name"] for t in TOOLS}
    assert "aether_ghidra_decompile" in tool_names
    assert "aether_webcrack" in tool_names
    assert "aether_minidump_audit" in tool_names
    assert "aether_ground_truth_eval" in tool_names

    dmp_res = AetherMcpDispatcher.handle_minidump_audit(str(sample_dmp))
    assert dmp_res["modules_count"] > 50

    wc_res = AetherMcpDispatcher.handle_webcrack(str(sample_js))
    assert wc_res["success"] is True

    src_tmp = Path("D:/AetherRE_Megazord/engineering_evidence/temp_gt_test.c")
    src_tmp.write_text("void dummy(int *p) { if (p) { *p = 1; } }", encoding="utf-8")
    try:
        gt_res = AetherMcpDispatcher.handle_ground_truth_eval(
            str(src_tmp),
            "void dummy(int *p) { if (p != 0) { *p = 1; } }",
            "dummy",
        )
        assert gt_res["empirical_fidelity_score_pct"] > 80.0
    finally:
        if src_tmp.exists():
            src_tmp.unlink()

    print(f" -> MCP Server tools verified: {len(tool_names)} registered tools.")
    print("ALL EMPIRICAL TESTS PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
