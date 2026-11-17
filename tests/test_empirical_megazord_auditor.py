"""
Empirical test script for AetherMind Strict Auditor.
Validates end-to-end functionality of megazord CLI, unpackers, heap forensics, C++ ground-truth, crypto detection, and Golang symbol recovery engines.
"""
from __future__ import annotations

import io
import json
import subprocess
import sys
import zlib
from pathlib import Path


def main() -> int:
    python_exe = sys.executable
    megazord_py = Path("D:/AetherRE_Megazord/megazord.py")
    sample_dmp = Path("D:/AetherRE_Megazord/engineering_evidence/live_audited_process.dmp")
    sample_js = Path("D:/AetherRE_Megazord/engineering_evidence/acorn_verified_cli.js")

    assert megazord_py.exists(), f"megazord.py not found: {megazord_py}"
    assert sample_dmp.exists(), f"sample_dmp not found: {sample_dmp}"
    assert sample_js.exists(), f"sample_js not found: {sample_js}"

    sys.path.insert(0, "D:/AetherRE_Megazord")

    # 1. Test CLI minidump-audit and Windows NT Heap Forensics
    print("[TEST 1/7] CLI minidump-audit & NT Heap Forensics...")
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

    from aether_re.minidump_parser import MiniDumpParser
    mf = MiniDumpParser(sample_dmp)
    heap_info = mf.get_heap_analysis()
    assert heap_info["status"] == "HEALTHY"
    assert heap_info["total_committed_heap_regions"] > 100
    assert heap_info["total_heap_bytes"] > 10_000_000
    print(f" -> Minidump & NT Heap verified: {heap_info['total_committed_heap_regions']} regions, {heap_info['total_heap_megabytes']} MB (Status: {heap_info['status']}).")

    # 2. Test CLI webcrack
    print("[TEST 2/7] CLI webcrack...")
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

    # 3. Test Container Unpackers (InnoSetup & NSIS)
    print("[TEST 3/7] Container Unpackers (InnoSetup & NSIS)...")
    from aether_re.unpackers import detect_container_format, unpack_container
    import shutil

    tmp_out = Path("D:/AetherRE_Megazord/engineering_evidence/temp_unpack_audit")
    if tmp_out.exists():
        shutil.rmtree(tmp_out)
    tmp_out.mkdir(parents=True, exist_ok=True)

    try:
        # Verify NSIS
        nsis_data = b"MZ" + b"\x00" * 128 + b"\xef\xbe\xad\xdeNullsoftInst" + zlib.compress(b"extracted_nsis_content")
        tmp_nsis = Path("D:/AetherRE_Megazord/engineering_evidence/temp_sample.nsis.exe")
        tmp_nsis.write_bytes(nsis_data)
        try:
            fmt = detect_container_format(tmp_nsis)
            assert fmt == "nsis"
            res_nsis = unpack_container(tmp_nsis, tmp_out / "nsis")
            assert res_nsis["container_format"] == "nsis"
            assert res_nsis["file_count"] >= 1
        finally:
            if tmp_nsis.exists():
                tmp_nsis.unlink()

        # Verify InnoSetup
        inno_data = b"MZ" + b"\x00" * 128 + b"Inno Setup Setup Data (5.5.0)" + b"\x00" * 32 + zlib.compress(b"innosetup_file_data")
        tmp_inno = Path("D:/AetherRE_Megazord/engineering_evidence/temp_sample.inno.exe")
        tmp_inno.write_bytes(inno_data)
        try:
            fmt = detect_container_format(tmp_inno)
            assert fmt == "innosetup"
            res_inno = unpack_container(tmp_inno, tmp_out / "inno")
            assert res_inno["container_format"] == "innosetup"
            assert res_inno["file_count"] >= 1
        finally:
            if tmp_inno.exists():
                tmp_inno.unlink()
    finally:
        if tmp_out.exists():
            shutil.rmtree(tmp_out)
    print(" -> Unpackers verified: NSIS and InnoSetup decompressed with zero defects.")

    # 4. Execute comparisons now; historical score JSON is not a live oracle.
    print("[TEST 4/7] Behavioral counterexample and explicit C32 model...")
    import tempfile
    from aether_re.ground_truth_eval import evaluate_decompilation_against_ground_truth
    with tempfile.TemporaryDirectory(prefix="aether-behavior-check-") as temp:
        reference = Path(temp) / "reference.c"
        reference.write_text("int add(int a,int b){return a+b;}", encoding="utf-8")
        wrong = evaluate_decompilation_against_ground_truth(reference,"int add(int a,int b){return 0;}","add")
        equivalent = evaluate_decompilation_against_ground_truth(reference,"int add(int a,int b){return b+a;}","add")
        assert wrong["behavioral_comparison"]["status"] == "different"
        assert equivalent["behavioral_comparison"]["status"] == "equivalent_in_model"
        assert wrong["empirical_fidelity_score_pct"] is None
    print(" -> Current evaluator produced a counterexample and scoped equivalence; no C++ universal certification.")

    # 5. Test MCP Server Dispatcher
    print("[TEST 5/7] MCP Server Dispatcher...")
    from aether_re.mcp_server import AetherMcpDispatcher, TOOLS

    tool_names = {t["name"] for t in TOOLS}
    assert "aether_ghidra_decompile" in tool_names
    assert "aether_webcrack" in tool_names
    assert "aether_minidump_audit" in tool_names
    assert "aether_ground_truth_eval" in tool_names
    assert "aether_detect_crypto" in tool_names
    assert "aether_golang_recover" in tool_names
    assert len(tool_names) == 27

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
        assert gt_res["empirical_fidelity_score_pct"] is None
        assert gt_res["structural_similarity_score_pct"] > 80.0
        assert gt_res["behavioral_comparison"]["status"] == "unknown"
    finally:
        if src_tmp.exists():
            src_tmp.unlink()

    print(f" -> MCP Server tools verified: {len(tool_names)} registered tools (including aether_detect_crypto, aether_golang_recover).")

    # 6. Test CLI crypto-detect and MCP handle_detect_crypto (FindCrypt GEAR-01)
    print("[TEST 6/7] CLI crypto-detect & Forensic Constant Engine...")
    from aether_re.crypto_detect import AES_SBOX, CHACHA20_CONST_32, SHA256_K_LE

    tmp_crypto = Path("D:/AetherRE_Megazord/engineering_evidence/temp_crypto_test.bin")
    payload = bytearray(b"\x90" * 4096)
    payload[0x100 : 0x100 + 256] = AES_SBOX
    payload[0x400 : 0x400 + len(CHACHA20_CONST_32)] = CHACHA20_CONST_32
    payload[0x600 : 0x600 + len(SHA256_K_LE)] = SHA256_K_LE
    tmp_crypto.write_bytes(payload)

    try:
        proc_crypto = subprocess.run(
            [python_exe, str(megazord_py), "crypto-detect", str(tmp_crypto)],
            capture_output=True,
            text=True,
            check=True,
        )
        c_data = json.loads(proc_crypto.stdout)
        assert c_data["total_constants_detected"] >= 3
        assert "AES" in c_data["identified_algorithms"]
        assert "ChaCha20" in c_data["identified_algorithms"]
        assert "SHA-256" in c_data["identified_algorithms"]

        mcp_crypto = AetherMcpDispatcher.handle_detect_crypto(str(tmp_crypto))
        assert mcp_crypto["total_constants_detected"] >= 3
        assert mcp_crypto["high_confidence_matches_count"] >= 3
    finally:
        if tmp_crypto.exists():
            tmp_crypto.unlink()

    print(" -> Crypto Detection verified: AES, ChaCha20, SHA-256 S-Boxes and tables detected accurately via CLI & MCP.")

    # 7. Test CLI golang-recover and MCP handle_golang_recover (GoReSym GEAR-02)
    print("[TEST 7/7] CLI golang-recover & Go pclntab Engine...")
    from tests.test_golang_recover import _build_go116_test_blob

    tmp_go = Path("D:/AetherRE_Megazord/engineering_evidence/temp_go_test.exe")
    blob = _build_go116_test_blob(ptr_size=8)
    tmp_go.write_bytes(b"\x90" * 256 + blob + b"\x90" * 256)

    try:
        # CLI invocation
        proc_go = subprocess.run(
            [python_exe, str(megazord_py), "golang-recover", str(tmp_go)],
            capture_output=True,
            text=True,
            check=True,
        )
        go_data = json.loads(proc_go.stdout)
        assert go_data["is_go_binary"] is True
        assert go_data["total_functions"] == 3
        recovered_names = [f["name"] for f in go_data["functions"]]
        assert "main.main" in recovered_names
        assert "runtime.morestack" in recovered_names
        assert "net/http.Get" in recovered_names

        # MCP Dispatcher invocation
        mcp_go = AetherMcpDispatcher.handle_golang_recover(str(tmp_go))
        assert mcp_go["is_go_binary"] is True
        assert mcp_go["total_functions"] == 3
    finally:
        if tmp_go.exists():
            tmp_go.unlink()

    print(" -> Golang Recovery verified: pclntab parsed and 3/3 functions recovered via CLI & MCP.")
    print("ALL 7/7 LOCAL SMOKE CHECKS PASSED WITHIN SCOPE. NO EXTERNAL CERTIFICATION IS INFERRED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
