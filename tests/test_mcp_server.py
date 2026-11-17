from __future__ import annotations

import json
from pathlib import Path
import pytest

from aether_re.mcp_server import (
    PROTOCOL_VERSION,
    SERVER_INFO,
    TOOLS,
    AetherMcpDispatcher,
    _categorize_strings,
)


def test_mcp_server_metadata_and_tools_schema():
    assert PROTOCOL_VERSION == "2024-11-05"
    assert SERVER_INFO["name"] == "aetherre-megazord"
    tool_names = {t["name"] for t in TOOLS}
    expected = {
        "aether_status",
        "aether_triage",
        "aether_inspect",
        "aether_detect_capabilities",
        "aether_strings_forensic",
        "aether_firmware_qualify",
        "aether_source_analyze",
        "aether_unpack",
        "aether_symbolic_explore",
        "aether_binary_diff",
        "aether_generate_yara",
        "aether_export_graph",
        "aether_function_simhash",
        "aether_packer_detect",
        "aether_graph_analytics",
        "aether_cfg_dominance",
        "aether_deobfuscate",
        "aether_abi_infer",
        "aether_taint_slice",
        "aether_struct_recovery",
        "aether_check_feasibility",
        "aether_ghidra_decompile",
        "aether_webcrack",
        "aether_minidump_audit",
        "aether_ground_truth_eval",
    }
    assert expected.issubset(tool_names)


def test_mcp_dispatcher_status():
    status = AetherMcpDispatcher.handle_status()
    assert "version" in status
    assert "adapters" in status
    assert isinstance(status["adapters"], list)


def test_mcp_dispatcher_triage_and_strings(tmp_path: Path):
    sample = tmp_path / "test.bin"
    sample.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00http://example.com\x00192.168.1.100\x00Software\\Microsoft\\Windows\x00C:\\Windows\\System32\x00")

    triage_res = AetherMcpDispatcher.handle_triage(str(sample))
    assert triage_res["detected_format"] == "pe/dos"
    assert len(triage_res["sha256"]) == 64

    strings_res = AetherMcpDispatcher.handle_strings_forensic(str(sample))
    cat = strings_res["categorized"]
    assert any("http://example.com" in s for s in cat["urls"])
    assert any("192.168.1.100" in s for s in cat["ips"])
    assert any("Software\\Microsoft\\Windows" in s for s in cat["registry_keys"])


def test_mcp_dispatcher_capabilities(tmp_path: Path):
    sample = tmp_path / "mal.bin"
    sample.write_bytes(b"IsDebuggerPresent\x00CreateRemoteThread\x00")
    caps = AetherMcpDispatcher.handle_capabilities(str(sample))
    assert caps["status"] == "complete"
    assert caps["summary"]["total"] >= 2


def test_mcp_dispatcher_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        AetherMcpDispatcher.handle_triage("non_existent_file.xyz")


def test_categorize_strings_logic():
    raw = [
        "https://api.github.com/v1",
        "10.0.0.1",
        "HKEY_LOCAL_MACHINE\\Software",
        "/etc/passwd",
        "d41d8cd98f00b204e9800998ecf8427e",
        "JustARandomString",
    ]
    res = _categorize_strings(raw)
    assert "https://api.github.com/v1" in res["urls"]
    assert "10.0.0.1" in res["ips"]
    assert "HKEY_LOCAL_MACHINE\\Software" in res["registry_keys"]
    assert "/etc/passwd" in res["file_paths"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in res["crypto_or_hashes"]
    assert "JustARandomString" in res["others"]


def test_mcp_dispatcher_unpack(tmp_path: Path):
    import zipfile
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("module/app.js", b"console.log('hello');")
        zf.writestr("manifest.json", b'{"name": "test"}')

    out_dir = tmp_path / "extracted"
    res = AetherMcpDispatcher.handle_unpack(str(zip_path), str(out_dir))
    assert res["status"] == "unpacked"
    assert res["container_format"] == "zip"
    assert res["file_count"] == 2
    assert (out_dir / "module" / "app.js").read_bytes() == b"console.log('hello');"
    assert (out_dir / "manifest.json").read_bytes() == b'{"name": "test"}'


def test_mcp_dispatcher_symbolic_explore(tmp_path: Path):
    sample = tmp_path / "dummy.bin"
    sample.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100)
    res = AetherMcpDispatcher.handle_symbolic_explore(str(sample), max_steps=5)
    assert res["schema"] == "symbolic-exploration.v1"
    assert res["engine"] == "angr"
    assert res["status"] in {"unavailable", "sat", "unsat", "bounded_cutoff", "failed"}


def test_mcp_dispatcher_binary_diff(tmp_path: Path):
    target_a = tmp_path / "bin_a.exe"
    target_b = tmp_path / "bin_b.exe"
    target_a.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00TEST_A_DATA\x00")
    target_b.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00TEST_B_DATA\x00")

    diff_res = AetherMcpDispatcher.handle_binary_diff(str(target_a), str(target_b))
    assert diff_res["schema"] == "binary-diff-report.v1"
    assert diff_res["status"] == "diff_completed"
    assert 0.0 <= diff_res["overall_similarity"] <= 1.0


def test_mcp_dispatcher_yara_and_graph(tmp_path: Path):
    target = tmp_path / "test_artifact.bin"
    target.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" + b"TEST_PAYLOAD_STRING_XYZ\x00" * 5)

    yara_res = AetherMcpDispatcher.handle_generate_yara(str(target), rule_name="Test_Rule_123")
    assert yara_res["status"] == "generated"
    assert "rule Test_Rule_123" in yara_res["yara_rule"]

    graph_res = AetherMcpDispatcher.handle_export_graph(str(target), output_format="mermaid")
    assert graph_res["status"] == "complete"
    assert "flowchart TD" in graph_res["graph_content"]

    sh_res = AetherMcpDispatcher.handle_function_simhash(str(target))
    assert sh_res["schema"] == "function-simhash-report.v1"
    assert "functions" in sh_res

    packer_res = AetherMcpDispatcher.handle_packer_detect(str(target))
    assert packer_res["schema"] == "packer-entropy-report.v1"
    assert "is_packed" in packer_res
    assert "compiler" in packer_res

    analytics_res = AetherMcpDispatcher.handle_graph_analytics(str(target))
    assert analytics_res["schema"] == "graph-analytics-report.v1"
    assert "metrics" in analytics_res
    assert "cyclomatic_complexity" in analytics_res["metrics"]

    dom_res = AetherMcpDispatcher.handle_cfg_dominance(str(target))
    assert dom_res["schema"] == "cfg-dominance-report.v1"
    assert "immediate_dominators" in dom_res
    assert "is_reducible" in dom_res

    deobf_res = AetherMcpDispatcher.handle_deobfuscate("(x ^ y) + 2*(x & y)")
    assert deobf_res["schema"] == "deobfuscation-report.v1"
    assert deobf_res["simplified"] == "(x + y)"

    abi_res = AetherMcpDispatcher.handle_abi_infer(str(target))
    assert abi_res["schema"] == "calling-convention-report.v1"
    assert "calling_convention" in abi_res
    assert "c_prototype" in abi_res

    taint_res = AetherMcpDispatcher.handle_taint_slice(str(target))
    assert taint_res["schema"] == "pdg-taint-report.v1"
    assert "is_vulnerable" in taint_res

    struct_res = AetherMcpDispatcher.handle_struct_recovery(str(target))
    assert struct_res["schema"] == "struct-recovery-report.v1"
    assert "total_structs_recovered" in struct_res

    feas_res = AetherMcpDispatcher.handle_check_feasibility("x > 10; x < 20")
    assert feas_res["schema"] == "constraint-feasibility-report.v1"
    assert feas_res["status"] == "SAT"


def test_instantiated_dispatcher_compares_behavior_like_stdio_server(tmp_path: Path):
    source = tmp_path / "add.c"
    source.write_text("int add(int a,int b){return a+b;}",encoding="utf-8")
    result = AetherMcpDispatcher().handle_ground_truth_eval(str(source),"int add(int a,int b){return a-b;}","add")
    assert result["behavioral_comparison"]["status"] == "different"
    assert result["empirical_fidelity_score_pct"] is None


def test_instantiated_dispatcher_detects_crypto_like_stdio_server(tmp_path: Path):
    from aether_re.crypto_detect import AES_SBOX
    target = tmp_path / "owned_crypto.bin"
    target.write_bytes(b"\0"*64+AES_SBOX+b"\0"*64)
    result = AetherMcpDispatcher().handle_detect_crypto(str(target))
    assert "AES" in result["identified_algorithms"]
    assert result["total_constants_detected"] >= 1


def test_mcp_dispatcher_new_sota_tools(tmp_path: Path):
    # 1. Ground truth evaluation
    src_file = tmp_path / "foo.c"
    src_file.write_text("""
    void foo(int *x) {
        if (x != NULL) {
            *x = 42;
            printf("val: %d", *x);
        }
    }
    """, encoding="utf-8")
    dec_c = """
    void foo(int *param_1) {
        if (param_1 != (int *)0x0) {
            *param_1 = 0x2a;
            printf("val: %d", *param_1);
        }
    }
    """
    gt_res = AetherMcpDispatcher.handle_ground_truth_eval(str(src_file), dec_c, "foo")
    assert gt_res["function_name"] == "foo"
    assert gt_res["empirical_fidelity_score_pct"] is None
    assert gt_res["structural_similarity_score_pct"] > 80.0
    assert gt_res["behavioral_comparison"]["status"] == "unknown"

    # 2. Webcrack tool
    js_file = tmp_path / "bundle.js"
    js_file.write_text("var a = 1; var b = 2; console.log(a + b);", encoding="utf-8")
    out_dir = tmp_path / "webcrack_out"
    wc_res = AetherMcpDispatcher.handle_webcrack(str(js_file), out_dir=str(out_dir))
    assert wc_res["success"] is True
    assert wc_res["input_path"] == str(js_file.resolve())

    # 3. Minidump audit
    dmp_file = Path("engineering_evidence/live_audited_process.dmp")
    if dmp_file.exists():
        dmp_res = AetherMcpDispatcher.handle_minidump_audit(str(dmp_file))
        assert "modules_count" in dmp_res
        assert dmp_res["modules_count"] > 0




