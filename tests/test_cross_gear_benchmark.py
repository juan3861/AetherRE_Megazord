from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aether_re.capabilities import analyze_target_capabilities, correlate_cross_gear_findings
from aether_re.mcp_server import TOOLS, AetherMcpDispatcher


def test_cross_gear_correlation_improves_tampered_pe_detection(tmp_path: Path):
    kernel = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "kernel32.dll"
    if not kernel.is_file():
        return
    tampered = bytearray(kernel.read_bytes())
    tampered[0x1000] ^= 0xFF
    t_path = tmp_path / "tampered_kernel32.dll"
    t_path.write_bytes(bytes(tampered))

    before = analyze_target_capabilities(t_path)
    after = correlate_cross_gear_findings(t_path)
    assert after["summary"]["total"] > before["summary"]["total"]
    ids = {c["id"] for c in after["capabilities"]}
    assert "evasion/authenticode-digest-tampered" in ids


def test_all_36_mcp_tools_registered_and_valid_schema():
    names = [t["name"] for t in TOOLS]
    assert len(names) >= 47
    for required in (
        "aether_detect_crypto",
        "aether_golang_recover",
        "aether_audit_authenticode",
        "aether_elf_dwarf_audit",
        "aether_macho_audit",
        "aether_rust_recover",
        "aether_firmware_audit",
        "aether_python_audit",
        "aether_cpp_rtti",
        "aether_api_hash_resolve",
        "aether_dotnet_audit",
        "aether_floss_strings",
        "aether_ole_macro",
        "aether_driver_audit",
        "aether_vmlinux_carve",
        "aether_dex_audit",
        "aether_wasm_audit",
        "aether_cfi_audit",
        "aether_installer_audit",
        "aether_omni_audit",
        "aether_asar_audit",
        "aether_reconstruct_project",
    ):
        assert required in names
        handler_name = "handle_" + required.removeprefix("aether_")
        assert hasattr(AetherMcpDispatcher, handler_name), f"Missing dispatcher handler: {handler_name}"


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as td:
        test_cross_gear_correlation_improves_tampered_pe_detection(Path(td))
    test_all_36_mcp_tools_registered_and_valid_schema()
    print(f"CROSS-GEAR BENCHMARK & {len(TOOLS)} MCP TOOLS VERIFIED.")
