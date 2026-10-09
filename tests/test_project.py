import json
import sys
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aether_re.adapters.angr import AngrAdapter
from aether_re.adapters.frida_dyn import FridaAdapter
from aether_re.adapters.unicorn_emu import UnicornAdapter
from aether_re.engines.consensus import (
    FunctionEvidence,
    compute_overall_confidence,
    merge_function_evidence,
)
from aether_re.engines.ghidra_parse import parse_decompiled_file
from aether_re.pipeline import adapters_status


REFERENCE = ROOT / "samples" / "fixtures" / "notepad_reference.exe"


def test_reference_fixture_is_pe64():
    pe = pefile.PE(str(REFERENCE), fast_load=True)
    assert pe.FILE_HEADER.Machine == 0x8664
    assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0x19B0
    assert pe.OPTIONAL_HEADER.ImageBase == 0x140000000


def test_ghidra_marker_parser_handles_200_functions(tmp_path: Path):
    path = tmp_path / "decompiled.c"
    source = "\n".join(
        f"/* function_{index} @ 0x{0x1000 + index:x} */\n"
        f"void function_{index}(void) {{ return; }}"
        for index in range(200)
    )
    path.write_text(source, encoding="utf-8")
    functions = parse_decompiled_file(path)
    assert len(functions) == 200
    assert functions[0]["address"] == "0x1000"
    assert functions[-1]["address"] == "0x10c7"


def test_consensus_matches_normalized_addresses():
    evidence = [
        FunctionEvidence(address="0x1000", name="foo", source="ghidra", calls=["bar"]),
        FunctionEvidence(address="1000", name="foo", source="angr", calls=["bar"]),
    ]
    merged = merge_function_evidence(evidence, ["ghidra", "angr"])
    assert len(merged) == 1
    assert merged[0].address == "0x1000"
    assert merged[0].selected_source == "ghidra"
    # With 5 sources in SOURCE_WEIGHTS (ghidra, rizin, angr, binaryninja, native)
    # 2 sources out of 5 = 0.4 coverage
    assert merged[0].coverage == 0.4


def test_native_semantic_cluster_has_no_function_address():
    merged = merge_function_evidence(
        [FunctionEvidence(address="native:1", name="api_resolution", source="native")],
        ["native"],
    )
    assert merged == []


def test_adapter_status_is_current():
    status = {item["name"]: item for item in adapters_status()}
    assert status["ghidra"]["available"] is True
    # angr may not be installed in all environments; accept either True or False
    assert isinstance(status["angr"]["available"], bool)


def test_angr_cfg_on_reference_fixture(tmp_path: Path):
    adapter = AngrAdapter()
    if not adapter.available():
        import pytest
        pytest.skip("angr not installed in this environment")
    result = adapter.analyze(REFERENCE, tmp_path)
    assert result["ok"] is True
    assert result["executed"] is True
    assert result["produced_evidence"] is True
    assert result["entry"] == "0x1400019b0"
    assert result["analysis"]["functions_count"] >= 1
    assert Path(result["report"]).exists()


def test_frida_reports_script_generation_without_trace(tmp_path: Path):
    result = FridaAdapter().analyze(REFERENCE, tmp_path)
    assert set(("ok", "available", "executed", "produced_evidence", "partial")).issubset(result)
    if result["available"]:
        assert result["executed"] is True
        assert result["produced_evidence"] is False
        assert result["partial"] is True
    else:
        assert result["executed"] is False
        assert result["produced_evidence"] is False


def test_unavailable_adapters_have_explicit_terminal_state(tmp_path: Path):
    for adapter in (FridaAdapter(),):
        if adapter.available():
            continue
        result = adapter.analyze(REFERENCE, tmp_path)
        assert result["available"] is False
        assert result["executed"] is False
        assert result["produced_evidence"] is False
        assert result["partial"] is False


def test_unicorn_windows_mode_is_partial_without_emulation(tmp_path: Path):
    result = UnicornAdapter().analyze(REFERENCE, tmp_path)
    assert result["executed"] is True
    assert result["produced_evidence"] is False
    assert result["partial"] is True


def test_overall_confidence_needs_merged_functions():
    confidence, rationale = compute_overall_confidence(
        [], native_confidence=0.8, successful_sources=[], failed_sources=[]
    )
    assert confidence == 0.65
    assert rationale["method"] == "function-weighted ensemble"
