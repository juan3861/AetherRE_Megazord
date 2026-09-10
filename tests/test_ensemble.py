from pathlib import Path

from aether_re.engines.ghidra_parse import parse_decompiled_text
from aether_re.engines.consensus import FunctionEvidence, merge_function_evidence
from aether_re.models import FunctionConsensus


def test_parse_ghidra_functions_by_marker():
    text = """
/* foo @ 140001000 */
void foo() { return bar(); }

/* FUN_140001020 @ 140001020 */
void FUN_140001020() { return 1; }
"""
    functions = parse_decompiled_text(text)
    assert len(functions) == 2
    assert functions[0].address == "0x140001000"
    assert functions[0].name == "foo"
    assert functions[1].address == "0x140001020"
    assert "bar" in functions[0].calls


def test_consensus_merges_same_address_sources():
    evidence = [
        FunctionEvidence(
            address="0x1000",
            name="foo",
            source="ghidra",
            confidence=0.95,
            quality=0.95,
            calls=["bar"],
        ),
        FunctionEvidence(
            address="1000",
            name="foo",
            source="angr",
            confidence=0.85,
            quality=0.75,
            calls=["bar"],
        ),
    ]
    functions = merge_function_evidence(evidence, ["ghidra", "angr"])
    assert len(functions) == 1
    assert functions[0].address == "0x1000"
    assert functions[0].selected_source == "ghidra"
    # With 5 sources in SOURCE_WEIGHTS (ghidra, rizin, angr, binaryninja, native)
    # 2 sources out of 5 = 0.4 coverage
    assert functions[0].coverage == 0.4


def test_native_clusters_do_not_create_function_addresses():
    evidence = [
        FunctionEvidence(
            address="native:1",
            name="api_resolution",
            source="native",
            confidence=0.6,
        )
    ]
    functions = merge_function_evidence(evidence, ["native"])
    assert functions == []


def test_unknown_address_is_not_merged():
    evidence = [
        FunctionEvidence(address="unknown", name="unknown", source="native"),
        FunctionEvidence(address="0x1000", name="foo", source="ghidra"),
    ]
    functions = merge_function_evidence(evidence, ["ghidra", "native"])
    assert len(functions) == 1
    assert functions[0].address == "0x1000"
