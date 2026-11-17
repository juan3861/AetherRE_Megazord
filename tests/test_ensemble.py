from pathlib import Path

from aether_re.engines.ghidra_parse import parse_decompiled_text
from aether_re.engines.consensus import FunctionEvidence, merge_function_evidence
from aether_re.models import FunctionConsensus, AnalysisReport
from aether_re.engines.comparative_report import compute_source_agreement_matrix


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


def test_single_backend_does_not_receive_source_agreement_credit():
    evidence = [
        FunctionEvidence(
            address="0x1000",
            name="sub_1000",
            source="rizin",
            confidence=0.85,
            quality=0.80,
            coverage=0.90,
        )
    ]

    functions = merge_function_evidence(evidence, ["rizin"])

    assert len(functions) == 1
    assert functions[0].source_agreement == 0.0
    assert functions[0].confidence == 0.5725
    assert any("não há corroboração independente" in warning for warning in functions[0].warnings)


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


def test_comparative_matrix_uses_pair_specific_evidence():
    evidence = [
        FunctionEvidence(address="0x1000", name="foo", source="ghidra", calls=["bar"]),
        FunctionEvidence(address="0x1000", name="foo", source="rizin", calls=["bar"]),
        FunctionEvidence(address="0x1000", name="other", source="angr", calls=["unrelated"]),
    ]
    merged = merge_function_evidence(evidence, ["ghidra", "rizin", "angr"])
    report = AnalysisReport(target="matrix-test", merged_functions=merged)
    matrix = compute_source_agreement_matrix(report)
    assert matrix["ghidra"]["rizin"] > matrix["ghidra"]["angr"]
