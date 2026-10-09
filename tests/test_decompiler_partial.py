from aether_re.engines.decompiler import merge_decompilation_results
import pytest


def test_partial_ghidra_export_is_not_preferred_or_reported_as_full_confidence():
    partial_function = {
        "address": "0x1000",
        "name": "entry",
        "source": "ghidra",
        "confidence": 0.95,
        "quality": 0.95,
        "coverage": 1.0,
    }

    merged = merge_decompilation_results(
        {
            "ok": True,
            "produced_evidence": True,
            "partial": True,
            "extraction_status": "truncated",
            "truncated": True,
            "attempted_functions": 2,
            "exported_functions": 2,
            "failed_functions": 0,
            "functions": [partial_function],
        },
        None,
        {"pseudo_source": "semantic reconstruction"},
    )

    assert merged["best_source"] == "reconstruct"
    assert merged["partial_sources"] == ["ghidra"]
    assert merged["functions"][0]["confidence"] <= 0.80
    assert merged["functions"][0]["partial"] is True
    assert any("partial" in warning.lower() for warning in merged["functions"][0]["warnings"])


def test_ghidra_without_explicit_complete_summary_is_not_assumed_complete():
    merged = merge_decompilation_results(
        {
            "ok": True,
            "produced_evidence": True,
            "functions": [
                {"address": "0x2000", "name": "unknown", "source": "ghidra", "confidence": 0.95}
            ],
        },
        None,
        {"pseudo_source": "semantic reconstruction"},
    )

    assert merged["best_source"] == "reconstruct"
    assert merged["partial_sources"] == ["ghidra"]


def test_explicitly_complete_ghidra_export_remains_eligible_for_preferred_source():
    merged = merge_decompilation_results(
        {
            "ok": True,
            "produced_evidence": True,
            "partial": False,
            "extraction_status": "complete",
            "truncated": False,
            "failed_functions": 0,
            "timed_out": False,
            "resource_exceeded": False,
            "returncode": 0,
            "attempted_functions": 1,
            "exported_functions": 1,
            "max_functions": 200,
            "functions": [
                {"address": "0x3000", "name": "complete", "source": "ghidra", "confidence": 0.95}
            ],
        },
        None,
        {"pseudo_source": "semantic reconstruction"},
    )

    assert merged["best_source"] == "ghidra"
    assert merged["confidence"] == 0.95
    assert merged["partial"] is False
    assert merged["partial_sources"] == []


def test_complete_flags_without_exit_and_function_counts_are_not_sufficient():
    merged = merge_decompilation_results(
        {
            "ok": True,
            "produced_evidence": True,
            "partial": False,
            "extraction_status": "complete",
            "truncated": False,
            "failed_functions": 0,
            "timed_out": False,
            "resource_exceeded": False,
            "functions": [
                {"address": "0x4000", "name": "unverified", "source": "ghidra", "confidence": 0.95}
            ],
        },
        None,
        {"pseudo_source": "semantic reconstruction"},
    )

    assert merged["best_source"] == "reconstruct"
    assert merged["partial_sources"] == ["ghidra"]
    assert merged["functions"][0]["confidence"] <= 0.80


@pytest.mark.parametrize(
    "override",
    [
        {"ok": False},
        {"returncode": 2},
        {"attempted_functions": 2, "exported_functions": 1},
        {"max_functions": 0},
        {"failed_functions": True},
    ],
)
def test_contradictory_ghidra_completion_summary_fails_closed(override):
    result = {
        "ok": True,
        "produced_evidence": True,
        "partial": False,
        "extraction_status": "complete",
        "truncated": False,
        "failed_functions": 0,
        "timed_out": False,
        "resource_exceeded": False,
        "returncode": 0,
        "attempted_functions": 1,
        "exported_functions": 1,
        "max_functions": 200,
        "functions": [
            {"address": "0x5000", "name": "untrusted-summary", "source": "ghidra", "confidence": 0.95}
        ],
    }
    result.update(override)

    merged = merge_decompilation_results(result, None, {"pseudo_source": "semantic reconstruction"})

    assert merged["best_source"] == "reconstruct"
    assert merged["partial_sources"] == ["ghidra"]
    assert merged["functions"][0]["confidence"] <= 0.80
