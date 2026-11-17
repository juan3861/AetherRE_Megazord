from aether_re.adapters.rizin import RizinAdapter


def test_rizin_function_metrics_are_not_fabricated_as_calibrated_values():
    functions = RizinAdapter()._parse_functions(
        '[{"offset":4096,"name":"sym.main","size":32,"type":"fcn","nbbs":4,"edges":3}]'
    )

    assert len(functions) == 1
    function = functions[0]
    assert function["confidence"] == 0.5
    assert function["quality"] == 0.5
    assert function["coverage"] == 0.0
    assert "rizin_confidence_uncalibrated" in function["warnings"]
    assert "rizin_function_coverage_not_measured" in function["warnings"]
    assert function["raw"]["metric_status"] == {
        "confidence": "unmeasured_default",
        "quality": "unmeasured_default",
        "coverage": "not_measured",
    }
