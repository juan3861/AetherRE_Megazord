from aether_re.models import FunctionEvidence


def test_adapter_mapping_preserves_unmodeled_fields_in_raw_evidence():
    item = {
        "address": "0x401000", "name": "sample", "source": "angr",
        "confidence": 0.82, "calls": ["0x401020"], "unresolved_call_sites": 2,
        "raw": {"blocks": [{"address": "0x401000", "size": 8}]},
    }
    evidence = FunctionEvidence.from_mapping(item)
    assert evidence.address == "0x401000"
    assert evidence.calls == ["0x401020"]
    assert evidence.raw["blocks"][0]["size"] == 8
    assert evidence.raw["adapter_extra_fields"] == {"unresolved_call_sites": 2}
