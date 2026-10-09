import pytest

from aether_re.contracts import adapter_state, validate_adapter_result


def test_adapter_contract_preserves_unavailable_and_terminal_states():
    result = validate_adapter_result("frida", {"available": False, "executed": False, "produced_evidence": False, "partial": False})
    assert result["schema"] == "adapter-result.v1"
    assert result["state"] == "unavailable"
    assert adapter_state({"available": True, "executed": True, "ok": False, "partial": True}) == "partial"


def test_adapter_contract_rejects_fake_success_and_bad_timeout():
    with pytest.raises(ValueError, match="succeeded_state_inconsistent"):
        validate_adapter_result("fake", {"available": True, "executed": False, "produced_evidence": True, "partial": False, "ok": True, "state": "succeeded"})
    with pytest.raises(ValueError, match="timeout_must_be_partial"):
        validate_adapter_result("fake", {"available": True, "executed": True, "produced_evidence": False, "partial": False, "timed_out": True, "state": "timed_out"})
