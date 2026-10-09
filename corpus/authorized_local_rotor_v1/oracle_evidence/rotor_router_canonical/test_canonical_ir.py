from dataclasses import FrozenInstanceError

import pytest

from router.canonical.ir import (
    CanonicalContentBlock,
    CanonicalMessage,
    CanonicalRequest,
    ExecutionPlan,
    ExecutionResult,
    ExecutionState,
    FailureEvent,
    SecurityContext,
    TaskRequirements,
    TraceContext,
)


def test_trace_and_security_are_validated_and_immutable():
    trace = TraceContext(idempotency_key="same-operation")
    security = SecurityContext(permissions=frozenset({"tool:read"}), max_steps=3, max_tool_calls=1)
    assert security.permits("tool:read")
    with pytest.raises(FrozenInstanceError):
        trace.attempt = 2
    with pytest.raises(ValueError):
        TraceContext(attempt=0)


def test_request_and_plan_carry_context_authority_and_lifecycle():
    trace = TraceContext()
    request = CanonicalRequest(
        messages=(CanonicalMessage("user", (CanonicalContentBlock("text", "status"),)),),
        trace=trace,
        security=SecurityContext(permissions=frozenset({"tool:status"}), max_tool_calls=1),
    )
    reqs = TaskRequirements("tool", required_capabilities=frozenset({"tools"}))
    plan = ExecutionPlan("plan-1", trace, reqs, "local", "model", 1, ("infer", "verify"))
    assert request.trace == plan.trace


def test_tier_zero_does_not_require_llm_but_other_tiers_do():
    reqs = TaskRequirements("deterministic")
    plan = ExecutionPlan("p0", TraceContext(), reqs, None, None, 0, ("resolve", "verify"))
    assert plan.selected_model is None
    with pytest.raises(ValueError):
        ExecutionPlan("p1", TraceContext(), reqs, None, None, 1, ("infer",))


def test_operational_failure_cannot_become_cognitive_penalty():
    assert not FailureEvent("transport", "timeout", True).cognitive_penalty_allowed
    with pytest.raises(ValueError):
        FailureEvent("quota", "429", True, cognitive_penalty_allowed=True)
    assert FailureEvent("semantic", "wrong", False, cognitive_penalty_allowed=True).cognitive_penalty_allowed


def test_execution_result_serializes_enums_and_collections():
    result = ExecutionResult("plan-1", ExecutionState.CANCELLED, failures=(FailureEvent("cancelled", "user", False),))
    data = result.to_dict()
    assert data["state"] == "cancelled"
    assert data["failures"][0]["category"] == "cancelled"
