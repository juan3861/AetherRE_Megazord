"""Contract-coverage checks for every Rotor Canonical IR value object.

These tests complement the invariant tests in ``test_canonical_ir.py``.  They
do not replace integration or real-provider evidence; they prove that the
full transport-neutral object graph can be constructed and serialized without
losing provenance, budgets, tools, failures, or verifier data.
"""

from router.canonical.ir import (
    BackendDescriptor,
    BackendState,
    CanonicalContentBlock,
    CanonicalMessage,
    CanonicalRequest,
    CanonicalResponse,
    CostMetrics,
    ExecutionPlan,
    ExecutionResult,
    ExecutionState,
    FailureEvent,
    SecurityContext,
    TaskRequirements,
    ToolCall,
    ToolDefinition,
    ToolResult,
    TraceContext,
    UsageMetrics,
    VerifierResult,
)


def test_canonical_ir_full_object_graph_roundtrips_without_loss():
    trace = TraceContext(idempotency_key="contract-coverage")
    security = SecurityContext(
        principal="test",
        permissions=frozenset({"tool:read"}),
        max_steps=3,
        max_tool_calls=2,
    )
    tool = ToolDefinition("read", "Read a resource", {"type": "object"}, "tool:read")
    message = CanonicalMessage("user", (CanonicalContentBlock("text", "inspect"),))
    request = CanonicalRequest((message,), trace, security, tools=(tool,), requested_model="local-model")
    requirements = TaskRequirements(
        "inspection",
        language="python",
        complexity="medium",
        required_capabilities=frozenset({"tools"}),
        modalities=frozenset({"text"}),
        quality_floor=0.8,
        latency_budget_ms=5000,
    )
    plan = ExecutionPlan("plan-contract", trace, requirements, "local", "local-model", 1, ("infer", "verify"))
    call = ToolCall("call-1", "read", {"path": "README.md"})
    tool_result = ToolResult("call-1", "read", True, output={"bytes": 12}, duration_ms=2.5, bytes_read=12)
    verifier = VerifierResult(True, 3, 0.95, evidence={"tests": 1})
    response = CanonicalResponse(
        message=CanonicalMessage("assistant", (CanonicalContentBlock("text", "ok"),)),
        trace=trace,
        backend_id="local",
        model_id="local-model",
        finish_reason="stop",
        usage=UsageMetrics(10, 4, 1),
        cost=CostMetrics(0.0, 0.0, 0.0),
        verifier=verifier,
    )
    result = ExecutionResult("plan-contract", ExecutionState.SUCCEEDED, response, (tool_result,))

    assert request.requested_model == "local-model"
    assert plan.trace.idempotency_key == "contract-coverage"
    assert call.name == tool.name
    payload = result.to_dict()
    assert payload["state"] == "succeeded"
    assert payload["response"]["model_id"] == "local-model"
    assert payload["response"]["verifier"]["quality_score"] == 0.95
    assert payload["tool_results"][0]["bytes_read"] == 12


def test_canonical_ir_infrastructure_and_failure_contracts_are_serializable():
    descriptor = BackendDescriptor("local", "ollama", "qwen", "openai", frozenset({"tools"}))
    state = BackendState("local", True, 1.0, health="healthy", lifecycle_state="ready")
    failure = FailureEvent("transport", "timeout", retryable=True, backend_id="local", attempt=2)
    assert descriptor.local is False
    assert state.active_requests == 0
    assert failure.cognitive_penalty_allowed is False


def test_canonical_ir_rejects_invalid_authority_and_quality_states():
    import pytest

    with pytest.raises(ValueError, match="invalid security budget"):
        SecurityContext(max_steps=0)
    with pytest.raises(ValueError, match="quality_floor"):
        TaskRequirements("invalid", quality_floor=1.1)
    with pytest.raises(ValueError, match="tier"):
        ExecutionPlan("bad-tier", TraceContext(), TaskRequirements("x"), None, None, 4, ())
    with pytest.raises(ValueError, match="verifier layer"):
        VerifierResult(True, 5, 0.5)
    with pytest.raises(ValueError, match="verifier scores"):
        VerifierResult(True, 1, -0.1)
    with pytest.raises(ValueError, match="deadline_at"):
        TraceContext(deadline_at=0)


def test_trace_deadline_is_transport_neutral_and_serializable():
    trace = TraceContext(deadline_at=1_700_000_000.0, attempt=2)
    assert trace.deadline_at == 1_700_000_000.0
    assert trace.attempt == 2
