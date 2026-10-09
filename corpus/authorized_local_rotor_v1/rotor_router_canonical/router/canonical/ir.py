"""ROTOR Canonical IR v1.

Transport-neutral contracts. The orchestrator owns lifecycle; the Cognitive
Router owns decisions; Bridge, Browser and Tools only execute explicit plans.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from enum import Enum, StrEnum
from typing import Any, Literal
from uuid import uuid4

JSON = dict[str, Any]


class ExecutionState(StrEnum):
    CREATED = "created"
    PLANNED = "planned"
    RUNNING = "running"
    WAITING_TOOL = "waiting_tool"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RECOVERING = "recovering"


@dataclass(frozen=True, slots=True)
class TraceContext:
    trace_id: str = field(default_factory=lambda: uuid4().hex)
    request_id: str = field(default_factory=lambda: uuid4().hex)
    parent_span_id: str | None = None
    attempt: int = 1
    idempotency_key: str | None = None
    deadline_at: float | None = None

    def __post_init__(self) -> None:
        if self.attempt < 1:
            raise ValueError("attempt must be >= 1")
        if self.deadline_at is not None and (
            not math.isfinite(float(self.deadline_at)) or self.deadline_at <= 0
        ):
            raise ValueError("deadline_at must be a positive finite timestamp")


@dataclass(frozen=True, slots=True)
class SecurityContext:
    principal: str = "anonymous"
    permissions: frozenset[str] = field(default_factory=frozenset)
    risk_level: Literal["low", "medium", "high", "critical"] = "low"
    max_cost_usd: float = 0.0
    max_steps: int = 1
    max_tool_calls: int = 0
    max_tool_seconds: float = 60.0
    requires_human_approval: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.max_steps, int)
            or isinstance(self.max_steps, bool)
            or self.max_steps < 1
            or not isinstance(self.max_tool_calls, int)
            or isinstance(self.max_tool_calls, bool)
            or self.max_tool_calls < 0
            or not math.isfinite(float(self.max_cost_usd))
            or self.max_cost_usd < 0
            or not math.isfinite(float(self.max_tool_seconds))
            or self.max_tool_seconds <= 0
        ):
            raise ValueError("invalid security budget")

    def permits(self, permission: str) -> bool:
        return permission in self.permissions


@dataclass(frozen=True, slots=True)
class CanonicalContentBlock:
    type: Literal["text", "image", "audio", "document", "tool_call", "tool_result"]
    data: Any
    mime_type: str | None = None
    metadata: JSON = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CanonicalMessage:
    role: Literal["system", "user", "assistant", "tool"]
    content: tuple[CanonicalContentBlock, ...]
    name: str | None = None


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: JSON
    required_permission: str
    risk_level: Literal["low", "medium", "high", "critical"] = "medium"
    version: str = "1"


@dataclass(frozen=True, slots=True)
class ToolCall:
    call_id: str
    name: str
    arguments: JSON


@dataclass(frozen=True, slots=True)
class ToolResult:
    call_id: str
    name: str
    success: bool
    output: Any = None
    error: str | None = None
    duration_ms: float = 0.0
    bytes_read: int = 0
    bytes_written: int = 0


@dataclass(frozen=True, slots=True)
class TaskRequirements:
    task_type: str
    language: str = "und"
    complexity: Literal["low", "medium", "high"] = "low"
    required_capabilities: frozenset[str] = field(default_factory=frozenset)
    modalities: frozenset[str] = field(default_factory=lambda: frozenset({"text"}))
    quality_floor: float = 0.0
    latency_budget_ms: int | None = None

    def __post_init__(self) -> None:
        if not 0 <= self.quality_floor <= 1:
            raise ValueError("quality_floor must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class BackendDescriptor:
    backend_id: str
    provider_id: str
    model_id: str
    protocol: str
    capabilities: frozenset[str] = field(default_factory=frozenset)
    modalities: frozenset[str] = field(default_factory=lambda: frozenset({"text"}))
    local: bool = False


@dataclass(frozen=True, slots=True)
class BackendState:
    backend_id: str
    available: bool
    observed_at: float
    health: Literal["unknown", "healthy", "degraded", "unavailable"] = "unknown"
    lifecycle_state: str = "unloaded"
    cooldown_until: float | None = None
    active_requests: int = 0


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    plan_id: str
    trace: TraceContext
    requirements: TaskRequirements
    selected_backend: str | None
    selected_model: str | None
    tier: int
    steps: tuple[str, ...]
    fallback_backends: tuple[str, ...] = ()
    state: ExecutionState = ExecutionState.PLANNED
    decision_reason: str = ""

    def __post_init__(self) -> None:
        if self.tier not in (0, 1, 2, 3):
            raise ValueError("tier must be 0..3")
        if self.tier > 0 and (not self.selected_backend or not self.selected_model):
            raise ValueError("non-deterministic plans require backend and model")


@dataclass(frozen=True, slots=True)
class UsageMetrics:
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0


@dataclass(frozen=True, slots=True)
class CostMetrics:
    estimated_usd: float = 0.0
    actual_usd: float = 0.0
    avoidable_usd: float = 0.0


@dataclass(frozen=True, slots=True)
class FailureEvent:
    category: Literal[
        "transport",
        "auth",
        "quota",
        "syntax",
        "semantic",
        "policy",
        "security",
        "cancelled",
        "resource_pressure",
        "unknown",
    ]
    message: str
    retryable: bool
    cognitive_penalty_allowed: bool = False
    backend_id: str | None = None
    attempt: int = 1

    def __post_init__(self) -> None:
        if self.category in {"transport", "auth", "quota", "resource_pressure"} and self.cognitive_penalty_allowed:
            raise ValueError("operational failures cannot automatically penalize competence")


@dataclass(frozen=True, slots=True)
class VerifierResult:
    passed: bool
    layer: int
    quality_score: float
    risk_score: float = 0.0
    errors: tuple[str, ...] = ()
    evidence: JSON = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.layer not in (0, 1, 2, 3, 4):
            raise ValueError("verifier layer must be 0..4")
        if not 0 <= self.quality_score <= 1 or not 0 <= self.risk_score <= 1:
            raise ValueError("verifier scores must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class CanonicalRequest:
    messages: tuple[CanonicalMessage, ...]
    trace: TraceContext
    security: SecurityContext
    tools: tuple[ToolDefinition, ...] = ()
    requested_model: str | None = None
    stream: bool = False
    metadata: JSON = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CanonicalResponse:
    message: CanonicalMessage
    trace: TraceContext
    backend_id: str | None
    model_id: str | None
    finish_reason: str
    usage: UsageMetrics = field(default_factory=UsageMetrics)
    cost: CostMetrics = field(default_factory=CostMetrics)
    verifier: VerifierResult | None = None
    metadata: JSON = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    plan_id: str
    state: ExecutionState
    response: CanonicalResponse | None = None
    tool_results: tuple[ToolResult, ...] = ()
    failures: tuple[FailureEvent, ...] = ()
    checkpoint_id: str | None = None

    def to_dict(self) -> JSON:
        def encode(value: Any) -> Any:
            if isinstance(value, Enum):
                return value.value
            if isinstance(value, (frozenset, set, tuple)):
                return [encode(v) for v in value]
            if hasattr(value, "__dataclass_fields__"):
                return {k: encode(v) for k, v in asdict(value).items()}
            if isinstance(value, dict):
                return {k: encode(v) for k, v in value.items()}
            if isinstance(value, list):
                return [encode(v) for v in value]
            return value

        return encode(self)
