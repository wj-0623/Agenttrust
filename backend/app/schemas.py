from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)

from .policy_schema import validate_policy


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    description: str = Field(default="", max_length=500)
    adapter: Literal["demo", "openai_compatible", "external_agent"] = "demo"
    endpoint: HttpUrl | None = None
    model: str = Field(default="qwen-plus", min_length=1, max_length=120)
    environment: Literal["development", "staging", "production"] = "development"
    auto_correct: bool = True


class GatewayRequest(BaseModel):
    project_id: str = "proj_demo"
    message: str = Field(min_length=1, max_length=20_000)
    tool_name: str | None = Field(default=None, max_length=120)
    tool_arguments: dict[str, Any] = Field(default_factory=dict)
    untrusted_context: str | None = Field(default=None, max_length=30_000)
    approval_token: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GatewayResponse(BaseModel):
    trace_id: str
    status: Literal["completed", "blocked", "failed", "approval_required"]
    output: str
    blocked: bool
    risk_level: Literal["low", "medium", "high", "critical"]
    score: float
    policy_version: int
    latency_ms: int
    correction_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class GuardCheckRequest(BaseModel):
    """A single enforcement boundary for an embedded Agent."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(default="proj_demo", min_length=2, max_length=160)
    phase: Literal["input", "context", "tool", "tool_result", "output"]
    text: str | None = Field(default=None, max_length=50_000)
    tool_name: str | None = Field(default=None, min_length=2, max_length=120)
    tool_arguments: dict[str, Any] = Field(default_factory=dict)
    source: str = Field(default="application", min_length=2, max_length=120, pattern=r"^[A-Za-z0-9._:-]+$")
    session_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")
    provenance_labels: list[
        Literal[
            "user_controlled",
            "untrusted_content",
            "external_network",
            "sensitive_data",
            "sensitive_source",
        ]
    ] = Field(default_factory=list, max_length=16)
    parent_guard_ids: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("parent_guard_ids")
    @classmethod
    def valid_parent_guard_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if len(value) > 160 or not re.fullmatch(r"[A-Za-z0-9._:-]+", value):
                raise ValueError("parent_guard_ids contain an invalid identifier")
        return list(dict.fromkeys(values))

    @model_validator(mode="after")
    def phase_payload(self) -> GuardCheckRequest:
        if self.phase == "tool":
            if not self.tool_name:
                raise ValueError("tool_name is required for the tool phase")
            if self.text is not None:
                raise ValueError("text is not accepted for the tool phase")
        elif self.phase == "tool_result":
            if not self.tool_name:
                raise ValueError("tool_name is required for the tool_result phase")
            if self.text is None:
                raise ValueError("text is required for the tool_result phase")
            if self.tool_arguments:
                raise ValueError("tool_arguments are not accepted for the tool_result phase")
        elif self.text is None:
            raise ValueError("text is required for input, context and output phases")
        elif self.tool_name is not None or self.tool_arguments:
            raise ValueError("tool fields are accepted only for the tool phase")
        return self


class GuardCheckResponse(BaseModel):
    guard_id: str
    project_id: str
    session_id: str
    phase: Literal["input", "context", "tool", "tool_result", "output"]
    action: Literal["allow", "block", "approval_required"]
    risk_level: Literal["low", "medium", "high", "critical"]
    reasons: list[str] = Field(default_factory=list)
    policy_version: int
    safe_text: str | None = None
    content_sha256: str
    provenance_id: str
    parent_guard_ids: list[str] = Field(default_factory=list)
    session_labels: list[str] = Field(default_factory=list)
    sequence_risk: Literal["none", "untrusted_to_side_effect", "sensitive_to_egress"] = "none"


class EvaluationRequest(BaseModel):
    project_id: str = "proj_demo"
    name: str = "Production readiness regression"
    dataset_id: str = "dataset_core_security_v1"


class EvaluationCase(BaseModel):
    id: str = Field(min_length=2, max_length=120)
    message: str = Field(min_length=1, max_length=20_000)
    context: str | None = Field(default=None, max_length=30_000)
    tool_name: str | None = Field(default=None, max_length=120)
    expected: Literal["allow", "block", "approval_required"]
    category: str = Field(default="custom", min_length=2, max_length=120)


class EvaluationDatasetCreate(BaseModel):
    project_id: str = "proj_demo"
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=500)
    cases: list[EvaluationCase] = Field(min_length=1, max_length=2_000)
    graders: list[Literal["policy_outcome", "attack_recall", "false_positive_rate"]] = Field(
        default_factory=lambda: ["policy_outcome", "attack_recall", "false_positive_rate"]
    )


class RedTeamRequest(BaseModel):
    project_id: str = "proj_demo"
    auto_correct: bool = True
    plugins: list[str] = Field(default_factory=list, max_length=20)
    strategies: list[Literal["direct", "obfuscated", "multilingual", "multi_turn"]] = Field(
        default_factory=lambda: ["direct"]
    )
    max_turns: int = Field(default=3, ge=1, le=8)
    max_cost_usd: float = Field(default=1.0, gt=0, le=100)
    stop_on_block: bool = True
    random_seed: int = Field(default=0, ge=0, le=2_147_483_647)


class CorrectionAction(BaseModel):
    actor: str = "human-reviewer"
    reason: str = Field(default="Reviewed in AgentTrust console", max_length=500)


class CorrectionRollbackAction(BaseModel):
    actor: str = "human-reviewer"
    reason: str = Field(default="Rollback requested from AgentTrust console", max_length=500)


class McpServerCreate(BaseModel):
    project_id: str = "proj_demo"
    name: str = Field(min_length=2, max_length=120)
    endpoint: HttpUrl
    transport: Literal["streamable_http", "sse", "http"] = "streamable_http"
    manifest: dict[str, Any] = Field(default_factory=dict)


class McpManifestUpdate(BaseModel):
    manifest: dict[str, Any]


class McpJsonRpcRequest(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int | None = None
    method: str = Field(min_length=1, max_length=160)
    params: dict[str, Any] = Field(default_factory=dict)


class PolicyUpdate(BaseModel):
    rules: dict[str, Any]
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("rules")
    @classmethod
    def validated_rules(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_policy(value)


class WorkflowCreate(BaseModel):
    project_id: str = "proj_demo"
    idempotency_key: str = Field(min_length=4, max_length=160)
    message: str = Field(min_length=1, max_length=20_000)
    tool_name: str | None = Field(default=None, max_length=120)
    tool_arguments: dict[str, Any] = Field(default_factory=dict)
    untrusted_context: str | None = Field(default=None, max_length=30_000)
    max_retries: int = Field(default=3, ge=0, le=10)


class WorkflowAction(BaseModel):
    actor: str = Field(default="human-reviewer", max_length=120)
    reason: str = Field(default="Approved in durable workflow", max_length=500)


class CapabilityLeaseCreate(BaseModel):
    project_id: str = "proj_demo"
    tool_name: str = Field(min_length=2, max_length=120)
    constraints: dict[str, Any] = Field(default_factory=dict)
    actor: str = Field(default="human-reviewer", max_length=120)
    ttl_seconds: int = Field(default=300, ge=30, le=3600)


class SandboxExecuteRequest(BaseModel):
    project_id: str = "proj_demo"
    tool_name: str = Field(min_length=2, max_length=120)
    arguments: dict[str, Any] = Field(default_factory=dict)
    capability_token: str | None = None
    workflow_id: str | None = None


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)


class WorkspaceCreate(BaseModel):
    organization_id: str
    name: str = Field(min_length=2, max_length=120)


class MembershipCreate(BaseModel):
    workspace_id: str = "ws_demo"
    subject: str = Field(min_length=2, max_length=200)
    display_name: str = Field(min_length=2, max_length=120)
    provider: Literal["local", "oidc"] = "local"
    role: Literal["viewer", "operator", "admin"] = "viewer"


class ApiKeyCreate(BaseModel):
    workspace_id: str = "ws_demo"
    name: str = Field(min_length=2, max_length=120)
    scopes: list[str] = Field(default_factory=lambda: ["gateway:invoke", "read"])
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10_000)
    monthly_budget_usd: float = Field(default=25.0, gt=0, le=1_000_000)


class A2AAgentCreate(BaseModel):
    project_id: str = "proj_demo"
    name: str = Field(min_length=2, max_length=120)
    endpoint: HttpUrl
    agent_card: dict[str, Any]


class A2ACardUpdate(BaseModel):
    agent_card: dict[str, Any]


class A2ATaskCreate(BaseModel):
    project_id: str = "proj_demo"
    target_agent_id: str
    source_agent_id: str | None = None
    message: dict[str, Any]


class A2AJsonRpcRequest(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int | None = None
    method: Literal["message/send", "message/stream", "tasks/get", "tasks/cancel"]
    params: dict[str, Any] = Field(default_factory=dict)


class RefundCreate(BaseModel):
    project_id: str = "proj_demo"
    idempotency_key: str = Field(min_length=8, max_length=160)
    order_id: str = Field(min_length=3, max_length=160)
    customer_id: str = Field(min_length=3, max_length=160)
    amount: float = Field(gt=0, le=1_000_000)
    currency: str = Field(default="CNY", pattern=r"^[A-Z]{3}$")
    reason: str = Field(min_length=2, max_length=2_000)
    evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator("amount", mode="before")
    @classmethod
    def exact_minor_units(cls, value: Any) -> Any:
        try:
            amount = Decimal(str(value))
            if not amount.is_finite() or amount != amount.quantize(Decimal("0.01")):
                raise ValueError("Refund amount must have at most two decimal places")
        except InvalidOperation as exc:
            raise ValueError("Invalid refund amount") from exc
        return value

    @field_validator("currency")
    @classmethod
    def supported_currency(cls, value: str) -> str:
        if value not in {"CNY", "USD", "EUR"}:
            raise ValueError("Personal demo supports only CNY, USD and EUR minor units")
        return value


class RefundAction(BaseModel):
    actor: str = Field(default="refund-reviewer", min_length=2, max_length=120)
    reason: str = Field(default="Approved after order evidence review", min_length=3, max_length=500)


class SecurityControlUpdate(BaseModel):
    enabled: bool
    actor: str = Field(min_length=2, max_length=120)
    reason: str = Field(default="", max_length=1000)


class CorrectionObservationCreate(BaseModel):
    traffic_id: str = Field(min_length=8, max_length=100)
    expected_action: Literal["allow", "block", "approval_required"]
    reason: str = Field(min_length=3, max_length=1000)
