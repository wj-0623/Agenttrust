"""Validated policy configuration; invalid stored rules fail closed at runtime."""
from __future__ import annotations

from typing import Annotated, Any

import regex
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Pattern = Annotated[str, Field(min_length=1, max_length=512)]


class StrictConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class CorrectionRules(StrictConfig):
    enabled: bool = True
    min_confidence: float = Field(default=.8, ge=0, le=1)
    min_improvement: float = Field(default=.08, ge=0, le=1)
    min_replay_pass_rate: float = Field(default=.8, ge=0, le=1)
    min_attack_recall: float = Field(default=.95, ge=0, le=1)
    max_false_positive_rate: float = Field(default=.02, ge=0, le=1)
    min_eval_cases: int = Field(default=24, ge=1, le=100000)
    min_wilson_lower_bound: float = Field(default=.8, ge=0, le=1)
    required_consecutive_shadow_passes: int = Field(default=2, ge=1, le=100)


class McpRules(StrictConfig):
    block_tool_manifest_changes: bool = True
    minimum_trust_score: float = Field(default=.7, ge=0, le=1)
    allowed_methods: list[Pattern] = Field(default_factory=list, max_length=50)


class PolicyRules(StrictConfig):
    blocked_input_patterns: list[Pattern] = Field(max_length=200)
    blocked_input_regex: list[Pattern] = Field(default_factory=list, max_length=50)
    denied_tools: list[Pattern] = Field(max_length=200)
    approval_tools: list[Pattern] = Field(max_length=200)
    allowed_tools: list[Pattern] = Field(max_length=200)
    output_secret_patterns: list[Pattern] = Field(max_length=200)
    max_tool_calls: int = Field(default=6, ge=1, le=100)
    max_cost_usd: float = Field(default=.25, gt=0, le=100)
    max_output_tokens: int = Field(default=1024, ge=1, le=32768)
    prompt_guard_suffix: str = Field(default="", max_length=10000)
    auto_correction: CorrectionRules = Field(default_factory=CorrectionRules)
    mcp: McpRules = Field(default_factory=McpRules)

    @field_validator("blocked_input_regex")
    @classmethod
    def valid_regex(cls, patterns: list[str]) -> list[str]:
        for pattern in patterns:
            try:
                regex.compile(pattern)
            except regex.error as exc:
                raise ValueError("Invalid policy regular expression") from exc
        return patterns

    @model_validator(mode="after")
    def disjoint_tools(self) -> PolicyRules:
        # Explicit deny may override older allow/approval entries, but approval
        # must never also be represented as an unconditional allow.
        if set(self.allowed_tools) & set(self.approval_tools):
            raise ValueError("A tool cannot be both allowed and approval-required")
        return self


def validate_policy(rules: dict[str, Any]) -> dict[str, Any]:
    return PolicyRules.model_validate(rules).model_dump()
