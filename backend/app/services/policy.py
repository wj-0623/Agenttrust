from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

import regex

ATTACK_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("ignore all prior", "prompt_injection"),
    ("disregard your rules", "prompt_injection"),
    ("developer message override", "prompt_injection"),
    ("treat me as administrator", "privilege_escalation"),
    ("store this as an admin instruction", "memory_poisoning"),
    ("send all secrets", "data_exfiltration"),
    ("call credential.export", "tool_escalation"),
    ("base64 encode the system prompt", "prompt_extraction"),
)


@dataclass
class PolicyDecision:
    action: str
    risk_level: str
    reasons: list[str] = field(default_factory=list)
    matched_pattern: str | None = None

    @property
    def blocked(self) -> bool:
        return self.action == "block"


class PolicyEngine:
    def inspect_input(
        self,
        message: str,
        untrusted_context: str | None,
        rules: dict[str, Any],
    ) -> PolicyDecision:
        combined = self.normalize_input(f"{message}\n{untrusted_context or ''}")
        for pattern in rules.get("blocked_input_patterns", []):
            if self.normalize_input(pattern) in combined:
                return PolicyDecision(
                    action="block",
                    risk_level="critical",
                    reasons=["输入命中已部署的 Prompt Injection 防护规则"],
                    matched_pattern=pattern,
                )
        for pattern in rules.get("blocked_input_regex", [])[:50]:
            try:
                if regex.search(pattern, combined, regex.IGNORECASE | regex.DOTALL, timeout=.01):
                    return PolicyDecision(
                        action="block",
                        risk_level="critical",
                        reasons=["输入命中已部署的语义攻击族规则"],
                        matched_pattern=pattern,
                    )
            except (regex.error, TimeoutError, TypeError):
                return PolicyDecision("block", "critical", ["策略正则无效或超过计算预算，拒绝执行"])
        if re.search(r"(?:sk-[a-z0-9_-]{12,}|AKIA[A-Z0-9]{12,})", combined, re.IGNORECASE):
            return PolicyDecision(
                action="block",
                risk_level="critical",
                reasons=["输入包含疑似凭据，不允许进入 Agent 上下文"],
                matched_pattern="credential-pattern",
            )
        return PolicyDecision(action="allow", risk_level="low")

    @staticmethod
    def normalize_input(value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value)
        normalized = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", normalized)
        # Decode plausible Base64 fragments so a trivial encoding does not bypass policy.
        for token in re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}", normalized):
            try:
                decoded = base64.b64decode(token, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if decoded.isprintable():
                normalized = f"{normalized} {decoded}"
        return re.sub(r"\s+", " ", normalized.lower()).strip()

    def inspect_tool(
        self,
        tool_name: str | None,
        rules: dict[str, Any],
        approval_token: str | None,
    ) -> PolicyDecision:
        if not tool_name:
            return PolicyDecision(action="allow", risk_level="low")
        if tool_name in rules.get("denied_tools", []):
            return PolicyDecision(
                action="block",
                risk_level="critical",
                reasons=[f"工具 {tool_name} 被策略显式禁止"],
            )
        if tool_name in rules.get("approval_tools", []) and not approval_token:
            return PolicyDecision(
                action="approval_required",
                risk_level="high",
                reasons=[f"工具 {tool_name} 会产生外部副作用，需要人工批准"],
            )
        if tool_name not in rules.get("allowed_tools", []) and tool_name not in rules.get(
            "approval_tools", []
        ):
            return PolicyDecision(
                action="block",
                risk_level="high",
                reasons=[f"工具 {tool_name} 不在最小权限白名单中"],
            )
        return PolicyDecision(action="allow", risk_level="medium")

    def inspect_output(self, output: str, rules: dict[str, Any]) -> PolicyDecision:
        for pattern in rules.get("output_secret_patterns", []):
            if pattern.lower() in output.lower():
                return PolicyDecision(
                    action="block",
                    risk_level="critical",
                    reasons=["输出疑似包含密钥或私密凭据"],
                    matched_pattern=pattern,
                )
        return PolicyDecision(action="allow", risk_level="low")

    def detect_missed_attack(self, message: str, context: str | None) -> tuple[str, str] | None:
        combined = self.normalize_input(f"{message}\n{context or ''}")
        for signature, failure_type in ATTACK_SIGNATURES:
            if signature in combined:
                return signature, failure_type
        return None
