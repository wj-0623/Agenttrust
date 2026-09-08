from __future__ import annotations

import functools
import inspect
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, ParamSpec, Self, TypeVar
from urllib.parse import urlsplit

import httpx

P = ParamSpec("P")
R = TypeVar("R")


@dataclass(frozen=True)
class GuardDecision:
    guard_id: str
    action: str
    risk_level: str
    reasons: tuple[str, ...]
    session_labels: tuple[str, ...]

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> GuardDecision:
        return cls(
            guard_id=str(payload["guard_id"]),
            action=str(payload["action"]),
            risk_level=str(payload["risk_level"]),
            reasons=tuple(str(item) for item in payload.get("reasons", [])),
            session_labels=tuple(str(item) for item in payload.get("session_labels", [])),
        )


class GuardRejected(RuntimeError):
    """Raised before guarded data can cross a denied Agent boundary."""

    def __init__(self, decision: GuardDecision):
        self.decision = decision
        super().__init__("; ".join(decision.reasons) or f"AgentTrust returned {decision.action}")


class GuardBlocked(GuardRejected):
    """The policy denied this boundary."""


class GuardApprovalRequired(GuardRejected):
    """A human decision and separately bound capability are required."""


class AgentTrustGuardClient:
    """Async boundary adapter for OpenAI Agents SDK function tools.

    Apply ``guard_async_tool`` below ``agents.function_tool`` so the SDK sees the
    original annotated signature. The adapter fails closed on transport errors,
    oversized tool results, policy blocks, and approval requirements. It never
    converts an approval response into an execution credential.
    """

    _MAX_GUARDED_TEXT = 50_000

    def __init__(
        self,
        *,
        base_url: str,
        project_id: str,
        session_id: str,
        api_key: str | None = None,
        timeout_seconds: float = 3.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.project_id = project_id
        self.session_id = session_id
        self._validate_control_plane_url(self.base_url)
        headers = {"X-API-Key": api_key} if api_key else {}
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def check_input(self, text: str, *, source: str = "openai_agents.user") -> GuardDecision:
        return await self._check("input", text=text, source=source)

    async def check_context(self, text: str, *, source: str = "openai_agents.context") -> GuardDecision:
        return await self._check("context", text=text, source=source)

    async def check_output(self, text: str, *, source: str = "openai_agents.output") -> GuardDecision:
        return await self._check("output", text=text, source=source)

    def guard_async_tool(
        self,
        tool_name: str,
        *,
        source: str = "openai_agents.function_tool",
    ) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
        """Guard an async function before execution and before its result reaches the model."""

        def decorator(function: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
            signature = inspect.signature(function)

            @functools.wraps(function)
            async def guarded(*args: P.args, **kwargs: P.kwargs) -> R:
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                arguments = dict(bound.arguments)
                before = await self._check(
                    "tool",
                    tool_name=tool_name,
                    tool_arguments=arguments,
                    source=source,
                )
                result = await function(*args, **kwargs)
                serialized = self._serialize_result(result)
                await self._check(
                    "tool_result",
                    text=serialized,
                    tool_name=tool_name,
                    source=source,
                    parent_guard_ids=[before.guard_id],
                )
                return result

            return guarded

        return decorator

    async def _check(
        self,
        phase: str,
        *,
        text: str | None = None,
        tool_name: str | None = None,
        tool_arguments: dict[str, Any] | None = None,
        source: str,
        parent_guard_ids: list[str] | None = None,
    ) -> GuardDecision:
        payload = {
            "project_id": self.project_id,
            "session_id": self.session_id,
            "phase": phase,
            "text": text,
            "tool_name": tool_name,
            "tool_arguments": tool_arguments or {},
            "source": source,
            "parent_guard_ids": parent_guard_ids or [],
        }
        try:
            response = await self._client.post("/api/v1/guard/check", json=payload)
            response.raise_for_status()
            decision = GuardDecision.from_payload(response.json())
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            raise GuardBlocked(
                GuardDecision(
                    guard_id="unavailable",
                    action="block",
                    risk_level="critical",
                    reasons=("AgentTrust control plane unavailable or returned an invalid decision",),
                    session_labels=(),
                )
            ) from exc
        if decision.action == "block":
            raise GuardBlocked(decision)
        if decision.action == "approval_required":
            raise GuardApprovalRequired(decision)
        if decision.action != "allow":
            raise GuardBlocked(
                GuardDecision(
                    guard_id=decision.guard_id,
                    action="block",
                    risk_level="critical",
                    reasons=("AgentTrust returned an unknown decision",),
                    session_labels=decision.session_labels,
                )
            )
        return decision

    @classmethod
    def _serialize_result(cls, result: Any) -> str:
        try:
            text = json.dumps(result, ensure_ascii=False, sort_keys=True, default=str)
        except (TypeError, ValueError) as exc:
            raise GuardBlocked(
                GuardDecision(
                    guard_id="local-serialization",
                    action="block",
                    risk_level="high",
                    reasons=("Tool result could not be serialized for policy inspection",),
                    session_labels=(),
                )
            ) from exc
        if len(text) > cls._MAX_GUARDED_TEXT:
            raise GuardBlocked(
                GuardDecision(
                    guard_id="local-size-limit",
                    action="block",
                    risk_level="high",
                    reasons=("Tool result exceeds the guarded boundary size limit",),
                    session_labels=(),
                )
            )
        return text

    @staticmethod
    def _validate_control_plane_url(base_url: str) -> None:
        parsed = urlsplit(base_url)
        is_loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("AgentTrust base_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("AgentTrust base_url must not contain credentials, query, or fragment")
        if parsed.scheme != "https" and not is_loopback:
            raise ValueError("Remote AgentTrust control planes require HTTPS")
