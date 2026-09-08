from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import settings
from .network_security import read_limited_json, validate_outbound_destination


@dataclass
class AgentResult:
    output: str
    tool_calls: list[dict[str, Any]]
    tokens: int
    cost_usd: float
    latency_ms: int
    runtime_metadata: dict[str, Any] = field(default_factory=dict)


class AgentRuntime:
    """Executes a demo, model endpoint, or explicitly allowlisted external Agent."""

    async def invoke(
        self,
        project: dict[str, Any],
        message: str,
        tool_name: str | None,
        tool_arguments: dict[str, Any],
        untrusted_context: str | None,
        policy: dict[str, Any],
        api_key: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AgentResult:
        if project["adapter"] == "openai_compatible":
            return await self._invoke_openai_compatible(
                project, message, untrusted_context, policy, api_key
            )
        if project["adapter"] == "external_agent":
            return await self._invoke_external_agent(
                project, message, untrusted_context, policy, metadata or {}
            )
        if project["adapter"] == "demo":
            return self._invoke_demo(message, tool_name, tool_arguments, untrusted_context)
        raise ValueError("Unsupported Agent adapter")

    async def _invoke_external_agent(
        self,
        project: dict[str, Any],
        message: str,
        untrusted_context: str | None,
        policy: dict[str, Any],
        metadata: dict[str, Any],
    ) -> AgentResult:
        """Call a compatible external Agent chat contract through a fixed destination.

        This outer adapter observes upstream tool reports after execution. It is
        sufficient for the current read-only Skill demo, but cannot authorize a
        future side effect; those tools must call AgentTrust before execution.
        """
        if not project.get("endpoint"):
            raise ValueError("External Agent project requires an endpoint")
        endpoint = str(project["endpoint"]).rstrip("/")
        if endpoint not in settings.external_agent_endpoint_allowlist:
            raise ValueError("External Agent endpoint is not deployment-approved")
        if settings.environment == "production":
            if not endpoint.startswith("https://"):
                raise ValueError("Production external Agent endpoints must use HTTPS")
            if not settings.external_agent_bearer_token:
                raise ValueError("Production external Agent calls require a bearer token")
        validate_outbound_destination(
            endpoint, allow_development_loopback=settings.environment == "development"
        )
        session_id = str(metadata.get("session_id") or "agenttrust")[:100]
        guarded_message = message
        if untrusted_context:
            guarded_message += f"\n\n<untrusted_context>\n{untrusted_context}\n</untrusted_context>"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Demo-User": f"agenttrust-{project['id']}",
            "X-AgentTrust-Project": str(project["id"]),
        }
        if settings.external_agent_bearer_token:
            headers["Authorization"] = f"Bearer {settings.external_agent_bearer_token}"
        started = time.perf_counter()
        async with httpx.AsyncClient(
            timeout=45, trust_env=False, follow_redirects=False
        ) as client, client.stream(
            "POST",
            endpoint,
            headers=headers,
            json={"message": guarded_message, "thread_id": session_id},
        ) as response:
            response.raise_for_status()
            data = await read_limited_json(response, settings.max_upstream_response_bytes)
        answer = data.get("answer")
        if not isinstance(answer, str):
            raise TypeError("External Agent response must contain a string answer")
        if len(answer) > max(1024, int(policy.get("max_output_tokens", 1024)) * 8):
            raise ValueError("External Agent answer exceeds the configured output budget")
        raw_calls = data.get("tool_calls", [])
        if not isinstance(raw_calls, list) or len(raw_calls) > 64:
            raise ValueError("External Agent returned an invalid tool call list")
        tool_calls: list[dict[str, Any]] = []
        for raw in raw_calls:
            if not isinstance(raw, dict):
                raise TypeError("External Agent tool calls must be objects")
            skill, action = raw.get("skill"), raw.get("action")
            risk, status = raw.get("risk"), raw.get("status")
            if not all(
                isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value)
                for value in (skill, action)
            ):
                raise ValueError("External Agent returned an invalid Skill identity")
            if risk not in {"low", "medium", "high", "critical"} or status not in {
                "planned", "awaiting_confirmation", "executed", "rejected"
            }:
                raise ValueError("External Agent returned invalid tool safety metadata")
            if status == "executed" and risk != "low":
                raise ValueError(
                    "External Agent reported an executed side effect without pre-execution governance"
                )
            tool_calls.append(
                {
                    "name": f"{skill}.{action}",
                    "arguments": {
                        "source": "external_agent",
                        "risk": risk,
                        "upstream_status": status,
                    },
                    "status": status,
                }
            )
        trace_id = data.get("trace_id")
        safe_trace_id = trace_id[:160] if isinstance(trace_id, str) else None
        return AgentResult(
            output=answer,
            tool_calls=tool_calls,
            tokens=0,
            cost_usd=0.0,
            latency_ms=int((time.perf_counter() - started) * 1000),
            runtime_metadata={
                "adapter": "external_agent",
                "upstream_trace_id": safe_trace_id,
                "usage_reported": False,
                "cost_reported": False,
                "side_effect_boundary": "post_execution_observation_only",
            },
        )

    def _invoke_demo(
        self,
        message: str,
        tool_name: str | None,
        tool_arguments: dict[str, Any],
        untrusted_context: str | None,
    ) -> AgentResult:
        started = time.perf_counter()
        lowered = message.lower()
        if tool_name:
            output = f"已安全调用 {tool_name}，参数摘要：{tool_arguments or '无参数'}。"
            tool_calls = [{"name": tool_name, "arguments": tool_arguments, "status": "proposed"}]
        elif "退款" in message or "refund" in lowered:
            output = "我可以核对订单与退款规则；涉及实际退款时会请求人工批准。"
            tool_calls = []
        elif "状态" in message or "status" in lowered:
            output = "服务运行正常。过去一小时没有发现需要升级处理的事件。"
            tool_calls = []
        elif untrusted_context:
            # Deliberately naïve demo behavior: AgentTrust must catch missed indirect attacks.
            output = "我已读取外部上下文并据此完成任务。"
            tool_calls = []
        else:
            output = f"已完成请求：{message[:180]}"
            tool_calls = []
        latency_ms = max(12, int((time.perf_counter() - started) * 1000) + 18)
        tokens = max(24, (len(message) + len(output)) // 3)
        return AgentResult(
            output=output,
            tool_calls=tool_calls,
            tokens=tokens,
            cost_usd=round(tokens * 0.000002, 6),
            latency_ms=latency_ms,
        )

    async def _invoke_openai_compatible(
        self,
        project: dict[str, Any],
        message: str,
        untrusted_context: str | None,
        policy: dict[str, Any],
        api_key: str | None,
    ) -> AgentResult:
        if not project.get("endpoint"):
            raise ValueError("OpenAI-compatible project requires an endpoint")
        if not api_key:
            raise ValueError("Model API key is not configured")
        endpoint = project["endpoint"].rstrip("/")
        # A tenant-controlled project must never choose the recipient of a platform key.
        if endpoint not in settings.model_endpoint_allowlist:
            raise ValueError("Model endpoint is not deployment-approved for shared credentials")
        if settings.environment == "production" and not endpoint.startswith("https://"):
            raise ValueError("Production model endpoints must use HTTPS")
        validate_outbound_destination(endpoint)
        started = time.perf_counter()
        guarded_user = message
        if untrusted_context:
            guarded_user += f"\n\n<untrusted_context>\n{untrusted_context}\n</untrusted_context>"
        input_rate = settings.model_input_usd_per_million
        output_rate = settings.model_output_usd_per_million
        if any(not math.isfinite(rate) or rate < 0 for rate in (input_rate, output_rate)):
            raise ValueError("Configure model prices before enabling paid model calls")
        max_output_tokens = int(policy.get("max_output_tokens", 1024))
        # Conservative estimate for this text-only request, including framing.
        input_bound = len((guarded_user + policy.get("prompt_guard_suffix", "")).encode("utf-8")) + 1024
        reserved_cost = (input_bound * input_rate + max_output_tokens * output_rate) / 1_000_000
        if reserved_cost > float(policy.get("max_cost_usd", .25)):
            raise ValueError("Model request exceeds configured cost budget")
        payload = {
            "model": project["model"],
            "messages": [
                {"role": "system", "content": policy.get("prompt_guard_suffix", "")},
                {"role": "user", "content": guarded_user},
            ],
            "temperature": 0.1,
            "max_tokens": max_output_tokens,
        }
        async with httpx.AsyncClient(timeout=45, trust_env=False, follow_redirects=False) as client, client.stream(
                "POST", f"{endpoint}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json=payload,
        ) as response:
            response.raise_for_status()
            data = await read_limited_json(response, settings.max_upstream_response_bytes)
        usage = data.get("usage", {})
        prompt_tokens = int(usage.get("prompt_tokens", input_bound))
        completion_tokens = int(usage.get("completion_tokens", max_output_tokens))
        if prompt_tokens < 0 or completion_tokens < 0:
            raise ValueError("Invalid upstream token usage")
        tokens = prompt_tokens + completion_tokens
        return AgentResult(
            output=data["choices"][0]["message"].get("content") or "",
            tool_calls=data["choices"][0]["message"].get("tool_calls", []),
            tokens=tokens,
            cost_usd=(prompt_tokens * input_rate + completion_tokens * output_rate) / 1_000_000,
            latency_ms=int((time.perf_counter() - started) * 1000),
        )
