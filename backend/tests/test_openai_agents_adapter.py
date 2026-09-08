from __future__ import annotations

import json

import httpx
import pytest
from app.integrations.openai_agents import (
    AgentTrustGuardClient,
    GuardApprovalRequired,
    GuardBlocked,
)


def decision(action: str, *, guard_id: str = "guard_demo") -> dict[str, object]:
    return {
        "guard_id": guard_id,
        "action": action,
        "risk_level": "high" if action != "allow" else "low",
        "reasons": ["review required"] if action != "allow" else [],
        "session_labels": ["untrusted_content"] if action != "allow" else [],
    }


@pytest.mark.asyncio
async def test_openai_agents_adapter_guards_tool_and_result() -> None:
    requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        requests.append(payload)
        return httpx.Response(200, json=decision("allow", guard_id=f"guard_{len(requests)}"))

    client = AgentTrustGuardClient(
        base_url="http://127.0.0.1:8010",
        project_id="proj_demo",
        session_id="session_adapter",
        transport=httpx.MockTransport(handler),
    )
    called = False

    @client.guard_async_tool("knowledge.search")
    async def search(query: str, limit: int = 3) -> dict[str, object]:
        nonlocal called
        called = True
        return {"query": query, "limit": limit, "matches": []}

    try:
        assert (await search("safe", limit=2))["limit"] == 2
    finally:
        await client.aclose()
    assert called
    assert [item["phase"] for item in requests] == ["tool", "tool_result"]
    assert requests[1]["parent_guard_ids"] == ["guard_1"]


@pytest.mark.asyncio
async def test_openai_agents_adapter_stops_approval_before_side_effect() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=decision("approval_required"))

    client = AgentTrustGuardClient(
        base_url="http://127.0.0.1:8010",
        project_id="proj_demo",
        session_id="session_approval",
        transport=httpx.MockTransport(handler),
    )
    called = False

    @client.guard_async_tool("email.send")
    async def send(recipient_id: str) -> str:
        nonlocal called
        called = True
        return recipient_id

    try:
        with pytest.raises(GuardApprovalRequired):
            await send("customer_demo")
    finally:
        await client.aclose()
    assert not called


@pytest.mark.asyncio
async def test_openai_agents_adapter_fails_closed_on_transport_error() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    client = AgentTrustGuardClient(
        base_url="http://127.0.0.1:8010",
        project_id="proj_demo",
        session_id="session_offline",
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(GuardBlocked, match="control plane unavailable"):
            await client.check_input("hello")
    finally:
        await client.aclose()


def test_openai_agents_adapter_requires_https_for_remote_control_plane() -> None:
    with pytest.raises(ValueError, match="require HTTPS"):
        AgentTrustGuardClient(
            base_url="http://agenttrust.example.com",
            project_id="proj_demo",
            session_id="session_remote",
        )

