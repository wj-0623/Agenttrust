"""OpenAI Agents SDK example with AgentTrust pre-tool and tool-result guards.

Install ``openai-agents`` separately, start AgentTrust on localhost:8010, set an
OpenAI API key, then run this file with ``backend`` on PYTHONPATH. This example
does not modify or depend on any other portfolio project.
"""

from __future__ import annotations

import asyncio
import os
import uuid

from agents import Agent, Runner, function_tool

from app.integrations.openai_agents import AgentTrustGuardClient


async def main() -> None:
    async with AgentTrustGuardClient(
        base_url=os.getenv("AGENTTRUST_URL", "http://127.0.0.1:8010"),
        project_id=os.getenv("AGENTTRUST_PROJECT_ID", "proj_demo"),
        session_id=f"openai-agents-{uuid.uuid4().hex}",
        api_key=os.getenv("AGENTTRUST_API_KEY"),
    ) as guard:
        @function_tool
        @guard.guard_async_tool("knowledge.search")
        async def knowledge_search(query: str) -> dict[str, object]:
            """Search a small read-only knowledge source."""
            return {"query": query, "matches": ["AgentTrust enforces model-external policy."]}

        prompt = "Explain why model-external authorization matters in one paragraph."
        await guard.check_input(prompt)
        agent = Agent(
            name="Guarded security explainer",
            instructions="Use the knowledge tool and answer concisely.",
            tools=[knowledge_search],
        )
        result = await Runner.run(agent, prompt)
        await guard.check_output(str(result.final_output))
        print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())

