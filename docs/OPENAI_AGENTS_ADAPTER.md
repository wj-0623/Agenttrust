# OpenAI Agents SDK boundary adapter

AgentTrust provides an async HTTP adapter for OpenAI Agents SDK function tools. It keeps authorization outside the model and checks both the call before execution and the result before it returns to model context.

```python
@function_tool
@guard.guard_async_tool("knowledge.search")
async def knowledge_search(query: str) -> dict[str, object]:
    return await read_only_search(query)
```

The decorator order is intentional: `guard_async_tool` is applied first and preserves the original annotated signature, then `function_tool` exposes the guarded callable to the SDK.

The adapter has four fail-closed properties:

- transport failures and malformed control-plane decisions become `GuardBlocked`;
- `approval_required` stops the function before execution and never becomes a credential;
- tool results are inspected before returning to model context;
- remote control planes require HTTPS, while HTTP is allowed only on loopback.

Side-effecting tools should remain registered in AgentTrust's trusted runner and execute only with a parameter-bound, one-time Capability Lease or durable workflow. The framework adapter is an enforcement hook, not a substitute for that execution boundary.

Run [the example](../examples/openai_agents_guarded_tool.py) after starting AgentTrust. The optional `openai-agents` dependency is deliberately excluded from the default runtime so the local deterministic demo and CI do not require an API key.

The integration follows the official OpenAI recommendation to use custom function tools for domain-specific side effects while keeping tool descriptions explicit about side effects and error behavior: <https://developers.openai.com/api/docs/guides/latest-model>.

