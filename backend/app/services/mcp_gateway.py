from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import httpx
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from ..config import settings
from ..db import Database, new_id, utc_now
from .network_security import (
    UnsafeOutboundDestination,
    read_limited_json,
    validate_http_endpoint,
    validate_outbound_destination,
)
from .policy import PolicyEngine
from .sandbox import SandboxService, SandboxViolation

POISON_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"ignore.{0,30}(instruction|policy|rule)", "MCP_TOOL_PROMPT_INJECTION"),
    (r"(reveal|export|send).{0,30}(secret|credential|system prompt)", "MCP_TOOL_EXFILTRATION"),
    (r"do not (tell|show|inform).{0,20}(user|operator)", "MCP_HIDDEN_BEHAVIOR"),
    (r"override.{0,20}(approval|permission|authorization)", "MCP_APPROVAL_BYPASS"),
)

DANGEROUS_TOOL_HINTS = ("delete", "exec", "shell", "credential", "payment", "send", "write")


class McpSecurityError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 403, findings: list[dict[str, Any]] | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.findings = findings or []


class McpGatewayService:
    """MCP control point: manifest pinning, policy enforcement and JSON-RPC forwarding."""

    def __init__(self, db: Database, policy_engine: PolicyEngine, sandbox: SandboxService):
        self.db = db
        self.policy_engine = policy_engine
        self.sandbox = sandbox

    @staticmethod
    def canonical_hash(manifest: dict[str, Any]) -> str:
        payload = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def tools_from_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
        tools = manifest.get("tools", [])
        if not tools and isinstance(manifest.get("result"), dict):
            tools = manifest["result"].get("tools", [])
        return [tool for tool in tools if isinstance(tool, dict) and isinstance(tool.get("name"), str)]

    def scan_manifest(self, manifest: dict[str, Any]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        tools = self.tools_from_manifest(manifest)
        seen: set[str] = set()
        for tool in tools:
            name = tool["name"]
            description = str(tool.get("description", ""))
            if name in seen:
                findings.append(self._finding("high", "MCP_DUPLICATE_TOOL", name, "工具名称重复，可能发生 Tool Shadowing"))
            seen.add(name)
            for pattern, code in POISON_PATTERNS:
                if re.search(pattern, description, re.IGNORECASE | re.DOTALL):
                    findings.append(self._finding("critical", code, name, "工具描述包含面向模型的隐藏或越权指令"))
            if any(hint in name.lower() for hint in DANGEROUS_TOOL_HINTS):
                findings.append(self._finding("medium", "MCP_HIGH_IMPACT_TOOL", name, "工具可能产生外部副作用，应绑定审批或拒绝策略"))
            schema = tool.get("inputSchema", {})
            if not isinstance(schema, dict) or schema.get("type", "object") != "object":
                findings.append(self._finding("high", "MCP_INVALID_SCHEMA", name, "工具输入 Schema 不是有效 object"))
            elif schema.get("additionalProperties") is True and not schema.get("properties"):
                findings.append(self._finding("medium", "MCP_UNBOUNDED_ARGUMENTS", name, "工具允许任意参数且没有声明字段"))
        penalties = {"critical": 0.45, "high": 0.25, "medium": 0.08, "low": 0.02}
        trust_score = max(0.0, 1.0 - sum(penalties[item["severity"]] for item in findings))
        blocking = any(item["severity"] in {"critical", "high"} for item in findings)
        return {
            "tools_total": len(tools),
            "trust_score": round(trust_score, 4),
            "blocking": blocking,
            "findings": findings,
        }

    def register(self, project_id: str, name: str, endpoint: str, transport: str, manifest: dict[str, Any]) -> dict[str, Any]:
        if not self.db.query_one("SELECT id FROM projects WHERE id = ?", (project_id,)):
            raise KeyError(project_id)
        self._validate_endpoint(endpoint)
        scan = self.scan_manifest(manifest)
        server_id = new_id("mcp")
        manifest_hash = self.canonical_hash(manifest)
        now = utc_now()
        status = "quarantined" if scan["blocking"] else "active"
        self.db.execute(
            """
            INSERT INTO mcp_servers
            (id, project_id, name, endpoint, transport, status, trust_score, manifest_hash,
             manifest_json, findings_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (server_id, project_id, name, endpoint, transport, status, scan["trust_score"], manifest_hash,
             json.dumps(manifest, ensure_ascii=False), json.dumps(scan["findings"], ensure_ascii=False), now, now),
        )
        self._snapshot(server_id, manifest_hash, manifest, {"initial": True}, scan["findings"])
        self.db.audit(project_id, "mcp.server_registered", f"注册 MCP Server {name}，状态 {status}", {
            "server_id": server_id, "manifest_hash": manifest_hash, "trust_score": scan["trust_score"]
        })
        return self.get_server(server_id)

    def update_manifest(self, server_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        server = self._raw_server(server_id)
        previous = json.loads(server["manifest_json"])
        old_hash = server["manifest_hash"]
        new_hash = self.canonical_hash(manifest)
        scan = self.scan_manifest(manifest)
        diff = self._manifest_diff(previous, manifest)
        rug_pull = old_hash != new_hash and bool(diff["security_relevant_changes"])
        findings = list(scan["findings"])
        if rug_pull:
            findings.append(self._finding("critical", "MCP_MANIFEST_RUG_PULL", "*", "已固定的工具描述或 Schema 在运行期发生变化"))
        policy = self.db.active_policy(server["project_id"])
        block_changes = bool(policy.get("mcp", {}).get("block_tool_manifest_changes", True))
        status = "quarantined" if scan["blocking"] or (rug_pull and block_changes) else "active"
        trust_score = max(0.0, float(scan["trust_score"]) - (0.35 if rug_pull else 0.0))
        self.db.execute(
            """
            UPDATE mcp_servers SET status = ?, trust_score = ?, manifest_hash = ?, manifest_json = ?,
            findings_json = ?, updated_at = ? WHERE id = ?
            """,
            (status, trust_score, new_hash, json.dumps(manifest, ensure_ascii=False),
             json.dumps(findings, ensure_ascii=False), utc_now(), server_id),
        )
        self._snapshot(server_id, new_hash, manifest, diff, findings)
        self.db.audit(server["project_id"], "mcp.manifest_changed", f"MCP 清单更新，状态 {status}", {
            "server_id": server_id, "old_hash": old_hash, "new_hash": new_hash, "diff": diff
        })
        return self.get_server(server_id)

    def list_servers(self, project_id: str) -> list[dict[str, Any]]:
        return [self._decode_server(row) for row in self.db.query_all(
            "SELECT * FROM mcp_servers WHERE project_id = ? ORDER BY created_at DESC", (project_id,)
        )]

    def get_server(self, server_id: str) -> dict[str, Any]:
        return self._decode_server(self._raw_server(server_id))

    async def proxy(self, server_id: str, payload: dict[str, Any], approval_token: str | None = None) -> dict[str, Any]:
        from .dlp import DLPService
        server = self._raw_server(server_id)
        from .security_response import SecurityResponseService
        SecurityResponseService(self.db).assert_runtime_enabled(server["project_id"])
        dlp = DLPService(self.db)
        scan = dlp.inspect_and_record(server["project_id"], payload, direction="input", action="block")
        if scan.findings or dlp.redact_value(payload) != payload:
            # Never silently mutate arguments bound to a capability signature.
            raise McpSecurityError("MCP 参数包含敏感数据；需使用受控凭据代理，不允许明文透传")
        if server["status"] != "active":
            raise McpSecurityError("MCP Server 已被隔离，流量未转发", findings=json.loads(server["findings_json"]))
        policy = self.db.active_policy(server["project_id"])
        method = str(payload.get("method", ""))
        allowed_methods = policy.get("mcp", {}).get("allowed_methods", [])
        if method not in allowed_methods:
            raise McpSecurityError(f"MCP 方法 {method} 未被策略允许")
        if method == "tools/call":
            params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
            tool_name = str(params.get("name", ""))
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            tool = next((item for item in self.tools_from_manifest(json.loads(server["manifest_json"])) if item["name"] == tool_name), None)
            if not tool:
                raise McpSecurityError("工具不在已固定 Manifest 中，疑似 Tool Shadowing")
            self._validate_arguments(tool.get("inputSchema", {}), arguments)
            decision = self.policy_engine.inspect_tool(tool_name, policy, None)
            if decision.action == "approval_required":
                if not approval_token:
                    raise McpSecurityError("; ".join(decision.reasons), status_code=428)
                try:
                    self.sandbox.authorize_capability(
                        server["project_id"], tool_name, arguments, approval_token,
                        target=f"mcp:{server_id}:{server['manifest_hash']}",
                    )
                except SandboxViolation as exc:
                    raise McpSecurityError(str(exc), status_code=exc.status_code) from exc
            elif decision.action != "allow":
                raise McpSecurityError("; ".join(decision.reasons))
        self._validate_proxy_destination(server["endpoint"])
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        async with (
            httpx.AsyncClient(timeout=15.0, follow_redirects=False, trust_env=False) as client,
            client.stream("POST", server["endpoint"], json=payload, headers=headers) as response,
        ):
            response.raise_for_status()
            try:
                result = await read_limited_json(response, settings.max_upstream_response_bytes)
            except ValueError as exc:
                raise McpSecurityError(str(exc), status_code=502) from exc
        output_decision = self.policy_engine.inspect_output(json.dumps(result, ensure_ascii=False), policy)
        instruction_decision = self.policy_engine.inspect_input(json.dumps(result, ensure_ascii=False), None, policy)
        dlp_output = dlp.inspect_and_record(server["project_id"], result, direction="output")
        if output_decision.blocked or instruction_decision.blocked or dlp_output.blocked:
            raise McpSecurityError("MCP 响应包含敏感信息，已在返回前拦截")
        self.db.audit(server["project_id"], "mcp.request_forwarded", f"转发 MCP 方法 {method}", {
            "server_id": server_id, "request_id": payload.get("id")
        })
        return dlp.redact_value(result)

    @staticmethod
    def _finding(severity: str, code: str, tool: str, message: str) -> dict[str, Any]:
        return {"severity": severity, "code": code, "tool": tool, "message": message}

    def _raw_server(self, server_id: str) -> dict[str, Any]:
        server = self.db.query_one("SELECT * FROM mcp_servers WHERE id = ?", (server_id,))
        if not server:
            raise KeyError(server_id)
        return server

    @staticmethod
    def _decode_server(server: dict[str, Any]) -> dict[str, Any]:
        result = dict(server)
        result["manifest"] = json.loads(result.pop("manifest_json"))
        result["findings"] = json.loads(result.pop("findings_json"))
        return result

    def _snapshot(self, server_id: str, manifest_hash: str, manifest: dict[str, Any], diff: dict[str, Any], findings: list[dict[str, Any]]) -> None:
        self.db.execute(
            """
            INSERT INTO mcp_manifest_snapshots
            (id, server_id, manifest_hash, manifest_json, diff_json, findings_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (new_id("mcpsnap"), server_id, manifest_hash, json.dumps(manifest, ensure_ascii=False),
             json.dumps(diff, ensure_ascii=False), json.dumps(findings, ensure_ascii=False), utc_now()),
        )

    def _manifest_diff(self, previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
        before = {tool["name"]: tool for tool in self.tools_from_manifest(previous)}
        after = {tool["name"]: tool for tool in self.tools_from_manifest(current)}
        added = sorted(after.keys() - before.keys())
        removed = sorted(before.keys() - after.keys())
        changed = sorted(name for name in before.keys() & after.keys() if before[name] != after[name])
        return {"added": added, "removed": removed, "changed": changed,
                "security_relevant_changes": sorted(set(added + removed + changed))}

    @staticmethod
    def _validate_arguments(schema: dict[str, Any], arguments: dict[str, Any]) -> None:
        # No remote schema fetching, recursion, or attacker-supplied regex in
        # the personal gateway. Unsupported schema features are rejected.
        nodes = 0
        def inspect(value: Any, depth: int = 0) -> None:
            nonlocal nodes
            nodes += 1
            if depth > 20 or nodes > 1000:
                raise McpSecurityError("Schema exceeds complexity budget", status_code=422)
            if isinstance(value, dict):
                if set(value) & {"$ref", "$dynamicRef", "$recursiveRef", "pattern", "patternProperties"}:
                    raise McpSecurityError("Schema references and regex are unsupported", status_code=422)
                for item in value.values():
                    inspect(item, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    inspect(item, depth + 1)
        inspect(schema)
        try:
            json.dumps(arguments, allow_nan=False)
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(arguments)
        except (SchemaError, ValidationError, TypeError, ValueError, RecursionError) as exc:
            raise McpSecurityError("工具参数或 Schema 无效", status_code=422) from exc

    @staticmethod
    def _validate_endpoint(endpoint: str) -> None:
        validate_http_endpoint(endpoint)

    @staticmethod
    def _validate_proxy_destination(endpoint: str) -> None:
        try:
            validate_outbound_destination(
                endpoint, allow_development_loopback=settings.environment == "development"
            )
        except UnsafeOutboundDestination as exc:
            raise McpSecurityError(f"MCP outbound destination rejected: {exc}") from exc
