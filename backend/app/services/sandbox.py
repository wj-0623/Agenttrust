from __future__ import annotations

import ast
import hashlib
import json
import math
import operator
import secrets
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from contextvars import copy_context
from datetime import UTC, datetime, timedelta
from threading import BoundedSemaphore
from typing import Any

from ..config import settings
from ..db import Database, new_id, utc_now
from .dlp import DLPService
from .policy import PolicyEngine
from .security_response import SecurityResponseService


class SandboxViolation(RuntimeError):
    def __init__(self, message: str, status_code: int = 403):
        super().__init__(message)
        self.status_code = status_code


class SandboxService:
    """Capability-based tool runner. It intentionally exposes no arbitrary shell or network API."""

    def __init__(self, db: Database):
        self.db = db
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="agenttrust-trusted-tools")
        self._slots = BoundedSemaphore(4)
        self.tools: dict[str, Callable[[dict[str, Any]], Any]] = {
            "calculator.run": self._calculator,
            "knowledge.search": self._knowledge_search,
            "weather.read": lambda args: {"location": args.get("location", "unknown"), "condition": "demo-clear"},
            "ticket.read": lambda args: {"ticket_id": args.get("ticket_id"), "status": "open"},
            "email.send": lambda args: {"delivery": "simulated", "recipient_id": args.get("recipient_id"), "message_id": new_id("mail")},
            "database.write": lambda args: {"write": "simulated", "rows": min(int(args.get("rows", 1)), 100)},
            "payment.create": lambda args: {"payment": "simulated", "amount": float(args.get("amount", 0)), "receipt": new_id("receipt")},
            "refund.issue": lambda args: {
                "refund": "simulated",
                "order_id": args.get("order_id"),
                "amount": float(args.get("amount", 0)),
                "currency": args.get("currency"),
                "provider_reference": new_id("refund_provider"),
            },
        }

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _arguments_hash(arguments: dict[str, Any]) -> str:
        payload = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def issue_lease(
        self,
        project_id: str,
        tool_name: str,
        constraints: dict[str, Any],
        actor: str,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        SecurityResponseService(self.db).assert_runtime_enabled(project_id)
        if not 30 <= ttl_seconds <= 3600:
            raise SandboxViolation("Invalid capability TTL", 422)
        if not isinstance(constraints.get("arguments_sha256"), str) or len(constraints["arguments_sha256"]) != 64:
            raise SandboxViolation("Capability must bind the complete argument hash", 422)
        constraints = {**constraints, "target": constraints.get("target", "adapter")}
        if not self.db.query_one("SELECT id FROM projects WHERE id = ?", (project_id,)):
            raise KeyError(project_id)
        policy = self.db.active_policy(project_id)
        if tool_name in policy.get("denied_tools", []):
            raise SandboxViolation(f"工具 {tool_name} 被策略禁止")
        token = f"cap_{secrets.token_urlsafe(32)}"
        lease_id = new_id("lease")
        expires = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
        self.db.execute(
            """
            INSERT INTO capability_leases
            (id, project_id, tool_name, token_hash, constraints_json, actor, expires_at, used_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                lease_id, project_id, tool_name, self._token_hash(token),
                json.dumps(constraints, ensure_ascii=False), actor, expires.isoformat(), utc_now(),
            ),
        )
        self.db.audit(project_id, "sandbox.lease_issued", f"为 {tool_name} 签发一次性能力租约", {
            "lease_id": lease_id, "expires_at": expires.isoformat(), "constraints": constraints
        }, actor=actor)
        return {"id": lease_id, "capability_token": token, "tool_name": tool_name, "expires_at": expires.isoformat(), "constraints": constraints}

    def execute(
        self,
        project_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        capability_token: str | None = None,
        workflow_id: str | None = None,
    ) -> dict[str, Any]:
        SecurityResponseService(self.db).assert_runtime_enabled(project_id)
        policy = self.db.active_policy(project_id)
        if tool_name in policy.get("denied_tools", []):
            raise SandboxViolation(f"工具 {tool_name} 被拒绝策略阻止")
        if tool_name == "email.send" and (not isinstance(arguments.get("recipient_id"), str) or not arguments["recipient_id"]):
            raise SandboxViolation("模拟邮件工具仅接受 recipient_id，不接收明文邮箱", 422)
        if tool_name in {"payment.create", "refund.issue"}:
            amount = arguments.get("amount")
            if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not math.isfinite(amount) or amount <= 0:
                raise SandboxViolation("Invalid payment amount", 422)
        requires_approval = tool_name in set(policy.get("approval_tools", [])) | {"email.send", "database.write", "payment.create", "refund.issue"}
        dlp = DLPService(self.db)
        scanned = dlp.inspect_and_record(project_id, arguments, direction="input")
        if scanned.blocked or dlp.redact_value(arguments) != arguments:
            raise SandboxViolation("敏感工具参数需要专用凭据适配器，拒绝明文执行")
        decision = PolicyEngine().inspect_input(json.dumps(arguments, ensure_ascii=False), None, policy)
        if decision.blocked:
            raise SandboxViolation("工具参数被输入策略阻止")
        lease: dict[str, Any] | None = None
        if requires_approval:
            if not capability_token:
                raise SandboxViolation("副作用工具需要一次性 capability token", 428)
            lease = self.authorize_capability(project_id, tool_name, arguments, capability_token)
        elif tool_name not in policy.get("allowed_tools", []):
            raise SandboxViolation(f"工具 {tool_name} 不在项目能力白名单")
        tool = self.tools.get(tool_name)
        if not tool:
            raise SandboxViolation("该工具没有受信任的 Sandbox Adapter", 501)
        started = time.perf_counter()
        if not self._slots.acquire(blocking=False):
            raise SandboxViolation("可信工具执行器已满，请稍后重试", 429)
        try:
            future = self._executor.submit(copy_context().run, tool, arguments)
        except Exception:
            self._slots.release()
            raise
        future.add_done_callback(lambda _: self._slots.release())
        try:
            result = future.result(timeout=settings.sandbox_timeout_seconds)
            encoded = json.dumps(result, ensure_ascii=False)
            if len(encoded) > settings.sandbox_max_output_chars:
                raise SandboxViolation("工具输出超过沙箱限制", 413)
            output_scan = dlp.inspect_and_record(project_id, result, direction="output")
            if output_scan.blocked or PolicyEngine().inspect_input(encoded, None, policy).blocked:
                raise SandboxViolation("工具结果被安全策略阻止")
            result = dlp.redact_value(result)
            status = "completed"
        except FutureTimeout as exc:
            future.cancel()
            status = "timeout"
            result = {"error": "sandbox timeout"}
            raise SandboxViolation("工具执行超过沙箱时间预算", 408) from exc
        except Exception as exc:
            status = "failed"
            result = {"error": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            duration = max(0, int((time.perf_counter() - started) * 1000))
            self.db.execute(
                """
                INSERT INTO sandbox_runs
                (id, project_id, workflow_id, tool_name, arguments_json, result_json,
                 status, duration_ms, policy_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id("sandbox"), project_id, workflow_id, tool_name,
                    json.dumps(DLPService(self.db).redact_value(arguments), ensure_ascii=False),
                    json.dumps(DLPService(self.db).redact_value(result), ensure_ascii=False),
                    status, duration, json.dumps({
                        "mode": "trusted_adapter", "os_isolation": False,
                        "timeout_seconds": settings.sandbox_timeout_seconds,
                        "max_output_chars": settings.sandbox_max_output_chars,
                    }, ensure_ascii=False), utc_now(),
                ),
            )
        self.db.audit(project_id, "sandbox.tool_executed", f"沙箱执行 {tool_name}", {
            "workflow_id": workflow_id, "duration_ms": duration, "lease_id": lease["id"] if lease else None
        })
        return {"status": "completed", "tool_name": tool_name, "result": result, "duration_ms": duration,
                "isolation": {"mode": "trusted_adapter", "os_isolation": False, "hard_timeout": False}}

    def list_runs(self, project_id: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.query_all(
            "SELECT * FROM sandbox_runs WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
            (project_id, limit),
        )
        for row in rows:
            for field in ("arguments_json", "result_json", "policy_json"):
                row[field.removesuffix("_json")] = json.loads(row.pop(field))
        return rows

    def authorize_capability(
        self, project_id: str, tool_name: str, arguments: dict[str, Any], token: str, *, target: str = "adapter"
    ) -> dict[str, Any]:
        """Validate and consume a lease atomically before a side effect starts."""
        token_hash = self._token_hash(token)
        now = datetime.now(UTC)
        with self.db.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM capability_leases WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            lease = dict(row) if row else None
            if not lease or lease["project_id"] != project_id or lease["tool_name"] != tool_name:
                raise SandboxViolation("capability token 无效或未绑定当前工具")
            if lease.get("used_at"):
                raise SandboxViolation("capability token 已使用，禁止重放")
            if datetime.fromisoformat(lease["expires_at"]) <= now:
                raise SandboxViolation("capability token 已过期")
            constraints = json.loads(lease["constraints_json"])
            expected_hash = constraints.get("arguments_sha256")
            if not expected_hash or expected_hash != self._arguments_hash(arguments):
                raise SandboxViolation("工具参数与批准时绑定的参数不一致")
            if constraints.get("target") != target:
                raise SandboxViolation("Capability is bound to a different execution target")
            if "max_amount" in constraints and float(arguments.get("amount", 0)) > float(constraints["max_amount"]):
                raise SandboxViolation("工具金额超过能力租约上限")
            claimed = connection.execute(
                "UPDATE capability_leases SET used_at = ? WHERE id = ? AND used_at IS NULL",
                (now.isoformat(), lease["id"]),
            )
            if claimed.rowcount != 1:
                raise SandboxViolation("capability token 已被并发消费，禁止重放")
            lease["used_at"] = now.isoformat()
            return lease

    @classmethod
    def arguments_hash(cls, arguments: dict[str, Any]) -> str:
        return cls._arguments_hash(arguments)

    @staticmethod
    def _calculator(arguments: dict[str, Any]) -> dict[str, Any]:
        expression = str(arguments.get("expression", ""))
        if not expression or len(expression) > 200:
            raise SandboxViolation("计算表达式为空或过长", 422)
        operators: dict[type[ast.AST], Callable[[Any, Any], Any]] = {
            ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
            ast.Div: operator.truediv, ast.Mod: operator.mod, ast.Pow: operator.pow,
        }

        def evaluate(node: ast.AST) -> float:
            if isinstance(node, ast.Expression):
                return evaluate(node.body)
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return float(node.value)
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
                value = evaluate(node.operand)
                return value if isinstance(node.op, ast.UAdd) else -value
            if isinstance(node, ast.BinOp) and type(node.op) in operators:
                left, right = evaluate(node.left), evaluate(node.right)
                if abs(left) > 1e12 or abs(right) > 1e12:
                    raise SandboxViolation("计算值超过预算", 422)
                if isinstance(node.op, ast.Pow) and abs(right) > 12:
                    raise SandboxViolation("指数超过计算预算", 422)
                return float(operators[type(node.op)](left, right))
            raise SandboxViolation("表达式包含未允许的语法", 422)

        value = evaluate(ast.parse(expression, mode="eval"))
        return {"expression": expression, "value": value}

    @staticmethod
    def _knowledge_search(arguments: dict[str, Any]) -> dict[str, Any]:
        query = str(arguments.get("query", "")).strip()
        if not query:
            raise SandboxViolation("query 不能为空", 422)
        return {"query": query, "matches": [{"title": "AgentTrust Demo Knowledge", "score": 0.94}]}
