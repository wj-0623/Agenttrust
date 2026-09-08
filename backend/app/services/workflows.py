from __future__ import annotations

import json
from typing import Any

from ..db import Database, new_id, utc_now
from ..schemas import GatewayRequest
from .dlp import DLPService
from .gateway import GatewayService
from .observability import ObservabilityService
from .sandbox import SandboxService


class WorkflowService:
    """Local durable state machine; production refunds use Temporal orchestration."""

    def __init__(
        self,
        db: Database,
        gateway: GatewayService,
        sandbox: SandboxService,
        observability: ObservabilityService,
    ):
        self.db = db
        self.gateway = gateway
        self.sandbox = sandbox
        self.observability = observability

    async def create(
        self,
        project_id: str,
        idempotency_key: str,
        message: str,
        tool_name: str | None,
        tool_arguments: dict[str, Any],
        untrusted_context: str | None,
        max_retries: int,
    ) -> dict[str, Any]:
        dlp = DLPService(self.db)
        workflow_input = {
            "message": message, "tool_name": tool_name, "tool_arguments": tool_arguments,
            "untrusted_context": untrusted_context,
        }
        scan = dlp.inspect_and_record(project_id, workflow_input, direction="input")
        decision = self.gateway.policy_engine.inspect_input(
            message, json.dumps({"context": untrusted_context, "arguments": tool_arguments}, ensure_ascii=False),
            self.db.active_policy(project_id),
        )
        blocked = scan.blocked or decision.blocked or dlp.redact_value(tool_arguments) != tool_arguments
        workflow_input = dlp.redact_value(workflow_input)
        existing = self.db.query_one(
            "SELECT id FROM durable_workflows WHERE project_id = ? AND idempotency_key = ?",
            (project_id, idempotency_key),
        )
        if existing:
            current = self.get(existing["id"])
            if current["input"] != workflow_input:
                raise ValueError("Idempotency key is bound to a different workflow input")
            return current
        if not self.db.query_one("SELECT id FROM projects WHERE id = ?", (project_id,)):
            raise KeyError(project_id)
        workflow_id = new_id("wf")
        now = utc_now()
        inserted = self.db.execute(
            """
            INSERT OR IGNORE INTO durable_workflows
            (id, project_id, idempotency_key, kind, status, input_json, state_json,
             result_json, current_step, retries, max_retries, waiting_for, error,
             created_at, updated_at)
            VALUES (?, ?, ?, 'agent_tool_workflow', 'pending', ?, '{}', '{}',
                    'created', 0, ?, NULL, NULL, ?, ?)
            """,
            (workflow_id, project_id, idempotency_key, json.dumps(workflow_input, ensure_ascii=False), max_retries, now, now),
        )
        if inserted != 1:
            concurrent = self.db.query_one(
                "SELECT id FROM durable_workflows WHERE project_id = ? AND idempotency_key = ?",
                (project_id, idempotency_key),
            )
            if concurrent:
                current = self.get(concurrent["id"])
                if current["input"] != workflow_input:
                    raise ValueError("Idempotency key is bound to a different workflow input")
                return current
            raise RuntimeError("Unable to create or recover the idempotent workflow")
        self._event(workflow_id, "workflow.created", {"idempotency_key": idempotency_key})
        if blocked:
            self.db.execute(
                "UPDATE durable_workflows SET status = 'blocked', current_step = 'input_guard', result_json = ? WHERE id = ?",
                (json.dumps({"gateway": {"status": "blocked", "blocked": True}, "sandbox": None}), workflow_id),
            )
            self._event(workflow_id, "workflow.blocked", {"reason": "Input safety check"})
            return self.get(workflow_id)
        return await self._run(workflow_id)

    async def approve(self, workflow_id: str, actor: str, reason: str) -> dict[str, Any]:
        workflow = self.get(workflow_id)
        if workflow["status"] != "waiting_approval":
            return workflow
        claimed = self.db.execute(
            """
            UPDATE durable_workflows SET status = 'approval_in_progress', current_step = 'approval_claimed',
                waiting_for = NULL, updated_at = ? WHERE id = ? AND status = 'waiting_approval'
            """,
            (utc_now(), workflow_id),
        )
        if claimed != 1:
            return self.get(workflow_id)
        data = workflow["input"]
        tool_name = data.get("tool_name")
        if not tool_name:
            raise ValueError("Workflow has no approval-bound tool")
        constraints = {"arguments_sha256": self.sandbox.arguments_hash(data.get("tool_arguments", {}))}
        if tool_name == "payment.create" and "amount" in data.get("tool_arguments", {}):
            constraints["max_amount"] = float(data["tool_arguments"]["amount"])
        try:
            lease = self.sandbox.issue_lease(workflow["project_id"], tool_name, constraints, actor, 300)
        except Exception:
            self._transition(
                workflow_id, "waiting_approval", "human_approval", "capability_lease", "approval failed"
            )
            raise
        self._event(workflow_id, "workflow.approved", {
            "actor": actor, "reason": reason, "lease_id": lease["id"], "expires_at": lease["expires_at"]
        })
        return await self._run(workflow_id, capability_token=lease["capability_token"])

    async def retry(self, workflow_id: str) -> dict[str, Any]:
        workflow = self.get(workflow_id)
        if workflow["status"] not in {"failed", "retry_scheduled"}:
            return workflow
        if workflow["retries"] >= workflow["max_retries"]:
            return workflow
        self._event(workflow_id, "workflow.retry_requested", {"attempt": workflow["retries"] + 1})
        return await self._run(workflow_id)

    def compensate(self, workflow_id: str, actor: str, reason: str) -> dict[str, Any]:
        workflow = self.get(workflow_id)
        if workflow["status"] not in {"completed", "failed"}:
            raise ValueError("Only completed or failed workflows can be compensated")
        result = dict(workflow["result"])
        result["compensation"] = {"status": "simulated", "actor": actor, "reason": reason, "at": utc_now()}
        self.db.execute(
            "UPDATE durable_workflows SET status = 'compensated', current_step = 'compensated', result_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(result, ensure_ascii=False), utc_now(), workflow_id),
        )
        self._event(workflow_id, "workflow.compensated", result["compensation"])
        return self.get(workflow_id)

    async def _run(self, workflow_id: str, capability_token: str | None = None) -> dict[str, Any]:
        workflow = self.get(workflow_id)
        data = workflow["input"]
        root = self.observability.start_span(
            workflow["project_id"], "invoke_workflow agent_tool_workflow", workflow_id=workflow_id,
            attributes={"gen_ai.operation.name": "invoke_workflow", "workflow.id": workflow_id,
                        "workflow.retry": workflow["retries"]},
        )
        self._transition(workflow_id, "running", "gateway_policy", None, None)
        self._event(workflow_id, "workflow.running", {"step": "gateway_policy"})
        try:
            response = await self.gateway.invoke(
                GatewayRequest(
                    project_id=workflow["project_id"], message=data["message"],
                    tool_name=data.get("tool_name"), tool_arguments=data.get("tool_arguments", {}),
                    untrusted_context=data.get("untrusted_context"), approval_token=capability_token,
                    metadata={"workflow_id": workflow_id, "idempotency_key": workflow["idempotency_key"]},
                ),
                trusted_approval=bool(capability_token),
            )
            if response.status == "approval_required":
                self._transition(workflow_id, "waiting_approval", "human_approval", "capability_lease", None)
                self._event(workflow_id, "workflow.waiting_approval", {"trace_id": response.trace_id, "tool_name": data.get("tool_name")})
                self.observability.end_span(root, "OK", {"workflow.status": "waiting_approval", "trace.id": response.trace_id})
                return self.get(workflow_id)
            if response.status == "failed":
                return self._record_failure(workflow_id, response.details.get("error", "gateway failed"), root)
            if response.status == "blocked":
                self.db.execute(
                    "UPDATE durable_workflows SET status = 'blocked', current_step = 'gateway_policy', result_json = ?, updated_at = ? WHERE id = ?",
                    (json.dumps({"gateway": response.model_dump(), "sandbox": None}, ensure_ascii=False), utc_now(), workflow_id),
                )
                self._event(workflow_id, "workflow.blocked", {"trace_id": response.trace_id})
                self.observability.end_span(root, "OK", {"workflow.status": "blocked"})
                return self.get(workflow_id)
            sandbox_result: dict[str, Any] | None = None
            if response.status == "completed" and data.get("tool_name"):
                self._transition(workflow_id, "running", "sandbox_tool", None, None)
                tool_span = self.observability.start_span(
                    workflow["project_id"], f"execute_tool {data['tool_name']}", workflow_id=workflow_id,
                    parent_span_id=root.id, trace_id=response.trace_id,
                    attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": data["tool_name"]},
                )
                sandbox_result = self.sandbox.execute(
                    workflow["project_id"], data["tool_name"], data.get("tool_arguments", {}),
                    capability_token, workflow_id,
                )
                self.observability.end_span(tool_span, "OK", {"sandbox.duration_ms": sandbox_result["duration_ms"]})
            result = {"gateway": response.model_dump(), "sandbox": sandbox_result}
            self.db.execute(
                """
                UPDATE durable_workflows SET status = 'completed', current_step = 'complete',
                    result_json = ?, state_json = ?, waiting_for = NULL, error = NULL, updated_at = ?
                WHERE id = ?
                """,
                (json.dumps(result, ensure_ascii=False), json.dumps({"trace_id": response.trace_id}, ensure_ascii=False), utc_now(), workflow_id),
            )
            self._event(workflow_id, "workflow.completed", {"trace_id": response.trace_id})
            self.observability.end_span(root, "OK", {"workflow.status": "completed", "trace.id": response.trace_id})
            return self.get(workflow_id)
        except Exception as exc:  # noqa: BLE001 - workflow must durably record all failures
            if self.get(workflow_id)["current_step"] == "sandbox_tool":
                # The tool might still be running after a timeout. Do not retry.
                self._transition(workflow_id, "unknown", "reconciliation_required", None, type(exc).__name__)
                self._event(workflow_id, "workflow.result_unknown", {"error": type(exc).__name__})
                self.observability.end_span(root, "ERROR", {"workflow.status": "unknown"})
                return self.get(workflow_id)
            return self._record_failure(workflow_id, type(exc).__name__, root)

    def _record_failure(self, workflow_id: str, error: str, root: Any) -> dict[str, Any]:
        error = DLPService(self.db).redact_value(error)
        workflow = self.get(workflow_id)
        retries = workflow["retries"] + 1
        status = "retry_scheduled" if retries <= workflow["max_retries"] else "failed"
        self.db.execute(
            "UPDATE durable_workflows SET status = ?, current_step = 'failed', retries = ?, error = ?, updated_at = ? WHERE id = ?",
            (status, retries, error[:1000], utc_now(), workflow_id),
        )
        self._event(workflow_id, "workflow.failed", {"error": error, "retries": retries, "status": status})
        self.observability.end_span(root, "ERROR", {"workflow.status": status, "error.type": error[:160]})
        return self.get(workflow_id)

    def _transition(self, workflow_id: str, status: str, step: str, waiting_for: str | None, error: str | None) -> None:
        self.db.execute(
            "UPDATE durable_workflows SET status = ?, current_step = ?, waiting_for = ?, error = ?, updated_at = ? WHERE id = ?",
            (status, step, waiting_for, error, utc_now(), workflow_id),
        )

    def _event(self, workflow_id: str, event_type: str, payload: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO workflow_events (id, workflow_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (new_id("wfevent"), workflow_id, event_type, json.dumps(DLPService(self.db).redact_value(payload), ensure_ascii=False), utc_now()),
        )

    def get(self, workflow_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM durable_workflows WHERE id = ?", (workflow_id,))
        if not row:
            raise KeyError(workflow_id)
        row["input"] = json.loads(row.pop("input_json"))
        row["state"] = json.loads(row.pop("state_json"))
        row["result"] = json.loads(row.pop("result_json"))
        events = self.db.query_all("SELECT * FROM workflow_events WHERE workflow_id = ? ORDER BY created_at", (workflow_id,))
        for event in events:
            event["payload"] = json.loads(event.pop("payload_json"))
        row["events"] = events
        return row

    def list(self, project_id: str, limit: int = 100) -> list[dict[str, Any]]:
        ids = self.db.query_all(
            "SELECT id FROM durable_workflows WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
            (project_id, limit),
        )
        return [self.get(row["id"]) for row in ids]
