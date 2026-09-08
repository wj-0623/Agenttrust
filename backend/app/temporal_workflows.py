from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import activity, workflow
from temporalio.common import RetryPolicy


@activity.defn
async def validate_refund_activity(payload: dict[str, str]) -> dict[str, Any]:
    from .tenant_context import workspace_context
    with workspace_context(payload["workspace_id"]):
        service = _refund_service()
        refund = service.get(payload["refund_id"])
        return {"status": refund["status"], "risk_score": refund["risk_score"]}


@activity.defn
async def issue_refund_activity(payload: dict[str, str]) -> dict[str, Any]:
    from .tenant_context import workspace_context
    with workspace_context(payload["workspace_id"]):
        return _refund_service().issue(payload["refund_id"], "temporal-refund-worker")


def _refund_service() -> Any:
    # Activities run outside the deterministic workflow sandbox and may use the
    # production database. PostgreSQL is required for multi-worker deployments.
    from .config import settings
    from .db import Database
    from .services.dlp import DLPService
    from .services.policy import PolicyEngine
    from .services.refunds import RefundService
    from .services.sandbox import SandboxService
    from .services.security_response import SecurityResponseService

    database = Database(settings.database_url or settings.database_path,
                        postgres_rls_enabled=settings.postgres_rls_enabled)
    return RefundService(database, PolicyEngine(), SandboxService(database), DLPService(database), SecurityResponseService(database))


@workflow.defn
class CustomerRefundWorkflow:
    def __init__(self) -> None:
        self._approved = False
        self._denied = False
        self._state = "created"

    @workflow.run
    async def run(self, payload: dict[str, str]) -> dict[str, Any]:
        decision = await workflow.execute_activity(
            validate_refund_activity,
            payload,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )
        self._state = decision["status"]
        if self._state == "denied":
            return decision
        if self._state == "waiting_approval":
            try:
                await workflow.wait_condition(
                    lambda: self._approved or self._denied,
                    timeout=timedelta(hours=24),
                )
            except TimeoutError:
                self._state = "approval_timeout"
                return {"status": self._state}
            if self._denied:
                self._state = "denied_by_reviewer"
                return {"status": self._state}
        self._state = "settling"
        result = await workflow.execute_activity(
            issue_refund_activity,
            payload,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )
        self._state = result["status"]
        return result

    @workflow.signal
    async def approve(self) -> None:
        self._approved = True

    @workflow.signal
    async def deny(self) -> None:
        self._denied = True

    @workflow.query
    def state(self) -> str:
        return self._state
