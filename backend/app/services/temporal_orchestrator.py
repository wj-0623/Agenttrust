from __future__ import annotations

from typing import Any

from ..config import settings


class TemporalOrchestrator:
    def __init__(self) -> None:
        self.client: Any | None = None

    async def connect(self) -> None:
        if not settings.temporal_enabled:
            return
        from temporalio.client import Client

        self.client = await Client.connect(
            settings.temporal_target,
            namespace=settings.temporal_namespace,
        )

    async def start_refund(self, refund_id: str, workspace_id: str) -> str:
        if not self.client:
            raise RuntimeError("Temporal is enabled but the client is unavailable")
        from ..temporal_workflows import CustomerRefundWorkflow

        workflow_id = f"agenttrust-refund-{refund_id}"
        from temporalio.exceptions import WorkflowAlreadyStartedError
        try:
            await self.client.start_workflow(
                CustomerRefundWorkflow.run,
                {"refund_id": refund_id, "workspace_id": workspace_id},
                id=workflow_id,
                task_queue=settings.temporal_task_queue,
            )
        except WorkflowAlreadyStartedError:
            pass  # Retry after a lost response must reference the same durable run.
        return workflow_id

    async def approve_refund(self, workflow_id: str) -> None:
        if not self.client:
            raise RuntimeError("Temporal is enabled but the client is unavailable")
        from ..temporal_workflows import CustomerRefundWorkflow

        handle = self.client.get_workflow_handle(workflow_id)
        await handle.signal(CustomerRefundWorkflow.approve)
