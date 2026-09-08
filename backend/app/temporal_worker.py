from __future__ import annotations

import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from .config import settings
from .db import Database
from .temporal_workflows import (
    CustomerRefundWorkflow,
    issue_refund_activity,
    validate_refund_activity,
)


async def main() -> None:
    settings.validate_deployment(api=False)
    Database(settings.database_url or settings.database_path,
             postgres_rls_enabled=settings.postgres_rls_enabled).verify_runtime_role()
    client = await Client.connect(settings.temporal_target, namespace=settings.temporal_namespace)
    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[CustomerRefundWorkflow],
        activities=[validate_refund_activity, issue_refund_activity],
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
