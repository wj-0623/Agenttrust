"""Local integration example: invoke the gateway or a registered tool workflow.

Run with backend/.venv Python. No external service or real payment is used by
the default demo project. The user's own Agent must explicitly use this API;
this is not a transparent interceptor for arbitrary framework traffic.
"""
from __future__ import annotations

import argparse
import json
import os
import uuid

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8010")
    parser.add_argument("--project-id", default="proj_demo")
    parser.add_argument("--workflow", action="store_true", help="Execute the registered calculator demo")
    args = parser.parse_args()
    headers = {}
    if key := os.getenv("AGENTTRUST_API_KEY"):
        headers["X-AgentTrust-Key"] = key
    payload = {"project_id": args.project_id, "message": "检查服务状态"}
    path = "/api/v1/gateway/invoke"
    if args.workflow:
        path = "/api/v1/workflows"
        payload.update(message="计算订单金额", idempotency_key=f"personal-{uuid.uuid4().hex}",
                       tool_name="calculator.run", tool_arguments={"expression": "19.5*4+2"})
    with httpx.Client(base_url=args.base_url, headers=headers, timeout=60, trust_env=False) as client:
        response = client.post(path, json=payload)
        response.raise_for_status()
        result = response.json()
    print(json.dumps({"status": result["status"], "trace_id": result.get("trace_id"),
                      "workflow_id": result.get("id"), "details": result.get("details", {})}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
