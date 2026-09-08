"""Legacy filename: run an opt-in black-box external Agent demo.

This script only creates an AgentTrust project and invokes an explicitly supplied
target URL. It never writes to or configures the target project. Use a read-only
demo target because post-response inspection cannot undo an upstream side effect.
"""
from __future__ import annotations

import argparse
import json
import os

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agenttrust-url", default="http://127.0.0.1:8010")
    parser.add_argument(
        "--target-url",
        required=True,
        help="Exact URL already present in AGENTTRUST_EXTERNAL_AGENT_ENDPOINT_ALLOWLIST",
    )
    parser.add_argument("--message", default="分析我的 Agent 项目并给出三步面试准备计划")
    args = parser.parse_args()
    headers: dict[str, str] = {}
    if key := os.getenv("AGENTTRUST_API_KEY"):
        headers["X-AgentTrust-Key"] = key

    with httpx.Client(
        base_url=args.agenttrust_url, headers=headers, timeout=90, trust_env=False
    ) as client:
        projects = client.get("/api/v1/projects")
        projects.raise_for_status()
        project = next(
            (
                item
                for item in projects.json()
                if item.get("adapter") == "external_agent"
                and str(item.get("endpoint", "")).rstrip("/") == args.target_url.rstrip("/")
            ),
            None,
        )
        if project is None:
            created = client.post(
                "/api/v1/projects",
                json={
                    "name": "External Agent portfolio demo",
                    "description": "Read-only black-box target observed by AgentTrust",
                    "adapter": "external_agent",
                    "endpoint": args.target_url,
                    "model": "external-agent-unreported",
                    "environment": "development",
                    "auto_correct": False,
                },
            )
            created.raise_for_status()
            project = created.json()

        response = client.post(
            "/api/v1/gateway/invoke",
            json={
                "project_id": project["id"],
                "message": args.message,
                "metadata": {"session_id": "external-portfolio-demo"},
            },
        )
        response.raise_for_status()
        result = response.json()
    print(
        json.dumps(
            {
                "project_id": project["id"],
                "status": result["status"],
                "trace_id": result["trace_id"],
                "output": result["output"],
                "runtime": result["details"].get("runtime", {}),
                "tool_calls": result["details"].get("tool_calls", []),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
