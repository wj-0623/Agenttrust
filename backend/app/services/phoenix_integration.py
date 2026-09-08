from __future__ import annotations

import hashlib
import json
from typing import Any

from ..config import settings
from ..db import Database, new_id, utc_now
from .dlp import DLPService
from .evaluation import HOLDOUT_CASES, REGRESSION_CASES, EvaluationService
from .policy import PolicyEngine


class PhoenixIntegration:
    """Explicit, tenant-namespaced export using the official Phoenix SDK.

    No customer traces are uploaded by this operation: only built-in regression
    examples and the reviewed security prompt are shared with the configured sink.
    """

    def __init__(self, db: Database, client: Any = None):
        self.db, self.client = db, client

    def publish(self, project_id: str, correction_id: str) -> dict[str, Any]:
        release = self.db.query_one("SELECT * FROM correction_releases WHERE project_id = ? AND correction_id = ? ORDER BY created_at DESC LIMIT 1", (project_id, correction_id))
        if not release:
            raise KeyError(correction_id)
        if self.client is None:
            if not settings.phoenix_base_url:
                return {"status": "not_configured", "exported": False}
            from phoenix.client import Client
            self.client = Client(base_url=settings.phoenix_base_url, api_key=settings.phoenix_api_key)
        evaluation = EvaluationService(PolicyEngine())
        dlp = DLPService(self.db)
        cases = [*REGRESSION_CASES, *HOLDOUT_CASES]
        dataset = self.client.datasets.create_dataset(
            name=f"agenttrust-{project_id}-{correction_id}",
            inputs=[dlp.redact_value({k: v for k, v in case.items() if k != "expected"}) for case in cases],
            outputs=[{"expected": case["expected"]} for case in cases],
            metadata=[{"split": "holdout" if i >= len(REGRESSION_CASES) else "regression"} for i in range(len(cases))],
            dataset_description="AgentTrust reviewed security regression + holdout; not customer traffic",
        )
        baseline = self.db.policy_at_version(project_id, release["baseline_version"])
        candidate = json.loads(release["candidate_rules_json"])

        def accuracy(output: dict[str, Any], expected: dict[str, Any]) -> bool:
            return output["actual"] == expected["expected"]

        def task_for(policy: dict[str, Any]) -> Any:
            def task(input: dict[str, Any]) -> dict[str, Any]:
                return evaluation.evaluate_cases(policy, [{**input, "expected": "allow"}])["results"][0]
            return task

        runs = {}
        for name, policy in (("baseline", baseline), ("candidate", candidate)):
            run = self.client.experiments.run_experiment(
                dataset=dataset, task=task_for(policy), evaluators={"policy_accuracy": accuracy},
                experiment_name=f"{correction_id}-{name}", experiment_metadata={"project_id": project_id, "release_id": release["id"]},
                print_summary=False, retries=0, timeout=5,
            )
            runs[name] = run["experiment_id"]
        template = dlp.scan(str(candidate.get("prompt_guard_suffix", ""))).safe_text
        digest = hashlib.sha256(template.encode()).hexdigest()
        with self.db.transaction() as conn:
            if self.db.backend == "postgresql":
                conn.execute("SELECT pg_advisory_xact_lock(hashtext(?))", (f"prompt:{project_id}",))
            row = conn.execute("SELECT MAX(version) AS version FROM prompt_versions WHERE project_id = ? AND name = 'security_guard'", (project_id,)).fetchone()
            version = int(row["version"] or 0) + 1
            conn.execute("INSERT INTO prompt_versions (id, project_id, name, version, template, sha256, created_at) VALUES (?, ?, 'security_guard', ?, ?, ?, ?)",
                         (new_id("prompt"), project_id, version, template, digest, utc_now()))
        from phoenix.client.types import PromptVersion
        self.client.prompts.create(
            name=f"agenttrust-{project_id}-security-guard",
            version=PromptVersion([{"role": "system", "content": template}], model_name="policy-only", template_format="NONE"),
            prompt_metadata={"project_id": project_id, "sha256": digest},
        )
        receipt = {"status": "exported", "exported": True, "experiments": runs, "prompt_sha256": digest, "cases": len(cases)}
        self.db.audit(project_id, "phoenix.experiment_exported", "Exported built-in security experiments", receipt)
        return receipt

    def replay_trace(self, project_id: str, trace_id: str) -> dict[str, Any]:
        trace = self.db.query_one("SELECT * FROM traces WHERE project_id = ? AND id = ?", (project_id, trace_id))
        if not trace:
            raise KeyError(trace_id)
        details = json.loads(trace["details_json"])
        engine = PolicyEngine()
        decision = engine.inspect_input(trace["input_text"], None, self.db.active_policy(project_id))
        tool = engine.inspect_tool(details.get("tool_name"), self.db.active_policy(project_id), None)
        return {"trace_id": trace_id, "mode": "policy-only-redacted-replay", "side_effects": False,
                "original_status": trace["status"], "input_decision": decision.__dict__, "tool_decision": tool.__dict__,
                "limitation": "Stored trace is redacted and may not include original retrieved context; this is not a ground-truth label."}
