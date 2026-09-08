from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

from ..config import settings
from ..db import Database, new_id, utc_now
from ..schemas import GatewayRequest
from .evaluation import EvaluationService
from .policy import PolicyEngine


class ReleaseGuard:
    """Server-observed policy canary, human labels, CAS promotion and SLO rollback.

    Labels never come from an LLM grader. Candidate and control run only policy
    evaluation; the business agent runs once, under the selected policy.
    """

    def __init__(self, db: Database, config: Any = None):
        self.db = db
        self.config = config or settings
        self.engine = PolicyEngine()

    def select(self, project_id: str, session_id: str) -> dict[str, Any] | None:
        release = self.db.query_one(
            "SELECT * FROM correction_releases WHERE project_id = ? AND stage IN ('canary', 'active') ORDER BY created_at DESC LIMIT 1",
            (project_id,),
        )
        if not release:
            return None
        version = self.db.active_policy_version(project_id)
        correction = self.db.query_one("SELECT policy_version FROM corrections WHERE id = ?", (release["correction_id"],)) or {}
        expected = release["baseline_version"] if release["stage"] == "canary" else correction.get("policy_version")
        if version != expected:
            return None  # Never silently overwrite a later manual policy deployment.
        secret = self.config.audit_anchor_secret or "development-canary-key"
        digest = hmac.new(secret.encode(), f"{project_id}:{session_id}".encode(), hashlib.sha256).digest()
        candidate = release["stage"] == "active" or int.from_bytes(digest[:4], "big") % 100 < self.config.correction_canary_percent
        return {
            "release": release,
            "baseline": self.db.policy_at_version(project_id, release["baseline_version"]),
            "candidate": json.loads(release["candidate_rules_json"]),
            "cohort": "candidate" if candidate else "control",
        }

    def action(self, request: GatewayRequest, policy: dict[str, Any]) -> str:
        input_decision = self.engine.inspect_input(request.message, request.untrusted_context, policy)
        tool = self.engine.inspect_tool(request.tool_name, policy, None)
        return "block" if input_decision.blocked or tool.blocked else tool.action

    def record(self, selection: dict[str, Any], request: GatewayRequest, status: str, latency_ms: int) -> str:
        traffic_id = new_id("traffic")
        release = selection["release"]
        self.db.execute(
            "INSERT INTO release_traffic (id, project_id, release_id, cohort, baseline_action, candidate_action, outcome, latency_ms, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (traffic_id, request.project_id, release["id"], selection["cohort"],
             self.action(request, selection["baseline"]), self.action(request, selection["candidate"]),
             "error" if status == "failed" else "success", latency_ms, utc_now()),
        )
        # Runtime errors can roll back an active release even before new labels arrive.
        if release["stage"] == "active":
            self.review(release["correction_id"])
        return traffic_id

    def label(self, correction_id: str, traffic_id: str, expected_action: str, reason: str, actor: str) -> dict[str, Any]:
        from .dlp import DLPService
        traffic = self.db.query_one(
            "SELECT t.* FROM release_traffic t JOIN correction_releases r ON r.id = t.release_id WHERE t.id = ? AND r.correction_id = ?",
            (traffic_id, correction_id),
        )
        if not traffic:
            raise KeyError("Server-observed traffic does not belong to this release")
        self.db.execute(
            "INSERT OR IGNORE INTO correction_appeals (id, project_id, traffic_id, expected_action, reason, actor, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (new_id("label"), traffic["project_id"], traffic_id, expected_action, DLPService(self.db).scan(reason).safe_text, actor, utc_now()),
        )
        return self.review(correction_id)

    def review(self, correction_id: str) -> dict[str, Any]:
        release = self.db.query_one("SELECT * FROM correction_releases WHERE correction_id = ? ORDER BY created_at DESC LIMIT 1", (correction_id,))
        if not release:
            raise KeyError(correction_id)
        rows = self.db.query_all(
            "SELECT t.*, a.expected_action FROM release_traffic t LEFT JOIN correction_appeals a ON a.traffic_id = t.id WHERE t.release_id = ? ORDER BY t.created_at DESC LIMIT 5000",
            (release["id"],),
        )
        candidate_rows = [r for r in rows if r["cohort"] == "candidate"]
        labelled = [r for r in rows if r["expected_action"]]
        benign = [r for r in labelled if r["expected_action"] == "allow"]
        attacks = [r for r in labelled if r["expected_action"] != "allow"]
        fpr = sum(r["candidate_action"] != "allow" for r in benign) / len(benign) if benign else 1.0
        recall = sum(r["candidate_action"] == r["expected_action"] for r in attacks) / len(attacks) if attacks else 0.0
        errors = sum(r["outcome"] == "error" for r in candidate_rows) / len(candidate_rows) if candidate_rows else 0.0
        latency = sorted(r["latency_ms"] for r in candidate_rows)
        p95 = latency[min(len(latency) - 1, int(len(latency) * .95))] if latency else 0
        successes = sum(r["candidate_action"] == r["expected_action"] for r in labelled)
        wilson = EvaluationService.wilson_lower_bound(successes, len(labelled))
        config = self.config
        enough_labels = (len(labelled) >= config.correction_canary_min_observations
                         and len(benign) >= config.correction_canary_min_benign
                         and len(attacks) >= config.correction_canary_min_attacks)
        age = (datetime.now(UTC) - datetime.fromisoformat(release["created_at"])).total_seconds()
        enough_traffic = len(candidate_rows) >= config.correction_canary_min_observations
        accuracy_ok = fpr <= config.correction_canary_max_false_positive_rate and recall >= .95
        slo_ok = errors <= config.correction_canary_max_error_rate and p95 <= config.correction_max_latency_ms
        metrics = {
            "observations": len(labelled), "candidate_requests": len(candidate_rows),
            "control_requests": len(rows) - len(candidate_rows), "benign_labels": len(benign),
            "attack_labels": len(attacks), "false_positive_rate": fpr, "attack_recall": recall,
            "error_rate": errors, "p95_latency_ms": p95, "wilson_lower_bound_95": wilson,
            "paired_block_rate_change": round(sum((r["candidate_action"] == "block") - (r["baseline_action"] == "block") for r in rows) / max(1, len(rows)), 4),
            "decision": "collecting",
        }
        if release["stage"] == "canary" and enough_labels and enough_traffic and age >= config.correction_canary_min_seconds:
            # Require statistical evidence in addition to the point estimates.
            precision_evidence = wilson >= .80
            metrics["decision"] = self._transition(release, "active" if accuracy_ok and slo_ok and precision_evidence else "rejected")
        elif release["stage"] == "active" and (
            (enough_traffic and not slo_ok) or (enough_labels and not accuracy_ok)
        ):
            metrics["decision"] = self._transition(release, "rolled_back")
        current = self.db.query_one("SELECT * FROM correction_releases WHERE id = ?", (release["id"],)) or release
        current["candidate_rules"] = json.loads(current.pop("candidate_rules_json"))
        current["gates"] = json.loads(current.pop("gates_json"))
        current["canary"] = metrics
        return current

    def _transition(self, release: dict[str, Any], stage: str, *, manual: bool = False) -> str:
        project_id = release["project_id"]
        version: int | None = None
        with self.db.transaction() as conn:
            if self.db.backend == "postgresql":
                conn.execute("SELECT pg_advisory_xact_lock(hashtext(?))", (f"policy:{project_id}",))
            current = conn.execute("SELECT * FROM correction_releases WHERE id = ?", (release["id"],)).fetchone()
            if current["stage"] != release["stage"]:
                return "already_transitioned"
            correction = conn.execute("SELECT policy_version FROM corrections WHERE id = ?", (release["correction_id"],)).fetchone()
            active = conn.execute("SELECT version FROM policy_versions WHERE project_id = ? AND status = 'active' ORDER BY version DESC LIMIT 1", (project_id,)).fetchone()
            expected = release["baseline_version"] if stage == "active" else correction["policy_version"]
            if stage in {"active", "rolled_back"} and active["version"] != expected:
                return "policy_conflict"
            if stage in {"active", "rolled_back"}:
                rules = release["candidate_rules_json"] if stage == "active" else conn.execute(
                    "SELECT rules_json FROM policy_versions WHERE project_id = ? AND version = ?", (project_id, release["baseline_version"])
                ).fetchone()["rules_json"]
                latest = conn.execute("SELECT MAX(version) AS version FROM policy_versions WHERE project_id = ?", (project_id,)).fetchone()
                version = int(latest["version"]) + 1
                conn.execute("UPDATE policy_versions SET status = 'superseded' WHERE project_id = ? AND status = 'active'", (project_id,))
                conn.execute("INSERT INTO policy_versions (id, project_id, version, rules_json, status, reason, created_at) VALUES (?, ?, ?, ?, 'active', ?, ?)",
                             (new_id("pol"), project_id, version, rules, f"Online release {stage}: {release['id']}", utc_now()))
            conn.execute("UPDATE correction_releases SET stage = ?, rollback_version = ?, updated_at = ? WHERE id = ?",
                         (stage, version if stage == "rolled_back" else None, utc_now(), release["id"]))
            conn.execute("UPDATE corrections SET status = ?, auto_applied = ?, policy_version = COALESCE(?, policy_version) WHERE id = ?",
                         (("applied" if manual else "auto_applied") if stage == "active" else stage,
                          int(stage == "active" and not manual), version if stage == "active" else None, release["correction_id"]))
            conn.execute("UPDATE security_experiments SET status = ? WHERE correction_id = ?", (stage, release["correction_id"]))
        self.db.audit(project_id, f"correction.online_{stage}", "Online release gate transition", {"release_id": release["id"], "policy_version": version})
        return "promoted" if stage == "active" else stage
