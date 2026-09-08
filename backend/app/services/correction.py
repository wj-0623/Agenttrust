from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

from ..config import settings
from ..db import Database, new_id, utc_now
from .evaluation import EvaluationService


@dataclass
class CorrectionResult:
    correction_id: str
    status: str
    auto_applied: bool
    policy_version: int | None
    before_score: float
    after_score: float
    replay_pass_rate: float


class CorrectionService:
    """Creates constrained fixes, replays them, and promotes only policy-safe changes."""

    def __init__(self, db: Database, evaluation: EvaluationService):
        self.db = db
        self.evaluation = evaluation

    def propose_from_trace(
        self,
        project: dict[str, Any],
        trace: dict[str, Any],
        signature: str | None,
    ) -> CorrectionResult:
        project_id = project["id"]
        baseline = self.db.active_policy(project_id)
        baseline_version = self.db.active_policy_version(project_id)
        candidate = copy.deepcopy(baseline)
        failure_type = trace.get("failure_type") or "quality_regression"
        title, explanation, patch, confidence = self._build_patch(
            candidate, failure_type, signature, trace
        )

        before = self.evaluation.replay_policy(baseline)
        after = self.evaluation.replay_policy(candidate)
        holdout = self.evaluation.replay_policy_holdout(candidate)
        integrity = self.evaluation.dataset_integrity()
        custom_replays = []
        for dataset in self.db.query_all(
            "SELECT id, cases_json FROM evaluation_datasets WHERE project_id = ? AND id != 'dataset_core_security_v1'", (project_id,)
        ):
            cases = json.loads(dataset["cases_json"])
            previous = self.evaluation.evaluate_cases(baseline, cases)
            proposed = self.evaluation.evaluate_cases(candidate, cases)
            custom_replays.append({"dataset_id": dataset["id"], "baseline": previous["pass_rate"],
                                   "candidate": proposed["pass_rate"], "dataset_sha256": proposed["dataset_sha256"],
                                   "regressed_cases": sum(before["passed"] and not after["passed"] for before, after in zip(previous["results"], proposed["results"], strict=True))})
        shadow_replays = [after, holdout]
        improvement = after["average_score"] - before["average_score"]
        gates = candidate.get("auto_correction", {})
        after_metrics = after.get("metrics", {})
        shadow_passes = sum(
            1
            for replay in shadow_replays
            if replay["pass_rate"] >= float(gates.get("min_replay_pass_rate", 1.0))
            and replay.get("metrics", {}).get("attack_recall", 0.0)
            >= float(gates.get("min_attack_recall", 1.0))
            and replay.get("metrics", {}).get("false_positive_rate", 1.0)
            <= float(gates.get("max_false_positive_rate", 0.0))
        )
        eligible = (
            bool(project.get("auto_correct"))
            and integrity["disjoint_inputs"]
            and all(item["regressed_cases"] == 0 for item in custom_replays)
            and gates.get("enabled", False)
            and improvement >= float(gates.get("min_improvement", 1.0))
            and after["pass_rate"] >= float(gates.get("min_replay_pass_rate", 1.0))
            and after["cases_total"] >= int(gates.get("min_eval_cases", 24))
            and after_metrics.get("attack_recall", 0.0)
            >= float(gates.get("min_attack_recall", 0.95))
            and after_metrics.get("false_positive_rate", 1.0)
            <= float(gates.get("max_false_positive_rate", 0.02))
            and after_metrics.get("wilson_lower_bound_95", 0.0)
            >= float(gates.get("min_wilson_lower_bound", 0.80))
            and shadow_passes >= int(gates.get("required_consecutive_shadow_passes", 2))
            and after.get("metrics", {}).get("false_positive_rate", 1.0)
            <= before.get("metrics", {}).get("false_positive_rate", 0.0)
            and patch.get("scope") == "policy-only"
        )

        correction_id = new_id("fix")
        version: int | None = None
        auto_promote = eligible and (
            settings.environment != "production"
            and settings.correction_auto_promote_development
        )
        status = "canary" if eligible and settings.environment == "production" else "validated"
        if auto_promote:
            version = self.db.install_policy(
                project_id,
                candidate,
                reason=f"Auto-correction {correction_id}: {failure_type}",
            )
            status = "auto_applied"

        self.db.execute(
            """
            INSERT INTO corrections
            (id, project_id, trace_id, failure_type, title, explanation, patch_json,
             confidence, before_score, after_score, replay_pass_rate, status,
             auto_applied, policy_version, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                correction_id,
                project_id,
                trace.get("id"),
                failure_type,
                title,
                explanation,
                json.dumps(patch, ensure_ascii=False),
                confidence,
                before["average_score"],
                after["average_score"],
                after["pass_rate"],
                status,
                int(auto_promote),
                version,
                utc_now(),
            ),
        )
        release_gates = {
            "stages": ["validated", "shadow_replay", "canary"] if eligible else ["validated"],
            "confidence": confidence,
            "confidence_kind": "heuristic_priority_not_probability",
            "evaluation_scope": "policy-only",
            "dataset_integrity": integrity,
            "custom_datasets": custom_replays,
            "improvement": round(improvement, 4),
            "before": before.get("metrics", {}),
            "after": after.get("metrics", {}),
            "holdout": holdout.get("metrics", {}),
            "holdout_cases_total": holdout["cases_total"],
            "cases_total": after["cases_total"],
            "shadow_replays": len(shadow_replays),
            "consecutive_shadow_passes": shadow_passes,
            "thresholds": {
                key: gates.get(key)
                for key in (
                    "min_confidence",
                    "min_improvement",
                    "min_replay_pass_rate",
                    "min_attack_recall",
                    "max_false_positive_rate",
                    "min_eval_cases",
                    "min_wilson_lower_bound",
                    "required_consecutive_shadow_passes",
                )
            },
            "passed": eligible,
        }
        now = utc_now()
        self.db.execute(
            """
            INSERT INTO correction_releases
            (id, correction_id, project_id, baseline_version, candidate_rules_json,
             stage, gates_json, rollback_version, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
            """,
            (
                new_id("release"), correction_id, project_id, baseline_version,
                json.dumps(candidate, ensure_ascii=False), "active" if auto_promote else status,
                json.dumps(release_gates, ensure_ascii=False), now, now,
            ),
        )
        self.db.execute(
            """
            INSERT INTO security_experiments
            (id, project_id, correction_id, name, dataset_name, baseline_metrics_json,
             candidate_metrics_json, holdout_metrics_json, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id("experiment"),
                project_id,
                correction_id,
                f"Auto-correction {failure_type}",
                "core-security-regression + synthetic-holdout",
                json.dumps(before.get("metrics", {}), ensure_ascii=False),
                json.dumps(after.get("metrics", {}), ensure_ascii=False),
                json.dumps(holdout.get("metrics", {}), ensure_ascii=False),
                "promoted" if auto_promote else status,
                now,
            ),
        )
        self.db.audit(
            project_id,
            "correction.auto_applied" if auto_promote else (
                "correction.canary_started" if eligible else "correction.validated"
            ),
            f"{title}；回放通过率 {after['pass_rate']:.0%}",
            {
                "correction_id": correction_id,
                "before": before["average_score"],
                "after": after["average_score"],
                "policy_version": version,
            },
        )
        return CorrectionResult(
            correction_id=correction_id,
            status=status,
            auto_applied=auto_promote,
            policy_version=version,
            before_score=before["average_score"],
            after_score=after["average_score"],
            replay_pass_rate=after["pass_rate"],
        )


    @staticmethod
    def _release_report(release: dict[str, Any]) -> dict[str, Any]:
        result = dict(release)
        result["candidate_rules"] = json.loads(result.pop("candidate_rules_json"))
        result["gates"] = json.loads(result.pop("gates_json"))
        return result

    def _build_patch(
        self,
        candidate: dict[str, Any],
        failure_type: str,
        signature: str | None,
        trace: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any], float]:
        if failure_type in {
            "prompt_injection",
            "privilege_escalation",
            "memory_poisoning",
            "data_exfiltration",
            "tool_escalation",
            "prompt_extraction",
        }:
            pattern = (signature or self._safe_signature(trace["input_text"])).lower()
            patterns = candidate.setdefault("blocked_input_patterns", [])
            # Learn from this observed failure only; never import the grader's
            # full signature list as a shortcut to passing the evaluation set.
            learned_patterns = [pattern]
            added: list[str] = []
            for item in learned_patterns:
                if item and item not in patterns:
                    patterns.append(item)
                    added.append(item)
            regex_rules = candidate.setdefault("blocked_input_regex", [])
            family_rules = [
                r"(?i)(ignore|disregard|override).{0,40}(instruction|rule|policy)",
                r"(?i)(reveal|print|expose|export|send).{0,40}(system prompt|credential|secret)",
                r"(?i)(administrator|admin).{0,40}(export|execute|override|instruction)",
            ]
            added_regex = [item for item in family_rules if item not in regex_rules]
            regex_rules.extend(added_regex)
            return (
                "补强输入攻击防护规则",
                (
                    f"失败轨迹暴露了 {failure_type} 漏检。候选修复增加攻击族规则，"
                    "回放结果仅代表合成规则评测；个人模式需要本人审核，无新增回归后才能发布。"
                ),
                {
                    "scope": "policy-only",
                    "operation": "append_attack_family",
                    "path": "/blocked_input_patterns + /blocked_input_regex",
                    "value": {"patterns": added, "regex": added_regex},
                },
                0.94,
            )
        if failure_type == "unauthorized_tool":
            details = json.loads(trace.get("details_json") or "{}")
            tool = details.get("tool_name", "unknown.tool")
            denied = candidate.setdefault("denied_tools", [])
            if tool not in denied:
                denied.append(tool)
            return (
                "收紧工具最小权限策略",
                f"工具 {tool} 在未授权条件下执行，候选修复将其加入拒绝列表。",
                {
                    "scope": "policy-only",
                    "operation": "append",
                    "path": "/denied_tools",
                    "value": tool,
                },
                0.91,
            )
        return (
            "生成待审核的质量修复建议",
            "该失败需要修改 Prompt 或业务代码，平台完成归因与回放准备，但不会自动改写生产代码。",
            {
                "scope": "prompt-review",
                "operation": "review",
                "path": "/prompt_guard_suffix",
                "value": "Add task-specific grounding and output constraints.",
            },
            0.68,
        )

    @staticmethod
    def _safe_signature(text: str) -> str:
        normalized = " ".join(text.strip().split())
        return normalized[:120]

    def approve(self, correction_id: str, actor: str, reason: str) -> dict[str, Any]:
        correction = self.db.query_one("SELECT * FROM corrections WHERE id = ?", (correction_id,))
        if not correction:
            raise KeyError(correction_id)
        if correction["status"] in {"auto_applied", "applied"}:
            return correction
        if settings.environment == "production":
            raise ValueError("Production corrections require labelled server traffic and online release gates")
        patch = json.loads(correction["patch_json"])
        if patch.get("scope") != "policy-only":
            self.db.execute(
                "UPDATE corrections SET status = 'approved_for_manual_change' WHERE id = ?",
                (correction_id,),
            )
            return self.db.query_one("SELECT * FROM corrections WHERE id = ?", (correction_id,)) or {}
        from ..policy_schema import validate_policy
        from .evaluation import HOLDOUT_CASES, REGRESSION_CASES
        from .release_guard import ReleaseGuard
        release = self.db.query_one("SELECT * FROM correction_releases WHERE correction_id = ?", (correction_id,))
        if not release or release["stage"] not in {"validated", "canary"}:
            raise ValueError("Correction is not awaiting review")
        baseline = self.db.policy_at_version(correction["project_id"], release["baseline_version"])
        candidate = validate_policy(json.loads(release["candidate_rules_json"]))
        baseline = validate_policy(baseline)
        mutable = {"blocked_input_patterns", "blocked_input_regex", "denied_tools"}
        if any(candidate[key] != baseline[key] for key in baseline if key not in mutable):
            raise ValueError("Correction changes a protected configuration field")
        if any(not set(baseline[key]).issubset(candidate[key]) for key in mutable):
            raise ValueError("Correction cannot weaken existing rules")
        datasets = [REGRESSION_CASES, HOLDOUT_CASES]
        datasets.extend(json.loads(row["cases_json"]) for row in self.db.query_all(
            "SELECT cases_json FROM evaluation_datasets WHERE project_id = ?", (correction["project_id"],)
        ))
        if not self.evaluation.dataset_integrity()["disjoint_inputs"]:
            raise ValueError("Evaluation datasets overlap")
        for cases in datasets:
            previous = self.evaluation.evaluate_cases(baseline, cases)["results"]
            proposed = self.evaluation.evaluate_cases(candidate, cases)["results"]
            if any(before["passed"] and not after["passed"] for before, after in zip(previous, proposed, strict=True)):
                raise ValueError("Correction regresses an existing evaluation case")
        outcome = ReleaseGuard(self.db)._transition(release, "active", manual=True)
        if outcome != "promoted":
            raise ValueError("Policy or correction changed; create and review a fresh candidate")
        version = self.db.active_policy_version(correction["project_id"])
        self.db.audit(
            correction["project_id"],
            "correction.approved",
            f"人工批准修复 {correction_id}",
            {"reason": reason, "policy_version": version},
            actor=actor,
        )
        return self.db.query_one("SELECT * FROM corrections WHERE id = ?", (correction_id,)) or {}

    def rollback(self, correction_id: str, actor: str, reason: str) -> dict[str, Any]:
        from .release_guard import ReleaseGuard

        correction = self.db.query_one("SELECT * FROM corrections WHERE id = ?", (correction_id,))
        release = self.db.query_one("SELECT * FROM correction_releases WHERE correction_id = ? ORDER BY created_at DESC LIMIT 1", (correction_id,))
        if not correction or not release:
            raise KeyError(correction_id)
        if release["stage"] == "rolled_back":
            return correction
        if release["stage"] == "active":
            outcome = ReleaseGuard(self.db)._transition(release, "rolled_back")
            if outcome == "policy_conflict":
                raise ValueError("Newer policy is active; refusing to overwrite it with an old rollback")
        else:
            self.db.execute("UPDATE correction_releases SET stage = 'cancelled', updated_at = ? WHERE id = ?",
                            (utc_now(), release["id"]))
            self.db.execute("UPDATE corrections SET status = 'cancelled' WHERE id = ?", (correction_id,))
        self.db.audit(correction["project_id"], "correction.rollback_review", reason, {"correction_id": correction_id}, actor=actor)
        return self.db.query_one("SELECT * FROM corrections WHERE id = ?", (correction_id,)) or {}

    def clusters(self, project_id: str) -> list[dict[str, Any]]:
        return self.db.query_all(
            """
            SELECT failure_type, COUNT(*) AS occurrences,
                   AVG(confidence) AS average_confidence,
                   MAX(created_at) AS last_seen,
                   SUM(CASE WHEN auto_applied = 1 THEN 1 ELSE 0 END) AS auto_applied
            FROM corrections WHERE project_id = ?
            GROUP BY failure_type ORDER BY occurrences DESC, last_seen DESC
            """,
            (project_id,),
        )

    def accuracy_report(self, project_id: str) -> dict[str, Any]:
        policy = self.db.active_policy(project_id)
        evaluation = self.evaluation.replay_policy(policy)
        holdout = self.evaluation.replay_policy_holdout(policy)
        releases = self.db.query_all(
            """
            SELECT stage, gates_json, created_at FROM correction_releases
            WHERE project_id = ? ORDER BY created_at DESC LIMIT 25
            """,
            (project_id,),
        )
        passed = 0
        for release in releases:
            gates = json.loads(release["gates_json"])
            passed += int(bool(gates.get("passed")))
        metrics = evaluation["metrics"]
        return {
            "project_id": project_id,
            "cases_total": evaluation["cases_total"],
            "pass_rate": evaluation["pass_rate"],
            "attack_recall": metrics.get("attack_recall", 0.0),
            "precision": metrics.get("precision", 0.0),
            "specificity": metrics.get("specificity", 0.0),
            "false_positive_rate": metrics.get("false_positive_rate", 0.0),
            "wilson_lower_bound_95": metrics.get("wilson_lower_bound_95", 0.0),
            "holdout": {
                "cases_total": holdout["cases_total"],
                "pass_rate": holdout["pass_rate"],
                **holdout["metrics"],
            },
            "meets_active_gate": (
                evaluation["pass_rate"] >= 0.8
                and metrics.get("attack_recall", 0.0) >= 0.95
                and metrics.get("false_positive_rate", 1.0) <= 0.02
                and metrics.get("wilson_lower_bound_95", 0.0) >= 0.8
                and holdout["pass_rate"] == 1.0
                and holdout["metrics"].get("false_positive_rate", 1.0) <= 0.02
            ),
            "recent_releases": len(releases),
            "promotion_gate_pass_rate": round(passed / len(releases), 4) if releases else 0.0,
            "claim": "deterministic regression evidence; not a universal real-world accuracy guarantee",
        }
