from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException

from ..api_utils import decode_rows
from ..db import Database, new_id, utc_now
from ..schemas import EvaluationDatasetCreate, EvaluationRequest, RedTeamRequest
from ..services.evaluation import EvaluationService
from ..services.evidence import build_run_manifest, compare_case_results
from ..services.redteam import RedTeamService


def create_evaluations_router(
    db: Database,
    evaluation_service: EvaluationService,
    red_team_service: RedTeamService,
    *,
    build_revision: str | None,
) -> APIRouter:
    router = APIRouter(tags=["evaluations"])

    @router.post("/api/v1/evaluations/run")
    def run_evaluation(payload: EvaluationRequest) -> dict[str, Any]:
        try:
            policy = db.active_policy(payload.project_id)
        except KeyError:
            raise HTTPException(404, "Project not found") from None
        dataset = db.query_one(
            """
            SELECT * FROM evaluation_datasets
            WHERE id = ? AND (project_id = ? OR id = 'dataset_core_security_v1')
            """,
            (payload.dataset_id, payload.project_id),
        )
        if not dataset:
            raise HTTPException(404, "Evaluation dataset not found")
        cases = json.loads(dataset["cases_json"])
        graders = json.loads(dataset["graders_json"])
        result = evaluation_service.evaluate_cases(policy, cases, graders)
        run_id = new_id("eval")
        project = db.query_one(
            "SELECT adapter, model FROM projects WHERE id = ?", (payload.project_id,)
        )
        if not project:
            raise HTTPException(404, "Project not found")
        created_at = utc_now()
        manifest = build_run_manifest(
            run_id=run_id,
            run_type="policy_evaluation",
            project_id=payload.project_id,
            created_at=created_at,
            policy_version=db.active_policy_version(payload.project_id),
            policy=policy,
            dataset_sha256=result["dataset_sha256"],
            model_snapshot=str(project["model"]),
            model_executed=False,
            build_revision=build_revision,
            random_seed=None,
            configuration={
                "name": payload.name,
                "dataset_id": payload.dataset_id,
                "graders": graders,
                "scope": result["scope"],
            },
            results=result["results"],
            cost_usd=None,
        )
        db.execute(
            """
            INSERT INTO evaluation_runs
            (id, project_id, name, pass_rate, average_score, cases_total,
             cases_passed, results_json, manifest_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                payload.project_id,
                payload.name,
                result["pass_rate"],
                result["average_score"],
                result["cases_total"],
                result["cases_passed"],
                json.dumps(result["results"], ensure_ascii=False),
                json.dumps(manifest, ensure_ascii=False),
                created_at,
            ),
        )
        db.audit(
            payload.project_id,
            "evaluation.completed",
            f"{payload.name}：通过率 {result['pass_rate']:.0%}",
            {"run_id": run_id},
        )
        return {
            "id": run_id,
            "name": payload.name,
            "dataset_id": payload.dataset_id,
            "manifest": manifest,
            **result,
        }

    @router.get("/api/v1/evaluation-datasets")
    def list_evaluation_datasets(project_id: str = "proj_demo") -> list[dict[str, Any]]:
        return decode_rows(
            db.query_all(
                "SELECT * FROM evaluation_datasets WHERE project_id = ? ORDER BY created_at DESC",
                (project_id,),
            ),
            "cases_json",
            "graders_json",
        )

    @router.post("/api/v1/evaluation-datasets", status_code=201)
    def create_evaluation_dataset(payload: EvaluationDatasetCreate) -> dict[str, Any]:
        if not db.query_one("SELECT id FROM projects WHERE id = ?", (payload.project_id,)):
            raise HTTPException(404, "Project not found")
        dataset_id = new_id("dataset")
        now = utc_now()
        db.execute(
            """
            INSERT INTO evaluation_datasets
            (id, project_id, name, description, cases_json, graders_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                dataset_id,
                payload.project_id,
                payload.name,
                payload.description,
                json.dumps([case.model_dump() for case in payload.cases], ensure_ascii=False),
                json.dumps(payload.graders, ensure_ascii=False),
                now,
                now,
            ),
        )
        db.audit(
            payload.project_id,
            "evaluation.dataset_created",
            f"创建评测数据集 {payload.name}",
            {"dataset_id": dataset_id, "cases": len(payload.cases)},
        )
        row = db.query_one("SELECT * FROM evaluation_datasets WHERE id = ?", (dataset_id,)) or {}
        return decode_rows([row], "cases_json", "graders_json")[0]

    @router.get("/api/v1/evaluations")
    def list_evaluations(project_id: str = "proj_demo") -> list[dict[str, Any]]:
        return decode_rows(
            db.query_all(
                "SELECT * FROM evaluation_runs WHERE project_id = ? ORDER BY created_at DESC",
                (project_id,),
            ),
            "results_json",
            "manifest_json",
        )

    @router.get("/api/v1/evaluations/{run_id}/manifest")
    def get_evaluation_manifest(run_id: str, project_id: str = "proj_demo") -> dict[str, Any]:
        row = db.query_one(
            "SELECT manifest_json FROM evaluation_runs WHERE id = ? AND project_id = ?",
            (run_id, project_id),
        )
        if not row:
            raise HTTPException(404, "Evaluation run not found")
        return json.loads(row["manifest_json"])

    @router.get("/api/v1/evaluations/compare/runs")
    def compare_evaluation_runs(
        baseline_id: str,
        candidate_id: str,
        project_id: str = "proj_demo",
    ) -> dict[str, Any]:
        rows = db.query_all(
            """
            SELECT id, pass_rate, results_json, manifest_json FROM evaluation_runs
            WHERE project_id = ? AND id IN (?, ?)
            """,
            (project_id, baseline_id, candidate_id),
        )
        indexed = {row["id"]: row for row in rows}
        if baseline_id not in indexed or candidate_id not in indexed:
            raise HTTPException(404, "Baseline or candidate evaluation run not found")
        baseline = indexed[baseline_id]
        candidate = indexed[candidate_id]
        return {
            "baseline_id": baseline_id,
            "candidate_id": candidate_id,
            "pass_rate_delta": round(
                float(candidate["pass_rate"]) - float(baseline["pass_rate"]), 4
            ),
            "baseline_manifest": json.loads(baseline["manifest_json"]),
            "candidate_manifest": json.loads(candidate["manifest_json"]),
            **compare_case_results(
                json.loads(baseline["results_json"]),
                json.loads(candidate["results_json"]),
            ),
        }

    @router.post("/api/v1/red-team/run")
    async def run_red_team(payload: RedTeamRequest) -> dict[str, Any]:
        if not db.query_one("SELECT id FROM projects WHERE id = ?", (payload.project_id,)):
            raise HTTPException(404, "Project not found")
        try:
            return await red_team_service.run(
                payload.project_id,
                payload.auto_correct,
                payload.plugins,
                payload.strategies,
                payload.max_turns,
                payload.max_cost_usd,
                payload.stop_on_block,
                payload.random_seed,
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.get("/api/v1/red-team/plugins")
    def list_red_team_plugins() -> list[dict[str, Any]]:
        return red_team_service.plugins()

    @router.get("/api/v1/red-team/runs")
    def list_red_team_runs(project_id: str = "proj_demo") -> list[dict[str, Any]]:
        return decode_rows(
            db.query_all(
                "SELECT * FROM red_team_runs WHERE project_id = ? ORDER BY created_at DESC",
                (project_id,),
            ),
            "results_json",
            "manifest_json",
        )

    @router.get("/api/v1/red-team/runs/{run_id}/manifest")
    def get_red_team_manifest(run_id: str, project_id: str = "proj_demo") -> dict[str, Any]:
        row = db.query_one(
            "SELECT manifest_json FROM red_team_runs WHERE id = ? AND project_id = ?",
            (run_id, project_id),
        )
        if not row:
            raise HTTPException(404, "Red-team run not found")
        return json.loads(row["manifest_json"])

    return router

