from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_run_manifest(
    *,
    run_id: str,
    run_type: str,
    project_id: str,
    created_at: str,
    policy_version: int,
    policy: dict[str, Any],
    dataset_sha256: str,
    model_snapshot: str,
    model_executed: bool,
    build_revision: str | None,
    random_seed: int | None,
    configuration: dict[str, Any],
    results: list[dict[str, Any]],
    cost_usd: float | None,
) -> dict[str, Any]:
    """Build a secret-free, content-addressed record for a repeatable run."""
    revision = (build_revision or "").strip()
    return {
        "schema": "agenttrust.run-manifest.v1",
        "run_id": run_id,
        "run_type": run_type,
        "project_id": project_id,
        "created_at": created_at,
        "policy": {
            "version": policy_version,
            "sha256": canonical_sha256(policy),
        },
        "dataset_sha256": dataset_sha256,
        "results_sha256": canonical_sha256(results),
        "model": {
            "snapshot": model_snapshot,
            "executed": model_executed,
        },
        "build": {
            "revision": revision or "unreported",
            "revision_reported": bool(revision),
        },
        "random_seed": random_seed,
        "configuration": configuration,
        "cost": {
            "usd": round(cost_usd, 8) if cost_usd is not None else None,
            "reported": cost_usd is not None,
        },
        "limitations": (
            "Manifest hashes prove artifact identity, not benchmark independence, "
            "real-world accuracy, or production readiness."
        ),
    }


def compare_case_results(
    baseline: list[dict[str, Any]], candidate: list[dict[str, Any]]
) -> dict[str, Any]:
    """Return an explicit per-case delta instead of comparing aggregate scores only."""
    def identity(item: dict[str, Any]) -> tuple[str, str]:
        return str(item.get("name", "case")), str(item.get("category", "custom"))

    before = {identity(item): item for item in baseline}
    after = {identity(item): item for item in candidate}
    case_ids = sorted(set(before) | set(after))
    deltas: list[dict[str, Any]] = []
    counts = {"improved": 0, "regressed": 0, "unchanged": 0, "added": 0, "removed": 0}
    for case_id in case_ids:
        old = before.get(case_id)
        new = after.get(case_id)
        if old is None:
            state = "added"
        elif new is None:
            state = "removed"
        elif bool(old.get("passed")) == bool(new.get("passed")):
            state = "unchanged"
        elif bool(new.get("passed")):
            state = "improved"
        else:
            state = "regressed"
        counts[state] += 1
        deltas.append(
            {
                "name": case_id[0],
                "category": case_id[1],
                "state": state,
                "baseline": None if old is None else {
                    "actual": old.get("actual"), "passed": bool(old.get("passed"))
                },
                "candidate": None if new is None else {
                    "actual": new.get("actual"), "passed": bool(new.get("passed"))
                },
            }
        )
    return {"summary": counts, "cases": deltas}
