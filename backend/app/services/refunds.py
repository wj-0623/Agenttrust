from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any

from ..db import Database, new_id, utc_now
from ..schemas import RefundCreate
from .dlp import DLPService
from .policy import PolicyEngine
from .sandbox import SandboxService
from .security_response import SecurityResponseService


class RefundError(RuntimeError):
    def __init__(self, message: str, status_code: int = 422):
        super().__init__(message)
        self.status_code = status_code


class RefundService:
    """Security-first refund domain service used by local and Temporal execution."""

    AUTO_APPROVE_LIMIT = 50.0

    @staticmethod
    def minor_units(amount: Any) -> int:
        value = Decimal(str(amount)) * 100
        if not value.is_finite() or value != value.to_integral_value():
            raise RefundError("Invalid currency minor units")
        return int(value)

    def _existing_request(self, refund_id: str, payload: RefundCreate, digest: str) -> dict[str, Any]:
        refund = self.get(refund_id)
        if not refund.get("request_digest"):
            raise RefundError("Legacy idempotency key has no payload fingerprint; use a new key", 409)
        if refund["request_digest"] != digest or refund["project_id"] != payload.project_id:
            raise RefundError("Idempotency key is already bound to a different request", 409)
        return refund

    def __init__(
        self,
        db: Database,
        policy: PolicyEngine,
        sandbox: SandboxService,
        dlp: DLPService | None = None,
        security_response: SecurityResponseService | None = None,
    ):
        self.db = db
        self.policy = policy
        self.sandbox = sandbox
        self.dlp = dlp
        self.security_response = security_response

    def create(self, workspace_id: str, payload: RefundCreate, temporal_enabled: bool) -> dict[str, Any]:
        from .access_control import AccessControlService
        AccessControlService._require_current_workspace(workspace_id)
        if not self.db.query_one("SELECT id FROM projects WHERE id = ? AND workspace_id = ?", (payload.project_id, workspace_id)):
            raise RefundError("Project does not belong to workspace", 403)
        digest = hashlib.sha256(json.dumps(payload.model_dump(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if self.security_response:
            self.security_response.assert_runtime_enabled(payload.project_id)
        existing = self.db.query_one(
            "SELECT id FROM refund_requests WHERE workspace_id = ? AND idempotency_key = ?",
            (workspace_id, payload.idempotency_key),
        )
        if existing:
            return self._existing_request(existing["id"], payload, digest)
        order = self.db.query_one(
            "SELECT * FROM customer_orders WHERE id = ? AND project_id = ?",
            (payload.order_id, payload.project_id),
        )
        if not order:
            raise RefundError("Order not found", 404)
        decision, risk_score, risk_level = self._decision(payload, order)
        safe_reason = payload.reason
        safe_evidence = payload.evidence
        if self.dlp:
            dlp_result = self.dlp.inspect_and_record(
                payload.project_id,
                {"reason": payload.reason, "evidence": payload.evidence},
                direction="input",
            )
            safe_reason = self.dlp.redact_value(payload.reason)
            safe_evidence = self.dlp.redact_value(payload.evidence)
            if dlp_result.blocked:
                decision = {"status": "denied", "code": "DLP_BLOCK", "reasons": ["Sensitive input was blocked"]}
                risk_score, risk_level = 1.0, "critical"
        refund_id = new_id("refund")
        now = utc_now()
        status = decision["status"]
        inserted = self.db.execute(
            """
            INSERT OR IGNORE INTO refund_requests
            (id, project_id, workspace_id, idempotency_key, order_id, customer_id,
             requested_amount, approved_amount, currency, reason, evidence_json,
             risk_score, risk_level, status, decision_json, temporal_workflow_id,
             created_at, updated_at, amount_minor, request_digest)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)
            """,
            (
                refund_id,
                payload.project_id,
                workspace_id,
                payload.idempotency_key,
                payload.order_id,
                payload.customer_id,
                payload.amount,
                payload.currency,
                safe_reason,
                json.dumps(safe_evidence, ensure_ascii=False),
                risk_score,
                risk_level,
                status,
                json.dumps(decision, ensure_ascii=False),
                now,
                now,
                self.minor_units(payload.amount),
                digest,
            ),
        )
        if inserted != 1:
            concurrent = self.db.query_one(
                "SELECT id FROM refund_requests WHERE workspace_id = ? AND idempotency_key = ?",
                (workspace_id, payload.idempotency_key),
            )
            if concurrent:
                return self._existing_request(concurrent["id"], payload, digest)
            raise RefundError("Unable to reserve idempotent refund", 409)
        self._event(refund_id, "refund.requested", "customer-service-agent", decision)
        if status == "denied":
            self._incident(payload.project_id, workspace_id, "refund_security_denial", risk_level, decision)
        elif not temporal_enabled and status == "approved":
            self.issue(refund_id, "refund-policy-engine")
        self.db.audit(
            payload.project_id,
            f"refund.{status}",
            f"退款 {refund_id} 决策为 {status}",
            {"refund_id": refund_id, "order_id": payload.order_id, "risk_score": risk_score},
        )
        return self.get(refund_id)

    def _decision(self, payload: RefundCreate, order: dict[str, Any]) -> tuple[dict[str, Any], float, str]:
        reasons: list[str] = []
        security = self.policy.inspect_input(
            payload.reason,
            json.dumps(payload.evidence, ensure_ascii=False),
            self.db.active_policy(payload.project_id),
        )
        if security.blocked:
            return (
                {"status": "denied", "code": "SECURITY_POLICY", "reasons": security.reasons},
                1.0,
                "critical",
            )
        if order["customer_id"] != payload.customer_id:
            reasons.append("customer_order_mismatch")
        if order["currency"] != payload.currency:
            reasons.append("currency_mismatch")
        if order["status"] not in {"paid", "shipped", "delivered"}:
            reasons.append("order_not_refundable")
        available = order.get("refundable_minor")
        if self.minor_units(payload.amount) > (available if available is not None else self.minor_units(order["refundable_amount"])):
            reasons.append("amount_exceeds_refundable_balance")
        if reasons:
            return {"status": "denied", "code": "BUSINESS_RULE", "reasons": reasons}, 0.95, "high"
        ratio = payload.amount / max(float(order["total_amount"]), 0.01)
        risk_score = min(0.9, 0.15 + ratio * 0.35 + (0.35 if payload.amount > self.AUTO_APPROVE_LIMIT else 0.0))
        requires_review = payload.amount > self.AUTO_APPROVE_LIMIT or ratio > 0.8
        status = "waiting_approval" if requires_review else "approved"
        return (
            {
                "status": status,
                "code": "HUMAN_REVIEW" if requires_review else "LOW_RISK_AUTO_APPROVAL",
                "reasons": ["amount_threshold"] if requires_review else ["deterministic_rules_passed"],
                "auto_approve_limit": self.AUTO_APPROVE_LIMIT,
            },
            round(risk_score, 4),
            "high" if requires_review else "low",
        )

    def approve(self, refund_id: str, actor: str, reason: str, temporal_enabled: bool) -> dict[str, Any]:
        claimed = self.db.execute(
            """
            UPDATE refund_requests SET status = 'approved', approved_amount = requested_amount,
                updated_at = ? WHERE id = ? AND status = 'waiting_approval'
            """,
            (utc_now(), refund_id),
        )
        if claimed != 1:
            refund = self.get(refund_id)
            if refund["status"] not in {"approved", "completed"}:
                raise RefundError("Refund is not awaiting approval", 409)
            return refund
        self._event(refund_id, "refund.approved", actor, {"reason": reason})
        if not temporal_enabled:
            return self.issue(refund_id, actor)
        return self.get(refund_id)

    def issue(self, refund_id: str, actor: str) -> dict[str, Any]:
        refund = self.get(refund_id)
        if self.security_response:
            self.security_response.assert_runtime_enabled(refund["project_id"])
        if refund["status"] == "completed":
            return refund
        if refund["status"] != "approved":
            raise RefundError("Refund has not been approved", 409)
        amount_minor = refund.get("amount_minor") or self.minor_units(refund["requested_amount"])
        # Reserve before crossing the side-effect boundary. This transaction
        # contains no network call and also serializes competing refund requests.
        with self.db.transaction() as connection:
            claimed = connection.execute(
                "UPDATE refund_requests SET status = 'settling', updated_at = ? WHERE id = ? AND status = 'approved'",
                (utc_now(), refund_id),
            )
            if claimed.rowcount != 1:
                raise RefundError("Refund settlement is already in progress", 409)
            connection.execute(
                "UPDATE customer_orders SET refundable_minor = CAST(ROUND(refundable_amount * 100) AS BIGINT) WHERE id = ? AND refundable_minor IS NULL",
                (refund["order_id"],),
            )
            reserved = connection.execute(
                "UPDATE customer_orders SET refundable_minor = refundable_minor - ?, refundable_amount = (refundable_minor - ?) / 100.0 WHERE id = ? AND project_id = ? AND refundable_minor >= ?",
                (amount_minor, amount_minor, refund["order_id"], refund["project_id"], amount_minor),
            )
            if reserved.rowcount != 1:
                raise RefundError("Insufficient unreserved refundable balance", 409)
        arguments = {
            "refund_id": refund_id,
            "idempotency_key": refund_id,
            "order_id": refund["order_id"],
            "amount": refund["requested_amount"],
            "currency": refund["currency"],
        }
        try:
            lease = self.sandbox.issue_lease(
                refund["project_id"],
                "refund.issue",
                {
                    "arguments_sha256": self.sandbox.arguments_hash(arguments),
                    "max_amount": refund["requested_amount"],
                },
                actor,
                300,
            )
            result = self.sandbox.execute(
                refund["project_id"], "refund.issue", arguments, lease["capability_token"]
            )
        except Exception as exc:
            # A timeout does not prove that an external side effect failed.
            # Retain the reservation and require reconciliation; never reissue.
            self.db.execute(
                "UPDATE refund_requests SET status = 'unknown', updated_at = ? WHERE id = ? AND status = 'settling'",
                (utc_now(), refund_id),
            )
            self._incident(
                refund["project_id"], refund["workspace_id"], "refund_result_unknown", "critical", {"error": type(exc).__name__}
            )
            raise
        with self.db.transaction() as connection:
            claimed = connection.execute(
                """
                UPDATE refund_requests SET status = 'completed', approved_amount = requested_amount,
                    decision_json = ?, updated_at = ? WHERE id = ? AND status = 'settling'
                """,
                (json.dumps({"status": "completed", "sandbox": result}, ensure_ascii=False), utc_now(), refund_id),
            )
            if claimed.rowcount != 1:
                raise RefundError("Refund was concurrently settled", 409)
        self._event(refund_id, "refund.completed", actor, result)
        return self.get(refund_id)

    def set_temporal_workflow(self, refund_id: str, workflow_id: str) -> None:
        self.db.execute(
            "UPDATE refund_requests SET temporal_workflow_id = ?, updated_at = ? WHERE id = ?",
            (workflow_id, utc_now(), refund_id),
        )

    def get(self, refund_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM refund_requests WHERE id = ?", (refund_id,))
        if not row:
            raise RefundError("Refund not found", 404)
        row["evidence"] = json.loads(row.pop("evidence_json"))
        row["decision"] = json.loads(row.pop("decision_json"))
        events = self.db.query_all(
            "SELECT * FROM refund_events WHERE refund_id = ? ORDER BY created_at", (refund_id,)
        )
        for event in events:
            event["payload"] = json.loads(event.pop("payload_json"))
        row["events"] = events
        return row

    def list(self, project_id: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.query_all(
            "SELECT id FROM refund_requests WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
            (project_id, limit),
        )
        return [self.get(row["id"]) for row in rows]

    def _event(self, refund_id: str, event_type: str, actor: str, payload: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO refund_events (id, refund_id, event_type, actor, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (new_id("refund_event"), refund_id, event_type, actor, json.dumps(DLPService(self.db).redact_value(payload), ensure_ascii=False), utc_now()),
        )

    def _incident(
        self, project_id: str, workspace_id: str, incident_type: str, severity: str, evidence: dict[str, Any]
    ) -> None:
        now = utc_now()
        self.db.execute(
            """
            INSERT INTO security_incidents
            (id, project_id, workspace_id, incident_type, severity, status, source,
             evidence_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'open', 'refund-agent', ?, ?, ?)
            """,
            (new_id("incident"), project_id, workspace_id, incident_type, severity, json.dumps(evidence, ensure_ascii=False), now, now),
        )
