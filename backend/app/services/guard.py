from __future__ import annotations

import hashlib
import json
from typing import Any

from ..db import Database, new_id, utc_now
from ..policy_schema import validate_policy
from ..schemas import GuardCheckRequest, GuardCheckResponse
from .dlp import DLPService
from .policy import PolicyDecision, PolicyEngine
from .security_response import SecurityResponseService


class GuardService:
    """Fail-closed checks that an Agent calls at each trust boundary."""

    _SENSITIVE_TOOL_MARKERS = ("credential", "secret", "token", "keychain", "vault")
    _EGRESS_TOOL_MARKERS = ("email", "network", "http", "webhook", "upload", "publish", "send", "export")
    _SIDE_EFFECT_MARKERS = (
        "write", "create", "update", "delete", "execute", "payment", "refund",
        "transfer", "device", "message", "database", "file",
    )

    def __init__(
        self,
        db: Database,
        policy_engine: PolicyEngine,
        dlp: DLPService,
        security_response: SecurityResponseService,
    ) -> None:
        self.db = db
        self.policy_engine = policy_engine
        self.dlp = dlp
        self.security_response = security_response

    def check(self, request: GuardCheckRequest) -> GuardCheckResponse:
        project = self.db.query_one("SELECT id FROM projects WHERE id = ?", (request.project_id,))
        if not project:
            raise KeyError(request.project_id)
        self.security_response.assert_runtime_enabled(request.project_id)
        policy = validate_policy(self.db.active_policy(request.project_id))
        policy_version = self.db.active_policy_version(request.project_id)

        history = self.session_provenance(request.project_id, request.session_id, limit=500)
        historical_labels = {
            str(label)
            for event in history["events"]
            for label in event.get("labels", [])
        }
        parent_guard_ids = self._validated_parents(request, history["events"])
        session_labels = historical_labels | set(request.provenance_labels)
        if request.phase == "input":
            session_labels.add("user_controlled")
        if request.phase in {"context", "tool_result"}:
            session_labels.add("untrusted_content")
        if request.phase in {"context", "tool_result"} and any(
            marker in request.source.lower() for marker in ("rag", "memory", "mcp", "a2a", "network", "external")
        ):
            session_labels.add("external_network")

        safe_text: str | None = None
        findings: list[dict[str, Any]] = []
        if request.phase == "tool":
            canonical = json.dumps(
                {"tool_name": request.tool_name, "tool_arguments": request.tool_arguments},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            dlp_result = self.dlp.inspect_and_record(
                request.project_id, request.tool_arguments, direction="input", action="block"
            )
            findings = dlp_result.findings
            redacted_arguments = self.dlp.redact_value(request.tool_arguments)
            dlp_blocked = dlp_result.blocked or redacted_arguments != request.tool_arguments
            policy_decision = self.policy_engine.inspect_tool(request.tool_name, policy, None)
        else:
            canonical = request.text or ""
            direction = "output" if request.phase == "output" else "input"
            dlp_result = self.dlp.inspect_and_record(
                request.project_id, canonical, direction=direction
            )
            findings = dlp_result.findings
            dlp_blocked = dlp_result.blocked
            safe_text = dlp_result.safe_text
            policy_decision = (
                self.policy_engine.inspect_output(safe_text, policy)
                if request.phase == "output"
                else self.policy_engine.inspect_input(
                    safe_text if request.phase == "input" else "",
                    safe_text if request.phase in {"context", "tool_result"} else None,
                    policy,
                )
            )

        if findings:
            session_labels.add("sensitive_data")
        if request.phase == "tool_result" and self._is_sensitive_tool(request.tool_name):
            session_labels.add("sensitive_source")

        decision = self._combine(policy_decision, dlp_blocked)
        sequence_risk = "none"
        if request.phase == "tool":
            sequence_action, sequence_risk, sequence_reasons = self._sequence_decision(
                request.tool_name, session_labels
            )
            decision = self._combine_sequence(
                decision, sequence_action, sequence_reasons
            )
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        guard_id = new_id("guard")
        provenance_id = new_id("prov")
        finding_summary = [
            {"type": item.get("type"), "severity": item.get("severity"), "category": item.get("category")}
            for item in findings
        ]
        self.db.audit(
            request.project_id,
            f"guard.{request.phase}.{decision.action}",
            f"Embedded guard {request.phase} decision: {decision.action}",
            {
                "guard_id": guard_id,
                "session_id": request.session_id,
                "source": request.source,
                "phase": request.phase,
                "action": decision.action,
                "risk_level": decision.risk_level,
                "reasons": decision.reasons,
                "tool_name": request.tool_name,
                "content_sha256": digest,
                "policy_version": policy_version,
                "dlp_findings": finding_summary,
                "provenance_id": provenance_id,
                "provenance_labels": sorted(session_labels),
                "parent_guard_ids": parent_guard_ids,
                "sequence_risk": sequence_risk,
            },
            actor=f"embedded:{request.source}",
        )
        self.db.execute(
            """
            INSERT INTO provenance_events
            (id, project_id, session_id, guard_id, phase, source, tool_name,
             decision, risk_level, sequence_risk, content_sha256, labels_json,
             parent_guard_ids_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                provenance_id,
                request.project_id,
                request.session_id,
                guard_id,
                request.phase,
                request.source,
                request.tool_name,
                decision.action,
                decision.risk_level,
                sequence_risk,
                digest,
                json.dumps(sorted(session_labels), ensure_ascii=False),
                json.dumps(parent_guard_ids, ensure_ascii=False),
                utc_now(),
            ),
        )
        return GuardCheckResponse(
            guard_id=guard_id,
            project_id=request.project_id,
            session_id=request.session_id,
            phase=request.phase,
            action=decision.action,
            risk_level=decision.risk_level,
            reasons=decision.reasons,
            policy_version=policy_version,
            safe_text=safe_text,
            content_sha256=digest,
            provenance_id=provenance_id,
            parent_guard_ids=parent_guard_ids,
            session_labels=sorted(session_labels),
            sequence_risk=sequence_risk,
        )

    def session_provenance(
        self, project_id: str, session_id: str, *, limit: int = 500
    ) -> dict[str, Any]:
        rows = self.db.query_all(
            """
            SELECT * FROM provenance_events
            WHERE project_id = ? AND session_id = ?
            ORDER BY created_at DESC LIMIT ?
            """,
            (project_id, session_id, limit),
        )
        events: list[dict[str, Any]] = []
        for row in reversed(rows):
            event = dict(row)
            event["labels"] = json.loads(event.pop("labels_json"))
            event["parent_guard_ids"] = json.loads(event.pop("parent_guard_ids_json"))
            events.append(event)
        labels = sorted({label for event in events for label in event["labels"]})
        return {
            "project_id": project_id,
            "session_id": session_id,
            "labels": labels,
            "tainted": any(label in labels for label in ("untrusted_content", "sensitive_data", "sensitive_source")),
            "events": events,
        }

    def list_provenance(self, project_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.db.query_all(
            "SELECT * FROM provenance_events WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
            (project_id, limit),
        )
        events: list[dict[str, Any]] = []
        for row in rows:
            event = dict(row)
            event["labels"] = json.loads(event.pop("labels_json"))
            event["parent_guard_ids"] = json.loads(event.pop("parent_guard_ids_json"))
            events.append(event)
        return events

    def _validated_parents(
        self, request: GuardCheckRequest, history: list[dict[str, Any]]
    ) -> list[str]:
        known = {str(event["guard_id"]) for event in history}
        if request.parent_guard_ids:
            requested = list(dict.fromkeys(request.parent_guard_ids))
            unknown = [guard_id for guard_id in requested if guard_id not in known]
            if unknown:
                raise ValueError("parent_guard_ids must belong to the same project and session")
            return requested
        return [str(history[-1]["guard_id"])] if history else []

    @classmethod
    def _is_sensitive_tool(cls, tool_name: str | None) -> bool:
        name = (tool_name or "").lower()
        return any(marker in name for marker in cls._SENSITIVE_TOOL_MARKERS)

    @classmethod
    def _sequence_decision(
        cls, tool_name: str | None, labels: set[str]
    ) -> tuple[str, str, list[str]]:
        name = (tool_name or "").lower()
        is_egress = any(marker in name for marker in cls._EGRESS_TOOL_MARKERS)
        is_side_effect = is_egress or any(marker in name for marker in cls._SIDE_EFFECT_MARKERS)
        has_sensitive = bool({"sensitive_data", "sensitive_source"} & labels)
        if is_egress and has_sensitive:
            return (
                "block",
                "sensitive_to_egress",
                ["会话接触过敏感来源，禁止将派生数据发送到出站工具"],
            )
        if is_side_effect and "untrusted_content" in labels:
            return (
                "approval_required",
                "untrusted_to_side_effect",
                ["副作用工具受到不可信上下文影响，需要独立人工批准和参数绑定租约"],
            )
        return "allow", "none", []

    @staticmethod
    def _combine_sequence(
        policy: PolicyDecision, action: str, reasons: list[str]
    ) -> PolicyDecision:
        if action == "allow" or policy.action == "block":
            return policy
        combined = list(dict.fromkeys([*policy.reasons, *reasons]))
        if action == "block":
            return PolicyDecision("block", "critical", combined)
        if policy.action == "approval_required":
            return PolicyDecision("approval_required", policy.risk_level, combined)
        return PolicyDecision("approval_required", "high", combined)

    @staticmethod
    def _combine(policy: PolicyDecision, dlp_blocked: bool) -> PolicyDecision:
        if not dlp_blocked:
            return policy
        reasons = [*policy.reasons, "内容包含不允许进入该边界的敏感数据"]
        return PolicyDecision("block", "critical", list(dict.fromkeys(reasons)))
