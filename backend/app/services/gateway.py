from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from ..config import settings
from ..db import Database, new_id, utc_now
from ..schemas import GatewayRequest, GatewayResponse
from .agent_runtime import AgentRuntime
from .correction import CorrectionService
from .dlp import DLPService
from .evaluation import EvaluationService
from .observability import ObservabilityService
from .policy import PolicyDecision, PolicyEngine
from .release_guard import ReleaseGuard
from .security_intelligence import SecurityIntelligenceService
from .security_response import SecurityResponseService


class GatewayService:
    def __init__(
        self,
        db: Database,
        policy_engine: PolicyEngine,
        runtime: AgentRuntime,
        evaluation: EvaluationService,
        correction: CorrectionService,
        observability: ObservabilityService | None = None,
        dlp: DLPService | None = None,
        security_response: SecurityResponseService | None = None,
        security_intelligence: SecurityIntelligenceService | None = None,
    ):
        self.db = db
        self.policy_engine = policy_engine
        self.runtime = runtime
        self.evaluation = evaluation
        self.correction = correction
        self.observability = observability
        self.dlp = dlp
        self.security_response = security_response
        self.security_intelligence = security_intelligence

    async def invoke(
        self, request: GatewayRequest, enable_auto_correct: bool = True, *, trusted_approval: bool = False,
    ) -> GatewayResponse:
        metadata = dict(request.metadata)
        metadata.setdefault("session_id", new_id("session"))
        request = request.model_copy(update={"metadata": metadata})
        guard = ReleaseGuard(self.db)
        selection = guard.select(request.project_id, str(request.metadata.get("session_id") or new_id("session")))
        started = time.perf_counter()
        try:
            response = await self._invoke(request, enable_auto_correct, trusted_approval=trusted_approval, selection=selection)
        except Exception:
            if selection:
                guard.record(selection, request, "failed", int((time.perf_counter() - started) * 1000))
            raise
        response.details["security_session_id"] = metadata["session_id"]
        if selection:
            response.details["release_id"] = selection["release"]["id"]
            response.details["cohort"] = selection["cohort"]
            response.details["release_traffic_id"] = guard.record(selection, request, response.status, int((time.perf_counter() - started) * 1000))
        return response

    async def _invoke(
        self,
        request: GatewayRequest,
        enable_auto_correct: bool = True,
        *,
        trusted_approval: bool = False,
        selection: dict[str, Any] | None = None,
    ) -> GatewayResponse:
        if self.security_response:
            self.security_response.assert_runtime_enabled(request.project_id)
        project = self.db.query_one("SELECT * FROM projects WHERE id = ?", (request.project_id,))
        if not project:
            raise KeyError(request.project_id)
        root_span = self.observability.start_span(
            request.project_id,
            "invoke_agent agenttrust_gateway",
            attributes={
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.agent.name": project["name"],
                "gen_ai.request.model": project["model"],
                "workflow.id": request.metadata.get("workflow_id"),
            },
        ) if self.observability else None
        policy = self.db.active_policy(request.project_id)
        from ..policy_schema import validate_policy
        policy = validate_policy(policy)
        if selection:
            policy = validate_policy(selection["candidate"] if selection["cohort"] == "candidate" else selection["baseline"])
        version = self.db.active_policy_version(request.project_id)
        session_id = str(request.metadata.get("session_id") or new_id("session"))[:160]
        ensemble = self.security_intelligence.inspect(
            request.project_id,
            session_id,
            request.message,
            request.untrusted_context,
            request.tool_name,
            policy,
        ) if self.security_intelligence else None
        if ensemble and ensemble.action == "block":
            response = self._store_terminal_trace(
                request,
                project,
                policy,
                version,
                PolicyDecision(
                    action="block",
                    risk_level=ensemble.risk_level,
                    reasons=ensemble.reasons,
                    matched_pattern="ensemble_consensus",
                ),
            )
            if root_span and self.observability:
                self.observability.end_span(root_span, "OK", {"agenttrust.status": response.status, "trace.id": response.trace_id})
            return response
        dlp_input = self.dlp.inspect_and_record(
            request.project_id,
            f"{request.message}\n{request.untrusted_context or ''}\n{json.dumps(request.tool_arguments, ensure_ascii=False)}",
            direction="input",
        ) if self.dlp else None
        if dlp_input and dlp_input.blocked:
            response = self._store_terminal_trace(
                request,
                project,
                policy,
                version,
                PolicyDecision(
                    action="block",
                    risk_level="critical",
                    reasons=["输入被 DLP 策略阻止"],
                    matched_pattern=dlp_input.findings[0]["type"],
                ),
            )
            if root_span and self.observability:
                self.observability.end_span(root_span, "OK", {"agenttrust.status": response.status, "trace.id": response.trace_id})
            return response
        runtime_request = request
        if self.dlp:
            # Scan fields independently so separator text is never introduced into a prompt.
            safe_message = self.dlp.scan(request.message, action="redact").safe_text
            safe_context = (
                self.dlp.scan(request.untrusted_context, action="redact").safe_text
                if request.untrusted_context
                else None
            )
            runtime_request = request.model_copy(
                update={"message": safe_message, "untrusted_context": safe_context,
                        "tool_arguments": self.dlp.redact_value(request.tool_arguments)}
            )
        policy_span = self.observability.start_span(
            request.project_id, "policy.evaluate", parent_span_id=root_span.id if root_span else None,
            attributes={"policy.version": version, "gen_ai.operation.name": "policy_evaluate"},
        ) if self.observability else None
        input_decision = self.policy_engine.inspect_input(
            request.message, f"{request.untrusted_context or ''}\n{json.dumps(request.tool_arguments, ensure_ascii=False)}", policy
        )
        tool_decision = self.policy_engine.inspect_tool(
            request.tool_name, policy, "internally-verified" if trusted_approval else None
        )
        terminal = self._terminal_decision(input_decision, tool_decision)
        if policy_span and self.observability:
            self.observability.end_span(policy_span, "OK", {
                "policy.input.action": input_decision.action, "policy.tool.action": tool_decision.action
            })
        if terminal:
            response = self._store_terminal_trace(request, project, policy, version, terminal)
            if root_span and self.observability:
                self.observability.end_span(root_span, "OK", {
                    "agenttrust.status": response.status, "trace.id": response.trace_id,
                    "agenttrust.risk_level": response.risk_level,
                })
            return response

        try:
            runtime_span = self.observability.start_span(
                request.project_id, f"chat {project['model']}", "CLIENT",
                parent_span_id=root_span.id if root_span else None,
                attributes={"gen_ai.operation.name": "chat", "gen_ai.request.model": project["model"]},
            ) if self.observability else None
            result = await self.runtime.invoke(
                project,
                runtime_request.message,
                runtime_request.tool_name,
                runtime_request.tool_arguments,
                runtime_request.untrusted_context,
                policy,
                settings.qwen_api_key,
                runtime_request.metadata,
            )
            if runtime_span and self.observability:
                self.observability.end_span(runtime_span, "OK", {
                    "gen_ai.usage.total_tokens": result.tokens, "gen_ai.usage.cost_usd": result.cost_usd
                })
                runtime_span = None
            dlp_output = self.dlp.inspect_and_record(
                request.project_id, {"output": result.output, "tool_calls": result.tool_calls}, direction="output"
            ) if self.dlp else None
            output_decision = self.policy_engine.inspect_output(result.output, policy)
            output = self.dlp.redact_value(result.output) if self.dlp else result.output
            blocked = output_decision.blocked or bool(dlp_output and dlp_output.blocked)
            tool_decisions = [self.policy_engine.inspect_tool(
                call.get("function", {}).get("name") or call.get("name"), policy,
                "internally-verified" if trusted_approval and call.get("name") == request.tool_name
                and call.get("arguments") == runtime_request.tool_arguments else None,
            ) for call in result.tool_calls]
            blocked = blocked or any(decision.blocked for decision in tool_decisions)
            blocked = blocked or len(result.tool_calls) > int(policy.get("max_tool_calls", 6))
            if blocked:
                output = "响应被 AgentTrust 输出防护层拦截，未返回可能包含敏感信息的内容。"
            trace_eval = self.evaluation.evaluate_trace(
                runtime_request.message,
                runtime_request.untrusted_context,
                result.output,
                blocked,
                request.tool_name,
                policy,
            )
            status = "completed" if trace_eval.passed else "failed"
            if any(decision.action == "approval_required" for decision in tool_decisions):
                status = "approval_required"
            if blocked:
                status = "blocked"
            trace_id = new_id("trace")
            details = {
                "input_policy": input_decision.__dict__,
                "tool_policy": tool_decision.__dict__,
                "output_policy": output_decision.__dict__,
                "tool_calls": self.dlp.redact_value(result.tool_calls) if self.dlp else result.tool_calls,
                "tokens": result.tokens,
                "cost_usd": result.cost_usd,
                "findings": trace_eval.findings,
                "tool_name": request.tool_name,
                "policy_version": version,
                "policy_sha256": hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest(),
                "evaluation_scope": "policy-only; score is heuristic",
                "model_snapshot": {"model": project["model"], "adapter": project["adapter"]},
                "runtime": result.runtime_metadata,
                "security_session_id": session_id,
                "ensemble": {
                    "score": ensemble.score,
                    "risk_level": ensemble.risk_level,
                    "detectors": ensemble.detectors,
                } if ensemble else None,
                "dlp": {
                    "input_findings": len(dlp_input.findings) if dlp_input else 0,
                    "output_findings": len(dlp_output.findings) if dlp_output else 0,
                    "output_blocked": bool(dlp_output and dlp_output.blocked),
                },
            }
            self._insert_trace(
                trace_id,
                runtime_request,
                output,
                status,
                "critical" if blocked else ("high" if not trace_eval.passed else "low"),
                trace_eval.score,
                result.latency_ms,
                result.cost_usd,
                blocked,
                trace_eval.failure_type,
                details,
            )
            correction_id: str | None = None
            if not trace_eval.passed and enable_auto_correct and not (selection and selection["release"]["stage"] == "canary"):
                attack = self.policy_engine.detect_missed_attack(
                    request.message, request.untrusted_context
                )
                correction = self.correction.propose_from_trace(
                    project,
                    self.db.query_one("SELECT * FROM traces WHERE id = ?", (trace_id,)) or {},
                    attack[0] if attack else None,
                )
                correction_id = correction.correction_id
            response = GatewayResponse(
                trace_id=trace_id,
                status=status,
                output=output,
                blocked=blocked,
                risk_level="critical" if blocked else ("high" if not trace_eval.passed else "low"),
                score=trace_eval.score,
                policy_version=version,
                latency_ms=result.latency_ms,
                correction_id=correction_id,
                details=details,
            )
            if root_span and self.observability:
                self.observability.end_span(root_span, "OK" if status != "failed" else "ERROR", {
                    "agenttrust.status": status, "trace.id": trace_id, "agenttrust.score": trace_eval.score,
                })
            return response
        except Exception as exc:  # noqa: BLE001 - gateway is the error-containment boundary
            if 'runtime_span' in locals() and runtime_span and self.observability:
                self.observability.end_span(runtime_span, "ERROR", {"error.type": type(exc).__name__})
            trace_id = new_id("trace")
            details = {
                "error": type(exc).__name__,
                "message": "Upstream agent execution failed; inspect server logs and the audit trail.",
                "policy_version": version,
            }
            self._insert_trace(
                trace_id,
                request,
                "Agent 执行失败，已保留轨迹供诊断。",
                "failed",
                "medium",
                0.2,
                0,
                0.0,
                False,
                "runtime_error",
                details,
            )
            response = GatewayResponse(
                trace_id=trace_id,
                status="failed",
                output="Agent 执行失败，已保留轨迹供诊断。",
                blocked=False,
                risk_level="medium",
                score=0.2,
                policy_version=version,
                latency_ms=0,
                details=details,
            )
            if root_span and self.observability:
                self.observability.end_span(root_span, "ERROR", {
                    "agenttrust.status": "failed", "trace.id": trace_id, "error.type": type(exc).__name__,
                })
            return response

    @staticmethod
    def _terminal_decision(
        input_decision: PolicyDecision, tool_decision: PolicyDecision
    ) -> PolicyDecision | None:
        if input_decision.blocked:
            return input_decision
        if tool_decision.action in {"block", "approval_required"}:
            return tool_decision
        return None

    def _store_terminal_trace(
        self,
        request: GatewayRequest,
        project: dict[str, Any],
        policy: dict[str, Any],
        version: int,
        decision: PolicyDecision,
    ) -> GatewayResponse:
        del project, policy
        trace_id = new_id("trace")
        approval_required = decision.action == "approval_required"
        status = "approval_required" if approval_required else "blocked"
        output = (
            "该操作需要人工审批。审批通过后，可携带一次性 approval_token 重新执行。"
            if approval_required
            else "请求已被 AgentTrust 策略引擎阻止。"
        )
        details = {
            "reasons": decision.reasons,
            "matched_pattern": decision.matched_pattern,
            "tool_name": request.tool_name,
            "policy_version": version,
        }
        stored_request = request
        if self.dlp:
            stored_request = request.model_copy(
                update={
                    "message": self.dlp.scan(request.message, action="redact").safe_text,
                    "untrusted_context": (
                        self.dlp.scan(request.untrusted_context, action="redact").safe_text
                        if request.untrusted_context
                        else None
                    ),
                }
            )
        self._insert_trace(
            trace_id,
            stored_request,
            output,
            status,
            decision.risk_level,
            0.98 if not approval_required else 0.92,
            4,
            0.0,
            not approval_required,
            None,
            details,
        )
        self.db.audit(
            request.project_id,
            f"gateway.{status}",
            "; ".join(decision.reasons),
            {"trace_id": trace_id, "tool_name": request.tool_name},
        )
        return GatewayResponse(
            trace_id=trace_id,
            status=status,
            output=output,
            blocked=not approval_required,
            risk_level=decision.risk_level,
            score=0.98 if not approval_required else 0.92,
            policy_version=version,
            latency_ms=4,
            details=details,
        )

    def _insert_trace(
        self,
        trace_id: str,
        request: GatewayRequest,
        output: str,
        status: str,
        risk_level: str,
        score: float,
        latency_ms: int,
        cost_usd: float,
        blocked: bool,
        failure_type: str | None,
        details: dict[str, Any],
    ) -> None:
        if self.dlp:
            request = request.model_copy(update={"message": self.dlp.scan(request.message).safe_text})
            details = self.dlp.redact_value(details)
        self.db.execute(
            """
            INSERT INTO traces
            (id, project_id, input_text, output_text, status, risk_level, score,
             latency_ms, cost_usd, blocked, failure_type, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trace_id,
                request.project_id,
                request.message,
                output,
                status,
                risk_level,
                score,
                latency_ms,
                cost_usd,
                int(blocked),
                failure_type,
                json.dumps(details, ensure_ascii=False),
                utc_now(),
            ),
        )
