from __future__ import annotations

import hmac
import json
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .api_utils import decode_rows
from .config import settings
from .db import DEFAULT_POLICY, Database, new_id, utc_now
from .routers.evaluations import create_evaluations_router
from .schemas import (
    A2AAgentCreate,
    A2ACardUpdate,
    A2AJsonRpcRequest,
    A2ATaskCreate,
    ApiKeyCreate,
    CapabilityLeaseCreate,
    CorrectionAction,
    CorrectionObservationCreate,
    CorrectionRollbackAction,
    GatewayRequest,
    GatewayResponse,
    GuardCheckRequest,
    GuardCheckResponse,
    McpJsonRpcRequest,
    McpManifestUpdate,
    McpServerCreate,
    MembershipCreate,
    OrganizationCreate,
    PolicyUpdate,
    ProjectCreate,
    RefundAction,
    RefundCreate,
    SandboxExecuteRequest,
    SecurityControlUpdate,
    WorkflowAction,
    WorkflowCreate,
    WorkspaceCreate,
)
from .services.a2a_gateway import A2AGatewayService, A2ASecurityError
from .services.access_control import AccessControlService, AccessDenied
from .services.agent_runtime import AgentRuntime
from .services.correction import CorrectionService
from .services.dlp import DLPService
from .services.evaluation import EvaluationService
from .services.gateway import GatewayService
from .services.guard import GuardService
from .services.mcp_gateway import McpGatewayService, McpSecurityError
from .services.observability import ObservabilityService
from .services.oidc import OIDCAuthenticationError, OIDCAuthenticator
from .services.phoenix_integration import PhoenixIntegration
from .services.policy import PolicyEngine
from .services.redteam import RedTeamService
from .services.refunds import RefundError, RefundService
from .services.release_guard import ReleaseGuard
from .services.sandbox import SandboxService, SandboxViolation
from .services.security_intelligence import (
    AssetGraphService,
    SecurityIntelligenceService,
)
from .services.security_response import RuntimeDisabled, SecurityResponseService
from .services.temporal_orchestrator import TemporalOrchestrator
from .services.workflows import WorkflowService
from .tenant_context import bind_workspace, reset_workspace
from .version import __version__

db = Database(
    settings.database_url or settings.database_path,
    migration_target=settings.migration_database_url,
    postgres_rls_enabled=settings.postgres_rls_enabled,
    postgres_app_role=settings.postgres_app_role,
    pool_size=settings.db_pool_size,
)
policy_engine = PolicyEngine()
evaluation_service = EvaluationService(policy_engine)
correction_service = CorrectionService(db, evaluation_service)
observability_service = ObservabilityService(db)
sandbox_service = SandboxService(db)
dlp_service = DLPService(db)
security_response_service = SecurityResponseService(db)
guard_service = GuardService(db, policy_engine, dlp_service, security_response_service)
security_intelligence_service = SecurityIntelligenceService(db, policy_engine, dlp_service)
asset_graph_service = AssetGraphService(db)
gateway_service = GatewayService(
    db,
    policy_engine,
    AgentRuntime(),
    evaluation_service,
    correction_service,
    observability_service,
    dlp_service,
    security_response_service,
    security_intelligence_service,
)
red_team_service = RedTeamService(db, gateway_service)
mcp_gateway_service = McpGatewayService(db, policy_engine, sandbox_service)
workflow_service = WorkflowService(db, gateway_service, sandbox_service, observability_service)
access_control_service = AccessControlService(db)
oidc_authenticator = OIDCAuthenticator(settings)
a2a_gateway_service = A2AGatewayService(db, policy_engine)
refund_service = RefundService(
    db, policy_engine, sandbox_service, dlp_service, security_response_service
)
temporal_orchestrator = TemporalOrchestrator()


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate_deployment()
    if settings.auto_initialize:
        db.initialize()
    db.verify_runtime_role()
    await temporal_orchestrator.connect()
    yield
    observability_service.shutdown()
    db.close()


app = FastAPI(
    title="AgentTrust API",
    description="Enterprise agent reliability, security and auto-correction control plane.",
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials="*" not in settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(
    create_evaluations_router(
        db,
        evaluation_service,
        red_team_service,
        build_revision=settings.build_revision,
    )
)


@app.exception_handler(RuntimeDisabled)
async def runtime_disabled_handler(_: Request, exc: RuntimeDisabled) -> JSONResponse:
    return JSONResponse(status_code=423, content={"detail": str(exc)})


@app.exception_handler(AccessDenied)
async def access_denied_handler(_: Request, exc: AccessDenied) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})


@app.middleware("http")
async def api_key_guard(request: Request, call_next):
    path = request.url.path
    request_id = request.headers.get("X-Request-ID", "")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", request_id):
        request_id = new_id("req")
    request.state.request_id = request_id

    body_json: dict[str, Any] = {}
    is_json = False
    if path.startswith("/api/v1/") and not settings.require_api_key:
        peer = request.client.host if request.client else ""
        if peer not in {"127.0.0.1", "::1", "testclient"}:
            return JSONResponse(status_code=403, content={"detail": "Unauthenticated personal mode is loopback-only"})
        if request.url.hostname not in {"localhost", "127.0.0.1", "::1", "testserver"}:
            return JSONResponse(status_code=403, content={"detail": "Untrusted local Host header"})
        origin = request.headers.get("origin")
        if origin and origin not in settings.cors_origins and origin != str(request.base_url).rstrip("/"):
            return JSONResponse(status_code=403, content={"detail": "Untrusted browser origin"})
    if path.startswith("/api/v1/") and request.method not in {"GET", "HEAD", "OPTIONS"}:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > settings.max_request_body_bytes:
                    response = JSONResponse(status_code=413, content={"detail": "Request body is too large"})
                    response.headers["X-Request-ID"] = request_id
                    return response
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        chunks: list[bytes] = []
        received = 0
        async for chunk in request.stream():
            received += len(chunk)
            if received > settings.max_request_body_bytes:
                response = JSONResponse(
                    status_code=413, content={"detail": "Request body is too large"}
                )
                response.headers["X-Request-ID"] = request_id
                return response
            chunks.append(chunk)
        body = b"".join(chunks)
        request._body = body
        media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        is_json = media_type == "application/json" or (media_type.startswith("application/") and media_type.endswith("+json"))
        if body and not is_json:
            return JSONResponse(status_code=415, content={"detail": "API request bodies must be JSON"})
        if body:
            try:
                parsed = json.loads(body)
                if not isinstance(parsed, dict):
                    return JSONResponse(status_code=422, content={"detail": "JSON body must be an object"})
                body_json = parsed
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
                return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})
    exempt = (
        request.method == "OPTIONS"
        or not path.startswith("/api/v1/")
        or path in {"/api/v1/access/config", "/api/v1/access/bootstrap"}
    )
    supplied = request.headers.get("X-AgentTrust-Key")
    authorization = request.headers.get("Authorization", "")
    if not supplied and authorization.startswith("Bearer at_"):
        supplied = authorization.removeprefix("Bearer ").strip()
    auth_context: dict[str, Any] | None = None
    workspace_token = None
    if not exempt and (settings.require_api_key or supplied or authorization.startswith("Bearer ")):
        try:
            required_scope = access_control_service.required_scope(request.method, path)
            if supplied:
                auth_context = access_control_service.authenticate(supplied, required_scope)
            elif authorization.startswith("Bearer "):
                claims = oidc_authenticator.verify(authorization.removeprefix("Bearer ").strip())
                auth_context = access_control_service.authenticate_oidc(
                    claims, required_scope, request.headers.get("X-AgentTrust-Workspace")
                )
            else:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "API key or OIDC Bearer token is required"},
                )
            workspace_token = bind_workspace(auth_context["workspace_id"])
            if path in {"/api/v1/access/api-keys", "/api/v1/access/memberships"}:
                body_json.setdefault("workspace_id", auth_context["workspace_id"])
            access_control_service.authorize_request_resources(
                auth_context, path, dict(request.query_params), body_json
            )
            request.state.api_key = auth_context
            request.state.auth_context = auth_context
            if (
                request.method in {"POST", "PUT", "PATCH"}
                and is_json
                and path != "/api/v1/guard/check"
            ):
                body_json["actor"] = auth_context["id"]
                request._body = json.dumps(body_json).encode("utf-8")
        except (AccessDenied, OIDCAuthenticationError) as exc:
            if workspace_token is not None:
                reset_workspace(workspace_token)
            status_code = exc.status_code if isinstance(exc, AccessDenied) else 401
            return JSONResponse(status_code=status_code, content={"detail": str(exc)})
    try:
        response = await call_next(request)
        if auth_context and auth_context.get("auth_type") == "api_key":
            access_control_service.record_usage(
                auth_context["id"],
                path,
                float(getattr(request.state, "usage_cost", 0.0)),
                auth_context.get("usage_event_id"),
            )
    finally:
        if workspace_token is not None:
            reset_workspace(workspace_token)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if path.startswith("/api/"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
    elif path not in {"/docs", "/redoc", "/openapi.json"}:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'self'"
        )
    response.headers["Cache-Control"] = "no-store"
    if settings.security_hsts_enabled:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "service": settings.app_name,
        "environment": settings.environment,
        "database": db.backend,
        "model_configured": bool(settings.qwen_api_key),
        "demo_mode": True,
        "version": __version__,
        "features": ["refund_security", "verified_auto_correction", "correction_canary", "dlp", "siem_export", "audit_anchors", "kill_switch", "postgres_rls", "temporal_workflows", "otel_phoenix", "oidc", "postgresql", "mcp_security", "a2a_security"],
    }


@app.get("/api/v1/projects")
def list_projects(request: Request) -> list[dict[str, Any]]:
    api_key = getattr(request.state, "api_key", None)
    rows = (
        access_control_service.list_projects(api_key["workspace_id"])
        if api_key
        else db.query_all("SELECT * FROM projects ORDER BY created_at DESC")
    )
    return decode_rows(rows)


@app.post("/api/v1/projects", status_code=201)
def create_project(payload: ProjectCreate, request: Request) -> dict[str, Any]:
    project_id = new_id("proj")
    api_key = getattr(request.state, "api_key", None)
    workspace_id = api_key["workspace_id"] if api_key else "ws_demo"
    endpoint = str(payload.endpoint).rstrip("/") if payload.endpoint else None
    if payload.adapter != "demo" and not endpoint:
        raise HTTPException(422, f"{payload.adapter} adapter requires endpoint")
    if payload.adapter == "openai_compatible" and endpoint not in settings.model_endpoint_allowlist:
        raise HTTPException(422, "Model endpoint must be approved in the deployment allowlist")
    if payload.adapter == "external_agent" and endpoint not in settings.external_agent_endpoint_allowlist:
        raise HTTPException(422, "External Agent endpoint must be approved in the deployment allowlist")
    db.execute(
        """
        INSERT INTO projects
        (id, workspace_id, name, description, adapter, endpoint, model, environment, auto_correct, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            workspace_id,
            payload.name,
            payload.description,
            payload.adapter,
            endpoint,
            payload.model,
            payload.environment,
            int(payload.auto_correct),
            utc_now(),
        ),
    )
    db.install_policy(project_id, DEFAULT_POLICY, "Initial project policy")
    if db.query_one("SELECT id FROM workspaces WHERE id = ?", (workspace_id,)):
        db.execute(
            "INSERT OR IGNORE INTO workspace_projects (workspace_id, project_id) VALUES (?, ?)",
            (workspace_id, project_id),
        )
    db.audit(project_id, "project.created", f"创建项目 {payload.name}")
    return db.query_one("SELECT * FROM projects WHERE id = ?", (project_id,)) or {}


@app.get("/api/v1/dashboard")
def dashboard(project_id: str = "proj_demo") -> dict[str, Any]:
    project = db.query_one("SELECT * FROM projects WHERE id = ?", (project_id,))
    if not project:
        raise HTTPException(404, "Project not found")
    metrics = db.query_one(
        """
        SELECT COUNT(*) AS total_traces,
               COALESCE(AVG(score), 0) AS average_score,
               COALESCE(AVG(latency_ms), 0) AS average_latency_ms,
               SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) AS blocked_requests,
               SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_requests,
               SUM(CASE WHEN score >= 0.8 THEN 1 ELSE 0 END) AS trusted_runs
        FROM traces WHERE project_id = ?
        """,
        (project_id,),
    ) or {}
    total = int(metrics.get("total_traces") or 0)
    trusted = int(metrics.get("trusted_runs") or 0)
    corrections = db.query_one(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN auto_applied = 1 THEN 1 ELSE 0 END) AS auto_applied
        FROM corrections WHERE project_id = ?
        """,
        (project_id,),
    ) or {"total": 0, "auto_applied": 0}
    latest_redteam = db.query_one(
        "SELECT * FROM red_team_runs WHERE project_id = ? ORDER BY created_at DESC LIMIT 1",
        (project_id,),
    )
    guard_metrics = db.query_one(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN event_type LIKE 'guard.%.block' THEN 1 ELSE 0 END) AS blocked,
               SUM(CASE WHEN event_type LIKE 'guard.%.approval_required' THEN 1 ELSE 0 END) AS approvals
        FROM audit_events WHERE project_id = ? AND event_type LIKE 'guard.%'
        """,
        (project_id,),
    ) or {"total": 0, "blocked": 0, "approvals": 0}
    recent = decode_rows(
        db.query_all(
            """
            SELECT id, status, risk_level, score, latency_ms, created_at, failure_type
            FROM traces WHERE project_id = ? ORDER BY created_at DESC LIMIT 12
            """,
            (project_id,),
        )
    )
    return {
        "project": {**project, "auto_correct": bool(project["auto_correct"])},
        "policy_version": db.active_policy_version(project_id),
        "metrics": {
            "total_traces": total,
            "trust_rate": round(trusted / total, 4) if total else 0,
            "average_score": round(float(metrics.get("average_score") or 0), 4),
            "average_latency_ms": round(float(metrics.get("average_latency_ms") or 0)),
            "blocked_requests": int(metrics.get("blocked_requests") or 0),
            "failed_requests": int(metrics.get("failed_requests") or 0),
            "corrections_total": int(corrections.get("total") or 0),
            "auto_applied": int(corrections.get("auto_applied") or 0),
            "protection_rate": float(latest_redteam["protection_rate"])
            if latest_redteam
            else 0,
            "guard_checks": int(guard_metrics.get("total") or 0),
            "guard_blocks": int(guard_metrics.get("blocked") or 0),
            "guard_approvals": int(guard_metrics.get("approvals") or 0),
        },
        "recent_traces": recent,
    }


@app.post("/api/v1/gateway/invoke", response_model=GatewayResponse)
async def invoke_agent(payload: GatewayRequest, request: Request) -> GatewayResponse:
    try:
        result = await gateway_service.invoke(payload)
        request.state.usage_cost = float(result.details.get("cost_usd", 0.0))
        return result
    except KeyError:
        raise HTTPException(404, "Project not found") from None
    except RuntimeError as exc:
        raise HTTPException(423, str(exc)) from exc


@app.post("/api/v1/guard/check", response_model=GuardCheckResponse)
def guard_check(payload: GuardCheckRequest) -> GuardCheckResponse:
    """Enforce policy at input, context, pre-tool, tool-result and output boundaries."""
    try:
        return guard_service.check(payload)
    except KeyError:
        raise HTTPException(404, "Project not found") from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeDisabled as exc:
        raise HTTPException(423, str(exc)) from exc


@app.get("/api/v1/guard/provenance")
def list_guard_provenance(
    project_id: str = "proj_demo", limit: int = Query(default=200, ge=1, le=500)
) -> list[dict[str, Any]]:
    """Return secret-free provenance nodes for investigation and portfolio demos."""
    return guard_service.list_provenance(project_id, limit=limit)


@app.get("/api/v1/guard/sessions/{session_id}/provenance")
def get_guard_session_provenance(
    session_id: str,
    project_id: str = "proj_demo",
    limit: int = Query(default=500, ge=1, le=500),
) -> dict[str, Any]:
    return guard_service.session_provenance(project_id, session_id, limit=limit)


@app.get("/api/v1/traces")
def list_traces(
    project_id: str = "proj_demo",
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, Any]]:
    return decode_rows(
        db.query_all(
            "SELECT * FROM traces WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
            (project_id, limit),
        ),
        "details_json",
    )


@app.get("/api/v1/traces/{trace_id}")
def get_trace(trace_id: str) -> dict[str, Any]:
    rows = decode_rows(
        db.query_all("SELECT * FROM traces WHERE id = ?", (trace_id,)), "details_json"
    )
    if not rows:
        raise HTTPException(404, "Trace not found")
    return rows[0]


@app.get("/api/v1/policies/{project_id}")
def get_policy(project_id: str) -> dict[str, Any]:
    try:
        return {
            "project_id": project_id,
            "version": db.active_policy_version(project_id),
            "rules": db.active_policy(project_id),
        }
    except KeyError:
        raise HTTPException(404, "Policy not found") from None


@app.put("/api/v1/policies/{project_id}")
def update_policy(project_id: str, payload: PolicyUpdate) -> dict[str, Any]:
    if not db.query_one("SELECT id FROM projects WHERE id = ?", (project_id,)):
        raise HTTPException(404, "Project not found")
    version = db.install_policy(project_id, payload.rules, payload.reason)
    db.audit(
        project_id,
        "policy.updated",
        f"人工发布策略 v{version}",
        {"reason": payload.reason},
        actor="human-reviewer",
    )
    return {"project_id": project_id, "version": version, "rules": payload.rules}


@app.get("/api/v1/corrections")
def list_corrections(project_id: str = "proj_demo") -> list[dict[str, Any]]:
    corrections = decode_rows(
        db.query_all(
            "SELECT * FROM corrections WHERE project_id = ? ORDER BY created_at DESC",
            (project_id,),
        ),
        "patch_json",
    )
    for correction in corrections:
        release = db.query_one(
            "SELECT * FROM correction_releases WHERE correction_id = ? ORDER BY created_at DESC LIMIT 1",
            (correction["id"],),
        )
        if release:
            release["candidate_rules"] = json.loads(release.pop("candidate_rules_json"))
            release["gates"] = json.loads(release.pop("gates_json"))
        correction["release"] = release
    return corrections


@app.post("/api/v1/corrections/{correction_id}/approve")
def approve_correction(correction_id: str, payload: CorrectionAction) -> dict[str, Any]:
    try:
        return decode_rows(
            [correction_service.approve(correction_id, payload.actor, payload.reason)],
            "patch_json",
        )[0]
    except KeyError:
        raise HTTPException(404, "Correction not found") from None
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/v1/corrections/{correction_id}/rollback")
def rollback_correction(correction_id: str, payload: CorrectionRollbackAction) -> dict[str, Any]:
    try:
        return decode_rows(
            [correction_service.rollback(correction_id, payload.actor, payload.reason)], "patch_json"
        )[0]
    except KeyError:
        raise HTTPException(404, "Correction or release not found") from None
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/v1/corrections/{correction_id}/canary-observations", status_code=201)
def record_correction_observation(
    correction_id: str, payload: CorrectionObservationCreate, request: Request
) -> dict[str, Any]:
    try:
        auth = getattr(request.state, "auth_context", None)
        return ReleaseGuard(db).label(
            correction_id, payload.traffic_id, payload.expected_action,
            dlp_service.scan(payload.reason).safe_text, auth["id"] if auth else "local-reviewer",
        )
    except KeyError:
        raise HTTPException(404, "Correction release not found") from None
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/api/v1/correction-clusters")
def list_correction_clusters(project_id: str = "proj_demo") -> list[dict[str, Any]]:
    return correction_service.clusters(project_id)


@app.get("/api/v1/corrections/accuracy")
def correction_accuracy(project_id: str = "proj_demo") -> dict[str, Any]:
    return correction_service.accuracy_report(project_id)


@app.get("/api/v1/refunds")
def list_refunds(
    project_id: str = "proj_demo", limit: int = Query(default=100, ge=1, le=200)
) -> list[dict[str, Any]]:
    return refund_service.list(project_id, limit)


@app.get("/api/v1/refunds/{refund_id}")
def get_refund(refund_id: str) -> dict[str, Any]:
    try:
        return refund_service.get(refund_id)
    except RefundError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@app.post("/api/v1/refunds", status_code=201)
async def create_refund(payload: RefundCreate, request: Request) -> dict[str, Any]:
    auth_context = getattr(request.state, "auth_context", None)
    workspace_id = auth_context["workspace_id"] if auth_context else "ws_demo"
    try:
        refund = refund_service.create(workspace_id, payload, settings.temporal_enabled)
        if settings.temporal_enabled and refund["status"] not in {"denied", "completed"}:
            workflow_id = await temporal_orchestrator.start_refund(refund["id"], workspace_id)
            refund_service.set_temporal_workflow(refund["id"], workflow_id)
            refund = refund_service.get(refund["id"])
        return refund
    except RefundError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
    except RuntimeError as exc:
        status_code = 423 if "kill switch" in str(exc).lower() else 503
        detail = str(exc) if status_code == 423 else "Temporal orchestration is unavailable"
        raise HTTPException(status_code, detail) from exc


@app.post("/api/v1/refunds/{refund_id}/approve")
async def approve_refund(refund_id: str, payload: RefundAction) -> dict[str, Any]:
    try:
        before = refund_service.get(refund_id)
        refund = refund_service.approve(
            refund_id, payload.actor, payload.reason, settings.temporal_enabled
        )
        if settings.temporal_enabled and before["status"] == "waiting_approval":
            workflow_id = refund.get("temporal_workflow_id")
            if not workflow_id:
                raise RefundError("Refund has no Temporal workflow", 409)
            try:
                await temporal_orchestrator.approve_refund(workflow_id)
            except Exception:
                db.execute(
                    "UPDATE refund_requests SET status = 'waiting_approval', updated_at = ? WHERE id = ? AND status = 'approved'",
                    (utc_now(), refund_id),
                )
                raise
        return refund_service.get(refund_id)
    except RefundError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(503, "Temporal approval signal failed") from exc


@app.get("/api/v1/security/incidents")
def list_security_incidents(
    project_id: str = "proj_demo", limit: int = Query(default=100, ge=1, le=200)
) -> list[dict[str, Any]]:
    return decode_rows(
        db.query_all(
            "SELECT * FROM security_incidents WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
            (project_id, limit),
        ),
        "evidence_json",
    )


@app.get("/api/v1/security/audit-integrity")
def audit_integrity(project_id: str = "proj_demo") -> dict[str, Any]:
    chain = db.verify_audit_chain(project_id)
    anchors = security_response_service.verify_anchors(project_id)
    return {**chain, "valid": chain["valid"] and anchors["valid"], "anchors": anchors}


@app.get("/api/v1/security/dlp-events")
def list_dlp_events(
    project_id: str = "proj_demo", limit: int = Query(default=100, ge=1, le=200)
) -> list[dict[str, Any]]:
    return dlp_service.list_events(project_id, limit)


@app.get("/api/v1/security/controls")
def security_controls(project_id: str = "proj_demo") -> dict[str, Any]:
    return security_response_service.controls(project_id)


@app.put("/api/v1/security/controls/kill-switch")
def update_kill_switch(
    payload: SecurityControlUpdate, project_id: str = "proj_demo"
) -> dict[str, Any]:
    try:
        return security_response_service.set_kill_switch(
            project_id, payload.enabled, payload.actor, payload.reason
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/api/v1/security/audit-anchors", status_code=201)
def create_audit_anchor(project_id: str = "proj_demo") -> dict[str, Any]:
    try:
        return security_response_service.create_anchor(project_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/v1/security/siem/export")
def export_security_findings(
    project_id: str = "proj_demo", limit: int = Query(default=100, ge=1, le=500)
) -> dict[str, Any]:
    return security_response_service.export_incidents(project_id, limit)


@app.post("/api/v1/security/outbox/deliver")
def deliver_security_outbox(project_id: str = "proj_demo") -> list[dict[str, Any]]:
    return security_response_service.deliver_pending(project_id)


@app.get("/api/v1/security/signals")
def list_security_signals(
    project_id: str = "proj_demo",
    session_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return security_intelligence_service.list_signals(project_id, session_id, limit)


@app.get("/api/v1/security/trajectories/{session_id}")
def get_security_trajectory(
    session_id: str, project_id: str = "proj_demo"
) -> dict[str, Any]:
    return security_intelligence_service.trajectory(project_id, session_id)


@app.post("/api/v1/security/assets/synchronize")
def synchronize_security_assets(project_id: str = "proj_demo") -> dict[str, Any]:
    try:
        return asset_graph_service.synchronize(project_id)
    except KeyError:
        raise HTTPException(404, "Project not found") from None


@app.get("/api/v1/security/assets")
def get_security_assets(project_id: str = "proj_demo") -> dict[str, Any]:
    return asset_graph_service.graph(project_id)


@app.get("/api/v1/mcp/servers")
def list_mcp_servers(project_id: str = "proj_demo") -> list[dict[str, Any]]:
    return mcp_gateway_service.list_servers(project_id)


@app.post("/api/v1/mcp/servers", status_code=201)
def register_mcp_server(payload: McpServerCreate) -> dict[str, Any]:
    try:
        return mcp_gateway_service.register(
            payload.project_id, payload.name, str(payload.endpoint), payload.transport, payload.manifest
        )
    except KeyError:
        raise HTTPException(404, "Project not found") from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.put("/api/v1/mcp/servers/{server_id}/manifest")
def update_mcp_manifest(server_id: str, payload: McpManifestUpdate) -> dict[str, Any]:
    try:
        return mcp_gateway_service.update_manifest(server_id, payload.manifest)
    except KeyError:
        raise HTTPException(404, "MCP server not found") from None


@app.post("/api/v1/mcp/proxy/{server_id}")
async def proxy_mcp_request(
    server_id: str,
    payload: McpJsonRpcRequest,
    approval_token: str | None = Header(default=None, alias="X-AgentTrust-Approval"),
) -> dict[str, Any]:
    try:
        return await mcp_gateway_service.proxy(server_id, payload.model_dump(), approval_token)
    except KeyError:
        raise HTTPException(404, "MCP server not found") from None
    except McpSecurityError as exc:
        raise HTTPException(exc.status_code, {"message": str(exc), "findings": exc.findings}) from exc


@app.post("/api/v1/workflows", status_code=201)
async def create_workflow(payload: WorkflowCreate, request: Request) -> dict[str, Any]:
    try:
        result = await workflow_service.create(
            payload.project_id, payload.idempotency_key, payload.message, payload.tool_name,
            payload.tool_arguments, payload.untrusted_context, payload.max_retries,
        )
        gateway_result = result.get("result", {}).get("gateway", {})
        request.state.usage_cost = float(gateway_result.get("details", {}).get("cost_usd", 0.0))
        return result
    except KeyError:
        raise HTTPException(404, "Project not found") from None
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/api/v1/workflows")
def list_workflows(
    project_id: str = "proj_demo", limit: int = Query(default=100, ge=1, le=500)
) -> list[dict[str, Any]]:
    return workflow_service.list(project_id, limit)


@app.get("/api/v1/workflows/{workflow_id}")
def get_workflow(workflow_id: str) -> dict[str, Any]:
    try:
        return workflow_service.get(workflow_id)
    except KeyError:
        raise HTTPException(404, "Workflow not found") from None


@app.post("/api/v1/workflows/{workflow_id}/approve")
async def approve_workflow(workflow_id: str, payload: WorkflowAction) -> dict[str, Any]:
    try:
        return await workflow_service.approve(workflow_id, payload.actor, payload.reason)
    except KeyError:
        raise HTTPException(404, "Workflow not found") from None
    except (ValueError, SandboxViolation) as exc:
        raise HTTPException(getattr(exc, "status_code", 422), str(exc)) from exc


@app.post("/api/v1/workflows/{workflow_id}/retry")
async def retry_workflow(workflow_id: str) -> dict[str, Any]:
    try:
        return await workflow_service.retry(workflow_id)
    except KeyError:
        raise HTTPException(404, "Workflow not found") from None


@app.post("/api/v1/workflows/{workflow_id}/compensate")
def compensate_workflow(workflow_id: str, payload: WorkflowAction) -> dict[str, Any]:
    try:
        return workflow_service.compensate(workflow_id, payload.actor, payload.reason)
    except KeyError:
        raise HTTPException(404, "Workflow not found") from None
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/v1/sandbox/leases", status_code=201)
def issue_capability_lease(payload: CapabilityLeaseCreate) -> dict[str, Any]:
    try:
        return sandbox_service.issue_lease(
            payload.project_id, payload.tool_name, payload.constraints, payload.actor, payload.ttl_seconds
        )
    except KeyError:
        raise HTTPException(404, "Project not found") from None
    except SandboxViolation as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@app.post("/api/v1/sandbox/execute")
def execute_sandbox_tool(payload: SandboxExecuteRequest) -> dict[str, Any]:
    try:
        return sandbox_service.execute(
            payload.project_id, payload.tool_name, payload.arguments,
            payload.capability_token, payload.workflow_id,
        )
    except KeyError:
        raise HTTPException(404, "Project not found") from None
    except SandboxViolation as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@app.get("/api/v1/sandbox/runs")
def list_sandbox_runs(
    project_id: str = "proj_demo", limit: int = Query(default=100, ge=1, le=500)
) -> list[dict[str, Any]]:
    return sandbox_service.list_runs(project_id, limit)


@app.get("/api/v1/observability/spans")
def list_agent_spans(
    project_id: str = "proj_demo", limit: int = Query(default=200, ge=1, le=1000)
) -> list[dict[str, Any]]:
    return observability_service.list_spans(project_id, limit)


@app.get("/api/v1/observability/metrics")
def agent_observability_metrics(project_id: str = "proj_demo") -> dict[str, Any]:
    return observability_service.metrics(project_id)


@app.get("/api/v1/observability/export")
def export_agent_spans(project_id: str = "proj_demo") -> dict[str, Any]:
    return observability_service.export_otlp_json(project_id)


@app.get("/api/v1/observability/experiments")
def list_security_experiments(project_id: str = "proj_demo") -> list[dict[str, Any]]:
    return decode_rows(
        db.query_all(
            "SELECT * FROM security_experiments WHERE project_id = ? ORDER BY created_at DESC",
            (project_id,),
        ),
        "baseline_metrics_json",
        "candidate_metrics_json",
        "holdout_metrics_json",
    )


@app.post("/api/v1/observability/phoenix/{correction_id}/publish")
def publish_phoenix_experiment(correction_id: str, project_id: str = "proj_demo") -> dict[str, Any]:
    try:
        return PhoenixIntegration(db).publish(project_id, correction_id)
    except KeyError:
        raise HTTPException(404, "Release not found in this project") from None
    except Exception as exc:
        raise HTTPException(502, "Phoenix export failed; local experiment remains available") from exc


@app.post("/api/v1/observability/replay/{trace_id}")
def replay_security_trace(trace_id: str, project_id: str = "proj_demo") -> dict[str, Any]:
    try:
        return PhoenixIntegration(db).replay_trace(project_id, trace_id)
    except KeyError:
        raise HTTPException(404, "Trace not found in this project") from None


@app.get("/api/v1/observability/prompts")
def list_prompt_versions(project_id: str = "proj_demo") -> list[dict[str, Any]]:
    return db.query_all("SELECT * FROM prompt_versions WHERE project_id = ? ORDER BY version DESC", (project_id,))


@app.get("/api/v1/access/config")
def access_config() -> dict[str, Any]:
    return {
        "require_api_key": settings.require_api_key,
        "oidc": {
            "enabled": bool(settings.oidc_issuer),
            "issuer": settings.oidc_issuer,
            "audience": settings.oidc_audience,
            "status": "discovery-ready" if settings.oidc_issuer else "not_configured",
        },
        "roles": {"viewer": ["read"], "operator": ["read", "gateway:invoke", "workflow:execute", "tool:execute", "mcp:proxy", "a2a:send"], "admin": ["*"]},
    }


@app.get("/api/v1/access/summary")
def access_summary(request: Request) -> dict[str, Any]:
    api_key = getattr(request.state, "api_key", None)
    return access_control_service.summary(api_key["workspace_id"] if api_key else None)


@app.post("/api/v1/access/bootstrap", status_code=201)
def bootstrap_api_key(payload: ApiKeyCreate, request: Request) -> dict[str, Any]:
    if settings.environment == "production" and (
        not settings.bootstrap_token or not hmac.compare_digest(
            request.headers.get("X-AgentTrust-Bootstrap", ""), settings.bootstrap_token
        )
    ):
        raise HTTPException(403, "Production bootstrap requires the deployment bootstrap token")
    try:
        return access_control_service.bootstrap_api_key(
            payload.workspace_id, payload.name, payload.rate_limit_per_minute, payload.monthly_budget_usd
        )
    except KeyError:
        raise HTTPException(404, "Workspace not found") from None
    except AccessDenied as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@app.post("/api/v1/access/organizations", status_code=201)
def create_organization(payload: OrganizationCreate) -> dict[str, Any]:
    return access_control_service.create_organization(payload.name)


@app.post("/api/v1/access/workspaces", status_code=201)
def create_workspace(payload: WorkspaceCreate) -> dict[str, Any]:
    try:
        return access_control_service.create_workspace(payload.organization_id, payload.name)
    except KeyError:
        raise HTTPException(404, "Organization not found") from None


@app.post("/api/v1/access/memberships", status_code=201)
def create_membership(payload: MembershipCreate) -> dict[str, Any]:
    try:
        return access_control_service.add_membership(
            payload.workspace_id, payload.subject, payload.display_name, payload.provider, payload.role
        )
    except KeyError:
        raise HTTPException(404, "Workspace not found") from None


@app.post("/api/v1/access/api-keys", status_code=201)
def create_api_key(payload: ApiKeyCreate) -> dict[str, Any]:
    try:
        return access_control_service.create_api_key(
            payload.workspace_id, payload.name, payload.scopes,
            payload.rate_limit_per_minute, payload.monthly_budget_usd,
        )
    except KeyError:
        raise HTTPException(404, "Workspace not found") from None


@app.post("/api/v1/access/workspaces/{workspace_id}/projects/{project_id}")
def attach_workspace_project(workspace_id: str, project_id: str) -> dict[str, str]:
    try:
        access_control_service.attach_project(workspace_id, project_id)
    except KeyError:
        raise HTTPException(404, "Workspace or project not found") from None
    return {"workspace_id": workspace_id, "project_id": project_id, "status": "attached"}


@app.get("/api/v1/a2a/agents")
def list_a2a_agents(project_id: str = "proj_demo") -> list[dict[str, Any]]:
    return a2a_gateway_service.list_agents(project_id)


@app.post("/api/v1/a2a/agents", status_code=201)
def register_a2a_agent(payload: A2AAgentCreate) -> dict[str, Any]:
    try:
        return a2a_gateway_service.register(
            payload.project_id, payload.name, str(payload.endpoint), payload.agent_card
        )
    except KeyError:
        raise HTTPException(404, "Project not found") from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.put("/api/v1/a2a/agents/{agent_id}/card")
def update_a2a_card(agent_id: str, payload: A2ACardUpdate) -> dict[str, Any]:
    try:
        return a2a_gateway_service.update_card(agent_id, payload.agent_card)
    except KeyError:
        raise HTTPException(404, "A2A agent not found") from None


@app.get("/api/v1/a2a/tasks")
def list_a2a_tasks(project_id: str = "proj_demo") -> list[dict[str, Any]]:
    return a2a_gateway_service.list_tasks(project_id)


@app.post("/api/v1/a2a/tasks", status_code=201)
def create_a2a_task(payload: A2ATaskCreate) -> dict[str, Any]:
    try:
        return a2a_gateway_service.submit_task(
            payload.project_id, payload.target_agent_id, payload.source_agent_id, payload.message
        )
    except KeyError:
        raise HTTPException(404, "A2A agent not found") from None
    except A2ASecurityError as exc:
        raise HTTPException(exc.status_code, {"message": str(exc), "findings": exc.findings}) from exc


@app.post("/api/v1/a2a/proxy/{agent_id}")
async def proxy_a2a_request(agent_id: str, payload: A2AJsonRpcRequest) -> dict[str, Any]:
    try:
        return await a2a_gateway_service.proxy(agent_id, payload.model_dump())
    except KeyError:
        raise HTTPException(404, "A2A agent not found") from None
    except A2ASecurityError as exc:
        raise HTTPException(exc.status_code, {"message": str(exc), "findings": exc.findings}) from exc


@app.get("/api/v1/audit")
def list_audit_events(
    project_id: str = "proj_demo",
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return decode_rows(
        db.query_all(
            "SELECT * FROM audit_events WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
            (project_id, limit),
        ),
        "payload_json",
    )


# A production build can be served by the same process, eliminating cross-origin
# drift between the console and control-plane API. API routes are registered first.
frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="console")
