from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from ..db import Database, new_id, utc_now
from ..tenant_context import current_workspace_id, identity_lookup

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "viewer": {"read"},
    "operator": {"read", "gateway:invoke", "workflow:execute", "tool:execute", "mcp:proxy", "a2a:send"},
    "admin": {"*"},
}


class AccessDenied(RuntimeError):
    def __init__(self, message: str, status_code: int = 403):
        super().__init__(message)
        self.status_code = status_code


class AccessControlService:
    def __init__(self, db: Database):
        self.db = db

    @staticmethod
    def _hash(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def create_organization(self, name: str) -> dict[str, Any]:
        organization_id = new_id("org")
        self.db.execute(
            "INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)",
            (organization_id, name, utc_now()),
        )
        return self.db.query_one("SELECT * FROM organizations WHERE id = ?", (organization_id,)) or {}

    def create_workspace(self, organization_id: str, name: str) -> dict[str, Any]:
        workspace = current_workspace_id()
        if workspace and not self.db.query_one(
            "SELECT id FROM workspaces WHERE id = ? AND organization_id = ?", (workspace, organization_id)
        ):
            raise AccessDenied("Cannot create a workspace in another organization")
        if not self.db.query_one("SELECT id FROM organizations WHERE id = ?", (organization_id,)):
            raise KeyError(organization_id)
        workspace_id = new_id("ws")
        self.db.execute(
            "INSERT INTO workspaces (id, organization_id, name, created_at) VALUES (?, ?, ?, ?)",
            (workspace_id, organization_id, name, utc_now()),
        )
        return self.db.query_one("SELECT * FROM workspaces WHERE id = ?", (workspace_id,)) or {}

    def add_membership(self, workspace_id: str, subject: str, display_name: str, provider: str, role: str) -> dict[str, Any]:
        self._require_current_workspace(workspace_id)
        if role not in ROLE_PERMISSIONS:
            raise ValueError(role)
        if not self.db.query_one("SELECT id FROM workspaces WHERE id = ?", (workspace_id,)):
            raise KeyError(workspace_id)
        identity = self.db.query_one("SELECT * FROM identities WHERE subject = ?", (subject,))
        identity_id = identity["id"] if identity else new_id("user")
        if not identity:
            self.db.execute(
                "INSERT INTO identities (id, subject, display_name, provider, created_at) VALUES (?, ?, ?, ?, ?)",
                (identity_id, subject, display_name, provider, utc_now()),
            )
        self.db.execute(
            "INSERT OR REPLACE INTO memberships (workspace_id, identity_id, role, created_at) VALUES (?, ?, ?, ?)",
            (workspace_id, identity_id, role, utc_now()),
        )
        return {"workspace_id": workspace_id, "identity_id": identity_id, "subject": subject, "display_name": display_name, "provider": provider, "role": role,
                "permissions": sorted(ROLE_PERMISSIONS[role])}

    def create_api_key(
        self,
        workspace_id: str,
        name: str,
        scopes: list[str],
        rate_limit_per_minute: int,
        monthly_budget_usd: float,
    ) -> dict[str, Any]:
        self._require_current_workspace(workspace_id)
        if not self.db.query_one("SELECT id FROM workspaces WHERE id = ?", (workspace_id,)):
            raise KeyError(workspace_id)
        secret = f"at_{secrets.token_urlsafe(36)}"
        key_id = new_id("key")
        prefix = secret[:12]
        self.db.execute(
            """
            INSERT INTO api_keys
            (id, workspace_id, name, key_prefix, secret_hash, scopes_json,
             rate_limit_per_minute, monthly_budget_usd, spend_usd, requests_count,
             status, last_used_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'active', NULL, ?)
            """,
            (
                key_id, workspace_id, name, prefix, self._hash(secret),
                json.dumps(sorted(set(scopes)), ensure_ascii=False), rate_limit_per_minute,
                monthly_budget_usd, utc_now(),
            ),
        )
        return {"id": key_id, "name": name, "workspace_id": workspace_id, "api_key": secret,
                "key_prefix": prefix, "scopes": sorted(set(scopes)), "rate_limit_per_minute": rate_limit_per_minute,
                "monthly_budget_usd": monthly_budget_usd, "warning": "This secret is returned once and is never stored in plaintext."}

    def bootstrap_api_key(
        self,
        workspace_id: str,
        name: str,
        rate_limit_per_minute: int,
        monthly_budget_usd: float,
    ) -> dict[str, Any]:
        """Create the first key under an immediate transaction to prevent bootstrap races."""
        secret = f"at_{secrets.token_urlsafe(36)}"
        key_id = new_id("key")
        prefix = secret[:12]
        now = utc_now()
        with self.db.transaction() as connection:
            if self.db.backend == "postgresql":
                connection.execute("SELECT pg_advisory_xact_lock(hashtext('agenttrust:bootstrap'))")
            if not connection.execute(
                "SELECT id FROM workspaces WHERE id = ?", (workspace_id,)
            ).fetchone():
                raise KeyError(workspace_id)
            if connection.execute("SELECT id FROM api_keys LIMIT 1").fetchone():
                raise AccessDenied("Bootstrap is disabled after the first API Key is created", 409)
            connection.execute(
                """
                INSERT INTO api_keys
                (id, workspace_id, name, key_prefix, secret_hash, scopes_json,
                 rate_limit_per_minute, monthly_budget_usd, spend_usd, requests_count,
                 status, last_used_at, created_at)
                VALUES (?, ?, ?, ?, ?, '["*"]', ?, ?, 0, 0, 'active', NULL, ?)
                """,
                (
                    key_id, workspace_id, name, prefix, self._hash(secret),
                    rate_limit_per_minute, monthly_budget_usd, now,
                ),
            )
        return {
            "id": key_id, "name": name, "workspace_id": workspace_id, "api_key": secret,
            "key_prefix": prefix, "scopes": ["*"], "rate_limit_per_minute": rate_limit_per_minute,
            "monthly_budget_usd": monthly_budget_usd,
            "warning": "This secret is returned once and is never stored in plaintext.",
        }

    def authenticate(self, secret: str, required_scope: str = "read") -> dict[str, Any]:
        now = datetime.now(UTC)
        window = (now - timedelta(minutes=1)).isoformat()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        usage_event_id = new_id("usage")
        with self.db.transaction() as connection:
            key_query = (
                "SELECT * FROM api_keys WHERE secret_hash = ? FOR UPDATE"
                if self.db.backend == "postgresql"
                else "SELECT * FROM api_keys WHERE secret_hash = ?"
            )
            row = connection.execute(
                key_query,
                (self._hash(secret),),
            ).fetchone()
            key = dict(row) if row else None
            if not key or key["status"] != "active":
                raise AccessDenied("API Key 无效或已禁用", 401)
            scopes = set(json.loads(key["scopes_json"]))
            if "*" not in scopes and required_scope not in scopes and not (
                required_scope == "read" and "read" in scopes
            ):
                raise AccessDenied(f"API Key 缺少作用域 {required_scope}")
            monthly = connection.execute(
                """
                SELECT COALESCE(SUM(cost_usd), 0) AS spend
                FROM api_usage_events WHERE api_key_id = ? AND created_at >= ?
                """,
                (key["id"], month_start),
            ).fetchone()
            monthly_spend = float(monthly["spend"] if monthly else 0)
            if monthly_spend >= float(key["monthly_budget_usd"]):
                raise AccessDenied("API Key 月度预算已耗尽", 429)
            usage = connection.execute(
                "SELECT COUNT(*) AS count FROM api_usage_events WHERE api_key_id = ? AND created_at >= ?",
                (key["id"], window),
            ).fetchone()
            if int(usage["count"] if usage else 0) >= int(key["rate_limit_per_minute"]):
                raise AccessDenied("API Key 每分钟请求额度已耗尽", 429)
            connection.execute(
                "INSERT INTO api_usage_events (id, api_key_id, route, cost_usd, created_at) VALUES (?, ?, '', 0, ?)",
                (usage_event_id, key["id"], now.isoformat()),
            )
            connection.execute(
                "UPDATE api_keys SET requests_count = requests_count + 1, last_used_at = ? WHERE id = ?",
                (now.isoformat(), key["id"]),
            )
            key["spend_usd"] = monthly_spend
            key["usage_event_id"] = usage_event_id
        key["scopes"] = sorted(scopes)
        key["auth_type"] = "api_key"
        key.pop("secret_hash", None)
        key.pop("scopes_json", None)
        return key

    def authenticate_oidc(
        self,
        claims: dict[str, Any],
        required_scope: str,
        requested_workspace_id: str | None,
    ) -> dict[str, Any]:
        subject = str(claims.get("sub", ""))
        identity = self.db.query_one(
            "SELECT * FROM identities WHERE subject = ? AND provider = 'oidc'", (subject,)
        )
        if not identity:
            raise AccessDenied("OIDC identity has not been provisioned", 403)
        with identity_lookup(identity["id"]):
            memberships = self.db.query_all(
                "SELECT * FROM memberships WHERE identity_id = ? ORDER BY created_at",
                (identity["id"],),
            )
        if not memberships:
            raise AccessDenied("OIDC identity has no workspace membership", 403)
        if requested_workspace_id:
            membership = next(
                (item for item in memberships if item["workspace_id"] == requested_workspace_id),
                None,
            )
            if not membership:
                raise AccessDenied("OIDC identity cannot access the requested workspace", 403)
        elif len(memberships) == 1:
            membership = memberships[0]
        else:
            raise AccessDenied("X-AgentTrust-Workspace is required for a multi-workspace identity", 400)
        permissions = ROLE_PERMISSIONS.get(membership["role"], set())
        if "*" not in permissions and required_scope not in permissions and not (
            required_scope == "read" and "read" in permissions
        ):
            raise AccessDenied(f"OIDC role lacks scope {required_scope}")
        return {
            "id": f"oidc:{identity['id']}",
            "auth_type": "oidc",
            "identity_id": identity["id"],
            "subject": subject,
            "workspace_id": membership["workspace_id"],
            "role": membership["role"],
            "scopes": sorted(permissions),
        }

    def record_usage(
        self, api_key_id: str, route: str, cost_usd: float = 0.0, usage_event_id: str | None = None
    ) -> None:
        cost = max(0.0, cost_usd)
        if usage_event_id:
            self.db.execute(
                "UPDATE api_usage_events SET route = ?, cost_usd = ? WHERE id = ? AND api_key_id = ?",
                (route, cost, usage_event_id, api_key_id),
            )
        else:
            self.db.execute(
                "INSERT INTO api_usage_events (id, api_key_id, route, cost_usd, created_at) VALUES (?, ?, ?, ?, ?)",
                (new_id("usage"), api_key_id, route, cost, utc_now()),
            )
            self.db.execute(
                "UPDATE api_keys SET requests_count = requests_count + 1, last_used_at = ? WHERE id = ?",
                (utc_now(), api_key_id),
            )
        self.db.execute(
            """
            UPDATE api_keys SET spend_usd = spend_usd + ? WHERE id = ?
            """,
            (cost, api_key_id),
        )

    def attach_project(self, workspace_id: str, project_id: str) -> None:
        if not self.db.query_one("SELECT id FROM workspaces WHERE id = ?", (workspace_id,)):
            raise KeyError(workspace_id)
        if not self.db.query_one("SELECT id FROM projects WHERE id = ? AND workspace_id = ?", (project_id, workspace_id)):
            raise KeyError(project_id)
        self.db.execute(
            "INSERT OR IGNORE INTO workspace_projects (workspace_id, project_id) VALUES (?, ?)",
            (workspace_id, project_id),
        )

    def authorize_workspace(self, key: dict[str, Any], workspace_id: str) -> None:
        if key["workspace_id"] != workspace_id:
            raise AccessDenied("API Key 无权访问其他工作空间的资源")

    @staticmethod
    def _require_current_workspace(workspace_id: str) -> None:
        active = current_workspace_id()
        if active and active != workspace_id:
            raise AccessDenied("Resource does not belong to the authenticated workspace")

    def authorize_project(self, key: dict[str, Any], project_id: str) -> None:
        allowed = self.db.query_one(
            "SELECT 1 AS allowed FROM workspace_projects WHERE workspace_id = ? AND project_id = ?",
            (key["workspace_id"], project_id),
        )
        if not allowed:
            raise AccessDenied("API Key 无权访问其他工作空间的项目")

    def authorize_request_resources(
        self,
        key: dict[str, Any],
        path: str,
        query: dict[str, str],
        body: dict[str, Any],
    ) -> None:
        for supplied_workspace in (body.get("workspace_id"), query.get("workspace_id")):
            if isinstance(supplied_workspace, str):
                self.authorize_workspace(key, supplied_workspace)
        workspace_id = body.get("workspace_id") or query.get("workspace_id")
        workspace_match = re.search(r"/access/workspaces/([^/]+)", path)
        if workspace_match:
            workspace_id = workspace_match.group(1)
        if isinstance(workspace_id, str):
            self.authorize_workspace(key, workspace_id)

        # Validate both sources: JSON must not mask the query parameter the endpoint uses.
        for supplied_project in (body.get("project_id"), query.get("project_id")):
            if isinstance(supplied_project, str):
                self.authorize_project(key, supplied_project)
        project_id = body.get("project_id") or query.get("project_id")
        if path.startswith(("/api/v1/security/", "/api/v1/observability/")):
            project_id = query.get("project_id", "proj_demo")
        policy_match = re.fullmatch(r"/api/v1/policies/([^/]+)", path)
        if policy_match:
            project_id = policy_match.group(1)
        attachment_match = re.fullmatch(
            r"/api/v1/access/workspaces/[^/]+/projects/([^/]+)", path
        )
        if attachment_match:
            project_id = attachment_match.group(1)

        resource_queries = {
            "traces": "SELECT project_id FROM traces WHERE id = ?",
            "corrections": "SELECT project_id FROM corrections WHERE id = ?",
            "workflows": "SELECT project_id FROM durable_workflows WHERE id = ?",
            "mcp/servers": "SELECT project_id FROM mcp_servers WHERE id = ?",
            "mcp/proxy": "SELECT project_id FROM mcp_servers WHERE id = ?",
            "a2a/agents": "SELECT project_id FROM a2a_agents WHERE id = ?",
            "a2a/proxy": "SELECT project_id FROM a2a_agents WHERE id = ?",
            "refunds": "SELECT project_id FROM refund_requests WHERE id = ?",
        }
        for prefix, resource_query in resource_queries.items():
            match = re.match(rf"/api/v1/{re.escape(prefix)}/([^/]+)", path)
            if match:
                row = self.db.query_one(resource_query, (match.group(1),))
                if row:
                    project_id = row["project_id"]
                break
        if isinstance(project_id, str):
            self.authorize_project(key, project_id)
        elif any(path.startswith(f"/api/v1/{prefix}") for prefix in (
            "dashboard", "gateway/", "traces", "evaluations", "evaluation-datasets",
            "red-team/runs", "red-team/run", "corrections", "correction-clusters",
            "refunds", "security/", "observability/", "mcp/", "a2a/", "workflows", "sandbox/", "guard/", "audit",
        )):
            self.authorize_project(key, "proj_demo")

    def list_projects(self, workspace_id: str) -> list[dict[str, Any]]:
        return self.db.query_all(
            """
            SELECT p.* FROM projects p
            JOIN workspace_projects wp ON wp.project_id = p.id
            WHERE wp.workspace_id = ? ORDER BY p.created_at DESC
            """,
            (workspace_id,),
        )

    def summary(self, workspace_id: str | None = None) -> dict[str, Any]:
        params: tuple[Any, ...] = (workspace_id, workspace_id)
        month_start = datetime.now(UTC).replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        ).isoformat()
        organizations = self.db.query_all(
            """
            SELECT DISTINCT o.* FROM organizations o
            JOIN workspaces w ON w.organization_id = o.id
            WHERE (? IS NULL OR w.id = ?) ORDER BY o.created_at
            """,
            params,
        )
        workspaces = self.db.query_all(
            """
            SELECT w.*, COUNT(DISTINCT wp.project_id) AS projects,
                   COUNT(DISTINCT m.identity_id) AS members
            FROM workspaces w
            LEFT JOIN workspace_projects wp ON wp.workspace_id = w.id
            LEFT JOIN memberships m ON m.workspace_id = w.id
            WHERE (? IS NULL OR w.id = ?)
            GROUP BY w.id ORDER BY w.created_at
            """,
            params,
        )
        keys = self.db.query_all(
            """
            SELECT id, workspace_id, name, key_prefix, scopes_json, rate_limit_per_minute,
                   monthly_budget_usd,
                   COALESCE((
                       SELECT SUM(u.cost_usd) FROM api_usage_events u
                       WHERE u.api_key_id = api_keys.id AND u.created_at >= ?
                   ), 0) AS spend_usd,
                   requests_count, status, last_used_at, created_at
            FROM api_keys WHERE (? IS NULL OR workspace_id = ?) ORDER BY created_at DESC
            """,
            (month_start, workspace_id, workspace_id),
        )
        for key in keys:
            key["scopes"] = json.loads(key.pop("scopes_json"))
        memberships = self.db.query_all(
            """
            SELECT m.workspace_id, m.role, i.id AS identity_id, i.subject,
                   i.display_name, i.provider, m.created_at
            FROM memberships m JOIN identities i ON i.id = m.identity_id
            WHERE (? IS NULL OR m.workspace_id = ?)
            ORDER BY m.created_at
            """,
            params,
        )
        return {"organizations": organizations, "workspaces": workspaces, "memberships": memberships, "api_keys": keys}

    @staticmethod
    def required_scope(method: str, path: str) -> str:
        if method == "GET":
            return "read"
        if path.endswith(("/approve", "/rollback", "/canary-observations")) or path == "/api/v1/sandbox/leases":
            return "admin"
        if "/gateway/" in path:
            return "gateway:invoke"
        if "/guard/" in path:
            return "gateway:invoke"
        if "/workflows" in path:
            return "workflow:execute"
        if "/sandbox/" in path:
            return "tool:execute"
        if "/mcp/proxy" in path:
            return "mcp:proxy"
        if "/a2a/agents" in path:
            return "admin"
        if "/a2a/" in path:
            return "a2a:send"
        if "/refunds" in path:
            return "workflow:execute"
        return "admin"
