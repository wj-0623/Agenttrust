"""Integration gate: use a dedicated disposable PostgreSQL database, never production.

Set AGENTTRUST_TEST_RLS_ADMIN_URL to opt in. Creates isolated test tenants and a
non-superuser role; intentionally does not delete any resources afterwards.
"""
from __future__ import annotations

import os
import secrets
import uuid

import pytest
from app.db import Database, utc_now
from app.tenant_context import identity_lookup, workspace_context

ADMIN_URL = os.getenv("AGENTTRUST_TEST_RLS_ADMIN_URL")
pytestmark = pytest.mark.skipif(not ADMIN_URL, reason="Dedicated PostgreSQL RLS test server not configured")


@pytest.fixture(scope="module")
def rls_db():
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    suffix = uuid.uuid4().hex[:12]
    role = f"at_test_{suffix}"
    password = secrets.token_urlsafe(32)
    admin = Database(ADMIN_URL, postgres_rls_enabled=True, postgres_app_role=role)
    with admin.connection(migration=True) as conn:
        conn.raw.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
    admin.initialize()
    parts = conninfo_to_dict(ADMIN_URL)
    parts.update(user=role, password=password)
    runtime = Database(ADMIN_URL, postgres_rls_enabled=True, pool_size=1)
    # A libpq DSN is supplied after the constructor's backend detection.
    runtime.database_url = make_conninfo(**parts)
    runtime.verify_runtime_role()
    ws, project, identity, server, snapshot = (f"{prefix}_{suffix}" for prefix in ("ws", "proj", "id", "mcp", "snap"))
    with admin.connection(migration=True) as conn:
        conn.execute("INSERT INTO workspaces VALUES (?, 'org_demo', 'RLS test', ?)", (ws, utc_now()))
        conn.execute("INSERT INTO projects (id, workspace_id, name, description, adapter, endpoint, model, environment, auto_correct, created_at) VALUES (?, ?, 'RLS test', '', 'demo', NULL, 'demo', 'test', 0, ?)", (project, ws, utc_now()))
        conn.execute("INSERT INTO workspace_projects VALUES (?, ?)", (ws, project))
        conn.execute("INSERT INTO identities VALUES (?, ?, 'RLS test', 'oidc', ?)", (identity, identity, utc_now()))
        conn.execute("INSERT INTO memberships VALUES (?, ?, 'admin', ?)", (ws, identity, utc_now()))
        conn.execute("INSERT INTO mcp_servers VALUES (?, ?, 'RLS MCP', 'https://example.com', 'streamable_http', 'active', 1, 'hash', '{}', '[]', ?, ?)", (server, project, utc_now(), utc_now()))
        conn.execute("INSERT INTO mcp_manifest_snapshots (id, server_id, manifest_hash, manifest_json, diff_json, findings_json, created_at) VALUES (?, ?, 'hash', '{}', '{}', '[]', ?)", (snapshot, server, utc_now()))
    yield runtime, admin, ws, project, identity, snapshot
    runtime.close()


def test_rls_denies_missing_context_and_resets_pool(rls_db):
    runtime, _, ws, project, _, snapshot = rls_db
    assert runtime.query_all("SELECT id FROM projects") == []
    with workspace_context(ws):
        assert runtime.query_one("SELECT id FROM projects WHERE id = ?", (project,))
        assert runtime.query_one("SELECT id FROM mcp_manifest_snapshots WHERE id = ?", (snapshot,))
        assert not runtime.query_one("SELECT id FROM projects WHERE id = 'proj_demo'")
    # Same one-connection pool, but no residual tenant state.
    assert runtime.query_all("SELECT id FROM projects") == []
    with workspace_context("ws_demo"):
        assert not runtime.query_one("SELECT id FROM mcp_manifest_snapshots WHERE id = ?", (snapshot,))
        assert runtime.execute("UPDATE projects SET name = 'forged' WHERE id = ?", (project,)) == 0


def test_rls_blocks_cross_tenant_insert_and_audit_mutation(rls_db):
    from psycopg.errors import InsufficientPrivilege
    runtime, _, ws, _, _, _ = rls_db
    with workspace_context(ws):
        with pytest.raises(InsufficientPrivilege):
            runtime.execute("INSERT INTO workspace_projects VALUES (?, 'proj_demo')", (ws,))
        with pytest.raises(InsufficientPrivilege):
            runtime.execute("UPDATE audit_events SET summary = 'forged'")


def test_rls_oidc_lookup_is_read_only_and_scoped(rls_db):
    from psycopg.errors import InsufficientPrivilege
    runtime, admin, ws, _, identity, _ = rls_db
    assert runtime.query_all("SELECT * FROM memberships") == []
    with identity_lookup(identity):
        rows = runtime.query_all("SELECT * FROM memberships")
        assert len(rows) == 1 and rows[0]["workspace_id"] == ws
        with pytest.raises(InsufficientPrivilege):
            runtime.execute("INSERT INTO memberships VALUES ('ws_demo', ?, 'admin', ?)", (identity, utc_now()))
    with pytest.raises(RuntimeError, match="superuser"):
        admin.verify_runtime_role()
