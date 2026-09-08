"""Versioned RLS migration. Identifiers are quoted; expressions are repository constants."""
from __future__ import annotations

from typing import Any

PROJECT_TABLES = (
    "policy_versions", "traces", "evaluation_runs", "red_team_runs", "corrections",
    "audit_events", "mcp_servers", "evaluation_datasets", "correction_releases",
    "durable_workflows", "agent_spans", "capability_leases", "sandbox_runs", "a2a_agents",
    "a2a_tasks", "customer_orders", "security_incidents", "security_audit_chain",
    "correction_observations", "agent_assets", "asset_edges", "security_experiments",
    "security_controls", "audit_anchors", "dlp_events", "security_signals", "refund_requests",
    "workspace_projects", "release_traffic", "correction_appeals", "security_outbox", "prompt_versions",
    "provenance_events",
)
CHILD_TABLES = (
    ("mcp_manifest_snapshots", "mcp_servers", "server_id"),
    ("a2a_card_snapshots", "a2a_agents", "agent_id"),
    ("workflow_events", "durable_workflows", "workflow_id"),
    ("refund_events", "refund_requests", "refund_id"),
)
RLS_TABLES = ("projects", "memberships", *PROJECT_TABLES, *(row[0] for row in CHILD_TABLES))


def install_rls(connection: Any) -> None:
    from psycopg import sql

    tenant = "current_setting('app.current_workspace_id', true)"
    predicates = {"projects": f"workspace_id = {tenant}"}
    for table in PROJECT_TABLES:
        # Ownership comes from projects, never from a caller-created link table.
        expression = sql.SQL("EXISTS (SELECT 1 FROM public.projects p WHERE p.id = {}.project_id AND p.workspace_id = {})").format(
            sql.Identifier(table), sql.SQL(tenant)
        ).as_string(connection)
        if table in {"workspace_projects", "refund_requests"}:
            expression += f" AND workspace_id = {tenant}"
        predicates[table] = expression
    for child, parent, foreign_key in CHILD_TABLES:
        predicates[child] = sql.SQL("EXISTS (SELECT 1 FROM public.{} p WHERE p.id = {}.{})").format(
            sql.Identifier(parent), sql.Identifier(child), sql.Identifier(foreign_key)
        ).as_string(connection)
    predicates["memberships"] = f"workspace_id = {tenant}"
    for table, expression in predicates.items():
        ident = sql.Identifier(table)
        connection.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(ident))
        connection.execute(sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(ident))
        for name in ("tenant_isolation", "tenant_project_isolation", "tenant_access", "oidc_lookup"):
            connection.execute(sql.SQL("DROP POLICY IF EXISTS {} ON {}").format(sql.Identifier(name), ident))
        connection.execute(sql.SQL("CREATE POLICY tenant_access ON {} USING ({}) WITH CHECK ({})").format(
            ident, sql.SQL(expression), sql.SQL(expression)
        ))
        if table == "memberships":
            connection.execute(sql.SQL(
                "CREATE POLICY oidc_lookup ON {} FOR SELECT USING (identity_id = current_setting('app.auth_identity_id', true))"
            ).format(ident))
