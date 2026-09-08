from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from ..config import settings
from ..db import Database, new_id, utc_now
from ..tenant_context import current_workspace_id
from .dlp import DLPService
from .policy import PolicyEngine
from .semantic_detector import detect_semantic


@dataclass(frozen=True)
class EnsembleDecision:
    action: str
    risk_level: str
    score: float
    reasons: list[str]
    detectors: list[dict[str, Any]]
    session_id: str


class SecurityIntelligenceService:
    """Composable runtime detectors with stateful, session-level trajectory risk."""

    _STAGES: tuple[tuple[str, re.Pattern[str]], ...] = (
        (
            "discovery",
            re.compile(r"(?i)(list|show|enumerate|discover|查看|列出).{0,24}(tool|capabilit|permission|工具|权限)"),
        ),
        (
            "credential_access",
            re.compile(r"(?i)(read|get|fetch|dump|读取|获取|导出).{0,30}(credential|secret|token|password|凭据|密钥)"),
        ),
        (
            "exfiltration",
            re.compile(r"(?i)(send|upload|post|forward|发送|上传).{0,40}(external|endpoint|webhook|http|外部|地址)"),
        ),
        (
            "impact",
            re.compile(r"(?i)(delete|disable|erase|refund|payment|删除|禁用|退款|付款)"),
        ),
    )

    def __init__(self, db: Database, policy: PolicyEngine, dlp: DLPService):
        self.db = db
        self.policy = policy
        self.dlp = dlp

    def inspect(
        self,
        project_id: str,
        session_id: str,
        message: str,
        context: str | None,
        tool_name: str | None,
        policy: dict[str, Any],
    ) -> EnsembleDecision:
        combined = f"{message}\n{context or ''}"
        normalized = self.policy.normalize_input(combined)
        results: list[dict[str, Any]] = []
        semantic = detect_semantic(self.dlp.scan(combined).safe_text)
        if semantic:
            results.append(semantic)

        policy_decision = self.policy.inspect_input(message, context, policy)
        results.append(
            self._result(
                "policy_rules",
                "prompt_injection" if policy_decision.blocked else "policy_clean",
                1.0 if policy_decision.blocked else 0.0,
                policy_decision.risk_level,
                policy_decision.reasons,
            )
        )
        dlp = self.dlp.scan(combined, action="redact")
        dlp_score = max(
            (
                {"medium": 0.35, "high": 0.75, "critical": 1.0}.get(item["severity"], 0.2)
                for item in dlp.findings
            ),
            default=0.0,
        )
        results.append(
            self._result(
                "dlp",
                "sensitive_data",
                dlp_score,
                self._severity(dlp_score),
                [f"Detected {item['type']}" for item in dlp.findings],
            )
        )
        obfuscation_score = 0.0
        obfuscation_reasons: list[str] = []
        if re.search(r"[\u200b-\u200f\u2060\ufeff]", combined):
            obfuscation_score += 0.55
            obfuscation_reasons.append("zero-width Unicode obfuscation")
        if re.search(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}", combined):
            obfuscation_score += 0.45
            obfuscation_reasons.append("long encoded payload")
        results.append(
            self._result(
                "obfuscation",
                "evasion",
                min(obfuscation_score, 1.0),
                self._severity(obfuscation_score),
                obfuscation_reasons,
            )
        )
        tool_score = 0.0
        tool_reasons: list[str] = []
        if tool_name in policy.get("denied_tools", []):
            tool_score = 1.0
            tool_reasons.append("denied tool requested")
        elif tool_name in policy.get("approval_tools", []):
            tool_score = 0.65
            tool_reasons.append("side-effect tool requires approval")
        elif tool_name and tool_name not in policy.get("allowed_tools", []):
            tool_score = 0.85
            tool_reasons.append("tool is outside the allowlist")
        results.append(
            self._result(
                "tool_boundary",
                "tool_abuse",
                tool_score,
                self._severity(tool_score),
                tool_reasons,
            )
        )

        matched_stages = [name for name, pattern in self._STAGES if pattern.search(normalized)]
        for stage in matched_stages:
            self._store_signal(
                project_id,
                session_id,
                "trajectory_stage",
                stage,
                "medium",
                0.45,
                {"stage": stage, "content_fingerprint": self._fingerprint(normalized)},
            )
        trajectory = self.trajectory(project_id, session_id)
        results.append(
            self._result(
                "trajectory",
                "multi_step_attack",
                trajectory["score"],
                trajectory["risk_level"],
                trajectory["reasons"],
            )
        )

        high_confidence = [item for item in results if item["score"] >= 0.7]
        critical = any(item["score"] >= 0.95 for item in results)
        score = max((item["score"] for item in results), default=0.0)
        if len(high_confidence) >= 2:
            score = max(score, min(1.0, sum(item["score"] for item in high_confidence) / len(high_confidence) + 0.1))
        action = "block" if critical or len(high_confidence) >= 2 or trajectory["score"] >= 0.75 else "allow"
        reasons = [reason for item in results for reason in item["reasons"]]
        if action == "block":
            reasons.append("ensemble consensus reached the runtime blocking threshold")
        decision = EnsembleDecision(
            action=action,
            risk_level=self._severity(score),
            score=round(score, 4),
            reasons=reasons,
            detectors=results,
            session_id=session_id,
        )
        self._store_signal(
            project_id,
            session_id,
            "ensemble",
            "runtime_decision",
            decision.risk_level,
            decision.score,
            {"action": action, "detectors": results},
        )
        if action == "block":
            self._incident(project_id, session_id, decision)
        return decision

    def trajectory(self, project_id: str, session_id: str) -> dict[str, Any]:
        cutoff = (datetime.now(UTC) - timedelta(minutes=30)).isoformat()
        rows = self.db.query_all(
            """
            SELECT category, score, created_at FROM security_signals
            WHERE project_id = ? AND session_id = ? AND detector = 'trajectory_stage'
              AND created_at >= ? ORDER BY created_at
            """,
            (project_id, session_id, cutoff),
        )
        stages: list[str] = []
        for row in rows:
            if row["category"] not in stages:
                stages.append(row["category"])
        ordered = stages
        score = min(1.0, len(ordered) * 0.22)
        credential_to_exfil = "credential_access" in ordered and "exfiltration" in ordered and ordered.index("credential_access") < ordered.index("exfiltration")
        if credential_to_exfil and "discovery" in ordered and ordered.index("discovery") < ordered.index("credential_access"):
            score = 0.95
        elif credential_to_exfil:
            score = 0.82
        reasons = [f"session trajectory observed stage: {stage}" for stage in ordered]
        if score >= 0.75:
            reasons.append("multi-step trajectory crosses the stateful risk threshold")
        return {
            "project_id": project_id,
            "session_id": session_id,
            "window_minutes": 30,
            "stages": ordered,
            "score": round(score, 4),
            "risk_level": self._severity(score),
            "reasons": reasons,
        }

    def list_signals(self, project_id: str, session_id: str | None, limit: int) -> list[dict[str, Any]]:
        if session_id:
            rows = self.db.query_all(
                """
                SELECT * FROM security_signals WHERE project_id = ? AND session_id = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (project_id, session_id, limit),
            )
        else:
            rows = self.db.query_all(
                "SELECT * FROM security_signals WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
                (project_id, limit),
            )
        for row in rows:
            row["evidence"] = json.loads(row.pop("evidence_json"))
        return rows

    def _store_signal(
        self,
        project_id: str,
        session_id: str,
        detector: str,
        category: str,
        severity: str,
        score: float,
        evidence: dict[str, Any],
    ) -> None:
        self.db.execute(
            """
            INSERT INTO security_signals
            (id, project_id, workspace_id, session_id, detector, category, severity,
             score, evidence_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id("signal"), project_id, current_workspace_id(), session_id, detector,
                category, severity, score, json.dumps(evidence, ensure_ascii=False), utc_now(),
            ),
        )

    def _incident(
        self, project_id: str, session_id: str, decision: EnsembleDecision
    ) -> None:
        now = utc_now()
        self.db.execute(
            """
            INSERT INTO security_incidents
            (id, project_id, workspace_id, incident_type, severity, status, source,
             evidence_json, created_at, updated_at)
            VALUES (?, ?, ?, 'runtime_ensemble_block', ?, 'open', 'security-intelligence', ?, ?, ?)
            """,
            (
                new_id("incident"), project_id, current_workspace_id(), decision.risk_level,
                json.dumps({"session_id": session_id, "score": decision.score, "detectors": decision.detectors}, ensure_ascii=False),
                now, now,
            ),
        )

    @staticmethod
    def _result(
        detector: str, category: str, score: float, severity: str, reasons: list[str]
    ) -> dict[str, Any]:
        return {
            "detector": detector,
            "category": category,
            "score": round(min(max(score, 0.0), 1.0), 4),
            "severity": severity,
            "reasons": reasons,
        }

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 0.9:
            return "critical"
        if score >= 0.7:
            return "high"
        if score >= 0.35:
            return "medium"
        return "low"

    @staticmethod
    def _fingerprint(value: str) -> str:
        import hashlib

        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


class AssetGraphService:
    """Discovers the agent supply chain and materializes explainable attack paths."""

    def __init__(self, db: Database):
        self.db = db

    def synchronize(self, project_id: str) -> dict[str, Any]:
        project = self.db.query_one("SELECT * FROM projects WHERE id = ?", (project_id,))
        if not project:
            raise KeyError(project_id)
        root = self._asset(project_id, "agent", project_id, project["name"], "trusted", 0.15, {"model": project["model"]})
        model = self._asset(project_id, "model", project["model"], project["model"], "configured", 0.25, {"adapter": project["adapter"], "endpoint": project["endpoint"]})
        self._edge(project_id, root, model, "invokes", 0.25, {})
        data = self._asset(project_id, "data_store", "tenant-database", f"Tenant {self.db.backend}", "rls_enabled" if self.db.postgres_rls_enabled else "application_isolation", 0.2 if self.db.postgres_rls_enabled else .55, {"rls": self.db.postgres_rls_enabled})
        self._edge(project_id, root, data, "reads_and_writes", 0.45, {"contains": ["refunds", "audit", "traces"]})
        temporal = self._asset(project_id, "orchestrator", "temporal", "Temporal" if settings.temporal_enabled else "Local workflow", "configured" if settings.temporal_enabled else "demo", 0.25, {"durable": settings.temporal_enabled})
        self._edge(project_id, root, temporal, "orchestrates", 0.3, {})

        for server in self.db.query_all("SELECT * FROM mcp_servers WHERE project_id = ?", (project_id,)):
            trust_state = server["status"]
            risk = max(0.0, 1.0 - float(server["trust_score"]))
            asset = self._asset(project_id, "mcp_server", server["id"], server["name"], trust_state, risk, {"endpoint": server["endpoint"], "manifest_hash": server["manifest_hash"]})
            self._edge(project_id, root, asset, "connects_to", max(0.4, risk), {"protocol": "MCP"})
            manifest = json.loads(server["manifest_json"])
            for tool in manifest.get("tools", []):
                tool_name = str(tool.get("name", "unknown"))
                tool_risk = 0.8 if any(word in tool_name for word in ("payment", "refund", "delete", "export")) else 0.35
                tool_asset = self._asset(project_id, "tool", f"{server['id']}:{tool_name}", tool_name, trust_state, tool_risk, {"server_id": server["id"]})
                self._edge(project_id, asset, tool_asset, "exposes", tool_risk, {})
        for agent in self.db.query_all("SELECT * FROM a2a_agents WHERE project_id = ?", (project_id,)):
            risk = max(0.0, 1.0 - float(agent["trust_score"]))
            asset = self._asset(project_id, "a2a_agent", agent["id"], agent["name"], agent["status"], risk, {"endpoint": agent["endpoint"], "card_hash": agent["card_hash"]})
            self._edge(project_id, root, asset, "delegates_to", max(0.45, risk), {"protocol": "A2A"})
        return self.graph(project_id)

    def graph(self, project_id: str) -> dict[str, Any]:
        assets = self.db.query_all(
            "SELECT * FROM agent_assets WHERE project_id = ? ORDER BY risk_score DESC, name",
            (project_id,),
        )
        edges = self.db.query_all(
            "SELECT * FROM asset_edges WHERE project_id = ? ORDER BY risk_score DESC",
            (project_id,),
        )
        for item in assets:
            item["metadata"] = json.loads(item.pop("metadata_json"))
        for item in edges:
            item["metadata"] = json.loads(item.pop("metadata_json"))
        risky_ids = {item["id"] for item in assets if float(item["risk_score"]) >= 0.7}
        attack_paths = [
            {
                "source": edge["source_asset_id"],
                "target": edge["target_asset_id"],
                "relationship": edge["relationship"],
                "risk_score": edge["risk_score"],
            }
            for edge in edges
            if edge["target_asset_id"] in risky_ids or float(edge["risk_score"]) >= 0.7
        ]
        return {
            "project_id": project_id,
            "assets": assets,
            "discovery_scope": "registered inventory only; no network/cloud asset scan",
            "risk_provenance": "explainable heuristic, not a calibrated probability",
            "edges": edges,
            "attack_paths": attack_paths,
            "summary": {
                "assets_total": len(assets),
                "external_assets": sum(item["asset_type"] in {"mcp_server", "a2a_agent"} for item in assets),
                "high_risk_assets": len(risky_ids),
                "quarantined_assets": sum(item["trust_state"] == "quarantined" for item in assets),
            },
        }

    def _asset(self, project_id: str, asset_type: str, external_id: str, name: str, trust_state: str, risk_score: float, metadata: dict[str, Any]) -> str:
        existing = self.db.query_one(
            "SELECT id FROM agent_assets WHERE project_id = ? AND asset_type = ? AND external_id = ?",
            (project_id, asset_type, external_id),
        )
        now = utc_now()
        if existing:
            self.db.execute(
                "UPDATE agent_assets SET name = ?, trust_state = ?, risk_score = ?, metadata_json = ?, updated_at = ? WHERE id = ?",
                (name, trust_state, risk_score, json.dumps(metadata, ensure_ascii=False), now, existing["id"]),
            )
            return existing["id"]
        asset_id = new_id("asset")
        self.db.execute(
            "INSERT INTO agent_assets (id, project_id, asset_type, external_id, name, trust_state, risk_score, metadata_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (asset_id, project_id, asset_type, external_id, name, trust_state, risk_score, json.dumps(metadata, ensure_ascii=False), now),
        )
        return asset_id

    def _edge(self, project_id: str, source: str, target: str, relationship: str, risk_score: float, metadata: dict[str, Any]) -> None:
        existing = self.db.query_one(
            "SELECT id FROM asset_edges WHERE project_id = ? AND source_asset_id = ? AND target_asset_id = ? AND relationship = ?",
            (project_id, source, target, relationship),
        )
        now = utc_now()
        if existing:
            self.db.execute(
                "UPDATE asset_edges SET risk_score = ?, metadata_json = ?, updated_at = ? WHERE id = ?",
                (risk_score, json.dumps(metadata, ensure_ascii=False), now, existing["id"]),
            )
            return
        self.db.execute(
            "INSERT INTO asset_edges (id, project_id, source_asset_id, target_asset_id, relationship, risk_score, metadata_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (new_id("edge"), project_id, source, target, relationship, risk_score, json.dumps(metadata, ensure_ascii=False), now),
        )
