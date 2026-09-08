from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from ..config import settings
from ..db import Database, new_id, utc_now
from .network_security import (
    UnsafeOutboundDestination,
    read_limited_json,
    validate_http_endpoint,
    validate_outbound_destination,
)
from .policy import PolicyEngine


class A2ASecurityError(RuntimeError):
    def __init__(self, message: str, status_code: int = 403, findings: list[dict[str, Any]] | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.findings = findings or []


class A2AGatewayService:
    """Agent Card pinning and untrusted cross-agent message enforcement."""

    def __init__(self, db: Database, policy_engine: PolicyEngine):
        self.db = db
        self.policy_engine = policy_engine

    @staticmethod
    def card_hash(card: dict[str, Any]) -> str:
        canonical = json.dumps(card, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def scan_card(self, card: dict[str, Any], endpoint: str) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        if not str(card.get("name", "")).strip():
            findings.append(self._finding("high", "A2A_CARD_NAME_MISSING", "Agent Card 缺少名称"))
        card_url = str(card.get("url", endpoint))
        if urlparse(card_url).hostname != urlparse(endpoint).hostname:
            findings.append(self._finding("critical", "A2A_CARD_ORIGIN_MISMATCH", "Agent Card URL 与注册来源不一致"))
        text_fields = [str(card.get("name", "")), str(card.get("description", ""))]
        skills = card.get("skills", []) if isinstance(card.get("skills", []), list) else []
        seen: set[str] = set()
        for skill in skills:
            if not isinstance(skill, dict):
                findings.append(self._finding("high", "A2A_INVALID_SKILL", "Skill 必须是对象"))
                continue
            skill_id = str(skill.get("id", ""))
            if not skill_id or skill_id in seen:
                findings.append(self._finding("high", "A2A_DUPLICATE_SKILL", "Skill ID 缺失或重复"))
            seen.add(skill_id)
            text_fields.extend([str(skill.get("name", "")), str(skill.get("description", ""))])
        combined = "\n".join(text_fields)
        attack_rules = (
            (r"ignore.{0,30}(instruction|policy|rule)", "A2A_CARD_PROMPT_INJECTION"),
            (r"(reveal|export|send).{0,30}(secret|credential|system prompt)", "A2A_CARD_EXFILTRATION"),
            (r"do not (tell|show|inform).{0,20}(user|operator)", "A2A_CARD_HIDDEN_BEHAVIOR"),
        )
        for pattern, code in attack_rules:
            if re.search(pattern, combined, re.IGNORECASE | re.DOTALL):
                findings.append(self._finding("critical", code, "Agent Card 包含可能污染下游模型的指令"))
        trust = max(0.0, 1.0 - sum({"critical": 0.45, "high": 0.25, "medium": 0.08}.get(item["severity"], 0.02) for item in findings))
        return {"trust_score": round(trust, 4), "blocking": any(item["severity"] in {"critical", "high"} for item in findings),
                "skills_total": len(skills), "findings": findings}

    def register(self, project_id: str, name: str, endpoint: str, card: dict[str, Any]) -> dict[str, Any]:
        if not self.db.query_one("SELECT id FROM projects WHERE id = ?", (project_id,)):
            raise KeyError(project_id)
        self._validate_endpoint(endpoint)
        scan = self.scan_card(card, endpoint)
        agent_id = new_id("agent")
        digest = self.card_hash(card)
        status = "quarantined" if scan["blocking"] else "active"
        now = utc_now()
        self.db.execute(
            """
            INSERT INTO a2a_agents
            (id, project_id, name, endpoint, status, trust_score, card_hash, card_json,
             findings_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (agent_id, project_id, name, endpoint, status, scan["trust_score"], digest,
             json.dumps(card, ensure_ascii=False), json.dumps(scan["findings"], ensure_ascii=False), now, now),
        )
        self._snapshot(agent_id, digest, card, {"initial": True}, scan["findings"])
        self.db.audit(project_id, "a2a.agent_registered", f"注册 A2A Agent {name}，状态 {status}", {
            "agent_id": agent_id, "card_hash": digest, "trust_score": scan["trust_score"]
        })
        return self.get_agent(agent_id)

    def update_card(self, agent_id: str, card: dict[str, Any]) -> dict[str, Any]:
        agent = self._raw_agent(agent_id)
        previous = json.loads(agent["card_json"])
        digest = self.card_hash(card)
        scan = self.scan_card(card, agent["endpoint"])
        changed = digest != agent["card_hash"]
        diff = self._card_diff(previous, card)
        findings = list(scan["findings"])
        if changed:
            findings.append(self._finding("critical", "A2A_CARD_RUG_PULL", "已固定 Agent Card 在运行期发生变化"))
        status = "quarantined" if scan["blocking"] or changed else "active"
        trust = max(0.0, float(scan["trust_score"]) - (0.35 if changed else 0))
        self.db.execute(
            """
            UPDATE a2a_agents SET status = ?, trust_score = ?, card_hash = ?, card_json = ?,
                findings_json = ?, updated_at = ? WHERE id = ?
            """,
            (status, trust, digest, json.dumps(card, ensure_ascii=False),
             json.dumps(findings, ensure_ascii=False), utc_now(), agent_id),
        )
        self._snapshot(agent_id, digest, card, diff, findings)
        self.db.audit(agent["project_id"], "a2a.card_changed", f"A2A Agent Card 更新，状态 {status}", {
            "agent_id": agent_id, "diff": diff
        })
        return self.get_agent(agent_id)

    def submit_task(self, project_id: str, target_agent_id: str, source_agent_id: str | None, message: dict[str, Any]) -> dict[str, Any]:
        from .dlp import DLPService
        from .security_response import SecurityResponseService
        SecurityResponseService(self.db).assert_runtime_enabled(project_id)
        dlp = DLPService(self.db)
        if dlp.inspect_and_record(project_id, message, direction="input").blocked:
            raise A2ASecurityError("A2A 消息包含禁止传递的敏感数据")
        target = self._raw_agent(target_agent_id)
        if target["project_id"] != project_id:
            raise A2ASecurityError("目标 Agent 不属于当前项目")
        if target["status"] != "active":
            raise A2ASecurityError("目标 Agent 已被隔离", findings=json.loads(target["findings_json"]))
        text = self._message_text(message)
        if not text:
            raise A2ASecurityError("A2A 消息缺少可验证的文本或结构化内容", 422)
        policy = self.db.active_policy(project_id)
        decision = self.policy_engine.inspect_input(text, json.dumps(message, ensure_ascii=False), policy)
        if decision.blocked:
            raise A2ASecurityError("跨 Agent 消息命中输入安全策略", findings=[{"severity": "critical", "code": "A2A_MESSAGE_INJECTION", "message": "; ".join(decision.reasons)}])
        task_id = new_id("a2atask")
        now = utc_now()
        self.db.execute(
            """
            INSERT INTO a2a_tasks
            (id, project_id, source_agent_id, target_agent_id, status, message_json,
             result_json, trace_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'submitted', ?, '{}', NULL, ?, ?)
            """,
            (task_id, project_id, source_agent_id, target_agent_id, json.dumps(dlp.redact_value(message), ensure_ascii=False), now, now),
        )
        self.db.audit(project_id, "a2a.task_submitted", f"提交跨 Agent 任务 {task_id}", {
            "target_agent_id": target_agent_id, "source_agent_id": source_agent_id
        })
        return self.get_task(task_id)

    async def proxy(self, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        from .dlp import DLPService
        agent = self._raw_agent(agent_id)
        from .security_response import SecurityResponseService
        SecurityResponseService(self.db).assert_runtime_enabled(agent["project_id"])
        dlp = DLPService(self.db)
        if dlp.inspect_and_record(agent["project_id"], payload, direction="input").blocked:
            raise A2ASecurityError("A2A 消息被 DLP 阻止")
        if agent["status"] != "active":
            raise A2ASecurityError("目标 Agent 已隔离", findings=json.loads(agent["findings_json"]))
        method = payload.get("method")
        if method not in {"message/send", "message/stream", "tasks/get", "tasks/cancel"}:
            raise A2ASecurityError("A2A 方法未被网关允许")
        if method in {"message/send", "message/stream"}:
            text = self._message_text(payload.get("params", {}))
            decision = self.policy_engine.inspect_input(text, json.dumps(payload.get("params", {}), ensure_ascii=False), self.db.active_policy(agent["project_id"]))
            if decision.blocked:
                raise A2ASecurityError("A2A 消息在转发前被策略阻止")
        self._validate_proxy_destination(agent["endpoint"])
        async with (
            httpx.AsyncClient(timeout=20.0, follow_redirects=False, trust_env=False) as client,
            client.stream(
                "POST", agent["endpoint"], json=dlp.redact_value(payload), headers={"Content-Type": "application/json"}
            ) as response,
        ):
            response.raise_for_status()
            try:
                result = await read_limited_json(response, settings.max_upstream_response_bytes)
            except ValueError as exc:
                raise A2ASecurityError(str(exc), 502) from exc
        output = json.dumps(result, ensure_ascii=False)
        dlp_output = dlp.inspect_and_record(agent["project_id"], result, direction="output")
        if dlp_output.blocked or self.policy_engine.inspect_output(output, self.db.active_policy(agent["project_id"])).blocked:
            raise A2ASecurityError("A2A 响应包含敏感内容")
        return dlp.redact_value(result)

    def list_agents(self, project_id: str) -> list[dict[str, Any]]:
        return [self._decode_agent(row) for row in self.db.query_all(
            "SELECT * FROM a2a_agents WHERE project_id = ? ORDER BY created_at DESC", (project_id,)
        )]

    def list_tasks(self, project_id: str) -> list[dict[str, Any]]:
        rows = self.db.query_all("SELECT * FROM a2a_tasks WHERE project_id = ? ORDER BY created_at DESC", (project_id,))
        for row in rows:
            row["message"] = json.loads(row.pop("message_json"))
            row["result"] = json.loads(row.pop("result_json"))
        return rows

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        return self._decode_agent(self._raw_agent(agent_id))

    def get_task(self, task_id: str) -> dict[str, Any]:
        task = self.db.query_one("SELECT * FROM a2a_tasks WHERE id = ?", (task_id,))
        if not task:
            raise KeyError(task_id)
        task["message"] = json.loads(task.pop("message_json"))
        task["result"] = json.loads(task.pop("result_json"))
        return task

    def _raw_agent(self, agent_id: str) -> dict[str, Any]:
        agent = self.db.query_one("SELECT * FROM a2a_agents WHERE id = ?", (agent_id,))
        if not agent:
            raise KeyError(agent_id)
        return agent

    @staticmethod
    def _decode_agent(agent: dict[str, Any]) -> dict[str, Any]:
        result = dict(agent)
        result["agent_card"] = json.loads(result.pop("card_json"))
        result["findings"] = json.loads(result.pop("findings_json"))
        return result

    def _snapshot(self, agent_id: str, digest: str, card: dict[str, Any], diff: dict[str, Any], findings: list[dict[str, Any]]) -> None:
        self.db.execute(
            """
            INSERT INTO a2a_card_snapshots
            (id, agent_id, card_hash, card_json, diff_json, findings_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (new_id("a2asnap"), agent_id, digest, json.dumps(card, ensure_ascii=False),
             json.dumps(diff, ensure_ascii=False), json.dumps(findings, ensure_ascii=False), utc_now()),
        )

    @staticmethod
    def _card_diff(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
        before = {str(item.get("id")): item for item in previous.get("skills", []) if isinstance(item, dict)}
        after = {str(item.get("id")): item for item in current.get("skills", []) if isinstance(item, dict)}
        return {
            "added_skills": sorted(after.keys() - before.keys()),
            "removed_skills": sorted(before.keys() - after.keys()),
            "changed_skills": sorted(key for key in before.keys() & after.keys() if before[key] != after[key]),
            "metadata_changed": {key: previous.get(key) != current.get(key) for key in ("name", "description", "url", "version")},
        }

    @staticmethod
    def _message_text(message: dict[str, Any]) -> str:
        chunks: list[str] = []
        if isinstance(message.get("text"), str):
            chunks.append(message["text"])
        parts = message.get("parts", [])
        if isinstance(parts, list):
            for part in parts:
                if isinstance(part, dict):
                    if isinstance(part.get("text"), str):
                        chunks.append(part["text"])
                    elif "data" in part:
                        chunks.append(json.dumps(part["data"], ensure_ascii=False))
        nested = message.get("message")
        if isinstance(nested, dict):
            chunks.append(A2AGatewayService._message_text(nested))
        return "\n".join(chunk for chunk in chunks if chunk).strip()

    @staticmethod
    def _finding(severity: str, code: str, message: str) -> dict[str, Any]:
        return {"severity": severity, "code": code, "message": message}

    @staticmethod
    def _validate_endpoint(endpoint: str) -> None:
        validate_http_endpoint(endpoint)

    @staticmethod
    def _validate_proxy_destination(endpoint: str) -> None:
        try:
            validate_outbound_destination(
                endpoint, allow_development_loopback=settings.environment == "development"
            )
        except UnsafeOutboundDestination as exc:
            raise A2ASecurityError(f"A2A outbound destination rejected: {exc}") from exc
