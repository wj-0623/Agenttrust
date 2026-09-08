from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from ..config import settings
from ..db import Database, new_id, utc_now
from ..version import __version__
from .network_security import validate_outbound_destination


class RuntimeDisabled(RuntimeError):
    pass


class SecurityResponseService:
    """Incident response controls, SIEM export and signed audit checkpoints."""

    def __init__(self, db: Database):
        self.db = db

    def controls(self, project_id: str) -> dict[str, Any]:
        row = self.db.query_one(
            "SELECT * FROM security_controls WHERE project_id = ?", (project_id,)
        )
        if not row:
            row = {"project_id": project_id, "kill_switch": False, "reason": "", "actor": "system", "updated_at": None}
        row["kill_switch"] = bool(row.get("kill_switch"))
        return row

    def set_kill_switch(
        self, project_id: str, enabled: bool, actor: str, reason: str
    ) -> dict[str, Any]:
        if enabled and not reason.strip():
            raise ValueError("A reason is required when enabling the kill switch")
        now = utc_now()
        self.db.execute(
            """INSERT INTO security_controls (project_id, kill_switch, reason, actor, updated_at)
            VALUES (?, ?, ?, ?, ?) ON CONFLICT (project_id) DO UPDATE SET
            kill_switch = EXCLUDED.kill_switch, reason = EXCLUDED.reason,
            actor = EXCLUDED.actor, updated_at = EXCLUDED.updated_at""",
            (project_id, int(enabled), reason.strip(), actor, now),
        )
        self.db.audit(
            project_id,
            "security.kill_switch_enabled" if enabled else "security.kill_switch_disabled",
            reason.strip() or "Runtime restored",
            {"enabled": enabled},
            actor=actor,
        )
        return self.controls(project_id)

    def assert_runtime_enabled(self, project_id: str) -> None:
        if self.controls(project_id)["kill_switch"]:
            raise RuntimeDisabled("Agent runtime is disabled by the security kill switch")

    def create_anchor(self, project_id: str) -> dict[str, Any]:
        integrity = self.db.verify_audit_chain(project_id)
        if not integrity["valid"]:
            raise ValueError("Cannot anchor an invalid audit chain")
        created_at = utc_now()
        payload = {
            "project_id": project_id,
            "chain_head": integrity["head"],
            "events_count": integrity["events"],
            "created_at": created_at,
        }
        signature = self._sign(payload, settings.audit_anchor_secret)
        if settings.environment == "production" and not settings.audit_anchor_secret:
            raise ValueError("Production audit anchors require a deployment signing secret")
        exported = False
        anchor_id = new_id("anchor")
        outbox_id = new_id("outbox")
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO audit_anchors
                (id, project_id, chain_head, events_count, signature, exported, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (anchor_id, project_id, integrity["head"], integrity["events"], signature, int(exported), created_at),
            )
            conn.execute(
                "INSERT INTO security_outbox (id, project_id, event_type, payload_json, status, attempts, created_at, updated_at) VALUES (?, ?, 'audit_anchor', ?, 'pending', 0, ?, ?)",
                (outbox_id, project_id, json.dumps(payload | {"signature": signature, "anchor_id": anchor_id}), created_at, created_at),
            )
        return {"id": anchor_id, **payload, "signature": signature, "exported": False, "outbox_id": outbox_id,
                "protection": "signed checkpoint; external WORM protection begins only after delivery"}

    def verify_anchors(self, project_id: str) -> dict[str, Any]:
        chain = self.db.query_all(
            "SELECT event_hash FROM security_audit_chain WHERE project_id = ? ORDER BY created_at, id",
            (project_id,),
        )
        anchors = self.db.query_all(
            "SELECT * FROM audit_anchors WHERE project_id = ? ORDER BY created_at, id",
            (project_id,),
        )
        for anchor in anchors:
            payload = {
                "project_id": project_id,
                "chain_head": anchor["chain_head"],
                "events_count": int(anchor["events_count"]),
                "created_at": anchor["created_at"],
            }
            signature_valid = hmac.compare_digest(
                anchor["signature"], self._sign(payload, settings.audit_anchor_secret)
            )
            count = int(anchor["events_count"])
            head_valid = (count == 0 and anchor["chain_head"] == "GENESIS") or (0 < count <= len(chain) and chain[count - 1]["event_hash"] == anchor["chain_head"])
            if not signature_valid or not head_valid:
                return {
                    "valid": False,
                    "anchors": len(anchors),
                    "broken_anchor_id": anchor["id"],
                    "signature_valid": signature_valid,
                    "chain_head_valid": head_valid,
                }
        return {"valid": True, "anchors": len(anchors), "chain_events": len(chain)}

    def export_incidents(self, project_id: str, limit: int = 100) -> dict[str, Any]:
        incidents = self.db.query_all(
            """
            SELECT * FROM security_incidents WHERE project_id = ?
            ORDER BY created_at DESC LIMIT ?
            """,
            (project_id, limit),
        )
        events = []
        for incident in incidents:
            evidence = json.loads(incident.pop("evidence_json"))
            events.append(
                {
                    "class_uid": 2004,
                    "category_name": "Findings",
                    "activity_name": "Security Finding",
                    "severity": incident["severity"],
                    "status": incident["status"],
                    "finding_info": {
                        "uid": incident["id"],
                        "title": incident["incident_type"],
                        "types": [incident["source"]],
                    },
                    "metadata": {"product": {"name": "AgentTrust", "version": __version__}},
                    "unmapped": {"project_id": project_id, "evidence": evidence},
                    "time": incident["created_at"],
                }
            )
        outbox_id = self.queue(project_id, "security_findings", {"events": events}) if events else None
        return {"format": "OCSF-inspired (not schema-certified)", "events": events, "exported": False, "outbox_id": outbox_id}

    def queue(self, project_id: str, event_type: str, payload: dict[str, Any]) -> str:
        from .dlp import DLPService
        event_id = new_id("outbox")
        now = utc_now()
        self.db.execute(
            "INSERT INTO security_outbox (id, project_id, event_type, payload_json, status, attempts, created_at, updated_at) VALUES (?, ?, ?, ?, 'pending', 0, ?, ?)",
            (event_id, project_id, event_type, json.dumps(payload if event_type == "audit_anchor" else DLPService(self.db).redact_value(payload)), now, now),
        )
        return event_id

    def deliver_pending(self, project_id: str) -> list[dict[str, Any]]:
        rows = self.db.query_all("SELECT * FROM security_outbox WHERE project_id = ? AND status IN ('pending', 'failed') ORDER BY created_at LIMIT 50", (project_id,))
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
                if row["event_type"] == "audit_anchor" and settings.audit_worm_bucket:
                    self._write_worm(row["id"], payload)
                    delivered = True
                else:
                    delivered = self._export(row["event_type"], {"event_id": row["id"], "created_at": row["created_at"], **payload})
                status = "delivered" if delivered else "pending"
                error = None
            except Exception as exc:  # noqa: BLE001 - independent external delivery failures stay retryable.
                status, error = "failed", type(exc).__name__  # Never log credentials or remote response bodies.
            self.db.execute("UPDATE security_outbox SET status = ?, attempts = attempts + 1, last_error = ?, updated_at = ? WHERE id = ?",
                            (status, error, utc_now(), row["id"]))
        return self.db.query_all("SELECT id, event_type, status, attempts, last_error, updated_at FROM security_outbox WHERE project_id = ? ORDER BY created_at DESC LIMIT 100", (project_id,))

    @staticmethod
    def _write_worm(event_id: str, payload: dict[str, Any]) -> None:
        import boto3
        client = boto3.client("s3")
        bucket = settings.audit_worm_bucket
        lock = client.get_object_lock_configuration(Bucket=bucket)
        if lock.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled":
            raise ValueError("Audit destination must enable S3 Object Lock")
        body = json.dumps(payload, sort_keys=True).encode()
        client.put_object(
            Bucket=bucket, Key=f"agenttrust/{payload['project_id']}/{event_id}.json",
            Body=body, ContentType="application/json", ServerSideEncryption="AES256",
            ObjectLockMode="COMPLIANCE", ObjectLockRetainUntilDate=datetime.now(UTC) + timedelta(days=max(1, settings.audit_worm_retention_days)),
        )

    @staticmethod
    def _sign(payload: dict[str, Any], secret: str | None) -> str:
        key = (secret or "development-only-anchor-key").encode("utf-8")
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(key, body, hashlib.sha256).hexdigest()

    def _export(self, event_type: str, payload: dict[str, Any]) -> bool:
        if not settings.security_webhook_url:
            return False
        if not settings.security_webhook_secret:
            raise ValueError("A signing secret is required for security webhook delivery")
        validate_outbound_destination(settings.security_webhook_url)
        if settings.environment == "production" and not settings.security_webhook_url.startswith("https://"):
            raise ValueError("Production security webhook must use HTTPS")
        envelope = {"type": event_type, "source": "agenttrust", "payload": payload}
        encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(
            (settings.security_webhook_secret or "").encode("utf-8"), encoded, hashlib.sha256
        ).hexdigest()
        with httpx.Client(timeout=3.0, follow_redirects=False, trust_env=False) as client:
            response = client.post(
                settings.security_webhook_url,
                content=encoded,
                headers={
                    "Content-Type": "application/json",
                    "X-AgentTrust-Signature-SHA256": signature,
                },
            )
            response.raise_for_status()
        return True
