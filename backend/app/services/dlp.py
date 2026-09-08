from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from typing import Any

from ..config import settings
from ..db import Database, new_id, utc_now
from ..tenant_context import current_workspace_id

_FINGERPRINT_KEY = settings.audit_anchor_secret.encode() if settings.audit_anchor_secret else secrets.token_bytes(32)


@dataclass(frozen=True)
class DLPResult:
    safe_text: str
    findings: list[dict[str, Any]]
    blocked: bool


class DLPService:
    """Deterministic, storage-safe DLP for agent prompts, evidence and outputs."""

    _PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
        (
            "private_key",
            "critical",
            "credential",
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|$)", re.IGNORECASE | re.DOTALL),
        ),
        (
            "cloud_or_api_key",
            "critical",
            "credential",
            re.compile(r"(?:sk-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{12,}|gh[pousr]_[A-Za-z0-9]{20,})"),
        ),
        (
            "password_assignment",
            "critical",
            "credential",
            re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|api_key|authorization)[\"']?\s*[:=]\s*[\"']?[^\s,;\"'}]{6,}"),
        ),
        (
            "medical_record_identifier", "high", "phi",
            re.compile(r"(?i)(?:\bMRN\b|medical.record.number|病历号|医保号)\s*[:：=#]?\s*[A-Z0-9-]{5,30}"),
        ),
        (
            "email",
            "medium",
            "pii",
            re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"),
        ),
        (
            "phone_cn",
            "medium",
            "pii",
            re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)"),
        ),
        (
            "national_id_cn",
            "high",
            "pii",
            re.compile(r"(?<!\d)\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?!\d)"),
        ),
        (
            "payment_card_candidate",
            "high",
            "pci",
            re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
        ),
    )

    def __init__(self, db: Database):
        self.db = db

    def scan(self, value: Any, *, action: str = "redact") -> DLPResult:
        if action not in {"redact", "block"}:
            raise ValueError("DLP action must be redact or block")
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        findings: list[dict[str, Any]] = []
        replacements: list[tuple[int, int, str]] = []
        for name, severity, category, pattern in self._PATTERNS:
            for match in pattern.finditer(text):
                raw = match.group(0)
                if name == "payment_card_candidate" and not self._luhn_valid(raw):
                    continue
                findings.append(
                    {
                        "type": name,
                        "category": category,
                        "severity": severity,
                        "start": match.start(),
                        "end": match.end(),
                        "fingerprint": hmac.new(_FINGERPRINT_KEY, raw.encode("utf-8"), hashlib.sha256).hexdigest()[:16],
                    }
                )
                replacements.append((match.start(), match.end(), f"[REDACTED:{name.upper()}]"))
        merged: list[tuple[int, int, str]] = []
        for start, end, replacement in sorted(replacements):
            if merged and start < merged[-1][1]:
                previous = merged[-1]
                merged[-1] = (previous[0], max(previous[1], end), previous[2])
            else:
                merged.append((start, end, replacement))
        safe_text = text
        for start, end, replacement in reversed(merged):
            safe_text = safe_text[:start] + replacement + safe_text[end:]
        blocked = action == "block" and any(
            finding["severity"] in {"high", "critical"} for finding in findings
        )
        return DLPResult(safe_text=safe_text, findings=findings, blocked=blocked)

    def inspect_and_record(
        self,
        project_id: str,
        value: Any,
        *,
        direction: str,
        action: str | None = None,
    ) -> DLPResult:
        selected_action = action or (
            settings.dlp_output_action if direction == "output" else settings.dlp_input_action
        )
        result = self.scan(value, action=selected_action) if settings.dlp_enabled else DLPResult(
            safe_text=value if isinstance(value, str) else json.dumps(value, ensure_ascii=False),
            findings=[],
            blocked=False,
        )
        if result.findings:
            self.db.execute(
                """
                INSERT INTO dlp_events
                (id, project_id, workspace_id, direction, action, findings_json,
                 content_fingerprint, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id("dlp"),
                    project_id,
                    current_workspace_id(),
                    direction,
                    "block" if result.blocked else "redact",
                    json.dumps(result.findings, ensure_ascii=False),
                    hashlib.sha256(result.safe_text.encode("utf-8")).hexdigest(),
                    utc_now(),
                ),
            )
        return result

    def list_events(self, project_id: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.query_all(
            "SELECT * FROM dlp_events WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
            (project_id, limit),
        )
        for row in rows:
            row["findings"] = json.loads(row.pop("findings_json"))
        return rows

    def redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.scan(value, action="redact").safe_text
        if isinstance(value, dict):
            secret_keys = {"password", "passwd", "pwd", "secret", "token", "api_key", "authorization", "private_key"}
            return {
                self.scan(str(key)).safe_text: (
                    "[REDACTED:SECRET]" if str(key).lower() in secret_keys else self.redact_value(item)
                ) for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.redact_value(item) for item in value]
        return value

    @staticmethod
    def _luhn_valid(value: str) -> bool:
        digits = [int(char) for char in value if char.isdigit()]
        if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
            return False
        checksum = 0
        parity = len(digits) % 2
        for index, digit in enumerate(digits):
            if index % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0
