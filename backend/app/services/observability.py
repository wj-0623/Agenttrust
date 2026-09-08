from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..config import settings
from ..db import Database, new_id, utc_now
from ..version import __version__


@dataclass(frozen=True)
class SpanHandle:
    id: str
    project_id: str
    started_monotonic: float
    native_span: Any | None = None


class ObservabilityService:
    """Local searchable spans plus a real OpenTelemetry/OTLP export path."""

    def __init__(self, db: Database):
        self.db = db
        self._native_spans: dict[str, Any] = {}
        self._tracer: Any | None = None
        self._provider: Any | None = None
        if settings.otel_enabled:
            self._configure_otel()

    def _configure_otel(self) -> None:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            provider = TracerProvider(
                resource=Resource.create(
                    {
                        "service.name": settings.otel_service_name,
                        "service.version": __version__,
                        "deployment.environment.name": settings.environment,
                        "openinference.project.name": settings.phoenix_project_name,
                    }
                )
            )
            if settings.otel_exporter_otlp_endpoint:
                provider.add_span_processor(
                    BatchSpanProcessor(
                        OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint)
                    )
                )
            self._provider = provider
            self._tracer = provider.get_tracer("agenttrust.control-plane", __version__)
        except Exception as exc:  # pragma: no cover - environment-specific startup failure
            if settings.environment == "production":
                raise RuntimeError("OTel was enabled but could not be configured") from exc
            self._tracer = None

    def start_span(
        self,
        project_id: str,
        name: str,
        kind: str = "INTERNAL",
        *,
        trace_id: str | None = None,
        workflow_id: str | None = None,
        parent_span_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> SpanHandle:
        span_id = new_id("span")
        native_span = None
        if self._tracer:
            from opentelemetry import trace

            parent = self._native_spans.get(parent_span_id or "")
            context = trace.set_span_in_context(parent) if parent else None
            safe_attributes = {
                key: value
                for key, value in (attributes or {}).items()
                if isinstance(value, (str, bool, int, float)) and value is not None
            }
            safe_attributes.update({"agenttrust.project.id": project_id, "agenttrust.span.id": span_id})
            if "openinference.span.kind" not in safe_attributes:
                lowered = name.lower()
                safe_attributes["openinference.span.kind"] = (
                    "LLM" if lowered.startswith("chat ") else
                    "TOOL" if "tool" in lowered else
                    "GUARDRAIL" if "policy" in lowered or "security" in lowered else
                    "AGENT"
                )
            native_span = self._tracer.start_span(name, context=context, attributes=safe_attributes)
            self._native_spans[span_id] = native_span
        self.db.execute(
            """
            INSERT INTO agent_spans
            (id, project_id, trace_id, workflow_id, parent_span_id, name, kind, status,
             attributes_json, started_at, ended_at, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'UNSET', ?, ?, NULL, 0)
            """,
            (
                span_id, project_id, trace_id, workflow_id, parent_span_id, name, kind,
                json.dumps(attributes or {}, ensure_ascii=False), utc_now(),
            ),
        )
        return SpanHandle(span_id, project_id, time.perf_counter(), native_span)

    def end_span(
        self,
        handle: SpanHandle,
        status: str = "OK",
        attributes: dict[str, Any] | None = None,
    ) -> str:
        current = self.db.query_one("SELECT attributes_json FROM agent_spans WHERE id = ?", (handle.id,))
        existing = json.loads(current["attributes_json"]) if current else {}
        existing.update(attributes or {})
        duration = max(0, int((time.perf_counter() - handle.started_monotonic) * 1000))
        self.db.execute(
            "UPDATE agent_spans SET status = ?, attributes_json = ?, ended_at = ?, duration_ms = ? WHERE id = ?",
            (status, json.dumps(existing, ensure_ascii=False), utc_now(), duration, handle.id),
        )
        if handle.native_span:
            from opentelemetry.trace import Status, StatusCode

            for key, value in (attributes or {}).items():
                if isinstance(value, (str, bool, int, float)) and value is not None:
                    handle.native_span.set_attribute(key, value)
            handle.native_span.set_status(
                Status(StatusCode.ERROR if status == "ERROR" else StatusCode.OK)
            )
            handle.native_span.end()
            self._native_spans.pop(handle.id, None)
        return handle.id

    def shutdown(self) -> None:
        if self._provider:
            self._provider.shutdown()

    def list_spans(self, project_id: str, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.db.query_all(
            "SELECT * FROM agent_spans WHERE project_id = ? ORDER BY started_at DESC LIMIT ?",
            (project_id, limit),
        )
        for row in rows:
            row["attributes"] = json.loads(row.pop("attributes_json"))
        return rows

    def metrics(self, project_id: str) -> dict[str, Any]:
        totals = self.db.query_one(
            """
            SELECT COUNT(*) AS spans_total,
                   COALESCE(AVG(duration_ms), 0) AS average_duration_ms,
                   SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) AS errors
            FROM agent_spans WHERE project_id = ?
            """,
            (project_id,),
        ) or {}
        operations = self.db.query_all(
            """
            SELECT name, COUNT(*) AS count, COALESCE(AVG(duration_ms), 0) AS average_duration_ms
            FROM agent_spans WHERE project_id = ? GROUP BY name ORDER BY count DESC
            """,
            (project_id,),
        )
        total = int(totals.get("spans_total") or 0)
        errors = int(totals.get("errors") or 0)
        return {
            "spans_total": total,
            "average_duration_ms": round(float(totals.get("average_duration_ms") or 0), 2),
            "error_rate": round(errors / total, 4) if total else 0.0,
            "operations": operations,
        }

    def export_otlp_json(self, project_id: str, limit: int = 500) -> dict[str, Any]:
        spans = self.list_spans(project_id, limit)
        by_id = {span["id"]: span for span in spans}
        def trace_hex(span: dict[str, Any]) -> str:
            seen = set()
            while span.get("parent_span_id") in by_id and span["id"] not in seen:
                seen.add(span["id"])
                span = by_id[span["parent_span_id"]]
            return hashlib.sha256(span["id"].encode()).hexdigest()[:32]
        encoded = []
        for span in reversed(spans):
            encoded.append(
                {
                    "traceId": trace_hex(span),
                    "spanId": hashlib.sha256(span["id"].encode()).hexdigest()[:16],
                    "parentSpanId": hashlib.sha256(span["parent_span_id"].encode()).hexdigest()[:16] if span.get("parent_span_id") else "",
                    "name": span["name"],
                    "kind": {"INTERNAL": 1, "SERVER": 2, "CLIENT": 3}.get(span["kind"], 1),
                    "startTimeUnixNano": str(int(datetime.fromisoformat(span["started_at"]).timestamp() * 1_000_000_000)),
                    "endTimeUnixNano": str(int(datetime.fromisoformat(span.get("ended_at") or span["started_at"]).timestamp() * 1_000_000_000)),
                    "status": {"code": {"UNSET": 0, "OK": 1, "ERROR": 2}.get(span["status"], 0)},
                    "attributes": [
                        {"key": key, "value": {"stringValue": json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value}}
                        for key, value in span["attributes"].items()
                    ],
                }
            )
        return {
            "resourceSpans": [{
                "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "agenttrust"}}]},
                "scopeSpans": [{"scope": {"name": "agenttrust.control-plane", "version": __version__}, "spans": encoded}],
            }]
        }
