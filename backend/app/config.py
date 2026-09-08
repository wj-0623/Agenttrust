from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    app_name: str = "AgentTrust"
    build_revision: str | None = os.getenv("AGENTTRUST_BUILD_REVISION")
    environment: str = os.getenv("AGENTTRUST_ENV", "development")
    database_path: Path = Path(
        os.getenv("AGENTTRUST_DB_PATH", str(BASE_DIR / "data" / "agenttrust.db"))
    )
    database_url: str | None = os.getenv("AGENTTRUST_DATABASE_URL")
    migration_database_url: str | None = os.getenv("AGENTTRUST_MIGRATION_DATABASE_URL")
    postgres_rls_enabled: bool = os.getenv(
        "AGENTTRUST_POSTGRES_RLS", "false"
    ).lower() == "true"
    postgres_app_role: str = os.getenv("AGENTTRUST_POSTGRES_APP_ROLE", "agenttrust_app")
    db_pool_size: int = int(os.getenv("AGENTTRUST_DB_POOL_SIZE", "10"))
    auto_initialize: bool = os.getenv("AGENTTRUST_AUTO_INITIALIZE", "true").lower() == "true"
    bootstrap_token: str | None = os.getenv("AGENTTRUST_BOOTSTRAP_TOKEN")
    cors_origins: tuple[str, ...] = tuple(
        origin.strip()
        for origin in os.getenv(
            "AGENTTRUST_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ).split(",")
        if origin.strip()
    )
    qwen_base_url: str = os.getenv(
        "QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"
    )
    qwen_api_key: str | None = os.getenv("DASHSCOPE_API_KEY")
    qwen_model: str = os.getenv("QWEN_MODEL", "qwen-plus")
    model_input_usd_per_million: float = float(os.getenv("AGENTTRUST_MODEL_INPUT_USD_PER_MILLION", "-1"))
    model_output_usd_per_million: float = float(os.getenv("AGENTTRUST_MODEL_OUTPUT_USD_PER_MILLION", "-1"))
    model_endpoint_allowlist: tuple[str, ...] = tuple(
        value.strip().rstrip("/") for value in os.getenv(
            "AGENTTRUST_MODEL_ENDPOINT_ALLOWLIST",
            os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        ).split(",") if value.strip()
    )
    external_agent_endpoint_allowlist: tuple[str, ...] = tuple(
        value.strip().rstrip("/")
        for value in os.getenv(
            "AGENTTRUST_EXTERNAL_AGENT_ENDPOINT_ALLOWLIST",
            "",
        ).split(",")
        if value.strip()
    )
    external_agent_bearer_token: str | None = os.getenv(
        "AGENTTRUST_EXTERNAL_AGENT_BEARER_TOKEN"
    )
    require_api_key: bool = os.getenv("AGENTTRUST_REQUIRE_API_KEY", "false").lower() == "true"
    oidc_issuer: str | None = os.getenv("AGENTTRUST_OIDC_ISSUER")
    oidc_audience: str = os.getenv("AGENTTRUST_OIDC_AUDIENCE", "agenttrust-api")
    oidc_jwks_url: str | None = os.getenv("AGENTTRUST_OIDC_JWKS_URL")
    oidc_algorithms: tuple[str, ...] = tuple(
        item.strip()
        for item in os.getenv("AGENTTRUST_OIDC_ALGORITHMS", "RS256,ES256").split(",")
        if item.strip()
    )
    oidc_jwks_cache_seconds: int = int(os.getenv("AGENTTRUST_OIDC_JWKS_CACHE_SECONDS", "300"))
    otel_enabled: bool = os.getenv("AGENTTRUST_OTEL_ENABLED", "false").lower() == "true"
    otel_exporter_otlp_endpoint: str | None = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    otel_service_name: str = os.getenv("OTEL_SERVICE_NAME", "agenttrust-api")
    phoenix_project_name: str = os.getenv("PHOENIX_PROJECT_NAME", "agenttrust-security")
    temporal_enabled: bool = os.getenv("AGENTTRUST_TEMPORAL_ENABLED", "false").lower() == "true"
    temporal_target: str = os.getenv("AGENTTRUST_TEMPORAL_TARGET", "temporal:7233")
    temporal_namespace: str = os.getenv("AGENTTRUST_TEMPORAL_NAMESPACE", "default")
    temporal_task_queue: str = os.getenv("AGENTTRUST_TEMPORAL_TASK_QUEUE", "agenttrust-refunds-v2")
    trusted_proxy_hops: int = int(os.getenv("AGENTTRUST_TRUSTED_PROXY_HOPS", "0"))
    security_hsts_enabled: bool = os.getenv(
        "AGENTTRUST_SECURITY_HSTS",
        "true" if os.getenv("AGENTTRUST_ENV", "development") == "production" else "false",
    ).lower() == "true"
    sandbox_timeout_seconds: float = float(os.getenv("AGENTTRUST_SANDBOX_TIMEOUT", "2.0"))
    sandbox_max_output_chars: int = int(os.getenv("AGENTTRUST_SANDBOX_MAX_OUTPUT", "12000"))
    max_request_body_bytes: int = int(os.getenv("AGENTTRUST_MAX_REQUEST_BODY_BYTES", "1048576"))
    max_upstream_response_bytes: int = int(os.getenv("AGENTTRUST_MAX_UPSTREAM_RESPONSE_BYTES", "2097152"))
    docs_enabled: bool = os.getenv(
        "AGENTTRUST_DOCS_ENABLED",
        "false" if os.getenv("AGENTTRUST_ENV", "development") == "production" else "true",
    ).lower() == "true"
    dlp_enabled: bool = os.getenv("AGENTTRUST_DLP_ENABLED", "true").lower() == "true"
    dlp_input_action: str = os.getenv("AGENTTRUST_DLP_INPUT_ACTION", "redact")
    dlp_output_action: str = os.getenv("AGENTTRUST_DLP_OUTPUT_ACTION", "block")
    security_webhook_url: str | None = os.getenv("AGENTTRUST_SECURITY_WEBHOOK_URL")
    security_webhook_secret: str | None = os.getenv("AGENTTRUST_SECURITY_WEBHOOK_SECRET")
    audit_anchor_secret: str | None = os.getenv("AGENTTRUST_AUDIT_ANCHOR_SECRET")
    audit_worm_bucket: str | None = os.getenv("AGENTTRUST_AUDIT_WORM_BUCKET")
    audit_worm_retention_days: int = int(os.getenv("AGENTTRUST_AUDIT_WORM_RETENTION_DAYS", "365"))
    correction_canary_min_observations: int = int(
        os.getenv("AGENTTRUST_CORRECTION_CANARY_MIN_OBSERVATIONS", "50")
    )
    correction_canary_max_error_rate: float = float(
        os.getenv("AGENTTRUST_CORRECTION_CANARY_MAX_ERROR_RATE", "0.01")
    )
    correction_canary_max_false_positive_rate: float = float(
        os.getenv("AGENTTRUST_CORRECTION_CANARY_MAX_FALSE_POSITIVE_RATE", "0.02")
    )
    correction_auto_promote_development: bool = os.getenv(
        "AGENTTRUST_CORRECTION_AUTO_PROMOTE_DEVELOPMENT", "false"
    ).lower() == "true"
    correction_canary_percent: int = int(os.getenv("AGENTTRUST_CORRECTION_CANARY_PERCENT", "10"))
    correction_canary_min_benign: int = int(os.getenv("AGENTTRUST_CORRECTION_MIN_BENIGN", "25"))
    correction_canary_min_attacks: int = int(os.getenv("AGENTTRUST_CORRECTION_MIN_ATTACKS", "10"))
    correction_canary_min_seconds: int = int(os.getenv("AGENTTRUST_CORRECTION_MIN_SECONDS", "300"))
    correction_max_latency_ms: int = int(os.getenv("AGENTTRUST_CORRECTION_MAX_LATENCY_MS", "5000"))
    phoenix_base_url: str | None = os.getenv("PHOENIX_BASE_URL")
    phoenix_api_key: str | None = os.getenv("PHOENIX_API_KEY")
    semantic_detector_url: str | None = os.getenv("AGENTTRUST_SEMANTIC_DETECTOR_URL")
    semantic_detector_key: str | None = os.getenv("AGENTTRUST_SEMANTIC_DETECTOR_KEY")
    semantic_detector_required: bool = os.getenv("AGENTTRUST_SEMANTIC_DETECTOR_REQUIRED", "false").lower() == "true"

    def validate_deployment(self, *, api: bool = True) -> None:
        if self.environment != "production":
            return
        if not self.database_url or not self.database_url.startswith(("postgres://", "postgresql://")):
            raise RuntimeError("Production requires PostgreSQL")
        if not self.postgres_rls_enabled or self.auto_initialize or self.migration_database_url:
            raise RuntimeError("Production requires RLS and a separate offline migration job")
        if api and not self.require_api_key:
            raise RuntimeError("Production API requires authenticated access")
        if not self.audit_anchor_secret or len(self.audit_anchor_secret) < 32:
            raise RuntimeError("Production requires a strong audit signing secret (at least 32 characters)")


settings = Settings()
