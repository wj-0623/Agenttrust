from __future__ import annotations

import math
from typing import Any

import httpx

from ..config import settings
from .network_security import validate_http_endpoint


def detect_semantic(text: str) -> dict[str, Any] | None:
    """Adapter contract for self-hosted PromptGuard/LlamaFirewall classifiers.

    The URL is deployment configuration, never accepted from an API request.
    No model is silently downloaded and no production content is sent by default.
    """
    if not settings.semantic_detector_url:
        if settings.semantic_detector_required:
            return {"detector": "semantic_model", "category": "detector_unavailable", "score": 1.0,
                    "severity": "critical", "reasons": ["required semantic detector is not configured"]}
        return None
    try:
        validate_http_endpoint(settings.semantic_detector_url)
        headers = {"Authorization": f"Bearer {settings.semantic_detector_key}"} if settings.semantic_detector_key else {}
        with httpx.Client(timeout=2, follow_redirects=False, trust_env=False) as client:  # noqa: SIM117
            with client.stream("POST", settings.semantic_detector_url, json={"text": text[:32000]}, headers=headers) as response:
                response.raise_for_status()
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > 8192:
                        raise ValueError("Detector response too large")
                import json
                result = json.loads(content)
        score = float(result["score"])
        if not math.isfinite(score) or not 0 <= score <= 1 or not isinstance(result.get("model_version"), str):
            raise ValueError("Invalid detector score or missing model version")
        return {"detector": "semantic_model", "category": "semantic_risk", "score": score,
                "severity": "high" if score >= .7 else "low", "reasons": ["model risk score"],
                "model_version": result["model_version"][:100]}
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return {"detector": "semantic_model", "category": "detector_unavailable",
                "score": 1.0 if settings.semantic_detector_required else 0.0,
                "severity": "critical" if settings.semantic_detector_required else "medium",
                "reasons": ["semantic detector failed; required detectors fail closed"]}
