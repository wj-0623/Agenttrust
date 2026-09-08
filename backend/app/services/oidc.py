from __future__ import annotations

import threading
from typing import Any
from urllib.parse import urlparse

import httpx
import jwt

from ..config import Settings


class OIDCAuthenticationError(RuntimeError):
    pass


class OIDCAuthenticator:
    """Strict OIDC JWT validation with cached discovery and signing keys."""

    def __init__(self, config: Settings):
        self.config = config
        self._jwk_client: jwt.PyJWKClient | None = None
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.config.oidc_issuer)

    def _client(self) -> jwt.PyJWKClient:
        if self._jwk_client:
            return self._jwk_client
        with self._lock:
            if self._jwk_client:
                return self._jwk_client
            issuer = (self.config.oidc_issuer or "").rstrip("/")
            jwks_url = self.config.oidc_jwks_url
            if not jwks_url:
                discovery_url = f"{issuer}/.well-known/openid-configuration"
                try:
                    response = httpx.get(discovery_url, timeout=5.0, follow_redirects=False)
                    response.raise_for_status()
                    if len(response.content) > 1_000_000:
                        raise OIDCAuthenticationError("OIDC discovery response is too large")
                    discovery = response.json()
                except (httpx.HTTPError, ValueError) as exc:
                    raise OIDCAuthenticationError("OIDC discovery failed") from exc
                if discovery.get("issuer", "").rstrip("/") != issuer:
                    raise OIDCAuthenticationError("OIDC discovery issuer mismatch")
                jwks_url = discovery.get("jwks_uri")
            parsed = urlparse(str(jwks_url))
            if parsed.scheme not in ({"https"} if self.config.environment == "production" else {"http", "https"}):
                raise OIDCAuthenticationError("OIDC JWKS must use an approved transport")
            self._jwk_client = jwt.PyJWKClient(
                str(jwks_url),
                cache_keys=True,
                lifespan=self.config.oidc_jwks_cache_seconds,
                timeout=5,
            )
            return self._jwk_client

    def verify(self, token: str) -> dict[str, Any]:
        if not self.enabled:
            raise OIDCAuthenticationError("OIDC is not configured")
        try:
            unverified = jwt.get_unverified_header(token)
            algorithm = unverified.get("alg")
            if algorithm not in self.config.oidc_algorithms or algorithm == "none":
                raise OIDCAuthenticationError("OIDC token algorithm is not allowed")
            signing_key = self._client().get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=list(self.config.oidc_algorithms),
                audience=self.config.oidc_audience,
                issuer=self.config.oidc_issuer,
                leeway=30,
                options={"require": ["exp", "iat", "iss", "sub", "aud"]},
            )
        except OIDCAuthenticationError:
            raise
        except jwt.PyJWTError as exc:
            raise OIDCAuthenticationError("OIDC token validation failed") from exc
        return dict(claims)
