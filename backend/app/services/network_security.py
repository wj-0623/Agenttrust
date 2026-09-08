from __future__ import annotations

import ipaddress
import json
import socket
from typing import Any
from urllib.parse import urlparse

import httpx


class UnsafeOutboundDestination(ValueError):
    pass


def validate_http_endpoint(endpoint: str) -> None:
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeOutboundDestination("endpoint must use HTTP(S) and include a hostname")
    if parsed.username or parsed.password:
        raise UnsafeOutboundDestination("endpoint must not contain embedded credentials")
    if len(endpoint) > 2048:
        raise UnsafeOutboundDestination("endpoint is too long")


def validate_outbound_destination(endpoint: str, *, allow_development_loopback: bool = False) -> None:
    """Fail closed unless every resolved address is globally routable.

    The check covers literal addresses and DNS answers. Production deployments should
    additionally enforce the same policy at the egress proxy/firewall to close the
    remaining DNS-rebinding interval between validation and connection.
    """
    validate_http_endpoint(endpoint)
    host = urlparse(endpoint).hostname or ""
    if allow_development_loopback and host.lower() in {"localhost", "127.0.0.1", "::1"}:
        return

    try:
        literal = ipaddress.ip_address(host)
        addresses = {literal}
    except ValueError:
        try:
            answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise UnsafeOutboundDestination("endpoint hostname could not be resolved") from exc
        addresses = {ipaddress.ip_address(answer[4][0]) for answer in answers}

    if not addresses or any(
        not address.is_global
        or address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_private
        for address in addresses
    ):
        raise UnsafeOutboundDestination(
            "outbound proxy forbids private, loopback, link-local, reserved, multicast, or unspecified addresses"
        )


async def read_limited_json(response: httpx.Response, max_bytes: int) -> dict[str, Any]:
    content_length = response.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise ValueError("upstream response exceeds the configured size limit")
        except ValueError as exc:
            if "exceeds" in str(exc):
                raise
            raise ValueError("upstream returned an invalid Content-Length") from exc

    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("upstream response exceeds the configured size limit")
        chunks.append(chunk)
    try:
        result = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("upstream returned a non-JSON response") from exc
    if not isinstance(result, dict):
        raise ValueError("upstream JSON-RPC response must be an object")  # noqa: TRY004
    return result
