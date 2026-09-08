from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token

_workspace_id: ContextVar[str | None] = ContextVar("agenttrust_workspace_id", default=None)
_identity_id: ContextVar[str] = ContextVar("agenttrust_auth_identity", default="")


def current_workspace_id() -> str | None:
    return _workspace_id.get()


def bind_workspace(workspace_id: str | None) -> Token[str | None]:
    return _workspace_id.set(workspace_id)


def reset_workspace(token: Token[str | None]) -> None:
    _workspace_id.reset(token)


def current_identity_id() -> str:
    return _identity_id.get()


@contextmanager
def identity_lookup(identity_id: str) -> Iterator[None]:
    token = _identity_id.set(identity_id)
    try:
        yield
    finally:
        _identity_id.reset(token)


@contextmanager
def workspace_context(workspace_id: str) -> Iterator[None]:
    token = bind_workspace(workspace_id)
    try:
        yield
    finally:
        reset_workspace(token)
