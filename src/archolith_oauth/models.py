"""Protocol-neutral OAuth data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class OAuthPrincipal:
    subject: str
    client_id: str = ""
    client_name: str = ""
    scopes: frozenset[str] = field(default_factory=frozenset)
    claims: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OAuthClient:
    client_id: str
    client_name: str
    redirect_uris: tuple[str, ...]
    scopes: tuple[str, ...]
    token_endpoint_auth_method: str = "none"
    created_at: float = 0.0
    last_exchanged: float | None = None


@dataclass(frozen=True)
class AuthorizationGrant:
    client_id: str
    redirect_uri: str
    scope: str
    code_challenge: str
    code_challenge_method: str
    resource: str
    subject: str


@dataclass(frozen=True)
class AuthCodeRecord(AuthorizationGrant):
    created_at: float = 0.0
    expires_at: float = 0.0
    redeemed_at: float | None = None
