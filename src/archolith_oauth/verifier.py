"""JWT access-token verifier with bounded JWKS caching."""

from __future__ import annotations

import asyncio
import base64
import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from . import jose
from .config import ResourceServerConfig
from .models import OAuthPrincipal


class OAuthAuthenticationError(Exception):
    def __init__(
        self,
        error: str,
        description: str,
        *,
        status_code: int = 401,
        scope: str | None = None,
    ) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status_code = status_code
        self.scope = scope


def extract_scopes(claims: dict[str, Any]) -> frozenset[str]:
    values: set[str] = set()
    for key in ("scope", "scp", "permissions"):
        raw = claims.get(key)
        if isinstance(raw, str):
            values.update(raw.split())
        elif isinstance(raw, (list, tuple, set)):
            values.update(str(item).strip() for item in raw if str(item).strip())
    return frozenset(values)


def _derive_subject(claims: dict[str, Any]) -> str:
    if claims.get("sub"):
        return str(claims["sub"])
    client = claims.get("client_id") or claims.get("azp")
    if client:
        return f"client:{client}"
    raise OAuthAuthenticationError(
        "invalid_token",
        "Access token has no subject or client identity",
    )


def _claim_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, (list, tuple, set)):
        return {str(item) for item in value}
    return set()


def _unverified_kid(token: str) -> str | None:
    try:
        segment = token.split(".")[0]
        payload = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        kid = json.loads(payload).get("kid")
        return str(kid) if kid else None
    except Exception:
        return None


class AccessTokenVerifier:
    def __init__(
        self,
        config: ResourceServerConfig,
        *,
        jwks_loader: Callable[[], Awaitable[dict]] | None = None,
    ) -> None:
        self.config = config
        self._custom_loader = jwks_loader
        self._jwks = None
        self._jwks_expires_at = 0.0
        self._lock = asyncio.Lock()
        self._last_forced_refresh = 0.0

    async def verify(
        self,
        token: str,
        *,
        required_scopes: set[str] | None = None,
    ) -> OAuthPrincipal:
        if not token:
            raise OAuthAuthenticationError("invalid_token", "Missing bearer token")
        claims = await self._decode(token)
        if claims.get("iss") != self.config.issuer:
            raise OAuthAuthenticationError(
                "invalid_token",
                "Access token issuer is not trusted",
            )
        if "exp" not in claims:
            raise OAuthAuthenticationError(
                "invalid_token",
                "Access token is missing exp",
            )
        token_resources = _claim_values(claims.get("aud")) | _claim_values(
            claims.get("resource")
        )
        if not token_resources.intersection(self.config.audiences):
            raise OAuthAuthenticationError(
                "invalid_token",
                "Access token audience/resource does not match",
            )
        scopes = extract_scopes(claims)
        if required_scopes and not scopes.intersection(required_scopes):
            raise OAuthAuthenticationError(
                "insufficient_scope",
                "Access token does not include a required scope",
                status_code=403,
                scope=" ".join(sorted(required_scopes)),
            )
        return OAuthPrincipal(
            subject=_derive_subject(claims),
            client_id=str(claims.get("client_id") or claims.get("azp") or ""),
            client_name=str(claims.get("client_name") or ""),
            scopes=scopes,
            claims=dict(claims),
        )

    async def _decode(self, token: str) -> dict[str, Any]:
        keyset = await self._load_jwks()
        try:
            return jose.verify_jwt(
                token,
                keyset,
                list(self.config.allowed_algorithms),
                self.config.clock_skew_s,
            )
        except jose.JoseError as first:
            kid = _unverified_kid(token)
            if kid is None or jose.jwks_has_kid(keyset, kid):
                raise OAuthAuthenticationError("invalid_token", str(first)) from first
            if time.monotonic() - self._last_forced_refresh < 30:
                raise OAuthAuthenticationError("invalid_token", str(first)) from first
            self._last_forced_refresh = time.monotonic()
            keyset = await self._load_jwks(force=True)
            try:
                return jose.verify_jwt(
                    token,
                    keyset,
                    list(self.config.allowed_algorithms),
                    self.config.clock_skew_s,
                )
            except jose.JoseError as second:
                raise OAuthAuthenticationError("invalid_token", str(second)) from second

    async def _load_jwks(self, *, force: bool = False):
        now = time.monotonic()
        if not force and self._jwks is not None and now < self._jwks_expires_at:
            return self._jwks
        async with self._lock:
            now = time.monotonic()
            if not force and self._jwks is not None and now < self._jwks_expires_at:
                return self._jwks
            try:
                if self._custom_loader is not None:
                    payload = await self._custom_loader()
                else:
                    async with httpx.AsyncClient(
                        timeout=self.config.http_timeout_s
                    ) as client:
                        response = await client.get(self.config.jwks_uri)
                        response.raise_for_status()
                        payload = response.json()
                if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
                    raise ValueError("malformed JWKS")
                self._jwks = jose.parse_jwks(payload)
                self._jwks_expires_at = now + max(1, self.config.jwks_cache_ttl_s)
                return self._jwks
            except OAuthAuthenticationError:
                raise
            except Exception as exc:
                raise OAuthAuthenticationError(
                    "server_error",
                    "Unable to fetch OAuth JWKS",
                    status_code=503,
                ) from exc
