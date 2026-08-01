"""Access-token issuance and authorization-code exchange."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from . import jose
from .config import AuthorizationServerConfig
from .models import OAuthClient
from .pkce import verify_s256
from .stores import AuthorizationCodeStore, OAuthClientStore


class TokenExchangeError(ValueError):
    """OAuth token-endpoint error that an HTTP adapter can render directly."""

    def __init__(self, error: str, description: str) -> None:
        super().__init__(description)
        self.error = error
        self.description = description


@dataclass(frozen=True)
class TokenResponse:
    access_token: str
    token_type: str
    expires_in: int
    scope: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": self.scope,
        }


class TokenIssuer:
    def __init__(self, config: AuthorizationServerConfig, signing_key) -> None:
        if "RS256" not in config.allowed_algorithms:
            raise ValueError("TokenIssuer currently requires RS256")
        self.config = config
        self.signing_key = signing_key

    def issue(
        self,
        *,
        subject: str,
        client: OAuthClient,
        scope: str,
        resource: str = "",
    ) -> TokenResponse:
        target_resource = resource or self.config.resource
        if target_resource != self.config.resource:
            raise ValueError("token resource does not match authorization server")
        now = int(time.time())
        ttl = self.config.access_token_ttl_s
        public = jose.serialize_key(self.signing_key, private=False)
        header = {"alg": "RS256", "kid": public["kid"], "typ": "JWT"}
        claims = {
            "iss": self.config.issuer,
            "sub": subject,
            "aud": target_resource,
            "client_id": client.client_id,
            "client_name": client.client_name,
            "scope": scope,
            "iat": now,
            "exp": now + ttl,
        }
        return TokenResponse(
            access_token=jose.sign_jwt(header, claims, self.signing_key),
            token_type="Bearer",
            expires_in=ttl,
            scope=scope,
        )


def exchange_authorization_code(
    *,
    code_store: AuthorizationCodeStore,
    client_store: OAuthClientStore,
    issuer: TokenIssuer,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
    resource: str,
) -> TokenResponse:
    """Redeem one authorization code using PKCE and RFC 8707 resource binding.

    MCP clients are required to send the same canonical ``resource`` value at
    both authorization and token exchange. The code is atomically consumed
    before binding/PKCE validation, matching OAuth's defensive single-use model.
    """
    if not resource:
        raise TokenExchangeError("invalid_request", "resource is required")
    record = code_store.redeem(
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
    )
    if record is None:
        raise TokenExchangeError(
            "invalid_grant",
            "authorization code is invalid, expired, or already used",
        )
    if resource != record.resource or resource != issuer.config.resource:
        raise TokenExchangeError(
            "invalid_grant",
            "resource does not match the authorization request",
        )
    if record.code_challenge_method != "S256" or not verify_s256(
        code_verifier,
        record.code_challenge,
    ):
        raise TokenExchangeError("invalid_grant", "PKCE verification failed")
    client = client_store.get(client_id)
    if client is None:
        raise TokenExchangeError("invalid_grant", "registered client no longer exists")
    response = issuer.issue(
        subject=record.subject,
        client=client,
        scope=record.scope,
        resource=resource,
    )
    client_store.mark_exchanged(client_id)
    return response
