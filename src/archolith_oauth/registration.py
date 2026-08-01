"""Dynamic client registration and authorization-request validation."""

from __future__ import annotations

import secrets
import time
from urllib.parse import urlsplit

from .models import AuthorizationGrant, OAuthClient


class ClientMetadataError(ValueError):
    def __init__(self, error: str, description: str) -> None:
        super().__init__(description)
        self.error = error
        self.description = description


def _valid_redirect_uri(uri: str) -> bool:
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return False
    if (
        parsed.fragment
        or not parsed.scheme
        or not parsed.netloc
        or parsed.username
        or parsed.password
    ):
        return False
    if parsed.scheme == "https":
        return True
    if parsed.scheme != "http":
        return False
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def register_public_client(
    metadata: dict,
    *,
    supported_scopes: tuple[str, ...],
    max_redirect_uris: int = 5,
) -> OAuthClient:
    redirect_uris = metadata.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise ClientMetadataError("invalid_redirect_uri", "redirect_uris is required")
    if len(redirect_uris) > max_redirect_uris:
        raise ClientMetadataError("invalid_redirect_uri", "too many redirect URIs")
    normalized = tuple(str(uri).strip() for uri in redirect_uris)
    if any(not _valid_redirect_uri(uri) for uri in normalized):
        raise ClientMetadataError("invalid_redirect_uri", "redirect URI is not allowed")

    auth_method = str(metadata.get("token_endpoint_auth_method", "none"))
    if auth_method != "none":
        raise ClientMetadataError(
            "invalid_client_metadata", "only public clients are supported"
        )
    grants = metadata.get("grant_types", ["authorization_code"])
    responses = metadata.get("response_types", ["code"])
    if grants != ["authorization_code"] or responses != ["code"]:
        raise ClientMetadataError(
            "invalid_client_metadata",
            "only authorization_code with response_type=code is supported",
        )

    requested = tuple(str(metadata.get("scope", "")).split())
    allowed = set(supported_scopes)
    unsupported = set(requested) - allowed
    if unsupported:
        raise ClientMetadataError(
            "invalid_client_metadata",
            "requested scope is not supported",
        )
    scopes = requested or tuple(supported_scopes)
    return OAuthClient(
        client_id=secrets.token_urlsafe(24),
        client_name=str(metadata.get("client_name", "OAuth client"))[:200],
        redirect_uris=normalized,
        scopes=scopes,
        token_endpoint_auth_method="none",
        created_at=time.time(),
    )


def validate_authorization_request(
    *,
    client: OAuthClient,
    response_type: str,
    redirect_uri: str,
    requested_scope: str,
    code_challenge: str,
    code_challenge_method: str,
    resource: str,
    expected_resource: str,
    subject: str,
) -> AuthorizationGrant:
    if redirect_uri not in client.redirect_uris:
        raise ValueError("redirect_uri does not exactly match a registered URI")
    if response_type != "code":
        raise ValueError("only response_type=code is supported")
    if not code_challenge or code_challenge_method != "S256":
        raise ValueError("PKCE S256 is required")
    if resource and resource != expected_resource:
        raise ValueError("resource does not match this authorization server")
    requested = tuple(part for part in requested_scope.split() if part) or client.scopes
    if not set(requested).issubset(set(client.scopes)):
        raise ValueError("requested scope exceeds the client's registered scopes")
    return AuthorizationGrant(
        client_id=client.client_id,
        redirect_uri=redirect_uri,
        scope=" ".join(requested),
        code_challenge=code_challenge,
        code_challenge_method="S256",
        resource=expected_resource,
        subject=subject,
    )
