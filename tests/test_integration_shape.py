from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from archolith_oauth import (
    AccessTokenVerifier,
    AuthorizationCodeStore,
    AuthorizationServerConfig,
    OAuthAuthenticationError,
    ResourceServerConfig,
    authorization_server_metadata,
    register_public_client_for_server,
)


def test_path_aware_discovery_urls_and_cross_advertisement():
    config = AuthorizationServerConfig(
        issuer="https://auth.example.com/harness",
        resource="https://harness.example.com/mcp",
        scopes_supported=("harness:read",),
    )
    assert config.metadata_url == (
        "https://auth.example.com/.well-known/oauth-authorization-server/harness"
    )
    metadata = authorization_server_metadata(config)
    assert metadata["protected_resources"] == ["https://harness.example.com/mcp"]

    resource = ResourceServerConfig(
        resource=config.resource,
        authorization_servers=(config.issuer,),
        issuer=config.issuer,
        jwks_uri=config.jwks_uri,
        scopes_supported=config.scopes_supported,
    )
    assert resource.metadata_url == (
        "https://harness.example.com/.well-known/oauth-protected-resource/mcp"
    )
    assert f'resource_metadata="{resource.metadata_url}"' in resource.challenge()


def test_harness_default_scopes_exclude_admin_and_offline_access():
    config = AuthorizationServerConfig(
        issuer="https://auth.example.com/harness",
        resource="https://harness.example.com/mcp",
        scopes_supported=("harness:read", "harness:session", "harness:admin"),
        default_scopes=("harness:read", "harness:session"),
        issue_refresh_tokens=True,
    )
    client = register_public_client_for_server(
        {"redirect_uris": ["https://chat.example.com/callback"]},
        config=config,
    )
    assert client.scopes == ("harness:read", "harness:session")
    assert "harness:admin" not in client.scopes
    assert "offline_access" not in client.scopes


def test_menhir_keyword_authorization_code_issue_shape(tmp_path: Path):
    codes = AuthorizationCodeStore(tmp_path / "menhir_oauth_as.db")
    raw = codes.issue(
        client_id="menhir-client",
        redirect_uri="https://chat.example.com/callback",
        scope="menhir:read",
        code_challenge="challenge",
        code_challenge_method="S256",
        resource="https://memory.example.com/mcp-http",
        subject="menhir-admin",
    )
    record = codes.redeem(
        code=raw,
        client_id="menhir-client",
        redirect_uri="https://chat.example.com/callback",
    )
    assert record is not None
    assert record.resource == "https://memory.example.com/mcp-http"
    assert record.subject == "menhir-admin"


@pytest.mark.asyncio
async def test_required_scopes_are_all_of_and_any_scopes_are_explicit():
    config = ResourceServerConfig(
        resource="https://harness.example.com/mcp",
        authorization_servers=("https://auth.example.com/harness",),
        issuer="https://auth.example.com/harness",
        jwks_uri="https://auth.example.com/harness/.well-known/jwks.json",
        scopes_supported=("harness:read", "harness:session"),
    )
    verifier = AccessTokenVerifier(config)
    verifier._decode = AsyncMock(
        return_value={
            "iss": config.issuer,
            "sub": "user-1",
            "aud": config.resource,
            "exp": 4_000_000_000,
            "scope": "harness:read",
        }
    )

    with pytest.raises(OAuthAuthenticationError) as exc:
        await verifier.verify(
            "token",
            required_scopes={"harness:read", "harness:session"},
        )
    assert exc.value.status_code == 403

    principal = await verifier.verify(
        "token",
        any_scopes={"harness:read", "harness:session"},
    )
    assert principal.scopes == frozenset({"harness:read"})
