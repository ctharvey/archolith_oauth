from __future__ import annotations

from pathlib import Path

import pytest

from archolith_oauth import (
    AccessTokenVerifier,
    AuthorizationCodeStore,
    AuthorizationServerConfig,
    OAuthClientStore,
    RefreshTokenStore,
    ResourceServerConfig,
    SigningKeyStore,
    TokenExchangeError,
    TokenIssuer,
    exchange_authorization_code,
    exchange_refresh_token,
    register_public_client,
    s256_challenge,
    validate_authorization_request,
)


@pytest.mark.asyncio
async def test_authorization_code_issues_rotating_refresh_token(tmp_path: Path):
    pytest.importorskip("joserfc")

    resource = "https://harness.example.com/mcp"
    config = AuthorizationServerConfig(
        issuer="https://auth.example.com/harness",
        resource=resource,
        scopes_supported=("harness:read", "harness:session"),
        issue_refresh_tokens=True,
    )
    client = register_public_client(
        {
            "redirect_uris": ["https://chat.example.com/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "harness:read offline_access",
        },
        supported_scopes=config.effective_scopes_supported,
        allow_refresh_tokens=True,
    )

    db = tmp_path / "oauth.db"
    clients = OAuthClientStore(db)
    codes = AuthorizationCodeStore(db)
    refreshes = RefreshTokenStore(db, ttl_s=config.refresh_token_ttl_s)
    clients.register(client)

    verifier_text = "v" * 64
    grant = validate_authorization_request(
        client=client,
        response_type="code",
        redirect_uri=client.redirect_uris[0],
        requested_scope="harness:read offline_access",
        code_challenge=s256_challenge(verifier_text),
        code_challenge_method="S256",
        resource=resource,
        expected_resource=resource,
        subject="user-1",
    )
    code = codes.issue(grant)
    key = SigningKeyStore(tmp_path / "signing-key.json").load_or_create()
    issuer = TokenIssuer(config, key)

    first = exchange_authorization_code(
        code_store=codes,
        client_store=clients,
        refresh_store=refreshes,
        issuer=issuer,
        code=code,
        client_id=client.client_id,
        redirect_uri=client.redirect_uris[0],
        code_verifier=verifier_text,
        resource=resource,
    )
    assert first.refresh_token

    second = exchange_refresh_token(
        refresh_store=refreshes,
        client_store=clients,
        issuer=issuer,
        refresh_token=first.refresh_token,
        client_id=client.client_id,
        resource=resource,
    )
    assert second.refresh_token
    assert second.refresh_token != first.refresh_token

    async def load_jwks():
        return SigningKeyStore.public_jwks(key)

    principal = await AccessTokenVerifier(
        ResourceServerConfig(
            resource=resource,
            authorization_servers=(config.issuer,),
            issuer=config.issuer,
            jwks_uri=config.jwks_uri,
            scopes_supported=config.effective_scopes_supported,
        ),
        jwks_loader=load_jwks,
    ).verify(second.access_token, required_scopes={"harness:read"})
    assert principal.subject == "user-1"
    assert principal.client_id == client.client_id

    with pytest.raises(TokenExchangeError) as replay:
        exchange_refresh_token(
            refresh_store=refreshes,
            client_store=clients,
            issuer=issuer,
            refresh_token=first.refresh_token,
            client_id=client.client_id,
            resource=resource,
        )
    assert replay.value.error == "invalid_grant"

    with pytest.raises(TokenExchangeError):
        exchange_refresh_token(
            refresh_store=refreshes,
            client_store=clients,
            issuer=issuer,
            refresh_token=second.refresh_token,
            client_id=client.client_id,
            resource=resource,
        )
