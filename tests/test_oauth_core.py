from __future__ import annotations

from pathlib import Path

import pytest

from archolith_oauth import (
    AccessTokenVerifier,
    AuthorizationCodeStore,
    AuthorizationServerConfig,
    ClientMetadataError,
    OAuthAuthenticationError,
    OAuthClientStore,
    ResourceServerConfig,
    SigningKeyStore,
    TokenIssuer,
    authorization_server_metadata,
    exchange_authorization_code,
    protected_resource_metadata,
    register_public_client,
    s256_challenge,
    validate_authorization_request,
    verify_s256,
)


def test_metadata_defaults():
    auth = AuthorizationServerConfig(
        issuer="https://auth.example.com/",
        resource="https://service.example.com/mcp",
        scopes_supported=("service:read",),
    )
    assert auth.token_endpoint == "https://auth.example.com/oauth/token"
    assert authorization_server_metadata(auth)["grant_types_supported"] == [
        "authorization_code"
    ]

    resource = ResourceServerConfig(
        resource=auth.resource,
        authorization_servers=(auth.issuer,),
        issuer=auth.issuer,
        jwks_uri=auth.jwks_uri,
        scopes_supported=auth.scopes_supported,
        metadata_url="https://service.example.com/.well-known/oauth-protected-resource",
    )
    assert resource.audiences == (auth.resource,)
    assert protected_resource_metadata(resource)["bearer_methods_supported"] == [
        "header"
    ]
    assert resource.challenge().startswith("Bearer resource_metadata=")


def test_pkce():
    verifier = "a" * 64
    challenge = s256_challenge(verifier)
    assert verify_s256(verifier, challenge)
    assert not verify_s256("wrong", challenge)


def test_dcr_rejects_unsupported_scope_and_credentialed_redirect():
    with pytest.raises(ClientMetadataError):
        register_public_client(
            {
                "redirect_uris": ["https://chat.example.com/callback"],
                "scope": "service:admin",
            },
            supported_scopes=("service:read",),
        )

    with pytest.raises(ClientMetadataError):
        register_public_client(
            {"redirect_uris": ["https://user:secret@chat.example.com/callback"]},
            supported_scopes=("service:read",),
        )


@pytest.mark.asyncio
async def test_full_code_exchange_and_verification(tmp_path: Path):
    pytest.importorskip("joserfc")

    resource = "https://service.example.com/mcp"
    scopes = ("service:read", "service:write")
    auth = AuthorizationServerConfig(
        issuer="https://auth.example.com",
        resource=resource,
        scopes_supported=scopes,
    )
    client = register_public_client(
        {
            "redirect_uris": ["https://chat.example.com/callback"],
            "client_name": "Test client",
            "scope": "service:read service:write",
        },
        supported_scopes=scopes,
    )
    db = tmp_path / "oauth.db"
    clients = OAuthClientStore(db)
    codes = AuthorizationCodeStore(db)
    clients.register(client)

    verifier_text = "v" * 64
    grant = validate_authorization_request(
        client=client,
        response_type="code",
        redirect_uri=client.redirect_uris[0],
        requested_scope="service:read",
        code_challenge=s256_challenge(verifier_text),
        code_challenge_method="S256",
        resource=resource,
        expected_resource=resource,
        subject="user-1",
    )
    raw_code = codes.issue(grant)
    key_store = SigningKeyStore(tmp_path / "signing-key.json")
    key = key_store.load_or_create()
    token = exchange_authorization_code(
        code_store=codes,
        client_store=clients,
        issuer=TokenIssuer(auth, key),
        code=raw_code,
        client_id=client.client_id,
        redirect_uri=client.redirect_uris[0],
        code_verifier=verifier_text,
    )
    assert token.token_type == "Bearer"
    assert (
        codes.redeem(
            code=raw_code,
            client_id=client.client_id,
            redirect_uri=client.redirect_uris[0],
        )
        is None
    )

    async def load_jwks():
        return SigningKeyStore.public_jwks(key)

    rs = ResourceServerConfig(
        resource=resource,
        authorization_servers=(auth.issuer,),
        issuer=auth.issuer,
        jwks_uri=auth.jwks_uri,
        scopes_supported=scopes,
    )
    principal = await AccessTokenVerifier(rs, jwks_loader=load_jwks).verify(
        token.access_token,
        required_scopes={"service:read"},
    )
    assert principal.subject == "user-1"
    assert principal.client_id == client.client_id
    assert principal.scopes == frozenset({"service:read"})

    with pytest.raises(OAuthAuthenticationError) as exc:
        await AccessTokenVerifier(rs, jwks_loader=load_jwks).verify(
            token.access_token,
            required_scopes={"service:admin"},
        )
    assert exc.value.status_code == 403
