from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from archolith_oauth import (
    ConsentNonceStore,
    ConsentTokenError,
    ConsentTokenManager,
    OAuthRuntime,
    OAuthSettings,
    ScopePolicy,
    ScopePolicyError,
    ScopeRequirement,
    s256_challenge,
)
from archolith_oauth.fastapi import (
    OAuthBearerMiddleware,
    authorize_and_redirect,
    create_protocol_router,
    get_oauth_principal,
)


def test_settings_runtime_and_redacted_preflight(tmp_path):
    settings = OAuthSettings.from_env(
        "TEST_OAUTH_",
        environ={
            "TEST_OAUTH_ISSUER": "https://auth.example.com/harness",
            "TEST_OAUTH_RESOURCE": "https://service.example.com/mcp",
            "TEST_OAUTH_SCOPES": "service:read,service:write service:admin",
            "TEST_OAUTH_DEFAULT_SCOPES": "service:read",
            "TEST_OAUTH_DATA_DIR": str(tmp_path / "oauth"),
            "TEST_OAUTH_REFRESH_TOKENS_ENABLED": "true",
            "TEST_OAUTH_CONSENT_SECRET": "s" * 32,
        },
    )
    assert settings.default_scopes == ("service:read",)
    assert settings.issue_refresh_tokens is True
    assert settings.redacted()["consent_secret_configured"] is True
    assert "consent_secret" not in settings.redacted()
    assert settings.preflight(require_consent_secret=True).ok

    runtime = OAuthRuntime.from_settings(settings)
    assert runtime.refresh_store is not None
    assert settings.signing_key_path.exists()


def test_consent_transactions_are_bound_and_single_use(tmp_path):
    manager = ConsentTokenManager("x" * 32, transaction_ttl_s=300)
    nonces = ConsentNonceStore(tmp_path / "oauth.db")
    params = {
        "redirect_uri": "https://chat.example.com/callback",
        "scope": "service:read",
        "resource": "https://service.example.com/mcp",
    }
    token = manager.create_transaction(
        client_id="client-1",
        params=params,
        subject="user-1",
        now=100,
    )
    transaction = manager.verify_transaction(
        token,
        expected_params=params,
        nonce_store=nonces,
        consume=True,
        now=101,
    )
    assert transaction.client_id == "client-1"
    assert transaction.subject == "user-1"

    with pytest.raises(ConsentTokenError):
        manager.verify_transaction(
            token,
            expected_params=params,
            nonce_store=nonces,
            consume=True,
            now=102,
        )
    with pytest.raises(ConsentTokenError):
        manager.verify_transaction(
            token,
            expected_params={**params, "scope": "service:admin"},
            now=102,
        )

    session_token = manager.create_session(
        subject="user-1",
        approved_clients={"client-2", "client-1"},
        now=100,
    )
    session = manager.verify_session(session_token, now=101)
    assert session.approved_clients == ("client-1", "client-2")


def test_scope_policy_enforces_and_filters():
    policy = ScopePolicy(
        {
            "list_sessions": "harness:read",
            "start_session": ("harness:read", "harness:session"),
            "admin_any": ScopeRequirement(
                frozenset({"harness:session", "harness:admin"}),
                "any",
            ),
        }
    )
    assert policy.allows("list_sessions", {"harness:read"})
    assert not policy.allows("start_session", {"harness:session"})
    assert policy.allows("admin_any", {"harness:session"})
    assert policy.filter_names(
        ["list_sessions", "start_session"],
        {"harness:read"},
    ) == ["list_sessions"]
    with pytest.raises(ScopePolicyError):
        policy.require("start_session", {"harness:read"})


def test_fastapi_protocol_and_middleware(tmp_path):
    settings = OAuthSettings(
        issuer="https://auth.example.com/harness",
        resource="https://service.example.com/mcp",
        scopes_supported=("service:read", "service:write", "service:admin"),
        default_scopes=("service:read",),
        data_dir=tmp_path / "oauth",
    )
    runtime = OAuthRuntime.from_settings(settings)
    app = FastAPI()
    app.include_router(create_protocol_router(runtime))
    client = TestClient(app)

    auth_metadata = client.get(urlsplit(runtime.authorization_config.metadata_url).path)
    assert auth_metadata.status_code == 200
    resource_metadata = client.get(urlsplit(runtime.resource_config.metadata_url).path)
    assert resource_metadata.status_code == 200

    registration = client.post(
        urlsplit(runtime.authorization_config.registration_endpoint).path,
        json={
            "redirect_uris": ["https://chat.example.com/callback"],
            "client_name": "Chat client",
        },
    )
    assert registration.status_code == 201
    registered = registration.json()
    assert registered["scope"] == "service:read"

    verifier = "v" * 64
    redirect = authorize_and_redirect(
        runtime,
        client_id=registered["client_id"],
        redirect_uri="https://chat.example.com/callback",
        response_type="code",
        requested_scope="service:read",
        code_challenge=s256_challenge(verifier),
        code_challenge_method="S256",
        resource=settings.resource,
        subject="user-1",
        state="state-1",
    )
    query = parse_qs(urlsplit(redirect).query)
    assert query["state"] == ["state-1"]

    token_response = client.post(
        urlsplit(runtime.authorization_config.token_endpoint).path,
        data={
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "client_id": registered["client_id"],
            "redirect_uri": "https://chat.example.com/callback",
            "code_verifier": verifier,
            "resource": settings.resource,
        },
    )
    assert token_response.status_code == 200
    access_token = token_response.json()["access_token"]

    protected = FastAPI()

    @protected.get("/mcp")
    async def mcp(request: Request):
        principal = get_oauth_principal(request)
        return {"subject": principal.subject, "scopes": sorted(principal.scopes)}

    protected.add_middleware(
        OAuthBearerMiddleware,
        runtime=runtime,
        protected_paths=("/mcp",),
        scope_resolver=lambda _method, _path: ScopeRequirement(
            frozenset({"service:read"}),
            "all",
        ),
    )
    protected_client = TestClient(protected)
    unauthorized = protected_client.get("/mcp")
    assert unauthorized.status_code == 401
    assert "resource_metadata" in unauthorized.headers["www-authenticate"]

    authorized = protected_client.get(
        "/mcp",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert authorized.status_code == 200
    assert authorized.json()["subject"] == "user-1"
