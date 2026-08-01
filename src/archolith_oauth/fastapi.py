"""Optional FastAPI/ASGI adoption helpers.

Install with ``archolith-oauth[fastapi]``. The package deliberately leaves the
login and consent UI to the application, but supplies discovery, DCR, token,
JWKS, authorization redirect, and protected-resource middleware.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .key_store import SigningKeyStore
from .metadata import authorization_server_metadata, protected_resource_metadata
from .models import OAuthPrincipal
from .policy import ScopeRequirement
from .registration import (
    ClientMetadataError,
    register_public_client_for_server,
    validate_authorization_request,
)
from .runtime import OAuthRuntime
from .tokens import (
    TokenExchangeError,
    exchange_authorization_code,
    exchange_refresh_token,
)
from .verifier import OAuthAuthenticationError


def _path(url: str) -> str:
    return urlsplit(url).path or "/"


def _no_store(payload: dict[str, Any], *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        payload,
        status_code=status_code,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _token_error(exc: TokenExchangeError) -> JSONResponse:
    status = 500 if exc.error == "server_error" else 400
    return _no_store(
        {"error": exc.error, "error_description": exc.description},
        status_code=status,
    )


def create_protocol_router(
    runtime: OAuthRuntime,
    *,
    include_registration: bool = True,
    include_token: bool = True,
) -> APIRouter:
    """Create the non-UI OAuth routes for an embedded authorization service."""

    router = APIRouter()
    auth = runtime.authorization_config
    resource = runtime.resource_config

    async def auth_metadata() -> JSONResponse:
        return JSONResponse(authorization_server_metadata(auth))

    async def resource_metadata() -> JSONResponse:
        return JSONResponse(protected_resource_metadata(resource))

    async def jwks() -> JSONResponse:
        return JSONResponse(SigningKeyStore.public_jwks(runtime.signing_key))

    router.add_api_route(
        _path(auth.metadata_url),
        auth_metadata,
        methods=["GET"],
        include_in_schema=False,
    )
    router.add_api_route(
        _path(resource.metadata_url),
        resource_metadata,
        methods=["GET"],
        include_in_schema=False,
    )
    router.add_api_route(
        _path(auth.jwks_uri),
        jwks,
        methods=["GET"],
        include_in_schema=False,
    )

    if include_registration:

        async def register(request: Request) -> JSONResponse:
            try:
                body = await request.json()
            except Exception:
                body = None
            if not isinstance(body, dict):
                return JSONResponse(
                    {
                        "error": "invalid_client_metadata",
                        "error_description": "Request body must be a JSON object",
                    },
                    status_code=400,
                )
            try:
                client = register_public_client_for_server(body, config=auth)
                runtime.client_store.register(client)
            except ClientMetadataError as exc:
                return JSONResponse(
                    {"error": exc.error, "error_description": exc.description},
                    status_code=400,
                )
            grants = body.get("grant_types", ["authorization_code"])
            return JSONResponse(
                {
                    "client_id": client.client_id,
                    "client_id_issued_at": int(client.created_at),
                    "redirect_uris": list(client.redirect_uris),
                    "token_endpoint_auth_method": "none",
                    "grant_types": grants,
                    "response_types": ["code"],
                    "client_name": client.client_name,
                    "scope": " ".join(client.scopes),
                },
                status_code=201,
            )

        router.add_api_route(
            _path(auth.registration_endpoint),
            register,
            methods=["POST"],
            include_in_schema=False,
        )

    if include_token:

        async def token(request: Request) -> JSONResponse:
            try:
                form = await request.form()
            except Exception:
                return _no_store(
                    {
                        "error": "invalid_request",
                        "error_description": "Token request must be form encoded",
                    },
                    status_code=400,
                )
            grant_type = str(form.get("grant_type", ""))
            try:
                if grant_type == "authorization_code":
                    response = exchange_authorization_code(
                        code_store=runtime.code_store,
                        client_store=runtime.client_store,
                        issuer=runtime.token_issuer,
                        code=str(form.get("code", "")),
                        client_id=str(form.get("client_id", "")),
                        redirect_uri=str(form.get("redirect_uri", "")),
                        code_verifier=str(form.get("code_verifier", "")),
                        resource=str(form.get("resource", "")),
                        refresh_store=runtime.refresh_store,
                    )
                elif grant_type == "refresh_token":
                    if runtime.refresh_store is None:
                        raise TokenExchangeError(
                            "unsupported_grant_type",
                            "refresh_token grant is not enabled",
                        )
                    response = exchange_refresh_token(
                        refresh_store=runtime.refresh_store,
                        client_store=runtime.client_store,
                        issuer=runtime.token_issuer,
                        refresh_token=str(form.get("refresh_token", "")),
                        client_id=str(form.get("client_id", "")),
                        resource=str(form.get("resource", "")),
                    )
                else:
                    raise TokenExchangeError(
                        "unsupported_grant_type",
                        "Only advertised grant types are supported",
                    )
            except TokenExchangeError as exc:
                return _token_error(exc)
            return _no_store(response.as_dict())

        router.add_api_route(
            _path(auth.token_endpoint),
            token,
            methods=["POST"],
            include_in_schema=False,
        )

    return router


def authorize_and_redirect(
    runtime: OAuthRuntime,
    *,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    requested_scope: str,
    code_challenge: str,
    code_challenge_method: str,
    resource: str,
    subject: str,
    state: str = "",
) -> str:
    """Validate an approved request, issue a code, and build the safe redirect."""

    client = runtime.client_store.get(client_id)
    if client is None:
        raise ValueError("unknown client_id")
    grant = validate_authorization_request(
        client=client,
        response_type=response_type,
        redirect_uri=redirect_uri,
        requested_scope=requested_scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        resource=resource,
        expected_resource=runtime.authorization_config.resource,
        subject=subject,
    )
    code = runtime.code_store.issue(grant)
    parsed = urlsplit(redirect_uri)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("code", code))
    if state:
        query.append(("state", state))
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
    )


ScopeResolver = Callable[[str, str], ScopeRequirement | None]


class OAuthBearerMiddleware:
    """Protect selected ASGI path prefixes and bind the verified principal to state."""

    def __init__(
        self,
        app,
        *,
        runtime: OAuthRuntime,
        protected_paths: Iterable[str] = ("/mcp",),
        scope_resolver: ScopeResolver | None = None,
    ) -> None:
        self.app = app
        self.runtime = runtime
        self.protected_paths = tuple(path.rstrip("/") or "/" for path in protected_paths)
        self.scope_resolver = scope_resolver

    def _protected(self, path: str) -> bool:
        return any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in self.protected_paths
        )

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or not self._protected(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        authorization = headers.get("authorization", "")
        token = authorization[7:].strip() if authorization.startswith("Bearer ") else ""
        method = str(scope.get("method", "GET"))
        path = str(scope.get("path", ""))
        requirement = self.scope_resolver(method, path) if self.scope_resolver else None

        try:
            principal = await self.runtime.token_verifier.verify(
                token,
                required_scopes=(
                    set(requirement.scopes)
                    if requirement is not None and requirement.mode == "all"
                    else None
                ),
                any_scopes=(
                    set(requirement.scopes)
                    if requirement is not None and requirement.mode == "any"
                    else None
                ),
            )
        except OAuthAuthenticationError as exc:
            challenge = self.runtime.resource_config.challenge(
                error=exc.error,
                description=exc.description,
                scope=exc.scope,
            )
            payload = json.dumps(
                {"error": exc.error, "error_description": exc.description}
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": exc.status_code,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"cache-control", b"no-store"),
                        (b"www-authenticate", challenge.encode("latin-1")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": payload})
            return

        scope.setdefault("state", {})["oauth_principal"] = principal
        await self.app(scope, receive, send)


def get_oauth_principal(request: Request) -> OAuthPrincipal:
    principal = getattr(request.state, "oauth_principal", None)
    if not isinstance(principal, OAuthPrincipal):
        raise RuntimeError("request has no verified OAuth principal")
    return principal
