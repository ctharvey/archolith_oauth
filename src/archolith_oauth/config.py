"""OAuth resource-server and authorization-server configuration."""

from __future__ import annotations

from dataclasses import dataclass


def _clean_base(value: str) -> str:
    return value.strip().rstrip("/")


def _quote_header_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


@dataclass(frozen=True)
class ResourceServerConfig:
    resource: str
    authorization_servers: tuple[str, ...]
    issuer: str
    jwks_uri: str
    audiences: tuple[str, ...] = ()
    scopes_supported: tuple[str, ...] = ()
    allowed_algorithms: tuple[str, ...] = ("RS256",)
    jwks_cache_ttl_s: int = 300
    http_timeout_s: float = 5.0
    clock_skew_s: int = 60
    resource_name: str = "OAuth protected resource"
    metadata_url: str = ""

    def __post_init__(self) -> None:
        if not self.resource:
            raise ValueError("resource is required")
        if not self.issuer:
            raise ValueError("issuer is required")
        if not self.jwks_uri:
            raise ValueError("jwks_uri is required")
        if not self.authorization_servers:
            raise ValueError("authorization_servers is required")
        if not self.audiences:
            object.__setattr__(self, "audiences", (self.resource,))

    def challenge(
        self,
        *,
        error: str | None = None,
        description: str | None = None,
        scope: str | None = None,
    ) -> str:
        params: list[str] = []
        if self.metadata_url:
            params.append(f'resource_metadata="{_quote_header_value(self.metadata_url)}"')
        if error:
            params.append(f'error="{_quote_header_value(error)}"')
        if description:
            params.append(f'error_description="{_quote_header_value(description)}"')
        if scope:
            params.append(f'scope="{_quote_header_value(scope)}"')
        return "Bearer" + (" " + ", ".join(params) if params else "")


@dataclass(frozen=True)
class AuthorizationServerConfig:
    issuer: str
    resource: str
    scopes_supported: tuple[str, ...]
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    registration_endpoint: str = ""
    jwks_uri: str = ""
    access_token_ttl_s: int = 3600
    authorization_code_ttl_s: int = 120
    allowed_algorithms: tuple[str, ...] = ("RS256",)

    def __post_init__(self) -> None:
        base = _clean_base(self.issuer)
        if not base:
            raise ValueError("issuer is required")
        if not self.resource:
            raise ValueError("resource is required")
        object.__setattr__(self, "issuer", base)
        defaults = {
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",
            "jwks_uri": f"{base}/.well-known/jwks.json",
        }
        for field_name, value in defaults.items():
            if not getattr(self, field_name):
                object.__setattr__(self, field_name, value)
