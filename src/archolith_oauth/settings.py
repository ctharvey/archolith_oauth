"""Environment-backed configuration and deployment preflight helpers."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .config import AuthorizationServerConfig, ResourceServerConfig


def _split_scopes(value: str) -> tuple[str, ...]:
    return tuple(part for part in value.replace(",", " ").split() if part)


def _as_bool(value: str | bool | None, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str | int | None, default: int) -> int:
    if value in (None, ""):
        return default
    return int(value)


@dataclass(frozen=True)
class PreflightCheck:
    name: str
    ok: bool
    detail: str
    warning: bool = False


@dataclass(frozen=True)
class PreflightReport:
    checks: tuple[PreflightCheck, ...]

    @property
    def ok(self) -> bool:
        return all(check.ok or check.warning for check in self.checks)

    @property
    def errors(self) -> tuple[PreflightCheck, ...]:
        return tuple(check for check in self.checks if not check.ok and not check.warning)

    @property
    def warnings(self) -> tuple[PreflightCheck, ...]:
        return tuple(check for check in self.checks if not check.ok and check.warning)

    def raise_for_errors(self) -> None:
        if self.errors:
            detail = "; ".join(f"{check.name}: {check.detail}" for check in self.errors)
            raise ValueError(f"OAuth preflight failed: {detail}")


@dataclass(frozen=True)
class OAuthSettings:
    """Portable settings for an embedded authorization server and resource server.

    ``from_env`` reads only the supplied prefix, making multiple OAuth resources
    safe to configure in the same process.
    """

    issuer: str
    resource: str
    scopes_supported: tuple[str, ...]
    default_scopes: tuple[str, ...] = ()
    data_dir: Path = Path(".oauth")
    resource_name: str = "OAuth protected resource"
    issue_refresh_tokens: bool = False
    access_token_ttl_s: int = 3600
    authorization_code_ttl_s: int = 120
    refresh_token_ttl_s: int = 30 * 24 * 60 * 60
    offline_access_scope: str = "offline_access"
    consent_secret: str = field(default="", repr=False)

    @classmethod
    def from_env(
        cls,
        prefix: str = "ARCHOLITH_OAUTH_",
        *,
        environ: Mapping[str, str] | None = None,
    ) -> "OAuthSettings":
        env = os.environ if environ is None else environ

        def read(name: str, default: str = "") -> str:
            return str(env.get(prefix + name, default)).strip()

        issuer = read("ISSUER")
        resource = read("RESOURCE")
        scopes = _split_scopes(read("SCOPES"))
        if not issuer:
            raise ValueError(f"{prefix}ISSUER is required")
        if not resource:
            raise ValueError(f"{prefix}RESOURCE is required")
        if not scopes:
            raise ValueError(f"{prefix}SCOPES is required")

        return cls(
            issuer=issuer,
            resource=resource,
            scopes_supported=scopes,
            default_scopes=_split_scopes(read("DEFAULT_SCOPES")),
            data_dir=Path(read("DATA_DIR", ".oauth")),
            resource_name=read("RESOURCE_NAME", "OAuth protected resource"),
            issue_refresh_tokens=_as_bool(read("REFRESH_TOKENS_ENABLED"), False),
            access_token_ttl_s=_as_int(read("ACCESS_TOKEN_TTL_S"), 3600),
            authorization_code_ttl_s=_as_int(read("AUTHORIZATION_CODE_TTL_S"), 120),
            refresh_token_ttl_s=_as_int(
                read("REFRESH_TOKEN_TTL_S"),
                30 * 24 * 60 * 60,
            ),
            offline_access_scope=read("OFFLINE_ACCESS_SCOPE", "offline_access"),
            consent_secret=read("CONSENT_SECRET"),
        )

    @property
    def database_path(self) -> Path:
        return self.data_dir / "oauth.db"

    @property
    def signing_key_path(self) -> Path:
        return self.data_dir / "oauth-signing-key.json"

    def authorization_server_config(self) -> AuthorizationServerConfig:
        return AuthorizationServerConfig(
            issuer=self.issuer,
            resource=self.resource,
            scopes_supported=self.scopes_supported,
            default_scopes=self.default_scopes,
            access_token_ttl_s=self.access_token_ttl_s,
            authorization_code_ttl_s=self.authorization_code_ttl_s,
            issue_refresh_tokens=self.issue_refresh_tokens,
            refresh_token_ttl_s=self.refresh_token_ttl_s,
            offline_access_scope=self.offline_access_scope,
        )

    def resource_server_config(self) -> ResourceServerConfig:
        auth = self.authorization_server_config()
        return ResourceServerConfig(
            resource=auth.resource,
            authorization_servers=(auth.issuer,),
            issuer=auth.issuer,
            jwks_uri=auth.jwks_uri,
            scopes_supported=auth.effective_scopes_supported,
            resource_name=self.resource_name,
        )

    def redacted(self) -> dict[str, object]:
        return {
            "issuer": self.issuer,
            "resource": self.resource,
            "scopes_supported": list(self.scopes_supported),
            "default_scopes": list(self.default_scopes),
            "data_dir": str(self.data_dir),
            "resource_name": self.resource_name,
            "issue_refresh_tokens": self.issue_refresh_tokens,
            "access_token_ttl_s": self.access_token_ttl_s,
            "authorization_code_ttl_s": self.authorization_code_ttl_s,
            "refresh_token_ttl_s": self.refresh_token_ttl_s,
            "offline_access_scope": self.offline_access_scope,
            "consent_secret_configured": bool(self.consent_secret),
        }

    def preflight(self, *, require_consent_secret: bool = False) -> PreflightReport:
        checks: list[PreflightCheck] = []
        try:
            self.authorization_server_config()
            self.resource_server_config()
            checks.append(PreflightCheck("configuration", True, "URLs and scopes are valid"))
        except Exception as exc:
            checks.append(PreflightCheck("configuration", False, str(exc)))

        existing_parent = self.data_dir
        while not existing_parent.exists() and existing_parent != existing_parent.parent:
            existing_parent = existing_parent.parent
        writable = existing_parent.exists() and os.access(existing_parent, os.W_OK)
        checks.append(
            PreflightCheck(
                "data_directory",
                writable,
                f"nearest existing parent is {existing_parent}",
            )
        )

        if self.signing_key_path.exists():
            mode = stat.S_IMODE(self.signing_key_path.stat().st_mode)
            restrictive = mode & 0o077 == 0
            checks.append(
                PreflightCheck(
                    "signing_key_permissions",
                    restrictive,
                    f"mode is {oct(mode)}; expected no group/other permissions",
                    warning=os.name == "nt",
                )
            )
        else:
            checks.append(
                PreflightCheck(
                    "signing_key_permissions",
                    True,
                    "key does not exist yet; it will be created restrictively",
                )
            )

        secret_ok = bool(self.consent_secret) or not require_consent_secret
        checks.append(
            PreflightCheck(
                "consent_secret",
                secret_ok,
                "configured" if self.consent_secret else "not configured",
                warning=not require_consent_secret,
            )
        )
        return PreflightReport(tuple(checks))
