"""One-call construction of the reusable OAuth protocol runtime."""

from __future__ import annotations

from dataclasses import dataclass

from .config import AuthorizationServerConfig, ResourceServerConfig
from .key_store import SigningKeyStore
from .refresh_tokens import RefreshTokenStore
from .settings import OAuthSettings
from .stores import AuthorizationCodeStore, OAuthClientStore
from .tokens import TokenIssuer
from .verifier import AccessTokenVerifier


@dataclass
class OAuthRuntime:
    settings: OAuthSettings
    authorization_config: AuthorizationServerConfig
    resource_config: ResourceServerConfig
    client_store: OAuthClientStore
    code_store: AuthorizationCodeStore
    key_store: SigningKeyStore
    signing_key: object
    token_issuer: TokenIssuer
    token_verifier: AccessTokenVerifier
    refresh_store: RefreshTokenStore | None = None

    @classmethod
    def from_settings(
        cls,
        settings: OAuthSettings,
        *,
        create_data_dir: bool = True,
    ) -> "OAuthRuntime":
        report = settings.preflight()
        report.raise_for_errors()
        if create_data_dir:
            settings.data_dir.mkdir(parents=True, exist_ok=True)

        auth_config = settings.authorization_server_config()
        resource_config = settings.resource_server_config()
        client_store = OAuthClientStore(settings.database_path)
        code_store = AuthorizationCodeStore(
            settings.database_path,
            ttl_s=auth_config.authorization_code_ttl_s,
        )
        key_store = SigningKeyStore(settings.signing_key_path)
        signing_key = key_store.load_or_create()
        issuer = TokenIssuer(auth_config, signing_key)

        async def local_jwks() -> dict:
            return key_store.public_jwks_all()

        verifier = AccessTokenVerifier(resource_config, jwks_loader=local_jwks)
        refresh_store = (
            RefreshTokenStore(
                settings.database_path,
                ttl_s=auth_config.refresh_token_ttl_s,
            )
            if auth_config.issue_refresh_tokens
            else None
        )
        return cls(
            settings=settings,
            authorization_config=auth_config,
            resource_config=resource_config,
            client_store=client_store,
            code_store=code_store,
            key_store=key_store,
            signing_key=signing_key,
            token_issuer=issuer,
            token_verifier=verifier,
            refresh_store=refresh_store,
        )

    def rotate_signing_key(self, *, retain_previous: int = 1) -> tuple[str, ...]:
        """Rotate the active signing key and return active + retained key IDs."""
        self.signing_key = self.key_store.rotate(retain_previous=retain_previous)
        self.token_issuer = TokenIssuer(self.authorization_config, self.signing_key)
        return self.key_store.key_ids()
