"""Reusable OAuth 2.1 building blocks for Archolith services."""

from .config import AuthorizationServerConfig, ResourceServerConfig
from .key_store import SigningKeyStore
from .metadata import authorization_server_metadata, protected_resource_metadata
from .models import AuthCodeRecord, AuthorizationGrant, OAuthClient, OAuthPrincipal
from .pkce import create_verifier, s256_challenge, verify_s256
from .registration import (
    ClientMetadataError,
    register_public_client,
    validate_authorization_request,
)
from .stores import AuthorizationCodeStore, OAuthClientStore, hash_secret
from .tokens import (
    TokenExchangeError,
    TokenIssuer,
    TokenResponse,
    exchange_authorization_code,
)
from .verifier import AccessTokenVerifier, OAuthAuthenticationError, extract_scopes

__all__ = [
    "AccessTokenVerifier",
    "AuthCodeRecord",
    "AuthorizationCodeStore",
    "AuthorizationGrant",
    "AuthorizationServerConfig",
    "ClientMetadataError",
    "OAuthAuthenticationError",
    "OAuthClient",
    "OAuthClientStore",
    "OAuthPrincipal",
    "ResourceServerConfig",
    "SigningKeyStore",
    "TokenExchangeError",
    "TokenIssuer",
    "TokenResponse",
    "authorization_server_metadata",
    "create_verifier",
    "exchange_authorization_code",
    "extract_scopes",
    "hash_secret",
    "protected_resource_metadata",
    "register_public_client",
    "s256_challenge",
    "validate_authorization_request",
    "verify_s256",
]

__version__ = "0.1.0"
