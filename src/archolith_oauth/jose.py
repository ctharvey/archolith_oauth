"""Narrow JOSE provider seam backed by joserfc.

The dependency is imported lazily so metadata, registration, and store-only
consumers can import the package without initializing crypto.
"""

from __future__ import annotations

from typing import Any

KeyHandle = Any
KeySetHandle = Any


class JoseError(Exception):
    pass


def _provider():
    try:
        from joserfc import jwt
        from joserfc.jwk import KeySet, RSAKey
        from joserfc.jwt import JWTClaimsRegistry
    except ImportError as exc:
        raise JoseError("joserfc is required for JWT operations") from exc
    return jwt, KeySet, RSAKey, JWTClaimsRegistry


def parse_jwks(payload: dict) -> KeySetHandle:
    _, key_set, _, _ = _provider()
    try:
        return key_set.import_key_set(payload)
    except Exception as exc:
        raise JoseError("Unable to parse JWKS") from exc


def jwks_has_kid(keyset: KeySetHandle, kid: str) -> bool:
    try:
        keyset.get_by_kid(kid)
        return True
    except Exception:
        return False


def verify_jwt(token: str, keyset: KeySetHandle, algorithms: list[str], leeway: float) -> dict[str, Any]:
    jwt, _, _, claims_registry = _provider()
    try:
        decoded = jwt.decode(token, keyset, algorithms=algorithms)
        claims_registry(leeway=leeway).validate(decoded.claims)
        return dict(decoded.claims)
    except Exception as exc:
        raise JoseError("Access token signature or claims are invalid") from exc


def generate_signing_key() -> KeyHandle:
    _, _, rsa_key, _ = _provider()
    key = rsa_key.generate_key(2048, private=True)
    key.ensure_kid()
    return key


def serialize_key(key: KeyHandle, *, private: bool) -> dict[str, Any]:
    return key.as_dict(private=private)


def load_key(data: dict) -> KeyHandle:
    _, _, rsa_key, _ = _provider()
    try:
        return rsa_key.import_key(data)
    except Exception as exc:
        raise JoseError("Unable to load signing key") from exc


def sign_jwt(header: dict, claims: dict, key: KeyHandle) -> str:
    jwt, _, _, _ = _provider()
    try:
        return jwt.encode(header, claims, key)
    except Exception as exc:
        raise JoseError("Unable to sign access token") from exc
