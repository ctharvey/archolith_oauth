"""RFC 7636 PKCE helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets


def create_verifier(size: int = 64) -> str:
    if size < 43:
        raise ValueError("PKCE verifier must be at least 43 characters")
    return secrets.token_urlsafe(size)[:128]


def s256_challenge(verifier: str) -> str:
    if not verifier:
        raise ValueError("verifier is required")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_s256(verifier: str, challenge: str) -> bool:
    if not verifier or not challenge:
        return False
    try:
        computed = s256_challenge(verifier)
    except (UnicodeEncodeError, ValueError):
        return False
    return hmac.compare_digest(computed, challenge)
