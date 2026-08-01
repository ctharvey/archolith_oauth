"""Framework-neutral signed consent transactions and approval sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class ConsentTransaction:
    client_id: str
    subject: str
    params: dict[str, str]
    jti: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class ConsentSession:
    subject: str
    approved_clients: tuple[str, ...]
    issued_at: int
    expires_at: int


class ConsentTokenError(ValueError):
    pass


class ConsentNonceStore:
    """Persistent single-use nonce store for consent transactions."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS oauth_consent_nonces (
                    jti TEXT PRIMARY KEY,
                    consumed_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )"""
            )

    def consume(self, jti: str, expires_at: float, *, now: float | None = None) -> bool:
        consumed_at = time.time() if now is None else now
        if expires_at <= consumed_at:
            return False
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            try:
                conn.execute(
                    "INSERT INTO oauth_consent_nonces VALUES (?, ?, ?)",
                    (jti, consumed_at, expires_at),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def purge_expired(self, *, now: float | None = None) -> int:
        cutoff = time.time() if now is None else now
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            cursor = conn.execute(
                "DELETE FROM oauth_consent_nonces WHERE expires_at <= ?",
                (cutoff,),
            )
            return int(cursor.rowcount)


class ConsentTokenManager:
    """Sign and verify consent state without prescribing a login or HTML UI."""

    def __init__(
        self,
        secret: str | bytes,
        *,
        transaction_ttl_s: int = 300,
        session_ttl_s: int = 600,
        clock_skew_s: int = 60,
    ) -> None:
        secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        if len(secret_bytes) < 32:
            raise ValueError("consent secret must be at least 32 bytes")
        self._secret = secret_bytes
        self.transaction_ttl_s = int(transaction_ttl_s)
        self.session_ttl_s = int(session_ttl_s)
        self.clock_skew_s = int(clock_skew_s)

    def _sign(self, payload: dict[str, object]) -> str:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        signature = hmac.new(self._secret, encoded, hashlib.sha256).digest()
        return f"{_b64encode(encoded)}.{_b64encode(signature)}"

    def _verify(self, token: str, *, kind: str, now: float | None = None) -> dict:
        if not token or token.count(".") != 1:
            raise ConsentTokenError("consent token is malformed")
        payload_segment, signature_segment = token.split(".", 1)
        try:
            payload_bytes = _b64decode(payload_segment)
            supplied = _b64decode(signature_segment)
        except Exception as exc:
            raise ConsentTokenError("consent token is malformed") from exc
        expected = hmac.new(self._secret, payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied, expected):
            raise ConsentTokenError("consent token signature is invalid")
        try:
            payload = json.loads(payload_bytes)
        except Exception as exc:
            raise ConsentTokenError("consent token payload is invalid") from exc
        if not isinstance(payload, dict) or payload.get("kind") != kind:
            raise ConsentTokenError("consent token has the wrong type")
        current = time.time() if now is None else now
        issued_at = payload.get("iat")
        expires_at = payload.get("exp")
        if not isinstance(issued_at, (int, float)) or not isinstance(
            expires_at,
            (int, float),
        ):
            raise ConsentTokenError("consent token is missing time bounds")
        if issued_at > current + self.clock_skew_s or expires_at <= current:
            raise ConsentTokenError("consent token is expired or not yet valid")
        return payload

    def create_transaction(
        self,
        *,
        client_id: str,
        params: Mapping[str, str],
        subject: str = "",
        now: int | None = None,
    ) -> str:
        issued_at = int(time.time()) if now is None else int(now)
        normalized = {str(key): str(value) for key, value in params.items()}
        return self._sign(
            {
                "kind": "consent_transaction",
                "client_id": client_id,
                "subject": subject,
                "params": normalized,
                "jti": secrets.token_urlsafe(24),
                "iat": issued_at,
                "exp": issued_at + self.transaction_ttl_s,
            }
        )

    def verify_transaction(
        self,
        token: str,
        *,
        expected_params: Mapping[str, str] | None = None,
        nonce_store: ConsentNonceStore | None = None,
        consume: bool = False,
        now: float | None = None,
    ) -> ConsentTransaction:
        payload = self._verify(token, kind="consent_transaction", now=now)
        params = payload.get("params")
        if not isinstance(params, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in params.items()
        ):
            raise ConsentTokenError("consent transaction parameters are invalid")
        if expected_params is not None:
            normalized = {str(key): str(value) for key, value in expected_params.items()}
            if params != normalized:
                raise ConsentTokenError("consent parameters do not match")
        jti = str(payload.get("jti", ""))
        if not jti:
            raise ConsentTokenError("consent transaction has no nonce")
        if consume:
            if nonce_store is None:
                raise ValueError("nonce_store is required when consume=True")
            if not nonce_store.consume(jti, float(payload["exp"]), now=now):
                raise ConsentTokenError("consent transaction was already used")
        return ConsentTransaction(
            client_id=str(payload.get("client_id", "")),
            subject=str(payload.get("subject", "")),
            params=dict(params),
            jti=jti,
            issued_at=int(payload["iat"]),
            expires_at=int(payload["exp"]),
        )

    def create_session(
        self,
        *,
        subject: str,
        approved_clients: tuple[str, ...] | list[str] | set[str],
        now: int | None = None,
    ) -> str:
        issued_at = int(time.time()) if now is None else int(now)
        return self._sign(
            {
                "kind": "consent_session",
                "subject": subject,
                "approved_clients": sorted(set(approved_clients)),
                "iat": issued_at,
                "exp": issued_at + self.session_ttl_s,
            }
        )

    def verify_session(
        self,
        token: str,
        *,
        now: float | None = None,
    ) -> ConsentSession:
        payload = self._verify(token, kind="consent_session", now=now)
        clients = payload.get("approved_clients")
        if not isinstance(clients, list) or not all(
            isinstance(client, str) for client in clients
        ):
            raise ConsentTokenError("consent session clients are invalid")
        subject = str(payload.get("subject", ""))
        if not subject:
            raise ConsentTokenError("consent session has no subject")
        return ConsentSession(
            subject=subject,
            approved_clients=tuple(clients),
            issued_at=int(payload["iat"]),
            expires_at=int(payload["exp"]),
        )
