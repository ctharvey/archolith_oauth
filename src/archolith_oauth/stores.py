"""SQLite stores for public clients and single-use authorization codes."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from .models import AuthCodeRecord, AuthorizationGrant, OAuthClient


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class OAuthClientStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_name TEXT NOT NULL,
                    redirect_uris TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    token_endpoint_auth_method TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    last_exchanged REAL
                )"""
            )

    def register(self, client: OAuthClient) -> None:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute(
                    "INSERT INTO oauth_clients VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        client.client_id,
                        client.client_name,
                        json.dumps(client.redirect_uris),
                        json.dumps(client.scopes),
                        client.token_endpoint_auth_method,
                        client.created_at,
                        client.last_exchanged,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("client_id already registered") from exc

    def get(self, client_id: str) -> OAuthClient | None:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT client_id, client_name, redirect_uris, scopes, token_endpoint_auth_method, created_at, last_exchanged FROM oauth_clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
        if row is None:
            return None
        return OAuthClient(
            client_id=row[0],
            client_name=row[1],
            redirect_uris=tuple(json.loads(row[2])),
            scopes=tuple(json.loads(row[3])),
            token_endpoint_auth_method=row[4],
            created_at=row[5],
            last_exchanged=row[6],
        )

    def mark_exchanged(self, client_id: str, *, now: float | None = None) -> None:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE oauth_clients SET last_exchanged = ? WHERE client_id = ?",
                (time.time() if now is None else now, client_id),
            )

    def reap_never_exchanged(self, max_age_s: float, *, now: float | None = None) -> int:
        cutoff = (time.time() if now is None else now) - max_age_s
        with self._lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM oauth_clients WHERE last_exchanged IS NULL AND created_at < ?",
                (cutoff,),
            )
            return int(cursor.rowcount)


class AuthorizationCodeStore:
    def __init__(self, db_path: Path, *, ttl_s: float = 120.0) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_s = float(ttl_s)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS oauth_codes (
                    code_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    code_challenge_method TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    redeemed_at REAL
                )"""
            )

    def issue(self, grant: AuthorizationGrant) -> str:
        raw = secrets.token_urlsafe(32)
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO oauth_codes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    _hash(raw),
                    grant.client_id,
                    grant.redirect_uri,
                    grant.scope,
                    grant.code_challenge,
                    grant.code_challenge_method,
                    grant.resource,
                    grant.subject,
                    now,
                    now + self.ttl_s,
                ),
            )
        return raw

    def redeem(self, *, code: str, client_id: str, redirect_uri: str) -> AuthCodeRecord | None:
        now = time.time()
        code_hash = _hash(code)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "UPDATE oauth_codes SET redeemed_at = ? WHERE code_hash = ? AND redeemed_at IS NULL AND expires_at > ?",
                (now, code_hash, now),
            )
            if cursor.rowcount != 1:
                return None
            row = conn.execute(
                "SELECT * FROM oauth_codes WHERE code_hash = ?",
                (code_hash,),
            ).fetchone()
        if row is None or row["client_id"] != client_id or row["redirect_uri"] != redirect_uri:
            return None
        return AuthCodeRecord(
            client_id=row["client_id"],
            redirect_uri=row["redirect_uri"],
            scope=row["scope"],
            code_challenge=row["code_challenge"],
            code_challenge_method=row["code_challenge_method"],
            resource=row["resource"],
            subject=row["subject"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            redeemed_at=row["redeemed_at"],
        )
