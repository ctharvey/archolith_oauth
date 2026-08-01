"""SQLite stores for public clients and single-use authorization codes.

The client schema is intentionally compatible with Menhir's embedded OAuth AS
so an existing ``menhir_oauth_as.db`` can be adopted without rewriting rows.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from .models import AuthCodeRecord, AuthorizationGrant, OAuthClient


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, timeout=30.0)


class OAuthClientStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with _connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_name TEXT NOT NULL,
                    redirect_uris TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    client_secret_hash TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    token_endpoint_auth_method TEXT NOT NULL,
                    last_exchanged REAL
                )"""
            )
            columns = {
                str(row[1]) for row in conn.execute("PRAGMA table_info(oauth_clients)")
            }
            if "client_secret_hash" not in columns:
                conn.execute(
                    "ALTER TABLE oauth_clients "
                    "ADD COLUMN client_secret_hash TEXT NOT NULL DEFAULT ''"
                )
            if "last_exchanged" not in columns:
                conn.execute("ALTER TABLE oauth_clients ADD COLUMN last_exchanged REAL")

    @staticmethod
    def _row_to_client(row: sqlite3.Row) -> OAuthClient:
        return OAuthClient(
            client_id=row["client_id"],
            client_name=row["client_name"],
            redirect_uris=tuple(json.loads(row["redirect_uris"])),
            scopes=tuple(json.loads(row["scopes"])),
            client_secret_hash=row["client_secret_hash"] or "",
            token_endpoint_auth_method=row["token_endpoint_auth_method"],
            created_at=float(row["created_at"]),
            last_exchanged=row["last_exchanged"],
        )

    def register(self, client: OAuthClient) -> None:
        with self._lock, _connect(self.db_path) as conn:
            try:
                conn.execute(
                    """INSERT INTO oauth_clients
                       (client_id, client_name, redirect_uris, scopes,
                        client_secret_hash, created_at,
                        token_endpoint_auth_method, last_exchanged)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        client.client_id,
                        client.client_name,
                        json.dumps(list(client.redirect_uris)),
                        json.dumps(list(client.scopes)),
                        client.client_secret_hash,
                        client.created_at,
                        client.token_endpoint_auth_method,
                        client.last_exchanged,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("client_id already registered") from exc

    def get(self, client_id: str) -> OAuthClient | None:
        with _connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """SELECT client_id, client_name, redirect_uris, scopes,
                          client_secret_hash, created_at,
                          token_endpoint_auth_method, last_exchanged
                   FROM oauth_clients WHERE client_id = ?""",
                (client_id,),
            ).fetchone()
        return None if row is None else self._row_to_client(row)

    def mark_exchanged(self, client_id: str, *, now: float | None = None) -> None:
        with self._lock, _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE oauth_clients SET last_exchanged = ? WHERE client_id = ?",
                (time.time() if now is None else now, client_id),
            )

    def reap_never_exchanged(self, max_age_s: float, *, now: float | None = None) -> int:
        cutoff = (time.time() if now is None else now) - max_age_s
        with self._lock, _connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM oauth_clients "
                "WHERE last_exchanged IS NULL AND created_at < ?",
                (cutoff,),
            )
            return int(cursor.rowcount)

    def reap_stale(self, max_age_s: float, *, now: float | None = None) -> int:
        """Menhir-compatible alias for ``reap_never_exchanged``."""
        return self.reap_never_exchanged(max_age_s, now=now)

    def count(self) -> int:
        with _connect(self.db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM oauth_clients").fetchone()
        return int(row[0]) if row else 0

    def all(self) -> list[OAuthClient]:
        with _connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT client_id, client_name, redirect_uris, scopes,
                          client_secret_hash, created_at,
                          token_endpoint_auth_method, last_exchanged
                   FROM oauth_clients ORDER BY created_at ASC"""
            ).fetchall()
        return [self._row_to_client(row) for row in rows]

    def verify_secret(self, client_id: str, presented_secret: str) -> bool:
        client = self.get(client_id)
        if client is None or not client.client_secret_hash:
            return False
        return hmac.compare_digest(
            client.client_secret_hash,
            hash_secret(presented_secret),
        )


class AuthorizationCodeStore:
    def __init__(self, db_path: Path, *, ttl_s: float = 120.0) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_s = float(ttl_s)
        self._lock = threading.Lock()
        with _connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS oauth_codes (
                    code_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    code_challenge_method TEXT NOT NULL,
                    resource TEXT,
                    subject TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    redeemed_at REAL
                )"""
            )

    def issue(
        self,
        grant: AuthorizationGrant | None = None,
        *,
        client_id: str = "",
        redirect_uri: str = "",
        scope: str = "",
        code_challenge: str = "",
        code_challenge_method: str = "S256",
        resource: str = "",
        subject: str = "",
    ) -> str:
        """Issue from a grant object or Menhir's existing keyword call shape."""
        if grant is None:
            if not all(
                (
                    client_id,
                    redirect_uri,
                    code_challenge,
                    resource,
                    subject,
                )
            ):
                raise ValueError(
                    "client_id, redirect_uri, code_challenge, resource, and subject are required"
                )
            grant = AuthorizationGrant(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                resource=resource,
                subject=subject,
            )
        if grant.code_challenge_method != "S256":
            raise ValueError("code_challenge_method must be S256")

        raw = secrets.token_urlsafe(32)
        now = time.time()
        with _connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO oauth_codes
                   (code_hash, client_id, redirect_uri, scope, code_challenge,
                    code_challenge_method, resource, subject, created_at,
                    expires_at, redeemed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
                (
                    hash_secret(raw),
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

    def redeem(
        self,
        *,
        code: str,
        client_id: str,
        redirect_uri: str,
    ) -> AuthCodeRecord | None:
        now = time.time()
        code_hash = hash_secret(code)
        with _connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """UPDATE oauth_codes SET redeemed_at = ?
                   WHERE code_hash = ? AND redeemed_at IS NULL AND expires_at > ?""",
                (now, code_hash, now),
            )
            if cursor.rowcount != 1:
                return None
            row = conn.execute(
                "SELECT * FROM oauth_codes WHERE code_hash = ?",
                (code_hash,),
            ).fetchone()
        if (
            row is None
            or row["client_id"] != client_id
            or row["redirect_uri"] != redirect_uri
        ):
            return None
        return AuthCodeRecord(
            client_id=row["client_id"],
            redirect_uri=row["redirect_uri"],
            scope=row["scope"],
            code_challenge=row["code_challenge"],
            code_challenge_method=row["code_challenge_method"],
            resource=row["resource"] or "",
            subject=row["subject"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            redeemed_at=row["redeemed_at"],
        )

    def purge_expired(self, *, now: float | None = None) -> int:
        cutoff = time.time() if now is None else now
        with self._lock, _connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM oauth_codes "
                "WHERE expires_at <= ? OR redeemed_at IS NOT NULL",
                (cutoff,),
            )
            return int(cursor.rowcount)
