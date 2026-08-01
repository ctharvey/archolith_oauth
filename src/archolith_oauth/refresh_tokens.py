"""Rotating, replay-detecting refresh-token storage for public OAuth clients."""

from __future__ import annotations

import secrets
import sqlite3
import time
from pathlib import Path

from .models import RefreshTokenRecord
from .stores import hash_secret


def _connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, timeout=30.0)


class RefreshTokenStore:
    """SQLite-backed refresh tokens stored only as SHA-256 hashes.

    A token is single-use. Redeeming it marks it used; replaying a used token
    revokes the entire token family, including its newest rotated token.
    """

    def __init__(self, db_path: Path, *, ttl_s: float = 30 * 24 * 60 * 60) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_s = float(ttl_s)
        with _connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
                    token_hash TEXT PRIMARY KEY,
                    family_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    used_at REAL,
                    revoked_at REAL
                )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_oauth_refresh_family "
                "ON oauth_refresh_tokens(family_id)"
            )

    def issue(
        self,
        *,
        client_id: str,
        subject: str,
        scope: str,
        resource: str,
        family_id: str | None = None,
        now: float | None = None,
    ) -> str:
        raw = secrets.token_urlsafe(48)
        issued_at = time.time() if now is None else now
        family = family_id or secrets.token_urlsafe(24)
        with _connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO oauth_refresh_tokens
                   (token_hash, family_id, client_id, subject, scope, resource,
                    created_at, expires_at, used_at, revoked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)""",
                (
                    hash_secret(raw),
                    family,
                    client_id,
                    subject,
                    scope,
                    resource,
                    issued_at,
                    issued_at + self.ttl_s,
                ),
            )
        return raw

    def redeem(
        self,
        *,
        token: str,
        client_id: str,
        resource: str,
        now: float | None = None,
    ) -> RefreshTokenRecord | None:
        token_hash = hash_secret(token)
        redeemed_at = time.time() if now is None else now
        with _connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM oauth_refresh_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None

            valid = (
                row["client_id"] == client_id
                and row["resource"] == resource
                and row["used_at"] is None
                and row["revoked_at"] is None
                and float(row["expires_at"]) > redeemed_at
            )
            if not valid:
                conn.execute(
                    "UPDATE oauth_refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) "
                    "WHERE family_id = ?",
                    (redeemed_at, row["family_id"]),
                )
                return None

            cursor = conn.execute(
                """UPDATE oauth_refresh_tokens SET used_at = ?
                   WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL
                     AND expires_at > ?""",
                (redeemed_at, token_hash, redeemed_at),
            )
            if cursor.rowcount != 1:
                conn.execute(
                    "UPDATE oauth_refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) "
                    "WHERE family_id = ?",
                    (redeemed_at, row["family_id"]),
                )
                return None

        return RefreshTokenRecord(
            family_id=row["family_id"],
            client_id=row["client_id"],
            subject=row["subject"],
            scope=row["scope"],
            resource=row["resource"],
            created_at=float(row["created_at"]),
            expires_at=float(row["expires_at"]),
            used_at=redeemed_at,
            revoked_at=row["revoked_at"],
        )

    def family_is_revoked(self, family_id: str) -> bool:
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM oauth_refresh_tokens "
                "WHERE family_id = ? AND revoked_at IS NOT NULL LIMIT 1",
                (family_id,),
            ).fetchone()
        return row is not None

    def purge_expired(self, *, now: float | None = None) -> int:
        cutoff = time.time() if now is None else now
        with _connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM oauth_refresh_tokens WHERE expires_at <= ?",
                (cutoff,),
            )
            return int(cursor.rowcount)
