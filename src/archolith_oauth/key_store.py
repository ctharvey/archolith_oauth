"""Persistent signing-key storage."""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from . import jose


class SigningKeyStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def _load(self):
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return jose.load_key(json.loads(self.path.read_text("utf-8")))

    def load_or_create(self):
        if self.path.exists():
            return self._load()

        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        try:
            lock_fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if self.path.exists():
                    return self._load()
                time.sleep(0.05)
            raise TimeoutError(f"timed out waiting for signing key: {self.path}")

        os.close(lock_fd)
        temp_path: Path | None = None
        try:
            if self.path.exists():
                return self._load()
            key = jose.generate_signing_key()
            payload = json.dumps(
                jose.serialize_key(key, private=True),
                separators=(",", ":"),
            )
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=self.path.name + ".",
                suffix=".tmp",
                delete=False,
            ) as temp:
                temp.write(payload)
                temp.flush()
                os.fsync(temp.fileno())
                temp_path = Path(temp.name)
            try:
                os.chmod(temp_path, 0o600)
            except OSError:
                pass
            os.replace(temp_path, self.path)
            temp_path = None
            return key
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            lock_path.unlink(missing_ok=True)

    @staticmethod
    def public_jwks(key) -> dict:
        public = jose.serialize_key(key, private=False)
        if "d" in public:
            raise AssertionError("private key material leaked into public JWKS")
        return {"keys": [public]}
