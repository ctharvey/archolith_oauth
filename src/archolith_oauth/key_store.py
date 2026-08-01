"""Persistent signing-key storage."""

from __future__ import annotations

import json
import os
from pathlib import Path

from . import jose


class SigningKeyStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load_or_create(self):
        if self.path.exists():
            return jose.load_key(json.loads(self.path.read_text("utf-8")))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        key = jose.generate_signing_key()
        payload = json.dumps(jose.serialize_key(key, private=True), separators=(",", ":"))
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(payload, encoding="utf-8")
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        os.replace(temp, self.path)
        return key

    @staticmethod
    def public_jwks(key) -> dict:
        return {"keys": [jose.serialize_key(key, private=False)]}
