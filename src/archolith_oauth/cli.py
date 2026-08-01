"""Small dependency-free operator CLI for new OAuth deployments."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from .key_store import SigningKeyStore
from .settings import OAuthSettings


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="archolith-oauth")
    parser.add_argument(
        "--prefix",
        default="ARCHOLITH_OAUTH_",
        help="environment variable prefix (default: ARCHOLITH_OAUTH_)",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    preflight = subcommands.add_parser("preflight", help="validate deployment settings")
    preflight.add_argument(
        "--require-consent-secret",
        action="store_true",
        help="fail when the consent HMAC secret is missing",
    )
    preflight.add_argument("--json", action="store_true", help="emit JSON")

    show = subcommands.add_parser("show-config", help="print redacted settings")
    show.add_argument("--json", action="store_true", help="emit JSON")

    rotate = subcommands.add_parser("rotate-key", help="rotate the active signing key")
    rotate.add_argument(
        "--retain-previous",
        type=int,
        default=1,
        help="number of retired public keys to keep in JWKS (default: 1)",
    )
    rotate.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        settings = OAuthSettings.from_env(args.prefix)
    except Exception as exc:
        print(f"configuration: ERROR — {exc}")
        return 2

    if args.command == "show-config":
        payload = settings.redacted()
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            for key, value in payload.items():
                print(f"{key}: {value}")
        return 0

    if args.command == "rotate-key":
        try:
            settings.preflight().raise_for_errors()
            store = SigningKeyStore(settings.signing_key_path)
            store.rotate(retain_previous=args.retain_previous)
            key_ids = store.key_ids()
        except Exception as exc:
            print(f"rotate-key: ERROR — {exc}")
            return 1
        payload = {
            "active_kid": key_ids[0] if key_ids else "",
            "retained_previous_kids": list(key_ids[1:]),
        }
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"active_kid: {payload['active_kid']}")
            print(
                "retained_previous_kids: "
                + (", ".join(payload["retained_previous_kids"]) or "none")
            )
        return 0

    report = settings.preflight(
        require_consent_secret=bool(args.require_consent_secret)
    )
    if args.json:
        print(
            json.dumps(
                {
                    "ok": report.ok,
                    "checks": [
                        {
                            "name": check.name,
                            "ok": check.ok,
                            "warning": check.warning,
                            "detail": check.detail,
                        }
                        for check in report.checks
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for check in report.checks:
            status = "OK" if check.ok else ("WARN" if check.warning else "ERROR")
            print(f"{check.name}: {status} — {check.detail}")
    return 0 if report.ok else 1


def main() -> None:
    raise SystemExit(run())
