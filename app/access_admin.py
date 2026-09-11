# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Operator CLI for Explorer's deployment-local email access list."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from dotenv import load_dotenv

from app.central_auth import AccessDeniedError, CentralAuthStore, normalize_email

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env.shared")
load_dotenv(ROOT_DIR / ".env", override=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="explorer access",
        description="Control which centrally authenticated emails may use Explorer.",
    )
    parser.add_argument(
        "--db",
        default=os.getenv("EXPLORER_ACCESS_DB", "/var/lib/explorer/access.db"),
        help=argparse.SUPPRESS,
    )
    scopes = parser.add_subparsers(dest="scope", required=True)
    access = scopes.add_parser("access", help="manage the email access list")
    commands = access.add_subparsers(dest="command", required=True)

    grant = commands.add_parser("grant", help="allow an email to use Explorer")
    grant.add_argument("email")

    revoke = commands.add_parser(
        "revoke", help="deny an email and revoke its Explorer sessions"
    )
    revoke.add_argument("email")

    listing = commands.add_parser("list", help="list allowed emails")
    listing.add_argument(
        "--all", action="store_true", help="include previously revoked emails"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if os.getenv("EXPLORER_AUTH_MODE", "elcano").strip().lower() != "central":
        print(
            "error: access commands require EXPLORER_AUTH_MODE=central",
            file=sys.stderr,
        )
        return 1
    try:
        store = CentralAuthStore(Path(args.db))
        if args.command == "grant":
            entry = store.grant_access(args.email)
            print(f"Granted Explorer access: {entry.email}")
        elif args.command == "revoke":
            if not store.revoke_access(args.email):
                raise AccessDeniedError("Email is not currently allowed")
            print(
                f"Revoked Explorer access and sessions: {normalize_email(args.email)}"
            )
        elif args.command == "list":
            entries = store.list_access(include_disabled=args.all)
            if not entries:
                print("No emails have Explorer access.")
            for entry in entries:
                status = "allowed" if entry.enabled else "revoked"
                print(f"{entry.email}\t{status}")
        else:  # pragma: no cover - argparse prevents this branch.
            raise RuntimeError("Unknown command")
    except (AccessDeniedError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
