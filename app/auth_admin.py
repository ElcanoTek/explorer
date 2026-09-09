# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Administrative CLI for deployment-local Explorer accounts."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from dotenv import load_dotenv

from app.local_auth import (
    LocalAuthError,
    LocalAuthStore,
    PasswordPolicyError,
    validate_password,
)

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env.shared")
load_dotenv(ROOT_DIR / ".env", override=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="explorer user",
        description="Manage local Explorer users without exposing a public signup flow.",
    )
    parser.add_argument(
        "--db",
        default=os.getenv("EXPLORER_AUTH_DB", "/var/lib/explorer/auth.db"),
        help=argparse.SUPPRESS,
    )
    scopes = parser.add_subparsers(dest="scope", required=True)
    user = scopes.add_parser("user", help="manage local users")
    commands = user.add_subparsers(dest="command", required=True)

    add = commands.add_parser("add", help="create a user with a temporary password")
    add.add_argument("username")

    commands.add_parser("list", help="list users without credential data")

    reset = commands.add_parser(
        "reset-password", help="issue a temporary password and revoke sessions"
    )
    reset.add_argument("username")

    for name in ("disable", "enable", "revoke-sessions"):
        command = commands.add_parser(name)
        command.add_argument("username")
    return parser


def _read_temporary_password(
    username: str, password_reader: Callable[[str], str]
) -> str:
    try:
        password = password_reader("Temporary password: ")
        confirmation = password_reader("Confirm temporary password: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise LocalAuthError(
            "Password entry cancelled; no account was changed."
        ) from exc
    if password != confirmation:
        raise PasswordPolicyError("Temporary passwords do not match.")
    return validate_password(password, username=username)


def main(
    argv: Sequence[str] | None = None,
    *,
    password_reader: Callable[[str], str] | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    if os.getenv("EXPLORER_AUTH_MODE", "elcano").strip().lower() != "local":
        print(
            "error: user commands require EXPLORER_AUTH_MODE=local",
            file=sys.stderr,
        )
        return 1
    if args.command in {"add", "reset-password"} and password_reader is None:
        if not sys.stdin.isatty():
            print(
                "error: add/reset-password requires an attached terminal",
                file=sys.stderr,
            )
            return 1
        password_reader = getpass.getpass
    try:
        if args.command == "add":
            assert password_reader is not None
            temporary_password = _read_temporary_password(
                args.username, password_reader
            )
            store = LocalAuthStore(Path(args.db))
            user = store.create_user(args.username, temporary_password)
            print(f"Created local Explorer user: {user.username}")
            print("The user must change the temporary password at next sign-in.")
        elif args.command == "list":
            store = LocalAuthStore(Path(args.db))
            users = store.list_users()
            if not users:
                print("No local Explorer users.")
            for user in users:
                status = "disabled" if user.disabled else "enabled"
                credential_state = (
                    "must-change-password" if user.must_change_password else "ready"
                )
                print(f"{user.username}\t{status}\t{credential_state}")
        elif args.command == "reset-password":
            assert password_reader is not None
            temporary_password = _read_temporary_password(
                args.username, password_reader
            )
            store = LocalAuthStore(Path(args.db))
            store.reset_password(args.username, temporary_password)
            user = store.get_user(args.username)
            print(f"Reset password and revoked sessions: {user.username}")
            print("The user must change the temporary password at next sign-in.")
        elif args.command == "disable":
            store = LocalAuthStore(Path(args.db))
            store.set_user_enabled(args.username, enabled=False)
            print(
                f"Disabled user and revoked sessions: {store.get_user(args.username).username}"
            )
        elif args.command == "enable":
            store = LocalAuthStore(Path(args.db))
            store.set_user_enabled(args.username, enabled=True)
            print(f"Enabled user: {store.get_user(args.username).username}")
        elif args.command == "revoke-sessions":
            store = LocalAuthStore(Path(args.db))
            user = store.get_user(args.username)
            count = store.revoke_user_sessions(user.id)
            print(f"Revoked {count} session(s) for {user.username}")
        else:  # pragma: no cover - argparse prevents this branch.
            raise RuntimeError("Unknown command")
    except (LocalAuthError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
