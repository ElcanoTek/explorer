# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Guards on the installer and updater shell scripts.

These are source-level checks, not a run of the scripts, which need root and a
service user. They pin two faults that are invisible until a real install:
a venv build that dies when the operator happens to run it from /root, and an
environment file whose mode silently loosened on update.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _lines_invoking_uv(text: str) -> list[str]:
    """Lines where uv is actually run.

    A mention inside a double-quoted string is a message, not a command: the
    scripts end their uv calls with `|| die "uv pip install failed ..."`.
    """
    found: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0]
        match = re.search(r"\buv (venv|pip)\b", line)
        if match is None:
            continue
        if line[: match.start()].count('"') % 2 == 1:
            continue
        found.append(line.strip())
    return found


@pytest.mark.parametrize("script", ["bootstrap.sh", "update.sh"])
def test_uv_runs_in_a_directory_the_service_user_can_read(script: str):
    """uv searches the working directory and its parents for a uv.toml.

    Started from /root (mode 0550) the unprivileged service user cannot stat
    that path, and uv fails the build rather than finding no config. Every uv
    invocation therefore sets its own working directory and turns config
    discovery off.
    """
    lines = _lines_invoking_uv((SCRIPTS / script).read_text())
    assert lines, f"no uv invocation found in {script}"
    for line in lines:
        assert "env -C " in line, (
            f"{script}: uv inherits the caller's directory: {line}"
        )
        assert "UV_NO_CONFIG=1" in line, (
            f"{script}: uv config discovery left on: {line}"
        )


def test_environment_file_is_owner_only_everywhere():
    """The env file holds the auth client secret and the AWS keys.

    bootstrap wrote 0600 while update and provision reset it to 0640, so a
    single update loosened the mode behind the operator's back.
    """
    for script in ("bootstrap.sh", "update.sh", "provision.sh"):
        text = (SCRIPTS / script).read_text()
        for line in text.splitlines():
            names_env = ".env" in line or "ENV_FILE" in line
            sets_mode = "chmod" in line or "install " in line
            if names_env and sets_mode:
                assert "0640" not in line, (
                    f"{script}: env file left group-readable: {line.strip()}"
                )


def test_provision_creates_every_file_private():
    """provision.sh rewrites the env file through a temporary copy.

    Without a umask at the top, that copy is born 0644 under root's usual
    umask and `mv` puts a world-readable secret file in place; a failure
    before the closing chmod leaves it that way. The umask has to be set
    before anything is written, not inside a branch.
    """
    lines = (SCRIPTS / "provision.sh").read_text().splitlines()
    top_level = [i for i, line in enumerate(lines) if line == "umask 077"]
    assert top_level, "provision.sh does not set a top-level umask 077"
    first_write = next(
        (i for i, line in enumerate(lines) if ">" in line and "ENV_FILE" in line),
        len(lines),
    )
    assert top_level[0] < first_write, (
        "provision.sh writes before its umask takes effect"
    )


def test_caddy_import_check_names_our_own_snippet_directory():
    """A generic "is there any import?" test is not enough.

    Fedora's caddy package ships a Caddyfile that already imports
    `Caddyfile.d/*.caddyfile`. The installer writes its site block to
    `conf.d/`, so a check for any import at all passed, nothing was added,
    and Caddy served plain HTTP with the site block unread while the install
    reported success.
    """
    text = (SCRIPTS / "bootstrap.sh").read_text()
    guard = [
        line
        for line in text.splitlines()
        if "grep" in line and "import" in line and "Caddyfile" in line
    ]
    assert guard, "bootstrap.sh no longer checks the Caddyfile for its import"
    for line in guard:
        assert "conf" in line and "caddy" in line, (
            f"the import check does not name our own snippet directory: {line.strip()}"
        )


def test_tls_failure_is_fatal():
    """A proxy that never answered used to be a warning under a success card.

    The box was left with Explorer healthy on loopback and nothing reachable,
    which is how a broken install passed for a finished one.
    """
    text = (SCRIPTS / "bootstrap.sh").read_text()
    assert 'die "https://${HOSTNAME_FOR_TLS} did not answer' in text, (
        "bootstrap.sh no longer fails when TLS does not come up"
    )
    assert "caddy adapt" in text, (
        "bootstrap.sh does not confirm the site block is actually loaded"
    )
