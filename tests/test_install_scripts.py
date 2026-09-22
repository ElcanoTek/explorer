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
            if "chmod" in line and (".env" in line or "ENV_FILE" in line):
                assert "0640" not in line, (
                    f"{script}: env file left group-readable: {line.strip()}"
                )
