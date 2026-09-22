# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Guards on the installer and updater shell scripts.

Most are source-level checks; Caddy planning runs against temporary fixture
files without root or a service user. They pin faults invisible until install:
a venv build that dies when the operator happens to run it from /root, and an
environment file whose mode silently loosened on update.
"""

from __future__ import annotations

import json
import re
import subprocess
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


def _caddy_helper(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "bash",
            "-euo",
            "pipefail",
            "-c",
            f'source "$1"; {script}',
            "bash",
            str(SCRIPTS / "lib/caddy-site.sh"),
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_caddy_template_contract_matches_installer():
    """Rendered sites must retain their cleanup marker and expected upstream.

    The marker is also a compatibility identifier for files already installed
    by earlier releases; changing both copies would strand those files.
    """
    template = (SCRIPTS.parent / "deploy/explorer.caddy").read_text()
    bootstrap = (SCRIPTS / "bootstrap.sh").read_text()
    marker_result = _caddy_helper('printf "%s\\n" "$EXPLORER_CADDY_MARKER"')
    assert marker_result.returncode == 0, marker_result.stderr
    marker = marker_result.stdout.rstrip("\n")
    assert (
        marker
        == "# Caddy site block for Explorer, imported by /etc/caddy/Caddyfile via"
    )
    assert template.splitlines()[0] == marker

    match = re.search(
        r'explorer_caddy_adapted_has_site "\$adapted" "\$HOSTNAME_FOR_TLS" "([^"]+)"',
        bootstrap,
    )
    assert match, "bootstrap no longer checks the rendered site's upstream"
    assert re.findall(r"^\s*reverse_proxy\s+(\S+)\s*$", template, re.MULTILINE) == [
        match.group(1)
    ]


@pytest.mark.parametrize(
    ("import_line", "target", "add_import"),
    [
        ("import Caddyfile.d/*.caddyfile", "Caddyfile.d/explorer.caddyfile", "0"),
        ("", "conf.d/explorer.caddy", "1"),
        ('import "Caddyfile.d/*.caddyfile"', "Caddyfile.d/explorer.caddyfile", "0"),
        ("import ./conf.d/*", "conf.d/explorer.caddy", "0"),
        ("import conf.d/*.caddy", "conf.d/explorer.caddy", "0"),
    ],
)
def test_caddy_plan_uses_a_loaded_glob(
    tmp_path: Path, import_line: str, target: str, add_import: str
):
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text(import_line + "\n")
    result = _caddy_helper(
        'explorer_caddy_plan "$2"; printf "%s\\n%s\\n" "$EXPLORER_CADDY_TARGET" "$EXPLORER_CADDY_ADD_IMPORT"',
        str(caddyfile),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [str(tmp_path / target), add_import]


def test_caddy_plan_resolves_absolute_import(tmp_path: Path):
    imported = tmp_path / "different" / "*.caddyfile"
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text(f'import "{imported}"\n')
    result = _caddy_helper(
        'explorer_caddy_plan "$2"; printf "%s\\n%s\\n" "$EXPLORER_CADDY_TARGET" "$EXPLORER_CADDY_ADD_IMPORT"',
        str(caddyfile),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        str(tmp_path / "different/explorer.caddyfile"),
        "0",
    ]


@pytest.mark.parametrize("orphan_also_imported", [False, True])
def test_caddy_plan_preserves_loaded_manual_copy_and_removes_only_owned_orphan(
    tmp_path: Path, orphan_also_imported: bool
):
    caddyfile = tmp_path / "Caddyfile"
    imports = "import Caddyfile.d/*.caddyfile\n"
    if orphan_also_imported:
        imports += "import conf.d/*.caddy\n"
    caddyfile.write_text(imports)
    loaded = tmp_path / "Caddyfile.d/explorer.caddyfile"
    orphan = tmp_path / "conf.d/explorer.caddy"
    unrelated = tmp_path / "conf.d/other.caddy"
    for path in (loaded, orphan, unrelated):
        path.parent.mkdir(exist_ok=True)
    marker = "# Caddy site block for Explorer, imported by /etc/caddy/Caddyfile via"
    content = f"{marker}\nexplorer.example {{\n}}\n"
    loaded.write_text(content)
    orphan.write_text(content)
    unrelated.write_text("other.example {\n}\n")
    result = _caddy_helper(
        'explorer_caddy_plan "$2"; printf "%s\\n%s\\n" "$EXPLORER_CADDY_TARGET" "$EXPLORER_CADDY_ADD_IMPORT"; explorer_caddy_remove_stale "$2" "$EXPLORER_CADDY_TARGET"',
        str(caddyfile),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [str(loaded), "0", str(orphan)]
    assert loaded.read_text() == content
    assert not orphan.exists()
    assert unrelated.exists()


def test_caddy_cleanup_removes_owned_old_hostname_but_not_unmarked_file(
    tmp_path: Path,
):
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text("import Caddyfile.d/*.caddyfile\n")
    directory = tmp_path / "conf.d"
    directory.mkdir()
    unmarked = directory / "explorer.caddy"
    old_hostname = directory / "old.caddy"
    unmarked.write_text("explorer.example {\n}\n")
    old_hostname.write_text(
        "# Caddy site block for Explorer, imported by /etc/caddy/Caddyfile via\nother.example {\n}\n"
    )
    result = _caddy_helper(
        'explorer_caddy_plan "$2"; explorer_caddy_remove_stale "$2" "$EXPLORER_CADDY_TARGET"',
        str(caddyfile),
    )
    assert result.returncode == 0, result.stderr
    assert unmarked.exists()
    assert not old_hostname.exists()


def test_caddy_adapted_check_requires_host_matcher_and_explorer_proxy(tmp_path: Path):
    adapted = tmp_path / "adapted.json"
    route = {
        "match": [{"host": ["other.example"]}],
        "handle": [
            {
                "handler": "subroute",
                "routes": [
                    {
                        "handle": [
                            {
                                "handler": "reverse_proxy",
                                "upstreams": [{"dial": "127.0.0.1:8080"}],
                            }
                        ]
                    }
                ],
            }
        ],
    }
    payload = {
        "email": "explorer.example",
        "apps": {"http": {"servers": {"srv0": {"routes": [route]}}}},
    }
    adapted.write_text(json.dumps(payload))
    script = 'explorer_caddy_adapted_has_site "$2" explorer.example 127.0.0.1:8080'
    assert _caddy_helper(script, str(adapted)).returncode != 0
    route["match"][0]["host"] = ["explorer.example"]
    adapted.write_text(json.dumps(payload))
    result = _caddy_helper(script, str(adapted))
    assert result.returncode == 0, result.stderr
    route["handle"][0]["routes"][0]["handle"][0]["upstreams"][0]["dial"] = (
        "127.0.0.1:9999"
    )
    adapted.write_text(json.dumps(payload))
    assert _caddy_helper(script, str(adapted)).returncode != 0


def test_bootstrap_uses_the_tested_caddy_helpers_before_opening_firewall():
    text = (SCRIPTS / "bootstrap.sh").read_text()
    assert 'explorer_caddy_plan "$caddyfile"' in text
    assert 'explorer_caddy_remove_stale "$caddyfile"' in text
    assert 'explorer_caddy_adapted_has_site "$adapted"' in text
    assert text.index("caddy validate --config") < text.index(
        "firewall-cmd --add-service"
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
    assert "explorer_caddy_adapted_has_site" in text, (
        "bootstrap.sh does not confirm the site block is actually loaded"
    )
