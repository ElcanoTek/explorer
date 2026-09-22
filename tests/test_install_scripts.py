# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Guards on the installer and updater shell scripts.

Most are source-level checks; Caddy planning runs against temporary fixture
files without root or a service user. They pin faults invisible until install:
a venv build that dies when the operator happens to run it from /root, and an
environment file whose mode silently loosened on update.
"""

from __future__ import annotations

import base64
import getpass
import importlib.util
import json
import re
import subprocess
import sys
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


def test_uv_runs_with_an_isolated_home_and_no_config_discovery():
    """uv searches the working directory and its parents for a uv.toml.

    Started from /root (mode 0550) the unprivileged service user cannot stat
    that path, and uv fails the build rather than finding no config. Every uv
    invocation therefore sets its own working directory and turns config
    discovery off.
    """
    script = "lib/layout.sh"
    text = (SCRIPTS / script).read_text()
    lines = _lines_invoking_uv(text.replace('"$uv_bin"', "uv"))
    assert lines, f"no uv invocation found in {script}"
    assert text.count('env -i -C "$staging"') == len(lines)
    assert text.count("UV_NO_CONFIG=1") == len(lines)
    assert text.count('HOME="$BUILD_CACHE"') == len(lines)


def test_root_never_installs_privileged_files_from_the_live_or_staged_tree():
    update = (SCRIPTS / "update.sh").read_text()
    bootstrap = (SCRIPTS / "bootstrap.sh").read_text()
    assert '"$SRC_DIR/deploy/explorer-cli"' in update
    assert '"$INSTALL_SRC_DIR/deploy/explorer-cli"' in bootstrap
    assert '"$APP_DIR/deploy/explorer-cli"' not in update + bootstrap
    assert 'chown -R "$APP_USER:$APP_USER"' not in update + bootstrap
    assert 'layout_revision_matches "$after_sha"' in update


def test_root_scripts_do_not_source_the_service_owned_environment():
    for script in ("bootstrap.sh", "update.sh"):
        text = (SCRIPTS / script).read_text()
        assert 'source "$ENV_FILE"' not in text
        assert '. "$ENV_FILE"' not in text
        assert "layout_read_env" in text


def test_service_owned_environment_is_parsed_as_data(tmp_path: Path):
    marker = tmp_path / "executed"
    env_file = tmp_path / ".env"
    literal = f"$(touch {marker})"
    env_file.write_text(f'EXPLORER_SESSION_SECRET="{literal}"\nPATH="/attacker"\n')
    result = subprocess.run(
        [
            "bash",
            "-euo",
            "pipefail",
            "-c",
            'APP_DIR=/unused APP_USER=nobody; source "$1"; '
            'layout_read_env "$2"; printf "%s\\n%s\\n" '
            '"$EXPLORER_SESSION_SECRET" "$PATH"',
            "bash",
            str(SCRIPTS / "lib/layout.sh"),
            str(env_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[0] == literal
    assert result.stdout.splitlines()[1] != "/attacker"
    assert not marker.exists()


def test_operator_cli_checks_source_before_root_handoff():
    text = (SCRIPTS.parent / "deploy/explorer-cli").read_text()
    assert text.count("trusted_source_or_die") >= 4
    assert text.index("trusted_source_or_die", text.index("  update)")) < text.index(
        'exec sudo bash "$SRC_DIR/scripts/update.sh"'
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


def test_root_env_writers_refuse_links():
    provision = (SCRIPTS / "provision.sh").read_text()
    cli = (SCRIPTS.parent / "deploy/explorer-cli").read_text()
    assert "! -L $ENV_FILE" in provision
    assert 'stat -c %h "$ENV_FILE"' in provision
    assert 'sudo test -L "$ENV_FILE"' in cli
    assert 'sudo stat -c %h "$ENV_FILE"' in cli


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


REPO_ROOT = SCRIPTS.parent


def test_install_sh_is_a_thin_clone_entrypoint():
    """The public one-liner downloads and pipes this to root bash.

    Same contract as the other Elcano services: parse-guarded function,
    root + dnf required, refuses to clobber an existing checkout, clones
    main and hands off to bootstrap.sh.
    """
    text = (REPO_ROOT / "install.sh").read_text()
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "SPDX-License-Identifier: BUSL-1.1" in text
    assert "set -euo pipefail" in text
    assert (
        "git clone --branch main --single-branch https://github.com/ElcanoTek/explorer.git"
        in text
    )
    assert 'exec bash "$src/scripts/bootstrap.sh"' in text
    assert "command -v dnf" in text, "install.sh lost its Fedora/RHEL detection"
    assert "[[ $EUID == 0 ]]" in text, "install.sh no longer demands root"
    assert "already exists. Use explorer update" in text, (
        "install.sh would overwrite an existing /opt/explorer-src"
    )


def test_doctor_wrapper_dispatches_to_sibling_doctor_py():
    """scripts/doctor.sh is a trampoline so `explorer doctor` has one home.

    It must resolve doctor.py next to itself (not via PATH or cwd), so the
    command behaves identically from any directory.
    """
    text = (SCRIPTS / "doctor.sh").read_text()
    assert "SPDX-License-Identifier: BUSL-1.1" in text
    assert 'exec python3 "$(dirname "${BASH_SOURCE[0]}")/doctor.py" "$@"' in text, (
        "doctor.sh no longer execs the sibling doctor.py"
    )


def test_doctor_py_never_imports_the_app():
    """doctor.py must run on a broken box — importing app/ would crash it.

    app/config.py reads the environment at import time, and the whole point
    of doctor is diagnosing a box where that environment is wrong. Secrets
    are parsed in-process and only key names/booleans/lengths ever leave it.
    The venv's python-dotenv is deliberately NOT used: that interpreter is
    service-writable and a root-run doctor must never execute it, so the
    parser mirrors python-dotenv's supported semantics in stdlib code.
    """
    text = (SCRIPTS / "doctor.py").read_text()
    assert "SPDX-License-Identifier: BUSL-1.1" in text
    for banned in ("import app", "from app", "import main", "uvicorn"):
        assert banned not in text, f"doctor.py imports the application: {banned}"
    assert "dotenv_values" not in text, (
        "doctor.py must not execute the service-owned venv interpreter for parsing"
    )
    assert "_parse_dotenv" in text, "doctor.py no longer carries its dotenv parser"


def test_operator_cli_dispatches_doctor():
    """`explorer doctor` must reach scripts/doctor.sh (src preferred, app fallback)."""
    text = (REPO_ROOT / "deploy/explorer-cli").read_text()
    assert "doctor)" in text
    assert (
        'exec sudo env EXPLORER_SRC_DIR="$SRC_DIR" APP_DIR="$APP_DIR" bash "$doctor_script" "$@"'
        in text
    )
    assert "doctor [--json] [--strict]" in text


def test_doctor_py_json_smoke_on_a_bare_box(tmp_path: Path):
    """doctor.py --json must emit a well-formed report and exit 1 when broken.

    Pointed at an empty APP_DIR/SRC_DIR (no venv, no units, no git) every
    probe degrades to a check line instead of an exception — that is the
    contract a real broken box relies on.
    """
    for flag in ("--help",):
        result = subprocess.run(
            ["python3", str(SCRIPTS / "doctor.py"), flag],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
    env = {
        "APP_DIR": str(tmp_path / "app"),
        "EXPLORER_SRC_DIR": str(tmp_path / "src"),
        "APP_USER": "explorer",
        "PATH": "/usr/bin:/bin",
    }
    result = subprocess.run(
        ["python3", str(SCRIPTS / "doctor.py"), "--json"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        timeout=120,
    )
    assert result.returncode == 1, result.stdout
    report = json.loads(result.stdout)
    assert report["ok"] is False
    checks = report["checks"]
    assert len(checks) > 5
    for check in checks:
        assert set(check) == {"name", "status", "detail"}, check
        assert check["status"] in ("ok", "warn", "fail"), check


def _run_doctor_json(
    tmp_path: Path,
    app_dir: Path,
    src_dir: Path,
    path: str = "/usr/bin:/bin",
    extra_env: dict | None = None,
) -> dict:
    """Run doctor.py --json against scratch dirs with a caller-chosen PATH.

    The default keeps the host tools (fast, degrades offline); reboot-chain
    tests pass a stub-only PATH so they decide which tier runs.
    """
    env = {
        "APP_DIR": str(app_dir),
        "EXPLORER_SRC_DIR": str(src_dir),
        # The invoking user owns fixture files; only the reboot/service
        # stubs care about the value itself.
        "APP_USER": getpass.getuser(),
        "PATH": path,
    }
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        ["python3", str(SCRIPTS / "doctor.py"), "--json"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        timeout=120,
    )
    assert result.returncode == 1, result.stdout
    return json.loads(result.stdout)


def _checks_by_name(report: dict) -> dict:
    return {check["name"]: check for check in report["checks"]}


_VALID_PUBKEY = base64.b64encode(bytes(range(32))).decode()


def _healthy_dotenv() -> str:
    return (
        f'EXPLORER_SESSION_SECRET="{"s" * 48}"\n'
        "EMAIL_S3_BUCKET=archive\n"
        "AWS_ACCESS_KEY_ID=AKIAEXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=example-secret\n"
        "EXPLORER_AUTH_MODE=elcano\n"
        f"AUTH_SIGNING_PUBKEY={_VALID_PUBKEY}\n"
    )


def _make_fake_app(tmp_path: Path) -> Path:
    """A scratch APP_DIR with a venv stand-in and a healthy .env.

    pyvenv.cfg stands in for the venv — the python check reads it because a
    root-run doctor must never execute the service-writable venv
    interpreter. Each test rewrites .env (and optionally .env.shared) with
    real dotenv text, so parsing is exercised end to end.
    """
    app = tmp_path / "app"
    (app / ".venv").mkdir(parents=True)
    (app / ".venv/pyvenv.cfg").write_text(
        "home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.11.9\n"
    )
    _write_dotenv(app, _healthy_dotenv())
    return app


def _write_dotenv(app: Path, local: str, shared: str = "") -> None:
    (app / ".env").write_text(local)
    (app / ".env").chmod(0o600)
    shared_path = app / ".env.shared"
    if shared:
        shared_path.write_text(shared)
        shared_path.chmod(0o600)
    else:
        shared_path.unlink(missing_ok=True)


def _drop_lines(text: str, *prefixes: str) -> str:
    return (
        "\n".join(line for line in text.splitlines() if not line.startswith(prefixes))
        + "\n"
    )


def test_doctor_static_aws_keys_do_not_crash(tmp_path: Path):
    """The static-credentials OK line used to omit the remedy argument.

    add() took remedy positionally, so a box with AWS keys set (a healthy
    box!) crashed doctor with TypeError instead of getting a clean report.
    """
    app = _make_fake_app(tmp_path)
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    checks = _checks_by_name(report)
    aws = checks["aws-credentials"]
    assert aws["status"] == "ok", aws
    assert aws["detail"] == "static AWS credentials configured"
    assert checks["python"]["status"] == "ok", checks["python"]


def test_doctor_short_session_secret_reported_once(tmp_path: Path):
    """The real-box case: pubkey fine, session secret 26 chars.

    The old remedy always named BOTH keys, and the one fault failed the box
    twice ('configuration' and 'session-secret'). Now configuration passes —
    the secret is not its concern — and the single FAIL names the actual
    length.
    """
    app = _make_fake_app(tmp_path)
    _write_dotenv(
        app, _healthy_dotenv().replace('"' + "s" * 48 + '"', '"' + "s" * 26 + '"')
    )
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    checks = _checks_by_name(report)
    assert checks["configuration"]["status"] == "ok", checks["configuration"]
    secret = checks["session-secret"]
    assert secret["status"] == "fail", secret
    assert "got 26 chars, need >= 32" in secret["detail"], secret
    assert "SESSION_SECRET" not in checks["configuration"]["detail"]
    names = [check["name"] for check in report["checks"]]
    assert names.count("session-secret") == 1, names


def test_doctor_configuration_remedy_names_missing_keys(tmp_path: Path):
    app = _make_fake_app(tmp_path)
    _write_dotenv(app, _drop_lines(_healthy_dotenv(), "AUTH_SIGNING_PUBKEY"))
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    config = _checks_by_name(report)["configuration"]
    assert config["status"] == "fail", config
    assert config["detail"] == "missing: AUTH_SIGNING_PUBKEY", config
    # a missing key is named once — not repeated as a shape problem
    assert "32-byte" not in config["detail"]


def test_doctor_configuration_remedy_names_bad_key_shape(tmp_path: Path):
    app = _make_fake_app(tmp_path)
    _write_dotenv(
        app,
        _healthy_dotenv().replace(
            f"AUTH_SIGNING_PUBKEY={_VALID_PUBKEY}", "AUTH_SIGNING_PUBKEY=not!!base64"
        ),
    )
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    config = _checks_by_name(report)["configuration"]
    assert config["status"] == "fail", config
    assert (
        config["detail"]
        == "AUTH_SIGNING_PUBKEY is set but is not a 32-byte base64 Ed25519 key"
    ), config


def test_doctor_configuration_remedy_names_bad_mode(tmp_path: Path):
    app = _make_fake_app(tmp_path)
    _write_dotenv(
        app,
        _healthy_dotenv().replace(
            "EXPLORER_AUTH_MODE=elcano", "EXPLORER_AUTH_MODE=ldap"
        ),
    )
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    config = _checks_by_name(report)["configuration"]
    assert config["status"] == "fail", config
    assert (
        config["detail"]
        == "EXPLORER_AUTH_MODE must be 'elcano' or 'central' (got 'ldap')"
    ), config


def test_doctor_configuration_names_missing_central_keys(tmp_path: Path):
    app = _make_fake_app(tmp_path)
    local = _healthy_dotenv().replace(
        "EXPLORER_AUTH_MODE=elcano", "EXPLORER_AUTH_MODE=central"
    )
    local += "AUTH_ISSUER_URL=https://auth.example.com\nAUTH_CLIENT_ID=explorer\n"
    _write_dotenv(app, local)
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    config = _checks_by_name(report)["configuration"]
    assert config["status"] == "fail", config
    assert config["detail"] == "missing: EXPLORER_PUBLIC_URL, AUTH_CLIENT_SECRET", (
        config
    )


@pytest.mark.parametrize(
    ("bad_line", "expected"),
    [
        (
            "AUTH_CLIENT_SECRET=short",
            "AUTH_CLIENT_SECRET must contain at least 32 bytes (got 5)",
        ),
        (
            "AUTH_ISSUER_URL=http://auth.example.com",
            "AUTH_ISSUER_URL must be an https origin without a path, query or embedded credentials",
        ),
        (
            "AUTH_ISSUER_URL=https://auth.example.com/some/path",
            "AUTH_ISSUER_URL must be an https origin without a path, query or embedded credentials",
        ),
        (
            'AUTH_CLIENT_ID="bad:id"',
            "AUTH_CLIENT_ID must be 1-128 characters without ':'",
        ),
    ],
)
def test_doctor_configuration_validates_central_values(
    tmp_path: Path, bad_line: str, expected: str
):
    """Mirror CentralAuthClient's rules: a restart would refuse to start.

    Presence-only validation reported configuration OK while the next
    restart would die — the old process keeps serving, so the lie surfaces
    only at the worst moment.
    """
    app = _make_fake_app(tmp_path)
    key = bad_line.split("=")[0]
    local = _drop_lines(_healthy_dotenv(), "EXPLORER_AUTH_MODE", "AUTH_SIGNING_PUBKEY")
    local += (
        "EXPLORER_AUTH_MODE=central\n"
        "AUTH_SIGNING_PUBKEY="
        + _VALID_PUBKEY
        + "\n"
        + "AUTH_ISSUER_URL=https://auth.example.com\n"
        + "EXPLORER_PUBLIC_URL=https://explorer.example.com\n"
        + "AUTH_CLIENT_ID=explorer\n"
        + "AUTH_CLIENT_SECRET="
        + "x" * 40
        + "\n"
    )
    lines = [bad_line if line.startswith(key) else line for line in local.splitlines()]
    _write_dotenv(app, "\n".join(lines) + "\n")
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    config = _checks_by_name(report)["configuration"]
    assert config["status"] == "fail", config
    assert expected in config["detail"], config
    assert "secret-value" not in config["detail"].lower()


def test_doctor_dotenv_interpolation_matches_the_app(tmp_path: Path):
    """${VAR} references across .env.shared/.env resolve like app/config.py.

    The app loads .env.shared then .env with interpolation on; a placeholder
    for a key defined in the shared file is valid there and must be valid
    here. ${VAR:-default} must work too.
    """
    app = _make_fake_app(tmp_path)
    local = _healthy_dotenv().replace(
        f"AUTH_SIGNING_PUBKEY={_VALID_PUBKEY}", "AUTH_SIGNING_PUBKEY=${SHARED_KEY}"
    )
    _write_dotenv(app, local, shared=f"SHARED_KEY={_VALID_PUBKEY}\n")
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    checks = _checks_by_name(report)
    assert checks["configuration"]["status"] == "ok", checks["configuration"]

    local = _healthy_dotenv().replace(
        f"AUTH_SIGNING_PUBKEY={_VALID_PUBKEY}",
        "AUTH_SIGNING_PUBKEY=${MISSING:-" + _VALID_PUBKEY + "}",
    )
    _write_dotenv(app, local)
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    assert _checks_by_name(report)["configuration"]["status"] == "ok"


def test_doctor_dotenv_local_overrides_shared(tmp_path: Path):
    app = _make_fake_app(tmp_path)
    _write_dotenv(app, _healthy_dotenv(), shared="AUTH_SIGNING_PUBKEY=garbage!!\n")
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    assert _checks_by_name(report)["configuration"]["status"] == "ok"


def test_doctor_env_shared_permissions_checked(tmp_path: Path):
    """A group-readable .env.shared exposes secrets while .env looks clean."""
    app = _make_fake_app(tmp_path)
    shared = app / ".env.shared"
    shared.write_text("AWS_SECRET_ACCESS_KEY=shared-secret\n")
    shared.chmod(0o644)
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    checks = _checks_by_name(report)
    assert checks["env-permissions"]["status"] == "ok", checks["env-permissions"]
    shared_check = checks["env-shared-permissions"]
    assert shared_check["status"] == "fail", shared_check
    assert "chmod 600" in shared_check["detail"], shared_check


def test_doctor_env_symlink_is_not_followed(tmp_path: Path):
    app = _make_fake_app(tmp_path)
    target = app / "real.env"
    target.write_text(_healthy_dotenv())
    (app / ".env").unlink()
    (app / ".env").symlink_to(target)
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    perms = _checks_by_name(report)["env-permissions"]
    assert perms["status"] == "fail", perms
    assert "symlink" in perms["detail"], perms


def _make_clone_behind_origin(tmp_path: Path) -> tuple[Path, Path]:
    """A local clone of a local origin, with N commits pushed after cloning."""
    origin = tmp_path / "origin.git"
    subprocess.run(
        ["git", "init", "--bare", "-b", "main", str(origin)],
        capture_output=True,
        check=True,
    )
    seed = tmp_path / "seed"
    seed.mkdir()
    for cmd in (
        ["git", "init", "-b", "main"],
        ["git", "config", "user.email", "test@example.com"],
        ["git", "config", "user.name", "Test"],
    ):
        subprocess.run(cmd, cwd=seed, capture_output=True, check=True)
    (seed / "file.txt").write_text("one\n")
    subprocess.run(["git", "add", "."], cwd=seed, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "one"], cwd=seed, capture_output=True, check=True
    )
    subprocess.run(
        ["git", "remote", "add", "origin", str(origin)],
        cwd=seed,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "push", "origin", "main"], cwd=seed, capture_output=True, check=True
    )
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", str(origin), str(clone)],
        capture_output=True,
        check=True,
    )
    return origin, clone


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, check=True)


def test_doctor_branch_warns_when_behind_origin(tmp_path: Path):
    """A stale local origin/main must not read as current (Codex #28 d).

    The check compares HEAD against the LIVE remote (git ls-remote) — no
    fetch, which would mutate the checkout from a read-only run. When the
    local tracking ref is itself stale the report says 'behind' without
    inventing a commit count.
    """
    origin, clone = _make_clone_behind_origin(tmp_path)
    seed = tmp_path / "seed"
    (seed / "file.txt").write_text("one\ntwo\nthree\n")
    _git(seed, "add", ".")
    _git(seed, "commit", "-m", "two")
    _git(seed, "push", "origin", "main")
    assert origin.is_dir() and clone.is_dir()

    report = _run_doctor_json(tmp_path, tmp_path / "app", clone)
    branch = _checks_by_name(report)["branch"]
    assert branch["status"] == "warn", branch
    assert branch["detail"] == (
        "checkout is behind origin/main — run explorer update"
    ), branch


def test_doctor_branch_up_to_date_against_live_remote(tmp_path: Path):
    """HEAD == live remote sha passes — only ls-remote can prove that."""
    _, clone = _make_clone_behind_origin(tmp_path)
    report = _run_doctor_json(tmp_path, tmp_path / "app", clone)
    branch = _checks_by_name(report)["branch"]
    assert branch["status"] == "ok", branch
    assert branch["detail"] == "on main, up to date with origin", branch


def test_doctor_branch_check_never_mutates_the_checkout(tmp_path: Path):
    """Read-only means read-only: no FETCH_HEAD, no ref movement (lead req).

    ls-remote contacts the remote without writing anything; assert both the
    tracking ref and FETCH_HEAD are untouched after a full doctor run.
    """
    _, clone = _make_clone_behind_origin(tmp_path)
    before = subprocess.run(
        ["git", "-C", str(clone), "rev-parse", "origin/main"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert not (clone / ".git" / "FETCH_HEAD").exists()
    _run_doctor_json(tmp_path, tmp_path / "app", clone)
    after = subprocess.run(
        ["git", "-C", str(clone), "rev-parse", "origin/main"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert after == before, "doctor moved origin/main"
    assert not (clone / ".git" / "FETCH_HEAD").exists(), (
        "doctor wrote FETCH_HEAD — a fetch leaked into the read-only path"
    )


def test_doctor_branch_honest_when_remote_unreachable(tmp_path: Path):
    """An unreachable origin must never read as 'up to date'.

    Point the clone's origin at a path that does not exist: ls-remote
    fails, and the check has to say it could not compare — not claim current.
    """
    _, clone = _make_clone_behind_origin(tmp_path)
    _git(clone, "remote", "set-url", "origin", str(tmp_path / "gone.git"))

    report = _run_doctor_json(tmp_path, tmp_path / "app", clone)
    branch = _checks_by_name(report)["branch"]
    assert branch["status"] == "warn", branch
    assert "could not reach origin" in branch["detail"], branch
    assert "up to date" not in branch["detail"], branch


REBOOT_WARN = "kernel or core libraries updated — reboot the host when convenient"
REBOOT_UNKNOWN = (
    "could not determine reboot status — needs-restarting, dnf "
    "needs-restarting and rpm/uname all unavailable or failed"
)

# The running kernel every stub below agrees on.
RUNNING_KERNEL = "6.9.1-1.fc40.x86_64"

STUB_NEEDS_REBOOT = "#!/bin/bash\nexit 1\n"
STUB_DNF_REBOOT = """#!/bin/bash
# stub dnf: check-update reports current; needs-restarting demands a reboot
if [[ "${1:-}" == "needs-restarting" ]]; then exit 1; fi
exit 0
"""
STUB_DNF_NO_REBOOT = """#!/bin/bash
# stub dnf: every subcommand, including needs-restarting, says all is fine
exit 0
"""
STUB_UNAME = f"#!/bin/bash\necho {RUNNING_KERNEL}\n"
STUB_RPM_NEWER_KERNEL = """#!/bin/bash
# rpm -q kernel --last, newest first; newer than the running kernel
echo "kernel-6.10.0-1.fc40.x86_64    Wed 01 Jan 2025 12:00:00 AM UTC"
echo "kernel-6.9.1-1.fc40.x86_64     Tue 01 Jan 2025 12:00:00 AM UTC"
"""
STUB_RPM_RUNNING_NEWEST = """#!/bin/bash
# the running kernel is the newest installed
echo "kernel-6.9.1-1.fc40.x86_64     Tue 01 Jan 2025 12:00:00 AM UTC"
echo "kernel-6.8.0-1.fc40.x86_64     Mon 01 Jan 2025 12:00:00 AM UTC"
"""
STUB_RPM_FAILS = """#!/bin/bash
echo "error: no package found" >&2
exit 1
"""


def _hermetic_path(tmp_path: Path, stubs: dict[str, str]) -> str:
    """A PATH holding only python3 plus the given command stubs.

    Stubs are bash scripts with a /bin/bash shebang so they run without
    /usr/bin on PATH. Everything else doctor probes for (needs-restarting,
    dnf, uname, rpm, ...) is genuinely absent, so the fallback chain under
    test is decided by which stubs exist — not by the host the suite runs on.
    """
    bin_dir = tmp_path / "stub-bin"
    bin_dir.mkdir(exist_ok=True)
    py_dir = tmp_path / "stub-py"
    py_dir.mkdir(exist_ok=True)
    (py_dir / "python3").symlink_to(Path(sys.executable).resolve())
    for name, script in stubs.items():
        path = bin_dir / name
        path.write_text(script)
        path.chmod(0o755)
    return f"{bin_dir}:{py_dir}"


def test_doctor_reboot_needs_restarting_tier_decides(tmp_path: Path):
    """Tier 1: needs-restarting present -> its verdict feeds the chain."""
    path = _hermetic_path(tmp_path, {"needs-restarting": STUB_NEEDS_REBOOT})
    report = _run_doctor_json(tmp_path, tmp_path / "app", tmp_path / "src", path=path)
    reboot = _checks_by_name(report)["reboot"]
    assert reboot["status"] == "warn", reboot
    assert reboot["detail"] == REBOOT_WARN, reboot


def test_doctor_reboot_f44_scenario_dnf_plugin_decides(tmp_path: Path):
    """F44: needs-restarting binary absent, dnf plugin answers -> verdict.

    This is the silent-skip scenario from the box review: the chain must
    still produce a 'reboot' line (a verdict, not nothing) when only the
    dnf plugin can speak.
    """
    path = _hermetic_path(tmp_path, {"dnf": STUB_DNF_REBOOT})
    report = _run_doctor_json(tmp_path, tmp_path / "app", tmp_path / "src", path=path)
    reboot = _checks_by_name(report)["reboot"]
    assert reboot["status"] == "warn", reboot
    assert reboot["detail"] == REBOOT_WARN, reboot


def test_doctor_reboot_line_always_present(tmp_path: Path):
    """No tier installed at all: the check still emits its unknown advisory.

    The lookup itself is the guard — a silently skipped 'reboot' check would
    KeyError here, which is exactly the failure mode the box review found.
    """
    path = _hermetic_path(tmp_path, {})
    report = _run_doctor_json(tmp_path, tmp_path / "app", tmp_path / "src", path=path)
    reboot = _checks_by_name(report)["reboot"]
    assert reboot["status"] == "warn", reboot
    assert reboot["detail"] == REBOOT_UNKNOWN, reboot


def test_doctor_reboot_any_yes_wins_across_tiers(tmp_path: Path):
    """The whole chain is walked: dnf says no but rpm proves a newer kernel.

    Under the old short-circuit the first 'no' skipped the remaining tiers
    and reported OK — a stale tier could outvote a current one. Now a single
    'yes' wins.
    """
    path = _hermetic_path(
        tmp_path,
        {"dnf": STUB_DNF_NO_REBOOT, "uname": STUB_UNAME, "rpm": STUB_RPM_NEWER_KERNEL},
    )
    report = _run_doctor_json(tmp_path, tmp_path / "app", tmp_path / "src", path=path)
    reboot = _checks_by_name(report)["reboot"]
    assert reboot["status"] == "warn", reboot
    assert reboot["detail"] == REBOOT_WARN, reboot


def test_doctor_reboot_uname_rpm_tier_newer_kernel_installed(tmp_path: Path):
    """Tier 3: both tools absent; uname runs an older kernel than rpm lists."""
    path = _hermetic_path(tmp_path, {"uname": STUB_UNAME, "rpm": STUB_RPM_NEWER_KERNEL})
    report = _run_doctor_json(tmp_path, tmp_path / "app", tmp_path / "src", path=path)
    reboot = _checks_by_name(report)["reboot"]
    assert reboot["status"] == "warn", reboot
    assert reboot["detail"] == REBOOT_WARN, reboot


def test_doctor_reboot_uname_rpm_tier_running_newest(tmp_path: Path):
    """Tier 3 the other way: running kernel is the newest installed -> OK."""
    path = _hermetic_path(
        tmp_path, {"uname": STUB_UNAME, "rpm": STUB_RPM_RUNNING_NEWEST}
    )
    report = _run_doctor_json(tmp_path, tmp_path / "app", tmp_path / "src", path=path)
    reboot = _checks_by_name(report)["reboot"]
    assert reboot["status"] == "ok", reboot
    assert reboot["detail"] == "no reboot pending", reboot


def test_doctor_reboot_unknown_when_rpm_fails(tmp_path: Path):
    """Tier 3 with rpm erroring: honest advisory, no crash, no guessed verdict."""
    path = _hermetic_path(tmp_path, {"uname": STUB_UNAME, "rpm": STUB_RPM_FAILS})
    report = _run_doctor_json(tmp_path, tmp_path / "app", tmp_path / "src", path=path)
    reboot = _checks_by_name(report)["reboot"]
    assert reboot["status"] == "warn", reboot
    assert reboot["detail"] == REBOOT_UNKNOWN, reboot


STUB_NEEDS_RESTARTING_ERRORS = "#!/bin/bash\nexit 2\n"

STUB_SYSTEMCTL_ACTIVE_BUT_DISABLED = """#!/bin/bash
# stub systemctl: the service runs but was disabled; timer absent
cmd="${1:-}"
case "$cmd" in
  is-active) exit 0 ;;
  is-enabled) exit 1 ;;
  cat) exit 1 ;;
  show) echo 0; exit 0 ;;
esac
exit 1
"""


def test_doctor_reboot_tier_error_is_unknown_not_ok(tmp_path: Path):
    """Codex #28 k: an errored tier (exit 2, or run()'s 127) is not a 'no'.

    Only a successful zero exit may produce OK; everything else leaves the
    tier unable to answer, and with no answering tier the verdict is the
    unknown advisory.
    """
    path = _hermetic_path(tmp_path, {"needs-restarting": STUB_NEEDS_RESTARTING_ERRORS})
    report = _run_doctor_json(tmp_path, tmp_path / "app", tmp_path / "src", path=path)
    reboot = _checks_by_name(report)["reboot"]
    assert reboot["status"] == "warn", reboot
    assert reboot["detail"] == REBOOT_UNKNOWN, reboot


def test_doctor_service_active_but_disabled_warns(tmp_path: Path):
    """Codex #28 m: active only means up; enabled means it survives reboot."""
    path = _hermetic_path(tmp_path, {"systemctl": STUB_SYSTEMCTL_ACTIVE_BUT_DISABLED})
    report = _run_doctor_json(tmp_path, tmp_path / "app", tmp_path / "src", path=path)
    checks = _checks_by_name(report)
    assert checks["service"]["status"] == "ok", checks["service"]
    enabled = checks["service-enabled"]
    assert enabled["status"] == "warn", enabled
    assert "DISABLED" in enabled["detail"], enabled


def test_doctor_operator_cli_missing_is_a_failure(tmp_path: Path):
    """Codex #28 j: a deleted /usr/local/bin/explorer must fail, not vanish.

    The fixture app ships no deploy/explorer-cli, so the check must report
    the missing side regardless of whether the real CLI exists on the host.
    """
    app = _make_fake_app(tmp_path)
    report = _run_doctor_json(tmp_path, app, tmp_path / "src")
    cli = _checks_by_name(report)["operator-cli"]
    assert cli["status"] == "fail", cli
    assert "missing" in cli["detail"], cli


def _caddy_fixture(tmp_path: Path, import_line: str, block_name: str) -> Path:
    """A scratch /etc/caddy layout with an installed Explorer site block."""
    root = tmp_path / "caddy"
    confd = root / "conf.d"
    confd.mkdir(parents=True)
    (root / "Caddyfile").write_text(import_line + "\n")
    (confd / block_name).write_text(
        "# Caddy site block for Explorer, imported by /etc/caddy/Caddyfile via\n"
        "# `import conf.d/*.caddy`\n"
        "explorer.example {\n"
        "\treverse_proxy 127.0.0.1:8080\n"
        "}\n"
    )
    return root / "Caddyfile"


def test_caddy_probe_follows_installed_import_path(tmp_path: Path):
    """Codex #28 a: find the block under whatever glob the Caddyfile loads."""
    doctor = _load_doctor()
    caddyfile = _caddy_fixture(tmp_path, "import conf.d/*.caddy", "explorer.caddy")
    snippet, host = doctor.caddy_site_host(str(caddyfile))
    assert snippet == str(tmp_path / "caddy/conf.d/explorer.caddy"), snippet
    assert host == "explorer.example", host


def test_caddy_probe_synthesizes_name_for_unconventional_glob(tmp_path: Path):
    """sites-enabled/*.caddy must resolve to sites-enabled/explorer.caddy."""
    doctor = _load_doctor()
    root = tmp_path / "caddy"
    sites = root / "sites-enabled"
    sites.mkdir(parents=True)
    (root / "Caddyfile").write_text("import sites-enabled/*.caddy\n")
    (sites / "explorer.caddy").write_text(
        "# Caddy site block for Explorer, imported by /etc/caddy/Caddyfile via\n"
        "explorer.example {\n}\n"
    )
    snippet, host = doctor.caddy_site_host(str(root / "Caddyfile"))
    assert snippet == str(sites / "explorer.caddy"), snippet
    assert host == "explorer.example", host


def test_caddy_probe_returns_none_without_installed_block(tmp_path: Path):
    doctor = _load_doctor()
    caddyfile = _caddy_fixture(tmp_path, "import conf.d/*.caddy", "other.caddy")
    assert doctor.caddy_site_host(str(caddyfile)) == (None, None)


def test_doctor_missing_caddy_binary_fails(tmp_path: Path):
    """Codex #28 b: an installed site block with no caddy binary is a FAIL.

    The loopback readiness can pass while the public endpoint is dead — a
    missing binary must not silently skip the Caddy checks.
    """
    caddyfile = _caddy_fixture(tmp_path, "import conf.d/*.caddy", "explorer.caddy")
    path = _hermetic_path(tmp_path, {})
    report = _run_doctor_json(
        tmp_path,
        tmp_path / "app",
        tmp_path / "src",
        path=path,
        extra_env={"EXPLORER_CADDYFILE": str(caddyfile)},
    )
    caddy = _checks_by_name(report)["caddy"]
    assert caddy["status"] == "fail", caddy
    assert "caddy binary is missing" in caddy["detail"], caddy


def test_doctor_tls_probe_verifies_hostname_and_chain():
    """Codex #28 e + lead TLS rule: wrong-host/untrusted certs must fail."""
    text = (SCRIPTS / "doctor.py").read_text()
    assert '"-verify_hostname"' in text, "s_client lost hostname verification"
    assert '"-verify_return_error"' in text, "s_client lost chain verification"


def _load_doctor():
    spec = importlib.util.spec_from_file_location(
        "explorer_doctor", SCRIPTS / "doctor.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_operator_cli_doctor_dispatch_is_sudo_env_safe():
    """Codex #28 c+i: forward the source path through sudo, survive .git loss."""
    text = (REPO_ROOT / "deploy/explorer-cli").read_text()
    assert "sudo env EXPLORER_SRC_DIR=" in text, (
        "doctor dispatch loses a custom EXPLORER_SRC_DIR across sudo's env reset"
    )
    assert '"$APP_DIR/scripts/doctor.sh"' in text, (
        "doctor dispatch has no fallback for a damaged source checkout"
    )


def test_install_sh_cleans_partial_clone():
    """Codex #28 h: an interrupted clone must not poison every retry."""
    text = (REPO_ROOT / "install.sh").read_text()
    assert "mktemp -d" in text, "install.sh no longer clones to a temp dir"
    assert "trap" in text and 'rm -rf "$tmp"' in text, (
        "install.sh no longer removes a partial clone on failure"
    )
    assert 'mv "$tmp/repo" "$src"' in text, (
        "install.sh does not move the finished clone into place"
    )
