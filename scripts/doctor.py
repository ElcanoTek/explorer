# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.
"""Read-only, bounded deployment diagnostics; never import the Explorer app."""

import argparse
import datetime
import json
import os
import platform
import pwd
import shutil
import subprocess
import sys
from pathlib import Path

if sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb":
    _C = {
        "ok": "\033[0;32m",
        "warn": "\033[0;33m",
        "fail": "\033[0;31m",
        "reset": "\033[0m",
    }
else:
    _C = {"ok": "", "warn": "", "fail": "", "reset": ""}


def run(*args, timeout=15, cwd=None):
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
        return result.returncode, result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def inspect_env(app):
    # Parse with the application's dotenv implementation, never source secrets
    # as shell commands. .env.shared is read first and .env overrides it,
    # matching app/config.py. Return key names and booleans, never values.
    return run(
        str(app / ".venv/bin/python"),
        "-c",
        """
import base64, json, sys
from dotenv import dotenv_values
v = {}
for f in ('.env.shared', '.env'):
    v.update(dotenv_values(f, interpolate=False) or {})
mode = v.get('EXPLORER_AUTH_MODE', 'elcano')
required = ['AUTH_SIGNING_PUBKEY']
missing = [k for k in required if not v.get(k)]
central_missing = []
if mode == 'central':
    central_missing = [k for k in ('AUTH_ISSUER_URL', 'EXPLORER_PUBLIC_URL',
                                   'AUTH_CLIENT_ID', 'AUTH_CLIENT_SECRET')
                       if not v.get(k)]
try:
    key_ok = len(base64.b64decode(v.get('AUTH_SIGNING_PUBKEY', ''), validate=True)) == 32
except (ValueError, TypeError):
    key_ok = False
print(json.dumps({'missing': missing, 'central_missing': central_missing,
                  'key_ok': key_ok, 'mode_ok': mode in ('elcano', 'central'),
                  'session_ok': len(v.get('EXPLORER_SESSION_SECRET') or '') >= 32,
                  's3_bucket': bool(v.get('EMAIL_S3_BUCKET')),
                  'aws_key': bool(v.get('AWS_ACCESS_KEY_ID')),
                  'aws_secret': bool(v.get('AWS_SECRET_ACCESS_KEY'))}))
""",
        cwd=app,
    )


def caddy_site_host():
    """Hostname of the installed Explorer Caddy site block, if there is one."""
    for snippet in (
        "/etc/caddy/conf.d/explorer.caddy",
        "/etc/caddy/Caddyfile.d/explorer.caddyfile",
    ):
        path = Path(snippet)
        if not path.is_file():
            continue
        try:
            for line in path.read_text().splitlines():
                stripped = line.strip()
                if (
                    stripped
                    and not stripped.startswith(("#", "import", "}"))
                    and stripped.endswith("{")
                ):
                    return snippet, stripped[:-1].strip().rstrip("{").strip()
        except OSError:
            continue
    return None, None


def diagnose(app, src, user):
    checks = []

    def add(name, good, detail, remedy="", warning=False):
        # remedy is only read when good is False; passing-detail-only call
        # sites (e.g. an OK line with no failure advice) omit it.
        checks.append(
            {
                "name": name,
                "status": "ok" if good else "warn" if warning else "fail",
                "detail": detail if good else remedy,
            }
        )

    for name in ("git", "curl", "rsync", "uv", "systemctl"):
        add(name, shutil.which(name), "installed", "Run bootstrap to install " + name)
    python = app / ".venv/bin/python"
    code, version = run(str(python), "--version")
    good = False
    if code == 0 and version.startswith("Python "):
        try:
            major, minor = (int(p) for p in version.split()[1].split(".")[:2])
            good = (major, minor) >= (3, 11)
        except (ValueError, IndexError):
            good = False
    add(
        "python",
        good,
        version,
        "Need Python >= 3.11; run explorer rebuild to rebuild the venv",
    )
    if code == 0:
        code, _ = run("uv", "pip", "check", "--python", str(python), timeout=60)
        add(
            "dependencies",
            code == 0,
            "locked dependencies consistent",
            "Run explorer rebuild; Python dependencies are broken",
        )
    else:
        add("dependencies", False, "", "venv missing; run explorer rebuild")
    env_file = app / ".env"
    try:
        stat = env_file.stat()
        mode = stat.st_mode & 0o777
        owner = pwd.getpwuid(stat.st_uid).pw_name
        add(
            "env-permissions",
            mode == 0o600 and owner == user,
            f"{owner}-owned 0600",
            f"chown {user}:{user} {env_file} && chmod 600 {env_file} "
            "(it holds the session secret, the auth client secret and any AWS keys)",
        )
        code, data = inspect_env(app)
        env = json.loads(data) if code == 0 else {}
        missing = env.get("missing", []) + env.get("central_missing", [])
        good = (
            bool(env)
            and not missing
            and env["key_ok"]
            and env["mode_ok"]
            and env["session_ok"]
        )
        add(
            "configuration",
            good,
            "auth signing key and session secret configured",
            "explorer env edit: set AUTH_SIGNING_PUBKEY (run 'auth pubkey' on the auth host)"
            " and EXPLORER_SESSION_SECRET (openssl rand -hex 32)"
            + (f"; missing: {', '.join(missing)}" if missing else "")
            + (
                ""
                if env.get("mode_ok", True)
                else "; EXPLORER_AUTH_MODE must be elcano or central"
            ),
        )
        if env:
            if env["mode_ok"] and not env["session_ok"]:
                add(
                    "session-secret",
                    False,
                    "",
                    "EXPLORER_SESSION_SECRET unset or short (<32 chars) — generate one: "
                    "openssl rand -hex 32, then: explorer env edit && explorer restart",
                )
            add(
                "s3-archive",
                env["s3_bucket"],
                "EMAIL_S3_BUCKET set",
                "EMAIL_S3_BUCKET unset — every S3-backed feature errors; set it with: "
                "explorer env edit && explorer restart",
                warning=True,
            )
            if env["aws_key"] != env["aws_secret"]:
                add(
                    "aws-credentials",
                    False,
                    "",
                    "Only one of AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY is set — "
                    "fix both or clear both (the ambient credential chain is used when blank)",
                    warning=True,
                )
            elif not env["aws_key"]:
                add(
                    "aws-credentials",
                    False,
                    "",
                    "No static AWS keys — relying on the ambient credential chain "
                    "(instance role, ~/.aws, AWS_PROFILE); ignore if that is intended",
                    warning=True,
                )
            else:
                add("aws-credentials", True, "static AWS credentials configured")
    except (OSError, KeyError, ValueError):
        add(
            "configuration",
            False,
            "",
            f"Cannot read {env_file}; run doctor with sudo or restore .env",
        )
    code, _ = run("systemctl", "is-active", "--quiet", "explorer.service")
    add(
        "service",
        code == 0,
        "explorer.service active",
        "Inspect explorer logs; then explorer restart",
    )
    code, status = run(
        "curl",
        "-sS",
        "--connect-timeout",
        "2",
        "--max-time",
        "5",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "http://127.0.0.1:8080/health",
    )
    add(
        "readiness",
        code == 0 and status == "200",
        "/health returns 200",
        "Readiness failed; inspect explorer logs",
    )
    code, pid = run(
        "systemctl", "show", "--property=MainPID", "--value", "explorer.service"
    )
    if code == 0 and pid.isdigit() and int(pid):
        try:
            same = os.path.samefile(f"/proc/{pid}/exe", python)
        except OSError:
            same = False
        add(
            "running-python",
            same,
            "running interpreter matches installed interpreter",
            "Run explorer restart; interpreter is stale or inaccessible",
        )
    if shutil.which("systemctl"):
        code, _ = run("systemctl", "cat", "explorer-attachment-cleanup.timer")
        if code != 0:
            add(
                "attachment-cleanup",
                False,
                "",
                "explorer-attachment-cleanup.timer not installed — rerun bootstrap.sh",
                warning=True,
            )
        else:
            code, _ = run(
                "systemctl",
                "is-enabled",
                "--quiet",
                "explorer-attachment-cleanup.timer",
            )
            enabled = code == 0
            code, _ = run(
                "systemctl", "is-active", "--quiet", "explorer-attachment-cleanup.timer"
            )
            active = code == 0
            if not enabled or not active:
                add(
                    "attachment-cleanup",
                    False,
                    "",
                    "attachment cleanup timer not firing — transient downloads are never swept: "
                    "systemctl enable --now explorer-attachment-cleanup.timer",
                    warning=True,
                )
            else:
                code, result = run(
                    "systemctl",
                    "show",
                    "--property=Result",
                    "--value",
                    "explorer-attachment-cleanup.service",
                )
                if code == 0 and result and result != "success":
                    add(
                        "attachment-cleanup",
                        False,
                        "",
                        f"explorer-attachment-cleanup.service last run FAILED (Result={result}) — "
                        "journalctl -u explorer-attachment-cleanup -n 50",
                    )
                else:
                    add(
                        "attachment-cleanup",
                        True,
                        "timer enabled + active, no failed run recorded",
                    )
    snippet, host = caddy_site_host()
    if snippet and shutil.which("caddy"):
        code, _ = run("systemctl", "is-active", "--quiet", "caddy.service")
        add("caddy", code == 0, "caddy.service active", "Inspect journalctl -u caddy")
        code, _ = run(
            "caddy",
            "validate",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
        )
        add(
            "caddy-config",
            code == 0,
            "/etc/caddy/Caddyfile validates",
            "Caddy configuration invalid — run: caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile",
        )
        if host:
            # s_client expects EOF on stdin to close the connection after the
            # handshake; pipe its (PEM) stdout into x509 ourselves.
            expiry = None
            try:
                s_client = subprocess.run(
                    [
                        "openssl",
                        "s_client",
                        "-servername",
                        host,
                        "-connect",
                        f"{host}:443",
                    ],
                    input="",
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if s_client.returncode == 0:
                    x509 = subprocess.run(
                        ["openssl", "x509", "-noout", "-enddate"],
                        input=s_client.stdout,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if x509.returncode == 0 and x509.stdout.strip().startswith(
                        "notAfter="
                    ):
                        expiry = datetime.datetime.strptime(
                            x509.stdout.strip().split("=", 1)[1].strip(),
                            "%b %d %H:%M:%S %Y %Z",
                        ).date()
            except (OSError, subprocess.TimeoutExpired):
                expiry = None
            if expiry is None:
                add(
                    "tls-cert",
                    False,
                    "",
                    f"could not read the certificate for {host} — check DNS + firewall",
                    warning=True,
                )
            else:
                days = (expiry - datetime.date.today()).days
                add(
                    "tls-cert",
                    days > 30,
                    f"{host} cert expires {expiry.isoformat()} ({days} days)",
                    f"certificate for {host} expired or expires within 30 days ({expiry.isoformat()})",
                    warning=0 < days <= 30,
                )
    for unit in (
        "explorer.service",
        "explorer-attachment-cleanup.service",
        "explorer-attachment-cleanup.timer",
    ):
        installed = Path("/etc/systemd/system") / unit
        shipped = app / "deploy/systemd" / unit
        if not shipped.is_file() or not installed.is_file():
            add(
                "units",
                False,
                "",
                f"{unit} missing ({shipped} vs {installed}) — rerun bootstrap.sh",
            )
        else:
            same = run("cmp", "-s", str(shipped), str(installed))[0] == 0
            add(
                "units",
                same,
                f"{unit} matches deploy/",
                f"{unit} drifted from deploy/ — run explorer update",
            )
    cli = Path("/usr/local/bin/explorer")
    shipped_cli = app / "deploy/explorer-cli"
    if shipped_cli.is_file() and cli.is_file():
        same = run("cmp", "-s", str(shipped_cli), str(cli))[0] == 0
        add(
            "operator-cli",
            same,
            "/usr/local/bin/explorer matches deploy/",
            "operator CLI drifted from deploy/ — run explorer update",
        )
    try:
        free = shutil.disk_usage(app).free
        add(
            "disk",
            free >= 1 * 1024**3,
            f"{free / 1024**3:.1f} GiB available",
            "Less than 1 GiB free; inspect attachment temp space",
        )
    except OSError:
        add("disk", False, "", "Application directory is missing or inaccessible")
    try:
        release = platform.freedesktop_os_release()
        end = release.get("SUPPORT_END")
        if end:
            days = (datetime.date.fromisoformat(end) - datetime.date.today()).days
            add(
                "os-support",
                days >= 30,
                f"support ends {end}",
                f"OS support ends {end}; plan host upgrade",
                warning=True,
            )
        else:
            add(
                "os-support",
                False,
                "",
                "OS does not publish SUPPORT_END; verify vendor lifecycle",
                warning=True,
            )
    except (OSError, ValueError, AttributeError):
        add("os-support", False, "", "Cannot read OS lifecycle metadata", warning=True)
    if shutil.which("dnf"):
        code, _ = run("dnf", "--refresh", "check-update", timeout=90)
        # DNF uses 100 for available updates; anything else nonzero is an error.
        if code == 0:
            add("packages", True, "no pending dnf updates")
        elif code == 100:
            add(
                "packages",
                False,
                "",
                "dnf updates available — run: sudo dnf upgrade --refresh",
                warning=True,
            )
        else:
            add(
                "packages",
                False,
                "",
                "dnf check-update failed (network or repo issue)",
                warning=True,
            )
        try:
            os_release = platform.freedesktop_os_release()
        except (OSError, AttributeError):
            os_release = {}
        if (
            os_release.get("ID") == "fedora"
            and os_release.get("VERSION_ID", "").isdigit()
        ):
            code, out = run(
                "curl",
                "-fsS",
                "--connect-timeout",
                "5",
                "--max-time",
                "15",
                "https://fedoraproject.org/releases.json",
            )
            latest = None
            if code == 0:
                try:
                    latest = max(
                        int(r["version"])
                        for r in json.loads(out)
                        if str(r.get("version", "")).isascii()
                        and str(r.get("version", "")).isdigit()
                    )
                except (ValueError, KeyError, TypeError):
                    latest = None
            current = int(os_release["VERSION_ID"])
            if latest is None:
                add(
                    "fedora",
                    False,
                    "",
                    "could not read the Fedora release feed",
                    warning=True,
                )
            elif latest > current:
                add(
                    "fedora",
                    False,
                    "",
                    f"Fedora {current} vs latest stable {latest} — plan a distro upgrade",
                    warning=True,
                )
            else:
                add("fedora", True, f"Fedora {current} (latest stable: {latest})")
    else:
        add(
            "packages",
            False,
            "",
            "dnf not found; keep host packages current manually",
            warning=True,
        )
    # Reboot needed — fallback chain, first success wins: needs-restarting,
    # then dnf needs-restarting, then uname -r vs the newest installed kernel
    # from rpm. Every step is bounded (10s) so a hung dnf cannot hang doctor;
    # an exit code other than 0/1 means "this tier cannot say" and falls
    # through. None means unknown, which is reported as such — never guessed.
    reboot_needed = None
    if shutil.which("needs-restarting"):
        code, _ = run("needs-restarting", "-r", timeout=10)
        if code in (0, 1):
            reboot_needed = code == 1
    if reboot_needed is None and shutil.which("dnf"):
        code, _ = run("dnf", "needs-restarting", "-r", timeout=10)
        if code in (0, 1):
            reboot_needed = code == 1
    if reboot_needed is None and shutil.which("uname") and shutil.which("rpm"):
        code, running = run("uname", "-r", timeout=10)
        code2, installed = run("rpm", "-q", "kernel", "--last", timeout=10)
        if code == 0 and code2 == 0 and running and installed:
            # rpm -q kernel --last sorts newest first; the NEVRA's version
            # (everything after "kernel-") is exactly what uname -r prints.
            newest = installed.splitlines()[0].split()[0].removeprefix("kernel-")
            reboot_needed = running != newest
    if reboot_needed is True:
        add(
            "reboot",
            False,
            "",
            "kernel or core libraries updated — reboot the host when convenient",
            warning=True,
        )
    elif reboot_needed is False:
        add("reboot", True, "no reboot pending")
    else:
        add(
            "reboot",
            False,
            "",
            "could not determine reboot status — needs-restarting, dnf "
            "needs-restarting and rpm/uname all unavailable or failed",
            warning=True,
        )
    if src.joinpath(".git").exists():
        git = ("git", "-c", f"safe.directory={src}", "-C", str(src))
        code, dirty = run(*git, "status", "--porcelain")
        add(
            "checkout",
            code == 0 and not dirty,
            "clean",
            "Resolve local source changes before explorer update",
        )
        code, branch = run(*git, "rev-parse", "--abbrev-ref", "HEAD")
        if code == 0 and branch != "main":
            add(
                "branch",
                False,
                "",
                f"checkout is on '{branch}', not main — run explorer update or: "
                f"git -C {src} checkout main",
                warning=True,
            )
        else:
            # Compare only after a successful fetch: without it, a stale
            # remote-tracking ref reports a weeks-behind checkout as current.
            code, _ = run(*git, "fetch", "--quiet", "origin", "main", timeout=10)
            if code != 0:
                add(
                    "branch",
                    False,
                    "",
                    "could not reach origin — cannot compare with upstream; "
                    "check network or remote credentials",
                    warning=True,
                )
            else:
                code2, behind = run(*git, "rev-list", "--count", "HEAD..origin/main")
                if code2 == 0 and behind.isdigit() and int(behind) > 0:
                    add(
                        "branch",
                        False,
                        "",
                        f"checkout is {behind} commit(s) behind origin/main — run explorer update",
                        warning=True,
                    )
                else:
                    add("branch", True, "on main, up to date with origin")
    else:
        add(
            "checkout",
            False,
            "",
            f"no source checkout at {src} — explorer update will not work",
            warning=True,
        )
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable checks")
    parser.add_argument("--check", action="store_true", help="read-only (the default)")
    parser.add_argument("--strict", action="store_true", help="warnings also exit 1")
    args = parser.parse_args()
    checks = diagnose(
        Path(os.environ.get("APP_DIR", "/opt/explorer")),
        Path(os.environ.get("EXPLORER_SRC_DIR", "/opt/explorer-src")),
        os.environ.get("APP_USER", "explorer"),
    )
    failed = any(
        c["status"] == "fail" or (args.strict and c["status"] == "warn") for c in checks
    )
    if args.json:
        print(json.dumps({"ok": not failed, "checks": checks}, indent=2))
    else:
        for check in checks:
            label = check["status"].upper()
            print(
                f"{_C[check['status']]}{label:4}{_C['reset']} {check['name']}: {check['detail']}"
            )
        print("\nHost packages: sudo dnf upgrade --refresh. Doctor changes nothing.")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
