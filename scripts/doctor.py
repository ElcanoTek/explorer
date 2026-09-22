# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.
"""Read-only, bounded deployment diagnostics; never import the Explorer app."""

import argparse
import base64
import datetime
import fnmatch
import json
import os
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import urllib.parse
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


# ── dotenv parsing ──────────────────────────────────────────────────────────
# app/config.py loads .env.shared then .env via python-dotenv (interpolation
# on, .env overriding). Doctor mirrors that with an in-process parser: the
# venv's interpreter is service-writable and must never be executed by a
# root-run check, so the probe cannot borrow the app's own dotenv. This is
# the supported subset of python-dotenv semantics: comments, optional
# `export`, whitespace around =, single/double quoting with the common
# escapes, and ${VAR} / ${VAR:-default} interpolation resolved against the
# ambient environment, earlier files, and this file's own values (file
# values win, as python-dotenv's new_values do).

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*(.*))?$")
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
_ENV_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    '"': '"',
    "'": "'",
    "\\": "\\",
    "$": "$",
}


def _parse_dotenv(text, base):
    values = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE.match(raw)
        if not match:
            continue
        key, val = match.group(1), match.group(2)
        if val is None:
            values[key] = ""
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            inner = val[1:-1]
            values[key] = re.sub(
                r"\\(.)",
                lambda m: _ENV_ESCAPES.get(m.group(1), m.group(1)),
                inner,
            )
        elif len(val) >= 2 and val[0] == "'" and val[-1] == "'":
            values[key] = val[1:-1]
        else:
            # Unquoted: a comment starts only at whitespace-then-#.
            values[key] = re.sub(r"\s+#.*$", "", val).rstrip()

    # Resolve references in PARSE ORDER, exactly like python-dotenv: an
    # entry sees only earlier entries of this file plus the ambient base —
    # a forward reference to a later line stays empty (or takes the
    # default), never the later value.
    resolved = {}

    def repl(match):
        name, default = match.group(1), match.group(2)
        if name in resolved:
            return resolved[name]
        if name in base:
            return base[name]
        return default or ""

    for key, val in values.items():
        resolved[key] = _ENV_REF.sub(repl, val)
    return resolved


def load_dotenv_pair(app):
    """Merged .env.shared + .env view, mirroring app/config.py precedence.

    lstat, never stat: a secrets file must not be probed through a symlink.
    Missing files contribute nothing; a damaged file contributes what
    parsed before the fault. Values stay inside this process — only key
    names, lengths and booleans ever reach the report.
    """
    merged = {}
    for name in (".env.shared", ".env"):
        path = app / name
        try:
            st = path.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        try:
            text = path.read_text()
        except OSError:
            continue
        merged.update(_parse_dotenv(text, {**os.environ, **merged}))
    return merged


# ── Caddy site resolution ───────────────────────────────────────────────────
# Port of scripts/lib/caddy-site.sh: follow the import globs the installed
# /etc/caddy/Caddyfile actually loads (sites-enabled/*.caddy, Caddyfile.d,
# conf.d, ...) instead of guessing conventional filenames — a supported
# install under any imported wildcard must still be found.

_CADDY_MARKER = "# Caddy site block for Explorer, imported by /etc/caddy/Caddyfile via"
_IMPORT_LINE = re.compile(r"^\s*import\s+(.+?)\s*$")


def _caddy_imports(caddyfile):
    patterns = []
    try:
        lines = Path(caddyfile).read_text().splitlines()
    except OSError:
        return patterns
    for line in lines:
        match = _IMPORT_LINE.match(line)
        if not match:
            continue
        rest = match.group(1).strip()
        if not rest:
            continue
        if rest[0] in "\"'":
            quote = rest[0]
            end = rest.find(quote, 1)
            if end < 0:
                continue
            pattern = rest[1:end]
            tail = rest[end + 1 :]
            if tail.strip() and not tail.strip().startswith("#"):
                continue
        else:
            pattern = rest.split()[0]
        if pattern:
            patterns.append(pattern)
    return patterns


def _caddy_candidate(caddyfile, pattern):
    directory, _, glob = pattern.rpartition("/")
    if not glob:
        return None
    if any(c in directory for c in "*?["):
        return None
    if not any(c in glob for c in "*?["):
        return None
    if not directory.startswith("/"):
        directory = os.path.join(os.path.dirname(caddyfile), directory)
    directory = os.path.realpath(directory)
    name = glob.replace("*", "explorer").replace("?", "x")
    if glob == "*":
        name = "explorer.caddy"
    if not fnmatch.fnmatchcase(name, glob):
        return None
    return os.path.join(directory, name)


def _caddy_is_ours(path):
    try:
        st = Path(path).lstat()
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    try:
        with open(path, encoding="utf-8") as handle:
            first = handle.readline().rstrip("\n")
    except OSError:
        return False
    return first == _CADDY_MARKER


def caddy_site_host(caddyfile=None):
    """Resolve the installed Explorer Caddy site exactly like caddy-site.sh.

    Returns (snippet_path, hostname) or (None, None) when no Explorer block
    is installed under any imported path.
    """
    caddyfile = caddyfile or os.environ.get(
        "EXPLORER_CADDYFILE", "/etc/caddy/Caddyfile"
    )
    candidates = []
    for pattern in _caddy_imports(caddyfile):
        candidate = _caddy_candidate(caddyfile, pattern)
        if candidate:
            candidates.append(candidate)
    target = None
    for candidate in candidates:
        if _caddy_is_ours(candidate):
            target = candidate
            break
    if target is None:
        for candidate in candidates:
            if not os.path.lexists(candidate):
                target = candidate
                break
    if target is None:
        fallback = os.path.join(os.path.dirname(caddyfile), "conf.d/explorer.caddy")
        if not os.path.lexists(fallback) or _caddy_is_ours(fallback):
            target = fallback
    if target is None or not _caddy_is_ours(target):
        return None, None
    try:
        for line in Path(target).read_text().splitlines():
            stripped = line.strip()
            if (
                stripped
                and not stripped.startswith(("#", "import", "}"))
                and stripped.endswith("{")
            ):
                return target, stripped[:-1].strip().rstrip("{").strip()
    except OSError:
        pass
    return None, None


def _requirements_pins(app):
    """name==version pins from the app's requirements.txt (normalized names).

    None when the file cannot be read. Version pins are not secret, but
    only names are ever reported as diverged.
    """
    try:
        text = (app / "requirements.txt").read_text()
    except OSError:
        return None
    pins = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==(\S+)(?:\s+#.*)?$",
            line,
        )
        if match:
            pins[_norm_name(match.group(1))] = match.group(2)
    return pins


def _norm_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _installed_package_versions(app):
    """name→version of everything installed in the venv, from dist-info
    METADATA files. Reading metadata never executes venv code — essential
    because .venv is service-writable and doctor runs as root."""
    versions = {}
    for site_packages in sorted((app / ".venv").glob("lib/python*/site-packages")):
        for metadata in site_packages.glob("*.dist-info/METADATA"):
            name = version = None
            try:
                for line in metadata.read_text(errors="replace").splitlines():
                    if line.startswith("Name: "):
                        name = line[len("Name: ") :].strip()
                    elif line.startswith("Version: "):
                        version = line[len("Version: ") :].strip()
                    if name and version:
                        break
            except OSError:
                continue
            if name:
                versions[_norm_name(name)] = version
    return versions


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
    # The venv interpreter is service-writable, so a root-run doctor must
    # never execute it (scripts/lib/layout.sh keeps only the venv writable).
    # pyvenv.cfg carries the version; uv pip check below reads metadata
    # without executing anything from the venv.
    if not python.exists():
        add("python", False, "", "venv missing — run explorer rebuild")
        add("dependencies", False, "", "venv missing — run explorer rebuild")
    else:
        # Parse pyvenv.cfg as key=value lines. uv writes version_info where
        # stdlib venv writes version — accept either, exact key match, and
        # ignore everything else in the file.
        version_text = None
        try:
            for line in (app / ".venv/pyvenv.cfg").read_text().splitlines():
                key, sep, value = line.partition("=")
                if sep and key.strip() in ("version", "version_info"):
                    version_text = value.strip()
                    break
        except (OSError, UnicodeError):
            # A corrupted (non-UTF-8) service-owned cfg is a damaged file,
            # not a doctor crash: the WARN below covers it.
            version_text = None
        version = None
        if version_text:
            try:
                version = tuple(int(p) for p in version_text.split(".")[:2])
            except ValueError:
                version = None
        if version is None:
            # Unreadable version is not a broken venv: the interpreter
            # exists, only the metadata could not be parsed. Warn, never
            # fail, and do not gate the dependencies check on it.
            add(
                "python",
                False,
                "",
                "could not read venv Python version",
                warning=True,
            )
        elif version >= (3, 11):
            add("python", True, f"venv Python {version[0]}.{version[1]}")
        else:
            add(
                "python",
                False,
                "",
                "Need Python >= 3.11 in the venv; run explorer rebuild",
            )
        pins = _requirements_pins(app)
        installed = _installed_package_versions(app)
        if pins is None:
            add(
                "dependencies",
                False,
                "",
                "requirements.txt is unreadable — run explorer rebuild",
            )
        elif not installed:
            add(
                "dependencies",
                False,
                "",
                "venv site-packages missing or empty — run explorer rebuild",
            )
        else:
            diverged = sorted(
                name for name, want in pins.items() if installed.get(name) != want
            )
            sample = ", ".join(diverged[:8]) + (" …" if len(diverged) > 8 else "")
            add(
                "dependencies",
                not diverged,
                "installed packages match requirements.txt pins",
                f"installed packages diverge from requirements.txt pins: {sample} "
                "— run explorer rebuild",
            )
    # Permissions on every dotenv the app loads (lstat: never through a
    # symlink — layout.sh requires a regular file, one link, owner-only).
    texts = {}
    for name, check_name in (
        (".env", "env-permissions"),
        (".env.shared", "env-shared-permissions"),
    ):
        env_path = app / name
        try:
            st = env_path.lstat()
        except OSError:
            if name == ".env":
                add(
                    check_name,
                    False,
                    "",
                    f"{env_path} missing — run bootstrap.sh",
                )
            continue
        is_link = stat.S_ISLNK(st.st_mode)
        is_reg = stat.S_ISREG(st.st_mode)
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)
        mode = stat.S_IMODE(st.st_mode)
        # layout.sh requires exactly this: a single-link regular file,
        # owner-only. A hard link (st_nlink > 1) or a fifo/socket/device
        # with friendly ownership must not pass.
        good = (
            is_reg
            and not is_link
            and st.st_nlink == 1
            and mode == 0o600
            and owner == user
        )
        problems = []
        if is_link:
            problems.append(f"{env_path} is a symlink — replace it with a regular file")
        if not is_reg:
            problems.append(f"{env_path} is not a regular file")
        if st.st_nlink > 1:
            problems.append(f"{env_path} has {st.st_nlink} hard links — want exactly 1")
        if mode != 0o600:
            problems.append(f"chmod 600 {env_path}")
        if owner != user:
            problems.append(f"chown {user}:{user} {env_path}")
        problems.append("(layout.sh requires a single-link regular file, owner-only)")
        add(
            check_name,
            good,
            f"{owner}-owned 0600, one link",
            "; ".join(problems),
        )
        # Read whatever parsed regardless of the verdict above: a
        # permissions fault must not hide a configuration fault (and root
        # can read the file anyway). Symlinks and non-regular files are
        # never opened (a fifo would block).
        if is_reg and not is_link:
            try:
                texts[name] = env_path.read_text()
            except OSError:
                pass
    merged = {}
    for name in (".env.shared", ".env"):
        if name in texts:
            merged.update(_parse_dotenv(texts[name], {**os.environ, **merged}))
    dotenv_ok = ".env" in texts
    mode = (merged.get("EXPLORER_AUTH_MODE") or "elcano").strip()
    missing = [k for k in ("AUTH_SIGNING_PUBKEY",) if not merged.get(k)]
    if mode == "central":
        missing += [
            k
            for k in (
                "AUTH_ISSUER_URL",
                "EXPLORER_PUBLIC_URL",
                "AUTH_CLIENT_ID",
                "AUTH_CLIENT_SECRET",
            )
            if not merged.get(k)
        ]
    try:
        key_ok = (
            len(base64.b64decode(merged.get("AUTH_SIGNING_PUBKEY", ""), validate=True))
            == 32
        )
    except (ValueError, TypeError):
        key_ok = False
    mode_ok = mode in ("elcano", "central")
    # Mirror CentralAuthClient's value validation (app/central_auth.py): a
    # restart would refuse to start on these, so doctor must not call the
    # box healthy while the old process keeps running. Lengths and rule
    # names only — never values.
    central_problems = []
    if mode == "central":

        def origin_ok(raw):
            try:
                parsed = urllib.parse.urlsplit(raw.strip())
            except ValueError:
                # Malformed URLs ('https://[') raise instead of parsing —
                # that is an invalid origin, not a doctor crash.
                return False
            return (
                parsed.scheme == "https"
                and bool(parsed.netloc)
                and not parsed.username
                and not parsed.password
                and not parsed.query
                and not parsed.fragment
                and parsed.path in ("", "/")
            )

        for key in ("AUTH_ISSUER_URL", "EXPLORER_PUBLIC_URL"):
            if merged.get(key) and not origin_ok(merged[key]):
                central_problems.append(
                    f"{key} must be an https origin without a path, query "
                    "or embedded credentials"
                )
        client_id = (merged.get("AUTH_CLIENT_ID") or "").strip()
        if client_id and (":" in client_id or len(client_id) > 128):
            central_problems.append(
                "AUTH_CLIENT_ID must be 1-128 characters without ':'"
            )
        secret = merged.get("AUTH_CLIENT_SECRET") or ""
        if secret:
            if len(secret.encode("utf-8")) < 32:
                central_problems.append("AUTH_CLIENT_SECRET is shorter than 32 bytes")
            elif len(secret) > 256 or ":" in secret:
                central_problems.append(
                    "AUTH_CLIENT_SECRET is longer than 256 characters or contains ':'"
                )
        # Mirror from_env: float(AUTH_HTTP_TIMEOUT_SECONDS) with the
        # constructor's 0 < timeout <= 60. Absent means the default and is
        # fine; anything a restart would choke on is named here.
        raw_timeout = merged.get("AUTH_HTTP_TIMEOUT_SECONDS")
        if raw_timeout is not None:
            try:
                timeout_value = float(str(raw_timeout).strip())
            except ValueError:
                central_problems.append("AUTH_HTTP_TIMEOUT_SECONDS must be a number")
            else:
                if timeout_value <= 0 or timeout_value > 60:
                    central_problems.append(
                        "AUTH_HTTP_TIMEOUT_SECONDS must be between 0 and 60"
                    )
    # Only the failures that are THIS check's to name: absent keys, a key
    # that is present but malformed, a bad auth mode, invalid central-mode
    # values. The session secret length belongs to the dedicated
    # session-secret check below — naming it here too used to fail the box
    # twice for one fault.
    good = dotenv_ok and not missing and key_ok and mode_ok and not central_problems
    problems = []
    if not dotenv_ok:
        problems.append("could not parse .env; run doctor with sudo or restore .env")
    else:
        if missing:
            problems.append("missing: " + ", ".join(missing))
        if not key_ok and "AUTH_SIGNING_PUBKEY" not in missing:
            problems.append(
                "AUTH_SIGNING_PUBKEY is set but is not a 32-byte base64 Ed25519 key"
            )
        if not mode_ok:
            problems.append(
                f"EXPLORER_AUTH_MODE must be 'elcano' or 'central' (got {mode!r})"
            )
        problems.extend(central_problems)
    add(
        "configuration",
        good,
        "auth signing key and auth mode configured",
        "; ".join(problems),
    )
    if dotenv_ok:
        if len(merged.get("EXPLORER_SESSION_SECRET") or "") < 32:
            add(
                "session-secret",
                False,
                "",
                "EXPLORER_SESSION_SECRET is shorter than 32 bytes — generate a "
                "longer one: openssl rand -hex 32, then: explorer env edit && explorer restart",
            )
        else:
            add("session-secret", True, "session secret >= 32 chars")
        add(
            "s3-archive",
            bool(merged.get("EMAIL_S3_BUCKET")),
            "EMAIL_S3_BUCKET set",
            "EMAIL_S3_BUCKET unset — every S3-backed feature errors; set it with: "
            "explorer env edit && explorer restart",
            warning=True,
        )
        aws_key, aws_secret = (
            bool(merged.get("AWS_ACCESS_KEY_ID")),
            bool(merged.get("AWS_SECRET_ACCESS_KEY")),
        )
        if aws_key != aws_secret:
            add(
                "aws-credentials",
                False,
                "",
                "Only one of AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY is set — "
                "fix both or clear both (the ambient credential chain is used when blank)",
                warning=True,
            )
        elif not aws_key:
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
    code, _ = run("systemctl", "is-active", "--quiet", "explorer.service")
    service_active = code == 0
    add(
        "service",
        service_active,
        "explorer.service active",
        "Inspect explorer logs; then explorer restart",
    )
    # Enablement is queried independently of activity: an inactive AND
    # disabled unit has two faults, and 'restart' alone would leave the
    # second one (no start after reboot) in place.
    code, _ = run("systemctl", "is-enabled", "--quiet", "explorer.service")
    if code == 0:
        add("service-enabled", True, "explorer.service enabled")
    elif service_active:
        add(
            "service-enabled",
            False,
            "",
            "explorer.service is active but DISABLED — it will not start on "
            "boot: systemctl enable explorer.service",
            warning=True,
        )
    else:
        add(
            "service-enabled",
            False,
            "",
            "explorer.service is DISABLED and inactive — it will not start "
            "on boot: systemctl enable --now explorer.service",
            warning=True,
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
    if snippet:
        if not shutil.which("caddy"):
            # A configured site block with no binary is an outage in
            # waiting, not something to skip silently.
            add(
                "caddy",
                False,
                "",
                f"Explorer Caddy site block is installed at {snippet} but the "
                "caddy binary is missing — dnf install caddy, then rerun bootstrap",
            )
        else:
            code, _ = run("systemctl", "is-active", "--quiet", "caddy.service")
            add(
                "caddy",
                code == 0,
                "caddy.service active",
                "Inspect journalctl -u caddy",
            )
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
                # s_client expects EOF on stdin to close the connection
                # after the handshake. -verify_hostname + -verify_return_error
                # make a wrong-host or unverifiable certificate fail the
                # command instead of merely printing the served leaf.
                expiry = None
                try:
                    s_client = subprocess.run(
                        [
                            "openssl",
                            "s_client",
                            "-servername",
                            host,
                            "-verify_hostname",
                            host,
                            "-verify_return_error",
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
                        f"could not verify the certificate for {host} — TLS "
                        "verification failed or the host is unreachable; check "
                        "DNS, firewall and the served certificate",
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
    if not shipped_cli.is_file() or not cli.is_file():
        # Missing either side is drift: the CLI is how operators restart,
        # update and grant access, so its absence is a fault, not a skip.
        add(
            "operator-cli",
            False,
            "",
            f"operator CLI missing ({cli} or {shipped_cli}) — rerun bootstrap.sh "
            "or explorer update",
        )
    else:
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
    # Reboot needed — always walk the WHOLE fallback chain: every installed
    # tier gets its say (each bounded at 10s so a hung dnf cannot hang
    # doctor). A single "yes" wins over any number of "no" (tiers can
    # disagree when one is stale), unanimity of "no" passes, and only when
    # NO tier could answer is the verdict unknown. Exit codes other than
    # 0/1 — including run()'s 127 for a timeout or execution error — mean
    # "this tier cannot say": never treated as "no reboot pending".
    answers = []
    if shutil.which("needs-restarting"):
        code, _ = run("needs-restarting", "-r", timeout=10)
        if code in (0, 1):
            answers.append(code == 1)
    if shutil.which("dnf"):
        code, _ = run("dnf", "needs-restarting", "-r", timeout=10)
        if code in (0, 1):
            answers.append(code == 1)
    if shutil.which("uname") and shutil.which("rpm"):
        code, running = run("uname", "-r", timeout=10)
        code2, installed = run("rpm", "-q", "kernel", "--last", timeout=10)
        if code == 0 and code2 == 0 and running and installed:
            # rpm -q kernel --last sorts newest first; the NEVRA's version
            # (everything after "kernel-") is exactly what uname -r prints.
            newest = installed.splitlines()[0].split()[0].removeprefix("kernel-")
            answers.append(running != newest)
    if any(answers):
        add(
            "reboot",
            False,
            "",
            "kernel or core libraries updated — reboot the host when convenient",
            warning=True,
        )
    elif answers:
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
            # Compare against the live remote. A fetch is forbidden here:
            # it writes FETCH_HEAD and remote refs, and a read-only check
            # must never mutate the checkout it diagnoses. ls-remote reads
            # only. Direction comes from ancestry between HEAD and the
            # local origin/main (both objects exist locally): ahead must
            # never be labeled behind — 'explorer update' on an ahead
            # checkout would ff-fail or clobber local work, so ahead and
            # divergence get neutral remedies instead.
            code, head = run(*git, "rev-parse", "HEAD")
            code2, remote = run(*git, "ls-remote", "origin", "main", timeout=10)
            remote_sha = remote.split()[0] if code2 == 0 and remote else ""
            if code != 0 or not remote_sha:
                add(
                    "branch",
                    False,
                    "",
                    "could not reach origin — cannot compare with upstream; "
                    "check network or remote credentials",
                    warning=True,
                )
            elif head == remote_sha:
                add("branch", True, "on main, up to date with origin")
            else:
                code3, local_ref = run(*git, "rev-parse", "origin/main")
                direction = None
                if code3 == 0 and local_ref:
                    if local_ref == head:
                        # HEAD == the local tracking ref but the live remote
                        # has moved on: strictly behind, no count available.
                        direction = "behind"
                    else:
                        code4, _ = run(
                            *git, "merge-base", "--is-ancestor", "HEAD", "origin/main"
                        )
                        code5, _ = run(
                            *git, "merge-base", "--is-ancestor", "origin/main", "HEAD"
                        )
                        if code4 == 0 and code5 != 0:
                            direction = "behind"
                        elif code5 == 0 and code4 != 0:
                            direction = "ahead"
                        elif code4 != 0 and code5 != 0:
                            direction = "diverged"
                if direction == "behind":
                    detail = "checkout is behind origin/main — run explorer update"
                    if local_ref == remote_sha:
                        _, behind = run(
                            *git, "rev-list", "--count", "HEAD..origin/main"
                        )
                        if behind.isdigit() and int(behind) > 0:
                            detail = (
                                f"checkout is {behind} commit(s) behind "
                                "origin/main — run explorer update"
                            )
                    add("branch", False, "", detail, warning=True)
                elif direction == "ahead":
                    _, ahead = run(*git, "rev-list", "--count", "origin/main..HEAD")
                    count = f"{ahead} " if ahead.isdigit() and int(ahead) > 0 else ""
                    add(
                        "branch",
                        False,
                        "",
                        f"checkout has {count}local commit(s) not on "
                        "origin/main — investigate before update",
                        warning=True,
                    )
                elif direction == "diverged":
                    add(
                        "branch",
                        False,
                        "",
                        "checkout and origin/main have diverged — "
                        "investigate before update",
                        warning=True,
                    )
                else:
                    add(
                        "branch",
                        False,
                        "",
                        "checkout differs from origin/main and local "
                        "ancestry is undeterminable — investigate before update",
                        warning=True,
                    )
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
