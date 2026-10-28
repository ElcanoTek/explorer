// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package ops is Explorer's operator CLI: service control, staged updates,
// the interactive bootstrap, read-only diagnostics, encrypted config
// bundles, and the env/TLS helpers. cmd/explorer handles `serve`,
// `version` and `access` and hands every other verb to Run.
//
// The install trust boundary is the one the shell tooling enforced: root
// owns the source checkout, the binary and every file outside the service's
// own state, and root never executes or installs anything from a path the
// service account can write.
package ops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// Usage is the operator help text printed by `explorer help`.
const Usage = `explorer — email-archive service operator CLI

SERVICE
  explorer serve                    run the web service (what explorer.service runs)
  explorer start | stop | restart | status
  explorer logs [journalctl args...]
  explorer version                  print the source revision of this binary

UPDATES
  explorer update [--yes]           git pull + build + staged swap + health check
                                    (also EXPLORER_UPDATE_YES=1, or answer y on stdin;
                                    rolls back automatically when the new build is unhealthy)
  explorer rebuild                  rebuild + reinstall the current checkout
                                    (no fetch — use after a manual rollback)
  explorer doctor [--json] [--strict]
                                    read-only diagnostics: configuration, service,
                                    readiness, TLS, disk, packages (--check is accepted
                                    and means the same: doctor never changes anything)
  explorer bootstrap                re-run the interactive installer (safe to re-run)

  explorer provision [--client=N]   decrypt an encrypted config bundle and merge it
                                    into .env, then restart (--no-restart to skip;
                                    --non-interactive for scripts)

TLS (when Caddy was installed by bootstrap)
  explorer tls status               show hostname + certificate validity + Caddy state
  explorer tls reload               reload /etc/caddy/Caddyfile
  explorer tls restart              restart Caddy

CONFIG
  explorer env                      print /opt/explorer/.env (secrets redacted)
  explorer env edit                 edit /opt/explorer/.env

CENTRAL-AUTH ACCESS (EXPLORER_AUTH_MODE=central)
  explorer access grant EMAIL       allow a central account to use Explorer
  explorer access list [--all]      list allowed (or all known) emails
  explorer access revoke EMAIL      deny access and revoke Explorer sessions
  explorer access backup [PATH]     consistent copy of the access database

API TOKENS (for /mcp and /api/v1: Fleet and scripts)
  explorer token create --label NAME [--scope S]... [--json]
                                    mint a token (shown once); scopes email:search,
                                    email:read (both by default)
  explorer token list               show tokens (never their secrets)
  explorer token revoke ID          revoke a token by id

Exit codes: 0 ok · 1 failure (doctor: a check failed) · 2 usage error.
`

// applyVerb is the hidden verb the staged binary runs to perform the swap,
// so the new build's own install logic always does the install.
const applyVerb = "__apply-update"

// Run executes one operator verb and returns the process exit code.
func Run(argv []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	u := newUI(os.Stdout, os.Stderr)
	if len(argv) == 0 {
		fmt.Fprint(os.Stdout, Usage)
		return 0
	}
	verb, args := argv[0], argv[1:]
	r := execRunner{}
	p := PathsFromEnv()
	switch verb {
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, Usage)
		return 0
	case "start", "stop", "restart", "status":
		if code, done := elevate(verb, args); done {
			return code
		}
		return r.Interactive(ctx, Cmd{Name: "systemctl", Args: []string{verb, p.Service}})
	case "logs":
		if code, done := elevate(verb, args); done {
			return code
		}
		if len(args) > 0 {
			return r.Interactive(ctx, Cmd{Name: "journalctl", Args: append([]string{"-u", p.Service}, args...)})
		}
		return r.Interactive(ctx, Cmd{Name: "journalctl", Args: []string{"-fu", p.Service}})
	case "update", "rebuild":
		if code, done := elevate(verb, args); done {
			return code
		}
		return exitCode(u, runUpdate(ctx, u, r, p, verb == "rebuild", args, os.Stdin))
	case applyVerb:
		return exitCode(u, runApply(ctx, u, r, p))
	case "doctor":
		if code, done := elevate(verb, args); done {
			return code
		}
		return runDoctorCLI(ctx, u, r, p, args)
	case "provision":
		if code, done := elevate(verb, args); done {
			return code
		}
		return exitCode(u, runProvision(ctx, u, r, p, args))
	case "bootstrap":
		if code, done := elevate(verb, args); done {
			return code
		}
		return exitCode(u, runBootstrap(ctx, u, r, p, args))
	case "env":
		return runEnv(ctx, u, r, p, args)
	case "tls":
		return runTLS(ctx, u, r, p, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", verb)
		fmt.Fprint(os.Stderr, Usage)
		return 2
	}
}

// usageError marks a bad command line (exit 2).
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func exitCode(u *ui, err error) int {
	if err == nil {
		return 0
	}
	var ue usageError
	if errors.As(err, &ue) {
		fmt.Fprintln(u.errw, "error: "+ue.msg)
		return 2
	}
	var ec exitCodeError
	if errors.As(err, &ec) {
		return ec.code
	}
	u.fail(err.Error())
	return 1
}

// exitCodeError carries a child's exit code through unchanged (no extra message).
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// passthroughPrefixes are the environment variables an elevated re-exec
// keeps: sudo resets the environment, and a custom path or a scripted answer
// must survive the hop.
var passthroughPrefixes = []string{
	"EXPLORER_", "AUTH_", "AWS_", "EMAIL_S3_", "ELCANO_",
}

var passthroughNames = map[string]bool{
	"SRC_DIR": true, "APP_DIR": true, "APP_USER": true, "DRY_RUN": true,
	"TERM": true, "EDITOR": true, "VISUAL": true,
}

// elevate re-executes the current command through sudo when not root.
// done is false when the caller is already root and should continue.
func elevate(verb string, args []string) (code int, done bool) {
	if os.Geteuid() == 0 {
		return 0, false
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot locate the explorer binary:", err)
		return 1, true
	}
	sudo, err := lookPath("sudo")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: `explorer %s` needs root; run it as root (sudo is not installed)\n", verb)
		return 1, true
	}
	argv := []string{"sudo", "env"}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if passthroughNames[name] || hasAnyPrefix(name, passthroughPrefixes) {
			argv = append(argv, kv)
		}
	}
	argv = append(argv, self, verb)
	argv = append(argv, args...)

	if err := syscall.Exec(sudo, argv, os.Environ()); err != nil { //nolint:gosec // G204: fixed system commands with installer-built arguments.
		fmt.Fprintln(os.Stderr, "error: sudo:", err)
		return 1, true
	}
	return 0, true
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// ui prints the installer's status lines in the shell tooling's style.
type ui struct {
	out, errw io.Writer
	color     bool
}

func newUI(out, errw io.Writer) *ui {
	color := false
	if f, ok := out.(*os.File); ok {
		color = term.IsTerminal(int(f.Fd())) && os.Getenv("TERM") != "dumb"
	}
	return &ui{out: out, errw: errw, color: color}
}

func (u *ui) paint(code, s string) string {
	if !u.color {
		return s
	}
	return code + s + "\033[0m"
}

func (u *ui) sayf(format string, a ...any) { fmt.Fprintf(u.out, format+"\n", a...) }
func (u *ui) infof(format string, a ...any) {
	fmt.Fprintln(u.out, u.paint("\033[2m", "» "+fmt.Sprintf(format, a...)))
}

func (u *ui) stepf(format string, a ...any) {
	fmt.Fprintln(u.out, "\n"+u.paint("\033[1m", "▸ "+fmt.Sprintf(format, a...)))
}

func (u *ui) okf(format string, a ...any) {
	fmt.Fprintln(u.out, u.paint("\033[0;32m", "✓ "+fmt.Sprintf(format, a...)))
}

func (u *ui) warnf(format string, a ...any) {
	fmt.Fprintln(u.errw, u.paint("\033[0;33m", "! "+fmt.Sprintf(format, a...)))
}
func (u *ui) fail(msg string) { fmt.Fprintln(u.errw, u.paint("\033[0;31m", "✗ "+msg)) }

func (u *ui) bold(s string) string { return u.paint("\033[1m", s) }
func (u *ui) dim(s string) string  { return u.paint("\033[2m", s) }
