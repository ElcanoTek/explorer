// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ElcanoTek/explorer/internal/dotenv"
)

// envManagedKeys are the keys bootstrap's template sets. On a re-run only
// these are updated, in place; every other byte of .env is kept.
var envManagedKeys = []string{
	"EXPLORER_SESSION_SECRET", "EXPLORER_AUTH_MODE", "EXPLORER_ACCESS_DB",
	"EXPLORER_AUTH_COOKIE_SECURE", "EXPLORER_SESSION_IDLE_SECONDS",
	"EXPLORER_SESSION_ABSOLUTE_SECONDS", "AUTH_SIGNING_PUBKEY", "AUTH_ISSUER_URL",
	"EXPLORER_PUBLIC_URL", "AUTH_CLIENT_ID", "AUTH_CLIENT_SECRET", "AWS_REGION", "EMAIL_S3_BUCKET",
}

// bootstrapAnswers is everything the installer asks before changing the
// box, so the rest of the run has no surprise prompts.
type bootstrapAnswers struct {
	values      map[string]string // managed .env keys (plus AWS keys when entered)
	hostname    string
	setupCaddy  bool
	letsEncrypt bool
	leEmail     string
}

func genSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// existingEnv reads the current .env (refusing links) and .env.shared as
// data and returns the value the service would use for each managed key.
func existingEnv(p Paths) (text string, present bool, shared map[string]string, current map[string]string, err error) {
	text, present, err = readEnvForRewrite(p.EnvFile())
	if err != nil {
		return "", false, nil, nil, err
	}
	shared = map[string]string{}
	if t, ok, serr := dotenv.ReadRegular(p.SharedEnvFile()); serr == nil && ok {
		shared = dotenv.SharedValues(t)
	}
	keys := append(append([]string{}, envManagedKeys...), "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
	current = map[string]string{}
	if present {
		current = dotenv.EffectiveValues(text, shared, keys)
	}
	return text, present, shared, current, nil
}

// collectAnswers asks the installer's questions. A value in the existing
// .env wins (re-runs keep settings), then the process environment (scripted
// installs pre-answer through it), then the prompt.
func collectAnswers(pr *prompter, current map[string]string, environ func(string) string) (bootstrapAnswers, error) {
	a := bootstrapAnswers{values: map[string]string{}}
	cur := func(k string) string {
		if v, ok := current[k]; ok {
			return v
		}
		return environ(k)
	}
	var err error
	v := a.values
	v["EXPLORER_SESSION_SECRET"] = cur("EXPLORER_SESSION_SECRET")
	if v["EXPLORER_SESSION_SECRET"] == "" {
		v["EXPLORER_SESSION_SECRET"] = genSecret()
	}
	mode := cur("EXPLORER_AUTH_MODE")
	def := mode
	if def == "" {
		def = "elcano"
	}
	if mode, err = pr.value(mode, "EXPLORER_AUTH_MODE", "Authentication mode: elcano (magic link) or central (shared auth service)", def, false); err != nil {
		return a, err
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "elcano", "central":
	case "local":
		return a, errors.New("local password auth was removed; choose 'central' and configure the client auth service")
	default:
		return a, errors.New("authentication mode must be 'elcano' or 'central'")
	}
	v["EXPLORER_AUTH_MODE"] = mode
	// Both modes need the auth service's public key: Elcano mode verifies
	// the shared cookie with it, central mode its signed back-channel events.
	if v["AUTH_SIGNING_PUBKEY"], err = pr.value(cur("AUTH_SIGNING_PUBKEY"), "AUTH_SIGNING_PUBKEY",
		"auth service AUTH_SIGNING_PUBKEY, base64 (run 'auth pubkey' on the auth host; blank to set later)", "", true); err != nil {
		return a, err
	}
	for k, d := range map[string]string{
		"EXPLORER_ACCESS_DB":                "/var/lib/explorer/access.db",
		"EXPLORER_SESSION_IDLE_SECONDS":     "43200",
		"EXPLORER_SESSION_ABSOLUTE_SECONDS": "86400",
	} {
		if v[k] = cur(k); v[k] == "" {
			v[k] = d
		}
	}
	v["EXPLORER_AUTH_COOKIE_SECURE"] = "1"

	if a.hostname, err = pr.value(environ("EXPLORER_BOOTSTRAP_HOSTNAME"), "EXPLORER_BOOTSTRAP_HOSTNAME",
		"Public hostname for TLS (e.g. explorer.example.com, blank to skip Caddy)", "", true); err != nil {
		return a, err
	}
	if a.hostname != "" && a.hostname != "localhost" {
		ans, err := pr.value(environ("EXPLORER_BOOTSTRAP_SETUP_CADDY"), "EXPLORER_BOOTSTRAP_SETUP_CADDY", "Set up Caddy + auto-TLS for "+a.hostname+"? (Y/n)", "Y", false)
		if err != nil {
			return a, err
		}
		a.setupCaddy = yes(ans)
		if a.setupCaddy {
			ans, err := pr.value(environ("EXPLORER_BOOTSTRAP_USE_LETSENCRYPT"), "EXPLORER_BOOTSTRAP_USE_LETSENCRYPT", "Use Let's Encrypt (needs public 80/443)? (Y/n)", "Y", false)
			if err != nil {
				return a, err
			}
			a.letsEncrypt = yes(ans)
			if a.letsEncrypt {
				if a.leEmail, err = pr.value(environ("EXPLORER_BOOTSTRAP_LE_EMAIL"), "EXPLORER_BOOTSTRAP_LE_EMAIL", "LE contact email (blank to skip)", "", true); err != nil {
					return a, err
				}
			}
		}
	}

	v["AUTH_ISSUER_URL"] = cur("AUTH_ISSUER_URL")
	v["EXPLORER_PUBLIC_URL"] = cur("EXPLORER_PUBLIC_URL")
	v["AUTH_CLIENT_ID"] = cur("AUTH_CLIENT_ID")
	if v["AUTH_CLIENT_ID"] == "" {
		v["AUTH_CLIENT_ID"] = "explorer"
	}
	v["AUTH_CLIENT_SECRET"] = cur("AUTH_CLIENT_SECRET")
	if mode == "central" {
		if v["AUTH_ISSUER_URL"], err = pr.value(v["AUTH_ISSUER_URL"], "AUTH_ISSUER_URL", "Central auth origin (for example https://auth.example.com)", "", false); err != nil {
			return a, err
		}
		publicDef := ""
		if a.hostname != "" {
			publicDef = "https://" + a.hostname
		}
		if v["EXPLORER_PUBLIC_URL"], err = pr.value(v["EXPLORER_PUBLIC_URL"], "EXPLORER_PUBLIC_URL", "Explorer public origin", publicDef, false); err != nil {
			return a, err
		}
		if v["AUTH_CLIENT_SECRET"], err = pr.secret(v["AUTH_CLIENT_SECRET"], "AUTH_CLIENT_SECRET", "Registered auth client secret (input hidden)", true); err != nil {
			return a, err
		}
	}

	// S3 archive. Nothing is generated; blanks can be filled in later with
	// `explorer env edit`.
	if v["EMAIL_S3_BUCKET"], err = pr.value(cur("EMAIL_S3_BUCKET"), "EMAIL_S3_BUCKET", "S3 bucket for email archive (blank to fill in later)", "", true); err != nil {
		return a, err
	}
	region := cur("AWS_REGION")
	if v["AWS_REGION"], err = pr.value(region, "AWS_REGION", "AWS region", "us-east-2", false); err != nil {
		return a, err
	}
	// Static AWS keys are optional (an instance role is better). They are
	// asked for only interactively, hidden, and only when not already set;
	// never written blank, so an existing commented-out line stays as is.
	if !pr.nonInteractive && cur("AWS_ACCESS_KEY_ID") == "" {
		id, err := pr.secret("", "AWS_ACCESS_KEY_ID", "AWS access key ID for the archive (blank to use the instance role / set later)", false)
		if err != nil {
			return a, err
		}
		if id != "" {
			secret, err := pr.secret(cur("AWS_SECRET_ACCESS_KEY"), "AWS_SECRET_ACCESS_KEY", "AWS secret access key (input hidden)", true)
			if err != nil {
				return a, err
			}
			v["AWS_ACCESS_KEY_ID"], v["AWS_SECRET_ACCESS_KEY"] = id, secret
		}
	}
	return a, nil
}

// envTemplate is the .env a first install writes.
func envTemplate(v map[string]string, now time.Time) string {
	q := func(k string) string { return dotenv.Quote(v[k]) }
	aws := "# AWS_ACCESS_KEY_ID=      (add with: explorer env edit; kept on re-runs)\n# AWS_SECRET_ACCESS_KEY=\n"
	if v["AWS_ACCESS_KEY_ID"] != "" {
		aws = "AWS_ACCESS_KEY_ID=" + q("AWS_ACCESS_KEY_ID") + "\nAWS_SECRET_ACCESS_KEY=" + q("AWS_SECRET_ACCESS_KEY") + "\n"
	}
	return "# Auto-generated by Explorer bootstrap on " + now.Format(time.RFC3339) + "\n\n" +
		"EXPLORER_SESSION_SECRET=" + q("EXPLORER_SESSION_SECRET") + "\n\n" +
		"# Authentication provider: elcano keeps magic-link auth; central delegates\n" +
		"# sign-in and keeps only an app access list plus opaque Explorer sessions.\n" +
		"EXPLORER_AUTH_MODE=" + q("EXPLORER_AUTH_MODE") + "\n" +
		"EXPLORER_ACCESS_DB=" + q("EXPLORER_ACCESS_DB") + "\n" +
		"EXPLORER_AUTH_COOKIE_SECURE=" + q("EXPLORER_AUTH_COOKIE_SECURE") + "\n" +
		"EXPLORER_SESSION_IDLE_SECONDS=" + q("EXPLORER_SESSION_IDLE_SECONDS") + "\n" +
		"EXPLORER_SESSION_ABSOLUTE_SECONDS=" + q("EXPLORER_SESSION_ABSOLUTE_SECONDS") + "\n\n" +
		"# Auth service public verification key (both modes).\n" +
		"AUTH_SIGNING_PUBKEY=" + q("AUTH_SIGNING_PUBKEY") + "\n" +
		"# AUTH_LOGIN_URL=\"https://auth.elcanotek.com\"\n\n" +
		"# Central mode only — exact callback: " + v["EXPLORER_PUBLIC_URL"] + "/auth/callback\n" +
		"AUTH_ISSUER_URL=" + q("AUTH_ISSUER_URL") + "\n" +
		"EXPLORER_PUBLIC_URL=" + q("EXPLORER_PUBLIC_URL") + "\n" +
		"AUTH_CLIENT_ID=" + q("AUTH_CLIENT_ID") + "\n" +
		"AUTH_CLIENT_SECRET=" + q("AUTH_CLIENT_SECRET") + "\n\n" +
		"# ── AWS / S3 ──\n" +
		"AWS_REGION=" + q("AWS_REGION") + "\n" +
		"EMAIL_S3_BUCKET=" + q("EMAIL_S3_BUCKET") + "\n" + aws
}

// writeEnv writes a new .env, or merges the managed keys into an existing
// one in place. The file is born 0600 and owned by the service account.
func writeEnv(p Paths, acct account, a bootstrapAnswers, text string, present bool, shared map[string]string, now time.Time) error {
	var out string
	if present {
		order := append([]string{}, envManagedKeys...)
		if a.values["AWS_ACCESS_KEY_ID"] != "" {
			order = append(order, "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
		}
		desired := map[string]string{}
		for _, k := range order {
			desired[k] = a.values[k]
		}
		out = dotenv.Merge(text, desired, order, shared)
	} else {
		out = envTemplate(a.values, now)
	}
	if _, err := requireSingleRegular(p.EnvFile()); err != nil {
		return err
	}
	return writeFileAtomic(p.EnvFile(), []byte(out), 0o600, acct.uid, acct.gid)
}

// seedSource copies the running checkout into the install source location
// as root-owned, non-group/world-writable files.
func seedSource(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil { //nolint:gosec // G301: a public, root-owned directory by design.
		return err
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode().Perm() &^ 0o022
		switch {
		case d.IsDir():
			if err := os.MkdirAll(target, mode|0o700); err != nil {
				return err
			}
			return os.Chmod(target, mode|0o700)
		case info.Mode().IsRegular():
			return copyFileAtomic(path, target, mode, 0, 0)
		default:
			return fmt.Errorf("%s is not a regular file or directory", path)
		}
	})
}

func runBootstrap(ctx context.Context, u *ui, r Runner, p Paths, args []string) error {
	source := ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--source" && i+1 < len(args):
			i++
			source = args[i]
		case strings.HasPrefix(args[i], "--source="):
			source = strings.TrimPrefix(args[i], "--source=")
		default:
			return usageError{"usage: explorer bootstrap [--source DIR]"}
		}
	}
	if source == "" {
		source = p.SrcDir
	}
	if os.Geteuid() != 0 {
		return errors.New("run as root: sudo bash scripts/bootstrap.sh")
	}
	if !exists(filepath.Join(source, "go.mod")) {
		return fmt.Errorf("not an Explorer checkout at %s", source)
	}
	if err := RequireTrusted(source); err != nil {
		return fmt.Errorf("%s is not an exclusively root-owned, non-writable, symlink-free checkout: %w", source, err)
	}
	pr := newPrompter(u, os.Getenv("EXPLORER_BOOTSTRAP_NON_INTERACTIVE") == "1")
	h := hostEnvFromEnv(u, r)
	now := time.Now()

	u.sayf("%s", u.bold("Elcano Explorer — bootstrap"))
	u.sayf("%s", u.dim("Fedora / RHEL 9+  •  systemd  •  Go email-archive UI"))
	u.sayf("")
	u.sayf("Safe to re-run: existing .env is preserved; only missing values are prompted.")

	u.stepf("1/7  Installing system dependencies via dnf")
	pkgs := []string{"git", "golang", "ca-certificates"}
	if h.dryRun {
		u.infof("[dry-run] dnf install -y %s", strings.Join(pkgs, " "))
	} else if res := r.Run(ctx, Cmd{Name: "dnf", Args: append([]string{"install", "-y"}, pkgs...), Timeout: 30 * time.Minute}); res.Code != 0 {
		return fmt.Errorf("dnf install failed: %s", strings.TrimSpace(res.Stderr))
	}
	u.okf("installed: %s", strings.Join(pkgs, " "))
	h.removeCockpit(ctx)
	h.sshKeyOnly(ctx)

	u.stepf("2/7  Preparing %s + '%s' user", p.AppDir, p.AppUser)
	acct, err := prepareAccountAndSource(ctx, u, r, p, source)
	if err != nil {
		return err
	}

	u.stepf("3/7  Building the Explorer binary")
	revision, err := gitOut(ctx, r, p.SrcDir, "rev-parse", "HEAD^{commit}")
	if err != nil {
		return fmt.Errorf("could not resolve the installed source revision: %w", err)
	}
	staging, err := newStaging(p, ".explorer-build.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	staged := filepath.Join(staging, "explorer")
	if err := buildBinary(ctx, u, r, p, p.SrcDir, staged, revision); err != nil {
		return fmt.Errorf("%w\nbuild failed — the installed service was not changed", err)
	}
	// Before anything in the app directory moves: it must be a real
	// directory under a trusted parent, on the same filesystem.
	if err := checkAppDirForMoves(p); err != nil {
		return err
	}
	if err := RequireTrustedPath(filepath.Dir(p.AppDir)); err != nil {
		return err
	}
	if _, err := preserveAndReport(u, p); err != nil {
		return err
	}
	if err := installApp(p, acct, staged, revision); err != nil {
		return err
	}
	u.okf("binary installed at %s (%s)", p.BinPath(), short(revision))

	u.stepf("4/7  Configuring the instance")
	text, present, shared, current, err := existingEnv(p)
	if err != nil {
		return err
	}
	if present {
		u.infof("found existing %s — re-using values, only asking for what's missing", p.EnvFile())
	}
	answers, err := collectAnswers(pr, current, os.Getenv)
	if err != nil {
		return err
	}
	if answers.hostname != "" {
		h.setHostname(ctx, answers.hostname)
	}
	if err := writeEnv(p, acct, answers, text, present, shared, now); err != nil {
		return err
	}
	if err := secureEnvFiles(p, acct); err != nil {
		return err
	}
	u.okf("env seeded at %s", p.EnvFile())

	offerProvision(ctx, u, r, p, pr)

	u.stepf("5/7  Installing systemd units + operator CLI")
	if err := installSystemFiles(ctx, u, r, p, staged); err != nil {
		return err
	}
	u.okf("systemd units + CLI installed")

	u.stepf("6/7  Starting explorer")
	r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"enable", p.Service}, Timeout: time.Minute})
	if res := r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"restart", p.Service}, Timeout: 2 * time.Minute}); res.Code != 0 {
		u.warnf("systemctl restart %s failed — check: explorer logs", p.Service)
	} else {
		u.okf("%s restarted", p.Service)
	}
	if healthy(ctx, p.HealthURL, 15) {
		u.okf("health check /health → 200")
	} else {
		u.warnf("explorer didn't answer /health in 15s — check: explorer logs")
	}

	u.stepf("7/7  Reverse proxy / TLS")
	if answers.setupCaddy {
		if err := setupCaddy(ctx, u, r, p, answers); err != nil {
			return err
		}
	} else {
		u.infof("skipping Caddy — reach explorer at http://127.0.0.1:8080 (or via your own proxy)")
	}

	if err := layoutCheck(p); err != nil {
		return fmt.Errorf("installed layout failed its ownership check: %w", err)
	}
	printBootstrapSummary(u, answers)
	return nil
}

// prepareAccountAndSource creates the service account and its state
// directory, and seeds the root-owned install checkout from source.
func prepareAccountAndSource(ctx context.Context, u *ui, r Runner, p Paths, source string) (account, error) {
	if _, err := lookupAccount(p.AppUser); err != nil {
		if res := r.Run(ctx, Cmd{Name: "useradd", Args: []string{"--system", "--home-dir", p.AppDir, "--shell", "/usr/sbin/nologin", p.AppUser}, Timeout: time.Minute}); res.Code != 0 {
			return account{}, fmt.Errorf("useradd failed: %s", strings.TrimSpace(res.Stderr))
		}
	}
	acct, err := lookupAccount(p.AppUser)
	if err != nil {
		return account{}, err
	}
	if err := os.MkdirAll(p.StateDir, 0o700); err != nil {
		return account{}, err
	}
	if err := os.Lchown(p.StateDir, acct.uid, acct.gid); err != nil {
		return account{}, err
	}
	if err := os.Chmod(p.StateDir, 0o700); err != nil { //nolint:gosec // G302: deliberate mode for a root-installed file.
		return account{}, err
	}
	if !exists(filepath.Join(p.SrcDir, ".git")) {
		if !exists(filepath.Join(source, ".git")) {
			return account{}, fmt.Errorf("bootstrap must run from a git checkout (no .git at %s)", source)
		}
		if err := seedSource(source, p.SrcDir); err != nil {
			return account{}, fmt.Errorf("could not copy %s → %s: %w", source, p.SrcDir, err)
		}
		u.okf("copied %s → %s", source, p.SrcDir)
	} else {
		u.infof("%s already exists — leaving it in place", p.SrcDir)
	}
	if err := RequireTrusted(p.SrcDir); err != nil {
		return account{}, fmt.Errorf("%s is not safe for root-run updates; re-clone it as root: %w", p.SrcDir, err)
	}
	return acct, nil
}

// offerProvision merges an encrypted config bundle when one is present.
func offerProvision(ctx context.Context, u *ui, r Runner, p Paths, pr *prompter) {
	if bundles := listBundles(filepath.Join(p.SrcDir, "provision", "clients")); len(bundles) > 0 {
		u.stepf("Encrypted config bundle (optional)")
		ans, _ := pr.value(os.Getenv("EXPLORER_BOOTSTRAP_PROVISION"), "EXPLORER_BOOTSTRAP_PROVISION", "Provision config from the encrypted bundle now? (Y/n)", "Y", false)
		if strings.HasPrefix(strings.ToLower(ans), "y") {
			client := os.Getenv("EXPLORER_BOOTSTRAP_PROVISION_CLIENT")
			if len(bundles) == 1 {
				client = bundles[0]
			}
			if err := provision(ctx, u, r, p, provisionOpts{client: client, restart: false, nonInteractive: pr.nonInteractive}, pr); err != nil {
				u.warnf("provision failed (%v) — continuing install. Retry later with: sudo explorer provision", err)
			} else {
				u.okf("config bundle provisioned")
			}
		} else {
			u.infof("skipping provision — run 'sudo explorer provision' later if you change your mind")
		}
	}
}

func printBootstrapSummary(u *ui, a bootstrapAnswers) {
	v := a.values
	u.sayf("")
	u.sayf("%s", u.paint("\033[0;32m", "═══════════════════════════════════════════════"))
	u.sayf("%s", u.bold(" ✓ Explorer installed"))
	u.sayf("%s", u.paint("\033[0;32m", "═══════════════════════════════════════════════"))
	u.sayf("")
	if a.setupCaddy {
		u.sayf("  URL         %s", u.bold("https://"+a.hostname))
	} else {
		u.sayf("  URL         %s  (front with your reverse proxy for HTTPS)", u.bold("http://127.0.0.1:8080"))
	}
	u.sayf("  Logs        %s", u.dim("explorer logs"))
	u.sayf("  CLI         %s", u.dim("explorer start|stop|restart|status|update|doctor|env|tls|access"))
	u.sayf("")
	if v["EXPLORER_AUTH_MODE"] == "central" {
		u.sayf("  Sign-in     %s", u.dim(fmt.Sprintf("central auth + app-scoped Explorer session (%ss idle, %ss absolute)", v["EXPLORER_SESSION_IDLE_SECONDS"], v["EXPLORER_SESSION_ABSOLUTE_SECONDS"])))
		u.sayf("  Callback    %s", u.dim(v["EXPLORER_PUBLIC_URL"]+"/auth/callback"))
		u.sayf("  Next        %s", u.dim("explorer access grant user@example.com"))
	} else {
		u.sayf("  Sign-in     %s", u.dim("via the external magic-link auth service — no local password"))
	}
	if v["AUTH_SIGNING_PUBKEY"] == "" {
		if v["EXPLORER_AUTH_MODE"] == "elcano" {
			u.warnf("AUTH_SIGNING_PUBKEY is unset — every request will redirect to sign-in.")
		} else {
			u.warnf("AUTH_SIGNING_PUBKEY is unset — central mode refuses to start until it is set (back-channel logout needs it).")
		}
		u.warnf("  Set it with: explorer env edit  (paste the auth service public key), then: explorer restart")
	}
	u.sayf("")
}

// setupCaddy installs and verifies the Caddy site for the public hostname.
func setupCaddy(ctx context.Context, u *ui, r Runner, p Paths, a bootstrapAnswers) error {
	host := a.hostname
	dnsPrecheck(ctx, u, host)

	if res := r.Run(ctx, Cmd{Name: "dnf", Args: []string{"install", "-y", "caddy"}, Timeout: 30 * time.Minute}); res.Code != 0 {
		return fmt.Errorf("dnf install caddy failed: %s", strings.TrimSpace(res.Stderr))
	}
	plan, err := planCaddySite(p.Caddyfile)
	if err != nil {
		return err
	}
	caddyText, _ := os.ReadFile(p.Caddyfile)
	text := string(caddyText)
	if plan.addImport {
		text += "\n# Managed by Elcano service bootstraps — each service drops\n# its own site block at /etc/caddy/conf.d/<service>.caddy.\nimport conf.d/*.caddy\n"
	}
	// One global block per Caddyfile set: add the LE contact only when none
	// is configured yet.
	if a.leEmail != "" && !hasCaddyEmail(text) {
		text = "{\n\temail " + a.leEmail + "\n}\n\n" + text
	}
	if text != string(caddyText) {
		if err := writeFileAtomic(p.Caddyfile, []byte(text), 0o644, 0, 0); err != nil {
			return err
		}
	}
	if exists(plan.target) && !caddyIsOurs(plan.target) {
		return fmt.Errorf("refusing to overwrite an unmarked Caddy site: %s", plan.target)
	}
	if err := os.MkdirAll(filepath.Dir(plan.target), 0o755); err != nil { //nolint:gosec // G301: a public, root-owned directory by design.
		return err
	}
	if err := writeFileAtomic(plan.target, []byte(renderCaddySite(host, a.letsEncrypt)), 0o644, 0, 0); err != nil {
		return err
	}
	removed, err := removeStaleCaddySites(p.Caddyfile, plan)
	if err != nil {
		return fmt.Errorf("could not remove a stale Explorer Caddy site: %w", err)
	}
	for _, s := range removed {
		u.infof("removed stale Explorer site: %s", s)
	}
	// The config must parse AND contain this site.
	if r.Run(ctx, Cmd{Name: "caddy", Args: []string{"validate", "--config", p.Caddyfile, "--adapter", "caddyfile"}, Timeout: time.Minute}).Code != 0 {
		return fmt.Errorf("the Caddy configuration does not validate — run: caddy validate --config %s --adapter caddyfile", p.Caddyfile)
	}
	adapted := r.Run(ctx, Cmd{Name: "caddy", Args: []string{"adapt", "--config", p.Caddyfile, "--adapter", "caddyfile"}, Timeout: time.Minute})
	if adapted.Code != 0 {
		return fmt.Errorf("caddy could not adapt %s", p.Caddyfile)
	}
	if !adaptedHasSite([]byte(adapted.Stdout), host, "127.0.0.1:8080") {
		return fmt.Errorf("caddy does not load an Explorer proxy for %s from %s", host, plan.target)
	}
	// Open 80/443 only after both checks pass. Soft-fail: some boxes run no
	// firewalld at all.
	if r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"is-active", "--quiet", "firewalld"}, Timeout: 30 * time.Second}).Code == 0 {
		r.Run(ctx, Cmd{Name: "firewall-cmd", Args: []string{"--add-service=http", "--permanent"}, Timeout: time.Minute})
		r.Run(ctx, Cmd{Name: "firewall-cmd", Args: []string{"--add-service=https", "--permanent"}, Timeout: time.Minute})
		r.Run(ctx, Cmd{Name: "firewall-cmd", Args: []string{"--reload"}, Timeout: time.Minute})
		u.okf("firewalld: http + https opened")
	}
	if _, hasNginx := r.LookPath("nginx"); hasNginx && r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"is-active", "--quiet", "nginx.service"}, Timeout: 30 * time.Second}).Code == 0 {
		r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"disable", "--now", "nginx.service", "certbot-renew.timer"}, Timeout: time.Minute})
		u.infof("disabled legacy nginx.service / certbot-renew.timer before starting Caddy")
	}
	r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"enable", "caddy"}, Timeout: time.Minute})
	if r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"is-active", "--quiet", "caddy"}, Timeout: 30 * time.Second}).Code == 0 {
		if r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"reload", "caddy"}, Timeout: 2 * time.Minute}).Code != 0 {
			return errors.New("caddy reload failed — run 'caddy validate' to debug")
		}
	} else if r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"start", "caddy"}, Timeout: 2 * time.Minute}).Code != 0 {
		return errors.New("caddy failed to start — check: journalctl -u caddy")
	}
	u.okf("Caddy running — auto-renews ~30 days before expiry, no cron needed")
	if !a.letsEncrypt {
		return nil
	}
	return waitForTLS(ctx, u, host)
}

// dnsPrecheck warns when the hostname does not point at this box yet.
// Warning only: an operator can still proceed with `tls internal` on a box
// without public reachability. It asks public DNS (lookupPublic), not this
// box's resolver, and checks every A and AAAA answer: one right address
// must not hide a stale one, and Let's Encrypt prefers IPv6 when there is an
// AAAA record.
func dnsPrecheck(ctx context.Context, u *ui, host string) {
	v4, v6, err := lookupPublic(ctx, host)
	if err != nil {
		u.warnf("could not check public DNS for %s (%v)", host, err)
		u.warnf("  LE's HTTP-01 challenge fails unless %s points at this box.", host)
		return
	}
	if len(v4) == 0 && len(v6) == 0 {
		u.warnf("%s doesn't resolve in public DNS yet — challenge will fail until DNS lands.", host)
		return
	}
	box4, box6 := boxPublicAddrs(ctx)
	ok := true
	if len(v4) > 0 {
		switch stray := strayAddrs(v4, box4); {
		case len(box4) == 0:
			ok = false
			u.warnf("could not learn this box's public IPv4; check that %s → %s is this box.", host, addrStrings(v4))
		case len(stray) > 0:
			ok = false
			u.warnf("DNS mismatch: %s → %s, this box → %s", host, addrStrings(v4), addrStrings(box4))
			u.warnf("  LE will fail the HTTP-01 challenge until the A record is updated.")
		}
	}
	if len(v6) > 0 {
		switch stray := strayAddrs(v6, box6); {
		case len(box6) == 0:
			ok = false
			u.warnf("%s has AAAA %s but this box has no public IPv6: LE tries IPv6 first, so the challenge can fail.", host, addrStrings(v6))
		case len(stray) > 0:
			ok = false
			u.warnf("DNS mismatch: %s AAAA → %s, this box → %s", host, addrStrings(v6), addrStrings(box6))
			u.warnf("  LE will fail the HTTP-01 challenge until the AAAA record is updated or removed.")
		}
	}
	if ok {
		u.okf("DNS resolves correctly (%s)", addrStrings(append(v4, v6...)))
	}
}

// boxPublicAddrs is this box's public IPv4 and IPv6, as the internet sees
// them (either may be empty).
var boxPublicAddrs = func(ctx context.Context) (v4, v6 []netip.Addr) {
	if a, err := netip.ParseAddr(publicIP(ctx, "https://api.ipify.org")); err == nil && a.Is4() {
		v4 = append(v4, a)
	}
	if a, err := netip.ParseAddr(publicIP(ctx, "https://api6.ipify.org")); err == nil && a.Is6() {
		v6 = append(v6, a)
	}
	return v4, v6
}

// waitForTLS waits up to two minutes for the public HTTPS site to answer.
func waitForTLS(ctx context.Context, u *ui, host string) error {
	u.infof("waiting for TLS at https://%s (up to 120s)", host)
	deadline := time.Now().Add(120 * time.Second)
	client := &http.Client{Timeout: 5 * time.Second}
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
		if err != nil {
			return err
		}
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
			if leaf, verr, err := certInfo(ctx, host); err == nil && verr == nil {
				u.okf("TLS live — cert valid until %s", leaf.NotAfter.UTC().Format("Jan 2 15:04:05 2006 MST"))
			} else {
				u.okf("TLS live")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("https://%s did not answer within 120s. Explorer itself is installed and healthy on 127.0.0.1:8080, but it is not reachable over TLS, so the install is not finished. Check: journalctl -u caddy, that 80 and 443 are open to the internet, and that the DNS record points here", host)
}

func hasCaddyEmail(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) > 1 && f[0] == "email" {
			return true
		}
	}
	return false
}

func publicIP(ctx context.Context, url string) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
