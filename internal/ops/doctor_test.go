// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

const validPubkey = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

func healthyDotenv() string {
	return "EXPLORER_SESSION_SECRET=" + strings.Repeat("a", 40) + "\n" +
		"EXPLORER_AUTH_MODE=elcano\n" +
		"AUTH_SIGNING_PUBKEY=" + validPubkey + "\n" +
		"EMAIL_S3_BUCKET=archive\n"
}

func centralDotenv(extra string) string {
	return healthyDotenv() + "EXPLORER_AUTH_MODE=central\nAUTH_ISSUER_URL=https://auth.example.com\n" +
		"EXPLORER_PUBLIC_URL=https://explorer.example.com\nAUTH_CLIENT_ID=explorer\n" +
		"AUTH_CLIENT_SECRET=" + strings.Repeat("x", 40) + "\n" + extra
}

type doctorFixture struct {
	d   *doctor
	f   *fakeRunner
	app string
}

// newDoctorFixture is a hermetic doctor: a scratch app dir owned by the test
// user, every probe stubbed, and no tool installed unless a test adds it.
func newDoctorFixture(t *testing.T, dotenvText string) *doctorFixture {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	app := filepath.Join(base, "app")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if dotenvText != "" {
		writeFile(t, filepath.Join(app, ".env"), dotenvText, 0o600)
	}
	p := Paths{
		SrcDir: filepath.Join(base, "src"), AppDir: app, AppUser: me.Username,
		StateDir: filepath.Join(base, "state"), SystemdDir: filepath.Join(base, "systemd"),
		TmpfilesDir: filepath.Join(base, "tmpfiles"), CLITarget: filepath.Join(base, "bin", "explorer"),
		Caddyfile: filepath.Join(base, "caddy", "Caddyfile"), Service: "explorer.service",
		HealthURL: "http://127.0.0.1:1/health", BuildCache: filepath.Join(base, "cache"),
	}
	f := newFake()
	d := newDoctor(p, f)
	d.httpStatus = func(context.Context, string) (int, error) { return 200, nil }
	d.certExpiry = func(context.Context, string) (time.Time, error) { return time.Time{}, errors.New("unreachable") }
	d.osRelease = func() (map[string]string, error) { return map[string]string{}, nil }
	d.fedoraFeed = func(context.Context) ([]byte, error) { return nil, errors.New("offline") }
	d.diskFree = func(string) (uint64, error) { return 10 << 30, nil }
	d.euid = func() int { return 1000 }
	d.environ = func() map[string]string { return map[string]string{} }
	d.selfPath = func() (string, error) { return "/nonexistent", nil }
	return &doctorFixture{d: d, f: f, app: app}
}

func (fx *doctorFixture) run(t *testing.T) map[string]Check {
	t.Helper()
	out := map[string]Check{}
	for _, c := range fx.d.Diagnose(context.Background()) {
		if _, dup := out[c.Name]; !dup || c.Status != "ok" {
			out[c.Name] = c
		}
	}
	return out
}

func TestDoctorConfigurationRemedies(t *testing.T) {
	drop := func(text, key string) string {
		var keep []string
		for _, l := range strings.Split(text, "\n") {
			if !strings.HasPrefix(l, key+"=") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	cases := []struct {
		name, dotenv, want string
		exact              bool
	}{
		{"missing key", drop(healthyDotenv(), "AUTH_SIGNING_PUBKEY"), "missing: AUTH_SIGNING_PUBKEY", true},
		{"bad key shape", strings.Replace(healthyDotenv(), validPubkey, "not!!base64", 1), "AUTH_SIGNING_PUBKEY is set but is not a 32-byte base64 Ed25519 key", true},
		{"bad mode", strings.Replace(healthyDotenv(), "=elcano", "=ldap", 1), "EXPLORER_AUTH_MODE must be 'elcano' or 'central' (got 'ldap')", true},
		{"missing central keys", healthyDotenv() + "EXPLORER_AUTH_MODE=central\nAUTH_ISSUER_URL=https://auth.example.com\nAUTH_CLIENT_ID=explorer\n", "missing: EXPLORER_PUBLIC_URL, AUTH_CLIENT_SECRET", true},
		{"short secret", centralDotenv("AUTH_CLIENT_SECRET=short\n"), "AUTH_CLIENT_SECRET must contain at least 32 bytes", false},
		{"http issuer", centralDotenv("AUTH_ISSUER_URL=http://auth.example.com\n"), "AUTH_ISSUER_URL must be an HTTPS origin without a path or query", false},
		{"issuer path", centralDotenv("AUTH_ISSUER_URL=https://auth.example.com/some/path\n"), "AUTH_ISSUER_URL must be an HTTPS origin", false},
		{"broken issuer", centralDotenv("AUTH_ISSUER_URL=https://[\n"), "AUTH_ISSUER_URL must be an HTTPS origin", false},
		{"bad client id", centralDotenv("AUTH_CLIENT_ID=\"bad:id\"\n"), "AUTH_CLIENT_ID must be 1-128 characters without ':'", false},
		{"timeout nan", centralDotenv("AUTH_HTTP_TIMEOUT_SECONDS=soon\n"), "AUTH_HTTP_TIMEOUT_SECONDS must be a number", false},
		{"timeout range", centralDotenv("AUTH_HTTP_TIMEOUT_SECONDS=61\n"), "AUTH_HTTP_TIMEOUT_SECONDS must be between 0 and 60", false},
		{"bad integer", healthyDotenv() + "EMAIL_S3_MAX_DATE_PREFIX_DAYS=lots\n", "EMAIL_S3_MAX_DATE_PREFIX_DAYS must be an integer", false},
	}
	for _, tc := range cases {
		c := newDoctorFixture(t, tc.dotenv).run(t)["configuration"]
		if c.Status != "fail" || (tc.exact && c.Detail != tc.want) || !strings.Contains(c.Detail, tc.want) {
			t.Errorf("%s: %+v", tc.name, c)
		}
		if strings.Contains(c.Detail, "short\"") || regexp.MustCompile(`\b5\b`).MatchString(c.Detail) {
			t.Errorf("%s: a value or its measurement leaked: %s", tc.name, c.Detail)
		}
	}
	for _, ok := range []string{healthyDotenv(), centralDotenv(""), centralDotenv("AUTH_HTTP_TIMEOUT_SECONDS=10\n")} {
		if c := newDoctorFixture(t, ok).run(t)["configuration"]; c.Status != "ok" {
			t.Errorf("healthy config failed: %+v", c)
		}
	}
}

func TestDoctorDotenvMatchesTheService(t *testing.T) {
	fx := newDoctorFixture(t, "")
	writeFile(t, filepath.Join(fx.app, ".env.shared"), "BASE=from-shared\nAUTH_SIGNING_PUBKEY=shared-key\n", 0o600)
	writeFile(t, filepath.Join(fx.app, ".env"), healthyDotenv()+"EMAIL_S3_BUCKET=${BASE}-bucket\nLATER=${FORWARD}\nFORWARD=x\n", 0o600)
	merged, ok := fx.d.checkEnvFiles()
	if !ok || merged["EMAIL_S3_BUCKET"] != "from-shared-bucket" || merged["AUTH_SIGNING_PUBKEY"] != validPubkey || merged["LATER"] != "" {
		t.Fatalf("merged = %v", merged)
	}
}

func TestDoctorEnvFilePermissions(t *testing.T) {
	fx := newDoctorFixture(t, healthyDotenv())
	if c := fx.run(t)["env-permissions"]; c.Status != "ok" {
		t.Fatalf("healthy env: %+v", c)
	}
	_ = os.Chmod(filepath.Join(fx.app, ".env"), 0o644)
	if c := fx.run(t)["env-permissions"]; c.Status != "fail" || !strings.Contains(c.Detail, "chmod 600") {
		t.Fatalf("0644 env: %+v", c)
	}
	_ = os.Chmod(filepath.Join(fx.app, ".env"), 0o600)
	if err := os.Link(filepath.Join(fx.app, ".env"), filepath.Join(fx.app, "env-copy")); err != nil {
		t.Fatal(err)
	}
	if c := fx.run(t)["env-permissions"]; c.Status != "fail" || !strings.Contains(c.Detail, "2 hard links") {
		t.Fatalf("hard link: %+v", c)
	}

	// A symlinked .env is reported and never followed.
	fx2 := newDoctorFixture(t, "")
	target := filepath.Join(t.TempDir(), "real")
	writeFile(t, target, healthyDotenv(), 0o600)
	_ = os.Symlink(target, filepath.Join(fx2.app, ".env"))
	checks := fx2.run(t)
	if c := checks["env-permissions"]; c.Status != "fail" || !strings.Contains(c.Detail, "is a symlink") {
		t.Fatalf("symlink: %+v", c)
	}
	if c := checks["configuration"]; c.Status != "fail" || !strings.Contains(c.Detail, "could not parse .env") {
		t.Fatalf("symlink target was read: %+v", c)
	}

	// A fifo fails without being opened (opening one would block).
	fx3 := newDoctorFixture(t, "")
	if err := syscall.Mkfifo(filepath.Join(fx3.app, ".env"), 0o600); err != nil {
		t.Skip("mkfifo unsupported")
	}
	done := make(chan map[string]Check, 1)
	go func() { done <- fx3.run(t) }()
	select {
	case checks := <-done:
		if checks["env-permissions"].Status != "fail" {
			t.Fatalf("fifo: %+v", checks["env-permissions"])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("doctor opened the fifo and blocked")
	}

	// .env.shared is checked too.
	fx4 := newDoctorFixture(t, healthyDotenv())
	writeFile(t, filepath.Join(fx4.app, ".env.shared"), "", 0o640)
	if c := fx4.run(t)["env-shared-permissions"]; c.Status != "fail" {
		t.Fatalf("shared perms: %+v", c)
	}
}

func TestDoctorSessionSecretReportedOnce(t *testing.T) {
	text := strings.Replace(healthyDotenv(), strings.Repeat("a", 40), "short", 1)
	fx := newDoctorFixture(t, text)
	checks := fx.d.Diagnose(context.Background())
	n := 0
	for _, c := range checks {
		if strings.Contains(c.Detail, "EXPLORER_SESSION_SECRET") {
			n++
			if c.Name != "session-secret" || c.Status != "fail" {
				t.Fatalf("%+v", c)
			}
		}
	}
	if n != 1 {
		t.Fatalf("short session secret reported %d times", n)
	}
}

func TestDoctorAWSCredentials(t *testing.T) {
	cases := map[string]string{
		"":                                "warn",
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE\n": "warn",
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE\nAWS_SECRET_ACCESS_KEY=s\n": "ok",
	}
	for extra, want := range cases {
		if c := newDoctorFixture(t, healthyDotenv()+extra).run(t)["aws-credentials"]; c.Status != want {
			t.Errorf("%q: %+v", extra, c)
		}
	}
}

func TestDoctorServiceEnablement(t *testing.T) {
	fx := newDoctorFixture(t, healthyDotenv())
	fx.f.handle = func(c Cmd) Result {
		if c.Name == "systemctl" && c.Args[0] == "is-enabled" {
			return Result{Code: 1}
		}
		return Result{}
	}
	if c := fx.run(t)["service-enabled"]; c.Status != "warn" || !strings.Contains(c.Detail, "active but DISABLED") {
		t.Fatalf("%+v", c)
	}
	fx.f.handle = func(c Cmd) Result {
		if c.Name == "systemctl" && (c.Args[0] == "is-enabled" || c.Args[0] == "is-active") {
			return Result{Code: 3}
		}
		return Result{}
	}
	checks := fx.run(t)
	if checks["service"].Status != "fail" || !strings.Contains(checks["service-enabled"].Detail, "DISABLED and inactive") {
		t.Fatalf("%+v %+v", checks["service"], checks["service-enabled"])
	}
}

func TestDoctorReboot(t *testing.T) {
	const running = "6.9.1-1.fc40.x86_64"
	cases := []struct {
		name   string
		tools  []string
		handle func(c Cmd) Result
		status string
		detail string
	}{
		{"needs-restarting decides", []string{"needs-restarting"}, func(Cmd) Result {
			return Result{Code: 1}
		}, "warn", "kernel or core libraries updated — reboot the host when convenient"},
		{"dnf plugin decides", []string{"dnf"}, func(c Cmd) Result {
			if c.Name == "dnf" && c.Args[0] == "needs-restarting" {
				return Result{Code: 1}
			}
			return Result{}
		}, "warn", "kernel or core libraries updated — reboot the host when convenient"},
		{"no tier", nil, nil, "warn", "could not determine reboot status — needs-restarting, dnf needs-restarting and rpm/uname all unavailable or failed"},
		{"any yes wins", []string{"dnf", "uname", "rpm"}, func(c Cmd) Result {
			switch c.Name {
			case "uname":
				return Result{Stdout: running + "\n"}
			case "rpm":
				return Result{Stdout: "kernel-6.10.0-1.fc40.x86_64  Mon 01 Jul 2024\nkernel-" + running + "  Sun\n"}
			}
			return Result{}
		}, "warn", "kernel or core libraries updated"},
		{"running newest", []string{"uname", "rpm"}, func(c Cmd) Result {
			switch c.Name {
			case "uname":
				return Result{Stdout: running + "\n"}
			case "rpm":
				return Result{Stdout: "kernel-" + running + "  Mon\n"}
			}
			return Result{}
		}, "ok", "no reboot pending"},
		{"tier error is unknown", []string{"needs-restarting"}, func(Cmd) Result { return Result{Code: 127} }, "warn", "could not determine reboot status"},
		{"rpm fails is unknown", []string{"uname", "rpm"}, func(c Cmd) Result {
			if c.Name == "rpm" {
				return Result{Code: 1}
			}
			return Result{Stdout: running}
		}, "warn", "could not determine reboot status"},
	}
	for _, tc := range cases {
		fx := newDoctorFixture(t, healthyDotenv())
		for _, tool := range tc.tools {
			fx.f.tools[tool] = true
		}
		fx.f.handle = tc.handle
		c := fx.run(t)["reboot"]
		if c.Status != tc.status || !strings.HasPrefix(c.Detail, tc.detail) {
			t.Errorf("%s: %+v", tc.name, c)
		}
	}
}

func TestDoctorSSHD(t *testing.T) {
	fx := newDoctorFixture(t, healthyDotenv())
	fx.f.tools["sshd"] = true
	fx.f.handle = func(c Cmd) Result {
		if c.Name == "sshd" {
			return Result{Stdout: "permitrootlogin yes\npasswordauthentication no\n"}
		}
		return Result{}
	}
	if _, ok := fx.run(t)["sshd"]; ok {
		t.Fatal("sshd checked without root")
	}
	fx.d.euid = func() int { return 0 }
	if c := fx.run(t)["sshd"]; c.Status != "warn" || c.Detail != "sshd accepts passwords — see production-support README, Access: SSH keys" {
		t.Fatalf("%+v", c)
	}
}

func TestDoctorCaddyBinaryMissingFails(t *testing.T) {
	fx := newDoctorFixture(t, healthyDotenv())
	caddyDir := filepath.Dir(fx.d.p.Caddyfile)
	_ = os.MkdirAll(filepath.Join(caddyDir, "conf.d"), 0o755)
	writeFile(t, fx.d.p.Caddyfile, "import conf.d/*.caddy\n", 0o644)
	writeFile(t, filepath.Join(caddyDir, "conf.d", "explorer.caddy"), CaddyMarker+"\nexplorer.example {\n}\n", 0o644)
	if c := fx.run(t)["caddy"]; c.Status != "fail" || !strings.Contains(c.Detail, "caddy binary is missing") {
		t.Fatalf("%+v", c)
	}
	fx.f.tools["caddy"] = true
	checks := fx.run(t)
	if checks["caddy"].Status != "ok" || checks["tls-cert"].Status != "warn" {
		t.Fatalf("%+v %+v", checks["caddy"], checks["tls-cert"])
	}
	fx.d.certExpiry = func(context.Context, string) (time.Time, error) { return time.Now().Add(10 * 24 * time.Hour), nil }
	if c := fx.run(t)["tls-cert"]; c.Status != "warn" || !strings.Contains(c.Detail, "within 30 days") {
		t.Fatalf("%+v", c)
	}
}

func TestDoctorInstalledFilesAndCLI(t *testing.T) {
	fx := newDoctorFixture(t, healthyDotenv())
	checks := fx.run(t)
	if checks["operator-cli"].Status != "fail" || checks["units"].Status != "fail" || checks["binary"].Status != "fail" {
		t.Fatalf("%+v %+v %+v", checks["operator-cli"], checks["units"], checks["binary"])
	}
	_ = os.MkdirAll(filepath.Join(fx.app, "bin"), 0o755)
	_ = os.MkdirAll(filepath.Dir(fx.d.p.CLITarget), 0o755)
	writeFile(t, fx.d.p.BinPath(), "binary-v2", 0o755)
	writeFile(t, fx.d.p.CLITarget, "binary-v1", 0o755)
	if c := fx.run(t)["operator-cli"]; c.Status != "fail" || !strings.Contains(c.Detail, "drifted") {
		t.Fatalf("%+v", c)
	}
	writeFile(t, fx.d.p.CLITarget, "binary-v2", 0o755)
	if c := fx.run(t)["operator-cli"]; c.Status != "ok" {
		t.Fatalf("%+v", c)
	}
	_ = os.MkdirAll(fx.d.p.SystemdDir, 0o755)
	writeFile(t, filepath.Join(fx.d.p.SystemdDir, "explorer-attachment-cleanup.timer"), "", 0o644)
	if c := fx.run(t)["legacy-units"]; c.Status != "warn" {
		t.Fatalf("%+v", c)
	}
}

func TestDoctorJSONOnBareBox(t *testing.T) {
	fx := newDoctorFixture(t, "")
	checks := fx.d.Diagnose(context.Background())
	raw, err := json.Marshal(checks)
	if err != nil || !bytes.Contains(raw, []byte(`"name":"env-permissions"`)) {
		t.Fatalf("%s %v", raw, err)
	}
	for _, c := range checks {
		if c.Status != "ok" && c.Status != "warn" && c.Status != "fail" {
			t.Fatalf("bad status %+v", c)
		}
	}
}

// ── branch checks against real git repositories ────────────────────────

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=t@example.com", "-c", "user.name=T", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// cloneBehindOrigin makes origin (bare), seed (pushes to it) and clone.
func cloneBehindOrigin(t *testing.T) (base, seed, clone string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base = t.TempDir()
	origin := filepath.Join(base, "origin.git")
	seed = filepath.Join(base, "seed")
	clone = filepath.Join(base, "clone")
	gitT(t, base, "init", "-q", "--bare", "-b", "main", origin)
	gitT(t, base, "init", "-q", "-b", "main", seed)
	writeFile(t, filepath.Join(seed, "file.txt"), "one\n", 0o644)
	gitT(t, seed, "add", ".")
	gitT(t, seed, "commit", "-qm", "one")
	gitT(t, seed, "remote", "add", "origin", origin)
	gitT(t, seed, "push", "-q", "origin", "main")
	gitT(t, base, "clone", "-q", origin, clone)
	return base, seed, clone
}

func branchCheck(t *testing.T, clone string) Check {
	t.Helper()
	fx := newDoctorFixture(t, healthyDotenv())
	fx.d.p.SrcDir = clone
	fx.f.real["git"] = true
	return fx.run(t)["branch"]
}

func pushSeed(t *testing.T, seed, text string) {
	t.Helper()
	writeFile(t, filepath.Join(seed, "file.txt"), text, 0o644)
	gitT(t, seed, "commit", "-qam", text)
	gitT(t, seed, "push", "-q", "origin", "main")
}

func TestDoctorBranch(t *testing.T) {
	_, _, clone := cloneBehindOrigin(t)
	if c := branchCheck(t, clone); c.Status != "ok" || c.Detail != "on main, up to date with origin" {
		t.Fatalf("up to date: %+v", c)
	}

	_, seed, clone := cloneBehindOrigin(t)
	before := gitT(t, clone, "rev-parse", "origin/main")
	pushSeed(t, seed, "two\n")
	if c := branchCheck(t, clone); c.Status != "warn" || c.Detail != "checkout is behind origin/main — run explorer update" {
		t.Fatalf("stale ref: %+v", c)
	}
	if gitT(t, clone, "rev-parse", "origin/main") != before || exists(filepath.Join(clone, ".git", "FETCH_HEAD")) {
		t.Fatal("doctor fetched: the read-only check mutated the checkout")
	}
	gitT(t, clone, "fetch", "-q", "origin", "main")
	if c := branchCheck(t, clone); c.Detail != "checkout is 1 commit(s) behind origin/main — run explorer update" {
		t.Fatalf("exact count: %+v", c)
	}

	_, _, clone = cloneBehindOrigin(t)
	writeFile(t, filepath.Join(clone, "local.txt"), "x", 0o644)
	gitT(t, clone, "add", ".")
	gitT(t, clone, "-c", "user.email=t@example.com", "commit", "-qm", "local")
	if c := branchCheck(t, clone); c.Status != "warn" || !strings.Contains(c.Detail, "1 local commit(s) not on origin/main") {
		t.Fatalf("ahead: %+v", c)
	}

	_, seed, clone = cloneBehindOrigin(t)
	writeFile(t, filepath.Join(clone, "local.txt"), "x", 0o644)
	gitT(t, clone, "add", ".")
	gitT(t, clone, "commit", "-qm", "local")
	pushSeed(t, seed, "two\n")
	gitT(t, clone, "fetch", "-q", "origin", "main")
	if c := branchCheck(t, clone); c.Detail != "checkout and origin/main have diverged — investigate before update" {
		t.Fatalf("diverged: %+v", c)
	}

	base, _, clone := cloneBehindOrigin(t)
	gitT(t, clone, "remote", "set-url", "origin", filepath.Join(base, "gone.git"))
	if c := branchCheck(t, clone); c.Status != "warn" || !strings.Contains(c.Detail, "could not reach origin") {
		t.Fatalf("unreachable: %+v", c)
	}
}
