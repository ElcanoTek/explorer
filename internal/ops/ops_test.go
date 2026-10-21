// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ElcanoTek/explorer/deploy"
	"github.com/ElcanoTek/explorer/internal/dotenv"
)

// rootTempDir is a scratch directory whose ancestors pass the trust checks
// (a root-owned, non-world-writable parent). Root only.
func rootTempDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: the trust checks require root-owned ancestors")
	}
	dir, err := os.MkdirTemp("/var/lib", "explorer-ops-test.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestRequireTrusted(t *testing.T) {
	base := rootTempDir(t)
	src := filepath.Join(base, "src")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, "sub", "f"), "x", 0o644)
	if err := RequireTrusted(src); err != nil {
		t.Fatalf("clean tree rejected: %v", err)
	}
	if err := os.Chmod(filepath.Join(src, "sub", "f"), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := RequireTrusted(src); err == nil {
		t.Fatal("group-writable file accepted")
	}
	_ = os.Chmod(filepath.Join(src, "sub", "f"), 0o644)
	if err := os.Symlink("f", filepath.Join(src, "sub", "link")); err != nil {
		t.Fatal(err)
	}
	if err := RequireTrusted(src); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink accepted: %v", err)
	}
	_ = os.Remove(filepath.Join(src, "sub", "link"))
	if err := os.Chown(filepath.Join(src, "sub"), 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := RequireTrusted(src); err == nil {
		t.Fatal("non-root-owned directory accepted")
	}
	_ = os.Chown(filepath.Join(src, "sub"), 0, 0)
	if err := os.Chmod(src, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := RequireTrusted(src); err == nil {
		t.Fatal("group-writable root accepted")
	}
}

func TestRequireTrustedPathRejectsWorldWritableAncestor(t *testing.T) {
	dir := t.TempDir() // under /tmp (1777) on every runner
	if err := RequireTrustedPath(dir); err == nil {
		t.Skip("TMPDIR has trusted ancestors on this host; nothing to assert")
	}
}

func TestHostsRewrite(t *testing.T) {
	cases := []struct{ name, in, old, want string }{
		{
			"renames a vultr default and keeps aliases",
			"127.0.0.1 localhost vultr.guest vultr\n::1 localhost vultr.guest\n",
			"vultr.guest",
			"127.0.0.1 localhost explorer.example.com explorer\n::1 localhost explorer.example.com explorer\n",
		},
		{
			"never rewrites a localhost-only line, appends instead",
			"127.0.0.1 localhost localhost.localdomain\n",
			"",
			"127.0.0.1 localhost localhost.localdomain\n127.0.0.1 explorer.example.com explorer\n::1 explorer.example.com explorer\n",
		},
		{
			"already named: unchanged",
			"127.0.0.1 explorer.example.com explorer localhost\n",
			"",
			"127.0.0.1 explorer.example.com explorer localhost\n",
		},
		{
			"comments are not names",
			"# 127.0.0.1 explorer.example.com\n127.0.0.1 localhost # explorer.example.com\n",
			"",
			"# 127.0.0.1 explorer.example.com\n127.0.0.1 localhost # explorer.example.com\n127.0.0.1 explorer.example.com explorer\n::1 explorer.example.com explorer\n",
		},
	}
	for _, tc := range cases {
		if got := hostsRewrite(tc.in, tc.old, "explorer.example.com"); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

func hostnameFixture(t *testing.T, current string) (hostEnv, *fakeRunner, *bytes.Buffer, string) {
	t.Helper()
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	writeFile(t, hosts, "127.0.0.1 localhost "+current+"\n", 0o644)
	cloud := filepath.Join(dir, "cloud")
	if err := os.Mkdir(cloud, 0o755); err != nil {
		t.Fatal(err)
	}
	f := newFake("hostnamectl")
	f.handle = func(c Cmd) Result {
		if c.Name == "hostnamectl" && len(c.Args) > 0 && c.Args[0] == "--static" {
			return Result{Stdout: current + "\n"}
		}
		return Result{}
	}
	u, buf := testUI()
	return hostEnv{u: u, r: f, hostsFile: hosts, cloudDir: cloud}, f, buf, dir
}

func TestSetHostnameRenamesDefaultOnce(t *testing.T) {
	t.Setenv("EXPLORER_SET_HOSTNAME", "")
	h, f, _, dir := hostnameFixture(t, "vultr.guest")
	h.setHostname(context.Background(), "Explorer.Example.com")
	if !f.called("hostnamectl set-hostname explorer.example.com") {
		t.Fatalf("not renamed: %v", f.calls)
	}
	if got := readFile(t, filepath.Join(dir, "hosts")); got != "127.0.0.1 localhost explorer.example.com explorer\n" {
		t.Fatalf("hosts = %q", got)
	}
	if !strings.Contains(readFile(t, filepath.Join(dir, "cloud", "cloud.cfg.d", "99-preserve-hostname.cfg")), "preserve_hostname: true") {
		t.Fatal("cloud-init preserve file missing")
	}
}

func TestSetHostnameLeavesDeliberateName(t *testing.T) {
	t.Setenv("EXPLORER_SET_HOSTNAME", "")
	h, f, buf, _ := hostnameFixture(t, "yoga")
	h.setHostname(context.Background(), "explorer.example.com")
	if f.called("hostnamectl set-hostname") || !strings.Contains(buf.String(), "left as is") {
		t.Fatalf("deliberate name touched: %v\n%s", f.calls, buf)
	}
	t.Setenv("EXPLORER_SET_HOSTNAME", "1")
	h.setHostname(context.Background(), "explorer.example.com")
	if !f.called("hostnamectl set-hostname explorer.example.com") {
		t.Fatal("EXPLORER_SET_HOSTNAME=1 did not force the rename")
	}
}

func TestSetHostnameSkips(t *testing.T) {
	t.Setenv("EXPLORER_SET_HOSTNAME", "0")
	h, f, _, _ := hostnameFixture(t, "vultr.guest")
	h.setHostname(context.Background(), "explorer.example.com")
	if len(f.calls) != 0 {
		t.Fatalf("=0 still ran %v", f.calls)
	}
	t.Setenv("EXPLORER_SET_HOSTNAME", "")
	h.setHostname(context.Background(), "10.0.0.1")
	h.setHostname(context.Background(), "nodots")
	if f.called("hostnamectl set-hostname") {
		t.Fatal("renamed to a non-FQDN")
	}
}

func sshFixture(t *testing.T, keys string, sshdT string, sshdTestOK bool) (hostEnv, *fakeRunner, *bytes.Buffer, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/ssh/sshd_config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if keys != "" {
		if err := os.MkdirAll(filepath.Join(root, "root/.ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(root, "root/.ssh/authorized_keys"), keys, 0o600)
	}
	f := newFake("sshd")
	f.handle = func(c Cmd) Result {
		if c.Name == "sshd" && c.Args[0] == "-T" {
			return Result{Stdout: sshdT}
		}
		if c.Name == "sshd" && c.Args[0] == "-t" && !sshdTestOK {
			return Result{Code: 1}
		}
		return Result{}
	}
	u, buf := testUI()
	return hostEnv{u: u, r: f, sshRoot: root}, f, buf, filepath.Join(root, "etc/ssh/sshd_config.d/01-no-password-login.conf")
}

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user@example.com\n"

func TestSSHKeyOnlyInstallsValidatesAndReloads(t *testing.T) {
	t.Setenv("EXPLORER_KEEP_SSH_PASSWORDS", "")
	h, f, _, conf := sshFixture(t, testKey, "passwordauthentication no\n", true)
	h.sshKeyOnly(context.Background())
	if readFile(t, conf) != sshKeyOnlyConf || !f.called("sshd -t") || !f.called("systemctl reload sshd") {
		t.Fatalf("drop-in not installed + validated + reloaded: %v", f.calls)
	}
	fi, _ := os.Stat(conf)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// Idempotent: a second run only re-checks the effective config.
	f.calls = nil
	h.sshKeyOnly(context.Background())
	if f.called("sshd -t") || f.called("systemctl reload") {
		t.Fatalf("second run rewrote: %v", f.calls)
	}
}

func TestSSHKeyOnlySkipsWithoutKeys(t *testing.T) {
	t.Setenv("EXPLORER_KEEP_SSH_PASSWORDS", "")
	h, _, buf, conf := sshFixture(t, "ssh-ed25519 garbage\n", "", true)
	h.sshKeyOnly(context.Background())
	if exists(conf) || !strings.Contains(buf.String(), "no SSH authorized keys") {
		t.Fatalf("installed without a usable key:\n%s", buf)
	}
	h2, _, _, conf2 := sshFixture(t, testKey, "pubkeyauthentication no\n", true)
	h2.sshKeyOnly(context.Background())
	if exists(conf2) {
		t.Fatal("installed although sshd refuses keys")
	}
	t.Setenv("EXPLORER_KEEP_SSH_PASSWORDS", "1")
	h3, f3, _, conf3 := sshFixture(t, testKey, "", true)
	h3.sshKeyOnly(context.Background())
	if exists(conf3) || len(f3.calls) != 0 {
		t.Fatal("EXPLORER_KEEP_SSH_PASSWORDS=1 ignored")
	}
}

func TestSSHKeyOnlyRevertsWhatSshdRejects(t *testing.T) {
	t.Setenv("EXPLORER_KEEP_SSH_PASSWORDS", "")
	h, f, buf, conf := sshFixture(t, testKey, "", false)
	h.sshKeyOnly(context.Background())
	if exists(conf) || f.called("systemctl reload") || !strings.Contains(buf.String(), "reverted") {
		t.Fatalf("rejected drop-in kept: %v\n%s", f.calls, buf)
	}
	h2, _, _, conf2 := sshFixture(t, testKey, "", false)
	writeFile(t, conf2, "# hand-made\n", 0o600)
	h2.sshKeyOnly(context.Background())
	if readFile(t, conf2) != "# hand-made\n" {
		t.Fatal("previous drop-in not restored")
	}
}

func TestSSHKeyOnlyWarnsWhenEarlierDirectiveWins(t *testing.T) {
	t.Setenv("EXPLORER_KEEP_SSH_PASSWORDS", "")
	h, _, buf, _ := sshFixture(t, testKey, "PermitRootLogin yes\n", true)
	h.sshKeyOnly(context.Background())
	if !strings.Contains(buf.String(), "an earlier directive wins") {
		t.Fatalf("no warning:\n%s", buf)
	}
}

func TestCockpitRemoval(t *testing.T) {
	t.Setenv("EXPLORER_KEEP_COCKPIT", "")
	f := newFake("rpm")
	u, _ := testUI()
	hostEnv{u: u, r: f}.removeCockpit(context.Background())
	if !f.called("dnf -y remove cockpit*") {
		t.Fatalf("cockpit not removed: %v", f.calls)
	}

	f = newFake("rpm")
	f.handle = func(c Cmd) Result {
		if c.Name == "rpm" {
			return Result{Code: 1}
		}
		return Result{}
	}
	hostEnv{u: u, r: f}.removeCockpit(context.Background())
	if f.called("dnf") {
		t.Fatal("removed although cockpit-ws is absent")
	}

	f = newFake("rpm")
	f.handle = func(c Cmd) Result {
		if c.Name == "dnf" {
			return Result{Code: 1}
		}
		return Result{}
	}
	u2, buf := testUI()
	hostEnv{u: u2, r: f}.removeCockpit(context.Background())
	if !strings.Contains(buf.String(), "could not remove Cockpit") {
		t.Fatal("failure should only warn")
	}

	t.Setenv("EXPLORER_KEEP_COCKPIT", "1")
	f = newFake("rpm")
	hostEnv{u: u, r: f}.removeCockpit(context.Background())
	if len(f.calls) != 0 {
		t.Fatal("EXPLORER_KEEP_COCKPIT=1 ignored")
	}
}

func TestCaddyTemplateContract(t *testing.T) {
	lines := strings.Split(string(deploy.CaddySite), "\n")
	if lines[0] != CaddyMarker {
		t.Fatalf("template lost its marker: %q", lines[0])
	}
	if !strings.Contains(string(deploy.CaddySite), "reverse_proxy 127.0.0.1:8080") {
		t.Fatal("template upstream changed; bootstrap checks 127.0.0.1:8080")
	}
	site := renderCaddySite("explorer.example", false)
	if !strings.Contains(site, "explorer.example {\n\ttls internal\n") {
		t.Fatalf("tls internal not injected:\n%s", site)
	}
	if strings.Contains(renderCaddySite("explorer.example", true), "\ttls internal") {
		t.Fatal("tls internal with Let's Encrypt")
	}
}

func TestCaddyPlanUsesALoadedGlob(t *testing.T) {
	cases := []struct {
		line, target string
		addImport    bool
	}{
		{"import Caddyfile.d/*.caddyfile", "Caddyfile.d/explorer.caddyfile", false},
		{"", "conf.d/explorer.caddy", true},
		{`import "Caddyfile.d/*.caddyfile"`, "Caddyfile.d/explorer.caddyfile", false},
		{"import ./conf.d/*", "conf.d/explorer.caddy", false},
		{"import conf.d/*.caddy", "conf.d/explorer.caddy", false},
		{"import sites-enabled/*.caddy", "sites-enabled/explorer.caddy", false},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		cf := filepath.Join(dir, "Caddyfile")
		writeFile(t, cf, tc.line+"\n", 0o644)
		plan, err := planCaddySite(cf)
		if err != nil || plan.target != filepath.Join(dir, tc.target) || plan.addImport != tc.addImport {
			t.Errorf("%q: plan=%+v err=%v", tc.line, plan, err)
		}
	}
	dir := t.TempDir()
	cf := filepath.Join(dir, "Caddyfile")
	writeFile(t, cf, `import "`+filepath.Join(dir, "different", "*.caddyfile")+`"`+"\n", 0o644)
	if plan, _ := planCaddySite(cf); plan.target != filepath.Join(dir, "different", "explorer.caddyfile") {
		t.Errorf("absolute import: %+v", plan)
	}
}

func TestCaddyPlanKeepsLoadedCopyAndRemovesOwnedOrphan(t *testing.T) {
	for _, orphanImported := range []bool{false, true} {
		dir := t.TempDir()
		cf := filepath.Join(dir, "Caddyfile")
		imports := "import Caddyfile.d/*.caddyfile\n"
		if orphanImported {
			imports += "import conf.d/*.caddy\n"
		}
		writeFile(t, cf, imports, 0o644)
		content := CaddyMarker + "\nexplorer.example {\n}\n"
		loaded := filepath.Join(dir, "Caddyfile.d", "explorer.caddyfile")
		orphan := filepath.Join(dir, "conf.d", "explorer.caddy")
		unrelated := filepath.Join(dir, "conf.d", "other.caddy")
		for _, p := range []string{loaded, orphan} {
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			writeFile(t, p, content, 0o644)
		}
		writeFile(t, unrelated, "other.example {\n}\n", 0o644)
		plan, err := planCaddySite(cf)
		if err != nil || plan.target != loaded {
			t.Fatalf("plan = %+v, %v", plan, err)
		}
		removed, err := removeStaleCaddySites(cf, plan)
		if err != nil || len(removed) != 1 || removed[0] != orphan || !exists(loaded) || !exists(unrelated) {
			t.Fatalf("removed=%v err=%v", removed, err)
		}
	}
	// An unmarked file is never removed; a marked one for an old host is.
	dir := t.TempDir()
	cf := filepath.Join(dir, "Caddyfile")
	writeFile(t, cf, "import Caddyfile.d/*.caddyfile\n", 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "conf.d"), 0o755)
	writeFile(t, filepath.Join(dir, "conf.d", "explorer.caddy"), "explorer.example {\n}\n", 0o644)
	writeFile(t, filepath.Join(dir, "conf.d", "old.caddy"), CaddyMarker+"\nother.example {\n}\n", 0o644)
	plan, _ := planCaddySite(cf)
	if _, err := removeStaleCaddySites(cf, plan); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(dir, "conf.d", "explorer.caddy")) || exists(filepath.Join(dir, "conf.d", "old.caddy")) {
		t.Fatal("cleanup removed the wrong file")
	}
}

func TestCaddySiteHost(t *testing.T) {
	dir := t.TempDir()
	cf := filepath.Join(dir, "Caddyfile")
	writeFile(t, cf, "import sites-enabled/*.caddy\n", 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "sites-enabled"), 0o755)
	if p, h := caddySiteHost(cf); p != "" || h != "" {
		t.Fatalf("found a site that is not there: %s %s", p, h)
	}
	writeFile(t, filepath.Join(dir, "sites-enabled", "explorer.caddy"), CaddyMarker+"\n# comment\nexplorer.example {\n}\n", 0o644)
	if p, h := caddySiteHost(cf); p != filepath.Join(dir, "sites-enabled", "explorer.caddy") || h != "explorer.example" {
		t.Fatalf("got %s %s", p, h)
	}
}

func TestAdaptedHasSite(t *testing.T) {
	route := map[string]any{
		"match": []any{map[string]any{"host": []any{"other.example"}}},
		"handle": []any{map[string]any{"handler": "subroute", "routes": []any{map[string]any{
			"handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": "127.0.0.1:8080"}}}},
		}}}},
	}
	doc := map[string]any{"email": "explorer.example", "apps": map[string]any{"http": map[string]any{"servers": map[string]any{"srv0": map[string]any{"routes": []any{route}}}}}}
	enc := func() []byte { b, _ := json.Marshal(doc); return b }
	if adaptedHasSite(enc(), "explorer.example", "127.0.0.1:8080") {
		t.Fatal("matched a route for another host")
	}
	route["match"] = []any{map[string]any{"host": []any{"explorer.example"}}}
	if !adaptedHasSite(enc(), "explorer.example", "127.0.0.1:8080") {
		t.Fatal("did not find the site")
	}
	if adaptedHasSite(enc(), "explorer.example", "127.0.0.1:9999") {
		t.Fatal("matched the wrong upstream")
	}
}

// encryptBundle produces what `openssl enc -aes-256-cbc -pbkdf2 -iter
// 600000 -salt` writes.
func encryptBundle(t *testing.T, plain []byte, pass string) []byte {
	t.Helper()
	salt := make([]byte, 8)
	_, _ = rand.Read(salt)
	keyIV, err := pbkdf2.Key(sha256.New, pass, salt, bundleIterations, 48)
	if err != nil {
		t.Fatal(err)
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, _ := aes.NewCipher(keyIV[:32])
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, keyIV[32:]).CryptBlocks(out, padded)
	return append(append([]byte(opensslMagic), salt...), out...)
}

func TestDecryptBundle(t *testing.T) {
	plain := []byte("EMAIL_S3_BUCKET=acme-archive\nAWS_REGION=us-east-2\n")
	enc := encryptBundle(t, plain, "correct horse")
	got, err := decryptBundle(enc, "correct horse")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := decryptBundle(enc, "wrong"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if _, err := decryptBundle([]byte("plain text"), "x"); err == nil {
		t.Fatal("non-bundle accepted")
	}
}

func TestDecryptBundleFromOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "acme.env")
	writeFile(t, in, "A=1\nB=two words\n", 0o600)
	cmd := exec.Command("openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "600000", "-salt", "-in", in, "-out", in+".enc", "-pass", "stdin")
	cmd.Stdin = strings.NewReader("s3cret pass\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("openssl enc failed: %v %s", err, out)
	}
	raw, _ := os.ReadFile(in + ".enc")
	got, err := decryptBundle(raw, passphraseLine("s3cret pass\n"))
	if err != nil || string(got) != "A=1\nB=two words\n" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestMergeProvisionBlock(t *testing.T) {
	begin, end := provisionMarkers("acme")
	current := "SECRET=keep\nAWS_REGION=us-east-1\n\n" + begin + "\nOLD=1\n" + end + "\n"
	merged, n, collisions := mergeProvisionBlock(current, "# comment\nAWS_REGION=us-east-2\nNEW=2\nnot a binding\n", "acme")
	want := "SECRET=keep\nAWS_REGION=us-east-1\n\n" + begin + "\nAWS_REGION=us-east-2\nNEW=2\n" + end + "\n"
	if merged != want {
		t.Fatalf("merged:\n%q\nwant\n%q", merged, want)
	}
	if n != 1 || len(collisions) != 1 || collisions[0] != "AWS_REGION" {
		t.Fatalf("n=%d collisions=%v", n, collisions)
	}
	again, _, _ := mergeProvisionBlock(merged, "AWS_REGION=us-east-2\nNEW=2\n", "acme")
	if again != merged {
		t.Fatalf("re-provision is not stable:\n%q", again)
	}
	if !strings.HasPrefix(begin, dotenv.ProvisionBegin) || !strings.HasPrefix(end, dotenv.ProvisionEnd) {
		t.Fatal("markers no longer match what bootstrap's merge leaves alone")
	}
}

func TestProvisionWritesPrivateFiles(t *testing.T) {
	base := rootTempDir(t)
	p := Paths{SrcDir: filepath.Join(base, "src"), AppDir: filepath.Join(base, "app"), AppUser: "root", Service: "explorer.service"}
	clients := filepath.Join(p.SrcDir, "provision", "clients")
	if err := os.MkdirAll(clients, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.AppDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clients, "acme.env.enc"), encryptBundle(t, []byte("K=v\n"), "pw"), 0o600); err != nil {
		t.Fatal(err)
	}
	passFile := filepath.Join(base, "elcano", "passphrase")
	t.Setenv("ELCANO_PASSPHRASE_FILE", passFile)
	t.Setenv("EXPLORER_PROVISION_PASSPHRASE", "pw")
	u, buf := testUI()
	f := newFake()
	err := provision(context.Background(), u, f, p, provisionOpts{restart: true, nonInteractive: true}, &prompter{u: u, nonInteractive: true})
	if err != nil {
		t.Fatalf("%v\n%s", err, buf)
	}
	fi, _ := os.Stat(p.EnvFile())
	if fi.Mode().Perm() != 0o600 || !strings.Contains(readFile(t, p.EnvFile()), "\nK=v\n") {
		t.Fatalf("env %v:\n%s", fi.Mode(), readFile(t, p.EnvFile()))
	}
	if !f.called("systemctl restart explorer.service") {
		t.Fatalf("no restart: %v", f.calls)
	}
	// Every file in the app dir stays private, including leftovers.
	_ = filepath.WalkDir(p.AppDir, func(path string, d fs.DirEntry, _ error) error {
		if !d.IsDir() {
			if info, _ := d.Info(); info.Mode().Perm()&0o077 != 0 {
				t.Errorf("%s is %v", path, info.Mode())
			}
		}
		return nil
	})
	// A linked .env is refused.
	_ = os.Remove(p.EnvFile())
	_ = os.Symlink("/etc/passwd", p.EnvFile())
	if err := provision(context.Background(), u, f, p, provisionOpts{nonInteractive: true}, &prompter{u: u, nonInteractive: true}); err == nil {
		t.Fatal("provision wrote through a symlink")
	}
}

func TestRedactEnv(t *testing.T) {
	in := "# comment\n  # indented comment\nEMAIL_S3_BUCKET=b\nAWS_SECRET_ACCESS_KEY=\"s\"\nAUTH_CLIENT_SECRET=x=y\nMY_TOKEN=t\nDB_PASSWORD=p\n\nnoequals\nAWS_REGION=us-east-2\n"
	want := "EMAIL_S3_BUCKET=b\nAWS_SECRET_ACCESS_KEY=[REDACTED]\nAUTH_CLIENT_SECRET=[REDACTED]\nMY_TOKEN=[REDACTED]\nDB_PASSWORD=[REDACTED]\nAWS_REGION=us-east-2\n"
	if got := redactEnv(in); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestCollectAnswersPrecedenceAndScriptedInstall(t *testing.T) {
	u, _ := testUI()
	pr := &prompter{u: u, nonInteractive: true}
	env := map[string]string{
		"EXPLORER_AUTH_MODE": "central", "AUTH_SIGNING_PUBKEY": "env-key",
		"AUTH_ISSUER_URL": "https://auth.example.com", "EXPLORER_PUBLIC_URL": "https://explorer.example.com",
		"AUTH_CLIENT_ID": "explorer", "EXPLORER_BOOTSTRAP_HOSTNAME": "explorer.example.com",
		"EXPLORER_BOOTSTRAP_SETUP_CADDY": "Y", "EXPLORER_BOOTSTRAP_USE_LETSENCRYPT": "Y", "AWS_REGION": "us-east-2",
	}
	getenv := func(k string) string { return env[k] }
	// Non-interactive without the secret fails, naming the variable.
	if _, err := collectAnswers(pr, map[string]string{}, getenv); err == nil || !strings.Contains(err.Error(), "AUTH_CLIENT_SECRET") {
		t.Fatalf("err = %v", err)
	}
	current := map[string]string{"AUTH_CLIENT_SECRET": strings.Repeat("s", 40), "AUTH_SIGNING_PUBKEY": "file-key", "EXPLORER_SESSION_SECRET": "kept"}
	a, err := collectAnswers(pr, current, getenv)
	if err != nil {
		t.Fatal(err)
	}
	if a.values["AUTH_SIGNING_PUBKEY"] != "file-key" || a.values["EXPLORER_SESSION_SECRET"] != "kept" ||
		a.values["EXPLORER_AUTH_MODE"] != "central" || !a.setupCaddy || !a.letsEncrypt || a.hostname != "explorer.example.com" {
		t.Fatalf("answers = %+v", a)
	}
	// Blank optional answers are fine non-interactively.
	if a2, err := collectAnswers(pr, map[string]string{}, func(string) string { return "" }); err != nil || a2.values["EXPLORER_AUTH_MODE"] != "elcano" || len(a2.values["EXPLORER_SESSION_SECRET"]) < 32 {
		t.Fatalf("elcano defaults: %+v %v", a2, err)
	}
	env["EXPLORER_AUTH_MODE"] = "local"
	if _, err := collectAnswers(pr, current, getenv); err == nil || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("local mode: %v", err)
	}
}

func TestEnvTemplateRoundTrips(t *testing.T) {
	v := map[string]string{}
	for _, k := range envManagedKeys {
		v[k] = `a"b\c $d ` + k
	}
	text := envTemplate(v, time.Unix(0, 0))
	got := dotenv.EffectiveValues(text, nil, envManagedKeys)
	for _, k := range envManagedKeys {
		if got[k] != v[k] {
			t.Errorf("%s = %q, want %q", k, got[k], v[k])
		}
	}
	if strings.Contains(text, "$(") || strings.Contains(text, "`") {
		t.Fatal("template contains shell syntax")
	}
}

func TestParseUpdateArgs(t *testing.T) {
	t.Setenv("EXPLORER_UPDATE_YES", "")
	t.Setenv("EXPLORER_UPDATE_NO_PULL", "")
	if o, _ := parseUpdateArgs(nil, false); o.yes || o.noPull {
		t.Fatalf("%+v", o)
	}
	if o, _ := parseUpdateArgs([]string{"--yes"}, false); !o.yes {
		t.Fatal("--yes ignored")
	}
	t.Setenv("EXPLORER_UPDATE_YES", "1")
	if o, _ := parseUpdateArgs(nil, false); !o.yes {
		t.Fatal("EXPLORER_UPDATE_YES ignored")
	}
	if o, _ := parseUpdateArgs(nil, true); !o.noPull || !o.yes {
		t.Fatal("rebuild must skip the fetch and the prompt")
	}
	if _, err := parseUpdateArgs([]string{"--bogus"}, false); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if !confirmed(readLine(strings.NewReader("y\n"))) || confirmed(readLine(strings.NewReader(""))) {
		t.Fatal("piped answers misread")
	}
}

func TestUsageNamesEveryVerb(t *testing.T) {
	for _, verb := range []string{"serve", "start | stop | restart | status", "logs", "update", "rebuild", "doctor", "provision", "tls status", "env edit", "access grant", "version", "bootstrap"} {
		if !strings.Contains(Usage, "explorer "+verb) {
			t.Errorf("Usage lacks %q", verb)
		}
	}
}

func TestResolveGoUsesAnAbsoluteFallback(t *testing.T) {
	fallback := filepath.Join(t.TempDir(), "go")
	if err := os.WriteFile(fallback, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveGo(newFake(), fallback); err != nil || got != fallback {
		t.Fatalf("fallback = %q, %v", got, err)
	}
	if got, err := resolveGo(newFake("go"), fallback); err != nil || got != "/usr/bin/go" {
		t.Fatalf("PATH go = %q, %v", got, err)
	}
	if _, err := resolveGo(newFake(), filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("missing toolchain not reported")
	}
}
