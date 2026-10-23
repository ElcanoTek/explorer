// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ElcanoTek/explorer/deploy"
)

// The privileged install lifecycle, end to end, against a scratch tree.
// Root only (CI runs it under sudo): ownership is the thing under test.
//
//	sudo env "PATH=$PATH" "GOCACHE=$(go env GOCACHE)" "GOMODCACHE=$(go env GOMODCACHE)" \
//	  go test -count=1 -run 'TestLifecycle' ./internal/ops/

const (
	testServiceUser = "daemon"
	revOld          = "1111111111111111111111111111111111111111"
	revNew          = "2222222222222222222222222222222222222222"
)

type lifecycle struct {
	t      *testing.T
	base   string
	p      Paths
	f      *fakeRunner
	health *int
	binary string
}

func newLifecycle(t *testing.T) *lifecycle {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the install lifecycle test needs root (CI runs it with sudo)")
	}
	acct, err := lookupAccount(testServiceUser)
	if err != nil {
		t.Skipf("needs the standard %s account: %v", testServiceUser, err)
	}
	base := rootTempDir(t)
	code := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
	t.Cleanup(srv.Close)
	lc := &lifecycle{t: t, base: base, health: &code}
	lc.p = Paths{
		SrcDir: filepath.Join(base, "src"), AppDir: filepath.Join(base, "app"), AppUser: testServiceUser,
		StateDir: filepath.Join(base, "state"), BuildCache: filepath.Join(base, "cache"),
		SystemdDir: filepath.Join(base, "systemd"), TmpfilesDir: filepath.Join(base, "tmpfiles"),
		CLITarget: filepath.Join(base, "usr-local-bin", "explorer"), MotdTarget: filepath.Join(base, "motd"),
		LockFile: filepath.Join(base, "update.lock"), HealthURL: srv.URL + "/health", HealthAttempts: 1,
		Service: "explorer.service", Caddyfile: filepath.Join(base, "Caddyfile"),
	}
	// The verified checkout: a root-owned git repository.
	for _, d := range []string{lc.p.SrcDir, lc.p.SystemdDir, lc.p.TmpfilesDir, filepath.Dir(lc.p.CLITarget)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(lc.p.SrcDir, "go.mod"), "module example\n", 0o644)
	if _, err := exec.LookPath("git"); err == nil {
		gitT(t, lc.p.SrcDir, "init", "-q", "-b", "main")
		gitT(t, lc.p.SrcDir, "add", ".")
		gitT(t, lc.p.SrcDir, "commit", "-qm", "fixture")
	}
	lc.binary = filepath.Join(base, "staged-explorer")
	writeFile(t, lc.binary, "#!/bin/sh\necho new binary\n", 0o755)
	lc.f = newFake()
	lc.f.handle = func(c Cmd) Result {
		if c.Name == "systemctl" && len(c.Args) > 0 && c.Args[0] == "is-enabled" {
			return Result{} // the legacy timer was enabled
		}
		return Result{}
	}
	lc.seedLegacy(acct)
	return lc
}

// seedLegacy lays down a Python-era install: a service-owned tree, venv,
// scratch space, old bash CLI and the attachment-cleanup timer.
func (lc *lifecycle) seedLegacy(acct account) {
	t := lc.t
	_ = os.RemoveAll(lc.p.AppDir)
	for _, d := range []string{"app", ".venv/bin", ".tmp/email_attachments"} {
		if err := os.MkdirAll(filepath.Join(lc.p.AppDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(lc.p.AppDir, "app", "old-marker"), "old-app\n", 0o644)
	writeFile(t, filepath.Join(lc.p.AppDir, ".venv", "bin", "python"), "old-venv\n", 0o755)
	writeFile(t, filepath.Join(lc.p.AppDir, ".env"), "SECRET=\"kept\"\n", 0o644)
	_ = filepath.Walk(lc.p.AppDir, func(path string, _ os.FileInfo, _ error) error {
		return os.Lchown(path, acct.uid, acct.gid)
	})
	for _, target := range systemTargets(lc.p) {
		writeFile(t, target, "old-privileged\n", 0o644)
	}
	_ = os.Chmod(lc.p.CLITarget, 0o755)
}

func (lc *lifecycle) apply() error {
	u, _ := testUI()
	return applyUpdate(context.Background(), u, lc.f, lc.p, applyInput{binary: lc.binary, before: revOld, after: revNew})
}

func ownerMode(t *testing.T, path string) (uint32, uint32, os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := statT(fi)
	return st.Uid, st.Gid, fi.Mode().Perm()
}

func noBackupsLeft(t *testing.T, base string) {
	t.Helper()
	if m, _ := filepath.Glob(filepath.Join(base, ".explorer-backup.*")); len(m) != 0 {
		t.Fatalf("backup left behind: %v", m)
	}
}

func TestLifecycleUpdateMigratesALegacyInstall(t *testing.T) {
	lc := newLifecycle(t)
	if err := lc.apply(); err != nil {
		t.Fatal(err)
	}
	p := lc.p
	if uid, gid, mode := ownerMode(t, p.AppDir); uid != 0 || gid != 0 || mode != 0o755 {
		t.Fatalf("app dir %d:%d %v", uid, gid, mode)
	}
	if uid, _, mode := ownerMode(t, p.BinPath()); uid != 0 || mode != 0o755 || readFile(t, p.BinPath()) != readFile(t, lc.binary) {
		t.Fatalf("binary %d %v", uid, mode)
	}
	if strings.TrimSpace(readFile(t, p.RevisionFile())) != revNew || !revisionMatches(p, revNew) {
		t.Fatal("revision marker wrong")
	}
	acct, _ := lookupAccount(testServiceUser)
	if uid, _, mode := ownerMode(t, p.EnvFile()); int(uid) != acct.uid || mode != 0o600 || readFile(t, p.EnvFile()) != "SECRET=\"kept\"\n" {
		t.Fatalf(".env %d %v", uid, mode)
	}
	for _, gone := range []string{"app", ".venv", ".tmp"} {
		if exists(filepath.Join(p.AppDir, gone)) {
			t.Errorf("legacy %s survived", gone)
		}
	}
	// Moved aside, not deleted: its names (app, docs, scripts) are generic.
	if preserved(t, p, filepath.Join("app", "old-marker")) != "old-app\n" || preserved(t, p, filepath.Join(".venv", "bin", "python")) != "old-venv\n" {
		t.Fatal("the Python-era tree was not preserved")
	}
	for _, legacy := range p.legacyUnits() {
		if exists(legacy) {
			t.Errorf("%s survived", legacy)
		}
	}
	if readFile(t, p.UnitPath()) != string(deploy.ServiceUnit) || readFile(t, p.TmpfilesPath()) != string(deploy.TmpfilesConf) ||
		readFile(t, p.MotdTarget) != string(deploy.Motd) || readFile(t, p.CLITarget) != readFile(t, lc.binary) {
		t.Fatal("privileged files not installed from the release")
	}
	if !lc.f.called("systemctl disable --now explorer-attachment-cleanup.timer") || !lc.f.called("systemctl start explorer.service") {
		t.Fatalf("calls: %v", lc.f.calls)
	}
	if err := layoutCheck(p); err != nil {
		t.Fatal(err)
	}
	noBackupsLeft(t, lc.base)

	// The service account cannot touch the installed program.
	if out, err := exec.Command("runuser", "-u", testServiceUser, "--", "touch", filepath.Join(p.AppDir, "bin", "service-write")).CombinedOutput(); err == nil {
		t.Fatalf("service user wrote into the program directory: %s", out)
	}
}

func TestLifecycleUnhealthyUpdateRollsBack(t *testing.T) {
	lc := newLifecycle(t)
	*lc.health = http.StatusInternalServerError
	if err := lc.apply(); err == nil {
		t.Fatal("an unhealthy update succeeded")
	}
	p := lc.p
	if readFile(t, filepath.Join(p.AppDir, "app", "old-marker")) != "old-app\n" ||
		readFile(t, filepath.Join(p.AppDir, ".venv", "bin", "python")) != "old-venv\n" || !exists(filepath.Join(p.AppDir, ".tmp")) {
		t.Fatal("legacy tree not restored")
	}
	if exists(p.BinPath()) || exists(p.RevisionFile()) {
		t.Fatal("new files survived the rollback")
	}
	for _, target := range systemTargets(p) {
		if readFile(t, target) != "old-privileged\n" {
			t.Errorf("%s not restored", target)
		}
	}
	if _, _, mode := ownerMode(t, p.CLITarget); mode != 0o755 {
		t.Fatalf("CLI mode %v", mode)
	}
	if !lc.f.called("systemctl enable --now explorer-attachment-cleanup.timer") {
		t.Fatal("the legacy timer was not re-enabled")
	}
	noBackupsLeft(t, lc.base)

	// A second, healthy attempt from the restored state succeeds.
	*lc.health = http.StatusOK
	if err := lc.apply(); err != nil {
		t.Fatal(err)
	}
}

// seedForeign adds files Explorer does not own: an env backup another tool
// left (owned by the service user, like the env file it copied) and an
// operator's notes.
func (lc *lifecycle) seedForeign(acct account) {
	backup := filepath.Join(lc.p.AppDir, ".env.backup.20261020T101010Z.AbC123")
	writeFile(lc.t, backup, "OLD_SECRET=1\n", 0o600)
	if err := os.Lchown(backup, acct.uid, acct.gid); err != nil {
		lc.t.Fatal(err)
	}
	writeFile(lc.t, filepath.Join(lc.p.AppDir, "operator-notes.txt"), "keep me\n", 0o644)
}

func preserved(t *testing.T, p Paths, name string) string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(p.PreservedDir(), "*", name))
	if len(m) != 1 {
		t.Fatalf("%s preserved %d times: %v", name, len(m), m)
	}
	return readFile(t, m[0])
}

func TestLifecycleUpdateKeepsFilesItDoesNotOwn(t *testing.T) {
	lc := newLifecycle(t)
	acct, _ := lookupAccount(testServiceUser)
	lc.seedForeign(acct)
	if err := lc.apply(); err != nil {
		t.Fatal(err)
	}
	p := lc.p
	if preserved(t, p, ".env.backup.20261020T101010Z.AbC123") != "OLD_SECRET=1\n" ||
		preserved(t, p, "operator-notes.txt") != "keep me\n" {
		t.Fatal("foreign files changed")
	}
	if exists(filepath.Join(p.AppDir, "operator-notes.txt")) {
		t.Fatal("foreign file left in the app directory")
	}
	if err := layoutCheck(p); err != nil {
		t.Fatal(err)
	}
	noBackupsLeft(t, lc.base)
}

func TestLifecycleRolledBackUpdateStillKeepsFilesItDoesNotOwn(t *testing.T) {
	lc := newLifecycle(t)
	acct, _ := lookupAccount(testServiceUser)
	lc.seedForeign(acct)
	*lc.health = http.StatusInternalServerError
	if err := lc.apply(); err == nil {
		t.Fatal("an unhealthy update succeeded")
	}
	// A rollback puts back exactly what the update moved aside.
	if readFile(t, filepath.Join(lc.p.AppDir, "operator-notes.txt")) != "keep me\n" ||
		readFile(t, filepath.Join(lc.p.AppDir, ".env.backup.20261020T101010Z.AbC123")) != "OLD_SECRET=1\n" {
		t.Fatal("a rollback did not restore the foreign files")
	}
	if readFile(t, filepath.Join(lc.p.AppDir, "app", "old-marker")) != "old-app\n" {
		t.Fatal("legacy tree not restored")
	}
}

func TestLifecycleRefusesUntrustedSource(t *testing.T) {
	lc := newLifecycle(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	u, _ := testUI()
	run := func() error {
		return runUpdate(context.Background(), u, lc.f, lc.p, true, nil, strings.NewReader(""))
	}
	if err := os.Chmod(lc.p.SrcDir, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil || !strings.Contains(err.Error(), "not safe") {
		t.Fatalf("group-writable source: %v", err)
	}
	_ = os.Chmod(lc.p.SrcDir, 0o755)
	if err := os.Symlink("go.mod", filepath.Join(lc.p.SrcDir, "service-link")); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked source: %v", err)
	}
	if lc.f.called("systemctl stop") {
		t.Fatal("an untrusted source reached the swap")
	}
}

func TestLifecycleLockIsExclusive(t *testing.T) {
	lc := newLifecycle(t)
	held, err := acquireLock(lc.p.LockFile)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := lc.apply(); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second update ran concurrently: %v", err)
	}
}
