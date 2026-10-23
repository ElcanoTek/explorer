// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/ElcanoTek/explorer/internal/config"
	"github.com/ElcanoTek/explorer/internal/dotenv"
)

// acquireLock takes the update lock (non-blocking). The returned file holds
// it until closed or the process exits.
func acquireLock(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // G301: a public, root-owned directory by design.
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // G304: a path the installer chose, not request input.
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("another Explorer update is already running")
	}
	return f, nil
}

// readLine reads one answer from in (a pipe works: `echo y | explorer update`).
func readLine(in io.Reader) string {
	line, _ := bufio.NewReader(in).ReadString('\n')
	return strings.TrimSpace(line)
}

func confirmed(answer string) bool {
	switch strings.ToLower(answer) {
	case "y", "yes":
		return true
	}
	return false
}

type updateOpts struct {
	noPull, yes bool
	branch      string
	baseSHA     string
}

func parseUpdateArgs(args []string, rebuild bool) (updateOpts, error) {
	o := updateOpts{
		noPull:  rebuild || os.Getenv("EXPLORER_UPDATE_NO_PULL") == "1",
		yes:     rebuild || config.Truthy(os.Getenv("EXPLORER_UPDATE_YES")),
		branch:  os.Getenv("EXPLORER_UPDATE_BRANCH"),
		baseSHA: os.Getenv("EXPLORER_UPDATE_BASE_SHA"),
	}
	for _, a := range args {
		switch a {
		case "--yes", "-y":
			o.yes = true
		case "--no-pull":
			o.noPull = true
		default:
			return o, usageError{"unknown update flag: " + a + " (try: explorer update [--yes])"}
		}
	}
	return o, nil
}

// runUpdate is phase one of an update: verify the checkout, fetch and
// fast-forward it, build the new binary into staging, and hand the swap to
// that new binary (runApply), so the new release's own install logic always
// performs the install.
func runUpdate(ctx context.Context, u *ui, r Runner, p Paths, rebuild bool, args []string, stdin io.Reader) error {
	o, err := parseUpdateArgs(args, rebuild)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("run as root: sudo explorer update")
	}
	if fi, err := os.Lstat(filepath.Join(p.SrcDir, ".git")); err != nil || fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("no real source checkout at %s", p.SrcDir)
	}
	if fi, err := os.Lstat(p.AppDir); err != nil || !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("no existing install at %s (run scripts/bootstrap.sh)", p.AppDir)
	}
	if err := RequireTrusted(p.SrcDir); err != nil {
		return fmt.Errorf("%s is not safe for root-run updates: %w", p.SrcDir, err)
	}
	lock, err := acquireLock(p.LockFile)
	if err != nil {
		return err
	}
	defer lock.Close()

	u.stepf("1/4  Fetching latest")
	before, err := gitOut(ctx, r, p.SrcDir, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	after := before
	if o.noPull {
		if o.baseSHA != "" {
			before = o.baseSHA
		}
		u.okf("rebuild-only mode — skipping fetch, building %s", short(after))
	} else {
		after, err = fetchAndMerge(ctx, u, r, p, o, before, stdin)
		if err != nil || after == "" {
			return err
		}
	}

	if !exists(filepath.Join(p.SrcDir, "go.mod")) {
		// A rollback to a commit from before the Go rewrite: that tree's own
		// update script knows how to install it.
		u.warnf("%s predates the Go rewrite — handing over to its scripts/update.sh", short(after))
		env := append(os.Environ(), "EXPLORER_UPDATE_NO_PULL=1", "EXPLORER_UPDATE_YES=1", "EXPLORER_UPDATE_BASE_SHA="+before, "SRC_DIR="+p.SrcDir, "APP_DIR="+p.AppDir)
		_ = lock.Close()
		if code := r.Interactive(ctx, Cmd{Name: "bash", Args: []string{filepath.Join(p.SrcDir, "scripts/update.sh")}, Env: env}); code != 0 {
			return exitCodeError{code}
		}
		return nil
	}

	if err := ensureAuthPubkey(u, p, stdin); err != nil {
		return err
	}

	u.stepf("2/4  Building the new binary in staging")
	staging, err := newStaging(p, ".explorer-build.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	staged := filepath.Join(staging, "explorer")
	if err := buildBinary(ctx, u, r, p, p.SrcDir, staged, after); err != nil {
		return fmt.Errorf("%w\nbuild failed — the installed service was not changed", err)
	}
	u.okf("staged build ready")

	env := append(os.Environ(), p.Env()...)
	env = append(env, "EXPLORER_UPDATE_BINARY="+staged, "EXPLORER_UPDATE_BEFORE="+before,
		"EXPLORER_UPDATE_AFTER="+after, "EXPLORER_UPDATE_LOCKED=1")
	if code := r.Interactive(ctx, Cmd{Name: staged, Args: []string{applyVerb}, Env: env}); code != 0 {
		return exitCodeError{code}
	}
	return nil
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// fetchAndMerge fetches origin and fast-forwards the target branch. It
// returns "" (and nil) when there is nothing to do.
func fetchAndMerge(ctx context.Context, u *ui, r Runner, p Paths, o updateOpts, before string, stdin io.Reader) (string, error) {
	if _, err := gitOut(ctx, r, p.SrcDir, "fetch", "--quiet", "origin"); err != nil {
		return "", err
	}
	current, _ := gitOut(ctx, r, p.SrcDir, "symbolic-ref", "--quiet", "--short", "HEAD")
	target := o.branch
	switch {
	case target != "":
	case current != "":
		target = current
	default:
		head, _ := gitOut(ctx, r, p.SrcDir, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
		target = strings.TrimPrefix(head, "origin/")
		if target == "" {
			return "", errors.New("detached checkout has no origin/HEAD; set EXPLORER_UPDATE_BRANCH")
		}
		u.warnf("HEAD is detached — defaulting to '%s'", target)
	}
	if _, err := gitOut(ctx, r, p.SrcDir, "check-ref-format", "--branch", target); err != nil {
		return "", fmt.Errorf("invalid update branch: %s", target)
	}
	ref := "refs/remotes/origin/" + target
	if res := git(ctx, r, p.SrcDir, "show-ref", "--quiet", "--verify", ref); res.Code != 0 {
		return "", fmt.Errorf("origin has no branch named %s", target)
	}
	after, err := gitOut(ctx, r, p.SrcDir, "rev-parse", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	if before == after {
		if layoutCheck(p) == nil && revisionMatches(p, after) {
			u.okf("already on %s; installed layout is healthy", short(after))
			return "", nil
		}
		u.warnf("source is current, but the installed layout is legacy or unhealthy; rebuilding it")
		return after, nil
	}
	log, _ := gitOut(ctx, r, p.SrcDir, "--no-pager", "log", "--oneline", "--no-decorate", before+".."+after)
	u.sayf("")
	u.sayf("%s", u.dim("  incoming commits:"))
	for _, line := range strings.Split(log, "\n") {
		u.sayf("    %s", line)
	}
	u.sayf("")
	if !o.yes {
		count, _ := gitOut(ctx, r, p.SrcDir, "rev-list", "--count", before+".."+after)
		fmt.Fprintf(u.out, "? Apply %s commits — %s..%s? (y/N) ", u.bold(count), short(before), short(after))
		if !confirmed(readLine(stdin)) {
			return "", errors.New("cancelled")
		}
	}
	if git(ctx, r, p.SrcDir, "show-ref", "--quiet", "--verify", "refs/heads/"+target).Code == 0 {
		if _, err := gitOut(ctx, r, p.SrcDir, "checkout", "--quiet", target); err != nil {
			return "", err
		}
		if _, err := gitOut(ctx, r, p.SrcDir, "merge", "--ff-only", ref); err != nil {
			return "", fmt.Errorf("%s has diverged from origin/%s", target, target)
		}
	} else if _, err := gitOut(ctx, r, p.SrcDir, "checkout", "--quiet", "-b", target, ref); err != nil {
		return "", err
	}
	if err := RequireTrusted(p.SrcDir); err != nil {
		return "", fmt.Errorf("the updated checkout violates the root ownership policy: %w", err)
	}
	return after, nil
}

// ensureAuthPubkey reads the dotenv files as inert data (never sourced or
// executed) and offers to record the auth service's public key when it is
// missing.
func ensureAuthPubkey(u *ui, p Paths, stdin io.Reader) error {
	found := ""
	for _, f := range []string{p.SharedEnvFile(), p.EnvFile()} {
		present, err := requireSingleRegular(f)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		text, _, err := dotenv.ReadRegular(f)
		if err != nil {
			return err
		}
		if v := dotenv.EffectiveValues(text, nil, []string{"AUTH_SIGNING_PUBKEY"})["AUTH_SIGNING_PUBKEY"]; v != "" {
			found = v
		}
	}
	if found != "" {
		return nil
	}
	u.warnf("AUTH_SIGNING_PUBKEY is unset; authentication cannot work until it is set")
	f, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return nil
	}
	fmt.Fprint(u.out, "? Paste the auth service public key now (blank to skip): ")
	key := readLine(stdin)
	if key == "" {
		return nil
	}
	acct, err := lookupAccount(p.AppUser)
	if err != nil {
		return err
	}
	text, _, _ := dotenv.ReadRegular(p.EnvFile())
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += "AUTH_SIGNING_PUBKEY=" + dotenv.Quote(key) + "\n"
	if err := writeFileAtomic(p.EnvFile(), []byte(text), 0o600, acct.uid, acct.gid); err != nil {
		return err
	}
	u.okf("AUTH_SIGNING_PUBKEY written to %s", p.EnvFile())
	return nil
}

// systemTarget is a privileged file the swap replaces and a rollback must
// restore (or remove, when it did not exist before).
type systemTarget struct {
	path   string
	backup string
	mode   fs.FileMode
	absent bool
}

// runApply is phase two, run by the staged binary: snapshot, swap, restart,
// health-check, and roll everything back on any failure.
func runApply(ctx context.Context, u *ui, r Runner, p Paths) error {
	return applyUpdate(ctx, u, r, p, applyInput{
		binary: os.Getenv("EXPLORER_UPDATE_BINARY"),
		before: os.Getenv("EXPLORER_UPDATE_BEFORE"),
		after:  os.Getenv("EXPLORER_UPDATE_AFTER"),
		locked: os.Getenv("EXPLORER_UPDATE_LOCKED") == "1",
	})
}

type applyInput struct {
	binary, before, after string
	locked                bool
}

func applyUpdate(ctx context.Context, u *ui, r Runner, p Paths, in applyInput) (err error) {
	if os.Geteuid() != 0 {
		return errors.New("run as root: sudo explorer update")
	}
	if in.binary == "" {
		self, serr := os.Executable()
		if serr != nil {
			return serr
		}
		in.binary = self
	}
	if !validRevision(in.after) {
		return fmt.Errorf("invalid target revision %q", in.after)
	}
	if !in.locked {
		lock, lerr := acquireLock(p.LockFile)
		if lerr != nil {
			return lerr
		}
		defer lock.Close()
	}
	acct, err := lookupAccount(p.AppUser)
	if err != nil {
		return err
	}
	if fi, lerr := os.Lstat(p.AppDir); lerr != nil || !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real directory", p.AppDir)
	}
	if err := checkAppDirForMoves(p); err != nil {
		return err
	}
	if err := RequireTrustedPath(filepath.Dir(p.AppDir)); err != nil {
		return err
	}

	backup, err := newStaging(p, ".explorer-backup.")
	if err != nil {
		return err
	}
	targets, err := snapshotSystem(p, backup)
	if err != nil {
		_ = os.RemoveAll(backup)
		return err
	}
	timerWasEnabled := r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"is-enabled", "--quiet", "explorer-attachment-cleanup.timer"}, Timeout: 30 * time.Second}).Code == 0 &&
		exists(p.legacyUnits()[0])
	// Everything Explorer does not own goes to PreservedDir first (and comes
	// back on a rollback): the swap below touches only the binary and the
	// revision marker, and nothing else in the app directory is deleted.
	preserved, err := preserveAndReport(u, p)
	if err != nil {
		_ = os.RemoveAll(backup)
		return err
	}

	u.stepf("3/4  Swapping in + restarting")
	r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"stop", p.Service}, Timeout: 2 * time.Minute})
	appBackup := filepath.Join(backup, "app")
	swap, err := moveOwnedFiles(p, appBackup)
	defer func() {
		if err == nil {
			_ = os.RemoveAll(backup)
			return
		}
		u.warnf("update failed — restoring the previous install")
		if rerr := restoreInstall(ctx, r, p, appBackup, swap, preserved, targets, timerWasEnabled); rerr != nil {
			u.warnf("automatic rollback was incomplete (%v); preserved root-only backup: %s", rerr, backup)
			return
		}
		u.warnf("previous install restored")
		_ = os.RemoveAll(backup)
	}()
	if err != nil {
		return err
	}
	if err = installApp(p, acct, in.binary, in.after); err != nil {
		return err
	}
	if err = installSystemFiles(ctx, u, r, p, in.binary); err != nil {
		return err
	}
	if res := r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"start", p.Service}, Timeout: 2 * time.Minute}); res.Code != 0 {
		err = fmt.Errorf("systemctl start %s failed: %s", p.Service, strings.TrimSpace(res.Stderr))
		return err
	}
	u.okf("service restarted")

	u.stepf("4/4  Health check")
	if !healthy(ctx, p.HealthURL, p.HealthAttempts) {
		err = fmt.Errorf("explorer did not answer %s within %d seconds", p.HealthURL, p.HealthAttempts)
		return err
	}
	if err = layoutCheck(p); err != nil {
		err = fmt.Errorf("updated layout failed its ownership check: %w", err)
		return err
	}
	u.okf("explorer %s → 200", p.HealthURL)

	u.sayf("")
	u.sayf("%s", u.paint("\033[0;32m", "═══════════════════════════════════════════════"))
	u.sayf("%s", u.bold(fmt.Sprintf(" ✓ Updated %s → %s", short(in.before), short(in.after))))
	u.sayf("%s", u.paint("\033[0;32m", "═══════════════════════════════════════════════"))
	u.sayf("")
	u.sayf("  Logs:      %s", u.dim("explorer logs"))
	if in.before != "" && in.before != in.after {
		u.sayf("  Roll back: %s", u.dim(fmt.Sprintf("cd %s && sudo git checkout -B rollback %s && sudo explorer rebuild", p.SrcDir, in.before)))
	}
	return nil
}

func systemTargets(p Paths) []string {
	return append([]string{p.UnitPath(), p.TmpfilesPath(), p.CLITarget, p.MotdTarget}, p.legacyUnits()...)
}

// snapshotSystem copies every privileged target into the backup.
func snapshotSystem(p Paths, backup string) ([]systemTarget, error) {
	dir := filepath.Join(backup, "system")
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	var out []systemTarget
	for i, path := range systemTargets(p) {
		t := systemTarget{path: path, backup: filepath.Join(dir, fmt.Sprint(i))}
		fi, err := os.Lstat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			t.absent = true
		case err != nil:
			return nil, err
		case !fi.Mode().IsRegular():
			return nil, fmt.Errorf("%s is not a regular file", path)
		default:
			t.mode = fi.Mode().Perm()
			if err := copyFileAtomic(path, t.backup, 0o600, -1, -1); err != nil {
				return nil, err
			}
		}
		out = append(out, t)
	}
	return out, nil
}

// ownedSwap records, for a rollback, which of the installer's own files
// existed before the update and which of them were moved into the backup.
type ownedSwap struct {
	binExisted     bool
	existed, moved map[string]bool
}

// moveOwnedFiles moves the installer's own files (the binary and the
// revision marker) into dst, a rename on the same filesystem. Nothing else
// in the app directory is touched.
func moveOwnedFiles(p Paths, dst string) (*ownedSwap, error) {
	s := &ownedSwap{existed: map[string]bool{}, moved: map[string]bool{}}
	if _, err := os.Lstat(filepath.Join(p.AppDir, appBinDir)); err == nil {
		s.binExisted = true
	}
	for _, rel := range appOwnedFiles {
		if fi, err := os.Lstat(filepath.Join(p.AppDir, rel)); err == nil && fi.Mode().IsRegular() {
			s.existed[rel] = true
		}
	}
	if err := os.MkdirAll(filepath.Join(dst, appBinDir), 0o700); err != nil {
		return s, err
	}
	for _, rel := range appOwnedFiles {
		if !s.existed[rel] {
			continue
		}
		if err := os.Rename(filepath.Join(p.AppDir, rel), filepath.Join(dst, rel)); err != nil {
			return s, err
		}
		s.moved[rel] = true
	}
	return s, nil
}

// restoreOwnedFiles undoes moveOwnedFiles: a moved file comes back from the
// backup, a file this update created goes, and an original that was never
// moved stays as it is.
func restoreOwnedFiles(p Paths, appBackup string, s *ownedSwap) []error {
	if s == nil {
		return nil
	}
	var errs []error
	for _, rel := range appOwnedFiles {
		cur := filepath.Join(p.AppDir, rel)
		switch {
		case s.moved[rel]:
			if err := os.Remove(cur); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
				continue
			}
			if err := os.MkdirAll(filepath.Dir(cur), 0o755); err != nil { //nolint:gosec // G301: the app tree is public and root-owned.
				errs = append(errs, err)
				continue
			}
			if err := os.Rename(filepath.Join(appBackup, rel), cur); err != nil {
				errs = append(errs, err)
			}
		case !s.existed[rel]:
			if err := os.Remove(cur); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	if !s.binExisted {
		_ = os.Remove(filepath.Join(p.AppDir, appBinDir)) // only when empty
	}
	return errs
}

// restoreInstall puts back the previous app tree (the installer's files and
// everything this run moved aside) and privileged files, and restarts the
// old service.
func restoreInstall(ctx context.Context, r Runner, p Paths, appBackup string, swap *ownedSwap, preserved *preservedSet,
	targets []systemTarget, timerWasEnabled bool) error {
	r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"stop", p.Service}, Timeout: 2 * time.Minute})
	errs := restoreOwnedFiles(p, appBackup, swap)
	if err := preserved.restore(p); err != nil {
		errs = append(errs, err)
	}
	for _, t := range targets {
		if t.absent {
			if err := os.Remove(t.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		if err := copyFileAtomic(t.backup, t.path, t.mode, int(trustedUID), int(trustedUID)); err != nil {
			errs = append(errs, err)
		}
	}
	if r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"daemon-reload"}, Timeout: time.Minute}).Code != 0 {
		errs = append(errs, errors.New("systemctl daemon-reload failed"))
	}
	if timerWasEnabled {
		r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"enable", "--now", "explorer-attachment-cleanup.timer"}, Timeout: time.Minute})
	}
	if r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"start", p.Service}, Timeout: 2 * time.Minute}).Code != 0 {
		errs = append(errs, errors.New("systemctl start failed"))
	}
	return errors.Join(errs...)
}
