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
	noPull, yes    bool
	fromSource     bool
	modeExplicit   bool
	allowDowngrade bool
	tag            string
	branch         string
	baseSHA        string
}

func fromSourceEnv(env map[string]string) bool {
	return config.Truthy(env["EXPLORER_FROM_SOURCE"]) || config.Truthy(env["EXPLORER_UPDATE_FROM_SOURCE"])
}

func parseUpdateArgs(args []string, rebuild bool) (updateOpts, error) {
	fromSrc := config.Truthy(os.Getenv("EXPLORER_FROM_SOURCE")) || config.Truthy(os.Getenv("EXPLORER_UPDATE_FROM_SOURCE"))
	_, hasFromSrcEnv := os.LookupEnv("EXPLORER_FROM_SOURCE")
	_, hasUpdateFromSrcEnv := os.LookupEnv("EXPLORER_UPDATE_FROM_SOURCE")
	o := updateOpts{
		noPull:         rebuild || os.Getenv("EXPLORER_UPDATE_NO_PULL") == "1",
		yes:            rebuild || config.Truthy(os.Getenv("EXPLORER_UPDATE_YES")),
		fromSource:     fromSrc,
		modeExplicit:   hasFromSrcEnv || hasUpdateFromSrcEnv,
		allowDowngrade: config.Truthy(os.Getenv("EXPLORER_UPDATE_ALLOW_DOWNGRADE")),
		tag:            envOr("", "EXPLORER_RELEASE_TAG", "EXPLORER_UPDATE_TAG"),
		branch:         os.Getenv("EXPLORER_UPDATE_BRANCH"),
		baseSHA:        os.Getenv("EXPLORER_UPDATE_BASE_SHA"),
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--yes" || a == "-y":
			o.yes = true
		case a == "--no-pull":
			o.noPull = true
		case a == "--from-source":
			o.fromSource = true
			o.modeExplicit = true
		case a == "--artifact":
			o.fromSource = false
			o.modeExplicit = true
		case a == "--allow-downgrade":
			o.allowDowngrade = true
		case a == "--tag" && i+1 < len(args):
			i++
			o.tag = strings.TrimSpace(args[i])
			if o.tag == "" {
				return o, usageError{"--tag requires a release tag (vYYYY.MM.DD.N)"}
			}
		case a == "--tag":
			return o, usageError{"--tag requires a release tag (vYYYY.MM.DD.N)"}
		case strings.HasPrefix(a, "--tag="):
			o.tag = strings.TrimSpace(strings.TrimPrefix(a, "--tag="))
			if o.tag == "" {
				return o, usageError{"--tag requires a release tag (vYYYY.MM.DD.N)"}
			}
		default:
			return o, usageError{"unknown update flag: " + a + " (try: explorer update [--yes] [--tag vYYYY.MM.DD.N] [--allow-downgrade] [--from-source])"}
		}
	}
	return o, nil
}

// runUpdate is phase one of an update: verify the checkout, resolve the
// target release (or fast-forward source when --from-source is set), verify
// or build the new binary into staging, and hand the swap to that new binary
// (runApply), so the new release's own install logic always performs the
// install.
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
	autoRebuildTag := false
	if rebuild && !o.modeExplicit && o.tag == "" {
		if t, ok := releaseTagAt(ctx, r, p.SrcDir, before); ok {
			o.tag = t.String()
			autoRebuildTag = true
		} else {
			o.fromSource = true
		}
	}
	if !o.fromSource {
		err := runSignedReleaseUpdate(ctx, u, r, p, lock, o, before, stdin)
		if err != nil && autoRebuildTag && errors.Is(err, ErrReleaseAssetsNotFound) {
			u.warnf("signed release assets for %s were pruned; falling back to --from-source", o.tag)
			o.fromSource = true
			o.tag = ""
		} else {
			return err
		}
	}

	before, after, err := resolveSourceTarget(ctx, u, r, p, o, before, stdin)
	if err != nil || after == "" {
		return err
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
	removeInstalledRelease(p)
	return nil
}

func resolveSourceTarget(ctx context.Context, u *ui, r Runner, p Paths, o updateOpts, before string, stdin io.Reader) (string, string, error) {
	after := before
	switch {
	case o.tag != "":
		headSHA := before
		if o.noPull && o.baseSHA != "" {
			before = o.baseSHA
		}
		curTagStr := ""
		if curTag, ok := releaseTagAt(ctx, r, p.SrcDir, before); ok {
			curTagStr = curTag.String()
		}
		_, resolved, err := resolveReleaseTarget(ctx, u, r, p, o, before, headSHA, curTagStr, stdin)
		if err != nil || resolved == "" {
			return before, resolved, err
		}
		after = resolved
		if !o.noPull || headSHA != after {
			if err := checkoutReleaseCommit(ctx, r, p.SrcDir, after); err != nil {
				return before, "", err
			}
		}
		return before, after, nil
	case o.noPull:
		if o.baseSHA != "" {
			before = o.baseSHA
		}
		u.okf("rebuild-only mode — skipping fetch, building %s", short(after))
		return before, after, nil
	default:
		resolved, err := fetchAndMerge(ctx, u, r, p, o, before, stdin)
		return before, resolved, err
	}
}

func runSignedReleaseUpdate(ctx context.Context, u *ui, r Runner, p Paths, lock *os.File, o updateOpts, before string, stdin io.Reader) error {
	headSHA := before
	if o.noPull && o.baseSHA != "" {
		before = o.baseSHA
	}
	curTagStr := ""
	if curTag, ok := releaseTagAt(ctx, r, p.SrcDir, before); ok {
		curTagStr = curTag.String()
	}
	targetTag, after, err := resolveReleaseTarget(ctx, u, r, p, o, before, headSHA, curTagStr, stdin)
	if err != nil || after == "" {
		return err
	}

	if err := ensureAuthPubkey(u, p, stdin); err != nil {
		return err
	}

	u.stepf("2/4  Verifying signed release binary in staging")
	staging, err := newStaging(p, ".explorer-release.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	staged := filepath.Join(staging, "explorer")
	if err := stageSignedRelease(ctx, p, targetTag, after, curTagStr, o.allowDowngrade, staging, staged); err != nil {
		return fmt.Errorf("%w\nrelease verification failed — the installed service was not changed", err)
	}
	u.okf("verified signed release %s (%s)", targetTag, short(after))

	if !o.noPull || headSHA != after {
		if err := checkoutReleaseCommit(ctx, r, p.SrcDir, after); err != nil {
			return err
		}
	}
	if !exists(filepath.Join(p.SrcDir, "go.mod")) {
		u.warnf("%s predates the Go rewrite — handing over to its scripts/update.sh", short(after))
		env := append(os.Environ(), "EXPLORER_UPDATE_NO_PULL=1", "EXPLORER_UPDATE_YES=1", "EXPLORER_UPDATE_BASE_SHA="+before, "SRC_DIR="+p.SrcDir, "APP_DIR="+p.AppDir)
		_ = lock.Close()
		if code := r.Interactive(ctx, Cmd{Name: "bash", Args: []string{filepath.Join(p.SrcDir, "scripts/update.sh")}, Env: env}); code != 0 {
			return exitCodeError{code}
		}
		return nil
	}

	env := append(os.Environ(), p.Env()...)
	env = append(env, "EXPLORER_UPDATE_BINARY="+staged, "EXPLORER_UPDATE_BEFORE="+before,
		"EXPLORER_UPDATE_AFTER="+after, "EXPLORER_UPDATE_LOCKED=1")
	if code := r.Interactive(ctx, Cmd{Name: staged, Args: []string{applyVerb}, Env: env}); code != 0 {
		return exitCodeError{code}
	}
	_ = writeInstalledRelease(p, targetTag, after, p.BinPath())
	return nil
}

func writeInstalledRelease(p Paths, tag Tag, commit, binPath string) error {
	sum, err := fileSHA256(binPath)
	if err != nil {
		return err
	}
	if err := EnsurePrivateDir(p.CosignCacheDir()); err != nil {
		return err
	}
	line := fmt.Sprintf("%s %s %s\n", tag, strings.ToLower(commit), sum)
	return writeFileAtomic(p.InstalledReleaseReceipt(), []byte(line), 0o600, -1, -1)
}

func removeInstalledRelease(p Paths) {
	_ = os.Remove(p.InstalledReleaseReceipt())
}

func releaseBinaryMatches(p Paths, tag Tag, commit string) bool {
	raw, err := os.ReadFile(p.InstalledReleaseReceipt())
	if err != nil {
		return false
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 3 || fields[0] != tag.String() || !strings.EqualFold(fields[1], commit) || len(fields[2]) != 64 {
		return false
	}
	gotSHA, err := fileSHA256(p.BinPath())
	return err == nil && strings.EqualFold(gotSHA, fields[2])
}

func releaseTagAt(ctx context.Context, r Runner, srcDir, rev string) (Tag, bool) {
	return bestReleaseTagFromGit(ctx, r, srcDir, "tag", "--points-at", rev)
}

func newestMergedReleaseTag(ctx context.Context, r Runner, srcDir, rev string) (Tag, bool) {
	return bestReleaseTagFromGit(ctx, r, srcDir, "tag", "--merged", rev, "--list", "v*")
}

func bestReleaseTagFromGit(ctx context.Context, r Runner, srcDir string, args ...string) (Tag, bool) {
	if len(args) == 0 || args[len(args)-1] == "" {
		return Tag{}, false
	}
	out, err := gitOut(ctx, r, srcDir, args...)
	if err != nil || out == "" {
		return Tag{}, false
	}
	var best Tag
	found := false
	for _, line := range strings.Split(out, "\n") {
		t, err := ParseTag(line)
		if err != nil {
			continue
		}
		if !found || t.Compare(best) > 0 {
			best = t
			found = true
		}
	}
	return best, found
}

func resolveReleaseTarget(ctx context.Context, u *ui, r Runner, p Paths, o updateOpts, before, headSHA, curTagStr string, stdin io.Reader) (Tag, string, error) {
	if !o.noPull {
		if _, err := gitOut(ctx, r, p.SrcDir, "fetch", "--quiet", "--force", "--tags", "origin"); err != nil {
			return Tag{}, "", err
		}
		_, _ = gitOut(ctx, r, p.SrcDir, "fetch", "--quiet", "origin", "main")
	}

	var targetTag Tag
	var err error
	switch {
	case o.tag != "":
		targetTag, err = ParseTag(o.tag)
		if err != nil {
			return Tag{}, "", err
		}
	case o.noPull:
		var ok bool
		if o.baseSHA == "" {
			targetTag, ok = releaseTagAt(ctx, r, p.SrcDir, headSHA)
		}
		if !ok {
			_, _ = gitOut(ctx, r, p.SrcDir, "fetch", "--quiet", "--force", "--tags", "origin")
			var lerr error
			targetTag, lerr = NewDownloader().LatestTag(ctx)
			if lerr != nil {
				return Tag{}, "", fmt.Errorf("HEAD (%s) is not at a release tag (pass --tag vYYYY.MM.DD.N or --from-source)", short(headSHA))
			}
		}
	default:
		targetTag, err = NewDownloader().LatestTag(ctx)
		if err != nil {
			return Tag{}, "", fmt.Errorf("resolve latest release tag: %w", err)
		}
	}

	tagRef := "refs/tags/" + targetTag.String()
	after, err := gitOut(ctx, r, p.SrcDir, "rev-parse", "--verify", "--quiet", tagRef+"^{commit}")
	if err != nil {
		if _, ferr := gitOut(ctx, r, p.SrcDir, "fetch", "--quiet", "--force", "origin", tagRef+":"+tagRef); ferr == nil {
			after, err = gitOut(ctx, r, p.SrcDir, "rev-parse", "--verify", "--quiet", tagRef+"^{commit}")
		}
	}
	if err != nil || after == "" {
		return Tag{}, "", fmt.Errorf("release tag %s was not found in %s", targetTag, p.SrcDir)
	}
	if envCommit := strings.TrimSpace(os.Getenv("EXPLORER_RELEASE_COMMIT")); envCommit != "" && !strings.EqualFold(envCommit, after) {
		return Tag{}, "", fmt.Errorf("EXPLORER_RELEASE_COMMIT %s does not match tag %s (%s)", envCommit, targetTag, after)
	}

	isDowngrade := false
	if cur, ok := ParseVersion(curTagStr); ok && targetTag.Compare(cur) < 0 {
		isDowngrade = true
	} else if before != "" && before != after && git(ctx, r, p.SrcDir, "merge-base", "--is-ancestor", after, before).Code == 0 {
		isDowngrade = true
	}
	if isDowngrade && !o.allowDowngrade {
		if curTagStr != "" {
			return Tag{}, "", fmt.Errorf("%w: %s is older than the installed %s (pass --allow-downgrade to roll back on purpose)", ErrDowngrade, targetTag, curTagStr)
		}
		return Tag{}, "", fmt.Errorf("%w: %s (%s) is older than the installed commit %s (pass --allow-downgrade to roll back on purpose)", ErrDowngrade, targetTag, short(after), short(before))
	}

	if o.noPull {
		u.okf("signed release mode — target %s (%s)", targetTag, short(after))
		return targetTag, after, nil
	}

	if before == after {
		if layoutCheck(p) == nil && revisionMatches(p, after) && (o.fromSource || releaseBinaryMatches(p, targetTag, after)) {
			u.okf("already on %s (%s); installed layout is healthy", targetTag, short(after))
			return Tag{}, "", nil
		}
		u.warnf("source is current (%s), but the installed binary or layout is not the verified release; reinstalling it", targetTag)
		return targetTag, after, nil
	}

	logRange := before + ".." + after
	if isDowngrade {
		logRange = after + ".." + before
	}
	log, _ := gitOut(ctx, r, p.SrcDir, "--no-pager", "log", "--oneline", "--no-decorate", logRange)
	u.sayf("")
	u.sayf("%s", u.dim("  commits ("+logRange+"):"))
	for _, line := range strings.Split(log, "\n") {
		if line != "" {
			u.sayf("    %s", line)
		}
	}
	u.sayf("")
	if !o.yes {
		count, _ := gitOut(ctx, r, p.SrcDir, "rev-list", "--count", logRange)
		fmt.Fprintf(u.out, "? Install release %s (%s commits — %s → %s)? (y/N) ", u.bold(targetTag.String()), u.bold(count), short(before), short(after))
		if !confirmed(readLine(stdin)) {
			return Tag{}, "", errors.New("cancelled")
		}
	}
	return targetTag, after, nil
}

var newReleaseVerifier = func(ctx context.Context, dl *Downloader, p Paths, arch string) (Verifier, error) {
	cosignBin, err := EnsureCosign(ctx, dl, p.CosignCacheDir(), arch)
	if err != nil {
		return nil, err
	}
	return &Cosign{Bin: cosignBin, Policy: ExplorerPolicy()}, nil
}

func stageSignedRelease(ctx context.Context, p Paths, targetTag Tag, commit, currentTag string, allowDowngrade bool, stagingDir, dstBinary string) error {
	dl := NewDownloader()
	arch := HostArch()
	verifier, err := newReleaseVerifier(ctx, dl, p, arch)
	if err != nil {
		return err
	}

	if preStaged := strings.TrimSpace(os.Getenv("EXPLORER_RELEASE_STAGING")); preStaged != "" {
		if cur, ok := ParseVersion(currentTag); ok && !allowDowngrade && targetTag.Compare(cur) < 0 {
			return fmt.Errorf("%w: %s is older than the installed %s (pass --allow-downgrade to roll back on purpose)", ErrDowngrade, targetTag, cur)
		}
		rel, err := LoadVerifiedRelease(ctx, verifier, preStaged, targetTag, arch, commit)
		if err != nil {
			return err
		}
		defer rel.BinaryFile.Close()
		CacheReleaseBundle(p.ReleaseCacheDir(), targetTag, currentTag, preStaged, arch, rel.BinarySHA256)
		if err := copyFromFD(rel.BinaryFile, dstBinary, rel.BinarySHA256); err != nil {
			return err
		}
		return os.Chmod(dstBinary, 0o755) //nolint:gosec // G302: staged binary is executed for __apply-update.
	}

	relDir := filepath.Join(stagingDir, "release")
	rel, err := FetchRelease(ctx, dl, verifier, FetchOptions{
		Tag:            targetTag,
		Arch:           arch,
		Dir:            relDir,
		Current:        currentTag,
		AllowDowngrade: allowDowngrade,
		Commit:         commit,
	})
	if err != nil {
		if errors.Is(err, ErrReleaseAssetsNotFound) {
			cachedDir := filepath.Join(p.ReleaseCacheDir(), targetTag.String())
			if cachedRel, cerr := LoadVerifiedRelease(ctx, verifier, cachedDir, targetTag, arch, commit); cerr == nil {
				defer cachedRel.BinaryFile.Close()
				if err := copyFromFD(cachedRel.BinaryFile, dstBinary, cachedRel.BinarySHA256); err != nil {
					return err
				}
				return os.Chmod(dstBinary, 0o755) //nolint:gosec // G302: staged binary is executed for __apply-update.
			}
		}
		return err
	}
	CacheReleaseBundle(p.ReleaseCacheDir(), targetTag, currentTag, relDir, arch, rel.BinarySHA256)
	return os.Rename(rel.Binary, dstBinary)
}

var checkTrustedCheckout = RequireTrusted

func checkoutReleaseCommit(ctx context.Context, r Runner, srcDir, commit string) error {
	if _, err := gitOut(ctx, r, srcDir, "checkout", "--detach", "--quiet", commit); err != nil {
		return err
	}
	if err := checkTrustedCheckout(srcDir); err != nil {
		return fmt.Errorf("the updated checkout violates the root ownership policy: %w", err)
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
