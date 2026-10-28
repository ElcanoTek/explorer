// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const versionPkg = "github.com/ElcanoTek/explorer/internal/version"

// git runs git against the trusted checkout with every repository-controlled
// hook and background maintenance disabled: no hooks, no fsmonitor, no auto
// gc/maintenance, and an explicit safe.directory.
func git(ctx context.Context, r Runner, src string, args ...string) Result {
	full := append([]string{
		"-c", "safe.directory=" + src, "-c", "core.hooksPath=/dev/null",
		"-c", "core.fsmonitor=false", "-c", "gc.auto=0",
		"-c", "maintenance.auto=false", "-C", src,
	}, args...)
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	return r.Run(ctx, Cmd{Name: "git", Args: full, Env: env, Timeout: 5 * time.Minute})
}

func gitOut(ctx context.Context, r Runner, src string, args ...string) (string, error) {
	res := git(ctx, r, src, args...)
	if res.Code != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = fmt.Sprintf("exit %d", res.Code)
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return strings.TrimSpace(res.Stdout), nil
}

// prepareBuildCache makes the Go caches root's alone. A cache left by the
// Python era belonged to the service account (uv ran as it); module caches
// are not re-verified on reuse, so a service-writable one is discarded.
func prepareBuildCache(cache string) error {
	if fi, err := os.Lstat(cache); err == nil {
		if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() || statT(fi).Uid != trustedUID || fi.Mode().Perm()&0o077 != 0 {
			if err := os.RemoveAll(cache); err != nil {
				return fmt.Errorf("could not discard the untrusted build cache %s: %w", cache, err)
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := RequireTrustedPath(filepath.Dir(cache)); err != nil {
		return err
	}
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return err
	}
	return os.Chmod(cache, 0o700) //nolint:gosec // G302: deliberate mode for a root-installed file.
}

// buildEnv is the whole environment the toolchain sees: nothing from the
// caller's shell except proxy and CA settings, so a root shell's GOFLAGS or
// a go.work above the checkout cannot steer the build.
func buildEnv(cache string) []string {
	env := []string{
		"PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin",
		"HOME=" + cache,
		"GOPATH=" + filepath.Join(cache, "gopath"),
		"GOMODCACHE=" + filepath.Join(cache, "mod"),
		"GOCACHE=" + filepath.Join(cache, "go-build"),
		"GOTOOLCHAIN=auto",
		"GOFLAGS=-mod=readonly",
		"CGO_ENABLED=0",
		"GOWORK=off",
		"GOENV=off",
		"GOTELEMETRY=off",
	}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "GOPROXY", "GOSUMDB", "GOPRIVATE"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// resolveGo finds the go command as an absolute path. The build runs with
// its own PATH, but an executable name is looked up in this process's PATH,
// which under sudo may lack /usr/local/go/bin, so the fallback must be
// passed as a path.
func resolveGo(r Runner, fallback string) (string, error) {
	if p, ok := r.LookPath("go"); ok {
		return p, nil
	}
	if st, err := os.Stat(fallback); err == nil && !st.IsDir() {
		return fallback, nil
	}
	return "", errors.New("the Go toolchain is not installed — run: dnf install -y golang")
}

// buildBinary compiles cmd/explorer from the trusted checkout src into out,
// stamping revision. It never writes into src.
func buildBinary(ctx context.Context, u *ui, r Runner, p Paths, src, out, revision string) error {
	if !validRevision(revision) {
		return fmt.Errorf("invalid source revision: %q", revision)
	}
	if err := RequireTrusted(src); err != nil {
		return err
	}
	goBin, err := resolveGo(r, "/usr/local/go/bin/go")
	if err != nil {
		return err
	}
	if err := prepareBuildCache(p.BuildCache); err != nil {
		return err
	}
	u.infof("go build ./cmd/explorer @ %s", revision[:12])
	res := r.Run(ctx, Cmd{
		Name: goBin,
		Args: []string{
			"build", "-trimpath", "-buildvcs=false",
			"-ldflags", "-s -w -X " + versionPkg + ".revision=" + revision,
			"-o", out, "./cmd/explorer",
		},
		Dir:     src,
		Env:     buildEnv(p.BuildCache),
		Timeout: 30 * time.Minute,
	})
	if res.Code != 0 {
		tail := strings.TrimSpace(res.Stderr + "\n" + res.Stdout)
		if len(tail) > 4000 {
			tail = tail[len(tail)-4000:]
		}
		return fmt.Errorf("go build failed:\n%s", tail)
	}
	return os.Chmod(out, 0o755) //nolint:gosec // G302: deliberate mode for a root-installed file.
}

// newStaging creates a private directory beside the app directory: same
// filesystem (renames are atomic) and, under SELinux, not /tmp.
func newStaging(p Paths, pattern string) (string, error) {
	parent := filepath.Dir(p.AppDir)
	if err := os.MkdirAll(parent, 0o755); err != nil { //nolint:gosec // G301: a public, root-owned directory by design.
		return "", err
	}
	dir, err := os.MkdirTemp(parent, pattern)
	if err != nil {
		return "", err
	}
	return dir, os.Chmod(dir, 0o700) //nolint:gosec // G302: deliberate mode for a root-installed file.
}
