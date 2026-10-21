// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ElcanoTek/explorer/deploy"
)

// installApp puts the binary and the revision marker into the app directory
// and re-secures the dotenv files. The directory itself is root:root 0755.
func installApp(p Paths, acct account, binarySrc, revision string) error {
	if !validRevision(revision) {
		return fmt.Errorf("invalid source revision: %s", revision)
	}
	if fi, err := os.Lstat(p.AppDir); err == nil && (!fi.IsDir() || fi.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("%s is not a real directory", p.AppDir)
	}
	if err := RequireTrustedPath(filepath.Dir(p.AppDir)); err != nil {
		return err
	}
	for _, d := range []string{p.AppDir, filepath.Join(p.AppDir, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil { //nolint:gosec // G301: a public, root-owned directory by design.
			return err
		}
		if fi, err := os.Lstat(d); err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a real directory", d)
		}
		if err := os.Lchown(d, int(trustedUID), int(trustedUID)); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // G302: deliberate mode for a root-installed file.
			return err
		}
	}
	if err := copyFileAtomic(binarySrc, p.BinPath(), 0o755, int(trustedUID), int(trustedUID)); err != nil {
		return fmt.Errorf("install %s: %w", p.BinPath(), err)
	}
	if err := writeFileAtomic(p.RevisionFile(), []byte(revision+"\n"), 0o644, int(trustedUID), int(trustedUID)); err != nil {
		return err
	}
	return secureEnvFiles(p, acct)
}

// installSystemFiles writes every file the service needs outside the app
// directory. They come from this binary (embedded at build time from the
// verified checkout) — never from a service-writable path.
func installSystemFiles(ctx context.Context, u *ui, r Runner, p Paths, binarySrc string) error {
	root := int(trustedUID)
	files := []struct {
		path string
		data []byte
	}{
		{p.UnitPath(), deploy.ServiceUnit},
		{p.TmpfilesPath(), deploy.TmpfilesConf},
		{p.MotdTarget, deploy.Motd},
	}
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil { //nolint:gosec // G301: a public, root-owned directory by design.
			return err
		}
		if err := writeFileAtomic(f.path, f.data, 0o644, root, root); err != nil {
			return fmt.Errorf("install %s: %w", f.path, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(p.CLITarget), 0o755); err != nil { //nolint:gosec // G301: a public, root-owned directory by design.
		return err
	}
	if err := copyFileAtomic(binarySrc, p.CLITarget, 0o755, root, root); err != nil {
		return fmt.Errorf("install %s: %w", p.CLITarget, err)
	}
	removeLegacyUnits(ctx, u, r, p)
	if res := r.Run(ctx, Cmd{Name: "systemd-tmpfiles", Args: []string{"--create", p.TmpfilesPath()}, Timeout: time.Minute}); res.Code != 0 {
		return fmt.Errorf("systemd-tmpfiles --create failed: %s", res.Stderr)
	}
	if _, ok := r.LookPath("restorecon"); ok {
		r.Run(ctx, Cmd{Name: "restorecon", Args: []string{"-RF", p.AppDir, p.SrcDir, p.UnitPath(), p.TmpfilesPath(), p.CLITarget, p.MotdTarget}, Timeout: 5 * time.Minute})
	}
	if res := r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"daemon-reload"}, Timeout: time.Minute}); res.Code != 0 {
		return fmt.Errorf("systemctl daemon-reload failed: %s", res.Stderr)
	}
	return nil
}

// removeLegacyUnits retires the Python era's attachment-cleanup timer:
// attachments now stream from memory and never touch disk.
func removeLegacyUnits(ctx context.Context, u *ui, r Runner, p Paths) {
	units := p.legacyUnits()
	if !exists(units[0]) && !exists(units[1]) {
		return
	}
	r.Run(ctx, Cmd{Name: "systemctl", Args: []string{"disable", "--now", "explorer-attachment-cleanup.timer"}, Timeout: time.Minute})
	for _, f := range units {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			u.warnf("could not remove %s: %v", f, err)
		}
	}
	u.infof("removed the legacy attachment-cleanup timer (downloads no longer touch disk)")
}

// healthy polls the health URL once a second until it answers 200.
func healthy(ctx context.Context, url string, attempts int) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return false
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
	}
	return false
}
