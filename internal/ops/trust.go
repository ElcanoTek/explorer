// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// trustedUID is the owner the trust checks require. Always root in
// production; the unit tests point it at the test user.
var trustedUID uint32

func statT(fi fs.FileInfo) *syscall.Stat_t {
	st, _ := fi.Sys().(*syscall.Stat_t)
	if st == nil {
		return &syscall.Stat_t{Uid: ^uint32(0), Gid: ^uint32(0)}
	}
	return st
}

// RequireTrustedPath checks that path (resolved) and every ancestor up to /
// is owned by root and writable by neither group nor others, so nobody but
// root can swap anything along the way.
func RequireTrustedPath(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("%s does not resolve: %w", path, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return err
	}
	for p := resolved; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		if statT(fi).Uid != trustedUID {
			return fmt.Errorf("%s is owned by uid %d; root must own it and every ancestor", p, statT(fi).Uid)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by group or others", p)
		}
		if p == "/" || p == filepath.Dir(p) {
			return nil
		}
	}
}

// RequireTrusted checks a source tree root updates execute from: a real
// directory with a trusted path, and inside it nothing owned by anyone but
// root, nothing group- or world-writable, and no symlink at all.
func RequireTrusted(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is not a real directory", dir)
	}
	if err := RequireTrustedPath(dir); err != nil {
		return err
	}
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("%s is a symlink; remove it (install trees must be symlink-free)", path)
		case statT(info).Uid != trustedUID:
			return fmt.Errorf("%s is not owned by root; fix its ownership", path)
		case info.Mode().Perm()&0o022 != 0:
			return fmt.Errorf("%s is writable by group or others; fix its mode", path)
		}
		return nil
	})
}

// account is a resolved service user.
type account struct {
	name     string
	uid, gid int
}

func lookupAccount(name string) (account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return account{}, fmt.Errorf("service user %s does not exist: %w", name, err)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return account{}, fmt.Errorf("service user %s has a non-numeric id", name)
	}
	return account{name: name, uid: uid, gid: gid}, nil
}

// requireSingleRegular refuses a path that exists but is not a single-link
// regular file. Root rewrites service-owned files; a symlink or hard link
// would redirect that write somewhere privileged.
func requireSingleRegular(path string) (exists bool, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() || statT(fi).Nlink != 1 {
		return true, fmt.Errorf("%s must be a single-link regular file", path)
	}
	return true, nil
}

// secureEnvFiles makes every dotenv file the service reads owned by the
// service account, mode 0600, after checking it is safe to touch.
func secureEnvFiles(p Paths, acct account) error {
	for _, f := range []string{p.EnvFile(), p.SharedEnvFile()} {
		exists, err := requireSingleRegular(f)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if err := os.Lchown(f, acct.uid, acct.gid); err != nil {
			return err
		}
		if err := os.Chmod(f, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// layoutCheck verifies the installed tree: the app directory and everything
// in it root-owned and not group/world-writable with no symlinks, except the
// dotenv files, which must be the service account's, 0600, single-link.
func layoutCheck(p Paths) error {
	acct, err := lookupAccount(p.AppUser)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(p.AppDir)
	if err != nil || !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real directory", p.AppDir)
	}
	if st := statT(fi); st.Uid != trustedUID || st.Gid != trustedUID || fi.Mode().Perm() != 0o755 {
		return fmt.Errorf("%s must be root:root 0755", p.AppDir)
	}
	envs := map[string]bool{p.EnvFile(): true, p.SharedEnvFile(): true}
	err = filepath.WalkDir(p.AppDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if envs[path] {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 || statT(info).Uid != trustedUID || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s violates the root-owned application layout", path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	bin, err := os.Lstat(p.BinPath())
	if err != nil || !bin.Mode().IsRegular() || bin.Mode().Perm() != 0o755 {
		return fmt.Errorf("%s must be a root-owned 0755 regular file", p.BinPath())
	}
	for f := range envs {
		info, err := os.Lstat(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		st := statT(info)
		if !info.Mode().IsRegular() || st.Nlink != 1 || int(st.Uid) != acct.uid || int(st.Gid) != acct.gid || info.Mode().Perm() != 0o600 {
			return fmt.Errorf("%s must be %s:%s 0600 with one link", f, acct.name, acct.name)
		}
	}
	return RequireTrusted(p.SrcDir)
}

// revisionMatches reports whether the installed revision marker is a sound
// root-owned file naming expected.
func revisionMatches(p Paths, expected string) bool {
	fi, err := os.Lstat(p.RevisionFile())
	if err != nil || !fi.Mode().IsRegular() || statT(fi).Uid != trustedUID || statT(fi).Nlink != 1 || fi.Mode().Perm() != 0o644 {
		return false
	}
	raw, err := os.ReadFile(p.RevisionFile())
	return err == nil && strings.TrimSpace(string(raw)) == expected
}

func validRevision(rev string) bool {
	if len(rev) < 40 || len(rev) > 64 {
		return false
	}
	for _, c := range rev {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// writeFileAtomic writes data to a temporary file in path's directory with
// the given mode and owner, then renames it over path. The file is never
// visible half-written or with the wrong mode.
func writeFileAtomic(path string, data []byte, mode fs.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if uid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// copyFileAtomic copies src to dst (atomically, as writeFileAtomic).
// uid < 0 keeps the caller's ownership.
func copyFileAtomic(src, dst string, mode fs.FileMode, uid, gid int) error {
	in, err := os.Open(src) //nolint:gosec // G304: a path the installer chose, not request input.
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, err = io.Copy(tmp, in)
	if err == nil && uid >= 0 {
		err = tmp.Chown(uid, gid)
	}
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, dst)
}

// sameContent reports whether two files hold identical bytes.
func sameContent(a, b string) bool {
	x, err1 := os.ReadFile(a) //nolint:gosec // G304: a path the installer chose, not request input.
	y, err2 := os.ReadFile(b) //nolint:gosec // G304: a path the installer chose, not request input.
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func fileEquals(path string, want []byte) bool {
	got, err := os.ReadFile(path) //nolint:gosec // G304: a path the installer chose, not request input.
	return err == nil && bytes.Equal(got, want)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
