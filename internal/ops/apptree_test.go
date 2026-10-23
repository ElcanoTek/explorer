// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// asTrustedOwner makes the test user the owner the trust checks require.
func asTrustedOwner(t *testing.T) {
	t.Helper()
	old := trustedUID
	trustedUID = uint32(os.Getuid())
	t.Cleanup(func() { trustedUID = old })
}

func appTreeFixture(t *testing.T) Paths {
	t.Helper()
	asTrustedOwner(t)
	base := t.TempDir()
	p := Paths{AppDir: filepath.Join(base, "explorer")}
	for _, d := range []string{"bin", ".venv/bin", "app", "notes-dir"} {
		if err := os.MkdirAll(filepath.Join(p.AppDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(p.AppDir, ".env"), "SECRET=1\n", 0o600)
	writeFile(t, filepath.Join(p.AppDir, ".env.shared"), "SHARED=1\n", 0o600)
	writeFile(t, filepath.Join(p.AppDir, "bin", "explorer"), "binary\n", 0o755)
	writeFile(t, filepath.Join(p.AppDir, ".explorer-revision"), "rev\n", 0o644)
	writeFile(t, filepath.Join(p.AppDir, ".venv", "bin", "python"), "venv\n", 0o755)
	writeFile(t, filepath.Join(p.AppDir, "app", "main.py"), "old\n", 0o644)
	// Not Explorer's: an env backup another tool left, and an operator's notes.
	writeFile(t, filepath.Join(p.AppDir, ".env.backup.20261020T101010Z.AbC123"), "OLD_SECRET=1\n", 0o600)
	writeFile(t, filepath.Join(p.AppDir, "notes-dir", "todo.txt"), "keep me\n", 0o644)
	return p
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func TestPreserveMovesOnlyWhatExplorerDoesNotOwn(t *testing.T) {
	p := appTreeFixture(t)
	dir, moved, err := preserveUnknownAppEntries(p)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(moved)
	if strings.Join(moved, ",") != ".env.backup.20261020T101010Z.AbC123,notes-dir" {
		t.Fatalf("moved %v", moved)
	}
	if !strings.HasPrefix(dir, p.PreservedDir()+string(os.PathSeparator)) {
		t.Fatalf("preserved into %s", dir)
	}
	if readFile(t, filepath.Join(dir, "notes-dir", "todo.txt")) != "keep me\n" ||
		readFile(t, filepath.Join(dir, ".env.backup.20261020T101010Z.AbC123")) != "OLD_SECRET=1\n" {
		t.Fatal("preserved files changed")
	}
	if fi, err := os.Stat(p.PreservedDir()); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("preserved folder mode: %v %v", fi, err)
	}
	if got := strings.Join(names(t, p.AppDir), ","); got != ".env,.env.shared,.explorer-revision,.venv,app,bin" {
		t.Fatalf("app dir now holds %s", got)
	}
	// Nothing to move the second time.
	if dir, moved, err := preserveUnknownAppEntries(p); err != nil || dir != "" || moved != nil {
		t.Fatalf("second run: %q %v %v", dir, moved, err)
	}
}

func TestPreserveRefusesALinkedOrForeignFolder(t *testing.T) {
	p := appTreeFixture(t)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, p.PreservedDir()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := preserveUnknownAppEntries(p); err == nil {
		t.Fatal("moved files through a symlinked preserved folder")
	}
	if !exists(filepath.Join(p.AppDir, "notes-dir", "todo.txt")) {
		t.Fatal("a refused move lost the file")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatal("wrote through the link")
	}
}

func TestBootstrapCleanupRemovesOnlyPythonEraLeftovers(t *testing.T) {
	p := appTreeFixture(t)
	u, _ := testUI()
	if err := removeLegacyAppTree(u, p); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(t, p.AppDir), ","); got != ".env,.env.shared,.explorer-revision,bin" {
		t.Fatalf("app dir now holds %s", got)
	}
	kept, _ := filepath.Glob(filepath.Join(p.PreservedDir(), "*", "notes-dir", "todo.txt"))
	if len(kept) != 1 || readFile(t, kept[0]) != "keep me\n" {
		t.Fatalf("operator file not preserved: %v", kept)
	}
}

func TestUpdateSwapMovesOnlyReplaceableEntries(t *testing.T) {
	p := appTreeFixture(t)
	dst := filepath.Join(t.TempDir(), "app")
	if _, err := moveAppEntries(p, dst); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(t, dst), ","); got != ".explorer-revision,.venv,app,bin" {
		t.Fatalf("moved %s", got)
	}
	if got := strings.Join(names(t, p.AppDir), ","); got != ".env,.env.backup.20261020T101010Z.AbC123,.env.shared,notes-dir" {
		t.Fatalf("left %s", got)
	}
}
