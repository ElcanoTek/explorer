// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runAccessIn(t *testing.T, dir string, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("EXPLORER_APP_DIR", dir)
	t.Setenv("EXPLORER_ACCESS_NO_HANDOFF", "1")
	var out, errb bytes.Buffer
	code := runAccess(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestAccessRefusesNonCentralDeployments(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("EXPLORER_AUTH_MODE=elcano\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runAccessIn(t, dir, "list")
	if code != 1 || !strings.Contains(stderr, "EXPLORER_AUTH_MODE=central") {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
}

func TestAccessGrantListRevokeBackup(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "state", "access.db")
	env := "EXPLORER_AUTH_MODE=central\nEXPLORER_ACCESS_DB=" + db + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"list"}, 0, "No emails have Explorer access."},
		{[]string{"grant", "  Ada@Example.COM "}, 0, "Granted Explorer access: ada@example.com"},
		{[]string{"list"}, 0, "ada@example.com\tallowed"},
		{[]string{"revoke", "ada@example.com"}, 0, "Revoked Explorer access and sessions: ada@example.com"},
		{[]string{"revoke", "ada@example.com"}, 1, "Email is not currently allowed"},
		{[]string{"list", "--all"}, 0, "ada@example.com\trevoked"},
		{[]string{"grant", "not-an-email"}, 1, "valid email"},
		{[]string{"frobnicate"}, 2, "usage"},
		{[]string{"backup", filepath.Join(dir, "copy.db")}, 0, filepath.Join(dir, "copy.db")},
	}
	for _, s := range steps {
		code, out, stderr := runAccessIn(t, dir, s.args...)
		if code != s.code || !strings.Contains(out+stderr, s.want) {
			t.Errorf("%v: code %d out %q err %q", s.args, code, out, stderr)
		}
	}
	if st, err := os.Stat(filepath.Join(dir, "copy.db")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("backup: %v %v", st, err)
	}
}

func TestRunDispatchesVersionAndRefusesServeArgs(t *testing.T) {
	if code := run([]string{"version"}); code != 0 {
		t.Fatalf("version = %d", code)
	}
	if code := run([]string{"serve", "--port", "1"}); code != 2 {
		t.Fatalf("serve with args = %d", code)
	}
}

func TestRelativeDBPathIsPinnedBeforeHandOff(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("EXPLORER_AUTH_MODE=central\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	code, out, stderr := runAccessIn(t, dir, "--db", "rel.db", "grant", "ada@example.com")
	if code != 0 || !strings.Contains(out, "ada@example.com") {
		t.Fatalf("code %d %q %q", code, out, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "rel.db")); err != nil {
		t.Fatalf("database not at the relative path: %v", err)
	}
}
