// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ElcanoTek/explorer/internal/apitoken"
)

func TestTokenCommand(t *testing.T) {
	store := apitoken.NewStore(filepath.Join(t.TempDir(), "tokens.db"))
	defer func() { _ = store.Close() }()
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := runToken(context.Background(), args, &out, &errOut, store, "https://explorer.example/")
		return code, out.String(), errOut.String()
	}
	code, out, _ := run("create", "--label", "fleet-prod")
	if code != 0 || !strings.Contains(out, "EXPLORER_MCP_URL=https://explorer.example/mcp") || !strings.Contains(out, apitoken.TokenPrefix) {
		t.Fatalf("create: %d %s", code, out)
	}
	code, out, _ = run("create", "--label=ci", "--json")
	var created map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &created) != nil || created["id"].(float64) != 2 {
		t.Fatalf("create --json: %d %s", code, out)
	}
	if code, out, _ = run("list"); code != 0 || !strings.Contains(out, "fleet-prod") || strings.Contains(out, created["token"].(string)) {
		t.Fatalf("list: %d %s", code, out)
	}
	if code, _, _ = run("revoke", "1"); code != 0 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _, _ = run("revoke", "1"); code != 1 {
		t.Fatalf("second revoke: %d", code)
	}
	for _, args := range [][]string{{}, {"create"}, {"create", "--label"}, {"revoke", "x"}, {"frobnicate"}, {"list", "extra"}} {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}
