// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ElcanoTek/explorer/internal/apitoken"
)

// The programmatic surfaces authenticate with bearer tokens only: no sign-in
// redirect, no UI cookie read or set, and a browser session grants nothing.
func TestAPIAndMCPUseBearerTokensNotTheBrowserSession(t *testing.T) {
	tokens := apitoken.NewStore(filepath.Join(t.TempDir(), "tokens.db"))
	_, raw, err := tokens.Create(context.Background(), "fleet", apitoken.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, map[string]string{"EXPLORER_AUTH_MODE": "elcano"}, func(o *Options) { o.Tokens = tokens })
	e.setCookie("elcano_auth", mintElcano(e.priv, "alice@example.com", time.Now().Add(time.Hour)))
	e.store.put("emails/2026/06/01/a", "Authentication-Results: amazonses.com; dmarc=pass header.from=vendor.example\r\n"+
		"From: <reports@vendor.example>\r\nSubject: Daily\r\nDate: Mon, 01 Jun 2026 10:00:00 +0000\r\n\r\nx\r\n",
		time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC))

	call := func(path, body, token string) response {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, e.ts.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := e.browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return response{resp, string(b)}
	}
	// The browser's Elcano cookie is not an API credential.
	for _, path := range []string{"/mcp", "/api/v1/search_emails"} {
		r := call(path, `{}`, "")
		if r.StatusCode != http.StatusUnauthorized || r.Header.Get("Set-Cookie") != "" ||
			!strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			t.Fatalf("%s without a token: %d %q %s", path, r.StatusCode, r.Header.Get("Set-Cookie"), r.body)
		}
	}
	r := call("/api/v1/search_emails", `{"date_from":"2026-06-01","date_to":"2026-06-01","sender_contains":"vendor.example"}`, raw)
	if r.StatusCode != http.StatusOK || !strings.Contains(r.body, `"matches_found":1`) || r.Header.Get("Set-Cookie") != "" {
		t.Fatalf("REST with a token: %d %s", r.StatusCode, r.body)
	}
	r = call("/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, raw)
	if r.StatusCode != http.StatusOK || !strings.Contains(r.body, "find_latest_report") ||
		r.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("MCP with a token: %d %s", r.StatusCode, r.body)
	}
}
