// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ElcanoTek/explorer/internal/api"
	"github.com/ElcanoTek/explorer/internal/apitoken"
	"github.com/ElcanoTek/explorer/internal/archive"
	"github.com/ElcanoTek/explorer/internal/config"
)

type memStore struct{ objects map[string][]byte }

func (m memStore) List(_ context.Context, prefix, _ string, _ int32) (archive.ListPage, error) {
	page := archive.ListPage{}
	for k, v := range m.objects {
		if strings.HasPrefix(k, prefix) {
			page.Objects = append(page.Objects, archive.Object{Key: k, LastModified: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC), Size: int64(len(v))})
		}
	}
	return page, nil
}

func (m memStore) Get(_ context.Context, key string, _ int64) ([]byte, error) {
	return m.objects[key], nil
}

func newServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, err := config.FromEnv(map[string]string{"EMAIL_S3_BUCKET": "b", "EXPLORER_PUBLIC_URL": "https://explorer.example"})
	if err != nil {
		t.Fatal(err)
	}
	store := memStore{objects: map[string][]byte{
		"emails/2026/06/01/a": []byte("Authentication-Results: amazonses.com; dmarc=pass header.from=vendor.example\r\n" +
			"From: <reports@vendor.example>\r\nSubject: Daily report\r\nDate: Mon, 01 Jun 2026 10:00:00 +0000\r\n\r\nhi\r\n"),
	}}
	tokens := apitoken.NewStore(filepath.Join(t.TempDir(), "tokens.db"))
	t.Cleanup(func() { _ = tokens.Close() })
	_, raw, err := tokens.Create(context.Background(), "test", apitoken.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	return New(api.New(api.Deps{Inbox: archive.New(store, s), Settings: s, Tokens: tokens})), raw
}

func rpc(t *testing.T, srv *Server, token, body string, headers map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestToolsMatchTheirOperations(t *testing.T) {
	if got := strings.Join(ToolNames(), ","); got != "search_emails,search_emails_fuzzy,find_latest_report" {
		t.Fatalf("tools %s", got)
	}
	for _, tool := range defs.Tools {
		var a map[string]any
		if err := json.Unmarshal(tool.Annotations, &a); err != nil || a["readOnlyHint"] != true {
			t.Errorf("%s must be annotated read-only", tool.Name)
		}
	}
}

func TestInitializeListAndCall(t *testing.T) {
	srv, raw := newServer(t)
	_, out := rpc(t, srv, raw, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, nil)
	res := out["result"].(map[string]any)
	if res["protocolVersion"] != "2025-06-18" || !strings.Contains(res["instructions"].(string), "s3_key") {
		t.Fatalf("initialize %v", out)
	}
	_, out = rpc(t, srv, raw, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, nil)
	if tools := out["result"].(map[string]any)["tools"].([]any); len(tools) != 3 {
		t.Fatalf("tools/list %v", out)
	}
	_, out = rpc(t, srv, raw, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_emails",`+
		`"arguments":{"sender_contains":"vendor.example","date_from":"2026-06-01","date_to":"2026-06-01"}}}`, nil)
	res = out["result"].(map[string]any)
	if res["isError"] != false {
		t.Fatalf("call %v", out)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte(res["content"].([]any)[0].(map[string]any)["text"].(string)), &body)
	if body["ok"] != true || body["matches_found"].(float64) != 1 {
		t.Fatalf("result %v", body)
	}
}

func TestToolErrorsAreToolResults(t *testing.T) {
	srv, raw := newServer(t)
	_, out := rpc(t, srv, raw, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_emails","arguments":{"date_from":"2026-06-01"}}}`, nil)
	res := out["result"].(map[string]any)
	if res["isError"] != true || !strings.Contains(res["content"].([]any)[0].(map[string]any)["text"].(string), "date_to") {
		t.Fatalf("missing argument: %v", out)
	}
	_, out = rpc(t, srv, raw, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_emails","arguments":{"date_from":"2026-06-01","date_to":"2026-06-01","x":1}}}`, nil)
	if out["result"].(map[string]any)["isError"] != true {
		t.Fatalf("unknown argument: %v", out)
	}
	_, out = rpc(t, srv, raw, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_everything"}}`, nil)
	if out["error"].(map[string]any)["code"].(float64) != -32602 {
		t.Fatalf("unknown tool: %v", out)
	}
}

func TestTransportRules(t *testing.T) {
	srv, raw := newServer(t)
	rec, _ := rpc(t, srv, "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: %d", rec.Code)
	}
	rec, _ = rpc(t, srv, raw, `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("batch: %d", rec.Code)
	}
	rec, _ = rpc(t, srv, raw, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("notification: %d", rec.Code)
	}
	rec, _ = rpc(t, srv, raw, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"Origin": "https://evil.example"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", rec.Code)
	}
	rec, _ = rpc(t, srv, raw, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"Origin": "https://explorer.example"})
	if rec.Code != http.StatusOK {
		t.Fatalf("own origin: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", w.Code)
	}
	_, out := rpc(t, srv, raw, `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`, nil)
	if out["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Fatalf("unknown method: %v", out)
	}
}
