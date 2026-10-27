// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package apitoken

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s := NewStore(filepath.Join(t.TempDir(), "state", "api_tokens.db"))
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestCreateVerifyRevoke(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	token, raw, err := s.Create(ctx, "  fleet   prod ", []string{ScopeSearch})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, TokenPrefix) || token.Label != "fleet prod" || token.Prefix != raw[:DisplayPrefixChars] {
		t.Fatalf("token %+v raw %q", token, raw)
	}
	st, err := os.Stat(s.Path())
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("database mode: %v %v", st.Mode(), err)
	}
	got, err := s.Verify(ctx, " "+raw+" ")
	if err != nil || got.ID != token.ID || !got.Allows(ScopeSearch) || got.LastUsedAt == "" {
		t.Fatalf("verify: %+v %v", got, err)
	}
	var te *TokenError
	if _, err := s.Verify(ctx, raw+"x"); !errors.As(err, &te) {
		t.Fatalf("wrong secret: %v", err)
	}
	if ok, err := s.Revoke(ctx, token.ID); !ok || err != nil {
		t.Fatalf("revoke: %v %v", ok, err)
	}
	if _, err := s.Verify(ctx, raw); !errors.As(err, &te) || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked token verified: %v", err)
	}
	if ok, _ := s.Revoke(ctx, token.ID); ok {
		t.Fatal("revoked twice")
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 1 || list[0].RevokedAt == "" {
		t.Fatalf("list: %+v %v", list, err)
	}
}

func TestVerifyNeverCreatesTheDatabase(t *testing.T) {
	s := newTestStore(t)
	var te *TokenError
	if _, err := s.Verify(context.Background(), TokenPrefix+"abc"); !errors.As(err, &te) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.Verify(context.Background(), "lens_abc"); !errors.As(err, &te) {
		t.Fatalf("foreign prefix: %v", err)
	}
	if _, err := os.Stat(s.Path()); !os.IsNotExist(err) {
		t.Fatalf("database created by an unauthenticated lookup: %v", err)
	}
	if list, err := s.List(context.Background()); err != nil || len(list) != 0 {
		t.Fatalf("list on a fresh host: %v %v", list, err)
	}
}

func TestCreateValidates(t *testing.T) {
	s := newTestStore(t)
	var ve *ValidationError
	if _, _, err := s.Create(context.Background(), "", []string{ScopeSearch}); !errors.As(err, &ve) {
		t.Fatalf("empty label: %v", err)
	}
	if _, _, err := s.Create(context.Background(), "x", []string{"jobs:run"}); !errors.As(err, &ve) {
		t.Fatalf("unknown scope: %v", err)
	}
	if _, _, err := s.Create(context.Background(), "x", nil); !errors.As(err, &ve) {
		t.Fatalf("no scope: %v", err)
	}
}

func TestLastUsedIsWrittenAtMostOncePerResolution(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	_, raw, err := s.Create(ctx, "fleet", Scopes)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := s.Verify(ctx, raw)
	now = now.Add(30 * time.Second)
	second, _ := s.Verify(ctx, raw)
	if first.LastUsedAt != second.LastUsedAt {
		t.Fatalf("rewritten within the resolution: %s then %s", first.LastUsedAt, second.LastUsedAt)
	}
	now = now.Add(time.Minute)
	third, _ := s.Verify(ctx, raw)
	if third.LastUsedAt == second.LastUsedAt {
		t.Fatal("not refreshed after the resolution")
	}
}

func TestDownloadTickets(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	token, _, err := s.Create(ctx, "fleet", Scopes)
	if err != nil {
		t.Fatal(err)
	}
	d := Download{Kind: "cached", Key: "emails/attachments/by-url/abc/r.csv", Name: "r.csv"}
	ticket, expires, err := s.SignDownload(ctx, token, d)
	if err != nil || expires != now.Unix()+DownloadLinkSeconds {
		t.Fatalf("sign: %v %d", err, expires)
	}
	got, gotD, err := s.VerifyDownload(ctx, ticket)
	if err != nil || got.ID != token.ID || gotD != d {
		t.Fatalf("verify: %+v %+v %v", got, gotD, err)
	}
	var te *TokenError
	now = now.Add(DownloadLinkSeconds*time.Second + time.Second)
	if _, _, err := s.VerifyDownload(ctx, ticket); !errors.As(err, &te) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired ticket: %v", err)
	}
	searchOnly, _, _ := s.Create(ctx, "search", []string{ScopeSearch})
	ticket, _, _ = s.SignDownload(ctx, searchOnly, d)
	if _, _, err := s.VerifyDownload(ctx, ticket); !errors.As(err, &te) {
		t.Fatalf("search-only ticket: %v", err)
	}
}

func TestAnUnreadableDatabaseIsAStorageErrorNotAnInvalidToken(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads through directory permissions")
	}
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := NewStore(filepath.Join(dir, "api_tokens.db"))
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	var te *TokenError
	if _, err := s.Verify(context.Background(), TokenPrefix+"abc"); err == nil || errors.As(err, &te) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.List(context.Background()); err == nil {
		t.Fatal("List must surface the stat error")
	}
}
