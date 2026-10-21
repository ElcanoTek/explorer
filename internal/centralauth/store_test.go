// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package centralauth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type storeClock struct{ unix int64 }

func (c *storeClock) now() time.Time { return time.Unix(c.unix, 0) }

func openTestStore(t *testing.T) (*Store, *storeClock) {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "state", "access.db"), time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	clock := &storeClock{unix: 1_000}
	s.Now = clock.now
	return s, clock
}

func rawDB(t *testing.T, s *Store) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", s.Path())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestAccessIsDefaultDenyAndCaseInsensitive(t *testing.T) {
	s, _ := openTestStore(t)
	if s.IsAllowed("alice@example.com") {
		t.Fatal("allowed before grant")
	}
	if _, err := s.GrantAccess("Alice@Example.com"); err != nil {
		t.Fatal(err)
	}
	entries, err := s.ListAccess(false)
	if !s.IsAllowed("alice@example.com") || err != nil || len(entries) != 1 || entries[0].Email != "alice@example.com" {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	st, _ := os.Stat(s.Path())
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("db mode %v", st.Mode().Perm())
	}
	dir, _ := os.Stat(filepath.Dir(s.Path()))
	if dir.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", dir.Mode().Perm())
	}
	if _, err := s.GetAccess("bob@example.com"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("GetAccess unknown: %v", err)
	}
	if _, err := s.GrantAccess("not-an-email"); err == nil {
		t.Fatal("invalid email granted")
	}
}

func TestSessionSecretIsHashedAtRest(t *testing.T) {
	s, clock := openTestStore(t)
	_, _ = s.GrantAccess("alice@example.com")
	issued, err := s.CreateSession("account-123", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := rawDB(t, s).QueryRow("SELECT token_hash FROM sessions").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(issued.Token))
	if stored != hex.EncodeToString(sum[:]) || stored == issued.Token || len(issued.Token) != 43 {
		t.Fatalf("stored %q token %q", stored, issued.Token)
	}
	clock.unix = 1_001
	if id := s.GetIdentity(issued.Token); id == nil || id.Email != "alice@example.com" || id.Subject != "account-123" || id.Provider != "central" {
		t.Fatalf("identity %+v", id)
	}
	for _, bad := range []string{"", "nope", "t\u00e9"} {
		if s.GetIdentity(bad) != nil {
			t.Errorf("%q resolved", bad)
		}
	}
}

func TestSessionObeysIdleAndAbsoluteExpiration(t *testing.T) {
	s, clock := openTestStore(t)
	_, _ = s.GrantAccess("alice@example.com")
	idle, _ := s.CreateSession("account-123", "alice@example.com")
	clock.unix = 4_599
	if s.GetIdentity(idle.Token) == nil {
		t.Fatal("expired early")
	}
	clock.unix = 8_200
	if s.GetIdentity(idle.Token) != nil {
		t.Fatal("idle session survived")
	}
	clock.unix = 10_000
	absolute, _ := s.CreateSession("account-123", "alice@example.com")
	for ts := int64(13_000); ts <= 52_000; ts += 3_000 {
		clock.unix = ts
		if s.GetIdentity(absolute.Token) == nil {
			t.Fatalf("expired at %d", ts)
		}
	}
	clock.unix = 53_199
	if s.GetIdentity(absolute.Token) == nil {
		t.Fatal("expired before absolute limit")
	}
	clock.unix = 53_200
	if s.GetIdentity(absolute.Token) != nil {
		t.Fatal("absolute limit not enforced")
	}
}

func TestRevokingAccessInvalidatesSessions(t *testing.T) {
	s, clock := openTestStore(t)
	_, _ = s.GrantAccess("alice@example.com")
	issued, _ := s.CreateSession("account-123", "alice@example.com")
	if ok, err := s.RevokeAccess("ALICE@example.com"); !ok || err != nil {
		t.Fatalf("revoke %v %v", ok, err)
	}
	if ok, _ := s.RevokeAccess("alice@example.com"); ok {
		t.Fatal("second revoke reported a change")
	}
	clock.unix = 1_001
	if s.GetIdentity(issued.Token) != nil {
		t.Fatal("session survived revocation")
	}
	if _, err := s.CreateSession("account-123", "alice@example.com"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("create after revoke: %v", err)
	}
	all, _ := s.ListAccess(true)
	allowed, _ := s.ListAccess(false)
	if len(all) != 1 || all[0].Enabled || len(allowed) != 0 {
		t.Fatalf("all=%v allowed=%v", all, allowed)
	}
}

func TestCreateSessionRejectsBadSubject(t *testing.T) {
	s, _ := openTestStore(t)
	_, _ = s.GrantAccess("alice@example.com")
	for _, subject := range []string{"", "a\x00b", string(make([]byte, 256))} {
		if _, err := s.CreateSession(subject, "alice@example.com"); !errors.Is(err, ErrCentralAuth) || errors.Is(err, ErrAccessDenied) {
			t.Errorf("subject %q: %v", subject, err)
		}
	}
}

func TestLogoutRevokesOnlyThePresentedSession(t *testing.T) {
	s, clock := openTestStore(t)
	_, _ = s.GrantAccess("alice@example.com")
	first, _ := s.CreateSession("account-123", "alice@example.com")
	second, _ := s.CreateSession("account-123", "alice@example.com")
	clock.unix = 1_001
	if !s.RevokeSession(first.Token) || s.RevokeSession(first.Token) {
		t.Fatal("revoke result wrong")
	}
	clock.unix = 1_002
	if s.GetIdentity(first.Token) != nil || s.GetIdentity(second.Token) == nil {
		t.Fatal("wrong session revoked")
	}
}

func TestBackchannelLogoutIsIdempotentAndScopedToSubject(t *testing.T) {
	s, clock := openTestStore(t)
	_, _ = s.GrantAccess("alice@example.com")
	first, _ := s.CreateSession("account-123", "alice@example.com")
	second, _ := s.CreateSession("account-456", "alice@example.com")
	ev := LogoutEvent{EventID: "event-123", Issuer: "https://auth.example.com", Subject: "account-123", IssuedAt: 1_001}
	clock.unix = 1_002
	if ok, err := s.ConsumeLogoutEvent(ev); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	clock.unix = 1_003
	if ok, _ := s.ConsumeLogoutEvent(ev); ok {
		t.Fatal("replay applied")
	}
	clock.unix = 1_004
	if s.GetIdentity(first.Token) != nil || s.GetIdentity(second.Token) == nil {
		t.Fatal("logout not scoped to subject")
	}
}

func TestReplayTableIsPrunedAfterRetention(t *testing.T) {
	s, clock := openTestStore(t)
	week := int64(RevocationEventRetention / time.Second)
	_, _ = s.ConsumeLogoutEvent(LogoutEvent{EventID: "old-event", Issuer: "i", Subject: "account-1", IssuedAt: 1_000})
	clock.unix = 1_000 + week + 1
	_, _ = s.ConsumeLogoutEvent(LogoutEvent{EventID: "new-event", Issuer: "i", Subject: "account-2", IssuedAt: 1_000 + week})
	rows, err := rawDB(t, s).Query("SELECT event_id FROM revocation_events")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	if len(ids) != 1 || ids[0] != "new-event" {
		t.Fatalf("ids %v", ids)
	}
}

func TestAccessProvisioningIsOrderedAndRevocationEndsSessions(t *testing.T) {
	s, clock := openTestStore(t)
	grant := AccessProvisionEvent{EventID: "grant-2", Subject: "account-123", Email: "alice@example.com",
		Issuer: "https://auth.example.com", IssuedAt: 1_000, Version: 2, Allowed: true}
	stale := grant
	stale.EventID, stale.Version, stale.Allowed = "revoke-1", 1, false
	revoke := grant
	revoke.EventID, revoke.Version, revoke.Allowed = "revoke-3", 3, false

	clock.unix = 1_010
	if ok, err := s.ApplyAccessProvisioning(grant); !ok || err != nil {
		t.Fatalf("grant: %v %v", ok, err)
	}
	clock.unix = 1_011
	issued, err := s.CreateSession(grant.Subject, grant.Email)
	if err != nil {
		t.Fatal(err)
	}
	clock.unix = 1_012
	if ok, _ := s.ApplyAccessProvisioning(stale); ok || !s.IsAllowed(grant.Email) {
		t.Fatal("stale revoke applied")
	}
	clock.unix = 1_013
	if ok, _ := s.ApplyAccessProvisioning(revoke); !ok || s.IsAllowed(grant.Email) {
		t.Fatal("revoke not applied")
	}
	clock.unix = 1_014
	if s.GetIdentity(issued.Token) != nil {
		t.Fatal("session survived provisioning revoke")
	}
	clock.unix = 1_015
	if ok, _ := s.ApplyAccessProvisioning(revoke); ok {
		t.Fatal("replayed version applied")
	}
}

func TestProvisioningEmailChangeRevokesOldEmail(t *testing.T) {
	s, _ := openTestStore(t)
	ev := AccessProvisionEvent{EventID: "e1", Subject: "acct", Email: "old@example.com", Issuer: "i", IssuedAt: 1, Version: 1, Allowed: true}
	_, _ = s.ApplyAccessProvisioning(ev)
	old, _ := s.CreateSession("acct", "old@example.com")
	ev.EventID, ev.Email, ev.Version = "e2", "new@example.com", 2
	if ok, _ := s.ApplyAccessProvisioning(ev); !ok {
		t.Fatal("not applied")
	}
	if s.IsAllowed("old@example.com") || !s.IsAllowed("new@example.com") || s.GetIdentity(old.Token) != nil {
		t.Fatal("email change not handled")
	}
}

func TestSessionTouchIsRateLimited(t *testing.T) {
	s, clock := openTestStore(t)
	_, _ = s.GrantAccess("alice@example.com")
	issued, _ := s.CreateSession("account-123", "alice@example.com")
	idle := int64(s.Idle() / time.Second)
	stamps := func() (int64, int64) {
		var last, exp int64
		if err := rawDB(t, s).QueryRow("SELECT last_seen_at, idle_expires_at FROM sessions WHERE token_hash = ?", issued.TokenHash).Scan(&last, &exp); err != nil {
			t.Fatal(err)
		}
		return last, exp
	}
	check := func(wantLast int64) {
		t.Helper()
		if last, exp := stamps(); last != wantLast || exp != wantLast+idle {
			t.Fatalf("stamps %d %d, want %d", last, exp, wantLast)
		}
	}
	check(1_000)
	for _, ts := range []int64{1_030, 1_059} {
		clock.unix = ts
		if s.GetIdentity(issued.Token) == nil {
			t.Fatal("rejected inside interval")
		}
	}
	check(1_000)
	clock.unix = 1_060
	if s.GetIdentity(issued.Token) == nil {
		t.Fatal("rejected at touch")
	}
	check(1_060)
	clock.unix = 1_060 + idle
	if s.GetIdentity(issued.Token) != nil {
		t.Fatal("idle limit exceeded")
	}
}

func TestOpenStoreValidation(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ idle, abs time.Duration }{{0, time.Hour}, {time.Hour, 0}, {2 * time.Hour, time.Hour}} {
		if _, err := OpenStore(filepath.Join(dir, "a.db"), c.idle, c.abs); err == nil {
			t.Errorf("%v/%v accepted", c.idle, c.abs)
		}
	}
	if _, err := OpenStore(filepath.Join(dir, "a?.db"), time.Hour, time.Hour); err == nil {
		t.Error("? in path accepted")
	}
}

func TestRefusesNewerSchema(t *testing.T) {
	s, _ := openTestStore(t)
	path := s.Path()
	if _, err := rawDB(t, s).Exec("UPDATE schema_meta SET value = '4' WHERE key = 'schema_version'"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := OpenStore(path, time.Hour, 2*time.Hour); err == nil {
		t.Fatal("newer schema accepted")
	}
}

// pythonSchema is the DDL exactly as app/central_auth.py executed it.
const pythonSchema = `
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_entries (
                    email TEXT PRIMARY KEY COLLATE NOCASE,
                    enabled INTEGER NOT NULL DEFAULT 1
                        CHECK (enabled IN (0, 1)),
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    email TEXT NOT NULL REFERENCES access_entries(email),
                    created_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    idle_expires_at INTEGER NOT NULL,
                    absolute_expires_at INTEGER NOT NULL,
                    revoked_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS sessions_email_idx ON sessions(email);
                CREATE INDEX IF NOT EXISTS sessions_expiry_idx
                    ON sessions(absolute_expires_at, idle_expires_at);

                CREATE TABLE IF NOT EXISTS revocation_events (
                    event_id TEXT PRIMARY KEY,
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    received_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_provisioning_state (
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    email TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
                    event_id TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    received_at INTEGER NOT NULL,
                    PRIMARY KEY (issuer, subject)
                );
`

// TestReadsADatabaseWrittenByThePythonService proves an existing
// /var/lib/explorer/access.db keeps working after the Go rewrite.
func TestReadsADatabaseWrittenByThePythonService(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	token := "python-issued-session-token"
	sum := sha256.Sum256([]byte(token))
	for _, stmt := range []string{
		"PRAGMA journal_mode = WAL",
		pythonSchema,
		"INSERT OR IGNORE INTO schema_meta(key, value) VALUES('schema_version', '3')",
		"INSERT INTO access_entries(email, enabled, created_at, updated_at) VALUES ('alice@example.com', 1, 900, 900)",
		"INSERT INTO access_entries(email, enabled, created_at, updated_at) VALUES ('bob@example.com', 0, 900, 950)",
		"INSERT INTO sessions VALUES ('" + hex.EncodeToString(sum[:]) + "', 'account-1', 'alice@example.com', 950, 950, 4550, 44150, NULL)",
		"INSERT INTO access_provisioning_state VALUES ('https://auth.example.com', 'account-1', 'alice@example.com', 5, 1, 'e5', 940, 945)",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	_ = db.Close()

	s, err := OpenStore(path, time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Now = func() time.Time { return time.Unix(1_000, 0) }
	if id := s.GetIdentity(token); id == nil || id.Email != "alice@example.com" || id.Subject != "account-1" {
		t.Fatalf("python session not honoured: %+v", id)
	}
	if !s.IsAllowed("ALICE@example.com") || s.IsAllowed("bob@example.com") {
		t.Fatal("python access list misread")
	}
	if ok, _ := s.ApplyAccessProvisioning(AccessProvisionEvent{EventID: "e4", Subject: "account-1", Email: "alice@example.com",
		Issuer: "https://auth.example.com", IssuedAt: 990, Version: 4}); ok {
		t.Fatal("older provisioning version applied over python state")
	}
	if _, err := s.GrantAccess("bob@example.com"); err != nil || !s.IsAllowed("bob@example.com") {
		t.Fatalf("grant over python row: %v", err)
	}
	issued, err := s.CreateSession("account-2", "bob@example.com")
	if err != nil || s.GetIdentity(issued.Token) == nil {
		t.Fatalf("new session in python db: %v", err)
	}
	var version string
	if err := rawDB(t, s).QueryRow("SELECT value FROM schema_meta WHERE key='schema_version'").Scan(&version); err != nil || version != "3" {
		t.Fatalf("schema version %q %v", version, err)
	}
}

func TestBackupIsAConsistentPrivateCopy(t *testing.T) {
	s, _ := openTestStore(t)
	if _, err := s.GrantAccess("ada@example.com"); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := s.Backup(context.Background(), dest); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dest)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v, %v", st, err)
	}
	if err := s.Backup(context.Background(), dest); err == nil {
		t.Fatal("overwrote an existing backup")
	}
	copyStore, err := OpenStore(dest, time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer copyStore.Close()
	if !copyStore.IsAllowed("ada@example.com") {
		t.Fatal("backup is missing the access list")
	}
}
