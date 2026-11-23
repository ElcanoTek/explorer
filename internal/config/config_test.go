// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestDefaultsMatchThePythonService(t *testing.T) {
	s, err := FromEnv(map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if s.AWSRegion != "us-east-2" || s.Prefix != "emails/" || s.DatePrefixFormat != "emails/%Y/%m/%d/" ||
		s.MaxDatePrefixDays != 62 || s.MaxBodySearchDays != 14 || s.HeaderFetchBytes != 65536 ||
		s.SearchJobMaxSeconds != 120 || s.AuthMode != "elcano" || s.AuthCookieName != "elcano_auth" ||
		s.AuthLoginURL != "https://auth.elcanotek.com" || s.AuthClientID != "explorer" ||
		s.AccessDB != "/var/lib/explorer/access.db" || !s.AuthCookieSecure || !s.UICookieSecure ||
		s.SessionIdleSeconds != 43200 || s.SessionAbsoluteSeconds != 86400 ||
		s.SessionSecret != DevSessionSecret || s.ListenAddr != "127.0.0.1:8080" {
		t.Fatalf("defaults drifted: %+v", s)
	}
}

func TestParsingAndNormalization(t *testing.T) {
	s, err := FromEnv(map[string]string{
		"EXPLORER_AUTH_MODE":            " Central ",
		"AUTH_LOGIN_URL":                "https://auth.example.com//",
		"AUTH_SIGNING_PUBKEY":           " key1 ",
		"AUTH_SIGNING_PREVIOUS_PUBKEYS": "key2, ,key3",
		"EMAIL_S3_MAX_DATE_PREFIX_DAYS": " 7 ",
		"EXPLORER_UI_COOKIE_SECURE":     "off",
		"EMAIL_S3_DATE_PREFIX_FORMAT":   "archive/%Y/",
		"EMAIL_S3_PREFIX":               "archive/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.AuthMode != "central" || s.AuthLoginURL != "https://auth.example.com" || s.MaxDatePrefixDays != 7 || s.UICookieSecure {
		t.Fatalf("got %+v", s)
	}
	if !reflect.DeepEqual(s.SigningKeys(), []string{"key1", "key2", "key3"}) {
		t.Fatalf("keys %v", s.SigningKeys())
	}
	if !reflect.DeepEqual(s.AllowedKeyRoots(), []string{"archive/"}) {
		t.Fatalf("roots %v", s.AllowedKeyRoots())
	}
}

func TestBadNumbersAreNamed(t *testing.T) {
	_, err := FromEnv(map[string]string{"EMAIL_HEADER_FETCH_BYTES": "lots", "EMAIL_SEARCH_JOB_MAX_SECONDS": "0"})
	if err == nil || !strings.Contains(err.Error(), "EMAIL_HEADER_FETCH_BYTES") || !strings.Contains(err.Error(), "EMAIL_SEARCH_JOB_MAX_SECONDS") {
		t.Fatalf("err = %v", err)
	}
}

func TestEmptyDateFormatLeavesOnlyThePrefix(t *testing.T) {
	s, _ := FromEnv(map[string]string{"EMAIL_S3_DATE_PREFIX_FORMAT": ""})
	if !reflect.DeepEqual(s.AllowedKeyRoots(), []string{"emails/"}) {
		t.Fatalf("roots %v", s.AllowedKeyRoots())
	}
}

func TestOutboxPrefix(t *testing.T) {
	base := map[string]string{"EMAIL_S3_BUCKET": "b"}
	with := func(v string) map[string]string {
		env := map[string]string{"EMAIL_S3_OUTBOX_PREFIX": v}
		for k, val := range base {
			env[k] = val
		}
		return env
	}
	s, err := FromEnv(base)
	if err != nil || s.OutboxPrefix != "outbox/" {
		t.Fatalf("default: %q %v", s.OutboxPrefix, err)
	}
	if s, err := FromEnv(with("")); err != nil || s.OutboxPrefix != "" {
		t.Fatalf("off: %q %v", s.OutboxPrefix, err)
	}
	whole := map[string]string{"EMAIL_S3_BUCKET": "b", "EMAIL_S3_PREFIX": "", "EMAIL_S3_DATE_PREFIX_FORMAT": ""}
	if s, err := FromEnv(whole); err != nil || s.OutboxPrefix != "" {
		t.Fatalf("a whole-bucket inbox keeps the default Outbox off: %q %v", s.OutboxPrefix, err)
	}
	whole["EMAIL_S3_OUTBOX_PREFIX"] = "outbox/"
	if _, err := FromEnv(whole); err == nil {
		t.Fatal("an Outbox asked for inside a whole-bucket inbox must be refused")
	}
	for _, bad := range []string{"outbox", "emails/outbox/", "emails/", "e"} {
		if _, err := FromEnv(with(bad)); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	for key, want := range map[string]bool{
		"emails/2026/06/01/x":      true,
		"outbox/2026/06/01/x.eml":  true,
		"outbox/2026/06/01/x.json": false,
		"outbox/x":                 false,
		"other/x":                  false,
	} {
		if got := s.AllowedEmailKey(key); got != want {
			t.Errorf("%q = %v", key, got)
		}
	}
}
