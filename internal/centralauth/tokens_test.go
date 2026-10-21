// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package centralauth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var t1010 = time.Unix(1_010, 0)

func TestLogoutTokenChecksSignatureIssuerAndAudience(t *testing.T) {
	k := newKey(t)
	raw := mintLogout(t, k, nil)
	ev, err := VerifyLogoutToken(raw, "https://auth.example.com", "explorer", []string{k.pub}, t1010)
	if err != nil || ev.EventID != "event-123" || ev.Subject != "account-123" || ev.IssuedAt != 1_000 {
		t.Fatalf("ev=%+v err=%v", ev, err)
	}
	// A trailing "/" on either issuer still matches for back-channel tokens.
	if _, err := VerifyLogoutToken(raw, "https://auth.example.com/", "explorer", []string{k.pub}, t1010); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLogoutToken(raw, "https://auth.example.com", "lens", []string{k.pub}, t1010); !errors.Is(err, ErrCentralAuth) {
		t.Fatalf("wrong audience accepted: %v", err)
	}
	bad := mintLogout(t, k, map[string]any{"iss": 123})
	if _, err := VerifyLogoutToken(bad, "https://auth.example.com", "explorer", []string{k.pub}, t1010); err == nil {
		t.Fatal("numeric issuer accepted")
	}
	other := newKey(t)
	if _, err := VerifyLogoutToken(raw, "https://auth.example.com", "explorer", []string{other.pub}, t1010); err == nil {
		t.Fatal("foreign key accepted")
	}
}

func TestLogoutTokenRejections(t *testing.T) {
	k := newKey(t)
	cases := map[string]map[string]any{
		"expired":        {"exp": 1_000},
		"string exp":     {"exp": "soon"},
		"bool exp":       {"exp": true},
		"float exp":      {"exp": 1300.0 + 0.5},
		"missing exp":    {"exp": deleteClaim},
		"future iat":     {"iat": 2_000},
		"zero iat":       {"iat": 0},
		"empty sub":      {"sub": ""},
		"long sub":       {"sub": strings.Repeat("s", 256)},
		"missing jti":    {"jti": deleteClaim},
		"no event":       {"events": map[string]any{}},
		"event not dict": {"events": map[string]any{BackchannelLogoutEvent: true}},
		"nonce present":  {"nonce": "x"},
		"aud list":       {"aud": []string{"explorer"}},
	}
	for name, overrides := range cases {
		now := t1010
		if name == "expired" {
			now = time.Unix(1_200, 0)
		}
		raw := mintLogout(t, k, overrides)
		if _, err := VerifyLogoutToken(raw, "https://auth.example.com", "explorer", []string{k.pub}, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// exp + skew is still live.
	raw := mintLogout(t, k, map[string]any{"exp": 1_000})
	if _, err := VerifyLogoutToken(raw, "https://auth.example.com", "explorer", []string{k.pub}, time.Unix(1_059, 0)); err != nil {
		t.Errorf("token inside clock skew rejected: %v", err)
	}
}

func TestAccessTokenChecksSignatureClaimsAndVersion(t *testing.T) {
	k := newKey(t)
	raw := mintAccess(t, k, "grant", 7, nil)
	ev, err := VerifyAccessToken(raw, "https://auth.example.com", "explorer", []string{k.pub}, t1010)
	want := AccessProvisionEvent{
		EventID: "access-7", Subject: "account-123", Email: "alice@example.com",
		Issuer: "https://auth.example.com", IssuedAt: 1_000, Version: 7, Allowed: true,
	}
	if err != nil || ev != want {
		t.Fatalf("ev=%+v err=%v", ev, err)
	}
	if _, err := VerifyAccessToken(raw, "https://auth.example.com", "lens", []string{k.pub}, t1010); err == nil {
		t.Fatal("wrong audience accepted")
	}
	for name, tok := range map[string]string{
		"bool version":  mintAccess(t, k, "grant", true, nil),
		"zero version":  mintAccess(t, k, "grant", 0, nil),
		"float version": mintAccess(t, k, "grant", 1.5, nil),
		"bad action":    mintAccess(t, k, "promote", 1, nil),
		"bad email":     mintAccess(t, k, "grant", 1, map[string]any{"email": "not-an-email"}),
		"email number":  mintAccess(t, k, "grant", 1, map[string]any{"email": 5}),
		"nonce":         mintAccess(t, k, "grant", 1, map[string]any{"nonce": "x"}),
		"no events":     mintAccess(t, k, "grant", 1, map[string]any{"events": "x"}),
	} {
		if _, err := VerifyAccessToken(tok, "https://auth.example.com", "explorer", []string{k.pub}, t1010); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	revoke := mintAccess(t, k, "revoke", 2, nil)
	if ev, err := VerifyAccessToken(revoke, "https://auth.example.com", "explorer", []string{k.pub}, t1010); err != nil || ev.Allowed {
		t.Fatalf("revoke: %+v %v", ev, err)
	}
}

func TestBackChannelTokensRefuseOddKids(t *testing.T) {
	k := newKey(t)
	for _, kid := range []any{"\u00e9", 7, nil, "", strings.Repeat("a", 65), "a.b"} {
		header := mustJSON(t, map[string]any{"typ": "logout+jwt", "alg": "EdDSA", "kid": kid})
		claims := mustJSON(t, map[string]any{
			"iss": "https://auth.example.com", "sub": "s", "aud": "explorer", "iat": 1_000,
			"exp": 1_300, "jti": "j", "events": map[string]any{BackchannelLogoutEvent: map[string]any{}},
		})
		if _, err := VerifyLogoutToken(sign(k, header, claims), "https://auth.example.com", "explorer", []string{k.pub}, t1010); err == nil {
			t.Errorf("kid %v accepted", kid)
		}
	}
	access := mintAccess(t, k, "grant", 1, nil)
	parts := strings.Split(access, ".")
	header := mustJSON(t, map[string]any{"typ": "access+jwt", "alg": "EdDSA", "kid": "\u00e9"})
	claims, _ := decodeSegment(parts[1])
	if _, err := VerifyAccessToken(sign(k, header, claims), "https://auth.example.com", "explorer", []string{k.pub}, t1010); err == nil {
		t.Error("non-ASCII kid accepted on access token")
	}
}

func TestMalformedTokensAreErrorsNotPanics(t *testing.T) {
	k := newKey(t)
	for _, raw := range []string{"", "a", "a.b", "a.b.c", "!!.!!.!!", strings.Repeat("a", MaxTokenBytes+1), "e30.e30.e30"} {
		if _, err := VerifyLogoutToken(raw, "https://auth.example.com", "explorer", []string{k.pub}, t1010); err == nil {
			t.Errorf("%q accepted", raw)
		}
		if _, err := VerifyIdentityToken(raw, "https://auth.example.com", "explorer", "n", []string{k.pub}, t1010); err == nil {
			t.Errorf("%q accepted as id token", raw)
		}
	}
}

func TestIdentityTokenClaims(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	n := now.Unix()
	verify := func(tok string) error {
		_, err := VerifyIdentityToken(tok, "https://auth.example.com", "explorer", "expected-nonce", []string{k.pub}, now)
		return err
	}
	if p, err := VerifyIdentityToken(mintID(t, k, n, nil, nil), "https://auth.example.com", "explorer", "expected-nonce", []string{k.pub}, now); err != nil || p.Subject != "account-123" || p.Email != "alice@example.com" {
		t.Fatalf("p=%+v err=%v", p, err)
	}
	if err := verify(mintID(t, k, n, nil, map[string]any{"exp": n - 10})); err != nil {
		t.Errorf("small clock skew rejected: %v", err)
	}
	for name, h := range map[string]map[string]any{
		"alg none": {"alg": "none"}, "alg hs256": {"alg": "HS256"}, "typ logout": {"typ": "logout+jwt"},
		"typ access": {"typ": "access+jwt"}, "kid \u00e9": {"kid": "\u00e9"}, "kid int": {"kid": 7}, "kid nil": {"kid": nil},
	} {
		if err := verify(mintID(t, k, n, h, nil)); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("header %s accepted (%v)", name, err)
		}
	}
	for name, c := range map[string]map[string]any{
		"wrong nonce": {"nonce": "wrong"}, "accented nonce": {"nonce": "expected-nonc\u00e9"},
		"aud lens": {"aud": "lens"}, "aud list": {"aud": []string{"explorer"}},
		"surrogate nonce": {"nonce": "\xed\xa0\x80"},
		"other iss":       {"iss": "https://other-auth.example.com"}, "iss slash": {"iss": "https://auth.example.com/"},
		"expired": {"exp": n - 120}, "exp str": {"exp": "soon"}, "exp bool": {"exp": true},
		"future iat": {"iat": n + 600}, "empty sub": {"sub": ""}, "bad email": {"email": "not-an-email"},
		"no nonce": {"nonce": deleteClaim},
	} {
		if err := verify(mintID(t, k, n, nil, c)); err == nil {
			t.Errorf("claims %s accepted", name)
		}
	}
	// A known kid signed by another key is refused.
	forged := mintID(t, newKey(t), n, map[string]any{"kid": k.kid}, nil)
	if err := verify(forged); err == nil {
		t.Error("forged signature accepted")
	}
}

func TestNormalizeEmail(t *testing.T) {
	good := map[string]string{
		"\tAlice@Example.COM\n":  "alice@example.com",
		"STRASSE@ex.example":     "strasse@ex.example",
		"stra\u00dfe@ex.example": "strasse@ex.example",
	}
	for in, want := range good {
		if got, err := NormalizeEmail(in); err != nil || got != want {
			t.Errorf("NormalizeEmail(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "no-at", "a@@b", "@b.example", "a@", "a@.b", "a@b.", "a\x00@b.example", "a\u200b@b.example", strings.Repeat("a", 250) + "@b.example"} {
		if _, err := NormalizeEmail(bad); err == nil {
			t.Errorf("NormalizeEmail(%q) accepted", bad)
		}
	}
}

func TestRequireSigningKeys(t *testing.T) {
	k := newKey(t)
	if err := RequireSigningKeys([]string{k.pub}); err != nil {
		t.Fatal(err)
	}
	for _, keys := range [][]string{nil, {"%%%"}, {"c2hvcnQ="}} {
		if err := RequireSigningKeys(keys); err == nil {
			t.Errorf("%v accepted", keys)
		}
	}
}

func TestCSRFBoundToSession(t *testing.T) {
	token := "browser-only-app-session-secret"
	csrf := CSRFToken(token)
	if !VerifyCSRF(token, csrf) || VerifyCSRF("a-different-session", csrf) || VerifyCSRF(token, "") || VerifyCSRF("", csrf) {
		t.Fatal("CSRF binding broken")
	}
}
