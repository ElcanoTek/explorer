// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var now = time.Unix(1_800_000_000, 0)

func newKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, base64.StdEncoding.EncodeToString(pub)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mint mints an elcano_auth token exactly like auth-server does.
func mint(t *testing.T, priv ed25519.PrivateKey, overrides map[string]any) string {
	t.Helper()
	payload := map[string]any{
		"email":  "alice@elcanotek.com",
		"tenant": "elcanotek.com",
		"iat":    now.Unix(),
		"exp":    now.Unix() + 3600,
	}
	for k, v := range overrides {
		payload[k] = v
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	body := b64url(raw)
	return body + "." + b64url(ed25519.Sign(priv, []byte(body)))
}

func TestValidCookieVerifies(t *testing.T) {
	priv, pub := newKey(t)
	id := VerifyElcanoCookie(mint(t, priv, nil), pub, now)
	if id == nil || id.Email != "alice@elcanotek.com" || id.Tenant != "elcanotek.com" || id.Provider != "elcano" {
		t.Fatalf("identity = %+v", id)
	}
}

func TestPaddedSegmentsAccepted(t *testing.T) {
	priv, pub := newKey(t)
	payload := `{"email":"a@example.com","exp":1900000000}`
	body := base64.URLEncoding.EncodeToString([]byte(payload))
	token := body + "." + base64.URLEncoding.EncodeToString(ed25519.Sign(priv, []byte(body)))
	if VerifyElcanoCookie(token, pub, now) == nil {
		t.Fatal("padded token rejected")
	}
}

func TestFloatExpiryAccepted(t *testing.T) {
	priv, pub := newKey(t)
	if VerifyElcanoCookie(mint(t, priv, map[string]any{"exp": float64(now.Unix()) + 0.5}), pub, now) == nil {
		t.Fatal("float exp in the future rejected")
	}
}

func TestRejections(t *testing.T) {
	priv, pub := newKey(t)
	other, _ := newKey(t)
	valid := mint(t, priv, nil)
	sig := valid[strings.IndexByte(valid, '.')+1:]
	tampered := b64url([]byte(`{"email":"mallory@evil.example","exp":9999999999}`)) + "." + sig
	cases := map[string]string{
		"expired":        mint(t, priv, map[string]any{"exp": now.Unix() - 1}),
		"expires now":    mint(t, priv, map[string]any{"exp": now.Unix()}),
		"bool exp":       mint(t, priv, map[string]any{"exp": true}),
		"string exp":     mint(t, priv, map[string]any{"exp": "9999999999"}),
		"missing email":  mint(t, priv, map[string]any{"email": ""}),
		"non-str email":  mint(t, priv, map[string]any{"email": 7}),
		"tampered":       tampered,
		"foreign key":    mint(t, other, nil),
		"empty":          "",
		"not a token":    "not-a-token",
		"one part":       "only-one-part",
		"three parts":    "a.b.c",
		"leading dot":    ".abc",
		"trailing dot":   "abc.",
		"bad sig chars":  valid[:strings.IndexByte(valid, '.')+1] + "!!" + sig,
		"payload array":  signRaw(priv, `[1,2]`),
		"trailing junk":  signRaw(priv, `{"email":"a@b.example","exp":9999999999} x`),
		"invalid utf8":   signRaw(priv, "{\"email\":\"\xff\",\"exp\":9999999999}"),
		"duplicate json": signRaw(priv, `{"email":"a@b.example","exp":9999999999}{}`),
	}
	for name, token := range cases {
		if id := VerifyElcanoCookie(token, pub, now); id != nil {
			t.Errorf("%s: verified %+v", name, id)
		}
	}
}

func signRaw(priv ed25519.PrivateKey, payload string) string {
	body := b64url([]byte(payload))
	return body + "." + b64url(ed25519.Sign(priv, []byte(body)))
}

func TestNoOrBadPublicKeyRejectsEverything(t *testing.T) {
	priv, pub := newKey(t)
	token := mint(t, priv, nil)
	for _, key := range []string{"", "not base64", base64.StdEncoding.EncodeToString([]byte("short")), strings.TrimRight(pub, "=")} {
		if VerifyElcanoCookie(token, key, now) != nil {
			t.Errorf("key %q accepted", key)
		}
	}
}
