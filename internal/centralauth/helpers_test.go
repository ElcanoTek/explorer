// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package centralauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type key struct {
	priv ed25519.PrivateKey
	pub  string // standard base64
	kid  string
}

func newKey(t testing.TB) key {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	return key{priv: priv, pub: base64.StdEncoding.EncodeToString(pub), kid: b64url(sum[:16])}
}

func (k key) rawPub() []byte { return k.priv.Public().(ed25519.PublicKey) }

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// sign builds a compact token from raw header and claims JSON.
func sign(k key, header, claims []byte) string {
	body := b64url(header) + "." + b64url(claims)
	return body + "." + b64url(ed25519.Sign(k.priv, []byte(body)))
}

func merge(base map[string]any, overrides map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overrides {
		if v == deleteClaim {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

type deleteMarker struct{}

var deleteClaim any = deleteMarker{}

func mintLogout(t testing.TB, k key, overrides map[string]any) string {
	t.Helper()
	header := map[string]any{"typ": "logout+jwt", "alg": "EdDSA", "kid": k.kid}
	claims := merge(map[string]any{
		"iss":    "https://auth.example.com",
		"sub":    "account-123",
		"aud":    "explorer",
		"email":  "alice@example.com",
		"iat":    1_000,
		"exp":    1_300,
		"jti":    "event-123",
		"events": map[string]any{BackchannelLogoutEvent: map[string]any{}},
	}, overrides)
	return sign(k, mustJSON(t, header), mustJSON(t, claims))
}

func mintAccess(t testing.TB, k key, action string, version any, overrides map[string]any) string {
	t.Helper()
	header := map[string]any{"typ": "access+jwt", "alg": "EdDSA", "kid": k.kid}
	claims := merge(map[string]any{
		"iss":   "https://auth.example.com",
		"sub":   "account-123",
		"aud":   "explorer",
		"email": "alice@example.com",
		"iat":   1_000,
		"exp":   1_300,
		"jti":   "access-" + string(mustJSON(t, version)),
		"events": map[string]any{
			ApplicationAccessEvent: map[string]any{"action": action, "version": version},
		},
	}, overrides)
	return sign(k, mustJSON(t, header), mustJSON(t, claims))
}

// mintID builds an id_token shaped like Auth's token.SignIdentity output.
func mintID(t testing.TB, k key, nowUnix int64, headerOverrides, overrides map[string]any) string {
	t.Helper()
	header := merge(map[string]any{"typ": "JWT", "alg": "EdDSA", "kid": k.kid}, headerOverrides)
	claims := merge(map[string]any{
		"iss":       "https://auth.example.com",
		"sub":       "account-123",
		"aud":       "explorer",
		"email":     "Alice@Example.com",
		"iat":       nowUnix,
		"exp":       nowUnix + 300,
		"nonce":     "expected-nonce",
		"auth_time": nowUnix,
		"amr":       []string{"pwd"},
		"acr":       "urn:elcanotek:loa:1",
	}, overrides)
	return sign(k, mustJSON(t, header), mustJSON(t, claims))
}

func jwksFor(keys ...key) []byte {
	entries := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, map[string]any{
			"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
			"kid": k.kid, "x": b64url(k.rawPub()),
		})
	}
	raw, _ := json.Marshal(map[string]any{"keys": entries})
	return raw
}
