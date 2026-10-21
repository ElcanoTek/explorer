// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package auth holds the identity type every Explorer auth mode produces and
// the verifier for Elcano's external magic-link cookie.
//
// The Elcano cookie format is
//
//	base64url(payload_json) + "." + base64url(ed25519_signature)
//
// where the signature covers the base64url body *string*. The payload is
// {"email", "tenant", "iat", "exp"}; Explorer reads email, tenant and exp.
// Any service that mints that shape works. Explorer only holds the public
// half of the key, so a compromised Explorer host cannot mint sessions.
package auth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Identity is a signed-in browser. Provider is "elcano" or "central".
type Identity struct {
	Subject  string
	Email    string
	Tenant   string
	Provider string
}

// ParsePublicKey decodes a standard-base64 (padded) 32-byte Ed25519 public
// key. Anything else is nil.
func ParsePublicKey(src string) ed25519.PublicKey {
	if src == "" {
		return nil
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(src)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(raw)
}

// decodeB64URL decodes base64url with or without "=" padding, rejecting any
// character outside the alphabet.
func decodeB64URL(s string) ([]byte, bool) {
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// VerifyElcanoCookie returns the identity in a valid elcano_auth cookie, or
// nil. Every failure (no key configured, malformed token, bad signature,
// expired, missing email) is the same nil: callers treat it as logged out.
func VerifyElcanoCookie(token, pubkeyB64 string, now time.Time) *Identity {
	key := ParsePublicKey(strings.TrimSpace(pubkeyB64))
	if key == nil || token == "" {
		return nil
	}
	dot := strings.IndexByte(token, '.')
	if dot < 1 || dot == len(token)-1 {
		return nil
	}
	body, sigText := token[:dot], token[dot+1:]
	sig, ok := decodeB64URL(sigText)
	if !ok || len(sig) != ed25519.SignatureSize {
		return nil
	}
	if !ed25519.Verify(key, []byte(body), sig) {
		return nil
	}
	rawPayload, ok := decodeB64URL(body)
	if !ok || !utf8.Valid(rawPayload) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(rawPayload))
	dec.UseNumber()
	var payload map[string]any
	if err := dec.Decode(&payload); err != nil || payload == nil || dec.More() {
		return nil
	}
	email, _ := payload["email"].(string)
	if email == "" {
		return nil
	}
	expNum, ok := payload["exp"].(json.Number)
	if !ok {
		return nil
	}
	exp, err := strconv.ParseFloat(expNum.String(), 64)
	if err != nil || exp <= float64(now.UnixNano())/1e9 {
		return nil
	}
	tenant, _ := payload["tenant"].(string)
	return &Identity{Email: email, Tenant: tenant, Provider: "elcano"}
}
