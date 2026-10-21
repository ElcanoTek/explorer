// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package centralauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Principal is who signed in, taken only from Auth's signed id_token.
type Principal struct {
	Subject string
	Email   string
	Nonce   string
}

// LogoutEvent is a verified back-channel logout and its replay key.
type LogoutEvent struct {
	EventID  string
	Subject  string
	Issuer   string
	IssuedAt int64
}

// AccessProvisionEvent is Auth's signed, versioned desired membership.
type AccessProvisionEvent struct {
	EventID  string
	Subject  string
	Email    string
	Issuer   string
	IssuedAt int64
	Version  int64
	Allowed  bool
}

const b64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func inB64URLAlphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(b64urlAlphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}

func decodeSegment(segment string) ([]byte, bool) {
	if segment == "" || !inB64URLAlphabet(segment) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	return raw, err == nil
}

// decodeObject parses one JSON object the way Python's json.loads +
// isinstance(dict) does: valid UTF-8, a single object, numbers kept exact.
func decodeObject(raw []byte) (map[string]any, bool) {
	if !utf8.Valid(raw) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return nil, false
	}
	obj, ok := v.(map[string]any)
	return obj, ok
}

// intClaim is Python's `isinstance(v, int) and not isinstance(v, bool)`:
// a JSON integer literal (no fraction or exponent).
func intClaim(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	i, err := strconv.ParseInt(n.String(), 10, 64)
	return i, err == nil
}

// identifier is a non-empty string of at most 255 characters.
func identifier(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || s == "" || utf8.RuneCountInString(s) > maxIdentifierLength {
		return "", false
	}
	return s, true
}

// headerKid returns the token's kid when it has the shape Auth emits
// (1-64 base64url characters). A kid is public, so it is compared with ==;
// the alphabet check keeps an exotic value away from any comparison.
func headerKid(header map[string]any) (string, bool) {
	kid, ok := header["kid"].(string)
	if !ok || len(kid) == 0 || len(kid) > 64 || !inB64URLAlphabet(kid) {
		return "", false
	}
	return kid, true
}

// KidForKey is base64url(sha256(raw key)[:16]) for a standard-base64 key, or
// "" when the key does not decode to 32 bytes.
func KidForKey(encoded string) string {
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

type parsedToken struct {
	header, claims map[string]any
	kid            string
}

// parseSigned splits, decodes and signature-checks a compact EdDSA token of
// the given typ against the keys whose kid matches the header's.
func parseSigned(raw, typ string, keys []string) (*parsedToken, bool) {
	if len(raw) > MaxTokenBytes {
		return nil, false
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, false
	}
	headerRaw, ok1 := decodeSegment(parts[0])
	claimsRaw, ok2 := decodeSegment(parts[1])
	signature, ok3 := decodeSegment(parts[2])
	if !ok1 || !ok2 || !ok3 {
		return nil, false
	}
	header, ok1 := decodeObject(headerRaw)
	claims, ok2 := decodeObject(claimsRaw)
	if !ok1 || !ok2 {
		return nil, false
	}
	if header["typ"] != typ || header["alg"] != "EdDSA" {
		return nil, false
	}
	kid, ok := headerKid(header)
	if !ok {
		return nil, false
	}
	signed := []byte(parts[0] + "." + parts[1])
	for _, encoded := range keys {
		if KidForKey(encoded) != kid {
			continue
		}
		key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			continue
		}
		if len(signature) == ed25519.SignatureSize && ed25519.Verify(ed25519.PublicKey(key), signed, signature) {
			return &parsedToken{header: header, claims: claims, kid: kid}, true
		}
	}
	return nil, false
}

// liveTimes checks exp (with skew) and iat (positive, not in the future).
func liveTimes(claims map[string]any, now int64) (int64, bool) {
	skew := int64(ClockSkew / time.Second)
	exp, ok := intClaim(claims["exp"])
	if !ok || exp+skew <= now {
		return 0, false
	}
	iat, ok := intClaim(claims["iat"])
	if !ok || iat <= 0 || iat > now+skew {
		return 0, false
	}
	return iat, true
}

func sameIssuer(v any, issuer string) bool {
	s, ok := v.(string)
	return ok && strings.TrimRight(s, "/") == strings.TrimRight(issuer, "/")
}

// VerifyLogoutToken verifies one OIDC back-channel logout token.
func VerifyLogoutToken(raw, issuer, audience string, keys []string, now time.Time) (LogoutEvent, error) {
	invalid := newErr(ErrCentralAuth, "The logout token was invalid")
	tok, ok := parseSigned(raw, "logout+jwt", keys)
	if !ok {
		return LogoutEvent{}, invalid
	}
	c := tok.claims
	iat, ok := liveTimes(c, now.Unix())
	if !ok || !sameIssuer(c["iss"], issuer) || c["aud"] != audience {
		return LogoutEvent{}, invalid
	}
	subject, ok1 := identifier(c["sub"])
	eventID, ok2 := identifier(c["jti"])
	events, ok3 := c["events"].(map[string]any)
	if !ok1 || !ok2 || !ok3 {
		return LogoutEvent{}, invalid
	}
	if _, ok := events[BackchannelLogoutEvent].(map[string]any); !ok {
		return LogoutEvent{}, invalid
	}
	if _, hasNonce := c["nonce"]; hasNonce {
		return LogoutEvent{}, invalid
	}
	return LogoutEvent{EventID: eventID, Subject: subject, Issuer: strings.TrimRight(issuer, "/"), IssuedAt: iat}, nil
}

// VerifyAccessToken verifies Auth's signed application-membership event.
func VerifyAccessToken(raw, issuer, audience string, keys []string, now time.Time) (AccessProvisionEvent, error) {
	invalid := newErr(ErrCentralAuth, "The access token was invalid")
	tok, ok := parseSigned(raw, "access+jwt", keys)
	if !ok {
		return AccessProvisionEvent{}, invalid
	}
	c := tok.claims
	emailRaw, isStr := c["email"].(string)
	if _, present := c["email"]; !present {
		emailRaw, isStr = "", true
	}
	if !isStr {
		return AccessProvisionEvent{}, invalid
	}
	email, err := NormalizeEmail(emailRaw)
	if err != nil {
		return AccessProvisionEvent{}, invalid
	}
	iat, ok := liveTimes(c, now.Unix())
	if !ok || !sameIssuer(c["iss"], issuer) || c["aud"] != audience {
		return AccessProvisionEvent{}, invalid
	}
	subject, ok1 := identifier(c["sub"])
	eventID, ok2 := identifier(c["jti"])
	events, _ := c["events"].(map[string]any)
	access, ok3 := events[ApplicationAccessEvent].(map[string]any)
	if !ok1 || !ok2 || !ok3 {
		return AccessProvisionEvent{}, invalid
	}
	version, ok := intClaim(access["version"])
	action := access["action"]
	if !ok || version <= 0 || (action != "grant" && action != "revoke") {
		return AccessProvisionEvent{}, invalid
	}
	if _, hasNonce := c["nonce"]; hasNonce {
		return AccessProvisionEvent{}, invalid
	}
	return AccessProvisionEvent{
		EventID: eventID, Subject: subject, Email: email, Issuer: strings.TrimRight(issuer, "/"),
		IssuedAt: iat, Version: version, Allowed: action == "grant",
	}, nil
}

// VerifyIdentityToken verifies the id_token from Auth's /token and returns
// who signed in. Identity is taken from a token signed with Auth's published
// keys, never from the plain claims beside it in the response.
func VerifyIdentityToken(raw, issuer, audience, expectedNonce string, keys []string, now time.Time) (Principal, error) {
	invalid := newErr(ErrCentralAuth, "The authentication response was invalid")
	tok, ok := parseSigned(raw, "JWT", keys)
	if !ok {
		return Principal{}, invalid
	}
	c := tok.claims
	subject, ok := identifier(c["sub"])
	if !ok {
		return Principal{}, invalid
	}
	nonce, ok := c["nonce"].(string)
	if !ok || subtle.ConstantTimeCompare([]byte(expectedNonce), []byte(nonce)) != 1 {
		return Principal{}, invalid
	}
	// Exact: Auth signs its canonical issuer, which never ends in "/".
	if iss, ok := c["iss"].(string); !ok || iss != strings.TrimRight(issuer, "/") {
		return Principal{}, invalid
	}
	if aud, ok := c["aud"].(string); !ok || aud != audience {
		return Principal{}, invalid
	}
	if _, ok := liveTimes(c, now.Unix()); !ok {
		return Principal{}, invalid
	}
	emailRaw, isStr := c["email"].(string)
	if _, present := c["email"]; !present {
		emailRaw, isStr = "", true
	}
	if !isStr {
		return Principal{}, invalid
	}
	email, err := NormalizeEmail(emailRaw)
	if err != nil {
		return Principal{}, invalid
	}
	return Principal{Subject: subject, Email: email, Nonce: nonce}, nil
}

// tokenKid is the kid of a compact token's header, if well formed.
func tokenKid(raw string) (string, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", false
	}
	headerRaw, ok := decodeSegment(parts[0])
	if !ok {
		return "", false
	}
	header, ok := decodeObject(headerRaw)
	if !ok {
		return "", false
	}
	return headerKid(header)
}
