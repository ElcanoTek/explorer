// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package centralauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RequireSigningKeys fails at startup, not at the first logout event, when
// no usable static key is configured. Central mode needs Auth's Ed25519
// public key to verify back-channel tokens even while Auth is unreachable.
func RequireSigningKeys(keys []string) error {
	if len(keys) == 0 {
		return errors.New("AUTH_SIGNING_PUBKEY is required in central mode: run `auth pubkey` on the auth host. " +
			"Rotation keys are fetched from Auth's /jwks.json at runtime, but one static key " +
			"is needed so verification works even when Auth is unreachable at startup")
	}
	for _, encoded := range keys {
		raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			return errors.New("AUTH_SIGNING_PUBKEY is not valid base64")
		}
		if len(raw) != 32 {
			return errors.New("AUTH_SIGNING_PUBKEY must decode to a 32-byte Ed25519 key")
		}
	}
	return nil
}

// FetchFunc fetches the JWKS document at url.
type FetchFunc func(ctx context.Context, url string) ([]byte, error)

// KeyResolver is Auth's Ed25519 public keys: the static env keys plus Auth's
// published /jwks.json. Auth rotates by publishing a new key beside the old
// one, so rotation is a one-sided change on Auth. Static keys stay the
// bootstrap and offline fallback: verifying a token whose key is already
// known never waits on Auth, and a fetch failure keeps the cached keys.
// Keys are returned in standard base64, the form the verifiers take.
type KeyResolver struct {
	jwksURL string
	static  []string
	fetch   FetchFunc
	now     func() time.Time

	mu          sync.Mutex
	remote      []string
	fetchedAt   time.Time
	lastAttempt time.Time
}

// NewKeyResolver builds a resolver for issuerURL. fetch nil uses
// DefaultFetch; now nil uses time.Now.
func NewKeyResolver(issuerURL string, static []string, fetch FetchFunc, now func() time.Time) *KeyResolver {
	if fetch == nil {
		fetch = DefaultFetch(nil)
	}
	if now == nil {
		now = time.Now
	}
	return &KeyResolver{
		jwksURL: strings.TrimRight(issuerURL, "/") + "/jwks.json",
		static:  append([]string(nil), static...),
		fetch:   fetch,
		now:     now,
	}
}

// DefaultFetch GETs a JWKS document without following redirects, within
// DefaultJWKSTimeout and MaxJWKSBytes. client nil uses a fresh client.
func DefaultFetch(client *http.Client) FetchFunc {
	if client == nil {
		client = &http.Client{}
	}
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return func(ctx context.Context, url string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, DefaultJWKSTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
		if err != nil {
			return nil, err
		}
		if len(raw) > MaxJWKSBytes {
			return nil, errors.New("the JWKS document was too large")
		}
		return raw, nil
	}
}

func dedupe(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, k := range l {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

// PublicKeys returns static plus published keys, refreshing the JWKS cache
// when it is older than JWKSCacheTTL.
func (r *KeyResolver) PublicKeys() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.publicKeysLocked()
}

func (r *KeyResolver) publicKeysLocked() []string {
	if r.fetchedAt.IsZero() || r.now().Sub(r.fetchedAt) > JWKSCacheTTL {
		r.refreshLocked(false)
	}
	return dedupe(r.static, r.remote)
}

// Refresh fetches the JWKS; true when the cache was updated. It is
// rate-limited (JWKSMinRefresh) so a flood of tokens with unknown kids
// cannot turn Explorer into a request amplifier against Auth.
func (r *KeyResolver) Refresh(force bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refreshLocked(force)
}

func (r *KeyResolver) refreshLocked(force bool) bool {
	now := r.now()
	if !force && !r.lastAttempt.IsZero() && now.Sub(r.lastAttempt) < JWKSMinRefresh {
		return false
	}
	r.lastAttempt = now
	raw, err := r.fetch(context.Background(), r.jwksURL)
	if err != nil {
		return false
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	var entries []json.RawMessage
	if keysRaw, ok := doc["keys"]; !ok || json.Unmarshal(keysRaw, &entries) != nil {
		return false
	}
	parsed := []string{}
	for _, entryRaw := range entries {
		var entry map[string]any
		if json.Unmarshal(entryRaw, &entry) != nil {
			continue
		}
		x, ok := entry["x"].(string)
		if entry["kty"] != "OKP" || entry["crv"] != "Ed25519" || !ok {
			continue
		}
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(x, "="))
		if err != nil || len(key) != 32 {
			continue
		}
		parsed = append(parsed, base64.StdEncoding.EncodeToString(key))
	}
	r.remote = parsed
	r.fetchedAt = now
	return true
}

// KeysForToken returns the keys to try for one token. A kid naming a static
// key returns at once and never waits on Auth's JWKS endpoint, which keeps
// revocation and provisioning available while Auth restarts. Otherwise the
// cache is refreshed when stale, so a key Auth retired stops being trusted
// within JWKSCacheTTL, and an unknown kid triggers one throttled refresh.
func (r *KeyResolver) KeysForToken(raw string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	kid, hasKid := tokenKid(raw)
	if hasKid {
		for _, k := range r.static {
			if KidForKey(k) == kid {
				return dedupe(r.static, r.remote)
			}
		}
	}
	keys := r.publicKeysLocked()
	if hasKid && !containsKid(keys, kid) && r.refreshLocked(false) {
		keys = r.publicKeysLocked()
	}
	return keys
}

func containsKid(keys []string, kid string) bool {
	for _, k := range keys {
		if KidForKey(k) == kid {
			return true
		}
	}
	return false
}
