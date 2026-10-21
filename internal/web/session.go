// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The "explorer_ui" cookie is a small signed JSON document: the browser's
// search-ownership id and, in central mode, the short-lived sign-in
// transaction. It is not the login: that is the verified Elcano cookie or the
// opaque central session. Signing (HMAC-SHA256 over EXPLORER_SESSION_SECRET)
// makes it tamper-evident; nothing in it is secret from its own browser.
const (
	uiCookieName   = "explorer_ui"
	uiCookieMaxAge = 14 * 24 * time.Hour
	uiCookieLimit  = 4096
)

type loginTransaction struct {
	State     string `json:"state"`
	Nonce     string `json:"nonce"`
	Verifier  string `json:"verifier"`
	Next      string `json:"next"`
	CreatedAt int64  `json:"created_at"`
}

type uiSessionData struct {
	SearchOwnerID string            `json:"search_owner_id,omitempty"`
	Login         *loginTransaction `json:"central_auth_transaction,omitempty"`
}

type uiSession struct {
	data    uiSessionData
	dirty   bool
	cleared bool
}

func (s *uiSession) clear() {
	s.data = uiSessionData{}
	s.dirty = true
	s.cleared = true
}

type sessionCodec struct {
	key    []byte
	secure bool
	now    func() time.Time
}

func (c sessionCodec) sign(payload string) string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// decode returns the session carried by r, or an empty one when the cookie
// is missing, malformed, forged or older than its max age.
func (c sessionCodec) decode(r *http.Request) *uiSession {
	s := &uiSession{}
	ck, err := r.Cookie(uiCookieName)
	if err != nil || len(ck.Value) > uiCookieLimit {
		return s
	}
	parts := strings.Split(ck.Value, ".")
	if len(parts) != 3 {
		return s
	}
	payload := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(c.sign(payload)), []byte(parts[2])) {
		return s
	}
	issued, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || c.now().Sub(time.Unix(issued, 0)) > uiCookieMaxAge {
		return s
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return s
	}
	var data uiSessionData
	if json.Unmarshal(raw, &data) == nil {
		s.data = data
	}
	return s
}

func (c sessionCodec) cookie(s *uiSession) *http.Cookie {
	ck := &http.Cookie{ //nolint:gosec // G124: Secure follows EXPLORER_UI_COOKIE_SECURE (on unless developing over HTTP).
		Name: uiCookieName, Path: "/", HttpOnly: true, Secure: c.secure,
		SameSite: http.SameSiteLaxMode,
	}
	if s.cleared && s.data == (uiSessionData{}) {
		ck.MaxAge = -1
		return ck
	}
	raw, _ := json.Marshal(s.data)
	payload := base64.RawURLEncoding.EncodeToString(raw) + "." + strconv.FormatInt(c.now().Unix(), 10)
	ck.Value = payload + "." + c.sign(payload)
	ck.MaxAge = int(uiCookieMaxAge / time.Second)
	return ck
}
