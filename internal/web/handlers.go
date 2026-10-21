// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"errors"
	"html/template"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/ElcanoTek/explorer/internal/archive"
	"github.com/ElcanoTek/explorer/internal/centralauth"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if len(next) > 2048 {
		next = ""
	}
	destination := safeLocalPath(next, "/")
	if identityFrom(r) != nil {
		http.Redirect(w, r, destination, http.StatusSeeOther) //nolint:gosec // G710: safeLocalPath admits only same-origin paths.
		return
	}
	if p, ok := s.auth.(*centralProvider); ok {
		p.beginLogin(w, r, destination)
		return
	}
	s.auth.unauthenticated(w, r)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	p, ok := s.auth.(*centralProvider)
	if !ok {
		s.messagePage(w, r, http.StatusNotFound, "Sign-in unavailable",
			"Central sign-in is not configured for this Explorer instance.")
		return
	}
	q := r.URL.Query()
	code, state, errParam := q.Get("code"), q.Get("state"), q.Get("error")
	if errParam != "" || code == "" || state == "" || len(code) > 4096 || len(state) > 512 || len(errParam) > 256 {
		sess := sessionFrom(r)
		sess.data.Login = nil
		sess.dirty = true
		s.messagePage(w, r, http.StatusBadRequest, "Sign-in was not completed",
			"Return to Explorer and try signing in again.")
		return
	}
	token, destination, err := p.completeLogin(r, code, state)
	switch {
	case err == nil:
	case errors.Is(err, centralauth.ErrTransaction), errors.Is(err, centralauth.ErrCodeRejected):
		// A consumed, expired or superseded code (a second tab that started
		// its own sign-in, a stale bookmark) is a retry, not an outage.
		s.messagePage(w, r, http.StatusBadRequest, "Sign-in expired",
			"The sign-in request is no longer valid. Start a new sign-in to continue.")
		return
	case errors.Is(err, centralauth.ErrAccessDenied):
		s.messagePage(w, r, http.StatusForbidden, "Explorer access needed",
			"Your account is signed in, but it has not been given access to this "+
				"Explorer instance. Ask an administrator to enable access, then try again.")
		return
	default:
		slog.Warn("central sign-in failed", "err", err)
		s.messagePage(w, r, http.StatusBadGateway, "Unable to sign in",
			"The authentication service is temporarily unavailable. Try again shortly.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.SetCookie(w, p.sessionCookie(token))
	http.Redirect(w, r, safeLocalPath(destination, "/"), http.StatusSeeOther) //nolint:gosec // G710: safeLocalPath admits only same-origin paths.
}

type signedOutPage struct{ AccountURL string }

func (s *Server) handleSignedOut(w http.ResponseWriter, r *http.Request) {
	if identityFrom(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	account := s.settings.AuthLoginURL
	if p, ok := s.auth.(*centralProvider); ok {
		account = p.client.IssuerURL() + "/account"
	}
	s.render(w, r, http.StatusOK, "signed_out", signedOutPage{account})
}

// handleBackchannel receives Auth's signed events: an OIDC back-channel
// logout token (revoke every session of that account) or a versioned
// application-access token (grant or revoke this Explorer).
func (s *Server) handleBackchannel(w http.ResponseWriter, r *http.Request) {
	p, ok := s.auth.(*centralProvider)
	if !ok {
		jsonError(w, http.StatusNotFound, "Not Found")
		return
	}
	// Auth posts application/x-www-form-urlencoded; multipart is accepted
	// too, as the Python endpoint's Form() fields did.
	var err error
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		err = r.ParseMultipartForm(maxBackchannelBody) //nolint:gosec // G120: the body is already capped by MaxBytesReader in requireAuthentication.
	} else {
		err = r.ParseForm()
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid back-channel request")
		return
	}
	logoutToken, accessToken := r.PostForm.Get("logout_token"), r.PostForm.Get("access_token")
	if (logoutToken == "") == (accessToken == "") {
		jsonError(w, http.StatusBadRequest, "Invalid back-channel request")
		return
	}
	issuer, audience, now := p.client.IssuerURL(), p.client.ClientID(), s.now()
	if accessToken != "" {
		event, err := centralauth.VerifyAccessToken(accessToken, issuer, audience, p.keys.KeysForToken(accessToken), now)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "Invalid access token")
			return
		}
		if _, err := p.store.ApplyAccessProvisioning(event); err != nil {
			slog.Error("apply access provisioning", "err", err)
			jsonError(w, http.StatusInternalServerError, "Could not apply the access change")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	event, err := centralauth.VerifyLogoutToken(logoutToken, issuer, audience, p.keys.KeysForToken(logoutToken), now)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid logout token")
		return
	}
	if _, err := p.store.ConsumeLogoutEvent(event); err != nil {
		slog.Error("consume logout event", "err", err)
		jsonError(w, http.StatusInternalServerError, "Could not apply the logout")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	p, ok := s.auth.(*centralProvider)
	if !ok {
		sess.clear()
		http.Redirect(w, r, s.settings.AuthLoginURL+"/logout", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid form")
		return
	}
	token := p.sessionToken(r)
	if !centralauth.VerifyCSRF(token, r.PostForm.Get("csrf_token")) {
		jsonError(w, http.StatusForbidden, "Invalid CSRF token")
		return
	}
	p.store.RevokeSession(token)
	sess.clear()
	// Logging out means signing out of every Elcano app: hand the browser to
	// Auth's RP-initiated logout, which ends the central session, fans a
	// back-channel logout out to every registered application (this one
	// included, harmlessly), and lands on Auth's login page. /signed-out
	// remains for direct visits.
	http.SetCookie(w, p.clearCookie())
	http.Redirect(w, r, p.client.IssuerURL()+"/logout?client_id="+quoteAll(p.client.ClientID()), http.StatusSeeOther)
}

type emailPage struct {
	Email    *archive.Email
	Sender   sender
	BodyHTML template.HTML
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request, message string) {
	s.render(w, r, http.StatusNotFound, "auth_error", messagePage{
		Heading: "Email not found", Message: message, ActionURL: "/", ActionLabel: "Back to Inbox",
	})
}

func (s *Server) handleEmail(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("s3_key")
	if !s.isAllowedS3Key(key) {
		s.notFound(w, r, "Unknown email key.")
		return
	}
	email, err := s.inbox.GetEmail(r.Context(), key)
	if err != nil {
		slog.Warn("open email", "err", err)
		s.notFound(w, r, "This message could not be read from the archive.")
		return
	}
	// BodyPreviewHTML is the sanitizer's output (internal/htmlsafe): the
	// allow-list there is the boundary that makes it safe to emit unescaped.
	page := emailPage{Email: email, Sender: parseSender(email.From),
		BodyHTML: template.HTML(email.BodyPreviewHTML)} //nolint:gosec // G203: sanitized by htmlsafe.RenderHTMLPreview.
	s.render(w, r, http.StatusOK, "email_detail", page)
}

// Attachments are served straight from the parsed message: nothing is
// written to disk. Active content types are downgraded to a download, and
// the response is sandboxed so a hostile file opened in the browser cannot
// script against Explorer's origin.
func (s *Server) handleAttachment(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	key, filename := q.Get("s3_key"), q.Get("filename")
	if !s.isAllowedS3Key(key) || filename == "" {
		s.notFound(w, r, "Unknown email key.")
		return
	}
	att, err := s.inbox.Attachment(r.Context(), key, filename)
	if err != nil {
		if !errors.Is(err, archive.ErrNotFound) {
			slog.Warn("download attachment", "err", err)
		}
		s.notFound(w, r, "That attachment is not part of this message.")
		return
	}
	name := path.Base(strings.ReplaceAll(att.Name, "\\", "/"))
	if name == "." || name == "/" || name == "" {
		name = "attachment"
	}
	w.Header().Set("Content-Type", safeAttachmentType(name, att.ContentType))
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(att.Data) //nolint:gosec // G705: a download: sandbox CSP, nosniff, active types sent as octet-stream.
}

// safeAttachmentType picks the Content-Type for a download from the file
// name, keeping images (so cid: inline images render) and plain types, and
// turning anything a browser would execute into application/octet-stream.
func safeAttachmentType(name, declared string) string {
	ct := mime.TypeByExtension(strings.ToLower(path.Ext(name)))
	if ct == "" {
		ct = declared
	}
	base, _, _ := mime.ParseMediaType(ct)
	switch {
	case base == "":
		return "application/octet-stream"
	case base == "image/svg+xml", strings.Contains(base, "html"), strings.Contains(base, "xml"),
		strings.Contains(base, "javascript"):
		return "application/octet-stream"
	case strings.HasPrefix(base, "image/"), strings.HasPrefix(base, "text/plain"), strings.HasPrefix(base, "text/csv"),
		base == "application/pdf":
		return ct
	default:
		return "application/octet-stream"
	}
}
