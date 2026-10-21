// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package centralauth

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

var errInvalidEmail = errors.New("A valid email address is required.") //nolint:revive,staticcheck // ST1005: shown verbatim to operators, as before.

// isOtherChar is Python's unicodedata.category(c).startswith("C"): control,
// format, surrogate, private use, or unassigned.
func isOtherChar(r rune) bool {
	if unicode.In(r, unicode.C) {
		return true
	}
	return !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z)
}

func hasOtherChar(s string) bool {
	for _, r := range s {
		if isOtherChar(r) {
			return true
		}
	}
	return false
}

// NormalizeEmail is the one spelling Explorer stores and compares: NFC,
// trimmed, Unicode case-folded, with exactly one "@" and no control or
// unassigned characters.
func NormalizeEmail(email string) (string, error) {
	if !utf8.ValidString(email) {
		return "", errInvalidEmail
	}
	normalized := cases.Fold().String(strings.TrimFunc(norm.NFC.String(email), unicode.IsSpace))
	if normalized == "" || utf8.RuneCountInString(normalized) > 254 || strings.Count(normalized, "@") != 1 {
		return "", errInvalidEmail
	}
	local, domain, _ := strings.Cut(normalized, "@")
	if local == "" || domain == "" || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", errInvalidEmail
	}
	if hasOtherChar(normalized) {
		return "", errors.New("Email contains unsupported control characters.") //nolint:revive,staticcheck // ST1005: operator-facing text.
	}
	return normalized, nil
}
