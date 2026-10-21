// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package htmlsafe

import (
	"regexp"
	"strings"
)

// Python's \s, for the CSS-noise pattern.
const pyWS = `\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}`

// One leading CSS rule, e.g. ".x { color: red }": what a <style> block's
// text looks like once a broken message has leaked it into the body.
var cssRuleRE = regexp.MustCompile(
	`^(?:\.[A-Za-z0-9_-]+|#[A-Za-z0-9_-]+|[A-Za-z][A-Za-z0-9_-]*)[` + pyWS + `]*\{[^{}]{1,800}\}[` + pyWS + `]*`)

// StripLeadingCSSNoise removes up to 50 CSS rules from the start of text
// (after leading whitespace). The result is always left-trimmed.
func StripLeadingCSSNoise(text string) string {
	if text == "" {
		return ""
	}
	cleaned := strings.TrimLeftFunc(text, isSpace)
	consumed := 0
	for i := 0; i < 50; i++ {
		loc := cssRuleRE.FindStringIndex(cleaned[consumed:])
		if loc == nil {
			break
		}
		consumed += loc[1]
	}
	if consumed > 0 {
		cleaned = strings.TrimLeftFunc(cleaned[consumed:], isSpace)
	}
	return cleaned
}

// RenderHTMLPreview turns an untrusted HTML body into sanitized, linkified
// markup that may be emitted unescaped.
func RenderHTMLPreview(bodyHTML string) string {
	if bodyHTML == "" {
		return ""
	}
	safe := Sanitize(bodyHTML)
	stripped := StripLeadingCSSNoise(safe)
	if stripped != safe {
		// The CSS strip works on markup and can cut a tag pair in half;
		// clean again so Linkify only ever sees well-formed markup.
		stripped = clean(stripped)
	}
	if stripped == "" {
		return ""
	}
	return Linkify(stripped)
}

// RenderPlainPreview turns a plain-text body into escaped, linkified markup.
func RenderPlainPreview(text string) string {
	if text == "" {
		return ""
	}
	return Linkify(EscapeText(text))
}
