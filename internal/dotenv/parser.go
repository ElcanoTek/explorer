// SPDX-License-Identifier: BSD-3-Clause
//
// Go port of the python-dotenv 1.2.4 parser and ${VAR} interpolation
// (https://github.com/theskumar/python-dotenv, src/dotenv/parser.py and
// src/dotenv/variables.py), which Explorer vendored before its Go rewrite.
// Keeping the exact grammar means an existing /opt/explorer/.env means the
// same thing to the Go service as it did to the Python one. See LICENSE in
// this directory.
// Copyright (c) 2014, Saurabh Kumar (python-dotenv), 2013, Ted Tieken
// (django-dotenv-rw), 2013, Jacob Kaplan-Moss (django-dotenv)

// Package dotenv parses dotenv files with python-dotenv's grammar: optional
// `export`, single- or double-quoted values (multi-line allowed), inline
// comments after whitespace, and ${VAR} / ${VAR:-default} interpolation
// resolved in file order.
package dotenv

import (
	"regexp"
	"strings"
	"unicode"
)

// Python's \s is Unicode-aware; RE2's is ASCII. This class is the Python set.
const pyWS = `\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}`

var (
	reMultilineWhitespace = regexp.MustCompile(`^[` + pyWS + `]*`)
	reWhitespace          = regexp.MustCompile(`^[^\S\r\n]*`)
	reExport              = regexp.MustCompile(`^(?:export[^\S\r\n]+)?`)
	reSingleQuotedKey     = regexp.MustCompile(`^'([^']+)'`)
	reUnquotedKey         = regexp.MustCompile(`^([^=#` + pyWS + `]+)`)
	reEqualSign           = regexp.MustCompile(`^(=[^\S\r\n]*)`)
	reSingleQuotedValue   = regexp.MustCompile(`(?s)^'((?:\\.|[^'\\])*)'`)
	reDoubleQuotedValue   = regexp.MustCompile(`(?s)^"((?:\\.|[^"\\])*)"`)
	reUnquotedValue       = regexp.MustCompile(`^([^\r\n]*)`)
	reComment             = regexp.MustCompile(`^(?:[^\S\r\n]*#[^\r\n]*)?`)
	reEndOfLine           = regexp.MustCompile(`^[^\S\r\n]*(?:\r\n|\n|\r|$)`)
	reRestOfLine          = regexp.MustCompile(`^[^\r\n]*(?:\r|\n|\r\n)?`)
	reDoubleQuoteEscapes  = regexp.MustCompile(`\\[\\'"abfnrtv]`)
	reSingleQuoteEscapes  = regexp.MustCompile(`\\[\\']`)
	reInlineComment       = regexp.MustCompile(`[` + pyWS + `]+#.*`)
	rePosixVariable       = regexp.MustCompile(`\$\{([^}:]*)(?::-([^}]*))?\}`)
)

// Binding is one statement of a dotenv file. A comment or blank run has no
// key; a parse error has no key and Error set. Original is the exact source
// text the statement spans, so an editor can rewrite one binding in place.
type Binding struct {
	Key      string
	HasKey   bool
	Value    string
	HasValue bool
	Original string
	Line     int
	Error    bool
}

type reader struct {
	s    string
	pos  int
	mark int
	line int
	mLn  int
}

type parseError struct{}

func (r *reader) hasNext() bool { return r.pos < len(r.s) }

// peek returns the next byte as a string, or "" at the end.
func (r *reader) peek() string {
	if r.pos >= len(r.s) {
		return ""
	}
	return r.s[r.pos : r.pos+1]
}

// read matches re at the cursor (every pattern is ^-anchored), advances past
// it, and returns the first capture group (or "" when there is none).
func (r *reader) read(re *regexp.Regexp) string {
	loc := re.FindStringSubmatchIndex(r.s[r.pos:])
	if loc == nil {
		panic(parseError{})
	}
	consumed := r.s[r.pos : r.pos+loc[1]]
	r.line += countNewlines(consumed)
	r.pos += loc[1]
	if len(loc) >= 4 && loc[2] >= 0 {
		return consumed[loc[2]:loc[3]]
	}
	return ""
}

func countNewlines(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n':
			n++
		case '\r':
			n++
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
		}
	}
	return n
}

func decodeEscapes(re *regexp.Regexp, s string) string {
	return re.ReplaceAllStringFunc(s, func(m string) string {
		switch m[1] {
		case 'a':
			return "\a"
		case 'b':
			return "\b"
		case 'f':
			return "\f"
		case 'n':
			return "\n"
		case 'r':
			return "\r"
		case 't':
			return "\t"
		case 'v':
			return "\v"
		default:
			return m[1:]
		}
	})
}

func (r *reader) parseValue() string {
	switch r.peek() {
	case "'":
		return decodeEscapes(reSingleQuoteEscapes, r.read(reSingleQuotedValue))
	case `"`:
		return decodeEscapes(reDoubleQuoteEscapes, r.read(reDoubleQuotedValue))
	case "", "\n", "\r":
		return ""
	default:
		part := r.read(reUnquotedValue)
		return strings.TrimRightFunc(reInlineComment.ReplaceAllString(part, ""), IsPySpace)
	}
}

func (r *reader) parseBinding() (b Binding) {
	r.mark, r.mLn = r.pos, r.line
	defer func() {
		if rec := recover(); rec != nil {
			if _, ok := rec.(parseError); !ok {
				panic(rec)
			}
			r.read(reRestOfLine)
			b = Binding{Original: r.s[r.mark:r.pos], Line: r.mLn, Error: true}
		}
	}()
	r.read(reMultilineWhitespace)
	if !r.hasNext() {
		return Binding{Original: r.s[r.mark:r.pos], Line: r.mLn}
	}
	r.read(reExport)
	var key string
	hasKey := true
	switch r.peek() {
	case "#":
		hasKey = false
	case "'":
		key = r.read(reSingleQuotedKey)
	default:
		key = r.read(reUnquotedKey)
	}
	r.read(reWhitespace)
	var value string
	hasValue := false
	if r.peek() == "=" {
		eq := r.read(reEqualSign)
		hasValue = true
		// `KEY= # comment` is an empty value; `KEY=#x` keeps the #.
		if len(eq) <= 1 || r.peek() != "#" {
			value = r.parseValue()
		}
	}
	r.read(reComment)
	r.read(reEndOfLine)
	return Binding{
		Key: key, HasKey: hasKey, Value: value, HasValue: hasValue && hasKey,
		Original: r.s[r.mark:r.pos], Line: r.mLn,
	}
}

// IsPySpace reports whether Python's str.isspace() holds for r.
func IsPySpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// Parse splits text into bindings exactly as python-dotenv's parse_stream
// does. A leading byte-order mark is ignored.
func Parse(text string) []Binding {
	r := &reader{s: strings.TrimPrefix(text, "\ufeff"), line: 1}
	var out []Binding
	for r.hasNext() {
		out = append(out, r.parseBinding())
	}
	return out
}

// Interpolate resolves ${NAME} and ${NAME:-default} in value against env,
// the way python-dotenv's variables.py does: a missing name takes the
// default, or "".
func Interpolate(value string, env func(string) (string, bool)) string {
	return rePosixVariable.ReplaceAllStringFunc(value, func(m string) string {
		sub := rePosixVariable.FindStringSubmatch(m)
		if v, ok := env(sub[1]); ok {
			return v
		}
		return sub[2]
	})
}
