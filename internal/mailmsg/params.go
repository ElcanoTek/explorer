// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package mailmsg

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// parseParams reads the ;-separated parameters of a structured header
// value (everything after the first ";"). It never fails: a segment that is
// not key=value is skipped. RFC 2231 extended values (name*=charset'lang'%xx)
// and continuations (name*0, name*1*, …) are joined and decoded, which is
// what Python's get_param plus collapse_rfc2231_value produced.
func parseParams(value string) map[string]string {
	out := map[string]string{}
	segments := splitParams(value)
	if len(segments) <= 1 {
		return out
	}
	type piece struct {
		n       int
		encoded bool
		value   string
	}
	continued := map[string][]piece{}
	for _, seg := range segments[1:] {
		eq := strings.IndexByte(seg, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(seg[:eq]))
		val := unquote(strings.TrimSpace(seg[eq+1:]))
		if key == "" {
			continue
		}
		base, rest, hasStar := strings.Cut(key, "*")
		if !hasStar {
			if _, exists := out[key]; !exists {
				out[key] = val
			}
			continue
		}
		p := piece{encoded: strings.HasSuffix(rest, "*") || rest == "", value: val}
		numPart := strings.TrimSuffix(rest, "*")
		if numPart == "" {
			p.n = 0
		} else {
			n, err := strconv.Atoi(numPart)
			if err != nil {
				continue
			}
			p.n = n
		}
		continued[base] = append(continued[base], p)
	}
	for name, pieces := range continued {
		sort.SliceStable(pieces, func(i, j int) bool { return pieces[i].n < pieces[j].n })
		charset := ""
		var raw strings.Builder
		for i, p := range pieces {
			v := p.value
			if p.encoded {
				if i == 0 {
					if parts := strings.SplitN(v, "'", 3); len(parts) == 3 {
						charset, v = parts[0], parts[2]
					}
				}
				if dec, err := url.PathUnescape(strings.ReplaceAll(v, "+", "%2B")); err == nil {
					v = dec
				}
			}
			raw.WriteString(v)
		}
		if charset != "" {
			out[name] = DecodeBytes([]byte(raw.String()), charset)
		} else {
			out[name] = toValidUTF8([]byte(raw.String()))
		}
	}
	return out
}

// splitParams splits on ";" outside double quotes.
func splitParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, escaped := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inQuote:
			escaped = true
		case c == '"':
			inQuote = !inQuote
		case c == ';' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	return append(out, cur.String())
}

// unquote removes surrounding double quotes and backslash escapes.
func unquote(v string) string {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return v
	}
	inner := v[1 : len(v)-1]
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		if inner[i] == '\\' && i+1 < len(inner) {
			i++
		}
		b.WriteByte(inner[i])
	}
	return b.String()
}
