// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package api

import (
	"math"
	"strings"
	"time"
)

// Argument readers over a decoded JSON object. A value of the wrong type is
// an invalid_argument *Error naming the argument; null is "absent".

func optString(args map[string]any, name string) (string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return "", nil
	}
	s, isString := v.(string)
	if !isString {
		return "", invalidArg("%s must be a string", name)
	}
	return s, nil
}

func optStrings(args map[string]any, name string) ([]string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return nil, nil
	}
	if s, isString := v.(string); isString {
		return []string{s}, nil
	}
	list, isList := v.([]any)
	if !isList {
		return nil, invalidArg("%s must be a list of strings", name)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, isString := item.(string)
		if !isString {
			return nil, invalidArg("%s must be a list of strings", name)
		}
		out = append(out, s)
	}
	return out, nil
}

// optBool returns nil when the argument is absent.
func optBool(args map[string]any, name string) (*bool, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return nil, nil
	}
	b, isBool := v.(bool)
	if !isBool {
		return nil, invalidArg("%s must be true or false", name)
	}
	return &b, nil
}

func boolOr(args map[string]any, name string, def bool) (bool, error) {
	b, err := optBool(args, name)
	if err != nil || b == nil {
		return def, err
	}
	return *b, nil
}

// intUpTo reads an integer in [1, hi], def when absent.
func intUpTo(args map[string]any, name string, def, hi int) (int, error) {
	const lo = 1
	v, ok := args[name]
	if !ok || v == nil {
		return def, nil
	}
	f, isNumber := v.(float64)
	if !isNumber || f != math.Trunc(f) {
		return 0, invalidArg("%s must be an integer", name)
	}
	if f < float64(lo) || f > float64(hi) {
		return 0, invalidArg("%s must be from %d to %d", name, lo, hi)
	}
	return int(f), nil
}

const isoDate = "2006-01-02"

var dateTimeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02T15:04",
}

// parseBound is the Python parse_date_bound: a date-only start is 00:00 UTC,
// a date-only end is 23:59:59.999999 UTC, and a datetime keeps its time (a
// naive one is UTC).
func parseBound(name, raw string, isEnd bool) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "T") {
		d, err := time.Parse(isoDate, raw)
		if err != nil {
			return time.Time{}, invalidArg("%s must be an ISO date (YYYY-MM-DD) or datetime (got %q)", name, raw)
		}
		if isEnd {
			return d.Add(24*time.Hour - time.Microsecond), nil
		}
		return d, nil
	}
	for _, layout := range dateTimeLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, invalidArg("%s must be an ISO date (YYYY-MM-DD) or datetime (got %q)", name, raw)
}

// isoformat renders t like Python's datetime.isoformat() for an aware UTC
// value: microseconds only when non-zero.
func isoformat(t time.Time) string {
	t = t.UTC().Truncate(time.Microsecond)
	if t.Nanosecond() != 0 {
		return t.Format("2006-01-02T15:04:05.000000") + "+00:00"
	}
	return t.Format("2006-01-02T15:04:05") + "+00:00"
}

// nonEmpty drops blank strings.
func nonEmpty(list []string) []string {
	var out []string
	for _, s := range list {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// strOrNil is s, or nil when empty (JSON null, as the Python tools echo).
func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func listOrNil(list []string) any {
	if len(list) == 0 {
		return nil
	}
	return list
}

func boolPtrOrNil(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}
