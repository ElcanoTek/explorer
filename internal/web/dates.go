// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"errors"
	"sort"
	"strings"
	"time"
)

const isoDate = "2006-01-02"

var errBadRanges = errors.New("Invalid date ranges. Use YYYY-MM-DD or YYYY-MM-DD..YYYY-MM-DD, separated by commas.") //nolint:revive,staticcheck // ST1005: shown to the user verbatim, as before.

// day is a calendar date, held as midnight UTC.
type day = time.Time

type dayRange struct{ Start, End day }

type dateWindow struct{ From, To string }

func parseDay(raw string) (day, error) {
	return time.Parse(isoDate, strings.TrimSpace(raw))
}

func ordered(a, b day) dayRange {
	if b.Before(a) {
		a, b = b, a
	}
	return dayRange{a, b}
}

// parseDateRanges reads the legacy single-field form: comma or newline
// separated entries, each a day or a range written a..b, a:b or "a to b".
func parseDateRanges(raw string, fallback day) ([]dayRange, error) {
	if strings.TrimSpace(raw) == "" {
		return []dayRange{{fallback, fallback}}, nil
	}
	var chunks []string
	for _, piece := range strings.Split(strings.ReplaceAll(raw, "\n", ","), ",") {
		if p := strings.TrimSpace(piece); p != "" {
			chunks = append(chunks, p)
		}
	}
	if len(chunks) == 0 {
		return []dayRange{{fallback, fallback}}, nil
	}
	var out []dayRange
	for _, chunk := range chunks {
		var start, end string
		switch {
		case strings.Contains(chunk, ".."):
			start, end, _ = strings.Cut(chunk, "..")
		case strings.Contains(chunk, ":"):
			start, end, _ = strings.Cut(chunk, ":")
		case strings.Contains(strings.ToLower(chunk), " to "):
			i := strings.Index(strings.ToLower(chunk), " to ")
			start, end = chunk[:i], chunk[i+4:]
		default:
			start, end = chunk, chunk
		}
		start, end = strings.TrimSpace(start), strings.TrimSpace(end)
		if start == "" || end == "" {
			return nil, errBadRanges
		}
		a, err := parseDay(start)
		if err != nil {
			return nil, errBadRanges
		}
		b, err := parseDay(end)
		if err != nil {
			return nil, errBadRanges
		}
		out = append(out, ordered(a, b))
	}
	return out, nil
}

// parseDateWindows reads the paired date_from/date_to lists the UI submits,
// falling back to the legacy date_ranges field. A row with only one side
// set covers that single day.
func parseDateWindows(fromValues, toValues []string, fallback day, legacy string) ([]dayRange, []dateWindow, error) {
	trimmed := func(in []string) []string {
		var out []string
		for _, v := range in {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	froms, tos := trimmed(fromValues), trimmed(toValues)
	var ranges []dayRange
	if len(froms) > 0 || len(tos) > 0 {
		total := max(len(froms), len(tos))
		for i := 0; i < total; i++ {
			var from, to string
			if i < len(froms) {
				from = froms[i]
			}
			if i < len(tos) {
				to = tos[i]
			}
			if from == "" {
				from = to
			}
			if to == "" {
				to = from
			}
			a, err := parseDay(from)
			if err != nil {
				return nil, nil, errBadRanges
			}
			b, err := parseDay(to)
			if err != nil {
				return nil, nil, errBadRanges
			}
			ranges = append(ranges, ordered(a, b))
		}
	} else {
		var err error
		if ranges, err = parseDateRanges(legacy, fallback); err != nil {
			return nil, nil, err
		}
	}
	windows := make([]dateWindow, len(ranges))
	for i, r := range ranges {
		windows[i] = dateWindow{r.Start.Format(isoDate), r.End.Format(isoDate)}
	}
	return ranges, windows, nil
}

// countDaysCovered is the number of distinct days the ranges cover, with
// overlapping and adjacent ranges merged.
func countDaysCovered(ranges []dayRange) int {
	if len(ranges) == 0 {
		return 0
	}
	norm := make([]dayRange, len(ranges))
	for i, r := range ranges {
		norm[i] = ordered(r.Start, r.End)
	}
	sort.SliceStable(norm, func(i, j int) bool { return norm[i].Start.Before(norm[j].Start) })
	merged := []dayRange{norm[0]}
	for _, r := range norm[1:] {
		last := &merged[len(merged)-1]
		if !r.Start.After(last.End.AddDate(0, 0, 1)) {
			if r.End.After(last.End) {
				last.End = r.End
			}
			continue
		}
		merged = append(merged, r)
	}
	total := 0
	for _, r := range merged {
		total += int(r.End.Sub(r.Start).Hours()/24) + 1
	}
	return total
}
