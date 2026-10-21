// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"fmt"
	"strings"
	"time"
)

// DateRange is an inclusive span of calendar days; Start and End are dates
// (midnight UTC). End before Start is swapped.
type DateRange struct {
	Start, End time.Time
}

// Day returns the date of t as midnight UTC.
func Day(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// Strftime formats t with the C/Python directives a date-partitioned key
// layout plausibly uses: %Y %y %m %d %e %j %H %M %S %b %B %a %A %u %w %%.
// An unknown directive is kept as written.
func Strftime(format string, t time.Time) string {
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		c := format[i]
		if c != '%' || i+1 == len(format) {
			b.WriteByte(c)
			continue
		}
		i++
		switch format[i] {
		case 'Y':
			fmt.Fprintf(&b, "%04d", t.Year())
		case 'y':
			fmt.Fprintf(&b, "%02d", t.Year()%100)
		case 'm':
			fmt.Fprintf(&b, "%02d", int(t.Month()))
		case 'd':
			fmt.Fprintf(&b, "%02d", t.Day())
		case 'e':
			fmt.Fprintf(&b, "%2d", t.Day())
		case 'j':
			fmt.Fprintf(&b, "%03d", t.YearDay())
		case 'H':
			fmt.Fprintf(&b, "%02d", t.Hour())
		case 'M':
			fmt.Fprintf(&b, "%02d", t.Minute())
		case 'S':
			fmt.Fprintf(&b, "%02d", t.Second())
		case 'b':
			b.WriteString(t.Month().String()[:3])
		case 'B':
			b.WriteString(t.Month().String())
		case 'a':
			b.WriteString(t.Weekday().String()[:3])
		case 'A':
			b.WriteString(t.Weekday().String())
		case 'u':
			wd := int(t.Weekday())
			if wd == 0 {
				wd = 7
			}
			fmt.Fprintf(&b, "%d", wd)
		case 'w':
			fmt.Fprintf(&b, "%d", int(t.Weekday()))
		case '%':
			b.WriteByte('%')
		default:
			b.WriteByte('%')
			b.WriteByte(format[i])
		}
	}
	return b.String()
}

// BuildSearchPrefixes expands a date span into one key prefix per day,
// newest first, so a search lists only the partitions it needs. Without a
// date format, or for a span wider than maxDays, it falls back to listing
// the root prefix.
func BuildSearchPrefixes(prefix, dateFormat string, maxDays int, from, to time.Time) []string {
	if dateFormat == "" || from.IsZero() || to.IsZero() {
		return []string{prefix}
	}
	start, end := Day(from), Day(to)
	if end.Before(start) {
		start, end = end, start
	}
	total := int(end.Sub(start).Hours()/24) + 1
	if total <= 0 || total > maxDays {
		return []string{prefix}
	}
	prefixes := make([]string, 0, total)
	for d := end; !d.Before(start); d = d.AddDate(0, 0, -1) {
		prefixes = append(prefixes, Strftime(dateFormat, d))
	}
	return prefixes
}

// window is one date range as an inclusive instant span in UTC.
type window struct{ start, end time.Time }

func (in *Inbox) windowsAndPrefixes(ranges []DateRange) ([]window, []string) {
	windows := make([]window, 0, len(ranges))
	var prefixes []string
	seen := map[string]bool{}
	for _, r := range ranges {
		start, end := Day(r.Start), Day(r.End)
		if end.Before(start) {
			start, end = end, start
		}
		last := end.Add(24*time.Hour - time.Microsecond)
		windows = append(windows, window{start, last})
		for _, p := range BuildSearchPrefixes(in.s.Prefix, in.s.DatePrefixFormat, in.s.MaxDatePrefixDays, start, last) {
			if !seen[p] {
				seen[p] = true
				prefixes = append(prefixes, p)
			}
		}
	}
	return windows, prefixes
}

func inWindows(t time.Time, windows []window) bool {
	t = t.UTC()
	for _, w := range windows {
		if !t.Before(w.start) && !t.After(w.end) {
			return true
		}
	}
	return false
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
