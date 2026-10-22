// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// The search form's date-range arithmetic, kept apart from the DOM so it is
// unit-tested under Node. It mirrors the server (dates.go countDaysCovered):
// reversed ranges are swapped, overlapping and adjacent ranges merge, and the
// total is the number of distinct days covered. The server stays the
// authority; this only drives the warning and the confirm prompt.
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.ExplorerDateRanges = api;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  /** YYYY-MM-DD as a whole-day number (days since 1970-01-01 UTC), else null. */
  function toDayNumber(value) {
    const parts = String(value || "").split("-").map(Number);
    if (parts.length !== 3 || parts.some((part) => Number.isNaN(part))) {
      return null;
    }
    return Math.floor(Date.UTC(parts[0], parts[1] - 1, parts[2]) / 86400000);
  }

  /** pairs: [[from, to], ...] as YYYY-MM-DD strings; incomplete rows are skipped. */
  function summarizeRanges(pairs) {
    const ranges = [];
    pairs.forEach(([from, to]) => {
      if (!from || !to) return;
      let start = toDayNumber(from);
      let end = toDayNumber(to);
      if (start === null || end === null) return;
      if (end < start) [start, end] = [end, start];
      ranges.push([start, end]);
    });
    ranges.sort((a, b) => a[0] - b[0]);
    const merged = [];
    ranges.forEach((range) => {
      const last = merged[merged.length - 1];
      if (last && range[0] <= last[1] + 1) {
        last[1] = Math.max(last[1], range[1]);
        return;
      }
      merged.push(range.slice());
    });
    const totalDays = merged.reduce((sum, range) => sum + (range[1] - range[0] + 1), 0);
    return { totalDays, rangeCount: ranges.length };
  }

  /** Days at which a search is slow enough to warn and ask before running. */
  function expensiveThreshold(mode, searchBody) {
    if (mode === "fuzzy") return searchBody ? 4 : 7;
    if (mode === "exact") return 14;
    return 21;
  }

  /** The most days a search may span (the body-search cap applies to fuzzy + Body). */
  function maxAllowedDays(mode, searchBody, maxDays, maxBodyDays) {
    if (mode === "fuzzy" && searchBody) return Math.min(maxDays, maxBodyDays);
    return maxDays;
  }

  return { toDayNumber, summarizeRanges, expensiveThreshold, maxAllowedDays };
});
