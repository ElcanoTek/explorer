// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Unit tests for static/js/date-ranges.js: node --test internal/web/jstest/*.test.js
// The day counts mirror dates.go countDaysCovered (TestCountDaysCovered*).
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const dr = require("../static/js/date-ranges.js");

test("toDayNumber", () => {
  assert.equal(dr.toDayNumber("1970-01-02"), 1);
  assert.equal(dr.toDayNumber("2026-10-22") - dr.toDayNumber("2026-10-01"), 21);
  assert.equal(dr.toDayNumber("bad"), null);
  assert.equal(dr.toDayNumber(""), null);
});

test("summarizeRanges merges overlaps and adjacent days, swaps reversed ranges", () => {
  assert.deepEqual(dr.summarizeRanges([["2026-10-01", "2026-10-01"]]), { totalDays: 1, rangeCount: 1 });
  assert.deepEqual(dr.summarizeRanges([["2026-10-10", "2026-10-01"]]), { totalDays: 10, rangeCount: 1 });
  assert.deepEqual(dr.summarizeRanges([["2026-10-01", "2026-10-05"], ["2026-10-03", "2026-10-08"]]), { totalDays: 8, rangeCount: 2 });
  assert.deepEqual(dr.summarizeRanges([["2026-10-01", "2026-10-05"], ["2026-10-06", "2026-10-06"]]), { totalDays: 6, rangeCount: 2 });
  assert.deepEqual(dr.summarizeRanges([["2026-10-20", "2026-10-21"], ["2026-10-01", "2026-10-02"]]), { totalDays: 4, rangeCount: 2 });
  assert.deepEqual(dr.summarizeRanges([["2026-02-27", "2026-03-02"]]), { totalDays: 4, rangeCount: 1 });
});

test("summarizeRanges skips incomplete or unreadable rows", () => {
  assert.deepEqual(dr.summarizeRanges([["", "2026-10-01"], ["2026-10-01", "nope"], []]), { totalDays: 0, rangeCount: 0 });
});

test("summarizeRanges does not mutate across calls", () => {
  const pairs = [["2026-10-01", "2026-10-02"], ["2026-10-02", "2026-10-04"]];
  assert.equal(dr.summarizeRanges(pairs).totalDays, 4);
  assert.equal(dr.summarizeRanges(pairs).totalDays, 4);
});

test("expensiveThreshold per mode", () => {
  assert.equal(dr.expensiveThreshold("fuzzy", true), 4);
  assert.equal(dr.expensiveThreshold("fuzzy", false), 7);
  assert.equal(dr.expensiveThreshold("exact", true), 14);
  assert.equal(dr.expensiveThreshold("view", false), 21);
});

test("maxAllowedDays caps body fuzzy search only", () => {
  assert.equal(dr.maxAllowedDays("fuzzy", true, 62, 14), 14);
  assert.equal(dr.maxAllowedDays("fuzzy", false, 62, 14), 62);
  assert.equal(dr.maxAllowedDays("exact", true, 62, 14), 62);
  assert.equal(dr.maxAllowedDays("fuzzy", true, 10, 14), 10);
});
