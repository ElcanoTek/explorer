// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Unit tests for static/js/datepicker.js (no DOM): node --test internal/web/jstest/*.test.js
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const dp = require("../static/js/datepicker.js");

const day = (iso) => {
  const t = dp.parseIsoDate(iso);
  assert.notEqual(t, null, iso);
  return t;
};

test("parseIsoDate accepts only real YYYY-MM-DD dates", () => {
  assert.equal(dp.toIsoDate(day("2026-10-22")), "2026-10-22");
  assert.equal(dp.toIsoDate(day(" 2024-02-29 ")), "2024-02-29");
  for (const bad of ["", "2026-02-30", "2025-02-29", "2026-13-01", "2026-1-5", "10/22/2026", "2026-10-22x", null, undefined]) {
    assert.equal(dp.parseIsoDate(bad), null, String(bad));
  }
});

test("toIsoDate pads month, day and year", () => {
  assert.equal(dp.toIsoDate(Date.UTC(2026, 0, 5)), "2026-01-05");
});

test("addDays crosses months, years and DST without drifting", () => {
  assert.equal(dp.toIsoDate(dp.addDays(day("2026-12-31"), 1)), "2027-01-01");
  assert.equal(dp.toIsoDate(dp.addDays(day("2026-03-01"), -1)), "2026-02-28");
  assert.equal(dp.toIsoDate(dp.addDays(day("2026-03-07"), 7)), "2026-03-14");
  assert.equal(dp.toIsoDate(dp.addDays(day("2026-11-01"), 1)), "2026-11-02");
});

test("addMonths clamps to the target month's last day", () => {
  assert.equal(dp.toIsoDate(dp.addMonths(day("2026-01-31"), 1)), "2026-02-28");
  assert.equal(dp.toIsoDate(dp.addMonths(day("2024-02-29"), 12)), "2025-02-28");
  assert.equal(dp.toIsoDate(dp.addMonths(day("2026-03-31"), -1)), "2026-02-28");
  assert.equal(dp.toIsoDate(dp.addMonths(day("2026-12-15"), 1)), "2027-01-15");
});

test("monthGrid is six weeks starting on the Sunday on or before the 1st", () => {
  const weeks = dp.monthGrid(day("2026-10-22"));
  assert.equal(weeks.length, 6);
  weeks.forEach((w) => assert.equal(w.length, 7));
  assert.equal(dp.toIsoDate(weeks[0][0]), "2026-09-27");
  assert.equal(dp.toIsoDate(weeks[5][6]), "2026-11-07");
  // A month starting on Sunday starts the grid on the 1st.
  assert.equal(dp.toIsoDate(dp.monthGrid(day("2026-02-10"))[0][0]), "2026-02-01");
});

test("keyTarget follows the WAI-ARIA date grid keys", () => {
  const from = day("2026-10-22"); // a Thursday
  const cases = {
    ArrowLeft: "2026-10-21",
    ArrowRight: "2026-10-23",
    ArrowUp: "2026-10-15",
    ArrowDown: "2026-10-29",
    Home: "2026-10-18",
    End: "2026-10-24",
    PageUp: "2026-09-22",
    PageDown: "2026-11-22",
  };
  for (const [key, want] of Object.entries(cases)) {
    assert.equal(dp.toIsoDate(dp.keyTarget(from, key, false)), want, key);
  }
  assert.equal(dp.toIsoDate(dp.keyTarget(from, "PageUp", true)), "2025-10-22");
  assert.equal(dp.toIsoDate(dp.keyTarget(from, "PageDown", true)), "2027-10-22");
  assert.equal(dp.keyTarget(from, "a", false), null);
  assert.equal(dp.keyTarget(from, "Enter", false), null);
});

test("placeCalendar keeps the calendar under the field and on screen", () => {
  const field = { top: 100, bottom: 140, left: 200 };
  assert.deepEqual(dp.placeCalendar(field, 300, 320, 1440, 900, 4), { top: 144, left: 200, maxHeight: 892 });
  // No room below: goes above.
  const low = { top: 700, bottom: 740, left: 20 };
  assert.deepEqual(dp.placeCalendar(low, 300, 320, 390, 844, 4), { top: 376, left: 20, maxHeight: 836 });
  // Too far right: pulled back inside the viewport.
  assert.equal(dp.placeCalendar({ top: 0, bottom: 40, left: 300 }, 300, 100, 390, 844, 4).left, 86);
  // Taller than the viewport: pinned to the gap and scrolls.
  assert.deepEqual(dp.placeCalendar({ top: 50, bottom: 90, left: 0 }, 300, 2000, 390, 400, 4), { top: 4, left: 4, maxHeight: 392 });
});

test("cssLengthPx reads px and rem tokens", () => {
  assert.equal(dp.cssLengthPx("0.25rem", 16), 4);
  assert.equal(dp.cssLengthPx(" 8px ", 16), 8);
  assert.equal(dp.cssLengthPx("6", 16), 6);
  assert.equal(dp.cssLengthPx("calc(1px + 1rem)", 16), 0);
});

test("todayUtc is the viewer's local calendar day", () => {
  assert.equal(dp.toIsoDate(dp.todayUtc(new Date(2026, 9, 22, 23, 59))), "2026-10-22");
});
