// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Explorer's date field (replaced the vendored flatpickr in 2026-10). The
// text input stays the source of truth: it is submitted as YYYY-MM-DD, and on
// desktop a person can type a date straight into it. The calendar is a
// helper that follows the WAI-ARIA date-picker dialog pattern: a click in the
// field, the calendar button or Alt+Down opens it; arrows move by day/week,
// Home/End to the week's ends, PageUp/PageDown by month (Shift: by year),
// Enter/Space picks, Escape closes and returns focus. On phones and tablets
// the field is read-only (no on-screen keyboard) and the calendar is the way
// in, as before. Styling is Flag tokens only (styles.css > .datepicker).
//
// Plain script, no build step: in the browser it defines
// window.ExplorerDatePicker; under Node (`node --test`) it exports the same
// object, so the date arithmetic and placement are unit-tested without a DOM.
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.ExplorerDatePicker = api;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const ISO = /^(\d{4})-(\d{2})-(\d{2})$/;
  const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
  const WEEKDAYS = [["Sun", "Sunday"], ["Mon", "Monday"], ["Tue", "Tuesday"], ["Wed", "Wednesday"], ["Thu", "Thursday"], ["Fri", "Friday"], ["Sat", "Saturday"]];

  // Calendar days are UTC-midnight timestamps. Whole-day moves go through
  // Date.UTC (never +/- 86,400,000 ms), so no DST change lands on the wrong day.

  /** A real calendar date written YYYY-MM-DD, as UTC-midnight ms; else null. */
  function parseIsoDate(value) {
    const m = ISO.exec(String(value == null ? "" : value).trim());
    if (!m) return null;
    const y = Number(m[1]);
    const mo = Number(m[2]) - 1;
    const d = Number(m[3]);
    const t = Date.UTC(y, mo, d);
    const back = new Date(t);
    return back.getUTCFullYear() === y && back.getUTCMonth() === mo && back.getUTCDate() === d ? t : null;
  }

  function toIsoDate(t) {
    const d = new Date(t);
    const p = (n) => String(n).padStart(2, "0");
    return `${String(d.getUTCFullYear()).padStart(4, "0")}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`;
  }

  function addDays(t, n) {
    const d = new Date(t);
    return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + n);
  }

  /** Same day n months on, clamped to the target month's last day. */
  function addMonths(t, n) {
    const d = new Date(t);
    const y = d.getUTCFullYear();
    const m = d.getUTCMonth() + n;
    const last = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
    return Date.UTC(y, m, Math.min(d.getUTCDate(), last));
  }

  function monthStart(t) {
    const d = new Date(t);
    return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
  }

  /** Today in the viewer's own zone, as a UTC-midnight day. */
  function todayUtc(now) {
    const n = now || new Date();
    return Date.UTC(n.getFullYear(), n.getMonth(), n.getDate());
  }

  /** The visible month: six week rows starting on the Sunday on/before the 1st. */
  function monthGrid(t) {
    const first = monthStart(t);
    const start = addDays(first, -new Date(first).getUTCDay());
    const weeks = [];
    for (let w = 0; w < 6; w += 1) {
      const week = [];
      for (let d = 0; d < 7; d += 1) week.push(addDays(start, w * 7 + d));
      weeks.push(week);
    }
    return weeks;
  }

  /** Where a grid key moves the active day, or null for keys the grid ignores. */
  function keyTarget(day, key, shiftKey) {
    const dow = new Date(day).getUTCDay();
    switch (key) {
      case "ArrowLeft": return addDays(day, -1);
      case "ArrowRight": return addDays(day, 1);
      case "ArrowUp": return addDays(day, -7);
      case "ArrowDown": return addDays(day, 7);
      case "Home": return addDays(day, -dow);
      case "End": return addDays(day, 6 - dow);
      case "PageUp": return addMonths(day, shiftKey ? -12 : -1);
      case "PageDown": return addMonths(day, shiftKey ? 12 : 1);
      default: return null;
    }
  }

  /** Where the fixed calendar goes: below the field when it fits, else above
   *  when that fits, else wherever keeps more of it on screen; always inside
   *  the viewport. A calendar taller than the viewport scrolls inside itself. */
  function placeCalendar(field, width, naturalHeight, viewportW, viewportH, gap) {
    const maxHeight = Math.max(0, viewportH - 2 * gap);
    const height = Math.min(naturalHeight, maxHeight);
    const below = field.bottom + gap;
    const above = field.top - gap - height;
    let top;
    if (below + height <= viewportH - gap) top = below;
    else if (above >= gap) top = above;
    else top = viewportH - field.bottom > field.top ? below : above;
    top = Math.max(gap, Math.min(top, viewportH - height - gap));
    const left = Math.max(gap, Math.min(field.left, viewportW - width - gap));
    return { top, left, maxHeight };
  }

  /** A CSS length token in px or rem as px; anything unreadable is 0. */
  function cssLengthPx(value, rootFontPx) {
    const m = /^(-?\d*\.?\d+)(px|rem)?$/.exec(String(value || "").trim());
    if (!m) return 0;
    const n = parseFloat(m[1]);
    return m[2] === "rem" ? n * rootFontPx : n;
  }

  // ---- DOM ------------------------------------------------------------------

  const COMPACT_QUERY = "(max-width: 1023px)";
  let open = null; // the one open calendar: { input, button, dialog, ... }
  let seq = 0;

  const el = (tag, cls, attrs) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (attrs) Object.keys(attrs).forEach((k) => node.setAttribute(k, attrs[k]));
    return node;
  };

  const isCompact = () => Boolean(window.matchMedia && window.matchMedia(COMPACT_QUERY).matches);

  /** Read-only with no on-screen keyboard on small screens; typeable on desktop. */
  function applyInputMode(input) {
    const compact = isCompact();
    input.readOnly = compact;
    input.setAttribute("inputmode", compact ? "none" : "text");
    input.setAttribute("autocomplete", "off");
    input.setAttribute("autocorrect", "off");
    input.setAttribute("autocapitalize", "off");
    input.spellcheck = false;
  }

  function fieldParts(input) {
    const wrap = input.closest(".date-input-wrap");
    const button = wrap ? wrap.querySelector("[data-date-button]") : null;
    return { wrap: wrap || input, button };
  }

  function setExpanded(input, button, isOpen, dialogId) {
    [input, button].forEach((node) => {
      if (!node) return;
      node.setAttribute("aria-expanded", isOpen ? "true" : "false");
      if (isOpen) node.setAttribute("aria-controls", dialogId);
      else node.removeAttribute("aria-controls");
    });
  }

  function close(returnFocusTo) {
    if (!open) return;
    const state = open;
    open = null;
    window.removeEventListener("scroll", state.place, true);
    window.removeEventListener("resize", state.place);
    document.removeEventListener("pointerdown", state.onOutside, true);
    state.dialog.remove();
    setExpanded(state.input, state.button, false);
    if (returnFocusTo) returnFocusTo.focus();
  }

  function pick(state, t) {
    const { input } = state;
    input.value = toIsoDate(t);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    close(input);
  }

  function render(state) {
    const { dialog, grid, title, monthSelect, yearInput } = state;
    const first = monthStart(state.focusDay);
    const month = new Date(first).getUTCMonth();
    const year = new Date(first).getUTCFullYear();
    const selected = parseIsoDate(state.input.value);
    const today = todayUtc();
    title.textContent = `${MONTHS[month]} ${year}`;
    monthSelect.value = String(month);
    if (document.activeElement !== yearInput) yearInput.value = String(year);

    const body = grid.tBodies[0];
    body.textContent = "";
    monthGrid(state.focusDay).forEach((week) => {
      const tr = el("tr");
      week.forEach((t) => {
        const outside = new Date(t).getUTCMonth() !== month;
        const td = el("td", "", { role: "gridcell" });
        if (selected === t) td.setAttribute("aria-selected", "true");
        const cls = ["datepicker__day"];
        if (outside) cls.push("is-outside");
        if (selected === t) cls.push("is-selected");
        if (today === t) cls.push("is-today");
        const btn = el("button", cls.join(" "), {
          type: "button",
          "data-day": toIsoDate(t),
          tabindex: t === state.focusDay ? "0" : "-1",
          "aria-label": new Date(t).toLocaleDateString("en-US", {
            weekday: "long", year: "numeric", month: "long", day: "numeric", timeZone: "UTC",
          }),
        });
        if (today === t) btn.setAttribute("aria-current", "date");
        btn.textContent = String(new Date(t).getUTCDate());
        td.appendChild(btn);
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    if (state.moveFocus) {
      const active = grid.querySelector('button[tabindex="0"]');
      if (active) active.focus();
    }
    state.place();
    return dialog;
  }

  function build(state) {
    const id = `datepicker-${++seq}`;
    const titleId = `${id}-title`;
    const dialog = el("div", "datepicker", { id, role: "dialog", "aria-modal": "false", "aria-labelledby": titleId });
    const header = el("div", "datepicker__header");
    const prev = el("button", "datepicker__nav", { type: "button", "aria-label": "Previous month" });
    const next = el("button", "datepicker__nav", { type: "button", "aria-label": "Next month" });
    prev.appendChild(navIcon("M15 18l-6-6 6-6"));
    next.appendChild(navIcon("M9 18l6-6-6-6"));
    const title = el("span", "datepicker__title", { id: titleId, "aria-live": "polite" });
    const monthSelect = el("select", "datepicker__month", { "aria-label": "Month" });
    MONTHS.forEach((name, i) => {
      const opt = el("option", "", { value: String(i) });
      opt.textContent = name;
      monthSelect.appendChild(opt);
    });
    const yearInput = el("input", "datepicker__year", {
      type: "number", "aria-label": "Year", min: "1970", max: "9999", step: "1", inputmode: "numeric",
    });
    const jump = el("div", "datepicker__jump");
    jump.append(monthSelect, yearInput);
    header.append(prev, title, jump, next);

    const grid = el("table", "datepicker__grid", { role: "grid", "aria-labelledby": titleId });
    const head = el("thead");
    const headRow = el("tr");
    WEEKDAYS.forEach(([abbr, full]) => {
      const th = el("th", "", { scope: "col", abbr: full });
      th.textContent = abbr;
      headRow.appendChild(th);
    });
    head.appendChild(headRow);
    grid.append(head, el("tbody"));
    dialog.append(header, grid);

    Object.assign(state, { dialog, grid, title, monthSelect, yearInput });

    const page = (delta) => {
      state.moveFocus = false;
      state.focusDay = addMonths(state.focusDay, delta);
      render(state);
    };
    prev.addEventListener("click", () => page(-1));
    next.addEventListener("click", () => page(1));
    monthSelect.addEventListener("change", () => {
      const d = new Date(state.focusDay);
      state.moveFocus = false;
      state.focusDay = addMonths(state.focusDay, Number(monthSelect.value) - d.getUTCMonth());
      render(state);
    });
    yearInput.addEventListener("input", () => {
      const y = Number(yearInput.value);
      if (!Number.isInteger(y) || y < 1970 || y > 9999) return;
      const d = new Date(state.focusDay);
      state.moveFocus = false;
      state.focusDay = addMonths(state.focusDay, (y - d.getUTCFullYear()) * 12);
      render(state);
    });

    grid.addEventListener("click", (event) => {
      const btn = event.target instanceof Element ? event.target.closest("button[data-day]") : null;
      const t = btn ? parseIsoDate(btn.getAttribute("data-day")) : null;
      if (t !== null) pick(state, t);
    });
    grid.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        const btn = event.target instanceof Element ? event.target.closest("button[data-day]") : null;
        const t = btn ? parseIsoDate(btn.getAttribute("data-day")) : null;
        event.preventDefault();
        if (t !== null) pick(state, t);
        return;
      }
      const target = keyTarget(state.focusDay, event.key, event.shiftKey);
      if (target === null) return;
      event.preventDefault();
      state.moveFocus = true;
      state.focusDay = target;
      render(state);
    });

    // Escape closes from anywhere in the dialog. Tab / Shift+Tab move through
    // the calendar's own controls and, past either end, close it and hand
    // focus back to the field (the dialog sits at the end of <body>, so the
    // browser's next stop would be nowhere useful).
    dialog.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        close(state.input);
        return;
      }
      if (event.key !== "Tab") return;
      const items = Array.from(dialog.querySelectorAll("button, select, input")).filter((n) => n.tabIndex >= 0 && !n.disabled);
      const at = items.indexOf(document.activeElement);
      if (at < 0) return;
      if (event.shiftKey && at === 0) {
        event.preventDefault();
        close(state.input);
      } else if (!event.shiftKey && at === items.length - 1) {
        event.preventDefault();
        close(state.button || state.input);
      }
    });
    dialog.addEventListener("focusout", (event) => {
      const to = event.relatedTarget;
      if (to instanceof Node && !dialog.contains(to) && !state.wrap.contains(to)) close();
    });
    return dialog;
  }

  function navIcon(d) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", d);
    svg.appendChild(path);
    return svg;
  }

  function readGapPx() {
    const rootStyle = getComputedStyle(document.documentElement);
    return cssLengthPx(rootStyle.getPropertyValue("--space-1"), parseFloat(rootStyle.fontSize) || 16);
  }

  function openFor(input, focusGrid) {
    if (open && open.input === input) {
      if (focusGrid) {
        open.moveFocus = true;
        render(open);
      }
      return;
    }
    close();
    const { wrap, button } = fieldParts(input);
    const state = {
      input, button, wrap,
      focusDay: parseIsoDate(input.value) !== null ? parseIsoDate(input.value) : todayUtc(),
      moveFocus: focusGrid,
    };
    state.place = () => {
      const r = wrap.getBoundingClientRect();
      const d = state.dialog;
      const natural = Math.max(d.offsetHeight, d.scrollHeight + d.offsetHeight - d.clientHeight);
      const pos = placeCalendar(r, d.offsetWidth, natural, window.innerWidth, window.innerHeight, readGapPx());
      d.style.top = `${pos.top}px`;
      d.style.left = `${pos.left}px`;
      d.style.maxHeight = `${pos.maxHeight}px`;
    };
    state.onOutside = (event) => {
      const t = event.target;
      if (t instanceof Node && !state.dialog.contains(t) && !wrap.contains(t)) close();
    };
    build(state);
    document.body.appendChild(state.dialog);
    open = state;
    setExpanded(input, button, true, state.dialog.id);
    render(state);
    window.addEventListener("scroll", state.place, true);
    window.addEventListener("resize", state.place);
    document.addEventListener("pointerdown", state.onOutside, true);
  }

  /** Wire one field; safe to call again (it re-applies the input mode only). */
  function attach(input) {
    if (!(input instanceof HTMLInputElement)) return;
    applyInputMode(input);
    if (input.dataset.datepicker === "1") return;
    input.dataset.datepicker = "1";
    // A text field that opens a dialog is a combobox (WAI-ARIA date picker
    // pattern); only that role may carry aria-expanded.
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-haspopup", "dialog");
    input.setAttribute("aria-expanded", "false");
    if (!input.placeholder) input.placeholder = "YYYY-MM-DD";
    const { button } = fieldParts(input);

    input.addEventListener("click", () => {
      if (!open || open.input !== input) openFor(input, false);
    });
    input.addEventListener("keydown", (event) => {
      const isOpen = open && open.input === input;
      if (event.key === "ArrowDown" && (event.altKey || isOpen)) {
        event.preventDefault();
        openFor(input, true);
      } else if (event.key === "Escape" && isOpen) {
        event.preventDefault();
        event.stopPropagation();
        close();
      } else if (event.key === "Tab" && isOpen) {
        close();
      }
    });
    // A complete typed date moves an open calendar to its month.
    input.addEventListener("input", () => {
      if (!open || open.input !== input) return;
      const t = parseIsoDate(input.value);
      if (t === null) return;
      open.focusDay = t;
      open.moveFocus = false;
      render(open);
    });
    if (button) {
      button.addEventListener("click", () => {
        if (open && open.input === input) close(input);
        else openFor(input, true);
      });
    }
  }

  function attachAll(root) {
    const scope = root && typeof root.querySelectorAll === "function" ? root : document;
    scope.querySelectorAll("input.custom-datepicker").forEach(attach);
  }

  /** Re-apply the read-only/typeable mode when the viewport crosses the breakpoint. */
  function watchViewport() {
    if (!window.matchMedia) return;
    const query = window.matchMedia(COMPACT_QUERY);
    const update = () => {
      close();
      document.querySelectorAll("input.custom-datepicker").forEach(applyInputMode);
    };
    if (typeof query.addEventListener === "function") query.addEventListener("change", update);
    else if (typeof query.addListener === "function") query.addListener(update);
  }

  return {
    parseIsoDate, toIsoDate, addDays, addMonths, monthStart, monthGrid, todayUtc,
    keyTarget, placeCalendar, cssLengthPx, attach, attachAll, watchViewport, close: () => close(),
  };
});
