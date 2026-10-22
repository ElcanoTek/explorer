// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

(function () {
  const form = document.getElementById("search-form");
  const submitButton = document.getElementById("search-submit");
  const warning = document.getElementById("search-warning");
  const rangeList = document.getElementById("date-range-list");
  const addButton = document.getElementById("add-date-range");
  if (!form || !submitButton) return;

  const maxSearchDays = Number(form.getAttribute("data-max-days") || "62");
  const maxBodySearchDays = Number(form.getAttribute("data-max-body-days") || String(maxSearchDays));
  const modeInput = form.querySelector('input[name="mode"]');
  const pagerForms = Array.from(document.querySelectorAll("[data-loading-form]"));
  const resultList = document.getElementById("result-list");
  const inboxShell = document.getElementById("inbox-shell");
  const detailPanel = document.getElementById("detail-panel");
  const detailPanelBody = document.getElementById("detail-panel-body");
  const detailPanelClose = document.getElementById("detail-panel-close");
  const resultsFilterToggle = document.getElementById("results-filter-toggle");
  const resultsFilterMenu = document.getElementById("results-filter-menu");
  const hasAttachmentsFilter = document.getElementById("filter-has-attachments");
  const mobilePanelQuery = window.matchMedia("(max-width: 1023px)");
  const mobileTimestampQuery = window.matchMedia("(max-width: 767px)");
  const datePicker = window.ExplorerDatePicker;
  const dateRanges = window.ExplorerDateRanges;
  let activeRow = null;

  const setupNumberInputs = () => {
    document.querySelectorAll("[data-number-input]").forEach((wrapper) => {
      const input = wrapper.querySelector('input[type="number"]');
      const dec = wrapper.querySelector("[data-number-decrement]");
      const inc = wrapper.querySelector("[data-number-increment]");
      if (!(input instanceof HTMLInputElement) || !(dec instanceof HTMLButtonElement) || !(inc instanceof HTMLButtonElement)) {
        return;
      }

      const updateButtons = () => {
        const value = Number(input.value || input.min || "0");
        const min = Number(input.min || "-Infinity");
        const max = Number(input.max || "Infinity");
        dec.disabled = Number.isFinite(min) && value <= min;
        inc.disabled = Number.isFinite(max) && value >= max;
      };

      const step = (direction) => {
        const min = Number(input.min || "1");
        const max = Number(input.max || "500");
        const stepAmount = Number(input.step || "1") || 1;
        const current = Number(input.value || min || 0);
        const next = Math.min(max, Math.max(min, current + direction * stepAmount));
        input.value = String(next);
        input.dispatchEvent(new Event("change", { bubbles: true }));
        updateButtons();
      };

      dec.addEventListener("click", () => step(-1));
      inc.addEventListener("click", () => step(1));
      input.addEventListener("input", updateButtons);
      input.addEventListener("change", updateButtons);
      updateButtons();
    });
  };

  const initDatePickers = (root) => {
    if (datePicker) {
      datePicker.attachAll(root);
    }
  };

  const formatReceivedTimestamps = () => {
    const desktopFormatter = new Intl.DateTimeFormat(undefined, {
      month: "long",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "2-digit",
      hour12: true,
    });
    const mobileSameYearFormatter = new Intl.DateTimeFormat(undefined, {
      month: "short",
      day: "numeric",
    });
    const mobilePreviousYearFormatter = new Intl.DateTimeFormat(undefined, {
      month: "numeric",
      day: "numeric",
      year: "2-digit",
    });
    const timeFormatter = new Intl.DateTimeFormat(undefined, {
      hour: "numeric",
      minute: "2-digit",
      hour12: true,
    });

    const normalizeMeridiem = (value) =>
      value
        .replace(/\ba\.?m\.?\b/gi, "AM")
        .replace(/\bp\.?m\.?\b/gi, "PM")
        .replace(/\b(am|pm)\b/gi, (match) => match.toUpperCase());

    const formatTime = (value) => normalizeMeridiem(timeFormatter.format(value));

    const formatMobileTimestamp = (value) => {
      const now = new Date();
      const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const valueStart = new Date(value.getFullYear(), value.getMonth(), value.getDate());
      const dayDiff = Math.round((todayStart.getTime() - valueStart.getTime()) / 86400000);
      const time = formatTime(value);

      if (dayDiff === 0) {
        return time;
      }

      if (dayDiff === 1) {
        return `Yesterday \u00B7 ${time}`;
      }

      if (value.getFullYear() === now.getFullYear()) {
        return `${mobileSameYearFormatter.format(value)} \u00B7 ${time}`;
      }

      return `${mobilePreviousYearFormatter.format(value)} \u00B7 ${time}`;
    };

    document.querySelectorAll(".inbox-row__time[data-received-at]").forEach((cell) => {
      const rawValue = cell.getAttribute("data-received-at");
      if (!rawValue) {
        return;
      }
      const parsed = new Date(rawValue);
      if (Number.isNaN(parsed.getTime())) {
        return;
      }
      const formatted = mobileTimestampQuery.matches
        ? formatMobileTimestamp(parsed)
        : normalizeMeridiem(desktopFormatter.format(parsed));
      cell.textContent = formatted;
    });
  };

  const toTimestampMs = (value) => {
    if (!value) {
      return Number.NEGATIVE_INFINITY;
    }
    const direct = Date.parse(value);
    if (!Number.isNaN(direct)) {
      return direct;
    }
    const normalized = value.replace(" ", "T");
    const fallback = Date.parse(normalized);
    if (!Number.isNaN(fallback)) {
      return fallback;
    }
    return Number.NEGATIVE_INFINITY;
  };

  const sortRowsByNewestReceived = () => {
    if (!resultList) {
      return;
    }
    const rows = Array.from(resultList.querySelectorAll(".inbox-row"));
    rows.sort((a, b) => {
      const aRaw = a.querySelector(".inbox-row__time")?.getAttribute("data-received-at") || "";
      const bRaw = b.querySelector(".inbox-row__time")?.getAttribute("data-received-at") || "";
      return toTimestampMs(bRaw) - toTimestampMs(aRaw);
    });
    rows.forEach((row) => resultList.appendChild(row));
  };

  const formatDetailPanelDates = (root) => {
    if (!root) {
      return;
    }
    const formatter = new Intl.DateTimeFormat(undefined, {
      month: "long",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "2-digit",
      hour12: true,
    });

    root.querySelectorAll(".email-meta__date[data-email-date]").forEach((node) => {
      const value = node.getAttribute("data-email-date");
      if (!value) {
        return;
      }
      const parsed = new Date(value);
      if (Number.isNaN(parsed.getTime())) {
        return;
      }
      node.textContent = formatter.format(parsed);
    });
  };

  const normalizeDetailPanelLinks = (root) => {
    if (!root) {
      return;
    }

    const escapeHtml = (value) =>
      value
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;")
        .replace(/'/g, "&#39;");

    const urlRegex = /(https?:\/\/[^\s<]+[^\s<\.)])/gi;
    root.querySelectorAll(".message-body--text").forEach((block) => {
      if (!(block instanceof HTMLElement) || block.dataset.linkified === "1") {
        return;
      }
      const text = block.textContent || "";
      const linked = escapeHtml(text).replace(urlRegex, (url) => {
        return `<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`;
      });
      block.innerHTML = linked.replace(/\r?\n/g, "<br>");
      block.dataset.linkified = "1";
    });

    root.querySelectorAll("a[href]").forEach((link) => {
      const href = (link.getAttribute("href") || "").trim();
      if (!href || href.startsWith("#") || href.startsWith("/attachment")) {
        return;
      }
      link.setAttribute("target", "_blank");
      link.setAttribute("rel", "noopener noreferrer");
    });
  };

  const syncDetailDateWithRow = (row, root) => {
    if (!(row instanceof HTMLElement) || !root) {
      return;
    }
    const rawReceived = row.querySelector(".inbox-row__time")?.getAttribute("data-received-at");
    if (!rawReceived) {
      return;
    }
    const parsed = new Date(rawReceived);
    if (Number.isNaN(parsed.getTime())) {
      return;
    }
    const detailDate = root.querySelector(".email-meta__date");
    if (!detailDate) {
      return;
    }
    const formatter = new Intl.DateTimeFormat(undefined, {
      month: "long",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "2-digit",
      hour12: true,
    });
    detailDate.textContent = formatter.format(parsed);
  };

  const applyResultsFilter = () => {
    if (!resultList || !hasAttachmentsFilter) {
      return;
    }
    const onlyAttachments = hasAttachmentsFilter.checked;
    resultList.querySelectorAll(".inbox-row").forEach((row) => {
      const hasAttachment = Boolean(row.querySelector(".inbox-row__clip"));
      const isVisible = !onlyAttachments || hasAttachment;
      row.hidden = !isVisible;
      row.classList.toggle("is-filtered-out", !isVisible);
      if (!isVisible && activeRow === row) {
        closeDetailPanel();
      }
    });
  };

  const setFilterMenuOpen = (isOpen) => {
    if (!resultsFilterToggle || !resultsFilterMenu) {
      return;
    }
    resultsFilterMenu.hidden = !isOpen;
    resultsFilterToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
  };


  const setPanelMobileState = () => {
    if (mobilePanelQuery.matches && detailPanel && !detailPanel.hidden) {
      document.body.classList.add("is-panel-open-mobile");
      return;
    }
    document.body.classList.remove("is-panel-open-mobile");
  };

  const closeDetailPanel = () => {
    if (!detailPanel || !inboxShell) {
      return;
    }
    detailPanel.hidden = true;
    inboxShell.classList.remove("is-panel-open");
    if (activeRow) {
      activeRow.classList.remove("is-active");
    }
    activeRow = null;
    setPanelMobileState();
  };

  const setActiveRow = (row) => {
    if (activeRow) {
      activeRow.classList.remove("is-active");
    }
    activeRow = row;
    if (activeRow) {
      activeRow.classList.add("is-active");
    }
  };

  const extractDetailHtml = (htmlText) => {
    const parser = new DOMParser();
    const doc = parser.parseFromString(htmlText, "text/html");
    const page = doc.querySelector("main.page");
    if (!page) {
      return "";
    }
    const cards = Array.from(page.querySelectorAll("section.card"));
    if (cards.length > 0) {
      return cards.map((card) => card.outerHTML).join("");
    }
    return page.innerHTML;
  };

  const openDetailPanel = async (row) => {
    if (!(row instanceof HTMLElement) || !detailPanel || !detailPanelBody || !inboxShell) {
      return;
    }
    const openUrl = row.getAttribute("data-open-url");
    if (!openUrl) {
      return;
    }
    setActiveRow(row);
    detailPanel.hidden = false;
    inboxShell.classList.add("is-panel-open");
    setPanelMobileState();
    detailPanelBody.innerHTML = '<div class="detail-panel__loading"><span class="loading-dot" aria-hidden="true"></span><span>Loading email...</span></div>';

    try {
      const response = await fetch(openUrl, {
        headers: {
          "X-Requested-With": "XMLHttpRequest",
        },
      });
      if (!response.ok) {
        throw new Error(`Request failed: ${response.status}`);
      }
      const html = await response.text();
      const detailHtml = extractDetailHtml(html);
      if (!detailHtml) {
        throw new Error("No email content found");
      }
      detailPanelBody.innerHTML = detailHtml;
      formatDetailPanelDates(detailPanelBody);
      syncDetailDateWithRow(row, detailPanelBody);
      normalizeDetailPanelLinks(detailPanelBody);
    } catch (_error) {
      detailPanelBody.innerHTML = '<section class="card"><p class="error">Could not load this email. Please try again.</p></section>';
    }
  };

  if (resultList) {
    resultList.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) {
        return;
      }
      const row = target.closest(".inbox-row[data-open-url]");
      openDetailPanel(row);
    });

    resultList.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") {
        return;
      }
      const target = event.target;
      if (!(target instanceof HTMLElement)) {
        return;
      }
      const row = target.closest(".inbox-row[data-open-url]");
      if (!row) {
        return;
      }
      event.preventDefault();
      openDetailPanel(row);
    });
  }

  if (detailPanelClose) {
    detailPanelClose.addEventListener("click", closeDetailPanel);
  }

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      setFilterMenuOpen(false);
    }
    if (event.key === "Escape" && detailPanel && !detailPanel.hidden) {
      closeDetailPanel();
    }
  });

  if (resultsFilterToggle && resultsFilterMenu) {
    resultsFilterToggle.addEventListener("click", () => {
      const isOpen = !resultsFilterMenu.hidden;
      setFilterMenuOpen(!isOpen);
    });

    document.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof Node)) {
        return;
      }
      if (resultsFilterToggle.contains(target) || resultsFilterMenu.contains(target)) {
        return;
      }
      setFilterMenuOpen(false);
    });
  }

  if (typeof mobilePanelQuery.addEventListener === "function") {
    mobilePanelQuery.addEventListener("change", setPanelMobileState);
  } else if (typeof mobilePanelQuery.addListener === "function") {
    mobilePanelQuery.addListener(setPanelMobileState);
  }

  if (typeof mobileTimestampQuery.addEventListener === "function") {
    mobileTimestampQuery.addEventListener("change", formatReceivedTimestamps);
  } else if (typeof mobileTimestampQuery.addListener === "function") {
    mobileTimestampQuery.addListener(formatReceivedTimestamps);
  }

  if (datePicker) {
    datePicker.watchViewport();
  }

  if (hasAttachmentsFilter) {
    hasAttachmentsFilter.addEventListener("change", applyResultsFilter);
    applyResultsFilter();
  }

  document.addEventListener("change", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement)) {
      return;
    }
    if (target.id !== "filter-has-attachments") {
      return;
    }
    applyResultsFilter();
  });

  const setButtonLoading = (button, loadingText) => {
    if (!button || button.disabled) {
      return;
    }
    button.dataset.originalHtml = button.innerHTML;
    button.disabled = true;
    button.innerHTML = `<span class="loading-dot" aria-hidden="true"></span><span>${loadingText}</span>`;
  };

  const startSearchLoading = () => {
    if (typeof window.startGlobalLoading === "function") {
      window.startGlobalLoading();
    }
  };

  const pad = (value) => String(value).padStart(2, "0");
  const today = new Date();
  const todayValue = `${today.getFullYear()}-${pad(today.getMonth() + 1)}-${pad(today.getDate())}`;

  const searchBodyChecked = () => {
    const searchBody = form.querySelector('input[name="search_body"]');
    return Boolean(searchBody && searchBody.checked);
  };

  const summarizeRanges = () => {
    const pairs = [];
    rangeList.querySelectorAll("[data-range-row]").forEach((row) => {
      const fromInput = row.querySelector('input[name="date_from"]');
      const toInput = row.querySelector('input[name="date_to"]');
      if (fromInput && toInput) {
        pairs.push([fromInput.value, toInput.value]);
      }
    });
    return dateRanges.summarizeRanges(pairs);
  };

  const currentMode = () => (modeInput ? modeInput.value : "view");

  const getExpensiveThreshold = () => dateRanges.expensiveThreshold(currentMode(), searchBodyChecked());

  const getMaxAllowedDays = () =>
    dateRanges.maxAllowedDays(currentMode(), searchBodyChecked(), maxSearchDays, maxBodySearchDays);

  const updateSearchWarning = () => {
    const summary = summarizeRanges();
    const threshold = getExpensiveThreshold();
    const maxAllowedDays = getMaxAllowedDays();
    if (summary.totalDays > maxAllowedDays) {
      warning.hidden = false;
      warning.className = "search-warning search-warning--error";
      const mode = modeInput ? modeInput.value : "view";
      const searchBody = form.querySelector('input[name="search_body"]');
      const bodyLimited = mode === "fuzzy" && searchBody && searchBody.checked && maxAllowedDays < maxSearchDays;
      warning.textContent = bodyLimited
        ? `Body fuzzy search is limited to ${maxAllowedDays} days. Narrow dates or uncheck Body.`
        : `This request spans ${summary.totalDays} days. Reduce it to ${maxAllowedDays} days or less.`;
      return;
    }

    if (summary.totalDays >= threshold) {
      warning.hidden = false;
      warning.className = "search-warning search-warning--caution";
      warning.textContent = `Heads up: ${summary.totalDays} days can take a while. Narrow dates if you need faster results.`;
      return;
    }

    warning.hidden = true;
    warning.className = "search-warning";
    warning.textContent = "";
  };

  // A new range row is a clean copy of the first server-rendered one, so its
  // markup (and the versioned icon-sprite URL) always matches the
  // date_input template. The picker's own state is stripped so attach()
  // wires the copy afresh.
  const renderRow = (fromValue, toValue) => {
    const template = rangeList.querySelector("[data-range-row]");
    if (!template) {
      return null;
    }
    const row = template.cloneNode(true);
    row.querySelectorAll("input.custom-datepicker").forEach((input) => {
      input.value = input.name === "date_to" ? toValue : fromValue;
      input.removeAttribute("data-datepicker");
      input.removeAttribute("aria-controls");
      input.setAttribute("aria-expanded", "false");
    });
    row.querySelectorAll("[data-date-button]").forEach((button) => {
      button.removeAttribute("aria-controls");
      button.setAttribute("aria-expanded", "false");
    });
    return row;
  };

  const syncRemoveButtons = () => {
    const rows = rangeList.querySelectorAll("[data-range-row]");
    rows.forEach((row) => {
      const removeButton = row.querySelector("[data-remove-range]");
      if (!removeButton) return;
      removeButton.disabled = rows.length === 1;
    });
  };

  pagerForms.forEach((pagerForm) => {
    pagerForm.addEventListener("submit", () => {
      const button = pagerForm.querySelector('button[type="submit"]');
      const loadingText = button && button.dataset.loadingText ? button.dataset.loadingText : "Loading...";
      pagerForms.forEach((formItem) => {
        const formButton = formItem.querySelector('button[type="submit"]');
        if (formButton) {
          formButton.disabled = true;
        }
      });
      if (button) {
        setButtonLoading(button, loadingText);
      }
    });
  });

  sortRowsByNewestReceived();
  formatReceivedTimestamps();
  setupNumberInputs();
  initDatePickers(document);

  if (!warning || !rangeList || !addButton) {
    form.addEventListener("submit", () => {
      setButtonLoading(submitButton, submitButton.dataset.loadingText || "Working...");
      startSearchLoading();
    });
    return;
  }

  addButton.addEventListener("click", () => {
    const row = renderRow(todayValue, todayValue);
    if (!row) {
      return;
    }
    rangeList.appendChild(row);
    initDatePickers(row);
    syncRemoveButtons();
    updateSearchWarning();
    const firstInput = row.querySelector('input[name="date_from"]');
    if (firstInput) {
      firstInput.focus();
    }
  });

  rangeList.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement) || !target.matches("[data-remove-range]")) {
      return;
    }

    const rows = rangeList.querySelectorAll("[data-range-row]");
    if (rows.length <= 1) {
      return;
    }

    const row = target.closest("[data-range-row]");
    if (row) {
      row.remove();
    }
    syncRemoveButtons();
    updateSearchWarning();
  });

  rangeList.addEventListener("input", updateSearchWarning);
  rangeList.addEventListener("change", updateSearchWarning);

  const searchBodyCheckbox = form.querySelector('input[name="search_body"]');
  if (searchBodyCheckbox) {
    searchBodyCheckbox.addEventListener("change", updateSearchWarning);
  }

  form.addEventListener("submit", (event) => {
    const summary = summarizeRanges();
    const maxAllowedDays = getMaxAllowedDays();
    if (summary.totalDays > maxAllowedDays) {
      event.preventDefault();
      updateSearchWarning();
      return;
    }

    const threshold = getExpensiveThreshold();
    if (summary.totalDays >= threshold) {
      const mode = modeInput ? modeInput.value : "view";
      const promptLabel = mode === "fuzzy" ? "fuzzy search" : mode === "exact" ? "search" : "view";
      const confirmed = window.confirm(
        `This ${promptLabel} spans ${summary.totalDays} days and may take a while. Continue?`
      );
      if (!confirmed) {
        event.preventDefault();
        return;
      }
    }

    setButtonLoading(submitButton, submitButton.dataset.loadingText || "Working...");
    startSearchLoading();
  });

  syncRemoveButtons();
  updateSearchWarning();

  const searchProgress = document.getElementById("search-progress");
  if (searchProgress && searchProgress.getAttribute("data-search-pending") === "1") {
    let elapsed = Number(searchProgress.getAttribute("data-pending-seconds") || "0");
    const elapsedNode = document.getElementById("search-progress-elapsed");
    window.setInterval(() => {
      elapsed += 1;
      if (elapsedNode) {
        elapsedNode.textContent = `Elapsed: ${elapsed}s`;
      }
    }, 1000);

    window.setTimeout(() => {
      window.location.reload();
    }, 2500);
  }
})();
