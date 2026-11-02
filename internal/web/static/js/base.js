// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

(function () {
  const root = document.documentElement;
  const toggle = document.getElementById("toggleTheme");
  const storageKey = "flag-theme-preference";
  const loadingBar = document.getElementById("global-loading-bar");
  const loadingNote = document.getElementById("global-loading-note");
  const mediaQuery = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  const getSystemTheme = function () {
    return mediaQuery && mediaQuery.matches ? "dark" : "light";
  };

  const getStoredPreference = function () {
    try {
      return window.localStorage.getItem(storageKey);
    } catch (error) {
      return null;
    }
  };

  const applyTheme = function (theme) {
    root.setAttribute("data-theme", theme);
    if (!toggle) {
      return;
    }
    const darkMode = theme === "dark";
    toggle.setAttribute("aria-pressed", darkMode ? "true" : "false");
    toggle.setAttribute("aria-label", darkMode ? "Switch to light mode" : "Switch to dark mode");
  };

  const storedPreference = getStoredPreference();
  applyTheme(storedPreference === "light" || storedPreference === "dark" ? storedPreference : getSystemTheme());

  if (toggle) {
    toggle.addEventListener("click", function () {
      const nextTheme = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      try {
        window.localStorage.setItem(storageKey, nextTheme);
      } catch (error) {
        // Ignore storage failures and still update the current page theme.
      }
      applyTheme(nextTheme);
    });
  }

  if (mediaQuery) {
    mediaQuery.addEventListener("change", function () {
      const preference = getStoredPreference();
      if (preference === "light" || preference === "dark") {
        return;
      }
      applyTheme(getSystemTheme());
    });
  }

  // Signing out asks first: a form marked data-confirm-dialog opens that
  // dialog instead of posting, and the dialog's own form signs out. Without
  // script, or without <dialog>, the form posts at once as it always did.
  document.querySelectorAll("form[data-confirm-dialog]").forEach(function (form) {
    const dialog = document.getElementById(form.getAttribute("data-confirm-dialog"));
    if (!dialog || typeof dialog.showModal !== "function") return;
    const trigger = form.querySelector('button[type="submit"]');
    if (trigger) {
      trigger.setAttribute("aria-haspopup", "dialog");
      trigger.setAttribute("aria-controls", dialog.id);
    }
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      if (!dialog.open) dialog.showModal();
    });
    // Safari does not focus a clicked button, so the browser's own focus
    // restore can land on <body>; send it back to the opener.
    dialog.addEventListener("close", function () {
      if (trigger) trigger.focus();
    });
  });

  if (!loadingBar || !loadingNote) return;

  let active = false;
  let noteTimer = null;
  window.startGlobalLoading = function () {
    if (active) return;
    active = true;
    loadingBar.classList.add("is-active");
    noteTimer = window.setTimeout(function () {
      loadingNote.classList.add("is-active");
    }, 2500);
  };

  const stopLoading = function () {
    active = false;
    loadingBar.classList.remove("is-active");
    loadingNote.classList.remove("is-active");
    if (noteTimer) {
      window.clearTimeout(noteTimer);
      noteTimer = null;
    }
  };

  window.addEventListener("pageshow", stopLoading);

})();
