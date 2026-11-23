// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// The Outbox page: its two date fields use the same date picker as the inbox.
(function () {
  const datePicker = window.ExplorerDatePicker;
  const form = document.getElementById("outbox-form");
  if (!datePicker || !form) return;
  datePicker.attachAll(form);
  datePicker.watchViewport();
})();
