// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

(function () {
  const formatDates = () => {
    const formatter = new Intl.DateTimeFormat(undefined, {
      month: "long",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "2-digit",
      hour12: true,
    });

    document.querySelectorAll(".email-meta__date[data-email-date]").forEach((node) => {
      const value = node.getAttribute("data-email-date");
      if (!value) return;
      const parsed = new Date(value);
      if (Number.isNaN(parsed.getTime())) return;
      node.textContent = formatter.format(parsed);
    });
  };

  const createTrimToggle = (target) => {
    if (!target || target.dataset.trimmed === "1") {
      return;
    }

    target.hidden = true;
    target.dataset.trimmed = "1";

    const button = document.createElement("button");
    button.type = "button";
    button.className = "trimmed-toggle";
    button.setAttribute("aria-expanded", "false");
    button.innerHTML = '<span class="trimmed-toggle__dots">...</span><span>Show trimmed content</span>';

    button.addEventListener("click", () => {
      const isHidden = target.hidden;
      target.hidden = !isHidden;
      button.setAttribute("aria-expanded", isHidden ? "true" : "false");
      button.lastChild.textContent = isHidden ? "Hide trimmed content" : "Show trimmed content";
    });

    target.parentNode.insertBefore(button, target);
  };

  const collapseQuotedHtml = () => {
    const htmlBody = document.querySelector(".body-preview-html");
    if (!htmlBody) {
      return;
    }

    const candidates = htmlBody.querySelectorAll("blockquote, div.gmail_quote, div[id='divRplyFwdMsg']");
    if (!candidates.length) {
      return;
    }

    createTrimToggle(candidates[0]);
  };

  const collapseQuotedText = () => {
    const textBody = document.querySelector(".message-body--text");
    if (!textBody) {
      return;
    }

    const rawText = textBody.textContent || "";
    if (!rawText.trim()) {
      return;
    }

    const lines = rawText.split(/\r?\n/);
    let splitIndex = -1;
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] || "";
      if (/^>/.test(line.trim()) || /^On\s.+wrote:\s*$/i.test(line.trim())) {
        splitIndex = i;
        break;
      }
    }

    if (splitIndex <= 0) {
      return;
    }

    const visibleText = lines.slice(0, splitIndex).join("\n").trimEnd();
    const quotedText = lines.slice(splitIndex).join("\n").trim();
    if (!quotedText) {
      return;
    }

    const visibleBlock = document.createElement("pre");
    visibleBlock.className = "body-preview message-body";
    visibleBlock.textContent = visibleText;

    const quotedBlock = document.createElement("pre");
    quotedBlock.className = "body-preview message-body message-body--quoted";
    quotedBlock.textContent = quotedText;

    const parent = textBody.parentNode;
    parent.replaceChild(visibleBlock, textBody);
    parent.appendChild(quotedBlock);
    createTrimToggle(quotedBlock);
  };

  const normalizeMessageLinks = (root) => {
    if (!root) {
      return;
    }
    root.querySelectorAll("a[href]").forEach((link) => {
      const href = (link.getAttribute("href") || "").trim();
      if (!href || href.startsWith("#")) {
        return;
      }
      link.setAttribute("target", "_blank");
      link.setAttribute("rel", "noopener noreferrer");
    });
  };

  const linkifyPlainTextBody = (root) => {
    if (!root || !root.classList.contains("message-body--text") || root.dataset.linkified === "1") {
      return;
    }

    const escapeHtml = (value) =>
      value
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;")
        .replace(/'/g, "&#39;");

    const text = root.textContent || "";
    const urlRegex = /(https?:\/\/[^\s<]+[^\s<\.)])/gi;
    const linked = escapeHtml(text).replace(urlRegex, (url) => {
      return `<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`;
    });

    root.innerHTML = linked.replace(/\r?\n/g, "<br>");
    root.dataset.linkified = "1";
  };

  formatDates();
  const messageBody = document.getElementById("message-body");
  linkifyPlainTextBody(messageBody);
  normalizeMessageLinks(messageBody);
  collapseQuotedHtml();
  collapseQuotedText();
})();
