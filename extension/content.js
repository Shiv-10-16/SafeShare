/**
 * SafeShare AI Shield - Content Script
 * Autonomous zero-trust privacy firewall for ChatGPT, Claude, and Gemini.
 */

(function () {
  const BACKEND_URL = "http://127.0.0.1:8000";
  let sessionVault = {};
  let isShieldActive = true;

  // Initialize UI components
  createFloatingBadge();

  // Listen for paste events across the webpage
  document.addEventListener("paste", handlePasteEvent, true);

  async function handlePasteEvent(e) {
    if (!isShieldActive) return;

    const pastedText = e.clipboardData?.getData("text/plain");
    if (!pastedText || pastedText.trim().length < 6) return;

    // Check if text has sensitive items via SafeShare Local API
    try {
      const response = await fetch(`${BACKEND_URL}/api/audit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: pastedText,
          source: "extension",
          mask_mode: "synthetic"
        })
      });

      if (!response.ok) return;

      const report = await response.json();
      const findings = report.findings || [];

      if (findings.length > 0 && report.sanitized_text && report.sanitized_text !== pastedText) {
        // Intercept paste!
        e.preventDefault();
        e.stopPropagation();

        // Update session vault
        if (report.vault) {
          Object.assign(sessionVault, report.vault);
          updateDecoderModal();
        }

        // Insert sanitized text safely into target element
        insertSanitizedText(e.target, report.sanitized_text);

        // Show toast alert
        const categories = [...new Set(findings.map(f => f.category || f.entity_type || "PII"))];
        showToast(findings.length, categories);

        // Send telemetry log
        try {
          fetch(`${BACKEND_URL}/api/guardian/log`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              source: "extension",
              threats_count: findings.length,
              categories: categories,
              snippet: report.sanitized_text.substring(0, 100)
            })
          });
        } catch (_) {}
      }
    } catch (err) {
      // If backend unreachable, allow default paste
      console.debug("SafeShare backend not active:", err);
    }
  }

  function insertSanitizedText(target, text) {
    if (!target) return;

    // If textarea or input
    if (target.tagName === "TEXTAREA" || target.tagName === "INPUT") {
      const start = target.selectionStart || 0;
      const end = target.selectionEnd || 0;
      const current = target.value;
      target.value = current.substring(0, start) + text + current.substring(end);
      target.selectionStart = target.selectionEnd = start + text.length;
      target.dispatchEvent(new Event("input", { bubbles: true }));
      target.dispatchEvent(new Event("change", { bubbles: true }));
      return;
    }

    // If contenteditable (e.g. ChatGPT, Claude, Gemini rich editors)
    if (target.isContentEditable || target.getAttribute("contenteditable") === "true") {
      target.focus();
      const success = document.execCommand("insertText", false, text);
      if (!success) {
        // Fallback for modern browsers deprecating execCommand
        const sel = window.getSelection();
        if (sel && sel.rangeCount > 0) {
          const range = sel.getRangeAt(0);
          range.deleteContents();
          const node = document.createTextNode(text);
          range.insertNode(node);
          range.setStartAfter(node);
          range.setEndAfter(node);
          sel.removeAllRanges();
          sel.addRange(range);
        }
      }
      target.dispatchEvent(new Event("input", { bubbles: true }));
      return;
    }

    // Default fallback
    document.execCommand("insertText", false, text);
  }

  function showToast(threatCount, categories) {
    const existing = document.querySelector(".safeshare-toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.className = "safeshare-toast";
    toast.innerHTML = `
      <div class="safeshare-toast-icon">🛡️</div>
      <div>
        <div class="safeshare-toast-title">
          SafeShare Intercepted ${threatCount} Threat${threatCount > 1 ? "s" : ""}
          <span class="safeshare-toast-badge">Gemma 4 AI</span>
        </div>
        <div class="safeshare-toast-desc">
          Protected: ${categories.join(", ")}. Sanitized before reaching AI.
        </div>
      </div>
    `;

    document.body.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(20px)";
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }

  function createFloatingBadge() {
    const badge = document.createElement("div");
    badge.className = "safeshare-floating-badge";
    badge.title = "SafeShare AI Shield is active and monitoring prompts for sensitive data.";
    badge.innerHTML = `
      <div class="safeshare-pulse-dot"></div>
      <span>SafeShare</span>
    `;

    badge.addEventListener("click", () => {
      const modal = document.querySelector(".safeshare-decoder-modal");
      if (modal) {
        modal.classList.toggle("visible");
      }
    });

    document.body.appendChild(badge);
    createDecoderModal();
  }

  function createDecoderModal() {
    const modal = document.createElement("div");
    modal.className = "safeshare-decoder-modal";
    modal.innerHTML = `
      <div class="safeshare-decoder-header">
        <h4>🛡️ SafeShare Local Vault</h4>
        <button id="safeshare-close-modal">✕</button>
      </div>
      <div id="safeshare-vault-list">
        <div style="font-size:12px; color:#94a3b8; text-align:center; padding:10px;">
          No sensitive tokens intercepted yet in this tab.
        </div>
      </div>
      <button class="safeshare-btn-restore" id="safeshare-reveal-btn">
        🔓 Decode AI Output on Screen
      </button>
    `;

    document.body.appendChild(modal);

    modal.querySelector("#safeshare-close-modal").addEventListener("click", () => {
      modal.classList.remove("visible");
    });

    modal.querySelector("#safeshare-reveal-btn").addEventListener("click", () => {
      revealInAssistantMessages();
    });
  }

  function updateDecoderModal() {
    const container = document.getElementById("safeshare-vault-list");
    if (!container) return;

    const entries = Object.entries(sessionVault);
    if (entries.length === 0) {
      container.innerHTML = `
        <div style="font-size:12px; color:#94a3b8; text-align:center; padding:10px;">
          No sensitive tokens intercepted yet in this tab.
        </div>
      `;
      return;
    }

    let html = "";
    for (const [token, secret] of entries) {
      html += `
        <div class="safeshare-token-row">
          <span class="safeshare-token-key">${escapeHtml(token)}</span>
          <span class="safeshare-token-val" title="${escapeHtml(secret)}">${escapeHtml(secret)}</span>
        </div>
      `;
    }
    container.innerHTML = html;
  }

  function revealInAssistantMessages() {
    if (Object.keys(sessionVault).length === 0) {
      alert("No active tokens in vault to restore.");
      return;
    }

    // Common assistant message selectors for ChatGPT, Claude, Gemini
    const selectors = [
      '[data-message-author-role="assistant"]',
      ".markdown",
      ".prose",
      ".font-claude-message",
      "model-response",
      ".model-response-text"
    ];

    let replacedCount = 0;
    const elements = document.querySelectorAll(selectors.join(", "));

    elements.forEach(el => {
      let content = el.innerHTML;
      let modified = false;

      for (const [token, secret] of Object.entries(sessionVault)) {
        if (content.includes(token)) {
          const highlightedSecret = `<span style="background:rgba(16,185,129,0.25); color:#34d399; font-weight:600; padding:1px 4px; border-radius:3px;">${escapeHtml(secret)}</span>`;
          content = content.replaceAll(token, highlightedSecret);
          modified = true;
          replacedCount++;
        }
      }

      if (modified) {
        el.innerHTML = content;
      }
    });

    if (replacedCount > 0) {
      showToast(replacedCount, ["Locally Decoded & Restored"]);
    } else {
      alert("No matching synthetic tokens found in visible AI response elements.");
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
})();
