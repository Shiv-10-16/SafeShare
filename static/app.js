/**
 * SafeShare Desktop Guardian - Modern UI Controller
 * Matching Coinview / Pastel & Obsidian Theme Reference
 */

const state = {
  isPaused: false,
  allLogs: [],
  filterCategory: "all",
  searchQuery: "",
  machineName: "APARAJEET",
  userName: "devhe",
};

const el = {
  heroThreatsTotal: document.getElementById("heroThreatsTotal"),
  statSecrets: document.getElementById("statSecrets"),
  statPii: document.getElementById("statPii"),
  statFinancial: document.getElementById("statFinancial"),
  headerStatusBadge: document.getElementById("headerStatusBadge"),
  controlStatusText: document.getElementById("controlStatusText"),
  controlStatusDot: document.getElementById("controlStatusDot"),
  togglePauseBtn: document.getElementById("togglePauseBtn"),
  togglePauseLabel: document.getElementById("togglePauseLabel"),
  restoreClipboardBtn: document.getElementById("restoreClipboardBtn"),
  auditTableBody: document.getElementById("auditTableBody"),
  threatFilterSelect: document.getElementById("threatFilterSelect"),
  logSearchInput: document.getElementById("logSearchInput"),
  exportLogsBtn: document.getElementById("exportLogsBtn"),
  machineNameBadge: document.getElementById("machineNameBadge"),
  machineHostTag: document.getElementById("machineHostTag"),
  machineUserTag: document.getElementById("machineUserTag"),
  sparklineLine: document.getElementById("sparklineLine"),
  sparklineArea: document.getElementById("sparklineArea"),
  sparklineDot: document.getElementById("sparklineDot"),
};

async function init() {
  lucide.createIcons();
  setupEvents();
  await refreshStats();
  setInterval(refreshStats, 1500);
}

function setupEvents() {
  // Pause / Resume Toggle
  el.togglePauseBtn.addEventListener("click", handleTogglePause);

  // Restore Last Clipboard
  el.restoreClipboardBtn.addEventListener("click", handleRestoreClipboard);

  // Filters
  el.threatFilterSelect.addEventListener("change", (e) => {
    state.filterCategory = e.target.value;
    renderTable();
  });

  el.logSearchInput.addEventListener("input", (e) => {
    state.searchQuery = e.target.value.toLowerCase().trim();
    renderTable();
  });

  // Export JSON
  el.exportLogsBtn.addEventListener("click", exportAuditLogs);

  // Sidebar navigation & simulator toggle
  const simPanel = document.getElementById("simulatorPanel");
  const simCopyBtn = document.getElementById("simCopyBtn");
  const simTextInput = document.getElementById("simTextInput");
  const simFeedback = document.getElementById("simFeedback");
  const closeSimBtn = document.getElementById("closeSimBtn");
  const sidebarPowerBtn = document.getElementById("sidebarPowerBtn");

  if (sidebarPowerBtn) {
    sidebarPowerBtn.addEventListener("click", handleTogglePause);
  }

  if (closeSimBtn && simPanel) {
    closeSimBtn.addEventListener("click", () => {
      simPanel.style.display = "none";
    });
  }

  // Preset Buttons
  document.querySelectorAll(".sim-preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const preset = btn.getAttribute("data-preset");
      if (simTextInput && preset) {
        simTextInput.value = preset;
        simTextInput.focus();
      }
    });
  });

  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach(i => i.classList.remove("active"));
      item.classList.add("active");
      const nav = item.getAttribute("data-nav");
      if (nav === "simulator" && simPanel) {
        simPanel.style.display = simPanel.style.display === "none" ? "block" : "none";
      }
    });
  });

  if (simCopyBtn && simTextInput) {
    simCopyBtn.addEventListener("click", async () => {
      const val = simTextInput.value.trim();
      if (!val) return;
      try {
        await navigator.clipboard.writeText(val);
        if (simFeedback) {
          simFeedback.style.display = "block";
          simFeedback.textContent = "[SUCCESS] Copied into Windows Clipboard! SafeShare intercepted & replaced confidential data.";
          setTimeout(() => { simFeedback.style.display = "none"; }, 3500);
        }
      } catch (_) {
        alert("Copied to clipboard: " + val);
      }
    });
  }
}

async function refreshStats() {
  try {
    const res = await fetch("/api/guardian/stats");
    if (!res.ok) return;
    const data = await res.json();

    state.isPaused = Boolean(data.is_paused);
    updatePauseUI();

    // Update numbers
    el.heroThreatsTotal.textContent = (data.total_threats_blocked || 0).toLocaleString();
    el.statSecrets.textContent = (data.secrets_count || 0).toLocaleString();
    el.statPii.textContent = (data.pii_count || 0).toLocaleString();
    el.statFinancial.textContent = (data.financial_count || 0).toLocaleString();

    // Logs
    state.allLogs = data.recent_logs || [];
    renderTable();

    // Update current device machine and user info
    if (data.machine) {
      state.machineName = data.machine;
      if (el.machineNameBadge) el.machineNameBadge.textContent = data.machine;
      if (el.machineHostTag) el.machineHostTag.textContent = `HOST: ${data.machine}`;
    }
    if (data.user) {
      state.userName = data.user;
      if (el.machineUserTag) el.machineUserTag.textContent = `USER: ${data.user}`;
    }

    // Dynamic Chart Update
    if (data.chart_points && data.chart_points.length >= 7) {
      updateSparkline(data.chart_points);
    }
  } catch (_) {}
}

function updatePauseUI() {
  if (state.isPaused) {
    el.togglePauseBtn.classList.add("is-paused");
    el.togglePauseLabel.textContent = "Resume Protection";
    el.controlStatusText.textContent = "Guardian Paused";
    el.controlStatusText.style.color = "#f59e0b";
    el.controlStatusDot.classList.add("paused");

    el.headerStatusBadge.innerHTML = `
      <span style="width: 6px; height: 6px; border-radius: 50%; background: #f59e0b;"></span>
      Shield Paused
    `;
    el.headerStatusBadge.style.background = "#fef3c7";
    el.headerStatusBadge.style.color = "#b45309";
  } else {
    el.togglePauseBtn.classList.remove("is-paused");
    el.togglePauseLabel.textContent = "Pause Protection";
    el.controlStatusText.textContent = "Guardian Active";
    el.controlStatusText.style.color = "#10b981";
    el.controlStatusDot.classList.remove("paused");

    el.headerStatusBadge.innerHTML = `
      <span style="width: 6px; height: 6px; border-radius: 50%; background: #16a34a;"></span>
      Shield Active
    `;
    el.headerStatusBadge.style.background = "#e2f8ec";
    el.headerStatusBadge.style.color = "#16a34a";
  }
}

async function handleTogglePause() {
  try {
    const nextState = !state.isPaused;
    const res = await fetch("/api/guardian/toggle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ paused: nextState }),
    });
    if (res.ok) {
      state.isPaused = nextState;
      updatePauseUI();
    }
  } catch (_) {}
}

async function handleRestoreClipboard() {
  if (state.allLogs.length === 0) {
    alert("No previous intercepted data to restore.");
    return;
  }
  const lastEntry = state.allLogs[0];
  const orig = lastEntry.original_text || "";
  if (!orig) return;

  try {
    await navigator.clipboard.writeText(orig);
    alert("Restored original sensitive text into your Windows clipboard!");
  } catch (_) {
    alert("Copied original value: " + orig.substring(0, 100));
  }
}

function renderTable() {
  let filtered = state.allLogs;

  // Filter by category
  if (state.filterCategory !== "all") {
    filtered = filtered.filter(entry => {
      const cats = (entry.categories || []).map(c => c.toUpperCase());
      const vaultKeys = Object.keys(entry.vault || {}).map(k => k.toUpperCase());
      
      if (state.filterCategory === "AMOUNT") {
        return vaultKeys.some(k => k.includes("AMOUNT")) || cats.some(c => c.includes("FINANCIAL") || c.includes("AMOUNT"));
      }
      return cats.some(c => c.includes(state.filterCategory)) || vaultKeys.some(k => k.includes(state.filterCategory));
    });
  }

  // Filter by search query
  if (state.searchQuery) {
    filtered = filtered.filter(entry => {
      return (
        (entry.original_text || "").toLowerCase().includes(state.searchQuery) ||
        (entry.sanitized_text || "").toLowerCase().includes(state.searchQuery) ||
        (entry.categories || []).join(" ").toLowerCase().includes(state.searchQuery) ||
        Object.keys(entry.vault || {}).join(" ").toLowerCase().includes(state.searchQuery) ||
        Object.values(entry.vault || {}).join(" ").toLowerCase().includes(state.searchQuery)
      );
    });
  }

  if (filtered.length === 0) {
    el.auditTableBody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align: center; color: #94a3b8; padding: 30px;">
          No matching records found.
        </td>
      </tr>
    `;
    return;
  }

  el.auditTableBody.innerHTML = filtered.slice(0, 25).map(item => {
    const cats = item.categories || ["SECRET"];
    const mainCat = cats[0] || "SECRET";
    const icon = getCategoryIcon(mainCat);
    const vault = item.vault || {};
    const tokens = Object.keys(vault);
    
    // Highlight tokens in sanitized text
    let sanitizedHtml = escapeHtml(item.sanitized_text || "");
    tokens.forEach(tok => {
      sanitizedHtml = sanitizedHtml.replaceAll(
        escapeHtml(tok),
        `<span class="token-badge-highlight">${escapeHtml(tok)}</span>`
      );
    });

    // Render tokens list
    const tokenBadgesHtml = tokens.length > 0 
      ? tokens.map(t => `<span class="token-badge" title="${escapeHtml(t)}: ${escapeHtml(vault[t])}">${escapeHtml(t)}</span>`).join(" ")
      : `<span class="token-badge">[SECURED]</span>`;

    return `
      <tr>
        <!-- What Was Copied (Original) -->
        <td>
          <div class="original-cell" title="Click to reveal/unmask full text" onclick="this.classList.toggle('revealed')">
            <span class="raw-copied-text">${escapeHtml(item.original_text || "")}</span>
            <span class="unmask-indicator"><i data-lucide="eye" style="width: 12px; height: 12px;"></i></span>
          </div>
        </td>

        <!-- What SafeShare Made (Sanitized) -->
        <td>
          <div class="sanitized-cell" title="Safe clipboard content created by SafeShare">
            <span class="safe-output-text">${sanitizedHtml}</span>
          </div>
        </td>

        <!-- Tokens & Threats -->
        <td>
          <div class="tokens-group">
            <div class="log-entity" style="margin-bottom: 4px;">
              <span class="entity-icon-small">${icon}</span>
              <span class="entity-cat-badge">${item.threats_count} secret${item.threats_count > 1 ? 's' : ''} neutralized</span>
            </div>
            <div class="token-list">
              ${tokenBadgesHtml}
            </div>
          </div>
        </td>

        <!-- Time & Machine -->
        <td style="color: #64748b; font-size: 11px; font-family: monospace;">
          <div>${escapeHtml(item.time_short || item.timestamp || '')}</div>
          <div style="font-size: 10px; color: #94a3b8;">${escapeHtml(item.machine || 'LOCAL')}</div>
        </td>

        <!-- Status -->
        <td>
          <span class="status-chip">
            <i data-lucide="shield-check" style="width: 12px; height: 12px;"></i>
            Protected
          </span>
        </td>
      </tr>
    `;
  }).join("");

  lucide.createIcons();
}

function getCategoryIcon(cat) {
  const c = cat.toUpperCase();
  if (c.includes("PASS") || c.includes("SECRET") || c.includes("KEY")) return "🔑";
  if (c.includes("AADHAAR") || c.includes("ID") || c.includes("GOV")) return "🪪";
  if (c.includes("AMOUNT") || c.includes("CARD") || c.includes("FINANCIAL") || c.includes("UPI") || c.includes("ACCOUNT")) return "💳";
  if (c.includes("NAME") || c.includes("CONTACT") || c.includes("BENEFICIARY")) return "👤";
  return "🛡️";
}

function updateSparkline(points) {
  const minVal = Math.min(...points);
  const maxVal = Math.max(...points, 1);
  const range = (maxVal - minVal) || 1;

  const width = 300;
  const height = 50;
  const padding = 6;

  const coords = points.map((val, idx) => {
    const x = (idx / (points.length - 1)) * width;
    const y = height - ((val - minVal) / range) * (height - 2 * padding) - padding;
    return { x: Math.round(x), y: Math.round(y) };
  });

  // Construct smooth bezier curve path
  let pathD = `M ${coords[0].x} ${coords[0].y}`;
  for (let i = 1; i < coords.length; i++) {
    const prev = coords[i - 1];
    const curr = coords[i];
    const cpx1 = prev.x + (curr.x - prev.x) / 2;
    const cpy1 = prev.y;
    const cpx2 = prev.x + (curr.x - prev.x) / 2;
    const cpy2 = curr.y;
    pathD += ` C ${cpx1} ${cpy1}, ${cpx2} ${cpy2}, ${curr.x} ${curr.y}`;
  }

  el.sparklineLine.setAttribute("d", pathD);
  el.sparklineArea.setAttribute("d", `${pathD} L ${width} 60 L 0 60 Z`);

  const lastCoord = coords[coords.length - 1];
  el.sparklineDot.setAttribute("cx", lastCoord.x);
  el.sparklineDot.setAttribute("cy", lastCoord.y);
}

function exportAuditLogs() {
  const blob = new Blob([JSON.stringify(state.allLogs, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `SafeShare_Audit_Log_${new Date().toISOString().split("T")[0]}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

window.addEventListener("DOMContentLoaded", init);

