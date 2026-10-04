const BACKEND_URL = "http://127.0.0.1:8000";

document.addEventListener("DOMContentLoaded", async () => {
  const statusText = document.getElementById("status-text");
  const statusDot = document.getElementById("status-dot");
  const modelTag = document.getElementById("model-tag");
  const statThreats = document.getElementById("stat-threats");
  const statScans = document.getElementById("stat-scans");
  const testInput = document.getElementById("test-input");
  const btnTest = document.getElementById("btn-test");
  const testOutput = document.getElementById("test-output");
  const btnDashboard = document.getElementById("btn-dashboard");

  // Check health and guardian stats
  try {
    const res = await fetch(`${BACKEND_URL}/api/health`);
    if (res.ok) {
      const data = await res.json();
      statusText.textContent = "Firewall Online";
      statusText.style.color = "#10b981";
      statusDot.style.background = "#10b981";
      modelTag.textContent = data.default_model ? "Gemma 4" : "Local AI";

      if (data.guardian_stats) {
        statThreats.textContent = data.guardian_stats.total_threats_blocked || 0;
        statScans.textContent = data.guardian_stats.total_scanned || 0;
      }
    } else {
      markOffline();
    }
  } catch (err) {
    markOffline();
  }

  function markOffline() {
    statusText.textContent = "SafeShare Offline";
    statusText.style.color = "#f43f5e";
    statusDot.style.background = "#f43f5e";
    statusDot.style.boxShadow = "none";
    modelTag.textContent = "Run run.py";
  }

  // Simulator button
  btnTest.addEventListener("click", async () => {
    const text = testInput.value.trim();
    if (!text) return;

    btnTest.textContent = "Auditing via Gemma 4...";
    btnTest.disabled = true;

    try {
      const res = await fetch(`${BACKEND_URL}/api/audit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: text,
          source: "extension",
          mask_mode: "synthetic"
        })
      });

      const report = await res.json();
      testOutput.style.display = "block";

      if (report.findings && report.findings.length > 0) {
        testOutput.innerHTML = `<strong>🛡️ Sanitized (${report.findings.length} threat${report.findings.length > 1 ? "s" : ""} blocked):</strong><br>${escapeHtml(report.sanitized_text)}`;
        statThreats.textContent = parseInt(statThreats.textContent || "0") + report.findings.length;
        statScans.textContent = parseInt(statScans.textContent || "0") + 1;
      } else {
        testOutput.innerHTML = `<span style="color:#94a3b8">No sensitive entities detected. Prompt is clean.</span>`;
      }
    } catch (err) {
      testOutput.style.display = "block";
      testOutput.innerHTML = `<span style="color:#f43f5e">Error connecting to SafeShare backend.</span>`;
    } finally {
      btnTest.textContent = "Simulate Interception";
      btnTest.disabled = false;
    }
  });

  // Open web dashboard
  btnDashboard.addEventListener("click", () => {
    window.open("http://127.0.0.1:8000", "_blank");
  });

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
});
