const DASHBOARD_URL = "http://localhost:5173";

function severityClass(severity) {
  const map = { "Critical": "critical", "Likely Malicious": "likely", "Suspicious": "suspicious", "Clean": "clean" };
  return map[severity] || "clean";
}

function renderHistory(history) {
  const container = document.getElementById("entries");
  if (!history || history.length === 0) {
    container.innerHTML = '<div class="empty">No URLs scanned yet.<br>Browse to start protection.</div>';
    return;
  }

  container.innerHTML = history.map(item => {
    const cls = severityClass(item.severity);
    return `
      <div class="entry">
        <div class="score ${cls}">${item.score}</div>
        <div class="meta">
          <div class="url-text" title="${item.url}">${item.url}</div>
          <div class="sev">${new Date(item.timestamp).toLocaleTimeString()}</div>
        </div>
        <div class="badge ${cls}">${item.severity}</div>
      </div>`;
  }).join("");
}

async function loadHistory() {
  chrome.runtime.sendMessage({ type: "GET_HISTORY" }, ({ history }) => {
    renderHistory(history || []);
    const statusEl = document.getElementById("status");
    if (history && history.length > 0) {
      statusEl.textContent = `${history.length} URL${history.length > 1 ? "s" : ""} scanned this session`;
    } else {
      statusEl.textContent = "Active — monitoring all navigation";
    }
  });
}

document.getElementById("btn-open").addEventListener("click", () => {
  chrome.tabs.create({ url: DASHBOARD_URL });
});

document.getElementById("btn-clear").addEventListener("click", async () => {
  await chrome.storage.local.set({ history: [] });
  renderHistory([]);
  document.getElementById("status").textContent = "Cleared";
});

loadHistory();
