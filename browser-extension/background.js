/**
 * SentinelAI Shield — Background Service Worker
 * Intercepts navigation events, submits URLs for threat analysis,
 * and injects warning overlays for high-risk pages.
 */

const SENTINEL_API = "http://localhost:8000";
const SCORE_THRESHOLD = 61; // Warn on Likely Malicious or above
const MAX_HISTORY = 10;

// ── Navigation listener ──────────────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only handle main frame navigations (not iframes)
  if (details.frameId !== 0) return;

  const url = details.url;

  // Skip internal chrome:// and extension pages
  if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) return;
  if (url.startsWith("about:") || url.startsWith("data:")) return;

  try {
    const result = await analyseURL(url, details.tabId);
    await storeResult(url, result);

    if (result.sentinel_score >= SCORE_THRESHOLD) {
      // Wait for page to load then inject warning
      chrome.tabs.onUpdated.addListener(function listener(tabId, info) {
        if (tabId === details.tabId && info.status === "complete") {
          chrome.scripting.executeScript({
            target: { tabId: details.tabId },
            func: injectWarningOverlay,
            args: [result],
          }).catch(() => {}); // Ignore errors on protected pages
          chrome.tabs.onUpdated.removeListener(listener);
        }
      });
    }
  } catch (e) {
    console.error("[SentinelAI] Analysis failed:", e.message);
  }
});

// ── URL Analysis ─────────────────────────────────────────────────────────────
async function analyseURL(url, tabId) {
  const response = await fetch(`${SENTINEL_API}/ingest/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url,
      tab_id: tabId,
      timestamp: new Date().toISOString(),
    }),
  });

  if (!response.ok) throw new Error(`API error: ${response.status}`);
  return await response.json();
}

// ── Storage ──────────────────────────────────────────────────────────────────
async function storeResult(url, result) {
  const { history = [] } = await chrome.storage.local.get("history");
  history.unshift({
    url: url.substring(0, 80),
    score: result.sentinel_score,
    severity: result.severity,
    timestamp: new Date().toISOString(),
  });
  await chrome.storage.local.set({ history: history.slice(0, MAX_HISTORY) });
}

// ── Warning Overlay (injected into page) ─────────────────────────────────────
function injectWarningOverlay(result) {
  // Avoid duplicate overlays
  if (document.getElementById("sentinel-overlay")) return;

  const severityColors = {
    "Critical": { bg: "#FEF2F2", border: "#EF4444", text: "#991B1B" },
    "Likely Malicious": { bg: "#FFF7ED", border: "#F97316", text: "#9A3412" },
    "Suspicious": { bg: "#FEFCE8", border: "#F59E0B", text: "#92400E" },
  };
  const colors = severityColors[result.severity] || severityColors["Suspicious"];

  const overlay = document.createElement("div");
  overlay.id = "sentinel-overlay";
  overlay.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: ${colors.bg}; border-bottom: 3px solid ${colors.border};
    padding: 12px 20px; font-family: -apple-system, sans-serif;
    display: flex; align-items: center; gap: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.15);
  `;

  overlay.innerHTML = `
    <div style="font-size:20px">🛡️</div>
    <div style="flex:1">
      <strong style="color:${colors.text}; font-size:14px">
        SentinelAI: ${result.severity} Threat Detected (Score: ${result.sentinel_score}/100)
      </strong>
      <p style="margin:2px 0 0; font-size:12px; color:${colors.text}; opacity:0.8">
        ${result.threat_brief || result.recommended_action || "Proceed with caution."}
      </p>
    </div>
    <button id="sentinel-dismiss" style="
      background:${colors.border}; color:#fff; border:none; border-radius:6px;
      padding:6px 12px; cursor:pointer; font-size:12px; white-space:nowrap;
    ">Dismiss</button>
  `;

  document.body.prepend(overlay);
  document.getElementById("sentinel-dismiss").addEventListener("click", () => overlay.remove());
}

// ── Message listener (from popup) ────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_HISTORY") {
    chrome.storage.local.get("history").then(({ history = [] }) => {
      sendResponse({ history });
    });
    return true; // Keep channel open for async response
  }
  if (msg.type === "ANALYSE_URL") {
    analyseURL(msg.url, 0).then(result => sendResponse({ result })).catch(e => sendResponse({ error: e.message }));
    return true;
  }
});
