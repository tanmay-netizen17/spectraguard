/**
 * SentinelAI Shield — Content Script
 * Handles UI injection for threat warnings.
 */

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "show_warning") {
    injectWarningOverlay(request.result);
    sendResponse({ status: "overlay_injected" });
  }
});

function injectWarningOverlay(result) {
  // Prevent duplicate overlays
  if (document.getElementById("sentinel-shield-overlay")) return;

  const overlay = document.createElement("div");
  overlay.id = "sentinel-shield-overlay";
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(15, 23, 42, 0.98);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 2147483647;
    color: white;
    font-family: 'Inter', sans-serif;
    text-align: center;
    padding: 20px;
  `;

  const color = result.severity === 'Critical' ? '#EF4444' : '#F97316';
  
  overlay.innerHTML = `
    <div style="max-width: 600px; padding: 40px; background: #1E293B; border-radius: 16px; border: 2px solid ${color}; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);">
      <div style="font-size: 64px; margin-bottom: 20px;">🛡️</div>
      <h1 style="font-size: 28px; font-weight: 700; margin-bottom: 12px; color: ${color};">Potentially Malicious Site Blocked</h1>
      <p style="font-size: 16px; color: #94A3B8; margin-bottom: 24px;">
        SentinelAI has detected a high threat level for this URL.<br>
        <strong>Sentinel Score: ${result.sentinel_score}/100 (${result.severity})</strong>
      </p>
      
      <div style="background: rgba(0,0,0,0.2); padding: 16px; border-radius: 8px; margin-bottom: 32px; text-align: left; font-size: 14px;">
        <div style="font-weight: 600; color: #6366F1; margin-bottom: 4px;">AI THREAT BRIEF:</div>
        <div style="color: #CBD5E1; line-height: 1.5;">${result.threat_brief || "No brief available."}</div>
      </div>

      <div style="display: flex; gap: 16px; justify-content: center;">
        <button id="sentinel-go-back" style="padding: 12px 24px; background: ${color}; color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; transition: opacity 0.2s;">
          Get me out of here
        </button>
        <button id="sentinel-proceed" style="padding: 12px 24px; background: transparent; color: #94A3B8; border: 1px solid #475569; border-radius: 8px; font-weight: 500; cursor: pointer;">
          I understand the risks, proceed
        </button>
      </div>
      <div style="margin-top: 24px; font-size: 12px; color: #475569;">
        Protected by SentinelAI Defense Platform
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  document.getElementById("sentinel-go-back").addEventListener("click", () => {
    window.history.back();
    if (window.history.length <= 1) {
      window.close();
    }
  });

  document.getElementById("sentinel-proceed").addEventListener("click", () => {
    overlay.remove();
  });
}
