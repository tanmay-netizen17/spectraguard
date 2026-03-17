const BACKEND = 'http://localhost:8000'
const THRESHOLD_WARN    = 61    // show warning overlay
const THRESHOLD_NOTIFY  = 40    // show browser notification
const CHECK_COOLDOWN_MS = 10000 // don't re-check same URL within 10s

const checkedUrls = new Map()  // url → { score, timestamp }

// ── Listen for navigation ────────────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return   // main frame only
  const url = details.url
  if (!url.startsWith('http')) return
  if (isInternalUrl(url)) return

  // Cooldown check
  const cached = checkedUrls.get(url)
  if (cached && Date.now() - cached.timestamp < CHECK_COOLDOWN_MS) return

  await checkUrl(url, details.tabId)
})

function isInternalUrl(url) {
  const skip = ['localhost','127.0.0.1','chrome://','chrome-extension://','about:']
  return skip.some(s => url.includes(s))
}

async function checkUrl(url, tabId) {
  try {
    const res = await fetch(`${BACKEND}/analyse`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ input: url, type: 'url' }),
    })
    const data = await res.json()
    const score    = data.sentinel_score || 0
    const severity = data.severity || 'Clean'
    const brief    = data.threat_brief || ''

    checkedUrls.set(url, { score, timestamp: Date.now() })

    // Update badge
    updateBadge(tabId, score)

    if (score >= THRESHOLD_NOTIFY) {
      chrome.notifications.create(`threat-${Date.now()}`, {
        type:     'basic',
        iconUrl:  'icons/icon128.png',
        title:    `SpectraGuard — ${severity} (${score}/100)`,
        message:  brief.slice(0, 150) || `Threat detected on ${new URL(url).hostname}`,
        priority: score >= 81 ? 2 : 1,
        buttons:  score >= 61 ? [{ title: 'Block & Go Back' }] : [],
      })
    }

    if (score >= THRESHOLD_WARN) {
      chrome.scripting.executeScript({
        target: { tabId },
        func:   injectWarningOverlay,
        args:   [score, severity, new URL(url).hostname, brief],
      }).catch(() => {})
    }

    // Send to popup if open
    chrome.runtime.sendMessage({
      type: 'SCAN_RESULT', url, score, severity, brief,
    }).catch(() => {})

    // Save to recent list
    saveToRecent({ url, score, severity, timestamp: Date.now() })

  } catch (err) {
    console.debug('[SpectraGuard] Backend unreachable:', err.message)
  }
}

function updateBadge(tabId, score) {
  const colour = score >= 81 ? '#F04438'
               : score >= 61 ? '#EF6820'
               : score >= 40 ? '#F79009'
               : '#12B76A'
  const text   = score >= 40 ? score.toString() : ''
  chrome.action.setBadgeBackgroundColor({ color: colour, tabId })
  chrome.action.setBadgeText({ text, tabId })
}

function injectWarningOverlay(score, severity, hostname, brief) {
  if (document.getElementById('spectraguard-overlay')) return

  const overlay = document.createElement('div')
  overlay.id    = 'spectraguard-overlay'
  overlay.style.cssText = `
    position:fixed; top:0; left:0; right:0; z-index:2147483647;
    background:${score >= 81 ? '#FEF2F2' : '#FFFAEB'};
    border-bottom:3px solid ${score >= 81 ? '#F04438' : '#F79009'};
    padding:12px 20px;
    display:flex; align-items:center; justify-content:space-between;
    font-family:-apple-system,BlinkMacSystemFont,sans-serif;
    font-size:13px; color:#0D1117;
    box-shadow:0 2px 12px rgba(0,0,0,0.15);
  `
  overlay.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px">
      <span style="font-size:18px">${score >= 81 ? '🚨' : '⚠️'}</span>
      <div>
        <strong>SpectraGuard — ${severity} (${score}/100)</strong>
        <div style="font-size:12px;color:#6B7280;margin-top:2px">
          ${hostname} · ${brief.slice(0,120)}
        </div>
      </div>
    </div>
    <div style="display:flex;gap:8px;flex-shrink:0;margin-left:12px">
      ${score >= 61 ? `<button id="sg-block" style="background:#F04438;color:#fff;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600">Go Back</button>` : ''}
      <button id="sg-dismiss" style="background:none;border:1px solid #E5E7EB;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:12px">Dismiss</button>
    </div>
  `
  document.body.prepend(overlay)

  document.getElementById('sg-dismiss')?.addEventListener('click', () => overlay.remove())
  document.getElementById('sg-block')?.addEventListener('click',   () => history.back())
}

// Handle notification button click
chrome.notifications.onButtonClicked.addListener((notifId, btnIdx) => {
  if (btnIdx === 0) {
    chrome.tabs.query({ active:true, currentWindow:true }, tabs => {
      if (tabs[0]) chrome.tabs.goBack(tabs[0].id)
    })
  }
})

// Recent scans storage
async function saveToRecent(item) {
  const { recent = [] } = await chrome.storage.local.get('recent')
  recent.unshift(item)
  await chrome.storage.local.set({ recent: recent.slice(0, 20) })
}
