async function loadRecent() {
  const { recent = [] } = await chrome.storage.local.get('recent')
  const list = document.getElementById('scan-list')

  if (recent.length === 0) {
    list.innerHTML = '<div class="empty">No scans yet this session</div>'
    return
  }

  document.getElementById('scan-count').textContent =
    `${recent.length} scan${recent.length > 1 ? 's' : ''} today`

  list.innerHTML = recent.slice(0, 10).map(item => {
    const badge = item.score >= 81 ? 'critical'
                : item.score >= 61 ? 'likely'
                : item.score >= 40 ? 'suspicious'
                : 'clean'
    const label = item.score >= 81 ? 'Critical'
                : item.score >= 61 ? 'Likely Malicious'
                : item.score >= 40 ? 'Suspicious'
                : 'Clean'
    const hostname = (() => { try { return new URL(item.url).hostname } catch { return item.url } })()
    const time = new Date(item.timestamp).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' })

    return `
      <div class="scan-item">
        <div>
          <div class="scan-url" title="${item.url}">${hostname}</div>
          <div class="scan-time">${time}</div>
        </div>
        <span class="badge badge-${badge}">${label}</span>
      </div>
    `
  }).join('')
}

loadRecent()
// Refresh every 3 seconds
setInterval(loadRecent, 3000)
