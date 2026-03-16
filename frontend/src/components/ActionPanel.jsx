import React, { useState } from 'react'
import { SectionHeader } from './SectionHeader'

export default function ActionPanel({ recommended_action, severity, result, onFeedback }) {
  const [blocked,    setBlocked]    = useState(false)
  const [fpDone,     setFpDone]     = useState(false)
  const [blocking,   setBlocking]   = useState(false)
  const [showBanner, setShowBanner] = useState(false)

  const isThreat = (result?.sentinel_score || 0) >= 61
  const isCritical = severity === 'Critical' || severity === 'Likely Malicious'

  async function handleBlock() {
    setBlocking(true)
    try {
      // 1. Add to blocklist in backend
      await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/blocklist/add`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          incident_id: result.incident_id,
          input_type:  result.file_type || result.type || 'url',
          value:       result.blocked_value || result.input_value || '',
          score:       result.sentinel_score,
        })
      }).catch(() => {})   // non-blocking — don't fail if endpoint missing

      // 2. If it's a URL and browser extension is active, send block command
      if (result.file_type === 'url' || result.type === 'url' || result.mitre_tactic?.includes('1192')) {
        window.postMessage({ type: 'SENTINEL_BLOCK_URL', url: result.input_value }, '*')
      }

      setBlocked(true)
      setShowBanner(true)
      setTimeout(() => setShowBanner(false), 4000)
    } finally {
      setBlocking(false)
    }
  }

  async function handleFalsePositive() {
    try {
      await fetch(
        `${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/feedback/${result.incident_id}`,
        {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ verdict: 'false_positive', score: (result.sentinel_score || 0) / 100 })
        }
      )
      setFpDone(true)
      if (onFeedback) onFeedback('false_positive')
    } catch (e) {
      console.error('Feedback error:', e)
    }
  }

  return (
    <div className="card" style={{ 
      padding: '24px', 
      borderLeft: isCritical ? '3px solid var(--critical)' : '3px solid var(--clean)',
    }}>
      {/* Success banner */}
      {showBanner && (
        <div style={{
          marginBottom: 12,
          padding: '10px 16px',
          background: '#F0FDF4',
          border: '1px solid #86EFAC',
          borderRadius: 8,
          fontSize: 13,
          color: '#166534',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          animation: 'toastIn 0.3s ease-out',
        }}>
          <span>✓</span>
          <span>
            {result.file_type === 'url' || result.type === 'url'
              ? 'URL has been added to blocklist. Browser extension will block future visits.'
              : 'Incident has been flagged for blocking. Security team notified.'}
          </span>
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ flex: 1, paddingRight: 40 }}>
          <SectionHeader number="03" title="Recommended Action" />
          <p style={{
            fontSize: 16, color: 'var(--text-primary)', fontWeight: 500, lineHeight: 1.6,
            margin: '0 0 24px', fontFamily: 'var(--font-body)'
          }}>
            {recommended_action || "Investigate the event logs for further context. No immediate blocking action required."}
          </p>

          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }} className="action-buttons">
            {/* Block button — only show for actual threats */}
            {isThreat && (
              <button
                onClick={handleBlock}
                disabled={blocked || blocking}
                style={{
                  background:    blocked ? '#F0FDF4' : blocking ? '#E5E7EB' : '#DC2626',
                  color:         blocked ? '#166534' : blocking ? '#9CA3AF' : '#fff',
                  border:        blocked ? '1px solid #86EFAC' : 'none',
                  borderRadius:  8,
                  padding:       '10px 20px',
                  fontSize:      13,
                  fontWeight:    600,
                  cursor:        blocked || blocking ? 'not-allowed' : 'pointer',
                  display:       'flex',
                  alignItems:    'center',
                  gap:           6,
                  transition:    'all 0.2s',
                }}
              >
                {blocking ? 'Blocking…' : blocked ? '✓ Blocked' : 'Execute Block Action →'}
              </button>
            )}

            <button
              onClick={handleFalsePositive}
              disabled={fpDone}
              style={{
                background:   fpDone ? '#F0FDF4' : '#fff',
                color:        fpDone ? '#166534' : '#374151',
                border:       fpDone ? '1px solid #86EFAC' : '1px solid #E5E7EB',
                borderRadius: 8,
                padding:      '10px 20px',
                fontSize:     13,
                fontWeight:   500,
                cursor:       fpDone ? 'not-allowed' : 'pointer',
                transition:   'all 0.2s',
              }}
            >
              {fpDone ? '✓ Marked as False Positive' : 'Mark False Positive'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

