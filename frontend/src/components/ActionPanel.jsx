import React from 'react'

const COLORS = {
  Clean: { bg: '#F0FDF4', text: '#10B981', border: '#A7F3D0' },
  Suspicious: { bg: '#FFFBEB', text: '#F59E0B', border: '#FDE68A' },
  'Likely Malicious': { bg: '#FFF7ED', text: '#F97316', border: '#FED7AA' },
  Critical: { bg: '#FEF2F2', text: '#EF4444', border: '#FCA5A5' },
}

export default function ActionPanel({ recommended_action, severity }) {
  const col = COLORS[severity] || COLORS['Suspicious']
  return (
    <div style={{
      padding: 16, borderRadius: 10,
      background: col.bg, border: `1px solid ${col.border}`,
      display: 'flex', gap: 12, alignItems: 'flex-start',
    }}>
      <div style={{ fontSize: 20 }}>
        {severity === 'Critical' ? '🚨' : severity === 'Likely Malicious' ? '⚠️' : severity === 'Suspicious' ? '🟡' : '✅'}
      </div>
      <div>
        <div style={{ fontWeight: 600, fontSize: 13, color: col.text, marginBottom: 4 }}>
          Recommended Action
        </div>
        <p style={{ margin: 0, fontSize: 13, color: '#374151', lineHeight: 1.6 }}>
          {recommended_action || 'No specific action required.'}
        </p>
      </div>
    </div>
  )
}
