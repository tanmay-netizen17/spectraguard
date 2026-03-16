import React from 'react'

const COLORS = {
  Clean: '#10B981', Suspicious: '#F59E0B',
  'Likely Malicious': '#F97316', Critical: '#EF4444',
}

export default function MitreTag({ tactic_id, mitre_label, mitre_phase }) {
  if (!tactic_id || tactic_id === 'T0000') return null
  return (
    <div style={{
      display: 'inline-flex', alignItems: 'center', gap: 8,
      padding: '6px 12px', borderRadius: 8,
      background: '#F0F4FF', border: '1px solid #C7D2FE',
    }}>
      <span style={{
        fontFamily: 'IBM Plex Mono', fontSize: 11, color: '#4F46E5', fontWeight: 600,
      }}>{tactic_id}</span>
      <span style={{ width: 1, height: 12, background: '#C7D2FE' }} />
      <span style={{ fontSize: 12, color: '#3730A3', fontWeight: 500 }}>{mitre_label}</span>
      {mitre_phase && (
        <span style={{
          fontSize: 10, color: '#818CF8',
          padding: '1px 6px', borderRadius: 4, background: '#EEF2FF',
        }}>{mitre_phase}</span>
      )}
    </div>
  )
}
