import React from 'react'

export function SeverityBadge({ severity }) {
  const sevMap = {
    'Clean':            { cls: 'sev-Clean', bg: 'bg-sev-Clean' },
    'Suspicious':       { cls: 'sev-Suspicious', bg: 'bg-sev-Suspicious' },
    'Likely Malicious': { cls: 'sev-Likely', bg: 'bg-sev-Likely' },
    'Critical':         { cls: 'sev-Critical', bg: 'bg-sev-Critical' },
  }

  const s = sevMap[severity] || sevMap['Clean']

  return (
    <span className={`${s.cls} ${s.bg}`} style={{
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      padding: '4px 10px',
      borderRadius: 9999, // fully rounded pill
      fontSize: 12,
      fontFamily: 'var(--font-body)',
      fontWeight: 600,
      borderWidth: 1,
      borderStyle: 'solid',
      whiteSpace: 'nowrap',
    }}>
      {severity}
    </span>
  )
}
