import React from 'react'

export function SectionHeader({ number, title, subtitle }) {
  return (
    <div style={{ position: 'relative', marginBottom: 32 }}>
      {/* Large background number — Cyber FZ's "01" style */}
      <span style={{
        position: 'absolute', top: -16, left: -6,
        fontFamily: 'var(--font-display)',
        fontSize: 72, fontWeight: 800,
        color: 'var(--text-primary)', opacity: 0.04,
        userSelect: 'none', lineHeight: 1,
        zIndex: 0
      }}>
        {number}
      </span>
      <div style={{ position: 'relative', zIndex: 1 }}>
        <h2 style={{
          fontFamily: 'var(--font-display)',
          fontSize: 28, fontWeight: 700,
          color: 'var(--text-primary)',
          margin: 0, letterSpacing: '-0.02em',
        }}>{title}</h2>
        {subtitle && (
          <p style={{
            fontFamily: 'var(--font-body)',
            color: 'var(--text-secondary)',
            marginTop: 4, marginBottom: 0,
            fontSize: 15
          }}>
            {subtitle}
          </p>
        )}
      </div>
    </div>
  )
}
