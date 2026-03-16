import React, { useContext } from 'react'
import { ThemeContext } from '../App'

// Shield SVG logo
function ShieldLogo() {
  return (
    <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
      <path d="M14 2L4 6.5V13.5C4 19.2 8.4 24.6 14 26C19.6 24.6 24 19.2 24 13.5V6.5L14 2Z"
        fill="var(--accent)" fillOpacity="0.15" stroke="var(--accent)" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M10 14l3 3 5-5" stroke="var(--accent)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

const NAV_ITEMS = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'scan',      label: 'Scan' },
  { key: 'log',       label: 'Incidents' },
  { key: 'redteam',   label: 'Red Team' },
  { key: 'settings',  label: 'Settings' },
]

export default function Topbar({ current, onNavigate }) {
  const { incidents, wsConnected, stats, localMode } = useContext(ThemeContext)
  const criticalCount = incidents.filter(i => i.severity === 'Critical').length

  return (
    <header style={{
      position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
      height: 60,
      background: 'rgba(255,255,255,0.92)',
      backdropFilter: 'blur(12px)',
      borderBottom: '1px solid var(--border)',
      display: 'flex', alignItems: 'center', padding: '0 24px',
      gap: 0,
    }}>
      {/* Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 200, flexShrink: 0 }}>
        <ShieldLogo />
        <span style={{
          fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 17,
          color: 'var(--text-primary)', letterSpacing: '-0.02em',
        }}>SentinelAI</span>
      </div>

      {/* Center Nav */}
      <nav style={{ flex: 1, display: 'flex', justifyContent: 'center', gap: 2 }}>
        {NAV_ITEMS.map(item => {
          const active = current === item.key
          return (
            <button key={item.key} onClick={() => onNavigate(item.key)} style={{
              padding: '6px 16px',
              background: 'none',
              border: 'none',
              borderBottom: active ? '2px solid var(--accent)' : '2px solid transparent',
              color: active ? 'var(--accent)' : 'var(--text-secondary)',
              fontFamily: 'var(--font-body)',
              fontSize: 14, fontWeight: active ? 600 : 500,
              cursor: 'pointer',
              transition: 'all 0.15s',
              marginBottom: active ? 0 : 0,
            }}
              onMouseEnter={e => { if (!active) e.currentTarget.style.color = 'var(--text-primary)' }}
              onMouseLeave={e => { if (!active) e.currentTarget.style.color = 'var(--text-secondary)' }}
            >{item.label}</button>
          )
        })}
      </nav>

      {/* Right: status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, minWidth: 200, justifyContent: 'flex-end' }}>
        {/* Critical threats */}
        {criticalCount > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="pulse-dot-red" />
            <span style={{
              fontFamily: 'var(--font-mono)', fontSize: 12,
              color: 'var(--critical)', fontWeight: 500,
            }}>{criticalCount} active threat{criticalCount !== 1 ? 's' : ''}</span>
          </div>
        )}

        {/* System status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{
            width: 7, height: 7, borderRadius: '50%',
            background: wsConnected ? 'var(--clean)' : 'var(--text-muted)',
            animation: wsConnected ? 'pulseDot 2s infinite' : 'none',
          }} />
          <span style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            {wsConnected ? 'All systems operational' : 'Connecting…'}
          </span>
        </div>

        {/* Air-gapped badge */}
        {localMode && (
          <span style={{
            padding: '3px 10px', borderRadius: 20,
            background: 'var(--clean-dim)', color: 'var(--clean)',
            fontSize: 11, fontWeight: 600, border: '1px solid rgba(18,183,106,0.3)',
            animation: 'feedIn 0.3s ease',
          }}>🔒 Air-gapped</span>
        )}
      </div>
    </header>
  )
}
