import React, { useContext } from 'react'
import { ThemeContext } from '../App'

// SVG icon primitives
const Icon = ({ path, size = 16, color = 'currentColor' }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke={color} strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
    <path d={path} />
  </svg>
)

const ICONS = {
  grid:      'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  activity:  'M22 12h-4l-3 9L9 3l-3 9H2',
  search:    'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z',
  shield:    'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  crosshair: 'M12 22a10 10 0 100-20 10 10 0 000 20zM22 12h-4M6 12H2M12 6V2M12 22v-4',
  heart:     'M22 12h-4l-3 9L9 3l-3 9H2',
  sliders:   'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6',
}

const NAV = [
  { key: 'dashboard', label: 'Overview',     icon: 'grid' },
  { key: 'scan',      label: 'Scan',         icon: 'search' },
  { key: 'log',       label: 'Incidents',    icon: 'shield' },
  { key: 'redteam',   label: 'Red Team',     icon: 'crosshair' },
  { key: 'settings',  label: 'Settings',     icon: 'sliders' },
]

export default function Sidebar({ current, onNavigate, wsConnected, localMode }) {
  const { incidents } = useContext(ThemeContext)
  const hasCritical = incidents.some(i => i.severity === 'Critical')

  return (
    <nav style={{
      width: 220, background: 'var(--bg-surface)',
      borderRight: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column',
      padding: '0 0 16px',
      position: 'fixed', top: 60, left: 0, bottom: 0,
      zIndex: 50, overflowY: 'auto',
    }}>
      {/* Nav items */}
      <div style={{ flex: 1, paddingTop: 12 }}>
        {NAV.map(item => {
          const active = current === item.key
          const showDot = item.key === 'log' && hasCritical
          return (
            <button key={item.key}
              onClick={() => onNavigate(item.key)}
              title={item.label}
              style={{
                display: 'flex', alignItems: 'center', gap: 10,
                width: '100%', padding: '10px 16px',
                background: active ? 'var(--accent-dim)' : 'transparent',
                border: 'none', cursor: 'pointer', textAlign: 'left',
                borderLeft: active ? '3px solid var(--accent)' : '3px solid transparent',
                color: active ? 'var(--accent)' : 'var(--text-secondary)',
                transition: 'all 0.15s',
                position: 'relative',
              }}
              onMouseEnter={e => { if (!active) { e.currentTarget.style.background = 'var(--bg-overlay)'; e.currentTarget.style.color = 'var(--text-primary)' } }}
              onMouseLeave={e => { if (!active) { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-secondary)' } }}
            >
              <Icon path={ICONS[item.icon]} size={16}
                color={active ? 'var(--accent)' : 'var(--text-muted)'} />
              <span style={{
                fontFamily: 'var(--font-body)', fontSize: 13,
                fontWeight: active ? 600 : 400, flex: 1,
              }}>{item.label}</span>
              {showDot && (
                <span className="pulse-dot-red" style={{ width: 6, height: 6 }} />
              )}
            </button>
          )
        })}
      </div>

      {/* Agent status card */}
      <div style={{
        margin: '0 12px 12px',
        padding: '12px',
        background: 'var(--bg-sunken)',
        borderRadius: 8,
        border: '1px solid var(--border)',
      }}>
        <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase' }}>
          Agent Status
        </div>
        {[
          { label: 'Live Feed', connected: wsConnected },
          { label: 'Email Daemon', connected: false },
          { label: 'Browser Ext', connected: false },
        ].map(agent => (
          <div key={agent.label} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
            <div style={{
              width: 6, height: 6, borderRadius: '50%',
              background: agent.connected ? 'var(--clean)' : 'var(--text-muted)',
              flexShrink: 0,
            }} />
            <span style={{ fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'var(--font-body)' }}>
              {agent.label}
            </span>
          </div>
        ))}
      </div>

      {/* Version */}
      <div style={{ padding: '0 16px' }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
          SentinelAI v1.0 · Build 20260316
        </div>
      </div>
    </nav>
  )
}
