import React, { useContext } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { ThemeContext } from '../App'

// SVG icon primitives
const GridIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect>
  </svg>
)
const SearchIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line>
  </svg>
)
const ShieldIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
  </svg>
)
const CrosshairIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"></circle><line x1="22" y1="12" x2="18" y2="12"></line><line x1="6" y1="12" x2="2" y2="12"></line><line x1="12" y1="6" x2="12" y2="2"></line><line x1="12" y1="22" x2="12" y2="18"></line>
  </svg>
)
const SlidersIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="4" y1="21" x2="4" y2="14"></line><line x1="4" y1="10" x2="4" y2="3"></line><line x1="12" y1="21" x2="12" y2="12"></line><line x1="12" y1="8" x2="12" y2="3"></line><line x1="20" y1="21" x2="20" y2="16"></line><line x1="20" y1="12" x2="20" y2="3"></line><line x1="1" y1="14" x2="7" y2="14"></line><line x1="9" y1="8" x2="15" y2="8"></line><line x1="17" y1="16" x2="23" y2="16"></line>
  </svg>
)

function ShieldLogo({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" fill="none">
      <path d="M14 2L4 6.5V13.5C4 19.2 8.4 24.6 14 26C19.6 24.6 24 19.2 24 13.5V6.5L14 2Z"
        fill="var(--accent)" fillOpacity="0.15" stroke="var(--accent)" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M10 14l3 3 5-5" stroke="var(--accent)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function IncidentBadge() {
  const { stats } = useContext(ThemeContext)
  if (!stats.critical) return null
  return (
    <span style={{
      background: 'var(--critical)', color: '#fff', fontSize: 10,
      padding: '2px 6px', borderRadius: 10, fontWeight: 700,
      marginLeft: 'auto'
    }}>
      {stats.critical}
    </span>
  )
}

function AgentStatusPanel() {
  const { wsConnected } = useContext(ThemeContext)
  return (
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
        { label: 'Email Deamnon', connected: false },
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
  )
}

export default function Sidebar({ mobileOpen, onClose }) {
  const location = useLocation()

  const NAV_ITEMS = [
    { path: '/',           label: 'Overview',   icon: GridIcon    },
    { path: '/scan',       label: 'Scan',       icon: SearchIcon  },
    { path: '/incidents',  label: 'Incidents',  icon: ShieldIcon  },
    { path: '/red-team',   label: 'Red Team',   icon: CrosshairIcon },
    { path: '/settings',   label: 'Settings',   icon: SlidersIcon },
  ]

  return (
    <>
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          onClick={onClose}
          style={{
            position:   'fixed', inset: 0,
            background: 'rgba(0,0,0,0.4)',
            zIndex:     998,
            animation:  'fadeIn 0.2s ease-out',
          }}
        />
      )}

      {/* Sidebar panel */}
      <nav style={{
        position:   'fixed',
        top:        0,
        left:       0,
        height:     '100vh',
        width:      220,
        background: '#fff',
        borderRight: '1px solid #E5E7EB',
        zIndex:     999,
        display:    'flex',
        flexDirection: 'column',
        padding:    '0 0 20px',
        // Slide animation
        transform:  mobileOpen || window.innerWidth >= 768
                    ? 'translateX(0)'
                    : 'translateX(-100%)',
        transition: 'transform 0.28s cubic-bezier(0.4, 0, 0.2, 1)',
        overflowY:  'auto',
      }}>
        {/* Logo */}
        <div style={{
          padding:     '20px 20px 16px',
          borderBottom: '1px solid #F0F0F0',
          display:     'flex',
          alignItems:  'center',
          justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <ShieldLogo size={24} />
            <span style={{
              fontFamily: 'var(--font-display, Syne, sans-serif)',
              fontWeight: 700, fontSize: 16, color: '#0D1117',
            }}>
              SpectraGuard
            </span>
          </div>
          {/* Mobile close button */}
          <button
            onClick={onClose}
            style={{
              display:    window.innerWidth < 768 ? 'block' : 'none',
              background: 'none', border: 'none', cursor: 'pointer',
              fontSize: 20, color: '#6B7280', padding: 0,
            }}
          >
            ×
          </button>
        </div>

        {/* Nav items */}
        <div style={{ padding: '12px 12px', flex: 1 }}>
          {NAV_ITEMS.map(({ path, label, icon: Icon }) => {
            const active = location.pathname === path ||
                           (path !== '/' && location.pathname.startsWith(path))
            return (
              <Link
                key={path}
                to={path}
                onClick={onClose}
                style={{
                  display:      'flex',
                  alignItems:   'center',
                  gap:          10,
                  padding:      '10px 12px',
                  borderRadius: 8,
                  marginBottom: 2,
                  textDecoration: 'none',
                  color:        active ? '#0A84FF' : '#374151',
                  background:   active ? '#E8F2FF' : 'transparent',
                  fontWeight:   active ? 600 : 400,
                  fontSize:     14,
                  borderLeft:   active ? '3px solid #0A84FF' : '3px solid transparent',
                  transition:   'all 0.15s ease',
                }}
              >
                <Icon size={16} />
                {label}
                {label === 'Incidents' && <IncidentBadge />}
              </Link>
            )
          })}
        </div>

        {/* Agent status at bottom */}
        <AgentStatusPanel />

        {/* Version */}
        <div style={{ padding: '0 20px', fontSize: 11, color: '#9CA3AF', fontFamily: 'monospace' }}>
          SpectraGuard v1.0 · Build {new Date().toISOString().slice(0,10).replace(/-/g,'')}
        </div>
      </nav>
    </>
  )
}
