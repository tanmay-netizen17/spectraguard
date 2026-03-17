import React, { useContext } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { ThemeContext } from '../App'
import { useLiveFeed } from '../hooks/useLiveFeed'

// Shield SVG logo
function ShieldLogo({ size = 28 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" fill="none">
      <path d="M14 2L4 6.5V13.5C4 19.2 8.4 24.6 14 26C19.6 24.6 24 19.2 24 13.5V6.5L14 2Z"
        fill="var(--accent)" fillOpacity="0.15" stroke="var(--accent)" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M10 14l3 3 5-5" stroke="var(--accent)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function ConnectionStatus() {
  const { status } = useLiveFeed()
  const config = {
    connected:    { dot: '#12B76A', label: 'Connected'   },
    connecting:   { dot: '#F79009', label: 'Connecting…' },
    disconnected: { dot: '#F04438', label: 'Disconnected' },
  }[status] || { dot: '#9CA3AF', label: 'Unknown' }

  return (
    <div style={{ display:'flex', alignItems:'center', gap:6, fontSize:13,
                  color:'var(--text-secondary)' }}>
      <span style={{
        width:8, height:8, borderRadius:'50%',
        background: config.dot,
        boxShadow: status === 'connected'
          ? `0 0 0 2px ${config.dot}33`
          : 'none',
        display:'inline-block'
      }}/>
      {config.label}
    </div>
  )
}

export default function Topbar({ onHamburgerClick, isMobile }) {
  const { stats } = useContext(ThemeContext)
  
  return (
    <header style={{
      position:   'fixed', top: 0, left: 0, right: 0,
      height:     60,
      background: '#fff',
      borderBottom: '1px solid #E5E7EB',
      zIndex:     1000,
      display:    'flex',
      alignItems: 'center',
      padding:    '0 20px',
      gap:        12,
    }}>
      {/* Hamburger — mobile only */}
      {isMobile && (
        <button
          onClick={onHamburgerClick}
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            padding: '4px', display: 'flex', flexDirection: 'column',
            gap: 4, flexShrink: 0,
          }}
          aria-label="Open menu"
        >
          {[0,1,2].map(i => (
            <span key={i} style={{
              display: 'block', width: 20, height: 2,
              background: '#374151', borderRadius: 1,
            }}/>
          ))}
        </button>
      )}

      {/* Logo — always visible */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0,
      }}>
        <ShieldLogo size={22} />
        {!isMobile && (
          <span style={{
            fontFamily: 'var(--font-display, Syne, sans-serif)',
            fontWeight: 700, fontSize: 16, color: '#0D1117',
          }}>
            SpectraGuard
          </span>
        )}
      </div>

      {/* Right side — always visible but compact on mobile */}
      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: isMobile ? 8 : 12 }}>
        <ConnectionStatus />
        {stats.critical > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{
               width: 8, height: 8, borderRadius: '50%', background: 'var(--critical)',
               animation: 'pulse-critical 1.5s infinite'
            }} />
            {!isMobile && (
              <span style={{ fontSize: 13, color: 'var(--critical)', fontWeight: 600 }}>
                {stats.critical} active threats
              </span>
            )}
          </div>
        )}
      </div>
    </header>
  )
}
