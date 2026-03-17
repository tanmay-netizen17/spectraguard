import React, { useState } from 'react'
import { Routes, Route, useNavigate, BrowserRouter, NavLink } from 'react-router-dom'
import { ModeProvider, useMode } from './context/ModeContext'
import { useLiveFeed } from './hooks/useLiveFeed'
import Dashboard from './pages/Dashboard'
import ScanPage from './pages/ScanPage'
import IncidentLog from './pages/IncidentLog'
import RedTeam from './pages/RedTeam'
import Settings from './pages/Settings'
import AlertToast from './components/AlertToast'
import { useAlerts } from './hooks/useAlerts'
import SpectraLogo from './components/SpectraLogo'
import './index.css'

// ── SVG Nav Icons ─────────────────────────────────────────────────────────────
const GridIcon      = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink:0 }}>
    <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
    <rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
  </svg>
)
const SearchIcon    = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink:0 }}>
    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
  </svg>
)
const ShieldIcon    = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink:0 }}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
)
const CrosshairIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink:0 }}>
    <circle cx="12" cy="12" r="10"/>
    <line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/>
    <line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/>
  </svg>
)
const SlidersIcon   = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink:0 }}>
    <line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/>
    <line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/>
    <line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/>
    <line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/>
    <line x1="17" y1="16" x2="23" y2="16"/>
  </svg>
)

const NAV_ITEMS = [
  { path:'/',          label:'Overview',  Icon: GridIcon },
  { path:'/scan',      label:'Scan',      Icon: SearchIcon },
  { path:'/incidents', label:'Incidents', Icon: ShieldIcon },
  { path:'/red-team',  label:'Red Team',  Icon: CrosshairIcon },
  { path:'/settings',  label:'Settings',  Icon: SlidersIcon },
]

export const ThemeContext = React.createContext({})

function AgentStatusPanel({ wsConnected }) {
  return (
    <div style={{ margin:'0 12px 12px', padding:'12px', background:'#F8F9FA', borderRadius:8, border:'1px solid #E5E7EB' }}>
      <div style={{ fontSize:10, fontWeight:600, color:'#9CA3AF', marginBottom:8, textTransform:'uppercase', letterSpacing:'0.05em' }}>Agent Status</div>
      <div style={{ display:'flex', alignItems:'center', gap:6 }}>
        <div style={{ width:6, height:6, borderRadius:'50%', background: wsConnected ? '#12B76A' : '#6B7280', flexShrink:0 }} />
        <span style={{ fontSize:11, color:'#6B7280' }}>Live Feed</span>
      </div>
    </div>
  )
}

function AppInner() {
  const [expanded, setExpanded] = useState(false)
  const SIDEBAR_W  = expanded ? 220 : 64
  const TRANSITION = 'width 0.22s cubic-bezier(0.4,0,0.2,1)'
  const navigate   = useNavigate()

  const { incidents, status, stats, surgeAlert, setIncidents, setStats } = useLiveFeed()
  const { mode } = useMode()

  const wsConnected = status === 'connected'
  const localMode   = mode === 'local'

  useAlerts({ onAlert: (alert) => { window.__spectraAddAlert?.(alert) } })

  const addIncident = (incident) => {
    setIncidents(prev => [incident, ...prev].slice(0, 200))
    setStats(prev => ({
      total:    prev.total + 1,
      critical: prev.critical + (incident.severity === 'Critical' ? 1 : 0),
      blocked:  prev.blocked + (incident.sentinel_score >= 61 ? 1 : 0),
      clean:    prev.clean + (incident.severity === 'Clean' ? 1 : 0),
    }))
  }

  return (
    <ThemeContext.Provider value={{ incidents, stats, wsConnected, addIncident, surgeAlert, localMode }}>
      <div style={{ display:'flex', minHeight:'100vh', background:'#F8F9FA' }}>

        {/* ── SIDEBAR ─────────────────────────────────────── */}
        <aside
          onMouseEnter={() => setExpanded(true)}
          onMouseLeave={() => setExpanded(false)}
          style={{
            width:         SIDEBAR_W,
            minWidth:      SIDEBAR_W,
            flexShrink:    0,
            height:        '100vh',
            position:      'sticky',
            top:           0,
            background:    '#fff',
            borderRight:   '1px solid #E5E7EB',
            display:       'flex',
            flexDirection: 'column',
            overflow:      'hidden',
            transition:    TRANSITION,
            zIndex:        100,
          }}
        >
          {/* Logo row */}
          <div style={{
            height:       60,
            display:      'flex',
            alignItems:   'center',
            gap:          10,
            padding:      '0 20px',
            borderBottom: '1px solid #F0F0F0',
            flexShrink:   0,
            overflow:     'hidden',
            whiteSpace:   'nowrap',
          }}>
            <SpectraLogo size={24} />
            <span style={{
              fontFamily: 'Syne, sans-serif',
              fontWeight: 800,
              fontSize:   16,
              color:      '#0D1117',
              opacity:    expanded ? 1 : 0,
              transition: 'opacity 0.15s ease',
              whiteSpace: 'nowrap',
            }}>
              Spectra<span style={{ color:'#0A84FF' }}>Guard</span>
            </span>
          </div>

          {/* Nav */}
          <nav style={{ flex:1, padding:'12px 8px', overflowY:'auto', overflowX:'hidden' }}>
            {NAV_ITEMS.map(({ path, label, Icon }) => (
              <NavLink key={path} to={path} end={path === '/'} style={{ textDecoration:'none' }}>
                {({ isActive }) => (
                  <div style={{
                    display:       'flex',
                    alignItems:    'center',
                    gap:           12,
                    padding:       '10px 12px',
                    borderRadius:  8,
                    marginBottom:  2,
                    color:         isActive ? '#0A84FF' : '#374151',
                    background:    isActive ? '#E8F2FF' : 'transparent',
                    fontWeight:    isActive ? 600 : 400,
                    fontSize:      14,
                    borderLeft:    isActive ? '3px solid #0A84FF' : '3px solid transparent',
                    transition:    'all 0.15s ease',
                    cursor:        'pointer',
                    whiteSpace:    'nowrap',
                    overflow:      'hidden',
                  }}
                  title={!expanded ? label : ''}
                  >
                    <Icon size={18} />
                    <span style={{
                      opacity:    expanded ? 1 : 0,
                      transition: 'opacity 0.15s ease',
                    }}>
                      {label}
                    </span>
                  </div>
                )}
              </NavLink>
            ))}
          </nav>

          {/* Agent status — only when expanded */}
          <div style={{
            opacity:    expanded ? 1 : 0,
            transition: 'opacity 0.15s ease',
            overflow:   'hidden',
          }}>
            <AgentStatusPanel wsConnected={wsConnected} />
          </div>

          {/* Version */}
          <div style={{
            padding:    '8px 20px 14px',
            fontSize:   10,
            color:      '#9CA3AF',
            fontFamily: 'monospace',
            whiteSpace: 'nowrap',
            opacity:    expanded ? 1 : 0,
            transition: 'opacity 0.15s ease',
          }}>
            SpectraGuard v1.0 · 20260317
          </div>
        </aside>

        {/* ── MAIN AREA ────────────────────────────────────── */}
        <div style={{ flex:1, display:'flex', flexDirection:'column', minWidth:0 }}>
          <main style={{ flex:1, padding:'24px 32px', overflowY:'auto' }}>
            <Routes>
              <Route path="/"          element={<Dashboard onNavigate={navigate} />} />
              <Route path="/scan"      element={<ScanPage />} />
              <Route path="/incidents" element={<IncidentLog />} />
              <Route path="/red-team"  element={<RedTeam />} />
              <Route path="/settings"  element={<Settings />} />
            </Routes>
          </main>
        </div>

        <AlertToast />
      </div>
    </ThemeContext.Provider>
  )
}

export default function App() {
  return (
    <ModeProvider>
      <BrowserRouter>
        <AppInner />
      </BrowserRouter>
    </ModeProvider>
  )
}
