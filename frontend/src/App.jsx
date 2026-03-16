import React, { useState } from 'react'
import { ModeProvider, useMode } from './context/ModeContext'
import { useLiveFeed } from './hooks/useLiveFeed'
import Topbar from './components/Topbar'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import ScanPage from './pages/ScanPage'
import IncidentLog from './pages/IncidentLog'
import RedTeam from './pages/RedTeam'
import Settings from './pages/Settings'
import AlertToast from './components/AlertToast'
import { useAlerts } from './hooks/useAlerts'
import './index.css'

export const ThemeContext = React.createContext({})

function AppContent() {
  const [page, setPage] = useState('dashboard')
  const { incidents, status, stats, surgeAlert, setIncidents, setStats } = useLiveFeed()
  const { mode, localServerOnline } = useMode()
  
  const wsConnected = status === 'connected'
  const localMode = mode === 'local'

  // ── Listen for SSE Alerts ────────────────────────────────────────────────
  useAlerts({
    onAlert: (alert) => {
      window.__sentinelAddAlert?.(alert)
    }
  })

  // ── Top-level incident injected from scan page ─────────────────────────
  const addIncident = (incident) => {
    setIncidents(prev => [incident, ...prev].slice(0, 200))
    setStats(prev => ({
      total:    prev.total + 1,
      critical: prev.critical + (incident.severity === 'Critical' ? 1 : 0),
      blocked:  prev.blocked + (incident.sentinel_score >= 61 ? 1 : 0),
      clean:    prev.clean + (incident.severity === 'Clean' ? 1 : 0),
    }))
  }

  const pages = { 
    dashboard: Dashboard, 
    scan: ScanPage, 
    log: IncidentLog, 
    redteam: RedTeam,
    settings: Settings 
  }
  const ActivePage = pages[page] || Dashboard

  return (
    <ThemeContext.Provider value={{ incidents, stats, wsConnected, addIncident, surgeAlert, localMode }}>
      <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', background: 'var(--bg-primary)' }}>
        <Topbar current={page} onNavigate={setPage} />
        <div style={{ display: 'flex', flex: 1, marginTop: 60 /* Topbar height */ }}>
          <Sidebar current={page} onNavigate={setPage} wsConnected={wsConnected} localMode={localMode} />
          <main style={{ 
            flex: 1, 
            marginLeft: 220, /* Sidebar width */
            padding: '40px 48px', 
            minHeight: 'calc(100vh - 60px)',
          }}>
            <ActivePage onNavigate={setPage} />
          </main>
        </div>
      </div>
      <AlertToast />
    </ThemeContext.Provider>
  )
}

export default function App() {
  return (
    <ModeProvider>
      <AppContent />
    </ModeProvider>
  )
}
