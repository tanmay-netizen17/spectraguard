import React, { useState, useEffect } from 'react'
import { Routes, Route, useNavigate } from 'react-router-dom'
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

function AppInner() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [isMobile,    setIsMobile]    = useState(window.innerWidth < 768)
  const navigate = useNavigate()

  useEffect(() => {
    function handleResize() {
      const mobile = window.innerWidth < 768
      setIsMobile(mobile)
      if (!mobile) setSidebarOpen(false)
    }
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])

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

  return (
    <ThemeContext.Provider value={{ incidents, stats, wsConnected, addIncident, surgeAlert, localMode }}>
      <Topbar
        onHamburgerClick={() => setSidebarOpen(true)}
        isMobile={isMobile}
      />
      <Sidebar
        mobileOpen={sidebarOpen || !isMobile}
        onClose={() => setSidebarOpen(false)}
      />
      <main style={{
        marginLeft:  isMobile ? 0    : 220,
        marginTop:   60,
        padding:     isMobile ? '16px 12px' : '24px 32px',
        minHeight:   'calc(100vh - 60px)',
        transition:  'margin-left 0.28s cubic-bezier(0.4, 0, 0.2, 1)',
        overflowX:   'hidden',
      }}>
        <Routes>
          <Route path="/"              element={<Dashboard onNavigate={navigate} />} />
          <Route path="/scan"          element={<ScanPage />} />
          <Route path="/incidents"     element={<IncidentLog />} />
          <Route path="/red-team"      element={<RedTeam />} />
          <Route path="/settings"      element={<Settings />} />
        </Routes>
      </main>
      <AlertToast />
    </ThemeContext.Provider>
  )
}

export default function App() {
  return (
    <ModeProvider>
      <AppInner />
    </ModeProvider>
  )
}
