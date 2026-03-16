import { createContext, useContext, useState, useEffect } from 'react'
import axios from 'axios'

const ModeContext = createContext()

export function ModeProvider({ children }) {
  const [mode, setMode] = useState(
    () => localStorage.getItem('sentinel_mode') || 'cloud'
  )
  const [localServerOnline, setLocalServerOnline] = useState(false)
  const [checking, setChecking] = useState(false)

  // Check if local server is reachable
  async function checkLocalServer() {
    setChecking(true)
    try {
      await axios.get('http://localhost:8001/local/health', { timeout: 2000 })
      setLocalServerOnline(true)
      return true
    } catch {
      setLocalServerOnline(false)
      return false
    } finally {
      setChecking(false)
    }
  }

  // Poll local server status every 5s when in local mode
  useEffect(() => {
    if (mode !== 'local') return
    checkLocalServer()
    const t = setInterval(checkLocalServer, 5000)
    return () => clearInterval(t)
  }, [mode])

  async function enableLocalMode() {
    const online = await checkLocalServer()
    if (!online) {
      return {
        success: false,
        error: 'Local server not running. Start it with: python local_server.py'
      }
    }
    setMode('local')
    localStorage.setItem('sentinel_mode', 'local')
    return { success: true }
  }

  function enableCloudMode() {
    setMode('cloud')
    localStorage.setItem('sentinel_mode', 'cloud')
  }

  return (
    <ModeContext.Provider value={{
      mode, localServerOnline, checking,
      enableLocalMode, enableCloudMode, checkLocalServer
    }}>
      {children}
    </ModeContext.Provider>
  )
}

export const useMode = () => useContext(ModeContext)
