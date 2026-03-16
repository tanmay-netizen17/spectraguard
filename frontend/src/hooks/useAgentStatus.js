import { useState, useEffect } from 'react'
import axios from 'axios'

const CLOUD = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export function useAgentStatus() {
  const [agents, setAgents] = useState({
    browser_extension: 'offline',
    email_daemon:      'offline',
    log_collector:     'offline',
  })

  useEffect(() => {
    async function check() {
      try {
        const res = await axios.get(`${CLOUD}/agents/status`, { timeout: 3000 })
        setAgents(res.data)
      } catch {
        // backend unreachable — keep all offline
      }
    }
    check()
    const t = setInterval(check, 5000)
    return () => clearInterval(t)
  }, [])

  return agents
}
