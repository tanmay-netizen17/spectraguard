import { useEffect, useRef } from 'react'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export function useAlerts({ onAlert }) {
  const esRef = useRef(null)

  useEffect(() => {
    // Request browser notification permission on mount
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission()
    }

    function connect() {
      const es = new EventSource(`${API}/alerts/stream`)
      esRef.current = es

      es.onmessage = (e) => {
        const data = JSON.parse(e.data)
        if (data.type === 'ping' || data.type === 'connected') return

        // Trigger in-app toast
        if (onAlert) onAlert(data)

        // Trigger OS browser notification (works even in background tab)
        if ('Notification' in window && Notification.permission === 'granted') {
          const severity = data.severity || 'Threat'
          const score    = data.score || 0
          const notif    = new Notification(`🚨 SpectraGuard — ${severity} Detected`, {
            body: [
              `Score: ${score}/100`,
              data.from    ? `From: ${data.from.slice(0, 60)}`    : '',
              data.subject ? `Subject: ${data.subject.slice(0, 80)}` : '',
            ].filter(Boolean).join('\n'),
            icon:  '/sentinel-icon.png',   // add a 64x64 shield icon to /public/
            tag:   `sentinel-${data.id}`,  // prevents duplicate notifications
            requireInteraction: score >= 81,  // critical alerts stay until dismissed
          })

          // Click notification → focus the app tab
          notif.onclick = () => {
            window.focus()
            if (data.incident_id) {
              window.location.href = `/incidents/${data.incident_id}`
            }
          }
        }
      }

      es.onerror = () => {
        es.close()
        setTimeout(connect, 5000)   // reconnect
      }
    }

    connect()
    return () => esRef.current?.close()
  }, [])
}
