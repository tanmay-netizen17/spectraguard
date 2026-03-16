import { useState, useEffect } from 'react'

const SEVERITY_STYLE = {
  Critical:         { bg:'#FEF3F2', border:'#FECDCA', text:'#B42318', icon:'🚨' },
  'Likely Malicious':{ bg:'#FFF4ED', border:'#FDDCAB', text:'#B93815', icon:'⚠️' },
  Suspicious:       { bg:'#FFFAEB', border:'#FEF0C7', text:'#B54708', icon:'🔍' },
}

export default function AlertToast() {
  const [alerts, setAlerts] = useState([])

  // Expose addAlert globally so useAlerts hook can call it
  useEffect(() => {
    window.__sentinelAddAlert = (alert) => {
      setAlerts(prev => [{ ...alert, _id: Date.now() }, ...prev].slice(0, 5))
      // Auto-dismiss non-critical after 8 seconds
      if (alert.severity !== 'Critical') {
        setTimeout(() => {
          setAlerts(prev => prev.filter(a => a._id !== Date.now()))
        }, 8000)
      }
    }
  }, [])

  function dismiss(id) {
    setAlerts(prev => prev.filter(a => a._id !== id))
  }

  if (alerts.length === 0) return null

  return (
    <div style={{
      position: 'fixed',
      top: 80, right: 20,
      zIndex: 9999,
      display: 'flex',
      flexDirection: 'column',
      gap: 10,
      maxWidth: 380,
    }}>
      {alerts.map(alert => {
        const style = SEVERITY_STYLE[alert.severity] || SEVERITY_STYLE['Suspicious']
        return (
          <div key={alert._id} style={{
            background:   style.bg,
            border:       `1px solid ${style.border}`,
            borderLeft:   `4px solid ${style.text}`,
            borderRadius: 10,
            padding:      '14px 16px',
            boxShadow:    '0 4px 16px rgba(0,0,0,0.12)',
            animation:    'toastIn 0.3s ease-out',
          }}>
            {/* Header */}
            <div style={{ display:'flex', justifyContent:'space-between',
                          alignItems:'flex-start', marginBottom:6 }}>
              <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                <span style={{ fontSize:16 }}>{style.icon}</span>
                <span style={{ fontSize:14, fontWeight:700, color: style.text }}>
                  {alert.severity} — Score {alert.score}/100
                </span>
              </div>
              <button onClick={() => dismiss(alert._id)}
                style={{ background:'none', border:'none', cursor:'pointer',
                         color: style.text, fontSize:18, lineHeight:1, padding:0 }}>
                ×
              </button>
            </div>

            {/* Details */}
            <div style={{ fontSize:12, color:'#374151', lineHeight:1.5 }}>
              {alert.from && (
                <div style={{ marginBottom:2 }}>
                  <span style={{ color:'#6B7280' }}>From: </span>
                  <span style={{ fontFamily:'var(--font-mono, monospace)', fontSize:11 }}>
                    {alert.from.slice(0, 55)}
                  </span>
                </div>
              )}
              {alert.subject && (
                <div>
                  <span style={{ color:'#6B7280' }}>Subject: </span>
                  {alert.subject.slice(0, 70)}
                </div>
              )}
            </div>

            {/* Action buttons */}
            <div style={{ marginTop:10, display:'flex', gap:8 }}>
              <a href={`/incidents/${alert.incident_id}`}
                style={{
                  fontSize:12, fontWeight:600,
                  color: style.text,
                  textDecoration:'none',
                  background: style.border,
                  padding:'4px 12px', borderRadius:6,
                }}>
                View incident →
              </a>
              <button onClick={() => dismiss(alert._id)}
                style={{ fontSize:12, color:'#6B7280', background:'none',
                         border:'none', cursor:'pointer', padding:'4px 8px' }}>
                Dismiss
              </button>
            </div>
          </div>
        )
      })}
    </div>
  )
}
