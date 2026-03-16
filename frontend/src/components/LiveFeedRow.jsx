import React from 'react'
import { SeverityBadge } from './SeverityBadge'
import { ThreatIcon } from './ThreatIcon'

// Extract simple threat parsing for icon mapping
function getThreatType(mitre, primary) {
  const text = (mitre || primary || '').toLowerCase()
  if (text.includes('phishing') || text.includes('t1566')) return 'phishing'
  if (text.includes('url') || text.includes('domain')) return 'url'
  if (text.includes('deepfake') || text.includes('media')) return 'deepfake'
  if (text.includes('injection') || text.includes('code')) return 'injection'
  if (text.includes('ai') || text.includes('gen')) return 'aigen'
  if (text.includes('anomaly')) return 'anomaly'
  return 'phishing'
}

export default function LiveFeedRow({ incident, index, onClick }) {
  const threatType = getThreatType(incident.mitre_label, incident.primary_threat)
  
  // Severity text color
  const colorVar = incident.severity === 'Critical' ? 'var(--critical)' :
                   incident.severity === 'Likely Malicious' ? 'var(--likely)' :
                   incident.severity === 'Suspicious' ? 'var(--suspicious)' :
                   'var(--clean)'

  return (
    <div 
      className="feed-item-new"
      onClick={() => onClick && onClick(incident)}
      style={{
        display: 'flex', alignItems: 'center', gap: 16,
        padding: '16px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-surface)',
        cursor: onClick ? 'pointer' : 'default',
        transition: 'background 0.15s',
        animationDelay: `${index * 50}ms`,
      }}
      onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-overlay)'}
      onMouseLeave={e => e.currentTarget.style.background = 'var(--bg-surface)'}
    >
      {/* Icon + Score block */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, width: 90, flexShrink: 0 }}>
        <div style={{ color: colorVar, display: 'flex' }}>
          <ThreatIcon type={threatType} size={18} />
        </div>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 18, fontWeight: 600,
          color: colorVar,
        }}>
          {incident.sentinel_score}
        </div>
      </div>

      {/* Main body */}
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <SeverityBadge severity={incident.severity} />
          <span style={{ 
            fontFamily: 'var(--font-body)', fontSize: 14, fontWeight: 500,
            color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' 
          }}>
            {incident.primary_threat || 'Threat Detected'}
          </span>
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-secondary)' }}>
          <span className="mono" style={{ color: 'var(--text-muted)' }}>{incident.incident_id}</span>
          <span style={{ color: 'var(--border)' }}>|</span>
          <span>{incident.ingestion_source}</span>
          {incident.mitre_label && (
            <>
              <span style={{ color: 'var(--border)' }}>|</span>
              <span style={{ 
                fontFamily: 'var(--font-mono)', fontSize: 11,
                background: 'var(--bg-sunken)', padding: '2px 6px', borderRadius: 4,
              }}>
                {incident.mitre_label}
              </span>
            </>
          )}
        </div>
      </div>

      {/* Right meta */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexShrink: 0 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>
          {incident.timestamp ? new Date(incident.timestamp).toLocaleTimeString() : ''}
        </span>
        {onClick && (
          <svg style={{ color: 'var(--text-muted)' }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="9 18 15 12 9 6"></polyline>
          </svg>
        )}
      </div>
    </div>
  )
}
