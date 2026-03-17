import React, { useContext, useState } from 'react'
import { ThemeContext } from '../App'
import { api } from '../api/spectraApi'
import { SectionHeader } from '../components/SectionHeader'
import { SeverityBadge } from '../components/SeverityBadge'
import { ThreatIcon } from '../components/ThreatIcon'

const SEV_OPTS = ['All', 'Threats (>40)', 'Critical', 'Likely Malicious', 'Suspicious', 'Clean']

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

export default function IncidentLog() {
  const { incidents } = useContext(ThemeContext)
  const [severity, setSeverity] = useState('Threats (>40)')
  const [search, setSearch] = useState('')

  const filtered = incidents.filter(inc => {
    if (severity === 'Threats (>40)' && inc.sentinel_score < 40) return false
    if (severity !== 'All' && severity !== 'Threats (>40)' && inc.severity !== severity) return false
    if (search && !JSON.stringify({...inc, evidence: undefined}).toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const handleFalsePositive = async (id, e) => {
    e.stopPropagation()
    try { await api.feedback(id, 'false_positive', 0) } catch {}
  }

  return (
    <div className="page-enter">
      <div style={{ marginBottom: 32, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <SectionHeader number="03" title="Incident Log" subtitle="Historical threat data across all vectors." />
        
        <button className="btn-secondary" style={{ marginBottom: 32 }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
          Export CSV
        </button>
      </div>

      {/* Filters */}
      <div className="card" style={{ padding: 16, marginBottom: 24, display: 'flex', gap: 16, alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: 1, maxWidth: 360 }}>
          <svg style={{ position: 'absolute', left: 12, top: 10, color: 'var(--text-muted)' }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
          <input
            placeholder="Search incident ID, IP, or threat…"
            value={search} onChange={e => setSearch(e.target.value)}
            style={{
              width: '100%', padding: '8px 12px 8px 36px', border: '1px solid var(--border)',
              borderRadius: 6, fontSize: 13, outline: 'none', background: 'var(--bg-sunken)',
              fontFamily: 'var(--font-body)'
            }}
          />
        </div>
        
        <div style={{ width: 1, height: 24, background: 'var(--border)' }} />

        <div style={{ display: 'flex', gap: 6 }}>
          {SEV_OPTS.map(s => (
            <button key={s} onClick={() => setSeverity(s)} style={{
              padding: '6px 12px', border: '1px solid',
              borderRadius: 20, cursor: 'pointer', fontSize: 12, fontWeight: 500, fontFamily: 'var(--font-body)',
              background: severity === s ? 'var(--text-primary)' : 'transparent',
              borderColor: severity === s ? 'var(--text-primary)' : 'var(--border-strong)',
              color: severity === s ? 'var(--text-inverse)' : 'var(--text-secondary)',
              transition: 'all 0.15s',
            }}>{s}</button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
          <thead>
            <tr style={{ background: 'var(--bg-sunken)', borderBottom: '1px solid var(--border)' }}>
              {['#', 'Time', 'Severity', 'Score', 'Threat Type', 'Source', ''].map(h => (
                <th key={h} style={{
                  padding: '12px 20px', fontSize: 11, color: 'var(--text-muted)',
                  fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
                No incidents match current filters.
              </td></tr>
            ) : filtered.slice(0, 100).map((inc, i) => {
              const tt = getThreatType(inc.mitre_label, inc.primary_threat)
              const isCrit = inc.severity === 'Critical'
              return (
                <tr key={inc.incident_id || i} style={{
                  borderBottom: '1px solid var(--border)',
                  background: 'var(--bg-surface)', transition: 'background 0.15s',
                  cursor: 'pointer',
                  animation: `slideInRight 0.25s ease ${i * 0.02}s both`,
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-overlay)'}
                onMouseLeave={e => e.currentTarget.style.background = 'var(--bg-surface)'}
                >
                  <td style={{ padding: '16px 20px', width: 60 }}>
                    <span style={{ 
                      fontFamily: 'var(--font-display)', fontSize: 24, fontWeight: 700, 
                      color: 'var(--text-muted)', opacity: 0.3 
                    }}>
                      {(i + 1).toString().padStart(2, '0')}
                    </span>
                  </td>
                  
                  <td style={{ padding: '16px 20px', fontSize: 13, color: 'var(--text-secondary)' }}>
                    {inc.timestamp ? new Date(inc.timestamp).toLocaleString(undefined, {
                       month: 'short', day: 'numeric', hour: '2-digit', minute:'2-digit', second:'2-digit'
                    }) : '—'}
                  </td>
                  
                  <td style={{ padding: '16px 20px' }}>
                    <SeverityBadge severity={inc.severity} />
                  </td>
                  
                  <td style={{ padding: '16px 20px', fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 600, color: isCrit ? 'var(--critical)' : 'var(--text-primary)' }}>
                    {inc.sentinel_score}
                  </td>
                  
                  <td style={{ padding: '16px 20px' }}>
                     <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                       <span style={{ color: 'var(--text-muted)' }}><ThreatIcon type={tt} size={14} /></span>
                       <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>{tt.charAt(0).toUpperCase() + tt.slice(1)}</span>
                       {inc.mitre_label && (
                         <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, background: 'var(--bg-sunken)', padding: '2px 4px', borderRadius: 4, color: 'var(--text-secondary)' }}>
                           {inc.mitre_label}
                         </span>
                       )}
                     </div>
                  </td>
                  
                  <td style={{ padding: '16px 20px', fontSize: 13, color: 'var(--text-secondary)' }}>
                    {inc.ingestion_source}
                  </td>
                  
                  <td style={{ padding: '16px 20px', textAlign: 'right' }}>
                    <button onClick={(e) => handleFalsePositive(inc.incident_id, e)} style={{
                      padding: '4px 8px', background: 'transparent', border: '1px solid var(--border-strong)',
                      borderRadius: 4, cursor: 'pointer', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)',
                      transition: 'all 0.15s'
                    }}
                    onMouseEnter={e => { e.currentTarget.style.color='var(--text-primary)'; e.currentTarget.style.borderColor='var(--text-muted)' }}
                    onMouseLeave={e => { e.currentTarget.style.color='var(--text-secondary)'; e.currentTarget.style.borderColor='var(--border-strong)' }}
                    >FP</button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
