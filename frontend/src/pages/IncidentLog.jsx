import React, { useContext, useState } from 'react'
import { ThemeContext } from '../App'
import { submitFeedback } from '../api/sentinelApi'

const SEV_COLORS = {
  Clean: '#10B981', Suspicious: '#F59E0B', 'Likely Malicious': '#F97316', Critical: '#EF4444',
}

const SEV_OPTS = ['All', 'Critical', 'Likely Malicious', 'Suspicious', 'Clean']

export default function IncidentLog() {
  const { incidents } = useContext(ThemeContext)
  const [severity, setSeverity] = useState('All')
  const [search, setSearch] = useState('')

  const filtered = incidents.filter(inc => {
    if (severity !== 'All' && inc.severity !== severity) return false
    if (search && !JSON.stringify(inc).toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const handleFalsePositive = async (id) => {
    try { await submitFeedback(id, true, 'Marked from SOC log') } catch {}
  }

  return (
    <div>
      <h1 style={{ fontFamily: 'DM Sans', fontSize: 24, fontWeight: 700, color: '#0F172A', marginBottom: 4 }}>
        SOC Incident Log
      </h1>
      <p style={{ color: '#6B7280', fontSize: 14, marginBottom: 20 }}>
        Full incident history with filtering and export.
      </p>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16, alignItems: 'center' }}>
        <input
          placeholder="Search incidents…"
          value={search} onChange={e => setSearch(e.target.value)}
          style={{
            flex: 1, padding: '8px 12px', border: '1px solid #E5E7EB',
            borderRadius: 8, fontSize: 13, outline: 'none', background: '#fff',
          }}
        />
        {SEV_OPTS.map(s => (
          <button key={s} onClick={() => setSeverity(s)} style={{
            padding: '7px 12px', border: '1px solid #E5E7EB',
            borderRadius: 6, cursor: 'pointer', fontSize: 12, fontWeight: 500,
            background: severity === s ? '#0F172A' : '#fff',
            color: severity === s ? '#fff' : '#374151',
            transition: 'all 0.15s',
          }}>{s}</button>
        ))}
      </div>

      {/* Table */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #E5E7EB' }}>
              {['Incident ID', 'Timestamp', 'Severity', 'Score', 'Threat Type', 'Source', 'Actions'].map(h => (
                <th key={h} style={{
                  padding: '10px 14px', fontSize: 11, color: '#9CA3AF',
                  fontWeight: 600, textAlign: 'left', letterSpacing: '0.05em',
                }}>{h.toUpperCase()}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: 32, textAlign: 'center', color: '#9CA3AF', fontSize: 13 }}>
                No incidents match your filters.
              </td></tr>
            ) : filtered.slice(0, 50).map((inc, i) => {
              const color = SEV_COLORS[inc.severity] || '#94A3B8'
              return (
                <tr key={inc.incident_id || i} style={{
                  borderBottom: '1px solid #F3F4F6',
                  animation: `slideInRight 0.3s ease ${i * 0.03}s both`,
                }}>
                  <td style={{ padding: '10px 14px', fontFamily: 'IBM Plex Mono', fontSize: 11, color: '#6B7280' }}>
                    {inc.incident_id || '—'}
                  </td>
                  <td style={{ padding: '10px 14px', fontSize: 12, color: '#6B7280' }}>
                    {inc.timestamp ? new Date(inc.timestamp).toLocaleString() : '—'}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <span style={{
                      padding: '2px 8px', borderRadius: 4,
                      background: color + '18', color, fontSize: 11, fontWeight: 600,
                    }}>{inc.severity}</span>
                  </td>
                  <td style={{ padding: '10px 14px', fontFamily: 'IBM Plex Mono', fontSize: 13, color, fontWeight: 700 }}>
                    {inc.sentinel_score}
                  </td>
                  <td style={{ padding: '10px 14px', fontSize: 12, color: '#374151' }}>
                    {inc.mitre_label || inc.primary_threat || '—'}
                  </td>
                  <td style={{ padding: '10px 14px', fontSize: 11, color: '#9CA3AF' }}>
                    {inc.ingestion_source}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <button onClick={() => handleFalsePositive(inc.incident_id)} style={{
                      padding: '4px 8px', background: 'none', border: '1px solid #E5E7EB',
                      borderRadius: 4, cursor: 'pointer', fontSize: 11, color: '#6B7280',
                    }}>FP</button>
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
