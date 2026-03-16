import React, { useContext } from 'react'
import { ThemeContext } from '../App'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, AreaChart, Area } from 'recharts'
import ModelHealth from '../components/ModelHealth'
import LiveFeedRow from '../components/LiveFeedRow'
import { SectionHeader } from '../components/SectionHeader'
import { SeverityBadge } from '../components/SeverityBadge'

const SEV_COLORS = {
  Clean: 'var(--clean)', Suspicious: 'var(--suspicious)', 'Likely Malicious': 'var(--likely)', Critical: 'var(--critical)',
}

// Dummy activity data for the sparkline (to match Cyber FZ DNA)
const SPARKLINE_DATA = [
  { time: '00:00', value: 12 }, { time: '04:00', value: 8 }, { time: '08:00', value: 45 },
  { time: '12:00', value: 82 }, { time: '16:00', value: 64 }, { time: '20:00', value: 38 },
  { time: '24:00', value: 24 }
]

function StatCard({ label, mainValue, subLabel, secondaryValue, isCritical }) {
  return (
    <div className="card" style={{ 
      padding: 24, 
      background: isCritical ? 'var(--critical-dim)' : 'var(--bg-surface)',
      border: isCritical ? '1px solid var(--critical)40' : '1px solid var(--border)',
    }}>
      <div style={{ fontSize: 13, color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase', marginBottom: 12 }}>
        {label}
      </div>
      <div className="count-up" style={{ 
        fontFamily: 'var(--font-mono)', fontSize: 48, fontWeight: 600, 
        color: isCritical ? 'var(--critical)' : 'var(--text-primary)',
        lineHeight: 1, marginBottom: 16
      }}>
        {mainValue}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border)', paddingTop: 12 }}>
        <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{subLabel}</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>{secondaryValue}</span>
      </div>
    </div>
  )
}

export default function Dashboard({ onNavigate }) {
  const { incidents, stats, surgeAlert, setSurgeAlert } = useContext(ThemeContext)

  // Distribution data
  const sevCounts = incidents.reduce((acc, inc) => {
    acc[inc.severity] = (acc[inc.severity] || 0) + 1; return acc
  }, {})
  const pieData = Object.entries(sevCounts).map(([k, v]) => ({ name: k, value: v }))

  // Mock trend data logic
  const now = new Date()
  const todayScans = stats.total + 1247
  const criticalToday = stats.critical + 3
  const blockedWeek = stats.blocked + 89
  const avgScore = 23.4

  return (
    <div className="page-enter">
      {/* Hero / Header Section */}
      <div className="geo-bg" style={{ 
        position: 'relative', padding: '40px 0 60px', marginBottom: -20,
        borderBottom: '1px solid var(--border)', margin: '-28px -32px 32px -32px',
        paddingLeft: 32, paddingRight: 32,
      }}>
        <div className="scan-line" style={{ top: 0, left: 0 }} />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <SectionHeader number="00" title="System Overview" subtitle="Real-time analysis and detection platform." />
          <button className="btn-accent" onClick={() => onNavigate('scan')}>
             <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg>
             Analyse Threat
          </button>
        </div>
      </div>

      {/* Surge Alert */}
      {surgeAlert && (
        <div style={{
          margin:       '0 0 20px 0',
          padding:      '14px 20px',
          background:   'linear-gradient(135deg, #FEF2F2 0%, #FFF5F5 100%)',
          border:       '1px solid #FECDCA',
          borderLeft:   '4px solid #F04438',
          borderRadius: 10,
          display:      'flex',
          alignItems:   'center',
          justifyContent: 'space-between',
          animation:    'slideDown 0.4s ease-out',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{
              width: 10, height: 10, borderRadius: '50%',
              background: '#F04438',
              display: 'inline-block',
              animation: 'pulse-critical 1.5s infinite',
              flexShrink: 0,
            }}/>
            <div>
              <span style={{ fontWeight: 700, fontSize: 14, color: '#B42318' }}>
                SURGE DETECTED
              </span>
              <span style={{ fontSize: 14, color: '#7F1D1D', marginLeft: 8 }}>
                {surgeAlert.message || `${stats.critical} critical threats detected recently`}
              </span>
            </div>
          </div>
          <button
            onClick={() => setSurgeAlert(null)}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: '#B42318', fontSize: 18, lineHeight: 1,
              padding: '0 4px', flexShrink: 0,
            }}
          >
            ×
          </button>
        </div>
      )}

      {/* Stats Row */}
      <div className="stats-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 24, marginBottom: 40 }}>
        <StatCard label="Total Scans" mainValue={todayScans.toLocaleString()} subLabel="Today so far" secondaryValue={`↑ ${stats.total} live`} />
        <StatCard label="Critical Threats" mainValue={criticalToday} subLabel="Last 1 hour" secondaryValue={`+${stats.critical}`} isCritical={criticalToday > 0} />
        <StatCard label="Automated Blocks" mainValue={blockedWeek} subLabel="This week" secondaryValue="99.9% success" />
        <StatCard label="Average Score" mainValue={avgScore} subLabel="Network status" secondaryValue="CLEAN" />
      </div>

      {/* Activity Sparkline */}
      <div style={{ marginBottom: 40 }}>
         <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Detection Activity — Last 24 Hours</span>
            <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
         </div>
         <div style={{ height: 120 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={SPARKLINE_DATA} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent)" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="var(--accent)" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <Tooltip 
                  contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-primary)', boxShadow: '0 4px 12px rgba(0,0,0,0.1)' }}
                  itemStyle={{ color: 'var(--accent)', fontWeight: 600 }}
                  labelStyle={{ color: 'var(--text-muted)', marginBottom: 4 }}
                 />
                <Area type="monotone" dataKey="value" stroke="var(--accent)" strokeWidth={2} fillOpacity={1} fill="url(#colorValue)" />
              </AreaChart>
            </ResponsiveContainer>
         </div>
      </div>

      {/* Main 2-Col Split */}
      <div className="dashboard-split" style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: 24 }}>
        
        {/* Left: Feed */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ padding: '24px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span className="pulse-dot" />
              <SectionHeader number="01" title="Live Threat Stream" />
            </div>
            <button className="btn-secondary" onClick={() => onNavigate('log')}>View All →</button>
          </div>
          
          <div style={{ flex: 1, maxHeight: 600, overflowY: 'auto' }}>
            {incidents.length === 0 ? (
              <div style={{ padding: 60, textAlign: 'center', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
                 <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                 <span style={{ fontSize: 15 }}>No incidents in the current memory buffer.</span>
              </div>
            ) : (
              incidents.slice(0, 50).map((inc, i) => (
                <LiveFeedRow key={inc.incident_id || i} incident={inc} index={i} onClick={() => onNavigate('log')} />
              ))
            )}
          </div>
        </div>

        {/* Right: Charts & System Info */}
        <div>
          <ModelHealth />

          <div className="card" style={{ padding: 24, marginBottom: 24 }}>
            <SectionHeader number="02" title="Threat Breakdown" />
            
            {pieData.length === 0 ? (
               <div style={{ height: 180, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>No data to visualise</div>
            ) : (
               <>
                  <div style={{ height: 220, marginBottom: 20 }}>
                     <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                           <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={4} dataKey="value" stroke="none">
                              {pieData.map((entry, index) => (
                                 <Cell key={index} fill={SEV_COLORS[entry.name] || 'var(--text-muted)'} />
                              ))}
                           </Pie>
                           <Tooltip 
                              contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 13, fontFamily: 'var(--font-body)' }}
                           />
                        </PieChart>
                     </ResponsiveContainer>
                  </div>
                  
                  {/* Legend */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                     {pieData.sort((a,b) => b.value - a.value).map(d => (
                        <div key={d.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                           <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                              <div style={{ width: 12, height: 12, borderRadius: 3, background: SEV_COLORS[d.name] || 'var(--text-muted)' }} />
                              <span style={{ fontSize: 14, color: 'var(--text-primary)', fontWeight: 500 }}>{d.name}</span>
                           </div>
                           <span style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--text-muted)' }}>{d.value}</span>
                        </div>
                     ))}
                  </div>
               </>
            )}
          </div>

        </div>
      </div>
    </div>
  )
}
