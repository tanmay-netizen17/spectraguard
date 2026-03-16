import React from 'react'
import MitreTag from './MitreTag'

export default function ThreatBrief({ incident }) {
  if (!incident) return null
  const { threat_brief, mitre_tactic, mitre_label, mitre_phase, coordination_multiplier, context_modifiers } = incident

  return (
    <div className="card" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: '#9CA3AF', letterSpacing: '0.08em' }}>
        AI THREAT BRIEF
      </div>

      <p style={{
        fontSize: 14, color: '#1E293B', lineHeight: 1.7,
        borderLeft: '3px solid #6366F1', paddingLeft: 12, margin: 0,
      }}>
        {threat_brief || 'Analysis complete. No summary generated.'}
      </p>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <MitreTag tactic_id={mitre_tactic} mitre_label={mitre_label} mitre_phase={mitre_phase} />

        {coordination_multiplier > 1 && (
          <span style={{
            padding: '4px 10px', borderRadius: 6,
            background: '#FFF7ED', border: '1px solid #FED7AA',
            color: '#C2410C', fontSize: 11, fontWeight: 600,
          }}>
            ⚡ Coordination ×{coordination_multiplier}
          </span>
        )}
      </div>

      {context_modifiers?.length > 0 && (
        <div>
          <div style={{ fontSize: 11, color: '#9CA3AF', marginBottom: 6 }}>CONTEXT SIGNALS ACTIVE</div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {context_modifiers.map(m => (
              <span key={m} style={{
                padding: '2px 8px', borderRadius: 4,
                background: '#FEF2F2', color: '#9B1C1C',
                fontSize: 11, fontFamily: 'IBM Plex Mono',
              }}>{m.replace(/_/g, ' ')}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
