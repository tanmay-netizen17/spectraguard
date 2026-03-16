import React from 'react'
import { SectionHeader } from './SectionHeader'

export default function ThreatBrief({ incident }) {
  if (!incident) return null

  // Find GPT explanation or fallback
  const expl = incident.evidence?.nlp?.explanation
            || incident.evidence?.aigen?.explanation
            || incident.evidence?.url?.explanation
            || incident.threat_brief
            || "System detected anomalous patterns consistent with known threat vectors."

  return (
    <div className="card" style={{ padding: 24, display: 'flex', flexDirection: 'column' }}>
      <SectionHeader number="01" title="Threat Brief" subtitle="AI-Generated Context" />
      
      <div style={{ flex: 1 }}>
        <p style={{
          fontSize: 15, lineHeight: 1.7, color: 'var(--text-secondary)',
          margin: 0, fontFamily: 'var(--font-body)',
        }}>
          {expl}
        </p>

        {incident.mitre_label && (
          <div style={{ marginTop: 24, padding: '16px', background: 'var(--bg-primary)', borderRadius: 8, border: '1px solid var(--border)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600, letterSpacing: '0.04em' }}>MITRE ATT&CK CLASSIFICATION</div>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: 'var(--accent-dim)', color: 'var(--accent-hover)', padding: '6px 12px', borderRadius: 6, border: '1px solid var(--accent)20' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 600 }}>{incident.mitre_label}</span>
            </div>
            {incident.primary_threat && (
              <div style={{ marginTop: 8, fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>
                {incident.primary_threat}
              </div>
            )}
          </div>
        )}
      </div>

      <div style={{
        marginTop: 24, paddingTop: 16, borderTop: '1px solid var(--border)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)'
      }}>
        <span>ID: {incident.incident_id}</span>
        <span>Source: {incident.ingestion_source}</span>
      </div>
    </div>
  )
}
