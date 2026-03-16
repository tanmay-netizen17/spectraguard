import React from 'react'
import { SectionHeader } from './SectionHeader'

export default function ActionPanel({ recommended_action, severity, onFalsePositive }) {
  const isCritical = severity === 'Critical' || severity === 'Likely Malicious'
  
  return (
    <div className="card" style={{ 
      padding: '24px', 
      borderLeft: isCritical ? '3px solid var(--critical)' : '3px solid var(--clean)',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ flex: 1, paddingRight: 40 }}>
          <SectionHeader number="03" title="Recommended Action" />
          <p style={{
            fontSize: 16, color: 'var(--text-primary)', fontWeight: 500, lineHeight: 1.6,
            margin: '0 0 24px', fontFamily: 'var(--font-body)'
          }}>
            {recommended_action || "Investigate the event logs for further context. No immediate blocking action required."}
          </p>

          <div style={{ display: 'flex', gap: 12 }}>
            {isCritical && (
              <button className="btn-primary" style={{ background: 'var(--critical)' }}>
                <span>Execute Block Action</span>
                <svg className="btn-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M5 12h14M12 5l7 7-7 7"/>
                </svg>
              </button>
            )}
            <button className="btn-secondary" onClick={onFalsePositive}>
              Mark False Positive
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
