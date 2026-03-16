import React, { useState } from 'react'

const DET_LABELS = {
  nlp: 'NLP Phishing Analysis',
  url: 'Domain & Lexical Scanner',
  deepfake: 'Media Authenticity Engine',
  anomaly: 'Behavioural Profiler',
  aigen: 'LLM Artifact Detector',
}

export default function EvidenceCard({ evidence = {}, detectors_triggered = [] }) {
  const [open, setOpen] = useState(null)

  if (!Object.keys(evidence).length) {
    return <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No detector evidence available.</p>
  }

  // Pre-expand if only one detector triggered
  React.useEffect(() => {
    const keys = Object.keys(evidence)
    if (keys.length === 1 && open === null) {
      setOpen(keys[0])
    }
  }, [evidence, open])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {Object.entries(evidence).map(([det, data]) => {
        const isOpen = open === det
        const score = data.score || 0
        const pct = Math.round(score * 100)
        
        const colour = pct > 70 ? 'var(--critical)' : 
                       pct > 40 ? 'var(--likely)' : 
                       pct > 20 ? 'var(--suspicious)' : 
                       'var(--clean)'
        const dimColour = pct > 70 ? 'var(--critical-dim)' : 
                          pct > 40 ? 'var(--likely-dim)' : 
                          pct > 20 ? 'var(--suspicious-dim)' : 
                          'var(--clean-dim)'

        return (
          <div key={det} className="card" style={{ 
            overflow: 'hidden', 
            borderLeft: `3px solid ${colour}`,
            borderRadius: '0 8px 8px 0',
          }}>
            <button
              onClick={() => setOpen(isOpen ? null : det)}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 16,
                padding: '16px 20px', background: isOpen ? 'var(--bg-primary)' : 'var(--bg-surface)', 
                border: 'none', cursor: 'pointer', textAlign: 'left',
                transition: 'background 0.15s',
              }}
            >
              {/* Score Box */}
              <div style={{
                width: 48, height: 48, borderRadius: 8, background: dimColour,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 15, fontWeight: 700, color: colour, fontFamily: 'var(--font-mono)',
                flexShrink: 0, border: `1px solid ${colour}20`,
              }}>
                {pct}%
              </div>
              
              {/* Info */}
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>
                  {DET_LABELS[det] || det.toUpperCase()}
                </div>
                {/* Micro progress bar */}
                <div style={{ marginTop: 8, background: 'var(--bg-sunken)', borderRadius: 4, height: 4, overflow: 'hidden', width: '100%', maxWidth: 200 }}>
                  <div style={{
                    width: `${pct}%`, height: '100%', background: colour,
                    transition: 'width 1s cubic-bezier(0.16, 1, 0.3, 1)', borderRadius: 4,
                  }} />
                </div>
              </div>

              {/* Toggle arrow */}
              <div style={{ 
                color: 'var(--text-muted)', 
                transform: `rotate(${isOpen ? 180 : 0}deg)`, 
                transition: 'transform 0.2s ease', 
                display: 'flex', alignItems: 'center' 
              }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
              </div>
            </button>

            {/* Expanded Content */}
            {isOpen && (
              <div style={{
                padding: '0 20px 20px 84px', 
                background: 'var(--bg-primary)',
                animation: 'fadeScaleIn 0.25s ease',
              }}>
                {/* Explanation */}
                {data.explanation && (
                  <p style={{ 
                    fontSize: 13, color: 'var(--text-secondary)', margin: '0 0 16px', lineHeight: 1.6 
                  }}>
                    {data.explanation}
                  </p>
                )}

                {/* NLP Tokens */}
                {det === 'nlp' && data.top_tokens?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600, letterSpacing: '0.04em' }}>ATTENTION TOKENS</div>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {data.top_tokens.map(t => (
                        <span key={t} style={{
                          padding: '3px 10px', borderRadius: 4,
                          background: 'var(--critical-dim)', color: 'var(--critical)',
                          fontSize: 12, fontFamily: 'var(--font-mono)', border: '1px solid var(--critical)20'
                        }}>{t}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* URL SHAP Values */}
                {det === 'url' && data.shap_values?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', margin: '8px 0', fontWeight: 600, letterSpacing: '0.04em' }}>FEATURE CONTRIBUTION</div>
                    <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 12 }}>
                      {data.shap_values.slice(0, 5).map(s => {
                        const isPos = s.shap_value > 0
                        return (
                          <div key={s.feature} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8, '&:lastChild': { marginBottom: 0 } }}>
                            <div style={{ width: 140, fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                              {s.feature}
                            </div>
                            <div style={{ flex: 1, height: 6, background: 'var(--bg-sunken)', borderRadius: 3, overflow: 'hidden' }}>
                              <div style={{
                                width: `${Math.min(100, Math.abs(s.shap_value) * 200)}%`,
                                height: '100%',
                                background: isPos ? 'var(--critical)' : 'var(--clean)',
                                borderRadius: 3,
                              }} />
                            </div>
                            <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: isPos ? 'var(--critical)' : 'var(--clean)', width: 56, textAlign: 'right' }}>
                              {isPos ? '+' : ''}{s.shap_value.toFixed(3)}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {/* AI / Deepfake / Anomaly metrics */}
                {det === 'deepfake' && (
                  <div style={{ display: 'flex', gap: 24, padding: 12, background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8 }}>
                    <div><div style={{ fontSize:10, color:'var(--text-muted)' }}>SPATIAL</div><div className="mono" style={{ fontSize:16, color:'var(--text-primary)'}}>{Math.round((data.spatial_score||0)*100)}%</div></div>
                    <div><div style={{ fontSize:10, color:'var(--text-muted)' }}>TEMPORAL</div><div className="mono" style={{ fontSize:16, color:'var(--text-primary)'}}>{Math.round((data.temporal_score||0)*100)}%</div></div>
                    <div><div style={{ fontSize:10, color:'var(--text-muted)' }}>FRAMES</div><div className="mono" style={{ fontSize:16, color:'var(--text-primary)'}}>{data.frames_analysed||1}</div></div>
                  </div>
                )}

                {det === 'aigen' && data.ai_markers_found?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600, letterSpacing: '0.04em' }}>SIGNATURE MARKERS</div>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {data.ai_markers_found.map(m => (
                        <span key={m} style={{
                          padding: '3px 10px', borderRadius: 4,
                          background: 'var(--accent-dim)', color: 'var(--accent-hover)', border: '1px solid var(--accent)20',
                          fontSize: 12, fontFamily: 'var(--font-mono)',
                        }}>{m}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
