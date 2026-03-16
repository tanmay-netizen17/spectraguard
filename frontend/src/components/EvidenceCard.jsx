import React, { useState } from 'react'

const DET_LABELS = {
  nlp: 'NLP Phishing / Injection',
  url: 'Malicious URL',
  deepfake: 'Deepfake Media',
  anomaly: 'Behaviour Anomaly',
  aigen: 'AI-Generated Content',
}

export default function EvidenceCard({ evidence = {}, detectors_triggered = [] }) {
  const [open, setOpen] = useState(null)

  if (!Object.keys(evidence).length) {
    return <p style={{ color: '#94A3B8', fontSize: 13 }}>No detector evidence available.</p>
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {Object.entries(evidence).map(([det, data]) => {
        const isOpen = open === det
        const score = data.score || 0
        const pct = Math.round(score * 100)
        const color = pct > 70 ? '#EF4444' : pct > 40 ? '#F97316' : '#F59E0B'

        return (
          <div key={det} className="card" style={{ overflow: 'hidden' }}>
            <button
              onClick={() => setOpen(isOpen ? null : det)}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 12,
                padding: '12px 16px', background: 'none', border: 'none',
                cursor: 'pointer', textAlign: 'left',
              }}
            >
              <div style={{
                width: 40, height: 40, borderRadius: 8, background: color + '18',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 14, fontWeight: 700, color, fontFamily: 'IBM Plex Mono',
                flexShrink: 0,
              }}>
                {pct}%
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 13, color: '#0F172A' }}>
                  {DET_LABELS[det] || det}
                </div>
                <div style={{ marginTop: 4, background: '#F1F5F9', borderRadius: 4, height: 4, overflow: 'hidden' }}>
                  <div style={{
                    width: `${pct}%`, height: '100%', background: color,
                    transition: 'width 0.8s ease', borderRadius: 4,
                  }} />
                </div>
              </div>
              <span style={{ color: '#9CA3AF', fontSize: 16 }}>{isOpen ? '▲' : '▼'}</span>
            </button>

            {isOpen && (
              <div style={{
                padding: '0 16px 14px', borderTop: '1px solid #F3F4F6',
                animation: 'fadeScaleIn 0.2s ease',
              }}>
                {/* Explanation */}
                {data.explanation && (
                  <p style={{ fontSize: 13, color: '#374151', margin: '10px 0 8px' }}>
                    {data.explanation}
                  </p>
                )}

                {/* NLP: top tokens */}
                {det === 'nlp' && data.top_tokens?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 11, color: '#9CA3AF', marginBottom: 4 }}>TOP TRIGGER TOKENS</div>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {data.top_tokens.map(t => (
                        <span key={t} style={{
                          padding: '2px 8px', borderRadius: 4,
                          background: '#FEF2F2', color: '#EF4444',
                          fontSize: 12, fontFamily: 'IBM Plex Mono',
                        }}>{t}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* URL: SHAP values */}
                {det === 'url' && data.shap_values?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 11, color: '#9CA3AF', margin: '8px 0 4px' }}>SHAP FEATURE IMPORTANCE</div>
                    {data.shap_values.slice(0, 6).map(s => (
                      <div key={s.feature} style={{
                        display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4,
                      }}>
                        <div style={{ width: 140, fontSize: 11, fontFamily: 'IBM Plex Mono', color: '#374151' }}>
                          {s.feature}
                        </div>
                        <div style={{ flex: 1, height: 6, background: '#F1F5F9', borderRadius: 3, overflow: 'hidden' }}>
                          <div style={{
                            width: `${Math.min(100, Math.abs(s.shap_value) * 200)}%`,
                            height: '100%',
                            background: s.shap_value > 0 ? '#EF4444' : '#10B981',
                            borderRadius: 3,
                          }} />
                        </div>
                        <div style={{ fontSize: 11, fontFamily: 'IBM Plex Mono', color: '#6B7280', width: 48 }}>
                          {s.shap_value > 0 ? '+' : ''}{s.shap_value.toFixed(3)}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Anomaly: deviations */}
                {det === 'anomaly' && data.deviation_map && (
                  <div>
                    <div style={{ fontSize: 11, color: '#9CA3AF', margin: '8px 0 4px' }}>FEATURE DEVIATIONS</div>
                    {Object.entries(data.deviation_map).slice(0, 5).map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', gap: 8, marginBottom: 3, fontSize: 12 }}>
                        <span style={{ fontFamily: 'IBM Plex Mono', color: '#374151', width: 180 }}>{k}</span>
                        <span style={{
                          color: v.is_anomalous ? '#EF4444' : '#10B981',
                          fontFamily: 'IBM Plex Mono',
                        }}>z={v.z_score}</span>
                        <span style={{ color: '#9CA3AF' }}>({v.value} vs μ={v.baseline_mean})</span>
                      </div>
                    ))}
                  </div>
                )}

                {/* Deepfake */}
                {det === 'deepfake' && (
                  <div style={{ fontSize: 12, color: '#6B7280', display: 'flex', gap: 16 }}>
                    <span>Spatial: {Math.round((data.spatial_score || 0) * 100)}%</span>
                    <span>Temporal: {Math.round((data.temporal_score || 0) * 100)}%</span>
                    <span>Frames: {data.frames_analysed || 1}</span>
                  </div>
                )}

                {/* AI-generated */}
                {det === 'aigen' && data.ai_markers_found?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 11, color: '#9CA3AF', marginBottom: 4 }}>AI TEXT MARKERS</div>
                    {data.ai_markers_found.map(m => (
                      <span key={m} style={{
                        display: 'inline-block', padding: '2px 8px', borderRadius: 4,
                        background: '#F0F9FF', color: '#0369A1',
                        fontSize: 12, margin: '0 4px 4px 0', fontFamily: 'IBM Plex Mono',
                      }}>{m}</span>
                    ))}
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
