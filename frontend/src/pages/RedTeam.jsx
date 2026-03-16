import React, { useState } from 'react'
import { SectionHeader } from '../components/SectionHeader'
import ModelHealth from '../components/ModelHealth'

export default function RedTeam() {
  const [input, setInput] = useState('')
  const [type, setType] = useState('text')
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState(null)

  const handleTest = () => {
    setRunning(true)
    // mock adversarial test run
    setTimeout(() => {
      setRunning(false)
      setResults({
        baseScore: Math.round(85 + Math.random() * 10),
        resilience: 75,
        attacks: [
          { name: "Homoglyph Substitution", target: "URL", orig: 0.94, new: 0.88, verdict: "robust" },
          { name: "Bypass Prompt Injection", target: "NLP", orig: 0.88, new: 0.41, verdict: "evaded" },
          { name: "Adversarial Noise", target: "Deepfake", orig: 0.91, new: 0.82, verdict: "robust" },
          { name: "Invisible Chars", target: "Text", orig: 0.86, new: 0.81, verdict: "robust" },
        ]
      })
    }, 1500)
  }

  return (
    <div className="page-enter" style={{ maxWidth: 1000, margin: '0 auto' }}>
      <div style={{ marginBottom: 40 }}>
        <SectionHeader number="04" title="Red Team Operations" subtitle="Stress-test the ensemble with automated adversarial mutations." />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 32, marginBottom: 40 }}>
        {/* Left: Input */}
        <div>
          <div className="card" style={{ padding: 24 }}>
            <div style={{ display: 'flex', gap: 4, marginBottom: 16 }}>
              {['URL', 'Text'].map(t => (
                <button key={t} onClick={() => setType(t.toLowerCase())} style={{
                  padding: '6px 16px', background: type === t.toLowerCase() ? 'var(--bg-sunken)' : 'transparent',
                  border: 'none', borderRadius: 6, fontWeight: type === t.toLowerCase() ? 600 : 500,
                  color: type === t.toLowerCase() ? 'var(--text-primary)' : 'var(--text-muted)', cursor: 'pointer',
                  fontFamily: 'var(--font-body)', fontSize: 13,
                }}>{t}</button>
              ))}
            </div>

            <textarea
              rows={4} value={input} onChange={e => setInput(e.target.value)}
              placeholder={`Paste baseline malicious ${type} here…`}
              style={{
                width: '100%', padding: '16px', border: '1px solid var(--border)', borderRadius: 8,
                background: 'var(--bg-sunken)', color: 'var(--text-primary)',
                fontFamily: type === 'url' ? 'var(--font-mono)' : 'var(--font-body)',
                fontSize: 14, resize: 'vertical', outline: 'none',
              }}
            />

            <div style={{ marginTop: 20, display: 'flex', justifyContent: 'flex-end' }}>
              <button 
                className="btn-primary" 
                onClick={handleTest} 
                disabled={running || !input.trim()}
              >
                {running ? 'Running Mutations…' : 'Execute Attack Suite →'}
              </button>
            </div>
          </div>
        </div>

        {/* Right: Health context */}
        <div>
           <ModelHealth />
        </div>
      </div>

      {/* Results */}
      {results && (
        <div style={{ animation: 'pageIn 0.3s ease' }}>
          <div style={{ 
            padding: '24px 32px', background: 'var(--bg-surface)', border: '1px solid var(--border)', 
            borderRadius: 8, marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'center' 
          }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>Suite Complete</div>
              <div style={{ fontSize: 28, fontFamily: 'var(--font-display)', fontWeight: 700, margin: '4px 0 0 0' }}>Ensemble Resilience: {results.resilience}%</div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>BASELINE DETECT</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 24, fontWeight: 600, color: 'var(--critical)' }}>{results.baseScore}</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
            {results.attacks.map((atk, i) => {
              const evaded = atk.verdict === 'evaded'
              return (
                <div key={i} className="card" style={{ 
                  padding: 20, position: 'relative', overflow: 'hidden',
                  borderLeft: evaded ? '4px solid var(--critical)' : '4px solid var(--clean)'
                }}>
                  {/* Cyber FZ background numbering */}
                  <div style={{
                    position: 'absolute', top: -10, right: -4,
                    fontFamily: 'var(--font-display)', fontSize: 64, fontWeight: 800,
                    color: 'var(--border)', opacity: 0.3, zIndex: 0,
                  }}>
                    0{i+1}
                  </div>
                  
                  <div style={{ position: 'relative', zIndex: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                      <span style={{ 
                        fontSize: 10, fontFamily: 'var(--font-body)', fontWeight: 600, 
                        background: evaded ? 'var(--critical-dim)' : 'var(--clean-dim)',
                        color: evaded ? 'var(--critical)' : 'var(--clean)', 
                        padding: '2px 8px', borderRadius: 4, textTransform: 'uppercase',
                        border: evaded ? '1px solid var(--critical)20' : '1px solid var(--clean)20',
                      }}>
                        {atk.verdict}
                      </span>
                    </div>

                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4, lineHeight: 1.3 }}>{atk.name}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>Target: {atk.target}</div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontFamily: 'var(--font-mono)', fontSize: 15, fontWeight: 600 }}>
                      <span style={{ color: 'var(--text-muted)' }}>{atk.orig}</span>
                      <span style={{ color: 'var(--text-secondary)' }}>→</span>
                      <span style={{ color: evaded ? 'var(--critical)' : 'var(--text-primary)' }}>{atk.new}</span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
