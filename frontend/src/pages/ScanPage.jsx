import React, { useState, useRef } from 'react'
import { analyseInput, ingestFile } from '../api/sentinelApi'
import SentinelGauge from '../components/SentinelGauge'
import EvidenceCard from '../components/EvidenceCard'
import ThreatBrief from '../components/ThreatBrief'
import ActionPanel from '../components/ActionPanel'

const TABS = ['URL', 'Text / Email', 'File Upload', 'Log Paste']

export default function ScanPage({ onNavigate }) {
  const [tab, setTab] = useState(0)
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const fileRef = useRef(null)

  const handleAnalyse = async () => {
    setError(''); setResult(null); setLoading(true)
    try {
      let res
      if (tab === 2 && fileRef.current?.files[0]) {
        res = await ingestFile(fileRef.current.files[0])
      } else {
        const type = tab === 0 ? 'url' : tab === 3 ? 'log' : 'text'
        const payload = { type, content: input }
        res = await analyseInput(payload)
      }
      setResult(res)
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Analysis failed. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h1 style={{ fontFamily: 'DM Sans', fontSize: 24, fontWeight: 700, color: '#0F172A', marginBottom: 4 }}>
        Analyse Threat
      </h1>
      <p style={{ color: '#6B7280', fontSize: 14, marginBottom: 24 }}>
        Submit any suspicious input for full multi-detector analysis.
      </p>

      {/* Input panel */}
      <div className="card" style={{ padding: 20, marginBottom: 24 }}>
        {/* Tabs */}
        <div style={{ display: 'flex', gap: 4, marginBottom: 16, borderBottom: '1px solid #E5E7EB', paddingBottom: 4 }}>
          {TABS.map((t, i) => (
            <button key={t} onClick={() => { setTab(i); setInput(''); setResult(null) }} style={{
              padding: '6px 14px', border: 'none', borderRadius: 6, cursor: 'pointer',
              background: tab === i ? '#6366F1' : 'transparent',
              color: tab === i ? '#fff' : '#6B7280',
              fontSize: 13, fontWeight: tab === i ? 600 : 400,
              transition: 'all 0.15s',
            }}>{t}</button>
          ))}
        </div>

        {/* Input area */}
        {tab === 2 ? (
          <div style={{
            border: '2px dashed #E5E7EB', borderRadius: 10, padding: 32,
            textAlign: 'center', color: '#9CA3AF', cursor: 'pointer',
          }} onClick={() => fileRef.current?.click()}>
            <input ref={fileRef} type="file" style={{ display: 'none' }} accept=".jpg,.jpeg,.png,.mp4,.avi,.mov,.txt,.log" />
            <div style={{ fontSize: 28 }}>📁</div>
            <div style={{ fontSize: 14, marginTop: 8 }}>Click to upload image, video, or log file</div>
            <div style={{ fontSize: 12, marginTop: 4 }}>JPG, PNG, MP4, AVI, TXT, LOG</div>
          </div>
        ) : (
          <textarea
            rows={tab === 0 ? 2 : 6}
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder={
              tab === 0 ? 'https://suspicious-site.xyz/login?verify=account' :
              tab === 1 ? 'Paste suspicious email or message here…' :
              'Paste auth.log / syslog lines here…'
            }
            style={{
              width: '100%', padding: 12, border: '1px solid #E5E7EB',
              borderRadius: 8, resize: 'vertical', fontSize: 13,
              fontFamily: tab === 0 ? 'IBM Plex Mono' : 'Inter',
              outline: 'none', background: '#FAFAFA', color: '#0F172A',
              boxSizing: 'border-box',
            }}
            onFocus={e => e.target.style.borderColor = '#6366F1'}
            onBlur={e => e.target.style.borderColor = '#E5E7EB'}
          />
        )}

        <div style={{ marginTop: 12, display: 'flex', gap: 10, alignItems: 'center' }}>
          <button onClick={handleAnalyse} disabled={loading || (tab !== 2 && !input.trim())} style={{
            padding: '10px 28px', background: loading ? '#C7D2FE' : '#6366F1',
            color: '#fff', border: 'none', borderRadius: 8, cursor: loading ? 'not-allowed' : 'pointer',
            fontWeight: 600, fontSize: 14, transition: 'background 0.15s',
          }}>
            {loading ? 'Analysing…' : 'Analyse'}
          </button>
          {error && <span style={{ color: '#EF4444', fontSize: 13 }}>{error}</span>}
        </div>
      </div>

      {/* Results */}
      {result && (
        <div style={{ animation: 'fadeScaleIn 0.35s ease' }}>
          {/* Score + brief top row */}
          <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: 20, marginBottom: 20 }}>
            <div className="card" style={{ padding: 20, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
              <SentinelGauge score={result.sentinel_score} severity={result.severity} animate={true} />
              <div style={{ fontSize: 12, color: '#9CA3AF', textAlign: 'center' }}>
                <span className="mono">{result.incident_id}</span>
              </div>
            </div>
            <ThreatBrief incident={result} />
          </div>

          {/* Action */}
          <div style={{ marginBottom: 20 }}>
            <ActionPanel recommended_action={result.recommended_action} severity={result.severity} />
          </div>

          {/* Evidence */}
          {result.evidence && Object.keys(result.evidence).length > 0 && (
            <div>
              <h3 style={{ fontSize: 14, fontWeight: 600, color: '#0F172A', marginBottom: 10 }}>
                Detector Evidence
              </h3>
              <EvidenceCard evidence={result.evidence} detectors_triggered={result.detectors_triggered} />
            </div>
          )}
        </div>
      )}
    </div>
  )
}
