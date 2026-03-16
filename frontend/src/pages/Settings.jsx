import React, { useState, useContext } from 'react'
import { ThemeContext } from '../App'
import { setMode } from '../api/sentinelApi'
import { SectionHeader } from '../components/SectionHeader'

function FormRow({ label, sublabel, children }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '20px 0', borderBottom: '1px solid var(--border)' }}>
      <div style={{ maxWidth: 400 }}>
        <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>{label}</div>
        {sublabel && <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4, lineHeight: 1.5 }}>{sublabel}</div>}
      </div>
      <div>{children}</div>
    </div>
  )
}

function StatusCard({ title, items }) {
  return (
    <div className="card" style={{ padding: 24, marginBottom: 24 }}>
      <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 18, margin: '0 0 20px 0', color: 'var(--text-primary)' }}>{title}</h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {items.map((item, i) => (
          <div key={i} style={{ 
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', 
            padding: '12px 16px', background: 'var(--bg-primary)', borderRadius: 8, border: '1px solid var(--border)' 
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ 
                width: 10, height: 10, borderRadius: '50%', 
                background: item.status === 'on' ? 'var(--clean)' : 'var(--text-muted)' 
              }} />
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{item.name}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{item.detail}</div>
              </div>
            </div>
            {item.action && (
              <button className="btn-secondary" style={{ padding: '6px 12px', fontSize: 12 }}>
                {item.action}
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

export default function Settings() {
  const { localMode, setLocalMode } = useContext(ThemeContext)
  const [apiKeys, setApiKeys] = useState({ openai: '', virustotal: '', emailPassword: '' })

  const inputStyle = {
    padding: '10px 14px', border: '1px solid var(--border-strong)', borderRadius: 8,
    fontSize: 14, fontFamily: 'var(--font-mono)', width: 320, outline: 'none',
    background: 'var(--bg-sunken)', color: 'var(--text-primary)',
    transition: 'all 0.2s',
  }

  return (
    <div className="page-enter" style={{ maxWidth: 860, margin: '0 auto' }}>
      <div style={{ marginBottom: 40 }}>
        <SectionHeader number="05" title="Platform Settings" subtitle="Configure integration agents, API credentials, and network modes." />
      </div>

      {/* Mode Settings */}
      <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20, marginBottom: 16 }}>1. Operational Mode</h3>
      <div className="card" style={{ padding: '0 24px', marginBottom: 40 }}>
        <FormRow 
          label="Local / Air-gapped Mode" 
          sublabel="All inference runs entirely on your local machine using ONNX quantised models. Zero data leaves your network. Disables GPT-4o-mini Explanations."
        >
          <button
            onClick={async () => {
              const newMode = !localMode;
              try { await setMode(newMode); setLocalMode(newMode); } catch (e) { console.error("Failed", e) }
            }}
            style={{
              width: 52, height: 28, borderRadius: 14, border: 'none', cursor: 'pointer',
              background: localMode ? 'var(--clean)' : 'var(--border-strong)',
              position: 'relative', transition: 'background-color 0.2s', padding: 0,
            }}
          >
            <span style={{
              display: 'block', width: 22, height: 22, background: '#fff', borderRadius: '50%',
              boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
              position: 'absolute', top: 3, left: localMode ? 27 : 3,
              transition: 'left 0.2s cubic-bezier(0.16, 1, 0.3, 1)'
            }} />
          </button>
        </FormRow>
      </div>

      {/* Integrations */}
      <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20, marginBottom: 16 }}>2. Passive Integrations</h3>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 40 }}>
        <StatusCard 
          title="Active Agents" 
          items={[
            { name: "Browser Extension", detail: "Chrome MV3 • v1.0.4", status: "on", action: "Configure" },
            { name: "Email Daemon", detail: "IMAP IDLE stream", status: "off", action: "Start" },
            { name: "Log Collector", detail: "syslog forwarder", status: "off", action: "Setup" }
          ]} 
        />
        <div className="card" style={{ padding: 24, background: 'var(--bg-primary)' }}>
          <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 18, margin: '0 0 16px 0', color: 'var(--text-primary)' }}>Security Posture</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[
              "WebSocket WSS encrypted",
              "Role-based API limits active",
              "Input payload sanitisation ON",
              "Audit logging enabled",
              "OWASP headers enforced",
            ].map((text, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, color: 'var(--text-secondary)' }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--clean)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                {text}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* API Keys */}
      <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20, marginBottom: 16 }}>3. External Providers</h3>
      <div className="card" style={{ padding: '0 24px', marginBottom: 60 }}>
        <FormRow label="OpenAI API Key" sublabel="Required for GPT-4o-mini Threat Breifs (if Local Mode is off).">
          <input type="password" placeholder="sk-proj-..." value={apiKeys.openai} onChange={e => setApiKeys(p => ({ ...p, openai: e.target.value }))} style={inputStyle} />
        </FormRow>
        <FormRow label="VirusTotal API Key" sublabel="Used by URL Detector to enrich domain intelligence and previous block markers.">
          <input type="password" placeholder="vt-key-..." value={apiKeys.virustotal} onChange={e => setApiKeys(p => ({ ...p, virustotal: e.target.value }))} style={inputStyle} />
        </FormRow>
        <div style={{ borderBottom: 'none' }}>
        <FormRow label="Email App Password" sublabel="For the Email Daemon to tail the IMAP IDLE connection securely.">
          <input type="password" placeholder="16-char app password" value={apiKeys.emailPassword} onChange={e => setApiKeys(p => ({ ...p, emailPassword: e.target.value }))} style={inputStyle} />
        </FormRow>
        </div>
      </div>
    </div>
  )
}
