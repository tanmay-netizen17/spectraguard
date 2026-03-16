import React, { useEffect, useRef } from 'react'

const COLORS = {
  Clean: '#10B981', Suspicious: '#F59E0B',
  'Likely Malicious': '#F97316', Critical: '#EF4444',
}

export default function SentinelGauge({ score = 0, severity = 'Clean', animate = true }) {
  const circleRef = useRef(null)
  const R = 70, C = 2 * Math.PI * R
  const pct = Math.min(100, Math.max(0, score)) / 100
  const color = COLORS[severity] || '#10B981'

  useEffect(() => {
    if (!circleRef.current || !animate) return
    circleRef.current.style.transition = 'none'
    circleRef.current.style.strokeDashoffset = C
    requestAnimationFrame(() => {
      circleRef.current.style.transition = 'stroke-dashoffset 1.2s ease'
      circleRef.current.style.strokeDashoffset = C - pct * C
    })
  }, [score, C, pct, animate])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
      <svg width={180} height={180} style={{ transform: 'rotate(-90deg)' }}>
        {/* Track */}
        <circle cx={90} cy={90} r={R} fill="none" stroke="#F1F5F9" strokeWidth={12} />
        {/* Score arc */}
        <circle
          ref={circleRef}
          cx={90} cy={90} r={R}
          fill="none"
          stroke={color}
          strokeWidth={12}
          strokeLinecap="round"
          strokeDasharray={C}
          strokeDashoffset={animate ? C : C - pct * C}
        />
        {/* Score text */}
        <text
          x={90} y={90}
          textAnchor="middle" dominantBaseline="middle"
          style={{ transform: 'rotate(90deg)', transformOrigin: '90px 90px' }}
          fill={color}
          fontSize={32}
          fontWeight={700}
          fontFamily="'IBM Plex Mono', monospace"
        >
          {score}
        </text>
        <text
          x={90} y={112}
          textAnchor="middle"
          style={{ transform: 'rotate(90deg)', transformOrigin: '90px 112px' }}
          fill="#94A3B8"
          fontSize={11}
          fontFamily="Inter"
        >/ 100</text>
      </svg>
      <div style={{
        padding: '4px 14px', borderRadius: 999,
        background: color + '18', border: `1px solid ${color}40`,
        color, fontSize: 13, fontWeight: 600, fontFamily: 'DM Sans',
        animation: 'fadeScaleIn 0.4s ease',
      }}>
        {severity}
      </div>
    </div>
  )
}
