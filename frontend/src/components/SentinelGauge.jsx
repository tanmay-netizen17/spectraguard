import React, { useEffect, useState } from 'react'

export default function SentinelGauge({ score }) {
  const [animatedScore, setAnimatedScore] = useState(0)

  // Arc geometry
  const R = 75               // radius
  const cx = 100, cy = 100   // center
  const circumference = Math.PI * R   // half-circle arc
  const offset = circumference * (1 - animatedScore / 100)

  // Color selection
  const colour = animatedScore <= 30 ? 'var(--clean)'
               : animatedScore <= 60 ? 'var(--suspicious)'
               : animatedScore <= 80 ? 'var(--likely)'
               :                       'var(--critical)'

  const label = animatedScore <= 30 ? 'Clean'
              : animatedScore <= 60 ? 'Suspicious'
              : animatedScore <= 80 ? 'Likely Malicious'
              :                       'Critical'

  useEffect(() => {
    // Count up animation
    setAnimatedScore(0)
    const duration = 1000 // ms
    const startTime = performance.now()

    const animate = (time) => {
      const elapsed = time - startTime
      const progress = Math.min(elapsed / duration, 1)
      // Ease out cubic
      const ease = 1 - Math.pow(1 - progress, 3)
      setAnimatedScore(Math.round(score * ease))
      
      if (progress < 1) {
        requestAnimationFrame(animate)
      } else {
        setAnimatedScore(score)
      }
    }
    requestAnimationFrame(animate)
  }, [score])

  return (
    <div style={{ position: 'relative', width: 200, height: 120 }}>
      <svg viewBox="0 0 200 120" width="200" height="120">
        {/* Track */}
        <path
          d={`M ${cx - R} ${cy} A ${R} ${R} 0 0 1 ${cx + R} ${cy}`}
          fill="none" stroke="var(--bg-sunken)" strokeWidth="12"
          strokeLinecap="round"
        />
        {/* Animated fill */}
        <path
          d={`M ${cx - R} ${cy} A ${R} ${R} 0 0 1 ${cx + R} ${cy}`}
          fill="none" stroke={colour} strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke 0.3s' }}
        />
        {/* Score text */}
        <text x={cx} y={cy - 12} textAnchor="middle"
          style={{
            fontFamily: 'var(--font-mono)', fontSize: 42,
            fontWeight: 600, fill: 'var(--text-primary)',
          }}>
          {animatedScore}
        </text>
        {/* Label text */}
        <text x={cx} y={cy + 8} textAnchor="middle"
          style={{
            fontFamily: 'var(--font-body)', fontSize: 11,
            fill: 'var(--text-muted)', letterSpacing: '0.08em',
            textTransform: 'uppercase', fontWeight: 600,
          }}>
          {label}
        </text>
      </svg>
    </div>
  )
}
