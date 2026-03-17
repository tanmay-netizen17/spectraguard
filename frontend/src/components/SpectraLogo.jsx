export default function SpectraLogo({ size = 24 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none">
      {/* Outer hexagon shield */}
      <path
        d="M16 2L4 8v8c0 6.627 5.149 12.373 12 14 6.851-1.627 12-7.373 12-14V8L16 2z"
        fill="#0A84FF" opacity="0.15"
        stroke="#0A84FF" strokeWidth="1.5"
      />
      {/* Spectrum bar — 3 colour bands */}
      <rect x="9"  y="13" width="4" height="8" rx="1" fill="#12B76A" />
      <rect x="14" y="10" width="4" height="11" rx="1" fill="#0A84FF" />
      <rect x="19" y="15" width="4" height="6" rx="1" fill="#F04438" />
      {/* Top dot */}
      <circle cx="16" cy="7" r="1.5" fill="#0A84FF" />
    </svg>
  )
}
