import { TrendingUp, TrendingDown, Minus } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

interface MetricCardProps {
  label:     string
  value:     string | number | null
  unit?:     string
  sublabel?: string
  icon?:     LucideIcon
  trend?:    'up' | 'down' | 'neutral'
  trendVal?: string
  color?:    'orange' | 'red' | 'green' | 'amber' | 'cyan' | 'default'
}

const colorConfig = {
  orange:  { value: '#E85D04', bg: 'rgba(232,93,4,0.08)',  border: 'rgba(232,93,4,0.18)',  icon: 'rgba(232,93,4,0.15)' },
  red:     { value: '#E8526E', bg: 'rgba(192,21,46,0.08)', border: 'rgba(192,21,46,0.18)', icon: 'rgba(192,21,46,0.15)' },
  green:   { value: '#3FD175', bg: 'rgba(45,184,99,0.07)', border: 'rgba(45,184,99,0.18)', icon: 'rgba(45,184,99,0.12)' },
  amber:   { value: '#F2C205', bg: 'rgba(242,194,5,0.07)', border: 'rgba(242,194,5,0.18)', icon: 'rgba(242,194,5,0.12)' },
  cyan:    { value: '#22D3EE', bg: 'rgba(34,211,238,0.07)', border: 'rgba(34,211,238,0.18)', icon: 'rgba(34,211,238,0.12)' },
  default: { value: '#EAEAEA', bg: 'rgba(255,255,255,0.03)', border: 'rgba(255,255,255,0.08)', icon: 'rgba(255,255,255,0.06)' },
}

const trendConfig = {
  up:      { icon: TrendingUp,   color: '#3FD175' },
  down:    { icon: TrendingDown, color: '#E8526E' },
  neutral: { icon: Minus,        color: '#5A5A5A' },
}

export function MetricCard({
  label, value, unit, sublabel, icon: Icon,
  trend, trendVal, color = 'default',
}: MetricCardProps) {
  const cfg = colorConfig[color]
  const TrendIcon = trend ? trendConfig[trend].icon : null

  return (
    <div
      className="relative rounded-2xl p-5 flex flex-col gap-2 overflow-hidden transition-all duration-200"
      style={{
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        boxShadow: '0 1px 4px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.04)',
      }}
      onMouseEnter={e => {
        (e.currentTarget as HTMLElement).style.boxShadow =
          `0 4px 20px rgba(0,0,0,0.6), 0 0 0 1px ${cfg.border}, inset 0 1px 0 rgba(255,255,255,0.06)`
      }}
      onMouseLeave={e => {
        (e.currentTarget as HTMLElement).style.boxShadow =
          '0 1px 4px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.04)'
      }}
    >
      {/* Subtle corner accent */}
      <div
        className="absolute top-0 right-0 w-16 h-16 rounded-full pointer-events-none"
        style={{
          background: `radial-gradient(circle, ${cfg.border} 0%, transparent 70%)`,
          transform: 'translate(30%, -30%)',
        }}
      />

      {/* Header row */}
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-widest leading-none"
           style={{ color: '#5A5A5A' }}>
          {label}
        </p>
        {Icon && (
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: cfg.icon }}
          >
            <Icon size={14} style={{ color: cfg.value }} />
          </div>
        )}
      </div>

      {/* Value */}
      <p className="text-3xl font-bold leading-none tracking-tight" style={{ color: cfg.value }}>
        {value ?? '—'}
        {unit && (
          <span className="text-base font-medium ml-1" style={{ color: cfg.value, opacity: 0.7 }}>
            {unit}
          </span>
        )}
      </p>

      {/* Footer */}
      <div className="flex items-center justify-between gap-2 mt-auto">
        {sublabel && (
          <p className="text-xs" style={{ color: '#5A5A5A' }}>{sublabel}</p>
        )}
        {trend && TrendIcon && trendVal && (
          <div className="flex items-center gap-1 ml-auto">
            <TrendIcon size={11} style={{ color: trendConfig[trend].color }} />
            <span className="text-xs font-medium" style={{ color: trendConfig[trend].color }}>
              {trendVal}
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
