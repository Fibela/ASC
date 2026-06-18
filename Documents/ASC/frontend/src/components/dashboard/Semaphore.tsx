import clsx from 'clsx'

const CONFIG: Record<string, {
  label:   string
  color:   string
  bg:      string
  border:  string
  glow:    string
  pulse?:  string
}> = {
  green: {
    label:  'NORMAL',
    color:  '#2DB863',
    bg:     'rgba(45,184,99,0.08)',
    border: 'rgba(45,184,99,0.5)',
    glow:   '0 0 20px rgba(45,184,99,0.35)',
  },
  yellow: {
    label:  'ELEVADO',
    color:  '#F2C205',
    bg:     'rgba(242,194,5,0.08)',
    border: 'rgba(242,194,5,0.5)',
    glow:   '0 0 20px rgba(242,194,5,0.35)',
  },
  red: {
    label:  'CRÍTICO',
    color:  '#C0152E',
    bg:     'rgba(192,21,46,0.12)',
    border: 'rgba(192,21,46,0.6)',
    glow:   '0 0 24px rgba(192,21,46,0.55)',
    pulse:  'animate-pulse-red',
  },
}

const POSTURE_TO_LEVEL: Record<string, string> = {
  NORMAL:   'green', LOW:      'green',
  ELEVATED: 'yellow', MEDIUM:  'yellow',
  HIGH:     'red',  CRITICAL:  'red',
}

const DOT_SYMBOL: Record<string, string> = {
  green: '●', yellow: '◆', red: '⚠',
}

const SIZES = {
  sm: { outer: 40,  font: 14, border: 2 },
  md: { outer: 64,  font: 18, border: 3 },
  lg: { outer: 96,  font: 26, border: 4 },
}

interface SemaphoreProps {
  posture?: string
  label?:  string
  size?:   'sm' | 'md' | 'lg'
}

export function Semaphore({ posture = 'NORMAL', label, size = 'md' }: SemaphoreProps) {
  const level = POSTURE_TO_LEVEL[posture?.toUpperCase()] ?? 'green'
  const cfg   = CONFIG[level]
  const sz    = SIZES[size]

  return (
    <div className="flex flex-col items-center gap-3">
      {/* Ring */}
      <div
        className={clsx('rounded-full flex items-center justify-center font-black select-none', cfg.pulse)}
        style={{
          width:       sz.outer,
          height:      sz.outer,
          fontSize:    sz.font,
          background:  cfg.bg,
          border:      `${sz.border}px solid ${cfg.border}`,
          boxShadow:   cfg.glow,
          color:       cfg.color,
          transition:  'box-shadow 0.3s ease',
        }}
      >
        {DOT_SYMBOL[level]}
      </div>

      {/* Label */}
      <div className="text-center space-y-0.5">
        <p
          className="font-bold tracking-widest uppercase"
          style={{
            fontSize: size === 'lg' ? 12 : 10,
            color:    cfg.color,
            textShadow: `0 0 12px ${cfg.color}55`,
          }}
        >
          {label ?? cfg.label}
        </p>
        <p className="text-[10px] font-mono uppercase tracking-wider" style={{ color: '#3A3A3A' }}>
          {posture}
        </p>
      </div>
    </div>
  )
}
