import clsx from 'clsx'

type Level = 'green' | 'yellow' | 'red' | string

const CONFIG: Record<string, { label: string; ring: string; glow: string; text: string }> = {
  green:  { label: 'NORMAL',    ring: 'border-green-500',  glow: 'shadow-green-500/40',  text: 'text-green-400' },
  yellow: { label: 'ELEVADO',   ring: 'border-yellow-400', glow: 'shadow-yellow-400/40', text: 'text-yellow-400' },
  red:    { label: 'CRÍTICO',   ring: 'border-red-500',    glow: 'shadow-red-500/40',    text: 'text-red-400' },
}

const POSTURE_TO_LEVEL: Record<string, Level> = {
  NORMAL: 'green', LOW: 'green',
  ELEVATED: 'yellow', MEDIUM: 'yellow',
  HIGH: 'red', CRITICAL: 'red',
}

interface SemaphoreProps {
  posture?: string
  label?: string
  size?: 'sm' | 'md' | 'lg'
}

export function Semaphore({ posture = 'NORMAL', label, size = 'md' }: SemaphoreProps) {
  const level = POSTURE_TO_LEVEL[posture?.toUpperCase()] ?? 'green'
  const cfg   = CONFIG[level]

  const sizes = {
    sm: 'w-10 h-10 text-xs border-2',
    md: 'w-16 h-16 text-sm border-[3px]',
    lg: 'w-24 h-24 text-base border-4',
  }

  return (
    <div className="flex flex-col items-center gap-2">
      <div className={clsx(
        'rounded-full flex items-center justify-center font-black shadow-lg',
        sizes[size], cfg.ring, cfg.glow, cfg.text,
        level === 'red' && 'animate-pulse',
      )}>
        {level === 'green' ? '●' : level === 'yellow' ? '●' : '⚠'}
      </div>
      <div className="text-center">
        <p className={clsx('font-bold tracking-widest text-xs uppercase', cfg.text)}>
          {label ?? cfg.label}
        </p>
        <p className="text-gray-500 text-xs">{posture}</p>
      </div>
    </div>
  )
}
