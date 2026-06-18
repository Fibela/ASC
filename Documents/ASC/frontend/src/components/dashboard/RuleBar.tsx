interface RuleBarProps {
  ruleId:   string
  name:     string
  ttp:      string
  count:    number
  maxCount: number
  severity: string
}

const SEV_CONFIG: Record<string, { bar: string; label: string; text: string }> = {
  critical: { bar: '#C0152E', label: 'CRI', text: '#E8526E' },
  high:     { bar: '#E85D04', label: 'ALT', text: '#FF7A25' },
  medium:   { bar: '#F2C205', label: 'MED', text: '#F2C205' },
  low:      { bar: '#2DB863', label: 'BAJ', text: '#3FD175' },
}

export function RuleBar({ ruleId, name, ttp, count, maxCount, severity }: RuleBarProps) {
  const pct = maxCount > 0 ? Math.max(4, Math.round((count / maxCount) * 100)) : 0
  const cfg = SEV_CONFIG[severity] ?? SEV_CONFIG.medium

  return (
    <div
      className="flex items-center gap-3 px-3 py-2 rounded-xl transition-all duration-150"
      onMouseEnter={e => (e.currentTarget.style.background = 'rgba(232,93,4,0.04)')}
      onMouseLeave={e => (e.currentTarget.style.background = '')}
    >
      {/* Severity + ruleId */}
      <div className="flex flex-col items-center flex-shrink-0 gap-0.5" style={{ minWidth: 46 }}>
        <span
          className="text-[9px] font-bold px-1.5 py-0.5 rounded-md leading-none uppercase tracking-wider"
          style={{
            background: `${cfg.bar}22`,
            color:      cfg.text,
            border:     `1px solid ${cfg.bar}44`,
          }}
        >
          {cfg.label}
        </span>
        <span className="text-[9px] font-mono" style={{ color: '#3A3A3A' }}>{ruleId}</span>
      </div>

      {/* Main content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs truncate" style={{ color: '#A0A0A0' }}>{name}</span>
          <span
            className="text-xs font-bold font-mono ml-2 flex-shrink-0"
            style={{ color: cfg.text }}
          >
            {count}
          </span>
        </div>

        {/* Progress bar */}
        <div
          className="h-1 rounded-full overflow-hidden"
          style={{ background: 'rgba(255,255,255,0.05)' }}
        >
          <div
            className="h-full rounded-full transition-all duration-700"
            style={{
              width:           `${pct}%`,
              backgroundImage: `linear-gradient(90deg, ${cfg.bar}aa, ${cfg.bar})`,
              boxShadow:       `0 0 4px ${cfg.bar}66`,
            }}
          />
        </div>
      </div>

      {/* TTP */}
      <span
        className="text-[10px] font-mono flex-shrink-0 text-right"
        style={{ color: '#3A3A3A', minWidth: 72 }}
      >
        {ttp}
      </span>
    </div>
  )
}
