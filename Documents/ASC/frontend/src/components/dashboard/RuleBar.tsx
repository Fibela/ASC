interface RuleBarProps {
  ruleId:  string
  name:    string
  ttp:     string
  count:   number
  maxCount: number
  severity: string
}

const SEV_COLOR: Record<string, string> = {
  critical: 'bg-red-500',
  high:     'bg-orange-400',
  medium:   'bg-yellow-400',
  low:      'bg-green-500',
}

export function RuleBar({ ruleId, name, ttp, count, maxCount, severity }: RuleBarProps) {
  const pct = maxCount > 0 ? Math.round((count / maxCount) * 100) : 0
  const color = SEV_COLOR[severity] ?? 'bg-cyan-400'

  return (
    <div className="flex items-center gap-3 py-1.5">
      <span className="text-xs font-mono text-gray-500 w-16 shrink-0">{ruleId}</span>
      <div className="flex-1">
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs text-gray-300">{name}</span>
          <span className="text-xs font-mono text-cyan-400">{count}</span>
        </div>
        <div className="h-1.5 bg-navy-900 rounded-full overflow-hidden">
          <div className={`h-full rounded-full transition-all duration-500 ${color}`} style={{ width: `${pct}%` }} />
        </div>
      </div>
      <span className="text-xs text-gray-600 w-20 shrink-0 text-right font-mono">{ttp}</span>
    </div>
  )
}
