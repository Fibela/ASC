interface MetricCardProps {
  label: string
  value: string | number | null
  unit?: string
  sublabel?: string
  color?: 'cyan' | 'red' | 'orange' | 'green'
}

const colorMap = {
  cyan:   'text-cyan-400',
  red:    'text-red-400',
  orange: 'text-orange-400',
  green:  'text-green-400',
}

export function MetricCard({ label, value, unit, sublabel, color = 'cyan' }: MetricCardProps) {
  return (
    <div className="bg-navy-800 border border-cyan-400/20 rounded-lg p-4 flex flex-col gap-1">
      <p className="text-xs text-gray-400 uppercase tracking-widest">{label}</p>
      <p className={`text-3xl font-bold ${colorMap[color]}`}>
        {value ?? '—'}{unit && <span className="text-lg ml-1">{unit}</span>}
      </p>
      {sublabel && <p className="text-xs text-gray-500">{sublabel}</p>}
    </div>
  )
}
