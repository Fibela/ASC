import clsx from 'clsx'

const MAP: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high:     'bg-orange-500 text-white',
  medium:   'bg-yellow-400 text-black',
  low:      'bg-green-500 text-white',
}

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={clsx('text-xs font-bold px-2 py-0.5 rounded uppercase tracking-wide', MAP[severity] ?? 'bg-gray-500 text-white')}>
      {severity}
    </span>
  )
}
