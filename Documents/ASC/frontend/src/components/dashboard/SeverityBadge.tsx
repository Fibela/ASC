export function SeverityBadge({ severity }: { severity: string }) {
  const sev = severity?.toLowerCase() ?? 'info'
  return (
    <span className={`severity-badge severity-${sev}`}>
      {severity}
    </span>
  )
}
