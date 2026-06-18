import { PageSkeleton } from '@/components/PageSkeleton'

export default function EventsLoading() {
  return (
    <div className="flex min-h-screen" style={{ background: '#0A0A0A' }}>
      <div style={{ width: 220, flexShrink: 0, borderRight: '1px solid rgba(255,255,255,0.05)' }} />
      <main className="flex-1">
        <PageSkeleton variant="table" rows={12} />
      </main>
    </div>
  )
}
