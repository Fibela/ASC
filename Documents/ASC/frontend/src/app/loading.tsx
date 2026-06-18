// Root-level Next.js loading UI (React Suspense).
// Shown during route transitions before the incoming page's JS executes.
// Pages that are Client Components handle their own data-loading states internally.
import { PageSkeleton } from '@/components/PageSkeleton'

export default function RootLoading() {
  return (
    <div className="flex min-h-screen" style={{ background: '#0A0A0A' }}>
      <div style={{ width: 220, flexShrink: 0, borderRight: '1px solid rgba(255,255,255,0.05)' }} />
      <main className="flex-1">
        <PageSkeleton variant="table" rows={8} />
      </main>
    </div>
  )
}
