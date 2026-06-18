'use client'

// Reusable skeleton loading component for ASC pages.
// Use `variant="table"` for list/alert pages, `variant="cards"` for dashboard-style grids.
// Pages show this while awaiting API data (after auth guard confirms session).

interface PageSkeletonProps {
  variant?: 'table' | 'cards' | 'metrics'
  rows?: number
}

function SkeletonLine({ w = 'w-full', h = 'h-3' }: { w?: string; h?: string }) {
  return (
    <div
      className={`${w} ${h} rounded-md animate-pulse`}
      style={{ background: 'rgba(255,255,255,0.05)' }}
    />
  )
}

function TableSkeleton({ rows }: { rows: number }) {
  return (
    <div className="space-y-3">
      {/* Header row */}
      <div className="flex gap-4 px-4 py-2">
        <SkeletonLine w="w-8"  h="h-2.5" />
        <SkeletonLine w="w-40" h="h-2.5" />
        <SkeletonLine w="w-20" h="h-2.5" />
        <SkeletonLine w="w-20" h="h-2.5" />
        <SkeletonLine w="w-16" h="h-2.5" />
      </div>
      {/* Data rows */}
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="flex gap-4 items-center px-4 py-3 rounded-xl"
          style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}
        >
          <SkeletonLine w="w-6"  h="h-4" />
          <SkeletonLine w="w-48" h="h-3" />
          <SkeletonLine w="w-16" h="h-5" />
          <SkeletonLine w="w-24" h="h-3" />
          <SkeletonLine w="w-20" h="h-3" />
        </div>
      ))}
    </div>
  )
}

function CardsSkeleton({ rows }: { rows: number }) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="p-5 rounded-2xl space-y-3"
          style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}
        >
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl animate-pulse" style={{ background: 'rgba(255,255,255,0.05)' }} />
            <div className="space-y-1.5 flex-1">
              <SkeletonLine w="w-3/4" h="h-3" />
              <SkeletonLine w="w-1/2" h="h-2.5" />
            </div>
          </div>
          <SkeletonLine w="w-full" h="h-8" />
          <SkeletonLine w="w-2/3"  h="h-2.5" />
        </div>
      ))}
    </div>
  )
}

function MetricsSkeleton() {
  return (
    <div className="space-y-6">
      {/* Metric cards row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="p-4 rounded-2xl space-y-3"
            style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}
          >
            <SkeletonLine w="w-1/2" h="h-2.5" />
            <SkeletonLine w="w-3/4" h="h-7" />
            <SkeletonLine w="w-1/3" h="h-2" />
          </div>
        ))}
      </div>
      {/* Chart area */}
      <div
        className="rounded-2xl animate-pulse"
        style={{
          height:     '220px',
          background: 'rgba(255,255,255,0.02)',
          border:     '1px solid rgba(255,255,255,0.05)',
        }}
      />
    </div>
  )
}

export function PageSkeleton({ variant = 'table', rows = 6 }: PageSkeletonProps) {
  return (
    <div className="p-6 space-y-5">
      {/* Page header skeleton */}
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <SkeletonLine w="w-40" h="h-4" />
          <SkeletonLine w="w-56" h="h-2.5" />
        </div>
        <SkeletonLine w="w-24" h="h-8" />
      </div>

      {variant === 'table'   && <TableSkeleton   rows={rows} />}
      {variant === 'cards'   && <CardsSkeleton   rows={rows} />}
      {variant === 'metrics' && <MetricsSkeleton />}
    </div>
  )
}
