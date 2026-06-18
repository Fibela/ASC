'use client'

export function AuthLoader() {
  return (
    <div className="flex min-h-screen items-center justify-center" style={{ background: '#0A0A0A' }}>
      <div
        className="w-5 h-5 rounded-full border-2 animate-spin"
        style={{ borderColor: 'rgba(232,93,4,0.2)', borderTopColor: '#E85D04' }}
      />
    </div>
  )
}
