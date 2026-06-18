'use client'

import { useEffect } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

interface ErrorPageProps {
  error: Error & { digest?: string }
  reset: () => void
}

// Next.js App Router route-level error boundary.
// Renders when any server or client error propagates up to this level.
// Does NOT catch errors in the root layout — see global-error.tsx for that.
export default function ErrorPage({ error, reset }: ErrorPageProps) {
  useEffect(() => {
    // Surface to monitoring without exposing internals to the DOM
    // Only log in development to avoid leaking stack traces to production console
    if (process.env.NODE_ENV !== 'production') {
      console.error('[ASC ErrorBoundary]', error)
    }
  }, [error])

  return (
    <div
      className="flex min-h-screen items-center justify-center"
      style={{ background: '#0A0A0A' }}
    >
      <div
        className="flex flex-col items-center gap-5 max-w-sm text-center px-6 py-8 rounded-2xl"
        style={{
          background: 'rgba(192,21,46,0.06)',
          border:     '1px solid rgba(192,21,46,0.2)',
        }}
      >
        <AlertTriangle size={32} style={{ color: '#C0152E' }} />

        <div>
          <h2 className="text-base font-bold mb-1" style={{ color: '#EAEAEA' }}>
            Ocurrió un error inesperado
          </h2>
          <p className="text-xs leading-relaxed" style={{ color: '#5A5A5A' }}>
            El módulo no pudo renderizarse correctamente.
            {error.digest && (
              <span className="block mt-1 font-mono" style={{ color: '#3A3A3A' }}>
                ref: {error.digest}
              </span>
            )}
          </p>
        </div>

        <button
          onClick={reset}
          className="btn-primary flex items-center gap-2 text-xs px-4 py-2"
        >
          <RefreshCw size={13} />
          Reintentar
        </button>
      </div>
    </div>
  )
}
