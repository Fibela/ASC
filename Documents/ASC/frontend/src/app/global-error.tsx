'use client'

import { useEffect } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

interface GlobalErrorProps {
  error: Error & { digest?: string }
  reset: () => void
}

// Root-level error boundary for the Next.js App Router.
// Catches errors thrown by the root layout (src/app/layout.tsx) or any
// error that error.tsx could not handle. Renders its own <html> and <body>
// because the root layout is unavailable at this point.
export default function GlobalError({ error, reset }: GlobalErrorProps) {
  useEffect(() => {
    if (process.env.NODE_ENV !== 'production') {
      console.error('[ASC GlobalError]', error)
    }
  }, [error])

  return (
    <html lang="es">
      <body style={{ margin: 0, background: '#0A0A0A', fontFamily: 'system-ui, sans-serif' }}>
        <div style={{
          display: 'flex',
          minHeight: '100vh',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <div style={{
            display:       'flex',
            flexDirection: 'column',
            alignItems:    'center',
            gap:           '20px',
            maxWidth:      '360px',
            textAlign:     'center',
            padding:       '32px 24px',
            background:    'rgba(192,21,46,0.06)',
            border:        '1px solid rgba(192,21,46,0.2)',
            borderRadius:  '16px',
          }}>
            <AlertTriangle size={36} color="#C0152E" />

            <div>
              <h1 style={{ color: '#EAEAEA', fontSize: '15px', fontWeight: 700, margin: '0 0 6px' }}>
                Error crítico — ASC no pudo iniciar
              </h1>
              <p style={{ color: '#5A5A5A', fontSize: '12px', lineHeight: 1.6, margin: 0 }}>
                Se produjo un error en el núcleo de la aplicación.
                {error.digest && (
                  <span style={{ display: 'block', marginTop: '6px', fontFamily: 'monospace', color: '#3A3A3A', fontSize: '11px' }}>
                    ref: {error.digest}
                  </span>
                )}
              </p>
            </div>

            <button
              onClick={reset}
              style={{
                display:        'flex',
                alignItems:     'center',
                gap:            '8px',
                background:     '#E85D04',
                color:          '#fff',
                border:         'none',
                borderRadius:   '8px',
                padding:        '8px 16px',
                fontSize:       '12px',
                fontWeight:     600,
                cursor:         'pointer',
              }}
            >
              <RefreshCw size={13} />
              Recargar aplicación
            </button>
          </div>
        </div>
      </body>
    </html>
  )
}
