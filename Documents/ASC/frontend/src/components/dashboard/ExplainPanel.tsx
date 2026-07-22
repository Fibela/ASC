'use client'
// Panel de explicación adaptativa (S102/S109) — consume el SSE del backend y muestra
// el texto en vivo, token a token. La ANTHROPIC_API_KEY vive SOLO en el servidor.
import { useEffect, useState } from 'react'
import { streamExplanation } from '@/lib/explainStream'
import { X, Sparkles } from 'lucide-react'

const PROFILE_LABEL: Record<string, string> = {
  hogar: 'Hogar',
  pyme: 'PyME',
  enterprise: 'Enterprise',
}

interface ExplainPanelProps {
  alertId: string
  alertTitle: string
  onClose: () => void
}

export function ExplainPanel({ alertId, alertTitle, onClose }: ExplainPanelProps) {
  const [text, setText] = useState('')
  const [profile, setProfile] = useState<string | null>(null)
  const [phase, setPhase] = useState<'streaming' | 'done' | 'error'>('streaming')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const ac = new AbortController()
    setText('')
    setProfile(null)
    setPhase('streaming')
    setError(null)
    streamExplanation(
      alertId,
      {
        onMeta: (m: { profile?: string }) => setProfile(m.profile ?? null),
        onDelta: (t: string) => setText(prev => prev + t),
        onDone: () => setPhase('done'),
        onError: (d: string) => {
          setError(d)
          setPhase('error')
        },
      },
      ac.signal,
    ).catch((e: unknown) => {
      const name = (e as { name?: string })?.name
      if (name !== 'AbortError') {
        setError('No se pudo obtener la explicación.')
        setPhase('error')
      }
    })
    return () => ac.abort()
  }, [alertId])

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.7)' }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-2xl p-6"
        style={{ background: '#111', border: '1px solid #222' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Sparkles size={16} style={{ color: '#E85D04' }} />
            <span className="text-sm font-semibold" style={{ color: '#EAEAEA' }}>
              Explicación adaptativa
            </span>
            {profile && (
              <span
                className="text-xs px-2 py-0.5 rounded-full"
                style={{ border: '1px solid #E85D04', color: '#E85D04' }}
              >
                {PROFILE_LABEL[profile] ?? profile}
              </span>
            )}
          </div>
          <button onClick={onClose} style={{ color: '#9CA3AF' }} aria-label="Cerrar">
            <X size={16} />
          </button>
        </div>

        <div className="text-xs mb-3 truncate" style={{ color: '#5A5A5A' }}>
          {alertTitle}
        </div>

        {error ? (
          <div
            className="text-sm rounded-lg p-3"
            style={{ background: '#1a0d0d', border: '1px solid #8B1E1E', color: '#EAEAEA' }}
          >
            {error}
          </div>
        ) : (
          <div
            className="text-sm whitespace-pre-wrap leading-relaxed"
            style={{ color: '#EAEAEA', minHeight: 80 }}
          >
            {text}
            {phase === 'streaming' && (
              <span className="animate-pulse" style={{ color: '#E85D04' }}>
                ▌
              </span>
            )}
          </div>
        )}

        <div className="mt-4 text-[11px]" style={{ color: '#3A3A3A' }}>
          El módulo EXPLICA y RECOMIENDA; nunca decide ni ejecuta. La acción la toma el
          motor determinista o el analista.
        </div>
      </div>
    </div>
  )
}
