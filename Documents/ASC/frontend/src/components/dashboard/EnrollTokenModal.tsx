'use client'
// S112.1 — Modal "Generar token de agente". Consume GET /agents/enrollment-token
// (admin; el backend lo ata al tenant del admin) y lo muestra con copiar + pasos.
import { useEffect, useState } from 'react'
import { getEnrollmentToken, EnrollmentTokenResponse } from '@/lib/api'
import { X, Copy, Check, KeyRound } from 'lucide-react'

export function EnrollTokenModal({ onClose }: { onClose: () => void }) {
  const [data, setData] = useState<EnrollmentTokenResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    let alive = true
    getEnrollmentToken()
      .then((d: EnrollmentTokenResponse) => { if (alive) setData(d) })
      .catch(() => { if (alive) setError('No se pudo obtener el token (¿eres admin?).') })
    return () => { alive = false }
  }, [])

  const copy = async () => {
    if (!data?.token) return
    try {
      await navigator.clipboard.writeText(data.token)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { /* clipboard no disponible */ }
  }

  const mins = data?.valid_for_seconds ? Math.floor(data.valid_for_seconds / 60) : null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
         style={{ background: 'rgba(0,0,0,0.7)' }} onClick={onClose}>
      <div className="w-full max-w-lg rounded-2xl p-6"
           style={{ background: '#111', border: '1px solid #222' }}
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <KeyRound size={16} style={{ color: '#E85D04' }} />
            <span className="text-sm font-semibold" style={{ color: '#EAEAEA' }}>
              Token de enrolamiento de agente
            </span>
          </div>
          <button onClick={onClose} style={{ color: '#9CA3AF' }} aria-label="Cerrar"><X size={16} /></button>
        </div>

        {error ? (
          <div className="text-sm rounded-lg p-3"
               style={{ background: '#1a0d0d', border: '1px solid #8B1E1E', color: '#EAEAEA' }}>{error}</div>
        ) : !data ? (
          <div className="text-sm" style={{ color: '#9CA3AF' }}>Generando…</div>
        ) : !data.configured ? (
          <div className="text-sm rounded-lg p-3"
               style={{ background: '#0d0d0d', border: '1px solid #F2860A', color: '#EAEAEA' }}>
            El enrolamiento está en modo dev (sin <code>SPECTER_ENROLLMENT_SECRET</code>). Cualquiera
            puede registrar un agente — configúralo en Vercel antes de producción.
          </div>
        ) : (
          <>
            <div className="flex items-stretch gap-2 mb-2">
              <code className="flex-1 text-xs break-all rounded-lg p-3"
                    style={{ background: '#0d0d0d', border: '1px solid #222', color: '#3ECF8E' }}>
                {data.token}
              </code>
              <button onClick={copy} className="btn-secondary px-3 flex items-center"
                      title="Copiar token">
                {copied ? <Check size={14} style={{ color: '#3ECF8E' }} /> : <Copy size={14} />}
              </button>
            </div>
            {mins != null && (
              <div className="text-[11px] mb-4" style={{ color: '#9CA3AF' }}>
                Válido ~{mins} min. Distribúyelo solo por canal seguro (no lo pegues en chats).
              </div>
            )}
            <div className="text-xs rounded-lg p-3" style={{ background: '#0d0d0d', border: '1px solid #222', color: '#EAEAEA' }}>
              <div className="mb-1" style={{ color: '#9CA3AF' }}>En el host del agente:</div>
              <code className="block whitespace-pre-wrap" style={{ color: '#EAEAEA' }}>
{`$env:SPECTER_BACKEND_URL   = "https://asc.premoscorp.com"
$env:SPECTER_ENROLLMENT_TOKEN = "<pega-el-token>"
python -m specter.agent`}
              </code>
            </div>
          </>
        )}
        <div className="mt-4 text-[11px]" style={{ color: '#3A3A3A' }}>
          El agente queda atado a tu tenant (el token lo embebe). Ver docs/SPECTER_DEPLOYMENT.md.
        </div>
      </div>
    </div>
  )
}
