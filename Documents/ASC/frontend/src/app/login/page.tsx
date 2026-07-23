'use client'

import { useState, useEffect, useCallback, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { isAuthenticated, initAuth } from '@/lib/auth'
import { Shield } from 'lucide-react'

const PORTAL_URL    = process.env.NEXT_PUBLIC_PORTAL_URL ?? 'https://premoscorp.com'
const PORTAL_PATH   = '/portal/seguridad'
const COUNTDOWN_SEC = 8

const SOC_CAPS = [
  'Alertas en tiempo real',
  'Threat Hunting MITRE ATT&CK',
  'Neutralizaciones PANL',
  'Ledger Forense PFN',
  'Reportes PCDI',
  'IoCs & TTPs globales',
]

const FLOW_STEPS = [
  { n: '01', text: 'Ir a premoscorp.com → Portal de Seguridad' },
  { n: '02', text: 'Iniciar sesión con Google o GitHub (OAuth)' },
  { n: '03', text: 'Redirección automática al ASC — sin contraseña adicional' },
]

function ArrowRightIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
      <polyline points="10 17 15 12 10 7" />
      <line x1="15" y1="12" x2="3" y2="12" />
    </svg>
  )
}

function LoginGateway() {
  const router         = useRouter()
  const params         = useSearchParams()
  const isExpired      = params.get('expired') === '1'

  const [seconds,  setSeconds]  = useState(COUNTDOWN_SEC)
  const [paused,   setPaused]   = useState(false)
  const [leaving,  setLeaving]  = useState(false)

  const goToPortal = useCallback(() => {
    setLeaving(true)
    window.location.href = `${PORTAL_URL}${PORTAL_PATH}`
  }, [])

  // If already authenticated, go straight to the app
  useEffect(() => {
    initAuth()
    if (isAuthenticated()) router.replace('/')
  }, [router])

  // Auto-countdown → redirect
  useEffect(() => {
    if (paused || leaving) return
    if (seconds <= 0) { goToPortal(); return }
    const t = setTimeout(() => setSeconds(s => s - 1), 1000)
    return () => clearTimeout(t)
  }, [seconds, paused, leaving, goToPortal])

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4 py-14"
      style={{
        background: '#0A0A0A',
        backgroundImage:
          'radial-gradient(ellipse at 15% 50%, rgba(232,93,4,0.065) 0%, transparent 55%),' +
          'radial-gradient(ellipse at 85% 15%, rgba(139,30,30,0.065) 0%, transparent 55%),' +
          'radial-gradient(ellipse at 50% 90%, rgba(232,93,4,0.04) 0%, transparent 45%)',
      }}
    >
      <div
        className="w-full max-w-[420px] animate-fade-in"
        style={{ opacity: leaving ? 0 : undefined, transition: 'opacity 0.3s ease' }}
      >

        {/* ── Brand header ─────────────────────────────────────────────── */}
        <div className="text-center mb-8">
          <div
            className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-5"
            style={{
              background: 'linear-gradient(135deg, #C44D03 0%, #E85D04 100%)',
              boxShadow: '0 0 36px rgba(232,93,4,0.38), 0 8px 24px rgba(0,0,0,0.55)',
            }}
          >
            <Shield size={30} color="#fff" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#EAEAEA' }}>
            Premos<span style={{ color: '#E85D04' }}>Corp</span> ASC
          </h1>
          <p className="text-sm mt-1" style={{ color: '#5A5A5A' }}>
            Analizador de Seguridad Cibernética
          </p>
        </div>

        {/* ── Gateway card ─────────────────────────────────────────────── */}
        <div className="card-orange p-8 mb-4 relative overflow-hidden">

          {/* Top accent line */}
          <div
            className="absolute top-0 left-1/2 -translate-x-1/2 h-px pointer-events-none"
            style={{
              width: '70%',
              background: 'linear-gradient(90deg, transparent, rgba(232,93,4,0.35), transparent)',
            }}
          />

          {/* ── State: expired vs first-visit ─────────────────────────── */}
          <div className="text-center mb-7">
            {isExpired ? (
              <>
                <span
                  className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-full mb-4"
                  style={{
                    background: 'rgba(242,194,5,0.08)',
                    border: '1px solid rgba(242,194,5,0.22)',
                    color: '#F2C205',
                  }}
                >
                  <span
                    className="w-1.5 h-1.5 rounded-full animate-pulse"
                    style={{ background: '#F2C205' }}
                  />
                  Sesión expirada
                </span>
                <h2 className="text-xl font-bold mb-2" style={{ color: '#EAEAEA' }}>
                  Tu sesión ha expirado
                </h2>
                <p className="text-sm leading-relaxed max-w-xs mx-auto" style={{ color: '#5A5A5A' }}>
                  Reanuda el acceso desde el portal PremosCorp —
                  el SSO te devolverá al ASC automáticamente sin contraseña.
                </p>
              </>
            ) : (
              <>
                <span className="chip-orange inline-flex items-center gap-1.5 mb-4">
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: '#E85D04' }} />
                  Autenticación centralizada
                </span>
                <h2 className="text-xl font-bold mb-2" style={{ color: '#EAEAEA' }}>
                  Accede vía Portal Premos
                </h2>
                <p className="text-sm leading-relaxed max-w-xs mx-auto" style={{ color: '#5A5A5A' }}>
                  El ASC usa el sistema de identidad de PremosCorp.
                  Inicia sesión una vez y serás redirigido automáticamente.
                </p>
              </>
            )}
          </div>

          {/* ── 3-step flow ──────────────────────────────────────────── */}
          <div className="space-y-2.5 mb-7">
            {FLOW_STEPS.map((step) => (
              <div key={step.n} className="flex items-center gap-3">
                <span
                  className="w-7 h-7 rounded-lg flex-shrink-0 flex items-center justify-center
                             text-xs font-bold font-mono"
                  style={{
                    background: 'rgba(232,93,4,0.10)',
                    border: '1px solid rgba(232,93,4,0.22)',
                    color: '#E85D04',
                  }}
                >
                  {step.n}
                </span>
                <span className="text-sm leading-snug" style={{ color: '#A0A0A0' }}>
                  {step.text}
                </span>
              </div>
            ))}
          </div>

          {/* ── Divider ──────────────────────────────────────────────── */}
          <div className="divider mb-6" />

          {/* ── Countdown strip ──────────────────────────────────────── */}
          {!paused && !leaving && (
            <div
              className="flex items-center gap-3 px-4 py-2.5 rounded-xl mb-3"
              style={{
                background: 'rgba(232,93,4,0.05)',
                border: '1px solid rgba(232,93,4,0.14)',
              }}
            >
              <span
                className="w-2 h-2 rounded-full flex-shrink-0 animate-pulse"
                style={{ background: '#E85D04' }}
              />
              <p className="text-xs flex-1" style={{ color: '#6b7280' }}>
                Redirigiendo en{' '}
                <span className="font-bold font-mono tabular-nums" style={{ color: '#E85D04' }}>
                  {seconds}s
                </span>
              </p>
              <button
                onClick={() => setPaused(true)}
                className="text-xs transition-colors"
                style={{ color: '#3A3A3A' }}
                onMouseEnter={e => (e.currentTarget.style.color = '#6b7280')}
                onMouseLeave={e => (e.currentTarget.style.color = '#3A3A3A')}
              >
                Cancelar
              </button>
            </div>
          )}

          {/* ── Primary CTA ──────────────────────────────────────────── */}
          <button
            onClick={goToPortal}
            disabled={leaving}
            className="btn-primary w-full py-3"
          >
            <ArrowRightIcon />
            {leaving ? 'Redirigiendo…' : 'Ir a premoscorp.com'}
          </button>

          {/* ── Resume auto-redirect ─────────────────────────────────── */}
          {paused && !leaving && (
            <button
              onClick={() => { setPaused(false); setSeconds(COUNTDOWN_SEC) }}
              className="btn-secondary w-full mt-3"
            >
              Reactivar redirección automática
            </button>
          )}
        </div>

        {/* ── Capabilities preview ─────────────────────────────────────── */}
        <div className="mb-6">
          <p
            className="text-xs font-semibold uppercase tracking-widest text-center mb-3"
            style={{ color: '#2A2A2A' }}
          >
            Accederás a
          </p>
          <div className="flex flex-wrap gap-2 justify-center">
            {SOC_CAPS.map(cap => (
              <span key={cap} className="chip-orange text-xs">
                {cap}
              </span>
            ))}
          </div>
        </div>

        {/* ── Footer ───────────────────────────────────────────────────── */}
        {/* Entrada self-service para clientes (S113) */}
        <p className="text-center text-xs mb-3" style={{ color: '#5A5A5A' }}>
          ¿Cliente nuevo?{' '}
          <a href="/register" style={{ color: '#E85D04' }}>Crea tu cuenta</a>
          {' · '}
          <a href="/login/password" style={{ color: '#8A8A8A' }}>acceso con contraseña</a>
        </p>
        <p className="text-center text-xs" style={{ color: '#1E1E1E' }}>
          Acceso restringido — Personal autorizado PremosCorp
        </p>
      </div>
    </div>
  )
}

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="min-h-screen" style={{ background: '#0A0A0A' }} />}>
      <LoginGateway />
    </Suspense>
  )
}
