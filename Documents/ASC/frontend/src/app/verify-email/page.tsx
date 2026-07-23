'use client'

// Verificación de email (S113) — el enlace del correo apunta aquí con ?token=...
// Llama a POST /onboarding/verify-email; en éxito el backend activa email_verified
// y el login por contraseña queda habilitado.
import { Suspense, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { Shield } from 'lucide-react'
import { verifyEmail } from '@/lib/api'

type Phase = 'verifying' | 'success' | 'error' | 'notoken'

function errMessage(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (detail && typeof detail === 'object' && 'message' in detail) {
    return String((detail as { message: unknown }).message)
  }
  return (e as { message?: string })?.message || fallback
}

function VerifyEmailInner() {
  const params = useSearchParams()
  const token = params.get('token')
  const [phase, setPhase] = useState<Phase>('verifying')
  const [message, setMessage] = useState('')
  const ran = useRef(false)

  useEffect(() => {
    if (ran.current) return
    ran.current = true
    if (!token) {
      setPhase('notoken')
      return
    }
    verifyEmail(token)
      .then(res => {
        setMessage(res.message || 'Email verificado correctamente. Ya puedes iniciar sesión.')
        setPhase('success')
      })
      .catch(err => {
        setMessage(errMessage(err, 'No se pudo verificar el email. El enlace puede haber expirado.'))
        setPhase('error')
      })
  }, [token])

  const ok = phase === 'success'
  const badge = ok ? '#3ECF8E' : phase === 'verifying' ? '#E85D04' : '#C0152E'

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4 py-14"
      style={{
        background: '#0A0A0A',
        backgroundImage: 'radial-gradient(ellipse at 50% 20%, rgba(232,93,4,0.06) 0%, transparent 55%)',
      }}
    >
      <div className="w-full max-w-[420px] animate-fade-in text-center">
        <div
          className="inline-flex items-center justify-center w-14 h-14 rounded-2xl mb-5"
          style={{
            background: 'linear-gradient(135deg, #C44D03 0%, #E85D04 100%)',
            boxShadow: '0 0 36px rgba(232,93,4,0.38)',
          }}
        >
          <Shield size={26} color="#fff" />
        </div>

        <div className="card-orange p-8">
          <div
            className="inline-flex items-center justify-center w-12 h-12 rounded-full mb-4"
            style={{ background: `${badge}1F`, border: `1px solid ${badge}55` }}
          >
            <span style={{ color: badge, fontSize: 22 }}>
              {ok ? '✓' : phase === 'verifying' ? '…' : '!'}
            </span>
          </div>

          <h1 className="text-lg font-bold mb-2" style={{ color: '#EAEAEA' }}>
            {phase === 'verifying' && 'Verificando tu email…'}
            {phase === 'success' && 'Email verificado'}
            {phase === 'error' && 'No se pudo verificar'}
            {phase === 'notoken' && 'Enlace inválido'}
          </h1>

          <p className="text-sm leading-relaxed mb-5" style={{ color: '#9A9A9A' }}>
            {phase === 'verifying' && 'Un momento por favor.'}
            {(phase === 'success' || phase === 'error') && message}
            {phase === 'notoken' && 'Falta el token de verificación en el enlace. Revisa el correo que te enviamos.'}
          </p>

          {phase === 'success' && (
            <Link href="/login/password" className="btn-primary w-full inline-block text-center py-2.5">
              Iniciar sesión
            </Link>
          )}
          {(phase === 'error' || phase === 'notoken') && (
            <Link href="/register" className="btn-secondary w-full inline-block text-center">
              Volver al registro
            </Link>
          )}
        </div>
      </div>
    </div>
  )
}

export default function VerifyEmailPage() {
  return (
    <Suspense fallback={<div className="min-h-screen" style={{ background: '#0A0A0A' }} />}>
      <VerifyEmailInner />
    </Suspense>
  )
}
