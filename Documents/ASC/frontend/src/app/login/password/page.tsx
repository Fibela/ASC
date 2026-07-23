'use client'

// Login por contraseña (S113) — para clientes self-service (no staff SSO).
// La página /login es el gateway SSO al portal; esta es la entrada email+contraseña.
// Usa auth.login(), que guarda los tokens y habilita axios.
import { useState, type FormEvent } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Shield } from 'lucide-react'
import { login, getMe, clearTokens } from '@/lib/auth'

function errMessage(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (detail && typeof detail === 'object' && 'message' in detail) {
    return String((detail as { message: unknown }).message)
  }
  return (e as { message?: string })?.message || fallback
}

const inputStyle =
  'w-full rounded-lg px-3 py-2.5 text-sm text-gray-100 placeholder-gray-600 outline-none transition-colors'

export default function PasswordLoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await login(email.trim(), password)
      // Sondeo con /auth/me: pasa por el gate de deps._resolve_user. Si el email
      // no está verificado devuelve 403 email_verification_required; avisamos aquí
      // en vez de dejar al usuario entrar a un dashboard que fallaría en cada llamada.
      try {
        await getMe()
      } catch (probe) {
        const d = (probe as { response?: { data?: { detail?: unknown }; status?: number } })?.response
        const detail = typeof d?.data?.detail === 'string' ? d.data.detail : ''
        if (d?.status === 403 && detail.includes('email_verification_required')) {
          clearTokens()
          setError('Tu email aún no está verificado. Revisa tu bandeja de entrada y haz clic en el enlace.')
          setSubmitting(false)
          return
        }
        // otro error en el sondeo: continúa; el guard de la app lo manejará.
      }
      router.replace('/')
    } catch (err) {
      setError(errMessage(err, 'No se pudo iniciar sesión. Verifica tus credenciales.'))
      setSubmitting(false)
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4 py-14"
      style={{
        background: '#0A0A0A',
        backgroundImage:
          'radial-gradient(ellipse at 15% 50%, rgba(232,93,4,0.065) 0%, transparent 55%),' +
          'radial-gradient(ellipse at 85% 15%, rgba(139,30,30,0.065) 0%, transparent 55%)',
      }}
    >
      <div className="w-full max-w-[420px] animate-fade-in">
        <div className="text-center mb-7">
          <div
            className="inline-flex items-center justify-center w-14 h-14 rounded-2xl mb-4"
            style={{
              background: 'linear-gradient(135deg, #C44D03 0%, #E85D04 100%)',
              boxShadow: '0 0 36px rgba(232,93,4,0.38), 0 8px 24px rgba(0,0,0,0.55)',
            }}
          >
            <Shield size={26} color="#fff" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#EAEAEA' }}>
            Premos<span style={{ color: '#E85D04' }}>Corp</span> ASC
          </h1>
          <p className="text-sm mt-1" style={{ color: '#5A5A5A' }}>
            Inicia sesión con tu cuenta
          </p>
        </div>

        <div className="card-orange p-7">
          <form onSubmit={handleSubmit} className="space-y-3.5">
            {error && (
              <div
                className="text-xs px-3 py-2.5 rounded-lg"
                style={{ background: 'rgba(192,21,46,0.10)', border: '1px solid rgba(192,21,46,0.3)', color: '#F2A0A0' }}
              >
                {error}
              </div>
            )}

            <label className="block">
              <span className="text-xs font-medium block mb-1.5" style={{ color: '#A0A0A0' }}>
                Email
              </span>
              <input
                className={inputStyle}
                style={{ background: '#141414', border: '1px solid #2A2A2A' }}
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="tu@empresa.com"
                autoComplete="email"
                required
              />
            </label>

            <label className="block">
              <span className="text-xs font-medium block mb-1.5" style={{ color: '#A0A0A0' }}>
                Contraseña
              </span>
              <input
                className={inputStyle}
                style={{ background: '#141414', border: '1px solid #2A2A2A' }}
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="current-password"
                required
              />
            </label>

            <button type="submit" disabled={submitting} className="btn-primary w-full py-2.5 mt-1">
              {submitting ? 'Entrando…' : 'Iniciar sesión'}
            </button>
          </form>

          <div className="divider my-5" />
          <p className="text-center text-xs" style={{ color: '#5A5A5A' }}>
            Staff PremosCorp:{' '}
            <Link href="/login" style={{ color: '#E85D04' }}>
              acceso SSO
            </Link>
          </p>
        </div>

        <p className="text-center text-xs mt-5" style={{ color: '#5A5A5A' }}>
          ¿No tienes cuenta?{' '}
          <Link href="/register" style={{ color: '#E85D04' }}>
            Crea una
          </Link>
        </p>
      </div>
    </div>
  )
}
