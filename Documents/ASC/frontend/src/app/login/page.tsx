'use client'
import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { login, isAuthenticated, initAuth } from '@/lib/auth'
import { Shield, Eye, EyeOff, AlertCircle } from 'lucide-react'

export default function LoginPage() {
  const router  = useRouter()
  const [email, setEmail]       = useState('')
  const [password, setPassword] = useState('')
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')

  useEffect(() => {
    initAuth()
    if (isAuthenticated()) router.replace('/')
  }, [router])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(email, password)
      router.replace('/')
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Credenciales inválidas')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4"
      style={{
        background: '#0A0A0A',
        backgroundImage:
          'radial-gradient(ellipse at 20% 50%, rgba(232,93,4,0.07) 0%, transparent 55%), ' +
          'radial-gradient(ellipse at 80% 20%, rgba(139,30,30,0.07) 0%, transparent 55%)',
      }}
    >
      <div className="w-full max-w-sm animate-fade-in">

        {/* ── Brand header ─────────────────────────────────── */}
        <div className="text-center mb-8">
          {/* Logo */}
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-5"
            style={{
              background: 'linear-gradient(135deg, #C44D03 0%, #E85D04 100%)',
              boxShadow: '0 0 32px rgba(232,93,4,0.35), 0 8px 24px rgba(0,0,0,0.5)',
            }}>
            <Shield size={30} color="#fff" />
          </div>

          <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#EAEAEA' }}>
            Premos<span style={{ color: '#E85D04' }}>Corp</span>
          </h1>
          <p className="text-sm mt-1 font-medium" style={{ color: '#5A5A5A' }}>
            Analizador de Seguridad Cibernética
          </p>
        </div>

        {/* ── Form card ────────────────────────────────────── */}
        <div
          className="rounded-2xl p-8"
          style={{
            background: 'rgba(16,16,16,0.85)',
            border: '1px solid rgba(255,255,255,0.07)',
            boxShadow: '0 8px 40px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.05)',
            backdropFilter: 'blur(12px)',
          }}
        >
          {/* Card inner top accent */}
          <div
            className="absolute top-0 left-1/2 -translate-x-1/2 h-px w-2/3 pointer-events-none"
            style={{ background: 'linear-gradient(90deg, transparent, rgba(232,93,4,0.3), transparent)' }}
          />

          <form onSubmit={handleSubmit} className="space-y-5">

            {/* Email */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-widest mb-2"
                     style={{ color: '#5A5A5A' }}>
                Correo electrónico
              </label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                autoComplete="email"
                placeholder="analista@premoscorp.com"
                className="input-asc"
              />
            </div>

            {/* Password */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-widest mb-2"
                     style={{ color: '#5A5A5A' }}>
                Contraseña
              </label>
              <div className="relative">
                <input
                  type={showPass ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  autoComplete="current-password"
                  placeholder="••••••••"
                  className="input-asc pr-11"
                />
                <button
                  type="button"
                  onClick={() => setShowPass(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
                  style={{ color: '#3A3A3A' }}
                  onMouseEnter={e => (e.currentTarget.style.color = '#A0A0A0')}
                  onMouseLeave={e => (e.currentTarget.style.color = '#3A3A3A')}
                >
                  {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div
                className="flex items-center gap-2.5 px-4 py-3 rounded-xl text-sm"
                style={{
                  background: 'rgba(192,21,46,0.1)',
                  border: '1px solid rgba(192,21,46,0.3)',
                  color: '#E8526E',
                }}
              >
                <AlertCircle size={15} className="flex-shrink-0" />
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full py-3 mt-2"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"/>
                  </svg>
                  Autenticando...
                </span>
              ) : 'Iniciar sesión'}
            </button>
          </form>
        </div>

        {/* Footer note */}
        <p className="text-center text-xs mt-6" style={{ color: '#2A2A2A' }}>
          Acceso restringido — Personal autorizado PremosCorp
        </p>
      </div>
    </div>
  )
}
