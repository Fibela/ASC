'use client'
import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { login, isAuthenticated, initAuth } from '@/lib/auth'
import { Shield, Eye, EyeOff } from 'lucide-react'

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
    <div className="min-h-screen flex items-center justify-center bg-[#0d1b2a]">
      <div className="w-full max-w-sm">

        {/* Logo / Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl mb-4"
            style={{ background: 'rgba(0,180,216,0.1)', border: '1px solid rgba(0,180,216,0.3)' }}>
            <Shield className="text-cyan-400" size={28} />
          </div>
          <h1 className="text-2xl font-bold text-white">ASC PremosCorp</h1>
          <p className="text-gray-500 text-sm mt-1">Advanced Security Center</p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit}
          className="rounded-xl p-8"
          style={{ background: '#1a2d42', border: '1px solid rgba(0,180,216,0.15)' }}>

          <div className="mb-5">
            <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              autoComplete="email"
              placeholder="analista@premoscorp.com"
              className="w-full rounded-lg px-4 py-3 text-sm text-white outline-none transition-colors"
              style={{ background: '#0d1b2a', border: '1px solid rgba(0,180,216,0.2)' }}
              onFocus={e => e.target.style.borderColor = 'rgba(0,180,216,0.6)'}
              onBlur={e => e.target.style.borderColor = 'rgba(0,180,216,0.2)'}
            />
          </div>

          <div className="mb-6">
            <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
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
                className="w-full rounded-lg px-4 py-3 pr-10 text-sm text-white outline-none transition-colors"
                style={{ background: '#0d1b2a', border: '1px solid rgba(0,180,216,0.2)' }}
                onFocus={e => e.target.style.borderColor = 'rgba(0,180,216,0.6)'}
                onBlur={e => e.target.style.borderColor = 'rgba(0,180,216,0.2)'}
              />
              <button type="button" onClick={() => setShowPass(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors">
                {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {error && (
            <div className="mb-4 px-4 py-2 rounded-lg text-sm text-red-400"
              style={{ background: 'rgba(217,43,43,0.1)', border: '1px solid rgba(217,43,43,0.3)' }}>
              {error}
            </div>
          )}

          <button type="submit" disabled={loading}
            className="w-full py-3 rounded-lg font-semibold text-sm transition-opacity disabled:opacity-50"
            style={{ background: 'linear-gradient(135deg, #0096c7 0%, #00b4d8 100%)', color: '#0d1b2a' }}>
            {loading ? 'Autenticando...' : 'Iniciar sesión'}
          </button>
        </form>

        <p className="text-center text-xs text-gray-600 mt-6">
          PremosCorp ASC — Acceso restringido a personal autorizado
        </p>
      </div>
    </div>
  )
}
