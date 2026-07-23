'use client'

// Registro self-service (S113) — alta de tenant + admin. El backend crea la cuenta
// con email_verified=False; el login queda bloqueado hasta verificar el email
// (gate en /auth/login). Tras registrar, el usuario recibe el enlace de verificación.
import { useState, type FormEvent, type ReactNode } from 'react'
import Link from 'next/link'
import { Shield } from 'lucide-react'
import { registerTenant } from '@/lib/api'

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$/
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

function slugify(v: string): string {
  return v
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 100)
}

function errMessage(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (detail && typeof detail === 'object' && 'message' in detail) {
    return String((detail as { message: unknown }).message)
  }
  const m = (e as { message?: string })?.message
  return m || fallback
}

const inputStyle =
  'w-full rounded-lg px-3 py-2.5 text-sm text-gray-100 placeholder-gray-600 outline-none transition-colors'

export default function RegisterPage() {
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [tenantName, setTenantName] = useState('')
  const [slug, setSlug] = useState('')
  const [slugEdited, setSlugEdited] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)

  const effectiveSlug = slugEdited ? slug : slugify(tenantName)

  function validate(): string | null {
    if (fullName.trim().length < 1) return 'Ingresa tu nombre completo.'
    if (!EMAIL_RE.test(email)) return 'Ingresa un email válido.'
    if (password.length < 8) return 'La contraseña debe tener al menos 8 caracteres.'
    if (tenantName.trim().length < 2) return 'El nombre de la organización es muy corto.'
    if (!SLUG_RE.test(effectiveSlug))
      return 'El identificador (slug) debe tener 3–100 caracteres: minúsculas, números y guiones, sin guion al inicio/fin.'
    return null
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    const v = validate()
    if (v) {
      setError(v)
      return
    }
    setSubmitting(true)
    try {
      const res = await registerTenant({
        tenant_name: tenantName.trim(),
        tenant_slug: effectiveSlug,
        email: email.trim(),
        password,
        full_name: fullName.trim(),
      })
      setDone(res.message || 'Cuenta creada. Revisa tu email para verificar tu cuenta.')
    } catch (err) {
      setError(errMessage(err, 'No se pudo crear la cuenta. Inténtalo de nuevo.'))
    } finally {
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
      <div className="w-full max-w-[440px] animate-fade-in">
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
            Crea tu cuenta y organización
          </p>
        </div>

        <div className="card-orange p-7">
          {done ? (
            <div className="text-center py-4">
              <div
                className="inline-flex items-center justify-center w-12 h-12 rounded-full mb-4"
                style={{ background: 'rgba(62,207,142,0.12)', border: '1px solid rgba(62,207,142,0.3)' }}
              >
                <span style={{ color: '#3ECF8E', fontSize: 22 }}>✓</span>
              </div>
              <h2 className="text-lg font-bold mb-2" style={{ color: '#EAEAEA' }}>
                Revisa tu correo
              </h2>
              <p className="text-sm leading-relaxed mb-5" style={{ color: '#9A9A9A' }}>
                {done}
              </p>
              <Link href="/login/password" className="btn-secondary w-full inline-block text-center">
                Ir a iniciar sesión
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-3.5">
              {error && (
                <div
                  className="text-xs px-3 py-2.5 rounded-lg"
                  style={{ background: 'rgba(192,21,46,0.10)', border: '1px solid rgba(192,21,46,0.3)', color: '#F2A0A0' }}
                >
                  {error}
                </div>
              )}

              <Field label="Nombre completo">
                <input
                  className={inputStyle}
                  style={{ background: '#141414', border: '1px solid #2A2A2A' }}
                  value={fullName}
                  onChange={e => setFullName(e.target.value)}
                  placeholder="Ada Lovelace"
                  autoComplete="name"
                />
              </Field>

              <Field label="Email">
                <input
                  className={inputStyle}
                  style={{ background: '#141414', border: '1px solid #2A2A2A' }}
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="tu@empresa.com"
                  autoComplete="email"
                />
              </Field>

              <Field label="Contraseña" hint="Mínimo 8 caracteres">
                <input
                  className={inputStyle}
                  style={{ background: '#141414', border: '1px solid #2A2A2A' }}
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="new-password"
                />
              </Field>

              <Field label="Organización">
                <input
                  className={inputStyle}
                  style={{ background: '#141414', border: '1px solid #2A2A2A' }}
                  value={tenantName}
                  onChange={e => setTenantName(e.target.value)}
                  placeholder="Mi Empresa S.A."
                />
              </Field>

              <Field label="Identificador (slug)" hint={`Se usará en tu espacio: ${effectiveSlug || 'mi-empresa'}`}>
                <input
                  className={inputStyle}
                  style={{ background: '#141414', border: '1px solid #2A2A2A' }}
                  value={effectiveSlug}
                  onChange={e => {
                    setSlugEdited(true)
                    setSlug(slugify(e.target.value))
                  }}
                  placeholder="mi-empresa"
                />
              </Field>

              <button type="submit" disabled={submitting} className="btn-primary w-full py-2.5 mt-1">
                {submitting ? 'Creando cuenta…' : 'Crear cuenta'}
              </button>
            </form>
          )}
        </div>

        {!done && (
          <p className="text-center text-xs mt-5" style={{ color: '#5A5A5A' }}>
            ¿Ya tienes cuenta?{' '}
            <Link href="/login/password" style={{ color: '#E85D04' }}>
              Inicia sesión
            </Link>
          </p>
        )}
      </div>
    </div>
  )
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs font-medium block mb-1.5" style={{ color: '#A0A0A0' }}>
        {label}
      </span>
      {children}
      {hint && (
        <span className="text-[11px] block mt-1" style={{ color: '#4A4A4A' }}>
          {hint}
        </span>
      )}
    </label>
  )
}
