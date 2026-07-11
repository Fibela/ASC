'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { ShieldCheck, Building2, ChevronRight, Loader2, AlertCircle } from 'lucide-react'
import { ssoCompleteOnboarding } from '@/lib/api'
import { getAccessToken } from '@/lib/auth'

type Step = 'welcome' | 'configure' | 'done'

export default function OnboardingPage() {
  const router = useRouter()
  const [step, setStep] = useState<Step>('welcome')
  const [tenantName, setTenantName] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Guard: redirect to login if no token
  useEffect(() => {
    if (!getAccessToken()) router.replace('/login')
  }, [router])

  async function handleComplete() {
    setSaving(true)
    setError(null)
    try {
      await ssoCompleteOnboarding(tenantName.trim() || undefined)
      setStep('done')
      // Short pause so the user sees the success message, then go to dashboard
      setTimeout(() => router.replace('/'), 1800)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Error al guardar la configuración')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="min-h-screen bg-navy-900 flex items-center justify-center p-4">
      <div className="w-full max-w-lg">

        {/* Brand header */}
        <div className="flex items-center gap-3 mb-8">
          <div className="w-10 h-10 rounded-lg bg-cyan-600/20 border border-cyan-700/40 flex items-center justify-center">
            <ShieldCheck size={22} className="text-cyan-400" />
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-widest">PremosCorp</p>
            <p className="text-sm font-bold text-white">Advanced Security Center</p>
          </div>
        </div>

        {/* Card */}
        <div className="bg-navy-800 border border-navy-700 rounded-xl p-8 shadow-2xl">

          {step === 'welcome' && (
            <>
              <div className="mb-6">
                <h1 className="text-xl font-bold text-white mb-2">¡Bienvenido a ASC!</h1>
                <p className="text-sm text-gray-400">
                  Tu cuenta fue creada automáticamente a través del portal PremosCorp.
                  Antes de acceder al panel, configura tu workspace en segundos.
                </p>
              </div>

              <div className="space-y-3 mb-8">
                {[
                  { icon: '🛡️', label: 'Monitoreo SOC en tiempo real' },
                  { icon: '🔍', label: 'Detección de amenazas y MITRE ATT&CK' },
                  { icon: '📊', label: 'Reportes ejecutivos y playbooks SOAR' },
                ].map(item => (
                  <div key={item.label} className="flex items-center gap-3 text-sm text-gray-300">
                    <span className="text-base">{item.icon}</span>
                    <span>{item.label}</span>
                  </div>
                ))}
              </div>

              <button
                onClick={() => setStep('configure')}
                className="w-full flex items-center justify-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-2.5 rounded-lg transition-colors text-sm"
              >
                Comenzar configuración <ChevronRight size={16} />
              </button>
            </>
          )}

          {step === 'configure' && (
            <>
              <div className="mb-6">
                <h2 className="text-lg font-bold text-white mb-1">Configura tu workspace</h2>
                <p className="text-xs text-gray-500">
                  Puedes dejar el nombre por defecto o personalizarlo. Siempre podrás cambiarlo desde Configuración.
                </p>
              </div>

              <div className="mb-6">
                <label className="flex items-center gap-2 text-xs text-gray-400 mb-2">
                  <Building2 size={13} /> Nombre del workspace
                </label>
                <input
                  type="text"
                  value={tenantName}
                  onChange={e => setTenantName(e.target.value)}
                  placeholder="ej. PremosCorp SOC · Equipo de Seguridad"
                  maxLength={255}
                  className="w-full bg-navy-900 border border-navy-600 rounded-lg px-3 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-700 transition-colors"
                />
                <p className="mt-1.5 text-xs text-gray-600">
                  Opcional — si lo dejas vacío, se usará el nombre generado automáticamente.
                </p>
              </div>

              {error && (
                <div className="mb-4 flex items-center gap-2 bg-red-900/20 border border-red-700/50 rounded-lg p-3 text-xs text-red-400">
                  <AlertCircle size={13} />
                  <span>{error}</span>
                </div>
              )}

              <div className="flex gap-3">
                <button
                  onClick={() => setStep('welcome')}
                  disabled={saving}
                  className="px-4 py-2.5 text-sm text-gray-400 hover:text-white border border-navy-600 rounded-lg transition-colors disabled:opacity-40"
                >
                  Atrás
                </button>
                <button
                  onClick={handleComplete}
                  disabled={saving}
                  className="flex-1 flex items-center justify-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-2.5 rounded-lg transition-colors text-sm disabled:opacity-40"
                >
                  {saving ? (
                    <><Loader2 size={15} className="animate-spin" /> Guardando…</>
                  ) : (
                    <>Acceder al panel <ChevronRight size={16} /></>
                  )}
                </button>
              </div>
            </>
          )}

          {step === 'done' && (
            <div className="text-center py-4">
              <div className="w-14 h-14 rounded-full bg-cyan-600/20 border border-cyan-700/40 flex items-center justify-center mx-auto mb-4">
                <ShieldCheck size={28} className="text-cyan-400" />
              </div>
              <h2 className="text-lg font-bold text-white mb-2">¡Todo listo!</h2>
              <p className="text-sm text-gray-400 mb-1">Redirigiendo al panel de seguridad…</p>
              <div className="mt-4 flex justify-center">
                <Loader2 size={18} className="text-cyan-500 animate-spin" />
              </div>
            </div>
          )}

        </div>

        <p className="mt-4 text-center text-xs text-gray-600">
          ASC PremosCorp · Calidad sobre Comodidad
        </p>
      </div>
    </div>
  )
}
