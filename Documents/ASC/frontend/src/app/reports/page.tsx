'use client'
import { useState } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import { api } from '@/lib/api'
import { FileText, Download, RefreshCw, CheckCircle } from 'lucide-react'

const PERIODS = [
  { h: 6,   label: '6h' },
  { h: 12,  label: '12h' },
  { h: 24,  label: '24h (default)' },
  { h: 48,  label: '48h' },
  { h: 72,  label: '72h' },
  { h: 168, label: '7 días' },
]

const REPORT_INCLUDES = [
  'Resumen ejecutivo con postura de riesgo',
  'KPIs: MTTD, MTTR, tasa de FP',
  'Tabla de alertas clasificadas por severidad',
  'Cobertura de IoCs',
  'Branding PremosCorp certificado',
  'Marca CONFIDENCIAL',
]

export default function ReportsPage() {
  useAuthGuard()
  const [hours, setHours]   = useState(24)
  const [analyst, setAnalyst] = useState('SOC Analyst')
  const [loading, setLoading] = useState<'pdf' | 'html' | null>(null)
  const [error, setError]   = useState('')

  async function download(format: 'pdf' | 'html') {
    setLoading(format)
    setError('')
    try {
      const resp = await api.get(`/reports/${format}`, {
        params: { hours, analyst },
        responseType: format === 'pdf' ? 'blob' : 'text',
      })
      if (format === 'pdf') {
        const blob = new Blob([resp.data], { type: 'application/pdf' })
        const url  = URL.createObjectURL(blob)
        const a    = document.createElement('a')
        a.href     = url
        a.download = `ASC_Report_${new Date().toISOString().slice(0, 10)}.pdf`
        a.click()
        URL.revokeObjectURL(url)
      } else {
        const blob = new Blob([resp.data], { type: 'text/html; charset=utf-8' })
        const url  = URL.createObjectURL(blob)
        window.open(url, '_blank')
        setTimeout(() => URL.revokeObjectURL(url), 60_000)
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || 'Error al generar el reporte')
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 overflow-auto">

        {/* Sticky header */}
        <div
          className="sticky top-0 z-20 px-6 py-3 flex items-center justify-between"
          style={{
            background:     'rgba(10,10,10,0.92)',
            borderBottom:   '1px solid rgba(255,255,255,0.05)',
            backdropFilter: 'blur(12px)',
          }}
        >
          <div className="flex items-center gap-3">
            <FileText size={18} style={{ color: '#E85D04' }} />
            <div>
              <h1 className="text-sm font-bold leading-none" style={{ color: '#EAEAEA' }}>
                Generación de Reportes
              </h1>
              <p className="text-xs mt-0.5" style={{ color: '#3A3A3A' }}>
                PDF · HTML · Firmados con JWT · Branding PremosCorp
              </p>
            </div>
          </div>
        </div>

        <div className="p-6 space-y-5 animate-fade-in">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">

            {/* Config card */}
            <div className="card p-5 space-y-5">
              <div className="flex items-center gap-2">
                <div
                  className="w-8 h-8 rounded-xl flex items-center justify-center"
                  style={{ background: 'rgba(232,93,4,0.1)', border: '1px solid rgba(232,93,4,0.2)' }}
                >
                  <FileText size={16} style={{ color: '#E85D04' }} />
                </div>
                <div>
                  <h2 className="text-sm font-semibold" style={{ color: '#EAEAEA' }}>Configurar Reporte</h2>
                  <p className="text-xs" style={{ color: '#3A3A3A' }}>Período + analista firmante</p>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: '#A0A0A0' }}>
                    Período de análisis
                  </label>
                  <select
                    value={hours}
                    onChange={e => setHours(Number(e.target.value))}
                    className="input-asc"
                  >
                    {PERIODS.map(p => (
                      <option key={p.h} value={p.h}>{p.label}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: '#A0A0A0' }}>
                    Analista firmante
                  </label>
                  <input
                    value={analyst}
                    onChange={e => setAnalyst(e.target.value)}
                    className="input-asc"
                    placeholder="Nombre del analista SOC"
                  />
                </div>

                {error && (
                  <div
                    className="flex items-start gap-2 rounded-xl px-3 py-2 text-xs"
                    style={{ background: 'rgba(192,21,46,0.08)', border: '1px solid rgba(192,21,46,0.25)' }}
                  >
                    <span style={{ color: '#E8526E' }}>{error}</span>
                  </div>
                )}

                <div className="flex gap-3 pt-1">
                  <button
                    onClick={() => download('pdf')}
                    disabled={!!loading}
                    className="btn-primary flex items-center gap-2 flex-1 justify-center disabled:opacity-50"
                  >
                    {loading === 'pdf'
                      ? <RefreshCw size={13} className="animate-spin" />
                      : <Download size={13} />}
                    Descargar PDF
                  </button>
                  <button
                    onClick={() => download('html')}
                    disabled={!!loading}
                    className="btn-secondary flex items-center gap-2 flex-1 justify-center disabled:opacity-50"
                  >
                    {loading === 'html'
                      ? <RefreshCw size={13} className="animate-spin" />
                      : <FileText size={13} />}
                    Ver HTML
                  </button>
                </div>
              </div>
            </div>

            {/* Includes card */}
            <div className="card p-5 space-y-4">
              <div className="flex items-center gap-2">
                <div
                  className="w-8 h-8 rounded-xl flex items-center justify-center"
                  style={{ background: 'rgba(45,184,99,0.08)', border: '1px solid rgba(45,184,99,0.2)' }}
                >
                  <CheckCircle size={15} style={{ color: '#3FD175' }} />
                </div>
                <div>
                  <h2 className="text-sm font-semibold" style={{ color: '#EAEAEA' }}>El reporte incluye</h2>
                  <p className="text-xs" style={{ color: '#3A3A3A' }}>Secciones garantizadas por plantilla</p>
                </div>
              </div>

              <ul className="space-y-2">
                {REPORT_INCLUDES.map(item => (
                  <li key={item} className="flex items-center gap-2.5 text-xs" style={{ color: '#A0A0A0' }}>
                    <span
                      className="w-4 h-4 rounded-full flex items-center justify-center flex-shrink-0"
                      style={{ background: 'rgba(232,93,4,0.12)' }}
                    >
                      <span style={{ color: '#E85D04', fontSize: 8 }}>●</span>
                    </span>
                    {item}
                  </li>
                ))}
              </ul>

              <div
                className="rounded-xl px-3 py-2 text-xs"
                style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}
              >
                <p style={{ color: '#3A3A3A' }}>
                  Los reportes se descargan directamente con autenticación JWT.
                  El token no se expone en la URL ni en logs.
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
