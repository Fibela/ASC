'use client'
import { useEffect, useState } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'
import { getIoCs, createIoC } from '@/lib/api'
import { Database, Plus, Copy, CheckCircle2, RefreshCw, X } from 'lucide-react'

const IOC_TYPES = ['hash_md5', 'hash_sha1', 'hash_sha256', 'ip', 'domain', 'url', 'mutex', 'registry_key']

// P64: PremosCorp palette for IoC types
const TYPE_STYLE: Record<string, { bg: string; color: string }> = {
  hash_md5:     { bg: 'rgba(90,90,90,0.12)',   color: '#5A5A5A' },
  hash_sha1:    { bg: 'rgba(90,90,90,0.12)',   color: '#5A5A5A' },
  hash_sha256:  { bg: 'rgba(90,90,90,0.12)',   color: '#5A5A5A' },
  ip:           { bg: 'rgba(232,93,4,0.12)',   color: '#FF7A25' },
  domain:       { bg: 'rgba(242,194,5,0.10)',  color: '#F2C205' },
  url:          { bg: 'rgba(242,194,5,0.10)',  color: '#F2C205' },
  mutex:        { bg: 'rgba(192,21,46,0.12)',  color: '#E8526E' },
  registry_key: { bg: 'rgba(192,21,46,0.12)',  color: '#E8526E' },
}

function confidenceColor(c: number): string {
  if (c >= 0.8) return '#E8526E'
  if (c >= 0.5) return '#F2C205'
  return '#3FD175'
}

async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    try {
      const el = document.createElement('textarea')
      el.value = text
      el.style.position = 'fixed'
      el.style.opacity  = '0'
      document.body.appendChild(el)
      el.focus(); el.select()
      document.execCommand('copy')
      document.body.removeChild(el)
      return true
    } catch { return false }
  }
}

export default function IoCsPage() {
  const { isReady } = useAuthGuard()
  const [iocs, setIoCs]       = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter]   = useState({ ioc_type: '', limit: 100 })
  const [showAdd, setShowAdd] = useState(false)
  const [copied, setCopied]   = useState<string | null>(null)
  const [form, setForm]       = useState({ ioc_type: 'hash_sha256', value: '', source: '', confidence: 0.9 })
  const [saving, setSaving]   = useState(false)

  async function load() {
    setLoading(true)
    try {
      const data = await getIoCs({ ioc_type: filter.ioc_type || undefined, limit: filter.limit })
      setIoCs(data)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  useEffect(() => {
    if (!isReady) return
    load()
    const id = setInterval(load, 30_000)  // tiempo real (S117.3)
    return () => clearInterval(id)
  }, [filter, isReady])

  async function addIoC() {
    setSaving(true)
    try {
      await createIoC(form)
      setShowAdd(false)
      setForm({ ioc_type: 'hash_sha256', value: '', source: '', confidence: 0.9 })
      await load()
    } catch (e) { console.error(e) }
    finally { setSaving(false) }
  }

  async function copy(val: string) {
    const ok = await copyToClipboard(val)
    if (ok) {
      setCopied(val)
      setTimeout(() => setCopied(null), 1500)
    }
  }

  if (!isReady) return <AuthLoader />

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
            <Database size={18} style={{ color: '#E85D04' }} />
            <div>
              <h1 className="text-sm font-bold leading-none" style={{ color: '#EAEAEA' }}>
                Indicadores de Compromiso
              </h1>
              <p className="text-xs mt-0.5" style={{ color: '#3A3A3A' }}>
                Hashes · IPs · Dominios · Mutexes · Claves de registro
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowAdd(v => !v)}
            className="btn-primary flex items-center gap-2 text-xs py-1.5 px-3"
          >
            {showAdd ? <X size={12} /> : <Plus size={12} />}
            {showAdd ? 'Cancelar' : 'Agregar IoC'}
          </button>
        </div>

        <div className="p-6 space-y-5 animate-fade-in">

          {/* Add IoC form */}
          {showAdd && (
            <div className="card p-5 max-w-lg animate-fade-in">
              <h3 className="text-sm font-semibold mb-4" style={{ color: '#E85D04' }}>
                Nuevo Indicador de Compromiso
              </h3>
              <div className="space-y-3">
                <div>
                  <label className="block text-xs mb-1.5" style={{ color: '#A0A0A0' }}>Tipo</label>
                  <select
                    value={form.ioc_type}
                    onChange={e => setForm(f => ({ ...f, ioc_type: e.target.value }))}
                    className="input-asc"
                  >
                    {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs mb-1.5" style={{ color: '#A0A0A0' }}>Valor</label>
                  <input
                    value={form.value}
                    onChange={e => setForm(f => ({ ...f, value: e.target.value }))}
                    placeholder="hash / IP / dominio / mutex..."
                    className="input-asc font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs mb-1.5" style={{ color: '#A0A0A0' }}>Fuente</label>
                  <input
                    value={form.source}
                    onChange={e => setForm(f => ({ ...f, source: e.target.value }))}
                    placeholder="VirusTotal, OSINT, análisis forense..."
                    className="input-asc"
                  />
                </div>
                <div>
                  <label className="block text-xs mb-1.5" style={{ color: '#A0A0A0' }}>
                    Confianza:{' '}
                    <span style={{ color: confidenceColor(form.confidence) }} className="font-mono font-bold">
                      {form.confidence.toFixed(2)}
                    </span>
                  </label>
                  <input
                    type="range" min={0} max={1} step={0.05}
                    value={form.confidence}
                    onChange={e => setForm(f => ({ ...f, confidence: parseFloat(e.target.value) }))}
                    className="w-full"
                    style={{ accentColor: '#E85D04' }}
                  />
                </div>
                <div className="flex gap-2 pt-1">
                  <button
                    onClick={addIoC}
                    disabled={!form.value || saving}
                    className="btn-primary flex-1 text-xs disabled:opacity-50"
                  >
                    {saving ? 'Guardando...' : 'Guardar IoC'}
                  </button>
                  <button
                    onClick={() => setShowAdd(false)}
                    className="btn-secondary text-xs px-4"
                  >
                    Cancelar
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Filters */}
          <div className="flex flex-wrap gap-3 items-center">
            <select
              value={filter.ioc_type}
              onChange={e => setFilter(f => ({ ...f, ioc_type: e.target.value }))}
              className="input-asc"
              style={{ width: 'auto', minWidth: 180 }}
            >
              <option value="">Todos los tipos</option>
              {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <select
              value={filter.limit}
              onChange={e => setFilter(f => ({ ...f, limit: Number(e.target.value) }))}
              className="input-asc"
              style={{ width: 'auto', minWidth: 130 }}
            >
              {[50, 100, 250, 500].map(n => <option key={n} value={n}>{n} IoCs</option>)}
            </select>
            <span className="text-xs ml-auto" style={{ color: '#3A3A3A' }}>
              {iocs.length} indicador{iocs.length !== 1 ? 'es' : ''}
            </span>
          </div>

          {/* Table */}
          {loading ? (
            <div className="flex items-center gap-3 py-16 justify-center" style={{ color: '#3A3A3A' }}>
              <RefreshCw size={18} className="animate-spin" style={{ color: '#E85D04' }} />
              <span className="text-sm">Cargando indicadores...</span>
            </div>
          ) : (
            <div className="card overflow-x-auto">
              <table className="table-asc">
                <thead>
                  <tr>
                    <th>Tipo</th>
                    <th>Valor</th>
                    <th>Fuente</th>
                    <th>Confianza</th>
                    <th>Registrado</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.length === 0 && (
                    <tr>
                      <td colSpan={6} className="text-center py-12 text-sm" style={{ color: '#3A3A3A' }}>
                        <Database size={28} className="mx-auto mb-2 opacity-20" />
                        Sin IoCs registrados
                      </td>
                    </tr>
                  )}
                  {iocs.map((ioc: any) => {
                    const ts = TYPE_STYLE[ioc.ioc_type] ?? TYPE_STYLE.hash_md5
                    return (
                      <tr key={ioc.id}>
                        <td>
                          <span
                            className="text-xs font-mono px-2 py-0.5 rounded-lg"
                            style={{ background: ts.bg, color: ts.color }}
                          >
                            {ioc.ioc_type}
                          </span>
                        </td>
                        <td className="font-mono text-xs max-w-xs truncate" style={{ color: '#EAEAEA' }}>
                          {ioc.value}
                        </td>
                        <td className="text-xs" style={{ color: '#5A5A5A' }}>{ioc.source ?? '—'}</td>
                        <td>
                          <span
                            className="font-mono text-xs font-bold"
                            style={{ color: confidenceColor(Number(ioc.confidence)) }}
                          >
                            {Number(ioc.confidence).toFixed(2)}
                          </span>
                        </td>
                        <td className="text-xs font-mono" style={{ color: '#3A3A3A' }}>
                          {ioc.created_at?.slice(0, 10)}
                        </td>
                        <td>
                          <button
                            onClick={() => copy(ioc.value)}
                            className="transition-colors"
                            style={{ color: copied === ioc.value ? '#3FD175' : '#3A3A3A' }}
                          >
                            {copied === ioc.value
                              ? <CheckCircle2 size={13} />
                              : <Copy size={13} />}
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
