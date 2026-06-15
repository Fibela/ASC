'use client'
import { useEffect, useState } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import { getIoCs, createIoC } from '@/lib/api'
import { Database, Plus, Copy, CheckCircle2 } from 'lucide-react'

const IOC_TYPES = ['hash_md5', 'hash_sha1', 'hash_sha256', 'ip', 'domain', 'url', 'mutex', 'registry_key']

async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    // Fallback for non-HTTPS or older browsers
    try {
      const el = document.createElement('textarea')
      el.value = text
      el.style.position = 'fixed'
      el.style.opacity  = '0'
      document.body.appendChild(el)
      el.focus()
      el.select()
      document.execCommand('copy')
      document.body.removeChild(el)
      return true
    } catch {
      return false
    }
  }
}

export default function IoCsPage() {
  useAuthGuard()
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
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [filter])

  async function addIoC() {
    setSaving(true)
    try {
      await createIoC(form)
      setShowAdd(false)
      setForm({ ioc_type: 'hash_sha256', value: '', source: '', confidence: 0.9 })
      await load()
    } catch (e) {
      console.error(e)
    } finally {
      setSaving(false)
    }
  }

  async function copy(val: string) {
    const ok = await copyToClipboard(val)
    if (ok) {
      setCopied(val)
      setTimeout(() => setCopied(null), 1500)
    }
  }

  const TYPE_COLOR: Record<string, string> = {
    hash_md5: 'text-gray-400', hash_sha1: 'text-gray-400', hash_sha256: 'text-gray-400',
    ip: 'text-orange-400', domain: 'text-yellow-400', url: 'text-yellow-400',
    mutex: 'text-red-400', registry_key: 'text-red-400',
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6 overflow-auto">
        <div className="flex items-center justify-between mb-1">
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Database className="text-cyan-400" size={22} />
            Indicadores de Compromiso
          </h1>
          <button onClick={() => setShowAdd(v => !v)} className="btn-primary flex items-center gap-2 text-sm py-1.5">
            <Plus size={14} /> Agregar IoC
          </button>
        </div>
        <p className="text-gray-500 text-xs mb-6">Hashes, IPs, dominios, mutexes y claves de registro comprometidos</p>

        {/* Add form */}
        {showAdd && (
          <div className="card max-w-lg mb-6">
            <h3 className="text-cyan-400 font-semibold mb-4">Nuevo Indicador de Compromiso</h3>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Tipo</label>
                <select value={form.ioc_type} onChange={e => setForm(f => ({ ...f, ioc_type: e.target.value }))}
                  className="w-full bg-navy-900 border border-navy-700 text-sm text-gray-300 rounded px-3 py-2 outline-none focus:border-cyan-400">
                  {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Valor</label>
                <input value={form.value} onChange={e => setForm(f => ({ ...f, value: e.target.value }))}
                  placeholder="hash / IP / dominio / mutex..."
                  className="w-full bg-navy-900 border border-navy-700 rounded px-3 py-2 text-white text-sm font-mono outline-none focus:border-cyan-400" />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Fuente</label>
                <input value={form.source} onChange={e => setForm(f => ({ ...f, source: e.target.value }))}
                  placeholder="VirusTotal, OSINT, análisis forense..."
                  className="w-full bg-navy-900 border border-navy-700 rounded px-3 py-2 text-white text-sm outline-none focus:border-cyan-400" />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Confianza: {form.confidence}</label>
                <input type="range" min={0} max={1} step={0.05} value={form.confidence}
                  onChange={e => setForm(f => ({ ...f, confidence: parseFloat(e.target.value) }))}
                  className="w-full accent-cyan-400" />
              </div>
              <div className="flex gap-2 pt-1">
                <button onClick={addIoC} disabled={!form.value || saving} className="btn-primary flex-1 text-sm disabled:opacity-50">
                  {saving ? 'Guardando...' : 'Guardar IoC'}
                </button>
                <button onClick={() => setShowAdd(false)} className="bg-navy-700 text-gray-300 px-4 py-2 rounded text-sm hover:bg-navy-600">
                  Cancelar
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="flex gap-3 mb-5">
          <select value={filter.ioc_type} onChange={e => setFilter(f => ({ ...f, ioc_type: e.target.value }))}
            className="bg-navy-800 border border-navy-700 text-sm text-gray-300 rounded px-3 py-1.5 outline-none focus:border-cyan-400">
            <option value="">Todos los tipos</option>
            {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <select value={filter.limit} onChange={e => setFilter(f => ({ ...f, limit: Number(e.target.value) }))}
            className="bg-navy-800 border border-navy-700 text-sm text-gray-300 rounded px-3 py-1.5 outline-none focus:border-cyan-400">
            {[50, 100, 250, 500].map(n => <option key={n} value={n}>{n} IoCs</option>)}
          </select>
          <span className="text-xs text-gray-600 self-center">{iocs.length} registros</span>
        </div>

        {loading ? (
          <p className="text-gray-400 text-sm">Cargando IoCs...</p>
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
                  <tr><td colSpan={6} className="text-center text-gray-500 py-10">Sin IoCs registrados</td></tr>
                )}
                {iocs.map((ioc: any) => (
                  <tr key={ioc.id}>
                    <td>
                      <span className={`text-xs font-mono px-2 py-0.5 rounded bg-navy-900 ${TYPE_COLOR[ioc.ioc_type] ?? 'text-gray-400'}`}>
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td className="font-mono text-xs text-gray-200 max-w-xs truncate">{ioc.value}</td>
                    <td className="text-gray-500 text-xs">{ioc.source ?? '—'}</td>
                    <td>
                      <span className={`font-mono text-xs ${ioc.confidence >= 0.8 ? 'text-red-400' : ioc.confidence >= 0.5 ? 'text-yellow-400' : 'text-green-400'}`}>
                        {Number(ioc.confidence).toFixed(2)}
                      </span>
                    </td>
                    <td className="text-gray-600 text-xs">{ioc.created_at?.slice(0, 10)}</td>
                    <td>
                      <button onClick={() => copy(ioc.value)} className="text-gray-600 hover:text-cyan-400 transition-colors">
                        {copied === ioc.value ? <CheckCircle2 size={13} className="text-green-400" /> : <Copy size={13} />}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </main>
    </div>
  )
}
