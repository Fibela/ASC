'use client'

import { useEffect, useState, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import {
  getTIStats, listTIIndicators, createTIIndicator, enrichTI, deleteTIIndicator,
  ThreatIntelIndicator, ThreatIntelStats, ThreatIntelListResponse, EnrichResult,
} from '@/lib/api'
import { getRole } from '@/lib/auth'
import {
  ShieldAlert, Search, Plus, Trash2, RefreshCw, ChevronLeft, ChevronRight,
  AlertTriangle, CheckCircle2, XCircle, Crosshair,
} from 'lucide-react'

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_CLS: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-700',
  high:     'text-orange-400 bg-orange-400/10 border-orange-700',
  medium:   'text-yellow-400 bg-yellow-400/10 border-yellow-700',
  low:      'text-blue-400 bg-blue-400/10 border-blue-700',
  info:     'text-gray-400 bg-gray-700 border-gray-600',
}

function SevBadge({ sev }: { sev: string }) {
  const cls = SEV_CLS[sev] ?? SEV_CLS.info
  return <span className={`px-1.5 py-0.5 rounded text-xs border ${cls}`}>{sev}</span>
}

function formatTs(ts: string | null | undefined): string {
  if (!ts) return '—'
  try { return new Date(ts).toLocaleDateString() } catch { return ts }
}

function pct(n: number): string { return `${Math.round(n * 100)}%` }

const PAGE_SIZE = 25

// ── Add Indicator Modal ───────────────────────────────────────────────────────

function AddModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({
    indicator_type: 'ip', value: '', severity: 'medium', confidence: '0.8',
    source: 'internal', threat_actor: '', malware_family: '', description: '',
    ttps: '', tags: '',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const field = (k: string, v: string) => setForm(f => ({ ...f, [k]: v }))

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      await createTIIndicator({
        indicator_type: form.indicator_type,
        value: form.value,
        severity: form.severity,
        confidence: parseFloat(form.confidence) || 0.8,
        source: form.source || 'internal',
        threat_actor: form.threat_actor || undefined,
        malware_family: form.malware_family || undefined,
        description: form.description || undefined,
        ttps: form.ttps ? form.ttps.split(',').map(s => s.trim()).filter(Boolean) : [],
        tags: form.tags ? form.tags.split(',').map(s => s.trim()).filter(Boolean) : [],
      })
      onCreated()
      onClose()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Error al crear indicador')
    } finally {
      setLoading(false)
    }
  }

  const inputCls = "w-full bg-navy-900 border border-navy-600 rounded px-2 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-cyan-700"
  const TYPES = ['ip','cidr','domain','url','email','hash_md5','hash_sha1','hash_sha256','file_path','mutex','registry_key','asn','cve']

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-navy-800 border border-navy-700 rounded-lg w-full max-w-lg p-5">
        <h2 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
          <Plus size={16} className="text-cyan-400" /> Nuevo Indicador TI
        </h2>
        {error && <div className="mb-3 text-xs text-red-400 bg-red-900/20 rounded p-2">{error}</div>}
        <form onSubmit={submit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Tipo *</label>
              <select value={form.indicator_type} onChange={e => field('indicator_type', e.target.value)} className={inputCls}>
                {TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Severidad</label>
              <select value={form.severity} onChange={e => field('severity', e.target.value)} className={inputCls}>
                {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Valor *</label>
            <input required value={form.value} onChange={e => field('value', e.target.value)} placeholder="1.2.3.4 / evil.com / abc123..." className={inputCls} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Confianza (0-1)</label>
              <input type="number" min="0" max="1" step="0.05" value={form.confidence} onChange={e => field('confidence', e.target.value)} className={inputCls} />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Fuente</label>
              <input value={form.source} onChange={e => field('source', e.target.value)} placeholder="internal" className={inputCls} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Threat Actor</label>
              <input value={form.threat_actor} onChange={e => field('threat_actor', e.target.value)} placeholder="APT29..." className={inputCls} />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Familia Malware</label>
              <input value={form.malware_family} onChange={e => field('malware_family', e.target.value)} placeholder="Cobalt Strike..." className={inputCls} />
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">TTPs (comma-separated)</label>
            <input value={form.ttps} onChange={e => field('ttps', e.target.value)} placeholder="T1055, T1071.001" className={inputCls} />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Tags (comma-separated)</label>
            <input value={form.tags} onChange={e => field('tags', e.target.value)} placeholder="c2, ransomware" className={inputCls} />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Descripción</label>
            <textarea value={form.description} onChange={e => field('description', e.target.value)} rows={2} className={`${inputCls} resize-none`} />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="px-3 py-1.5 text-xs text-gray-400 hover:text-white border border-navy-600 rounded">Cancelar</button>
            <button type="submit" disabled={loading} className="px-3 py-1.5 text-xs bg-cyan-600 hover:bg-cyan-500 text-white rounded disabled:opacity-40">
              {loading ? 'Guardando…' : 'Crear indicador'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Enrich Panel ──────────────────────────────────────────────────────────────

function EnrichPanel() {
  const [query, setQuery]     = useState('')
  const [result, setResult]   = useState<EnrichResult | null>(null)
  const [loading, setLoading] = useState(false)

  async function doEnrich() {
    if (!query.trim()) return
    setLoading(true)
    try {
      const r = await enrichTI(query.trim())
      setResult(r)
    } catch { /* ignore */ } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-navy-800 border border-navy-700 rounded-lg p-4 mb-5">
      <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
        <Crosshair size={14} className="text-cyan-400" /> Enriquecimiento rápido
      </h2>
      <div className="flex gap-2">
        <input
          value={query} onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && doEnrich()}
          placeholder="IP, dominio, hash, email…"
          className="flex-1 bg-navy-900 border border-navy-600 rounded px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-cyan-700"
        />
        <button onClick={doEnrich} disabled={loading || !query.trim()}
          className="px-3 py-1.5 rounded text-xs bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-40 flex items-center gap-1">
          <Search size={12} /> {loading ? '…' : 'Enriquecer'}
        </button>
      </div>
      {result && (
        <div className={`mt-3 rounded p-3 text-xs border ${result.is_known_bad ? 'bg-red-900/10 border-red-700/50' : 'bg-green-900/10 border-green-700/50'}`}>
          <div className="flex items-center gap-2 mb-2">
            {result.is_known_bad
              ? <AlertTriangle size={14} className="text-red-400" />
              : <CheckCircle2 size={14} className="text-green-400" />
            }
            <span className={`font-semibold ${result.is_known_bad ? 'text-red-400' : 'text-green-400'}`}>
              {result.is_known_bad
                ? `⚠️ ${result.match_count} coincidencia(s) — severidad máx: ${result.max_severity}`
                : 'No encontrado en corpus TI local'}
            </span>
          </div>
          {result.matches.map(m => (
            <div key={m.id} className="pl-4 text-gray-300 space-y-0.5 mt-1">
              <div>Fuente: <span className="text-gray-400">{m.source}</span> | Actor: <span className="text-gray-400">{m.threat_actor || '—'}</span></div>
              {m.ttps.length > 0 && <div>TTPs: <span className="font-mono text-cyan-400">{m.ttps.join(', ')}</span></div>}
              {m.description && <div className="text-gray-500 italic">{m.description}</div>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ThreatIntelPage() {
  useAuthGuard()
  const role = typeof window !== 'undefined' ? getRole() : null

  const [stats, setStats]     = useState<ThreatIntelStats | null>(null)
  const [data, setData]       = useState<ThreatIntelListResponse | null>(null)
  const [page, setPage]       = useState(0)
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [typeFilter, setTypeFilter] = useState('')
  const [sevFilter, setSevFilter]   = useState('')
  const [deleting, setDeleting]     = useState<string | null>(null)
  const [error, setError]           = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [s, d] = await Promise.all([
        getTIStats(),
        listTIIndicators({
          indicator_type: typeFilter || undefined,
          severity: sevFilter || undefined,
          limit: PAGE_SIZE, offset: page * PAGE_SIZE,
        }),
      ])
      setStats(s)
      setData(d)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Error cargando TI')
    } finally {
      setLoading(false)
    }
  }, [page, typeFilter, sevFilter])

  useEffect(() => { load() }, [load])

  async function handleDelete(id: string) {
    setDeleting(id)
    try {
      await deleteTIIndicator(id)
      await load()
    } catch { /* ignore */ } finally {
      setDeleting(null)
    }
  }

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 1

  return (
    <div className="flex min-h-screen bg-navy-900 text-white">
      <Sidebar />
      <main className="flex-1 p-6 overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <ShieldAlert size={22} className="text-cyan-400" />
            <div>
              <h1 className="text-xl font-bold text-white">Threat Intelligence</h1>
              <p className="text-xs text-gray-400">Corpus local de indicadores · Enriquecimiento · MITRE ATT&CK</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={load} disabled={loading}
              className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-cyan-400 disabled:opacity-40">
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            </button>
            <button onClick={() => setShowAdd(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs bg-cyan-600 hover:bg-cyan-500 text-white">
              <Plus size={14} /> Nuevo indicador
            </button>
          </div>
        </div>

        {error && <div className="mb-4 text-xs text-red-400 bg-red-900/20 border border-red-700/50 rounded p-3">{error}</div>}

        {/* Stats */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
            <div className="bg-navy-800 border border-navy-700 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-cyan-400">{stats.active}</p>
              <p className="text-xs text-gray-400 mt-0.5">Indicadores activos</p>
            </div>
            <div className="bg-navy-800 border border-navy-700 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-red-400">{stats.by_severity?.critical ?? 0}</p>
              <p className="text-xs text-gray-400 mt-0.5">Severidad crítica</p>
            </div>
            <div className="bg-navy-800 border border-navy-700 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-orange-400">{stats.by_severity?.high ?? 0}</p>
              <p className="text-xs text-gray-400 mt-0.5">Severidad alta</p>
            </div>
            <div className="bg-navy-800 border border-navy-700 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-gray-400">{stats.total}</p>
              <p className="text-xs text-gray-400 mt-0.5">Total corpus</p>
            </div>
          </div>
        )}

        {/* Enrich */}
        <EnrichPanel />

        {/* Filters */}
        <div className="flex gap-3 mb-3">
          <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(0) }}
            className="bg-navy-800 border border-navy-700 rounded px-2 py-1.5 text-xs text-gray-300">
            <option value="">Todos los tipos</option>
            {['ip','cidr','domain','url','email','hash_md5','hash_sha1','hash_sha256','file_path','mutex','registry_key','asn','cve']
              .map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <select value={sevFilter} onChange={e => { setSevFilter(e.target.value); setPage(0) }}
            className="bg-navy-800 border border-navy-700 rounded px-2 py-1.5 text-xs text-gray-300">
            <option value="">Todas las severidades</option>
            {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <span className="ml-auto text-xs text-gray-500 self-center">
            {data?.total ?? 0} indicadores
          </span>
        </div>

        {/* Table */}
        <div className="bg-navy-800 border border-navy-700 rounded-lg overflow-x-auto">
          {loading ? (
            <p className="text-center text-gray-500 text-sm py-10">Cargando corpus TI…</p>
          ) : (data?.indicators ?? []).length === 0 ? (
            <div className="text-center py-16">
              <ShieldAlert size={32} className="mx-auto text-gray-600 mb-3" />
              <p className="text-gray-500 text-sm">Corpus TI vacío</p>
              <p className="text-xs text-gray-600 mt-1">Agrega indicadores manualmente o usa importación masiva</p>
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-navy-700 text-gray-400">
                  <th className="px-4 py-3 text-left">Tipo</th>
                  <th className="px-4 py-3 text-left">Valor</th>
                  <th className="px-4 py-3 text-left">Severidad</th>
                  <th className="px-4 py-3 text-left">Confianza</th>
                  <th className="px-4 py-3 text-left">Actor / Malware</th>
                  <th className="px-4 py-3 text-left">Fuente</th>
                  <th className="px-4 py-3 text-center">Hits</th>
                  <th className="px-4 py-3 text-left">Visto</th>
                  {role === 'admin' && <th className="px-4 py-3 text-left"></th>}
                </tr>
              </thead>
              <tbody>
                {(data?.indicators ?? []).map((ind: ThreatIntelIndicator) => (
                  <tr key={ind.id} className="border-b border-navy-700/50 hover:bg-navy-700/30 transition-colors">
                    <td className="px-4 py-2 font-mono text-cyan-300">{ind.indicator_type}</td>
                    <td className="px-4 py-2 text-gray-200 max-w-[200px] truncate font-mono text-xs" title={ind.value}>
                      {ind.value}
                    </td>
                    <td className="px-4 py-2"><SevBadge sev={ind.severity} /></td>
                    <td className="px-4 py-2 text-gray-400">{pct(ind.confidence)}</td>
                    <td className="px-4 py-2 text-gray-300">
                      {ind.threat_actor || ind.malware_family
                        ? <span>{ind.threat_actor ?? ''}{ind.threat_actor && ind.malware_family ? ' / ' : ''}{ind.malware_family ?? ''}</span>
                        : <span className="text-gray-600">—</span>
                      }
                    </td>
                    <td className="px-4 py-2 text-gray-400">{ind.source}</td>
                    <td className="px-4 py-2 text-center">
                      <span className={ind.hit_count > 0 ? 'text-orange-400 font-semibold' : 'text-gray-600'}>
                        {ind.hit_count}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-gray-500 whitespace-nowrap">{formatTs(ind.last_seen)}</td>
                    {role === 'admin' && (
                      <td className="px-4 py-2">
                        <button onClick={() => handleDelete(ind.id)} disabled={deleting === ind.id}
                          className="text-gray-600 hover:text-red-400 transition-colors disabled:opacity-30">
                          <Trash2 size={13} />
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-center gap-3 mt-4 text-sm">
            <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
              className="flex items-center gap-1 text-gray-400 hover:text-white disabled:opacity-30">
              <ChevronLeft size={16} /> Anterior
            </button>
            <span className="text-gray-500">Pág {page + 1} / {totalPages}</span>
            <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
              className="flex items-center gap-1 text-gray-400 hover:text-white disabled:opacity-30">
              Siguiente <ChevronRight size={16} />
            </button>
          </div>
        )}

        {showAdd && <AddModal onClose={() => setShowAdd(false)} onCreated={load} />}
      </main>
    </div>
  )
}
