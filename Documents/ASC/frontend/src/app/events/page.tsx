'use client'
import { useEffect, useState, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import { useAuthGuard } from '@/lib/auth-guard'
import { getEvents } from '@/lib/api'
import { useSSENotifications } from '@/lib/useSSENotifications'
import { Activity, RefreshCw, Wifi, WifiOff } from 'lucide-react'

export default function EventsPage() {
  useAuthGuard()
  const [events, setEvents]   = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter]   = useState({ severity: '', limit: 100 })

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await getEvents({ severity: filter.severity || undefined, limit: filter.limit })
      setEvents(data)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [filter])

  const { connected } = useSSENotifications({
    onEvent: (evt) => {
      if (['event_created', 'ingest_completed'].includes(evt.type)) load()
    },
  })

  useEffect(() => { load() }, [load])

  const ECS_FIELDS = ['timestamp', 'host', 'process', 'api_call', 'category', 'dst_ip', 'severity']

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6 overflow-auto">
        <div className="flex items-center gap-3 mb-1">
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Activity className="text-cyan-400" size={22} />
            Eventos Ingestados
          </h1>
          <span title={connected ? 'SSE conectado — actualizaciones en tiempo real' : 'SSE desconectado'}
            className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border ${connected ? 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10' : 'text-gray-500 border-gray-700 bg-gray-800'}`}>
            {connected ? <Wifi size={11} /> : <WifiOff size={11} />}
            {connected ? 'live' : 'offline'}
          </span>
        </div>
        <p className="text-gray-500 text-xs mb-6">Eventos normalizados en formato ECS — fuente de datos para las reglas de detección</p>

        {/* Filters */}
        <div className="flex gap-3 mb-5 flex-wrap">
          <select value={filter.severity} onChange={e => setFilter(f => ({ ...f, severity: e.target.value }))}
            className="bg-navy-800 border border-navy-700 text-sm text-gray-300 rounded px-3 py-1.5 outline-none focus:border-cyan-400">
            <option value="">Todas las severidades</option>
            {['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={filter.limit} onChange={e => setFilter(f => ({ ...f, limit: Number(e.target.value) }))}
            className="bg-navy-800 border border-navy-700 text-sm text-gray-300 rounded px-3 py-1.5 outline-none focus:border-cyan-400">
            {[25, 50, 100, 250].map(n => <option key={n} value={n}>{n} eventos</option>)}
          </select>
          <button onClick={load} className="btn-primary flex items-center gap-2 text-sm py-1.5">
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refrescar
          </button>
          <span className="text-xs text-gray-600 self-center">{events.length} eventos cargados</span>
        </div>

        {loading ? (
          <p className="text-gray-400 text-sm">Cargando eventos...</p>
        ) : (
          <div className="card overflow-x-auto">
            <table className="table-asc">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Host</th>
                  <th>Proceso</th>
                  <th>API / Acción</th>
                  <th>Categoría</th>
                  <th>Severidad</th>
                  <th>Score</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 && (
                  <tr><td colSpan={7} className="text-center text-gray-500 py-10">Sin eventos con ese filtro</td></tr>
                )}
                {events.map((e: any, i: number) => (
                  <tr key={e.id ?? i}>
                    <td className="text-gray-500 text-xs font-mono">{e.timestamp?.slice(0, 19).replace('T', ' ')}</td>
                    <td className="text-cyan-400 font-mono text-xs">{e.host ?? '—'}</td>
                    <td className="text-gray-200 text-xs">{e.process ?? '—'}</td>
                    <td className="text-gray-400 text-xs font-mono">{e.api_call ?? e.action ?? '—'}</td>
                    <td className="text-gray-500 text-xs">{e.category ?? '—'}</td>
                    <td>{e.severity ? <SeverityBadge severity={e.severity} /> : '—'}</td>
                    <td className="font-mono text-cyan-400 text-xs">{e.risk_score != null ? Number(e.risk_score).toFixed(2) : '—'}</td>
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
