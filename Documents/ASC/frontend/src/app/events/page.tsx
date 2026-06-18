'use client'
import { useEffect, useState, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'
import { getEvents } from '@/lib/api'
import { useSSENotifications } from '@/lib/useSSENotifications'
import { Activity, RefreshCw, Wifi, WifiOff } from 'lucide-react'

const SEVERITIES   = ['critical', 'high', 'medium', 'low']
const LIMIT_OPTIONS = [25, 50, 100, 250]

export default function EventsPage() {
  const { isReady } = useAuthGuard()
  const [events, setEvents]   = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter]   = useState({ severity: '', limit: 100 })

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await getEvents({
        severity: filter.severity || undefined,
        limit:    filter.limit,
      })
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

  useEffect(() => { if (!isReady) return; load() }, [load, isReady])

  if (!isReady) return <AuthLoader />

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 overflow-auto">

        {/* Header */}
        <div
          className="sticky top-0 z-20 px-6 py-3 flex items-center justify-between"
          style={{
            background:   'rgba(10,10,10,0.92)',
            borderBottom: '1px solid rgba(255,255,255,0.05)',
            backdropFilter: 'blur(12px)',
          }}
        >
          <div className="flex items-center gap-3">
            <Activity size={18} style={{ color: '#E85D04' }} />
            <div>
              <h1 className="text-sm font-bold leading-none" style={{ color: '#EAEAEA' }}>
                Eventos Ingestados
              </h1>
              <p className="text-xs mt-0.5" style={{ color: '#3A3A3A' }}>
                Formato ECS · Fuente de reglas de detección
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <span
              className="flex items-center gap-1 text-xs px-2 py-1 rounded-lg"
              style={{
                background:   connected ? 'rgba(45,184,99,0.1)'  : 'rgba(58,58,58,0.3)',
                border:       connected ? '1px solid rgba(45,184,99,0.3)' : '1px solid rgba(58,58,58,0.4)',
                color:        connected ? '#3FD175' : '#5A5A5A',
              }}
            >
              {connected ? <Wifi size={11} /> : <WifiOff size={11} />}
              {connected ? 'live' : 'offline'}
            </span>
            <button onClick={load} disabled={loading}
              className="btn-secondary flex items-center gap-1.5 text-xs py-1.5 px-3">
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
              Refrescar
            </button>
          </div>
        </div>

        <div className="p-6 space-y-5 animate-fade-in">

          {/* Filters */}
          <div className="flex flex-wrap gap-3 items-center">
            <select
              value={filter.severity}
              onChange={e => setFilter(f => ({ ...f, severity: e.target.value }))}
              className="input-asc"
              style={{ width: 'auto', minWidth: 180 }}
            >
              <option value="">Todas las severidades</option>
              {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>

            <select
              value={filter.limit}
              onChange={e => setFilter(f => ({ ...f, limit: Number(e.target.value) }))}
              className="input-asc"
              style={{ width: 'auto', minWidth: 140 }}
            >
              {LIMIT_OPTIONS.map(n => <option key={n} value={n}>{n} eventos</option>)}
            </select>

            <span className="text-xs ml-auto" style={{ color: '#3A3A3A' }}>
              {events.length} evento{events.length !== 1 ? 's' : ''} cargados
            </span>
          </div>

          {/* Table */}
          {loading ? (
            <div className="flex items-center gap-3 py-16 justify-center" style={{ color: '#3A3A3A' }}>
              <RefreshCw size={18} className="animate-spin" style={{ color: '#E85D04' }} />
              <span className="text-sm">Cargando eventos...</span>
            </div>
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
                    <tr>
                      <td colSpan={7} className="text-center py-12 text-sm" style={{ color: '#3A3A3A' }}>
                        Sin eventos con los filtros seleccionados
                      </td>
                    </tr>
                  )}
                  {events.map((e: any, i: number) => (
                    <tr key={e.id ?? i}>
                      <td className="font-mono text-xs" style={{ color: '#3A3A3A' }}>
                        {e.timestamp?.slice(0, 19).replace('T', ' ')}
                      </td>
                      <td className="font-mono text-xs font-medium" style={{ color: '#E85D04' }}>
                        {e.host ?? '—'}
                      </td>
                      <td className="text-xs" style={{ color: '#EAEAEA' }}>
                        {e.process ?? '—'}
                      </td>
                      <td className="font-mono text-xs" style={{ color: '#A0A0A0' }}>
                        {e.api_call ?? e.action ?? '—'}
                      </td>
                      <td className="text-xs" style={{ color: '#5A5A5A' }}>
                        {e.category ?? '—'}
                      </td>
                      <td>
                        {e.severity ? <SeverityBadge severity={e.severity} /> : (
                          <span style={{ color: '#3A3A3A' }}>—</span>
                        )}
                      </td>
                      <td className="font-mono text-xs font-bold" style={{ color: '#E85D04' }}>
                        {e.risk_score != null ? Number(e.risk_score).toFixed(2) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
