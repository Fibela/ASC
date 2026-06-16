'use client'
import { useEffect, useState, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { getAlerts, updateAlert, createHuntFromAlert, AlertItem } from '@/lib/api'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import { useAuthGuard } from '@/lib/auth-guard'
import { useSSENotifications } from '@/lib/useSSENotifications'
import { ShieldAlert, RefreshCw, Crosshair, AlertCircle, Wifi, WifiOff, X } from 'lucide-react'

const STATUSES = ['open', 'investigating', 'contained', 'resolved', 'false_positive']
const SEVERITIES = ['critical', 'high', 'medium', 'low']

function AlertsLoader() {
  return (
    <div className="flex min-h-screen items-center justify-center" style={{ background: '#0A0A0A' }}>
      <div className="w-5 h-5 rounded-full border-2 animate-spin"
        style={{ borderColor: 'rgba(232,93,4,0.2)', borderTopColor: '#E85D04' }} />
    </div>
  )
}

export default function AlertsPage() {
  const { isReady }               = useAuthGuard()
  const [alerts, setAlerts]       = useState<AlertItem[]>([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState<string | null>(null)
  const [filter, setFilter]       = useState({ severity: '', status: 'open' })
  const [huntMsg, setHuntMsg]     = useState('')
  const [huntErr, setHuntErr]     = useState(false)
  const [huntingId, setHuntingId] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getAlerts({
        severity: filter.severity || undefined,
        status:   filter.status   || undefined,
        limit:    100,
      })
      setAlerts(data)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error desconocido'
      setError(`No se pudieron cargar las alertas. ${msg}`)
    } finally {
      setLoading(false)
    }
  }, [filter])

  const { connected } = useSSENotifications({
    onEvent: (evt) => {
      if (['alert_created', 'alert_updated', 'escalation'].includes(evt.type)) load()
    },
  })

  useEffect(() => { if (!isReady) return; load() }, [load, isReady])

  if (!isReady) return <AlertsLoader />

  async function setStatus(id: string, status: string) {
    await updateAlert(id, { status })
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: status as AlertItem['status'] } : a))
  }

  async function startHunt(alertId: string) {
    setHuntingId(alertId)
    setHuntErr(false)
    try {
      const hunt = await createHuntFromAlert(alertId)
      setHuntMsg(`Hunt creada: "${hunt.name}" (${hunt.id.slice(0, 8)})`)
      setTimeout(() => setHuntMsg(''), 4000)
    } catch {
      setHuntMsg('Error al crear hunt desde alerta')
      setHuntErr(true)
      setTimeout(() => { setHuntMsg(''); setHuntErr(false) }, 3000)
    } finally {
      setHuntingId('')
    }
  }

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
            <ShieldAlert size={18} style={{ color: '#E85D04' }} />
            <div>
              <h1 className="text-sm font-bold leading-none" style={{ color: '#EAEAEA' }}>
                Gestión de Alertas
              </h1>
              <p className="text-xs mt-0.5" style={{ color: '#3A3A3A' }}>
                Triaje · Escalada · Hunt
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* SSE badge */}
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

          {/* Error banner */}
          {error && !loading && (
            <div className="flex items-center gap-3 rounded-xl px-4 py-3 text-sm"
              style={{ background: 'rgba(192,21,46,0.1)', border: '1px solid rgba(192,21,46,0.3)', color: '#F87171' }}>
              <AlertCircle size={15} style={{ flexShrink: 0 }} />
              <span className="flex-1">{error}</span>
              <button onClick={load} className="text-xs underline opacity-80 hover:opacity-100">Reintentar</button>
            </div>
          )}

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
              value={filter.status}
              onChange={e => setFilter(f => ({ ...f, status: e.target.value }))}
              className="input-asc"
              style={{ width: 'auto', minWidth: 160 }}
            >
              <option value="">Todos los estados</option>
              {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>

            <span className="text-xs ml-auto" style={{ color: '#3A3A3A' }}>
              {alerts.length} alerta{alerts.length !== 1 ? 's' : ''}
            </span>
          </div>

          {/* Hunt notification */}
          {huntMsg && (
            <div
              className="flex items-center justify-between gap-3 px-4 py-2.5 rounded-xl text-sm"
              style={{
                background: huntErr ? 'rgba(192,21,46,0.1)'  : 'rgba(45,184,99,0.1)',
                border:     huntErr ? '1px solid rgba(192,21,46,0.3)' : '1px solid rgba(45,184,99,0.3)',
                color:      huntErr ? '#E8526E' : '#3FD175',
              }}
            >
              {huntMsg}
              <button onClick={() => setHuntMsg('')} style={{ color: 'inherit', opacity: 0.6 }}>
                <X size={13} />
              </button>
            </div>
          )}

          {/* Table */}
          {loading ? (
            <div className="flex items-center gap-3 py-16 justify-center" style={{ color: '#3A3A3A' }}>
              <RefreshCw size={18} className="animate-spin" style={{ color: '#E85D04' }} />
              <span className="text-sm">Cargando alertas...</span>
            </div>
          ) : (
            <div className="card overflow-x-auto">
              <table className="table-asc">
                <thead>
                  <tr>
                    <th>Título</th>
                    <th>Severidad</th>
                    <th>Risk Score</th>
                    <th>TTPs</th>
                    <th>Estado</th>
                    <th>Detectada</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.length === 0 && (
                    <tr>
                      <td colSpan={7} className="text-center py-12 text-sm" style={{ color: '#3A3A3A' }}>
                        Sin alertas con los filtros seleccionados
                      </td>
                    </tr>
                  )}
                  {alerts.map((a: any) => (
                    <tr key={a.id}>
                      <td className="max-w-xs truncate font-medium text-xs" style={{ color: '#EAEAEA' }}>
                        {a.title}
                      </td>
                      <td><SeverityBadge severity={a.severity} /></td>
                      <td
                        className="font-mono text-xs font-bold"
                        style={{ color: '#E85D04' }}
                      >
                        {Number(a.risk_score).toFixed(2)}
                      </td>
                      <td className="text-xs" style={{ color: '#5A5A5A' }}>
                        {a.ttps?.join(', ') || '—'}
                      </td>
                      <td>
                        <select
                          value={a.status}
                          onChange={e => setStatus(a.id, e.target.value)}
                          className="input-asc text-xs py-1"
                          style={{ minWidth: 130 }}
                        >
                          {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                        </select>
                      </td>
                      <td className="font-mono text-xs" style={{ color: '#3A3A3A' }}>
                        {a.detected_at?.slice(0, 19).replace('T', ' ')}
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => setStatus(a.id, 'false_positive')}
                            className="btn-ghost text-xs py-1 px-2 flex items-center gap-1"
                            title="Marcar como falso positivo"
                          >
                            <AlertCircle size={11} /> FP
                          </button>
                          <button
                            onClick={() => startHunt(a.id)}
                            disabled={huntingId === a.id}
                            className="btn-ghost text-xs py-1 px-2 flex items-center gap-1 disabled:opacity-40"
                            title="Crear Hunt desde esta alerta"
                            style={{ color: huntingId === a.id ? '#3A3A3A' : '#E85D04' }}
                          >
                            <Crosshair size={11} />
                            {huntingId === a.id ? '…' : 'Hunt'}
                          </button>
                        </div>
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
