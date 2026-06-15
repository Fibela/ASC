'use client'
import { useEffect, useState, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { getAlerts, updateAlert, createHuntFromAlert } from '@/lib/api'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import { useAuthGuard } from '@/lib/auth-guard'
import { useSSENotifications } from '@/lib/useSSENotifications'
import { CheckCircle, AlertCircle, Crosshair, Wifi, WifiOff } from 'lucide-react'

const STATUSES = ['open', 'investigating', 'contained', 'resolved', 'false_positive']

export default function AlertsPage() {
  useAuthGuard()
  const [alerts, setAlerts]   = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter]   = useState({ severity: '', status: 'open' })
  const [huntMsg, setHuntMsg] = useState('')
  const [huntingId, setHuntingId] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    const data = await getAlerts({ severity: filter.severity || undefined, status: filter.status || undefined, limit: 100 })
    setAlerts(data)
    setLoading(false)
  }, [filter])

  const { connected } = useSSENotifications({
    onEvent: (evt) => {
      if (['alert_created', 'alert_updated', 'escalation'].includes(evt.type)) load()
    },
  })

  useEffect(() => { load() }, [load])

  async function setStatus(id: string, status: string) {
    await updateAlert(id, { status })
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status } : a))
  }

  async function startHunt(alertId: string) {
    setHuntingId(alertId)
    try {
      const hunt = await createHuntFromAlert(alertId)
      setHuntMsg(`Hunt creada: "${hunt.name}" (${hunt.id.slice(0, 8)})`)
      setTimeout(() => setHuntMsg(''), 4000)
    } catch {
      setHuntMsg('Error al crear hunt desde alerta')
      setTimeout(() => setHuntMsg(''), 3000)
    } finally {
      setHuntingId('')
    }
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6">
        <div className="flex items-center gap-3 mb-6">
          <h1 className="text-2xl font-bold text-white">Gestión de Alertas</h1>
          <span title={connected ? 'SSE conectado — actualizaciones en tiempo real' : 'SSE desconectado'}
            className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border ${connected ? 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10' : 'text-gray-500 border-gray-700 bg-gray-800'}`}>
            {connected ? <Wifi size={11} /> : <WifiOff size={11} />}
            {connected ? 'live' : 'offline'}
          </span>
        </div>

        {/* Filters */}
        <div className="flex gap-3 mb-5">
          <select value={filter.severity} onChange={e => setFilter(f => ({ ...f, severity: e.target.value }))}
            className="bg-navy-800 border border-navy-700 text-sm text-gray-300 rounded px-3 py-1.5 outline-none focus:border-cyan-400">
            <option value="">Todas las severidades</option>
            {['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={filter.status} onChange={e => setFilter(f => ({ ...f, status: e.target.value }))}
            className="bg-navy-800 border border-navy-700 text-sm text-gray-300 rounded px-3 py-1.5 outline-none focus:border-cyan-400">
            <option value="">Todos los estados</option>
            {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <button onClick={load} className="btn-primary text-sm py-1.5">Refrescar</button>
        </div>

        {huntMsg && (
          <div className="mb-4 px-3 py-2 bg-cyan-500/20 border border-cyan-500/40 rounded text-cyan-400 text-sm">
            {huntMsg}
          </div>
        )}

        {loading ? (
          <p className="text-gray-400">Cargando alertas...</p>
        ) : (
          <div className="card overflow-x-auto">
            <table className="table-asc">
              <thead>
                <tr>
                  <th>Título</th>
                  <th>Severidad</th>
                  <th>Risk</th>
                  <th>TTPs</th>
                  <th>Estado</th>
                  <th>Detectada</th>
                  <th>Acciones</th>
                </tr>
              </thead>
              <tbody>
                {alerts.length === 0 && (
                  <tr><td colSpan={7} className="text-center text-gray-500 py-8">Sin alertas con ese filtro</td></tr>
                )}
                {alerts.map((a: any) => (
                  <tr key={a.id}>
                    <td className="max-w-xs truncate font-medium">{a.title}</td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td className="font-mono text-cyan-400">{Number(a.risk_score).toFixed(2)}</td>
                    <td className="text-xs text-gray-400">{a.ttps?.join(', ') || '—'}</td>
                    <td>
                      <select value={a.status}
                        onChange={e => setStatus(a.id, e.target.value)}
                        className="bg-navy-900 border border-navy-700 text-xs text-gray-300 rounded px-2 py-1 outline-none">
                        {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                      </select>
                    </td>
                    <td className="text-gray-400 text-xs">{a.detected_at?.slice(0, 19).replace('T', ' ')}</td>
                    <td>
                      <div className="flex items-center gap-2">
                        <button onClick={() => setStatus(a.id, 'false_positive')}
                          className="text-xs text-gray-500 hover:text-orange-400 flex items-center gap-1">
                          <AlertCircle size={12} /> FP
                        </button>
                        <button onClick={() => startHunt(a.id)} disabled={huntingId === a.id}
                          className="text-xs text-cyan-600 hover:text-cyan-400 flex items-center gap-1 disabled:opacity-40"
                          title="Crear Hunt desde esta alerta">
                          <Crosshair size={12} /> {huntingId === a.id ? '...' : 'Hunt'}
                        </button>
                      </div>
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
