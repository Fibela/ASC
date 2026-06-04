'use client'
import { useEffect, useState } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { getAlerts, updateAlert } from '@/lib/api'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import { CheckCircle, AlertCircle } from 'lucide-react'

const STATUSES = ['open', 'investigating', 'contained', 'resolved', 'false_positive']

export default function AlertsPage() {
  const [alerts, setAlerts]   = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter]   = useState({ severity: '', status: 'open' })

  async function load() {
    setLoading(true)
    const data = await getAlerts({ severity: filter.severity || undefined, status: filter.status || undefined, limit: 100 })
    setAlerts(data)
    setLoading(false)
  }
  useEffect(() => { load() }, [filter])

  async function setStatus(id: string, status: string) {
    await updateAlert(id, { status })
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status } : a))
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6">
        <h1 className="text-2xl font-bold text-white mb-6">Gestión de Alertas</h1>

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
                      <button onClick={() => setStatus(a.id, 'false_positive')}
                        className="text-xs text-gray-500 hover:text-orange-400 flex items-center gap-1">
                        <AlertCircle size={12} /> FP
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
