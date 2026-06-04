'use client'
import { useEffect, useState } from 'react'
import { getSocMetrics, getAlerts, getTimeline } from '@/lib/api'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { MetricCard } from '@/components/dashboard/MetricCard'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts'
import { RefreshCw, Shield } from 'lucide-react'

export default function DashboardPage() {
  const [metrics, setMetrics]   = useState<any>(null)
  const [alerts, setAlerts]     = useState<any[]>([])
  const [timeline, setTimeline] = useState<any[]>([])
  const [loading, setLoading]   = useState(true)
  const [lastRefresh, setLastRefresh] = useState(new Date())

  async function load() {
    setLoading(true)
    try {
      const [m, a, t] = await Promise.all([getSocMetrics(24), getAlerts({ limit: 10 }), getTimeline(24)])
      setMetrics(m)
      setAlerts(a)
      setTimeline(t)
      setLastRefresh(new Date())
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(load, 30_000)
    return () => clearInterval(interval)
  }, [])

  const posture = metrics?.risk_posture ?? 'NORMAL'
  const postureColor = { CRITICAL: 'text-red-400', HIGH: 'text-orange-400', ELEVATED: 'text-yellow-400', NORMAL: 'text-green-400' }[posture] ?? 'text-cyan-400'

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6 overflow-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <Shield className="text-cyan-400" size={24} />
              SOC Dashboard
            </h1>
            <p className="text-gray-400 text-sm mt-0.5">Últimas 24 horas • Auto-refresh 30s</p>
          </div>
          <div className="flex items-center gap-3">
            <span className={`text-lg font-black ${postureColor}`}>{posture}</span>
            <button onClick={load} className="btn-primary flex items-center gap-2 text-sm py-1.5">
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
              Actualizar
            </button>
          </div>
        </div>

        {/* KPI Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <MetricCard label="Total Alertas"    value={metrics?.total_alerts ?? '—'} color="cyan" />
          <MetricCard label="Críticas"         value={metrics?.by_severity?.critical ?? '—'} color="red" />
          <MetricCard label="MTTD"             value={metrics?.mttd_minutes ?? '—'} unit="min" color="orange" sublabel="Mean Time to Detect" />
          <MetricCard label="MTTR"             value={metrics?.mttr_minutes ?? '—'} unit="min" color="orange" sublabel="Mean Time to Respond" />
          <MetricCard label="Eventos Ingestados" value={metrics?.total_events ?? '—'} color="cyan" />
          <MetricCard label="Tasa FP"          value={metrics?.false_positive_rate != null ? `${(metrics.false_positive_rate * 100).toFixed(1)}%` : '—'} color="green" sublabel="False Positive Rate" />
          <MetricCard label="Cobertura IoC"    value={metrics?.ioc_coverage != null ? `${(metrics.ioc_coverage * 100).toFixed(1)}%` : '—'} color="green" />
          <MetricCard label="Alertas Altas"    value={metrics?.by_severity?.high ?? '—'} color="orange" />
        </div>

        {/* Timeline Chart */}
        <div className="card mb-6">
          <h2 className="text-cyan-400 font-semibold mb-4">Actividad de Alertas — 24h</h2>
          {timeline.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={timeline}>
                <defs>
                  <linearGradient id="cGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00b4d8" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00b4d8" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="rGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#d92b2b" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#d92b2b" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#243e58" />
                <XAxis dataKey="timestamp" tick={{ fill: '#6b7280', fontSize: 10 }} tickFormatter={v => v.slice(11, 16)} />
                <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#1a2d42', border: '1px solid #00b4d8', borderRadius: 6, color: '#e0e8f0' }} />
                <Area type="monotone" dataKey="total"    stroke="#00b4d8" fill="url(#cGrad)" strokeWidth={2} name="Total" />
                <Area type="monotone" dataKey="critical" stroke="#d92b2b" fill="url(#rGrad)" strokeWidth={1.5} name="Críticas" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-48 flex items-center justify-center text-gray-500">Sin datos de actividad</div>
          )}
        </div>

        {/* Recent Alerts */}
        <div className="card">
          <h2 className="text-cyan-400 font-semibold mb-4">Alertas Recientes</h2>
          {alerts.length === 0 ? (
            <p className="text-gray-500 text-sm">Sin alertas en las últimas 24 horas.</p>
          ) : (
            <table className="table-asc">
              <thead>
                <tr>
                  <th>Título</th>
                  <th>Severidad</th>
                  <th>Risk Score</th>
                  <th>Estado</th>
                  <th>Detectada</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a: any) => (
                  <tr key={a.id}>
                    <td className="font-medium">{a.title}</td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td className="font-mono text-cyan-400">{Number(a.risk_score).toFixed(2)}</td>
                    <td className="text-gray-300">{a.status}</td>
                    <td className="text-gray-400 text-xs">{a.detected_at?.slice(0, 19).replace('T', ' ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </main>
    </div>
  )
}
