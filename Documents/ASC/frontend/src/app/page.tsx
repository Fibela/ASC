'use client'
import { useEffect, useState } from 'react'
import { getSocMetrics, getAlerts, getTimeline } from '@/lib/api'
import { useAuthGuard } from '@/lib/auth-guard'
import { getRole } from '@/lib/auth'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { MetricCard } from '@/components/dashboard/MetricCard'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import { Semaphore } from '@/components/dashboard/Semaphore'
import { RuleBar } from '@/components/dashboard/RuleBar'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  BarChart, Bar, Cell,
} from 'recharts'
import { RefreshCw, Shield, AlertTriangle, Eye, Cpu } from 'lucide-react'

// Detection rules metadata for the breakdown widget
const RULES = [
  { ruleId: 'DET-001', name: 'Suspicious acord32.exe', ttp: 'T1036.005', severity: 'critical' },
  { ruleId: 'DET-002', name: 'Windows Hook API',       ttp: 'T1056.001', severity: 'critical' },
  { ruleId: 'DET-003', name: 'Registry Persistence',   ttp: 'T1547.001', severity: 'high'     },
  { ruleId: 'DET-004', name: 'Deferred Network Traffic',ttp: 'T1071.001', severity: 'critical' },
]

export default function DashboardPage() {
  useAuthGuard()
  const [role, setRole] = useState<string | null>(null)

  const [metrics, setMetrics]     = useState<any>(null)
  const [alerts, setAlerts]       = useState<any[]>([])
  const [timeline, setTimeline]   = useState<any[]>([])
  const [loading, setLoading]     = useState(true)
  const [lastRefresh, setLastRefresh] = useState(new Date())

  async function load() {
    setLoading(true)
    try {
      const [m, a, t] = await Promise.all([
        getSocMetrics(24),
        getAlerts({ limit: 8 }),
        getTimeline(24),
      ])
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

  useEffect(() => {
    setRole(getRole())
    load()
  }, [])
  useEffect(() => {
    const interval = setInterval(load, 30_000)
    return () => clearInterval(interval)
  }, [])

  const posture = metrics?.risk_posture ?? 'NORMAL'

  // Simulate per-rule counts from alerts until detection endpoint is wired
  const bySeverity = metrics?.by_severity ?? {}
  const ruleData = RULES.map((r, i) => ({
    ...r,
    count: [bySeverity.critical ?? 0, bySeverity.critical ?? 0, bySeverity.high ?? 0, bySeverity.high ?? 0][i] ?? 0,
  }))
  const maxCount = Math.max(...ruleData.map(r => r.count), 1)

  // Severity distribution for bar chart
  const sevData = [
    { name: 'Critical', value: bySeverity.critical ?? 0, fill: '#d92b2b' },
    { name: 'High',     value: bySeverity.high     ?? 0, fill: '#e5720d' },
    { name: 'Medium',   value: bySeverity.medium   ?? 0, fill: '#f2c205' },
    { name: 'Low',      value: bySeverity.low      ?? 0, fill: '#34b85a' },
  ]

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6 overflow-auto">

        {/* ─── Header ─── */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <Shield className="text-cyan-400" size={24} />
              SOC Dashboard
            </h1>
            <p className="text-gray-500 text-xs mt-0.5">
              Últimas 24h · Auto-refresh 30s · Rol: <span className="text-cyan-400">{role ?? '…'}</span> ·
              Actualizado: <span className="text-gray-400">{lastRefresh.toLocaleTimeString()}</span>
            </p>
          </div>
          <button onClick={load} disabled={loading}
            className="btn-primary flex items-center gap-2 text-sm py-1.5 disabled:opacity-50">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Actualizar
          </button>
        </div>

        {/* ─── Row 1: Semaphore + KPI Cards ─── */}
        <div className="grid grid-cols-12 gap-4 mb-6">

          {/* Semaphore widget */}
          <div className="col-span-12 md:col-span-3 card flex flex-col items-center justify-center gap-4 py-6">
            <p className="text-xs text-gray-500 uppercase tracking-widest">Postura de Riesgo</p>
            <Semaphore posture={posture} size="lg" />
            <div className="flex gap-4 text-center text-xs">
              <div>
                <p className="text-red-400 font-bold text-lg">{bySeverity.critical ?? 0}</p>
                <p className="text-gray-500">Críticas</p>
              </div>
              <div>
                <p className="text-orange-400 font-bold text-lg">{bySeverity.high ?? 0}</p>
                <p className="text-gray-500">Altas</p>
              </div>
              <div>
                <p className="text-yellow-400 font-bold text-lg">{bySeverity.medium ?? 0}</p>
                <p className="text-gray-500">Medias</p>
              </div>
            </div>
          </div>

          {/* KPI grid */}
          <div className="col-span-12 md:col-span-9 grid grid-cols-2 lg:grid-cols-4 gap-4">
            <MetricCard label="Total Alertas"   value={metrics?.total_alerts ?? '—'}   color="cyan" />
            <MetricCard label="MTTD"            value={metrics?.mttd_minutes ?? '—'}   unit="min" color="orange" sublabel="Mean Time to Detect" />
            <MetricCard label="MTTR"            value={metrics?.mttr_minutes ?? '—'}   unit="min" color="orange" sublabel="Mean Time to Respond" />
            <MetricCard label="Eventos 24h"     value={metrics?.total_events ?? '—'}   color="cyan" />
            <MetricCard label="Tasa FP"         value={metrics?.false_positive_rate != null ? `${(metrics.false_positive_rate * 100).toFixed(1)}%` : '—'} color="green" sublabel="False Positive Rate" />
            <MetricCard label="Cobertura IoC"   value={metrics?.ioc_coverage != null ? `${(metrics.ioc_coverage * 100).toFixed(1)}%` : '—'} color="green" />
            <MetricCard label="Alertas Abiertas" value={metrics?.open_alerts ?? metrics?.total_alerts ?? '—'} color="cyan" />
            <MetricCard label="Contenidas"      value={metrics?.contained_alerts ?? '—'} color="green" />
          </div>
        </div>

        {/* ─── Row 2: Timeline + Severity Bar ─── */}
        <div className="grid grid-cols-12 gap-4 mb-6">

          {/* Timeline */}
          <div className="col-span-12 lg:col-span-8 card">
            <h2 className="text-cyan-400 font-semibold mb-4 flex items-center gap-2">
              <Eye size={16} /> Actividad de Alertas — 24h
            </h2>
            {timeline.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={timeline}>
                  <defs>
                    <linearGradient id="cGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#00b4d8" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#00b4d8" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="rGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#d92b2b" stopOpacity={0.3} />
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
              <div className="h-48 flex items-center justify-center text-gray-500 text-sm">
                Sin datos de actividad en las últimas 24h
              </div>
            )}
          </div>

          {/* Severity distribution */}
          <div className="col-span-12 lg:col-span-4 card">
            <h2 className="text-cyan-400 font-semibold mb-4 flex items-center gap-2">
              <AlertTriangle size={16} /> Distribución de Severidad
            </h2>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={sevData} barCategoryGap="20%">
                <XAxis dataKey="name" tick={{ fill: '#6b7280', fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis hide allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#1a2d42', border: '1px solid #00b4d8', borderRadius: 6, color: '#e0e8f0' }} cursor={{ fill: '#1e3448' }} />
                <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                  {sevData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ─── Row 3: Detection Rules + Recent Alerts ─── */}
        <div className="grid grid-cols-12 gap-4 mb-6">

          {/* Detection rules breakdown */}
          <div className="col-span-12 lg:col-span-5 card">
            <h2 className="text-cyan-400 font-semibold mb-4 flex items-center gap-2">
              <Cpu size={16} /> Reglas de Detección Activas
            </h2>
            <div className="space-y-1">
              {RULES.map(r => (
                <RuleBar
                  key={r.ruleId}
                  ruleId={r.ruleId}
                  name={r.name}
                  ttp={r.ttp}
                  severity={r.severity}
                  count={ruleData.find(x => x.ruleId === r.ruleId)?.count ?? 0}
                  maxCount={maxCount}
                />
              ))}
            </div>
            <div className="mt-4 pt-3 border-t border-navy-700 flex items-center justify-between text-xs text-gray-500">
              <span>4 reglas MITRE ATT&CK activas</span>
              <a href="/detection" className="text-cyan-400 hover:underline">Ver detecciones →</a>
            </div>
          </div>

          {/* Recent alerts */}
          <div className="col-span-12 lg:col-span-7 card">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-cyan-400 font-semibold flex items-center gap-2">
                <Shield size={16} /> Alertas Recientes
              </h2>
              <a href="/alerts" className="text-xs text-gray-500 hover:text-cyan-400">Ver todas →</a>
            </div>
            {alerts.length === 0 ? (
              <div className="h-32 flex items-center justify-center text-gray-500 text-sm">
                Sin alertas en las últimas 24 horas
              </div>
            ) : (
              <table className="table-asc">
                <thead>
                  <tr>
                    <th>Título</th>
                    <th>Sev.</th>
                    <th>Score</th>
                    <th>Estado</th>
                    <th>Hora</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((a: any) => (
                    <tr key={a.id}>
                      <td className="max-w-[180px] truncate font-medium text-xs">{a.title}</td>
                      <td><SeverityBadge severity={a.severity} /></td>
                      <td className="font-mono text-cyan-400 text-xs">{Number(a.risk_score).toFixed(2)}</td>
                      <td className="text-gray-400 text-xs">{a.status}</td>
                      <td className="text-gray-500 text-xs">{a.detected_at?.slice(11, 19)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

      </main>
    </div>
  )
}
