'use client'
import { useEffect, useState } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { MetricCard } from '@/components/dashboard/MetricCard'
import { Semaphore } from '@/components/dashboard/Semaphore'
import { useAuthGuard } from '@/lib/auth-guard'
import { getSocMetrics, getTimeline, getAlertStats } from '@/lib/api'
import { BarChart3, RefreshCw, TrendingUp, TrendingDown, Minus } from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  RadialBarChart, RadialBar, PieChart, Pie, Cell, Legend,
} from 'recharts'

const COLORS = ['#d92b2b', '#e5720d', '#f2c205', '#34b85a']

export default function MetricsPage() {
  useAuthGuard()
  const [metrics24, setMetrics24]   = useState<any>(null)
  const [metrics7d, setMetrics7d]   = useState<any>(null)
  const [timeline, setTimeline]     = useState<any[]>([])
  const [alertStats, setAlertStats] = useState<any>(null)
  const [loading, setLoading]       = useState(true)
  const [period, setPeriod]         = useState(24)

  async function load() {
    setLoading(true)
    try {
      const [m24, m7d, tl, ast] = await Promise.all([
        getSocMetrics(24),
        getSocMetrics(168),
        getTimeline(period),
        getAlertStats().catch(() => null),
      ])
      setMetrics24(m24)
      setMetrics7d(m7d)
      setTimeline(tl)
      setAlertStats(ast)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [period])

  const sevPie = metrics24?.by_severity
    ? [
        { name: 'Critical', value: metrics24.by_severity.critical ?? 0 },
        { name: 'High',     value: metrics24.by_severity.high     ?? 0 },
        { name: 'Medium',   value: metrics24.by_severity.medium   ?? 0 },
        { name: 'Low',      value: metrics24.by_severity.low      ?? 0 },
      ]
    : []

  function trend(a: number, b: number) {
    if (a === b) return <Minus size={12} className="text-gray-500" />
    return a > b
      ? <TrendingUp   size={12} className="text-red-400" />
      : <TrendingDown size={12} className="text-green-400" />
  }

  const iocCovPct  = Math.round((metrics24?.ioc_coverage ?? 0) * 100)
  const fpRatePct  = Math.round((metrics24?.false_positive_rate ?? 0) * 100)

  const radialData = [
    { name: 'IoC Coverage', value: iocCovPct, fill: '#00b4d8' },
    { name: 'FP Rate',      value: fpRatePct, fill: '#d92b2b' },
  ]

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6 overflow-auto">
        <div className="flex items-center justify-between mb-1">
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <BarChart3 className="text-cyan-400" size={22} />
            Métricas SOC
          </h1>
          <div className="flex items-center gap-3">
            <div className="flex rounded overflow-hidden border border-navy-700">
              {[24, 48, 168].map(h => (
                <button key={h} onClick={() => setPeriod(h)}
                  className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                    period === h ? 'bg-cyan-400 text-navy-900' : 'bg-navy-800 text-gray-400 hover:text-white'
                  }`}>
                  {h === 24 ? '24h' : h === 48 ? '48h' : '7d'}
                </button>
              ))}
            </div>
            <button onClick={load} disabled={loading} className="btn-primary text-sm py-1.5 flex items-center gap-2">
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Actualizar
            </button>
          </div>
        </div>
        <p className="text-gray-500 text-xs mb-6">MTTD · MTTR · Cobertura IoC · Tasa de Falsos Positivos · Distribución de Severidad</p>

        {/* ─── Row 1: Posture + KPIs ─── */}
        <div className="grid grid-cols-12 gap-4 mb-6">
          <div className="col-span-12 md:col-span-3 card flex flex-col items-center justify-center py-6 gap-3">
            <p className="text-xs text-gray-500 uppercase tracking-widest">Postura Actual</p>
            <Semaphore posture={metrics24?.risk_posture ?? 'NORMAL'} size="lg" />
            <div className="text-center">
              <p className="text-xs text-gray-600">Período 24h vs 7d</p>
              <div className="flex items-center gap-1 justify-center mt-1">
                {metrics24 && metrics7d && trend(metrics24.total_alerts, metrics7d.total_alerts / 7)}
                <span className="text-xs text-gray-500">{metrics24?.total_alerts ?? 0} vs {metrics7d ? (metrics7d.total_alerts / 7).toFixed(0) : 0} alertas/día</span>
              </div>
            </div>
          </div>

          <div className="col-span-12 md:col-span-9 grid grid-cols-2 lg:grid-cols-4 gap-4">
            <MetricCard label="Total Alertas 24h"  value={metrics24?.total_alerts ?? '—'} color="cyan" />
            <MetricCard label="Total Alertas 7d"   value={metrics7d?.total_alerts ?? '—'} color="cyan" />
            <MetricCard label="MTTD (24h)"         value={metrics24?.mttd_minutes ?? '—'} unit="min" color="orange" sublabel="Mean Time to Detect" />
            <MetricCard label="MTTR (24h)"         value={metrics24?.mttr_minutes ?? '—'} unit="min" color="orange" sublabel="Mean Time to Respond" />
            <MetricCard label="Eventos Ingestados" value={metrics24?.total_events ?? '—'} color="cyan" />
            <MetricCard label="Cobertura IoC"      value={`${iocCovPct}%`} color="green" />
            <MetricCard label="Tasa Falsos Pos."   value={`${fpRatePct}%`} color={fpRatePct > 20 ? 'red' : 'green'} />
            <MetricCard label="Críticas 7d"        value={metrics7d?.by_severity?.critical ?? '—'} color="red" />
          </div>
        </div>

        {/* ─── Row 2: Timeline + Pie ─── */}
        <div className="grid grid-cols-12 gap-4 mb-6">
          <div className="col-span-12 lg:col-span-8 card">
            <h3 className="text-cyan-400 font-semibold mb-4">Actividad de Alertas — {period === 168 ? '7 días' : `${period}h`}</h3>
            {timeline.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={timeline}>
                  <defs>
                    <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#00b4d8" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#00b4d8" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="g2" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#d92b2b" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#d92b2b" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#243e58" />
                  <XAxis dataKey="timestamp" tick={{ fill: '#6b7280', fontSize: 10 }} tickFormatter={v => v.slice(5, 16)} />
                  <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: '#1a2d42', border: '1px solid #00b4d8', borderRadius: 6, color: '#e0e8f0' }} />
                  <Area type="monotone" dataKey="total"    stroke="#00b4d8" fill="url(#g1)" strokeWidth={2} name="Total" />
                  <Area type="monotone" dataKey="critical" stroke="#d92b2b" fill="url(#g2)" strokeWidth={1.5} name="Críticas" />
                  <Area type="monotone" dataKey="high"     stroke="#e5720d" fill="none"       strokeWidth={1} name="Altas" strokeDasharray="4 2" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-52 flex items-center justify-center text-gray-500 text-sm">Sin datos de actividad</div>
            )}
          </div>

          <div className="col-span-12 lg:col-span-4 card flex flex-col">
            <h3 className="text-cyan-400 font-semibold mb-4">Distribución de Severidad (24h)</h3>
            {sevPie.every(s => s.value === 0) ? (
              <div className="flex-1 flex items-center justify-center text-gray-500 text-sm">Sin alertas en 24h</div>
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={sevPie} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={3} dataKey="value">
                    {sevPie.map((_, i) => <Cell key={i} fill={COLORS[i]} />)}
                  </Pie>
                  <Legend iconSize={10} formatter={v => <span style={{ fontSize: 11, color: '#9ca3af' }}>{v}</span>} />
                  <Tooltip contentStyle={{ background: '#1a2d42', border: '1px solid #00b4d8', borderRadius: 6, color: '#e0e8f0', fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* ─── Row 3: Radial gauges ─── */}
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12 md:col-span-6 card">
            <h3 className="text-cyan-400 font-semibold mb-4">Indicadores de Efectividad</h3>
            <div className="flex items-center gap-8">
              <ResponsiveContainer width={160} height={160}>
                <RadialBarChart innerRadius={30} outerRadius={70} data={radialData} startAngle={90} endAngle={-270}>
                  {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                  <RadialBar minAngle={5} dataKey="value" {...{ cornerRadius: 4 } as any} />
                  <Tooltip contentStyle={{ background: '#1a2d42', border: '1px solid #00b4d8', borderRadius: 6, fontSize: 12 }} formatter={(v: any) => `${v}%`} />
                </RadialBarChart>
              </ResponsiveContainer>
              <div className="space-y-4">
                <div>
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-cyan-400" />
                    <span className="text-xs text-gray-400">Cobertura IoC</span>
                  </div>
                  <p className="text-2xl font-bold text-cyan-400 ml-5">{iocCovPct}%</p>
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500" />
                    <span className="text-xs text-gray-400">Tasa Falsos Pos.</span>
                  </div>
                  <p className={`text-2xl font-bold ml-5 ${fpRatePct > 20 ? 'text-red-400' : 'text-green-400'}`}>{fpRatePct}%</p>
                </div>
              </div>
            </div>
          </div>

          {alertStats && (
            <div className="col-span-12 md:col-span-6 card">
              <h3 className="text-cyan-400 font-semibold mb-4">Resumen por Estado</h3>
              <div className="space-y-2">
                {Object.entries(alertStats).map(([status, count]: any) => (
                  <div key={status} className="flex items-center justify-between">
                    <span className="text-sm text-gray-400 capitalize">{status.replace('_', ' ')}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-24 h-1.5 bg-navy-900 rounded-full overflow-hidden">
                        <div className="h-full bg-cyan-400 rounded-full" style={{ width: `${Math.min((count / (metrics24?.total_alerts || 1)) * 100, 100)}%` }} />
                      </div>
                      <span className="font-mono text-xs text-cyan-400 w-8 text-right">{count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
