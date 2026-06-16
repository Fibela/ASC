'use client'
import { useEffect, useState } from 'react'
import {
  getDetectionRules, getSocMetrics, getAlerts, getTimeline,
  SocMetrics, AlertItem, TimelinePoint, DetectionRule,
} from '@/lib/api'
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
import {
  RefreshCw, Shield, AlertTriangle, Eye, Cpu,
  Clock, Activity, Target, CheckCircle, AlertCircle,
} from 'lucide-react'


const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'rgba(14,14,14,0.97)',
      border: '1px solid rgba(232,93,4,0.25)',
      borderRadius: 10,
      padding: '8px 12px',
      fontSize: 12,
      color: '#EAEAEA',
    }}>
      <p style={{ color: '#5A5A5A', marginBottom: 4 }}>{label}</p>
      {payload.map((p: any) => (
        <p key={p.name} style={{ color: p.color }}>
          {p.name}: <strong>{p.value}</strong>
        </p>
      ))}
    </div>
  )
}

// Minimal loading screen shown until auth check completes (prevents FOUC)
function AuthLoader() {
  return (
    <div className="flex min-h-screen items-center justify-center" style={{ background: '#0A0A0A' }}>
      <div className="w-5 h-5 rounded-full border-2 animate-spin"
        style={{ borderColor: 'rgba(232,93,4,0.2)', borderTopColor: '#E85D04' }} />
    </div>
  )
}

export default function DashboardPage() {
  const { isReady } = useAuthGuard()

  const [role, setRole]               = useState<string | null>(null)
  const [metrics, setMetrics]         = useState<SocMetrics | null>(null)
  const [alerts, setAlerts]           = useState<AlertItem[]>([])
  const [timeline, setTimeline]       = useState<TimelinePoint[]>([])
  const [rules, setRules]             = useState<DetectionRule[]>([])
  const [loading, setLoading]         = useState(true)
  const [error, setError]             = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState(new Date())

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const [m, a, t, r] = await Promise.all([
        getSocMetrics(24),
        getAlerts({ limit: 8 }),
        getTimeline(24),
        getDetectionRules(),
      ])
      setMetrics(m)
      setAlerts(a)
      setTimeline(t)
      // API always returns { rules: DetectionRule[] }; take up to 4 active ones
      setRules(r.rules.filter(x => x.is_active !== false).slice(0, 4))
      setLastRefresh(new Date())
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error desconocido'
      setError(`No se pudo conectar con el servidor ASC. ${msg}`)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!isReady) return
    setRole(getRole())
    load()
  }, [isReady])

  useEffect(() => {
    if (!isReady) return
    const id = setInterval(load, 30_000)
    return () => clearInterval(id)
  }, [isReady])

  // Block render until auth guard confirms the session is valid
  if (!isReady) return <AuthLoader />

  const posture    = metrics?.risk_posture ?? 'NORMAL'
  const bySeverity = metrics?.by_severity  ?? { critical: 0, high: 0, medium: 0, low: 0 }

  const ruleData = rules.map(r => ({
    ruleId:   r.rule_id,
    name:     r.name,
    ttp:      r.mitre_ttp ?? '—',
    severity: r.severity,
    count:    r.hit_count ?? 0,
  }))
  const maxCount = Math.max(...ruleData.map(r => r.count), 1)

  const sevData = [
    { name: 'Crítica', value: bySeverity.critical ?? 0, fill: '#C0152E' },
    { name: 'Alta',    value: bySeverity.high     ?? 0, fill: '#E85D04' },
    { name: 'Media',   value: bySeverity.medium   ?? 0, fill: '#F2C205' },
    { name: 'Baja',    value: bySeverity.low      ?? 0, fill: '#2DB863' },
  ]

  return (
    <div className="flex min-h-screen">
      <Sidebar />

      <main className="flex-1 overflow-auto" style={{ background: 'transparent' }}>

        {/* ── Top header bar ─────────────────────────────── */}
        <div
          className="sticky top-0 z-20 px-6 py-3 flex items-center justify-between"
          style={{
            background: 'rgba(10,10,10,0.92)',
            borderBottom: '1px solid rgba(255,255,255,0.05)',
            backdropFilter: 'blur(12px)',
          }}
        >
          <div className="flex items-center gap-3">
            <Shield size={18} style={{ color: '#E85D04' }} />
            <div>
              <h1 className="text-sm font-bold leading-none" style={{ color: '#EAEAEA' }}>
                SOC Dashboard
              </h1>
              <p className="text-xs mt-0.5" style={{ color: '#3A3A3A' }}>
                Últimas 24h · Auto-refresh 30s
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <span
              className="text-xs font-semibold px-2.5 py-1 rounded-lg uppercase tracking-wider"
              style={{
                background: 'rgba(232,93,4,0.1)',
                border: '1px solid rgba(232,93,4,0.2)',
                color: '#E85D04',
              }}
            >
              {role ?? '…'}
            </span>

            <span className="text-xs hidden sm:block" style={{ color: '#3A3A3A' }} suppressHydrationWarning>
              {lastRefresh.toLocaleTimeString()}
            </span>

            <button
              onClick={load}
              disabled={loading}
              className="btn-secondary flex items-center gap-1.5 text-xs py-1.5 px-3"
            >
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
              Actualizar
            </button>
          </div>
        </div>

        <div className="p-6 space-y-6 animate-fade-in">

          {/* ── Error banner ───────────────────────────────── */}
          {error && !loading && (
            <div
              className="flex items-center gap-3 px-5 py-3.5 rounded-xl text-sm"
              style={{
                background: 'rgba(192,21,46,0.08)',
                border: '1px solid rgba(192,21,46,0.28)',
                color: '#E8526E',
              }}
            >
              <AlertCircle size={16} className="flex-shrink-0" />
              <span>{error}</span>
              <button
                onClick={load}
                className="ml-auto text-xs underline hover:no-underline"
                style={{ color: '#E8526E' }}
              >
                Reintentar
              </button>
            </div>
          )}

          {/* ── Row 1: Postura + KPIs ──────────────────────── */}
          <div className="grid grid-cols-12 gap-4">

            <div
              className="col-span-12 md:col-span-3 rounded-2xl p-6 flex flex-col items-center justify-center gap-4"
              style={{
                background: 'rgba(14,14,14,0.8)',
                border: '1px solid rgba(255,255,255,0.06)',
                boxShadow: '0 1px 4px rgba(0,0,0,0.6)',
              }}
            >
              <p className="text-xs font-semibold uppercase tracking-widest" style={{ color: '#3A3A3A' }}>
                Postura de Riesgo
              </p>
              <Semaphore posture={posture} size="lg" />
              <div className="flex gap-5 text-center text-xs">
                <div>
                  <p className="text-xl font-bold" style={{ color: '#C0152E' }}>
                    {bySeverity.critical ?? 0}
                  </p>
                  <p style={{ color: '#5A5A5A' }}>Críticas</p>
                </div>
                <div>
                  <p className="text-xl font-bold" style={{ color: '#E85D04' }}>
                    {bySeverity.high ?? 0}
                  </p>
                  <p style={{ color: '#5A5A5A' }}>Altas</p>
                </div>
                <div>
                  <p className="text-xl font-bold" style={{ color: '#F2C205' }}>
                    {bySeverity.medium ?? 0}
                  </p>
                  <p style={{ color: '#5A5A5A' }}>Medias</p>
                </div>
              </div>
            </div>

            <div className="col-span-12 md:col-span-9 grid grid-cols-2 lg:grid-cols-4 gap-3">
              <MetricCard label="Total Alertas"    value={metrics?.total_alerts ?? '—'}   icon={Shield}       color="orange" />
              <MetricCard label="MTTD"             value={metrics?.mttd_minutes ?? '—'}   unit="min" sublabel="Mean Time to Detect"  icon={Clock}        color="amber" />
              <MetricCard label="MTTR"             value={metrics?.mttr_minutes ?? '—'}   unit="min" sublabel="Mean Time to Respond" icon={Activity}     color="amber" />
              <MetricCard label="Eventos 24h"      value={metrics?.total_events ?? '—'}   icon={Target}       color="default" />
              <MetricCard label="Tasa FP"          value={metrics?.false_positive_rate != null ? `${(metrics.false_positive_rate * 100).toFixed(1)}%` : '—'} sublabel="False Positive Rate" icon={CheckCircle}  color="green" />
              <MetricCard label="Cobertura IoC"    value={metrics?.ioc_coverage != null ? `${(metrics.ioc_coverage * 100).toFixed(1)}%` : '—'} icon={Eye}          color="green" />
              <MetricCard label="Alertas Abiertas" value={metrics?.open_alerts ?? '—'}    icon={AlertTriangle} color="red" />
              <MetricCard label="Contenidas"       value={metrics?.contained_alerts ?? '—'} icon={CheckCircle} color="green" />
            </div>
          </div>

          {/* ── Row 2: Timeline + Severity ─────────────────── */}
          <div className="grid grid-cols-12 gap-4">

            <div className="col-span-12 lg:col-span-8 card p-5">
              <div className="flex items-center justify-between mb-4">
                <h2 className="flex items-center gap-2 text-sm font-semibold" style={{ color: '#EAEAEA' }}>
                  <Eye size={15} style={{ color: '#E85D04' }} />
                  Actividad de Alertas — 24h
                </h2>
                <span className="chip-orange text-xs">24h</span>
              </div>
              {timeline.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={timeline}>
                    <defs>
                      <linearGradient id="gOrange" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#E85D04" stopOpacity={0.25} />
                        <stop offset="95%" stopColor="#E85D04" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="gRed" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#C0152E" stopOpacity={0.25} />
                        <stop offset="95%" stopColor="#C0152E" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                    <XAxis dataKey="timestamp" tick={{ fill: '#3A3A3A', fontSize: 10 }}
                      tickFormatter={v => v.slice(11, 16)} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#3A3A3A', fontSize: 10 }} allowDecimals={false}
                      axisLine={false} tickLine={false} />
                    <Tooltip content={<CustomTooltip />} />
                    <Area type="monotone" dataKey="total"    stroke="#E85D04" fill="url(#gOrange)" strokeWidth={2}   name="Total" />
                    <Area type="monotone" dataKey="critical" stroke="#C0152E" fill="url(#gRed)"    strokeWidth={1.5} name="Críticas" />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-48 flex items-center justify-center text-sm" style={{ color: '#3A3A3A' }}>
                  Sin datos de actividad en las últimas 24h
                </div>
              )}
            </div>

            <div className="col-span-12 lg:col-span-4 card p-5">
              <h2 className="flex items-center gap-2 text-sm font-semibold mb-4" style={{ color: '#EAEAEA' }}>
                <AlertTriangle size={15} style={{ color: '#E85D04' }} />
                Distribución
              </h2>
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={sevData} barCategoryGap="25%">
                  <XAxis dataKey="name" tick={{ fill: '#3A3A3A', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis hide allowDecimals={false} />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.02)' }} />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {sevData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* ── Row 3: Rules + Alerts ──────────────────────── */}
          <div className="grid grid-cols-12 gap-4">

            <div className="col-span-12 lg:col-span-5 card p-5">
              <h2 className="flex items-center gap-2 text-sm font-semibold mb-4" style={{ color: '#EAEAEA' }}>
                <Cpu size={15} style={{ color: '#E85D04' }} />
                Reglas de Detección Activas
              </h2>

              {loading && ruleData.length === 0 ? (
                <div className="space-y-2">
                  {[1, 2, 3, 4].map(i => (
                    <div key={i} className="h-10 rounded-lg animate-pulse"
                      style={{ background: 'rgba(255,255,255,0.03)' }} />
                  ))}
                </div>
              ) : ruleData.length === 0 ? (
                <div className="h-32 flex items-center justify-center text-sm" style={{ color: '#3A3A3A' }}>
                  Sin reglas de detección activas
                </div>
              ) : (
                <div className="space-y-1">
                  {ruleData.map(r => (
                    <RuleBar
                      key={r.ruleId}
                      ruleId={r.ruleId}
                      name={r.name}
                      ttp={r.ttp}
                      severity={r.severity}
                      count={r.count}
                      maxCount={maxCount}
                    />
                  ))}
                </div>
              )}

              <div className="mt-4 pt-3 flex items-center justify-between text-xs"
                style={{ borderTop: '1px solid rgba(255,255,255,0.05)', color: '#3A3A3A' }}>
                <span>{ruleData.length} reglas MITRE ATT&CK activas</span>
                <a href="/detection" style={{ color: '#E85D04' }}
                  className="hover:underline transition-opacity hover:opacity-80">
                  Ver detecciones →
                </a>
              </div>
            </div>

            <div className="col-span-12 lg:col-span-7 card p-5">
              <div className="flex items-center justify-between mb-4">
                <h2 className="flex items-center gap-2 text-sm font-semibold" style={{ color: '#EAEAEA' }}>
                  <Shield size={15} style={{ color: '#E85D04' }} />
                  Alertas Recientes
                </h2>
                <a href="/alerts" className="text-xs hover:underline" style={{ color: '#3A3A3A' }}
                  onMouseEnter={e => (e.currentTarget.style.color = '#E85D04')}
                  onMouseLeave={e => (e.currentTarget.style.color = '#3A3A3A')}>
                  Ver todas →
                </a>
              </div>

              {loading && alerts.length === 0 ? (
                <div className="space-y-2">
                  {[1, 2, 3, 4].map(i => (
                    <div key={i} className="h-10 rounded-lg animate-pulse"
                      style={{ background: 'rgba(255,255,255,0.03)' }} />
                  ))}
                </div>
              ) : alerts.length === 0 ? (
                <div className="h-32 flex items-center justify-center text-sm" style={{ color: '#3A3A3A' }}>
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
                        <td className="max-w-[200px] truncate font-medium text-xs" style={{ color: '#EAEAEA' }}>
                          {a.title}
                        </td>
                        <td><SeverityBadge severity={a.severity} /></td>
                        <td className="font-mono text-xs font-bold" style={{ color: '#E85D04' }}>
                          {Number(a.risk_score).toFixed(2)}
                        </td>
                        <td className="text-xs" style={{ color: '#5A5A5A' }}>{a.status}</td>
                        <td className="font-mono text-xs" style={{ color: '#3A3A3A' }}>
                          {a.detected_at?.slice(11, 19)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

        </div>
      </main>
    </div>
  )
}
