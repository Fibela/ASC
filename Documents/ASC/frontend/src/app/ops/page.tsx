'use client'

import { useEffect, useState, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'
import {
  getFleetSummary, getCommandMetrics, getInflightCommands, getNeutralizationMetrics,
  getCrossDomainMetrics,
  FleetSummary, CommandMetrics, InflightCommandsResponse, NeutralizationMetrics, CrossDomainMetrics,
} from '@/lib/api'
import { useSSENotifications, SSENotification } from '@/lib/useSSENotifications'
import {
  MonitorDot, RefreshCw, Wifi, WifiOff, AlertTriangle, CheckCircle2, XCircle,
  Clock, Zap, Activity, ShieldAlert, TrendingUp, Bell, BellOff,
  Brain, Search, Database, Globe,
} from 'lucide-react'

// ── Pure helpers (exported for tests) ────────────────────────────────────────

export function formatAge(seconds: number | null): string {
  if (seconds === null) return '—'
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  return `${Math.round(seconds / 3600)}h`
}

export function formatTs(ts: string | null | undefined): string {
  if (!ts) return '—'
  try { return new Date(ts).toLocaleString() } catch { return ts }
}

export function statusColor(status: string): string {
  switch (status) {
    case 'completed':  return 'text-green-400'
    case 'executing':  return 'text-cyan-400'
    case 'delivered':  return 'text-blue-400'
    case 'pending':    return 'text-yellow-400'
    case 'failed':     return 'text-red-400'
    case 'cancelled':  return 'text-gray-500'
    default:           return 'text-gray-400'
  }
}

export function threatColor(level: string): string {
  switch (level) {
    case 'critical': return 'text-red-400 bg-red-400/10'
    case 'elevated': return 'text-yellow-400 bg-yellow-400/10'
    default:         return 'text-green-400 bg-green-400/10'
  }
}

// ── KPI Card ──────────────────────────────────────────────────────────────────

function KpiCard({
  label, value, sub, accent = 'cyan', icon: Icon,
}: {
  label: string
  value: string | number
  sub?: string
  accent?: 'cyan' | 'green' | 'yellow' | 'red'
  icon: React.ElementType
}) {
  const accentCls = {
    cyan:   'text-cyan-400 bg-cyan-400/10',
    green:  'text-green-400 bg-green-400/10',
    yellow: 'text-yellow-400 bg-yellow-400/10',
    red:    'text-red-400 bg-red-400/10',
  }[accent]
  return (
    <div className="bg-navy-800 border border-navy-700 rounded-lg p-4 flex items-start gap-3">
      <div className={`p-2 rounded ${accentCls}`}>
        <Icon size={18} />
      </div>
      <div>
        <p className="text-xs text-gray-400 mb-0.5">{label}</p>
        <p className="text-2xl font-bold text-white leading-none">{value}</p>
        {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
      </div>
    </div>
  )
}

// ── Stat pill ─────────────────────────────────────────────────────────────────

function StatPill({ label, value, cls = 'text-gray-300' }: { label: string; value: number; cls?: string }) {
  return (
    <div className="flex items-center justify-between py-1 border-b border-navy-700 last:border-0">
      <span className="text-xs text-gray-400">{label}</span>
      <span className={`text-sm font-semibold ${cls}`}>{value}</span>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function OpsDashboardPage() {
  const { isReady } = useAuthGuard()

  const [fleet, setFleet]         = useState<FleetSummary | null>(null)
  const [cmdMetrics, setCmdMetrics]   = useState<CommandMetrics | null>(null)
  const [inflight, setInflight]   = useState<InflightCommandsResponse | null>(null)
  const [neut, setNeut]           = useState<NeutralizationMetrics | null>(null)
  const [crossDomain, setCrossDomain] = useState<CrossDomainMetrics | null>(null)
  const [loading, setLoading]     = useState(true)
  const [hours, setHours]         = useState(24)
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null)
  const [sseToasts, setSSEToasts] = useState<SSENotification[]>([])

  // P21-F4: SSE hook — auto-refresh on relevant neutralization events
  const { connected: sseConnected } = useSSENotifications({
    onEvent: (evt) => {
      const relevant = ['pending_approval_created', 'action_completed', 'action_failed', 'action_escalated']
      if (relevant.includes(evt.type)) {
        setSSEToasts(prev => [evt, ...prev].slice(0, 5))
        load()
      }
    },
  })

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [f, cm, inf, nm, xd] = await Promise.all([
        getFleetSummary(),
        getCommandMetrics(hours),
        getInflightCommands(100),
        getNeutralizationMetrics(hours),
        getCrossDomainMetrics(hours),
      ])
      setFleet(f)
      setCmdMetrics(cm)
      setInflight(inf)
      setNeut(nm)
      setCrossDomain(xd)
      setLastRefresh(new Date())
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [hours])

  useEffect(() => { if (!isReady) return; load() }, [load, isReady])

  // Auto-refresh every 30 seconds
  useEffect(() => {
    if (!isReady) return
    const id = setInterval(load, 30_000)
    return () => clearInterval(id)
  }, [load, isReady])

  if (!isReady) return <AuthLoader />

  return (
    <div className="flex min-h-screen bg-navy-900 text-white">
      <Sidebar />
      <main className="flex-1 p-6 overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <MonitorDot size={22} className="text-cyan-400" />
            <div>
              <h1 className="text-xl font-bold text-white">Dashboard Operativo</h1>
              <p className="text-xs text-gray-400">Flota SPECTER · Pipeline de comandos · Neutralizaciones</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <select
              value={hours}
              onChange={e => setHours(Number(e.target.value))}
              className="text-xs bg-navy-800 border border-navy-700 rounded px-2 py-1 text-gray-300"
            >
              <option value={1}>Última hora</option>
              <option value={6}>Últimas 6h</option>
              <option value={24}>Últimas 24h</option>
              <option value={72}>Últimas 72h</option>
              <option value={168}>7 días</option>
            </select>
            <span className={`flex items-center gap-1 text-xs ${sseConnected ? 'text-green-400' : 'text-gray-600'}`}>
              {sseConnected ? <Bell size={12} /> : <BellOff size={12} />}
              SSE
            </span>
            <button
              onClick={load}
              disabled={loading}
              className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-cyan-400 transition-colors disabled:opacity-40"
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
              {lastRefresh ? `Actualizado ${lastRefresh.toLocaleTimeString()}` : 'Actualizar'}
            </button>
          </div>
        </div>

        {/* SSE event toasts */}
        {sseToasts.length > 0 && (
          <div className="mb-4 space-y-1">
            {sseToasts.map((t, i) => (
              <div key={i} className="flex items-center gap-2 text-xs bg-navy-800 border border-cyan-700/40 rounded px-3 py-2 text-cyan-300">
                <Bell size={12} className="text-cyan-400 shrink-0" />
                <span className="font-semibold">{t.type}</span>
                {t.action_type && <span className="text-gray-400">— {t.action_type}</span>}
                {t.target && <span className="text-gray-500 truncate max-w-xs">{t.target}</span>}
                <button onClick={() => setSSEToasts(p => p.filter((_, j) => j !== i))}
                  className="ml-auto text-gray-600 hover:text-white">×</button>
              </div>
            ))}
          </div>
        )}

        {loading && !fleet ? (
          <div className="text-center text-gray-500 py-20">Cargando métricas operativas…</div>
        ) : (
          <>
            {/* ── Fleet KPIs ── */}
            <section className="mb-6">
              <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Activity size={14} /> Flota SPECTER
              </h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <KpiCard label="Total Agentes"   value={fleet?.total_agents ?? 0}                    icon={MonitorDot} accent="cyan"   />
                <KpiCard label="En línea (5 min)" value={fleet?.connectivity.online_5m ?? 0}         icon={Wifi}       accent="green"  sub="activos recientes" />
                <KpiCard label="Fuera de línea"  value={fleet?.connectivity.offline ?? 0}             icon={WifiOff}    accent="yellow" />
                <KpiCard label="En riesgo"       value={fleet?.at_risk ?? 0}                          icon={AlertTriangle} accent="red" sub="elevado + crítico" />
              </div>
            </section>

            {/* ── Fleet breakdown + Command status side by side ── */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              {/* Fleet by status */}
              <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Estado de agentes</h3>
                {Object.entries(fleet?.by_status ?? {}).map(([k, v]) => (
                  <StatPill key={k} label={k} value={v as number}
                    cls={k === 'active' ? 'text-green-400' : k === 'compromised' ? 'text-red-400' : 'text-yellow-400'} />
                ))}
                {!fleet?.by_status && <p className="text-xs text-gray-500">Sin datos</p>}
              </div>

              {/* Fleet by threat */}
              <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Nivel de amenaza</h3>
                {Object.entries(fleet?.by_threat_level ?? {}).map(([k, v]) => (
                  <StatPill key={k} label={k} value={v as number}
                    cls={k === 'critical' ? 'text-red-400' : k === 'elevated' ? 'text-yellow-400' : 'text-green-400'} />
                ))}
                {!fleet?.by_threat_level && <p className="text-xs text-gray-500">Sin datos</p>}
              </div>

              {/* Command status */}
              <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Comandos por estado</h3>
                {Object.entries(cmdMetrics?.by_status ?? {}).map(([k, v]) => (
                  <StatPill key={k} label={k} value={v as number} cls={statusColor(k)} />
                ))}
                {!cmdMetrics?.by_status && <p className="text-xs text-gray-500">Sin datos</p>}
              </div>
            </div>

            {/* ── Command metrics KPIs ── */}
            <section className="mb-6">
              <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <TrendingUp size={14} /> Pipeline de Comandos — últimas {hours}h
              </h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <KpiCard label="Total comandos"   value={cmdMetrics?.total_commands ?? 0}                      icon={Zap}         accent="cyan"  />
                <KpiCard label="Tasa de éxito"    value={cmdMetrics?.success_rate_pct != null ? `${cmdMetrics.success_rate_pct}%` : '—'} icon={CheckCircle2} accent="green" />
                <KpiCard label="Latencia p50"     value={cmdMetrics?.latency.p50_ms != null ? `${cmdMetrics.latency.p50_ms}ms` : '—'}   icon={Clock}       accent="cyan"  />
                <KpiCard label="Latencia p95"     value={cmdMetrics?.latency.p95_ms != null ? `${cmdMetrics.latency.p95_ms}ms` : '—'}   icon={Clock}       accent={cmdMetrics?.latency.p95_ms && cmdMetrics.latency.p95_ms > 5000 ? 'yellow' : 'cyan'} />
              </div>
            </section>

            {/* ── In-flight commands table ── */}
            <section className="mb-6">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
                  <Clock size={14} /> Comandos en vuelo
                  {(inflight?.total_inflight ?? 0) > 0 && (
                    <span className="ml-1 px-1.5 py-0.5 rounded text-xs bg-yellow-400/10 text-yellow-400">
                      {inflight?.total_inflight}
                    </span>
                  )}
                </h2>
              </div>
              <div className="bg-navy-800 border border-navy-700 rounded-lg overflow-x-auto">
                {(inflight?.commands ?? []).length === 0 ? (
                  <p className="text-center text-gray-500 text-sm py-6">Sin comandos en vuelo ✓</p>
                ) : (
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-navy-700 text-gray-400">
                        <th className="px-4 py-2 text-left">Tipo</th>
                        <th className="px-4 py-2 text-left">Estado</th>
                        <th className="px-4 py-2 text-left">Agente</th>
                        <th className="px-4 py-2 text-left">Emitido por</th>
                        <th className="px-4 py-2 text-left">Edad</th>
                        <th className="px-4 py-2 text-left">Emitido</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(inflight?.commands ?? []).map(cmd => (
                        <tr key={cmd.id} className="border-b border-navy-700/50 hover:bg-navy-700/30 transition-colors">
                          <td className="px-4 py-2 font-mono text-cyan-300">{cmd.command_type}</td>
                          <td className={`px-4 py-2 font-semibold ${statusColor(cmd.status)}`}>{cmd.status}</td>
                          <td className="px-4 py-2 text-gray-400 font-mono text-xs">{cmd.agent_id.slice(0, 8)}…</td>
                          <td className="px-4 py-2 text-gray-300">{cmd.issued_by.slice(0, 16)}</td>
                          <td className={`px-4 py-2 ${(cmd.age_seconds ?? 0) > 300 ? 'text-yellow-400' : 'text-gray-300'}`}>
                            {formatAge(cmd.age_seconds)}
                          </td>
                          <td className="px-4 py-2 text-gray-400">{formatTs(cmd.issued_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </section>

            {/* ── Neutralization metrics ── */}
            <section className="mb-6">
              <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <ShieldAlert size={14} /> Neutralizaciones — últimas {hours}h
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Por estado</h3>
                  {Object.entries(neut?.by_status ?? {}).map(([k, v]) => (
                    <StatPill key={k} label={k} value={v as number}
                      cls={k === 'completed' ? 'text-green-400' : k === 'failed' || k === 'escalated' ? 'text-red-400' : 'text-gray-300'} />
                  ))}
                  {!neut?.by_status && <p className="text-xs text-gray-500">Sin datos</p>}
                </div>

                <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Por tipo de acción</h3>
                  {Object.entries(neut?.by_type ?? {}).map(([k, v]) => (
                    <StatPill key={k} label={k} value={v as number} />
                  ))}
                  {!neut?.by_type && <p className="text-xs text-gray-500">Sin datos</p>}
                </div>

                <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Por severidad</h3>
                  {Object.entries(neut?.by_severity ?? {}).map(([k, v]) => (
                    <StatPill key={k} label={k} value={v as number}
                      cls={k === 'critical' ? 'text-red-400' : k === 'high' ? 'text-orange-400' : k === 'medium' ? 'text-yellow-400' : 'text-blue-400'} />
                  ))}
                  {!neut?.by_severity && <p className="text-xs text-gray-500">Sin datos</p>}
                </div>
              </div>

              {/* Escalations alert */}
              {(neut?.escalation_count ?? 0) > 0 && (
                <div className="mt-3 bg-red-900/20 border border-red-700/50 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <AlertTriangle size={14} className="text-red-400" />
                    <span className="text-xs font-semibold text-red-400 uppercase">
                      {neut?.escalation_count} escalaciones sin aprobación en las últimas {hours}h
                    </span>
                  </div>
                  <div className="space-y-1">
                    {neut?.escalations.map(e => (
                      <div key={e.id} className="flex items-center gap-3 text-xs text-gray-300">
                        <span className="font-mono text-red-300">{e.action_type}</span>
                        <span className="text-gray-500">→</span>
                        <span>{e.target}</span>
                        <span className="text-gray-500">{formatTs(e.escalated_at)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Approval rate */}
              {neut?.approval_rate_pct != null && (
                <div className="mt-3 flex items-center gap-3 text-sm text-gray-300">
                  <CheckCircle2 size={14} className="text-green-400" />
                  <span>Tasa de aprobación: <strong className="text-green-400">{neut.approval_rate_pct}%</strong></span>
                  <span className="text-gray-500">|</span>
                  <span>Total: {neut.total_actions} acciones</span>
                </div>
              )}
            </section>

            {/* ── Cross-Domain Intelligence Panel ── */}
            {crossDomain && (
              <section className="mb-6">
                <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Brain size={14} className="text-purple-400" />
                  Inteligencia Cruzada PCDI — últimas {hours}h
                </h2>

                {/* Top KPIs row */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                  <KpiCard
                    label="Hunts Críticos Activos"
                    value={crossDomain.hunting.critical_priority_hunts}
                    icon={Search}
                    accent={crossDomain.hunting.critical_priority_hunts > 0 ? 'red' : 'green'}
                    sub={`de ${crossDomain.hunting.active_hunts} activos`}
                  />
                  <KpiCard
                    label="Hallazgos Alto/Crítico"
                    value={crossDomain.hunting.high_severity_findings}
                    icon={AlertTriangle}
                    accent={crossDomain.hunting.high_severity_findings > 0 ? 'yellow' : 'green'}
                    sub="en hunts activos"
                  />
                  <KpiCard
                    label="Indicadores TI Totales"
                    value={crossDomain.threat_intel.total_indicators}
                    icon={Database}
                    accent="cyan"
                    sub={`+${crossDomain.threat_intel.new_in_window} en ventana`}
                  />
                  <KpiCard
                    label="Reportes PCDI Alto Score"
                    value={crossDomain.pcdi.high_score_reports}
                    icon={Brain}
                    accent={crossDomain.pcdi.high_score_reports > 0 ? 'red' : 'green'}
                    sub={crossDomain.pcdi.avg_adaptive_score != null ? `avg ${crossDomain.pcdi.avg_adaptive_score}` : undefined}
                  />
                </div>

                {/* Three-column detail grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  {/* Hunting domain */}
                  <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
                    <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                      <Search size={12} className="text-cyan-400" /> Threat Hunting
                    </h3>
                    <StatPill label="Hunts activos" value={crossDomain.hunting.active_hunts} cls="text-cyan-400" />
                    <StatPill label="Prioridad crítica" value={crossDomain.hunting.critical_priority_hunts} cls={crossDomain.hunting.critical_priority_hunts > 0 ? 'text-red-400' : 'text-green-400'} />
                    <StatPill label="Completados en ventana" value={crossDomain.hunting.completed_in_window} />
                    <StatPill label="Verdaderos positivos" value={crossDomain.hunting.true_positives_in_window} cls="text-green-400" />
                    <StatPill label="Hallazgos alto/crítico" value={crossDomain.hunting.high_severity_findings} cls={crossDomain.hunting.high_severity_findings > 0 ? 'text-orange-400' : 'text-green-400'} />
                  </div>

                  {/* TI + PANL domain */}
                  <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
                    <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                      <Globe size={12} className="text-blue-400" /> TI + PANL
                    </h3>
                    <p className="text-xs text-gray-500 mb-1.5 font-medium">Threat Intelligence</p>
                    {Object.entries(crossDomain.threat_intel.by_severity).map(([k, v]) => (
                      <StatPill key={k} label={k} value={v}
                        cls={k === 'critical' ? 'text-red-400' : k === 'high' ? 'text-orange-400' : k === 'medium' ? 'text-yellow-400' : 'text-gray-300'} />
                    ))}
                    <div className="my-2 border-t border-navy-700" />
                    <p className="text-xs text-gray-500 mb-1.5 font-medium">Neutralizaciones</p>
                    <StatPill label="Total acciones" value={crossDomain.panl.actions_in_window} />
                    <StatPill label="Pendiente aprobación" value={crossDomain.panl.pending_approval} cls={crossDomain.panl.pending_approval > 0 ? 'text-yellow-400' : 'text-green-400'} />
                    {crossDomain.panl.approval_rate_pct != null && (
                      <StatPill label="Tasa aprobación %" value={Math.round(crossDomain.panl.approval_rate_pct)} cls="text-green-400" />
                    )}
                  </div>

                  {/* PCDI domain */}
                  <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
                    <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                      <Brain size={12} className="text-purple-400" /> PCDI
                    </h3>
                    <StatPill label="Reportes firmados" value={crossDomain.pcdi.total_signed_reports} />
                    <StatPill label="Score alto (≥80)" value={crossDomain.pcdi.high_score_reports} cls={crossDomain.pcdi.high_score_reports > 0 ? 'text-red-400' : 'text-green-400'} />
                    <StatPill label="Hunts críticos activos" value={crossDomain.pcdi.active_critical_hunts} cls={crossDomain.pcdi.active_critical_hunts > 0 ? 'text-red-400' : 'text-green-400'} />
                    {crossDomain.pcdi.avg_adaptive_score != null && (
                      <div className="mt-2 flex items-center justify-between py-1">
                        <span className="text-xs text-gray-400">Score promedio</span>
                        <span className={`text-sm font-bold ${crossDomain.pcdi.avg_adaptive_score >= 80 ? 'text-red-400' : crossDomain.pcdi.avg_adaptive_score >= 60 ? 'text-orange-400' : 'text-yellow-400'}`}>
                          {crossDomain.pcdi.avg_adaptive_score}
                        </span>
                      </div>
                    )}
                    {crossDomain.pcdi.top_reports.length > 0 && (
                      <div className="mt-3">
                        <p className="text-xs text-gray-500 mb-1.5 font-medium">Top reportes</p>
                        {crossDomain.pcdi.top_reports.map(r => (
                          <div key={r.report_id} className="flex items-center justify-between py-0.5">
                            <span className="text-xs text-gray-400 truncate max-w-[120px]">{r.hunt_name || r.hunt_id.slice(0, 8)}</span>
                            <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${r.adaptive_score >= 80 ? 'bg-red-900/40 text-red-400' : 'bg-orange-900/40 text-orange-400'}`}>
                              {r.adaptive_score}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Fleet summary row */}
                <div className="bg-navy-800/50 border border-navy-700/60 rounded-lg p-3 flex flex-wrap gap-4 text-xs text-gray-400">
                  <span className="flex items-center gap-1.5"><MonitorDot size={12} className="text-cyan-400" />
                    Agentes: <strong className="text-white ml-0.5">{crossDomain.fleet.active_agents}/{crossDomain.fleet.total_agents}</strong> activos
                  </span>
                  <span className="flex items-center gap-1.5"><Wifi size={12} className="text-green-400" />
                    En línea 5m: <strong className="text-white ml-0.5">{crossDomain.fleet.online_5m}</strong>
                  </span>
                  <span className="flex items-center gap-1.5">
                    <AlertTriangle size={12} className={crossDomain.fleet.at_risk_agents > 0 ? 'text-red-400' : 'text-gray-500'} />
                    En riesgo: <strong className={`ml-0.5 ${crossDomain.fleet.at_risk_agents > 0 ? 'text-red-400' : 'text-gray-400'}`}>{crossDomain.fleet.at_risk_agents}</strong>
                  </span>
                  {crossDomain.fleet.command_success_rate_pct != null && (
                    <span className="flex items-center gap-1.5"><CheckCircle2 size={12} className="text-green-400" />
                      Cmds éxito: <strong className="text-green-400 ml-0.5">{crossDomain.fleet.command_success_rate_pct}%</strong>
                    </span>
                  )}
                  <span className="ml-auto text-gray-600 italic">
                    Panel unificado PCDI · generado {formatTs(crossDomain.ts)}
                  </span>
                </div>
              </section>
            )}
          </>
        )}
      </main>
    </div>
  )
}
