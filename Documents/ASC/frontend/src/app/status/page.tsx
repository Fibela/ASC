'use client'
import { useState, useEffect, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'
import {
  getSystemLiveness, getSystemReadiness, getSystemInfo, getObservabilitySummary,
  HealthLiveness, HealthReadiness, HealthSystem, ObservabilitySummary,
} from '@/lib/api'
import {
  Activity, CheckCircle2, XCircle, RefreshCw, Server,
  Database, Clock, Cpu, AlertTriangle, Loader2, BarChart3, Bot,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

type FetchStatus = 'loading' | 'ok' | 'error'

interface StatusState<T> {
  status: FetchStatus
  data: T | null
  error: string | null
  lastUpdated: string | null
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function statusColor(status: FetchStatus): string {
  switch (status) {
    case 'ok':      return 'text-green-400'
    case 'error':   return 'text-red-400'
    default:        return 'text-yellow-400'
  }
}

function statusBorderColor(status: FetchStatus): string {
  switch (status) {
    case 'ok':      return 'border-green-400/30'
    case 'error':   return 'border-red-400/30'
    default:        return 'border-yellow-400/30'
  }
}

function statusDot(status: FetchStatus): string {
  switch (status) {
    case 'ok':      return 'bg-green-400'
    case 'error':   return 'bg-red-400'
    default:        return 'bg-yellow-400 animate-pulse'
  }
}

function checkStatusLabel(ready: HealthReadiness): string {
  return ready.status === 'ready' ? 'Listo' : 'Degradado'
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusCard({
  title,
  icon: Icon,
  status,
  children,
}: {
  title: string
  icon: React.ElementType<{ size?: number | string; className?: string }>
  status: FetchStatus
  children: React.ReactNode
}) {
  return (
    <div className={`card border rounded-lg p-5 transition-colors ${statusBorderColor(status)}`}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Icon size={16} className="text-cyan-400" />
          <h3 className="text-sm font-semibold text-white">{title}</h3>
        </div>
        <span className={`w-2.5 h-2.5 rounded-full ${statusDot(status)}`} />
      </div>
      {children}
    </div>
  )
}

function InfoRow({ label, value, mono = false }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-navy-700 last:border-0">
      <span className="text-xs text-gray-500">{label}</span>
      <span className={`text-xs text-gray-200 ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  )
}

function CheckRow({ label, check }: { label: string; check: { ok: boolean; detail: string } }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-navy-700 last:border-0">
      <span className="text-xs text-gray-500">{label}</span>
      <span className={`flex items-center gap-1 text-xs font-medium ${check.ok ? 'text-green-400' : 'text-red-400'}`}>
        {check.ok
          ? <CheckCircle2 size={11} />
          : <XCircle size={11} />
        }
        {check.ok ? 'OK' : check.detail}
      </span>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

const AUTO_REFRESH_MS = 30_000

export default function StatusPage() {
  const { isReady } = useAuthGuard()

  const [liveness,   setLiveness]   = useState<StatusState<HealthLiveness>>({ status: 'loading', data: null, error: null, lastUpdated: null })
  const [readiness,  setReadiness]  = useState<StatusState<HealthReadiness>>({ status: 'loading', data: null, error: null, lastUpdated: null })
  const [systemInfo, setSystemInfo] = useState<StatusState<HealthSystem>>({ status: 'loading', data: null, error: null, lastUpdated: null })
  const [obsSummary, setObsSummary] = useState<StatusState<ObservabilitySummary>>({ status: 'loading', data: null, error: null, lastUpdated: null })
  const [refreshing, setRefreshing] = useState(false)

  const fetchAll = useCallback(async () => {
    setRefreshing(true)

    // Liveness
    try {
      const data = await getSystemLiveness()
      setLiveness({ status: 'ok', data, error: null, lastUpdated: new Date().toISOString() })
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? (e as Error)?.message ?? 'Sin conexión'
      setLiveness({ status: 'error', data: null, error: msg, lastUpdated: new Date().toISOString() })
    }

    // Readiness
    try {
      const data = await getSystemReadiness()
      setReadiness({
        status: data.status === 'ready' ? 'ok' : 'error',
        data, error: null, lastUpdated: new Date().toISOString(),
      })
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? (e as Error)?.message ?? 'Sin conexión'
      setReadiness({ status: 'error', data: null, error: msg, lastUpdated: new Date().toISOString() })
    }

    // System info
    try {
      const data = await getSystemInfo()
      setSystemInfo({ status: 'ok', data, error: null, lastUpdated: new Date().toISOString() })
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? (e as Error)?.message ?? 'Sin conexión'
      setSystemInfo({ status: 'error', data: null, error: msg, lastUpdated: new Date().toISOString() })
    }

    // Observability summary (analyst+ only; graceful fallback if 403)
    try {
      const data = await getObservabilitySummary()
      setObsSummary({ status: 'ok', data, error: null, lastUpdated: new Date().toISOString() })
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? (e as Error)?.message ?? 'No disponible'
      setObsSummary({ status: 'error', data: null, error: msg, lastUpdated: new Date().toISOString() })
    }

    setRefreshing(false)
  }, [])

  useEffect(() => {
    if (!isReady) return
    fetchAll()
    const timer = setInterval(fetchAll, AUTO_REFRESH_MS)
    return () => clearInterval(timer)
  }, [fetchAll, isReady])

  // Overall posture
  const allOk = liveness.status === 'ok' && readiness.status === 'ok' && systemInfo.status === 'ok'
  const anyError = liveness.status === 'error' || readiness.status === 'error' || systemInfo.status === 'error'
  const overallStatus: FetchStatus = allOk ? 'ok' : anyError ? 'error' : 'loading'

  if (!isReady) return <AuthLoader />

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6 space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Estado del Sistema</h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Liveness, readiness y métricas de runtime — auto-refresh cada 30s
            </p>
          </div>
          <button
            onClick={fetchAll}
            disabled={refreshing}
            className="btn-primary flex items-center gap-2 text-sm py-1.5"
          >
            <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
            Refrescar
          </button>
        </div>

        {/* Overall banner */}
        <div className={`flex items-center gap-3 px-4 py-3 rounded-lg border ${
          overallStatus === 'ok'
            ? 'bg-green-400/5 border-green-400/20'
            : overallStatus === 'error'
              ? 'bg-red-400/5 border-red-400/20'
              : 'bg-yellow-400/5 border-yellow-400/20'
        }`}>
          {overallStatus === 'loading'
            ? <Loader2 size={16} className="text-yellow-400 animate-spin" />
            : overallStatus === 'ok'
              ? <CheckCircle2 size={16} className="text-green-400" />
              : <AlertTriangle size={16} className="text-red-400" />
          }
          <span className={`text-sm font-semibold ${statusColor(overallStatus)}`}>
            {overallStatus === 'ok'
              ? 'Todos los sistemas operativos'
              : overallStatus === 'error'
                ? 'Uno o más sistemas con problemas'
                : 'Verificando estado del sistema…'
            }
          </span>
        </div>

        {/* Cards grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

          {/* Liveness */}
          <StatusCard title="Liveness" icon={Activity} status={liveness.status}>
            {liveness.status === 'loading' && (
              <div className="flex items-center gap-2 text-yellow-400 text-xs">
                <Loader2 size={12} className="animate-spin" /> Verificando…
              </div>
            )}
            {liveness.status === 'ok' && liveness.data && (
              <div className="space-y-0">
                <InfoRow label="Estado" value="Proceso activo" />
                <InfoRow label="Última respuesta" value={new Date(liveness.data.ts).toLocaleTimeString('es', { hour12: false })} mono />
              </div>
            )}
            {liveness.status === 'error' && (
              <div className="flex items-center gap-2 text-red-400 text-xs">
                <XCircle size={12} /> {liveness.error}
              </div>
            )}
          </StatusCard>

          {/* Readiness */}
          <StatusCard title="Readiness" icon={Database} status={readiness.status}>
            {readiness.status === 'loading' && (
              <div className="flex items-center gap-2 text-yellow-400 text-xs">
                <Loader2 size={12} className="animate-spin" /> Verificando…
              </div>
            )}
            {readiness.data && (
              <div className="space-y-0">
                <InfoRow label="Estado" value={checkStatusLabel(readiness.data)} />
                {Object.entries(readiness.data.checks).map(([key, check]) => (
                  <CheckRow key={key} label={key} check={check} />
                ))}
              </div>
            )}
            {readiness.status === 'error' && !readiness.data && (
              <div className="flex items-center gap-2 text-red-400 text-xs">
                <XCircle size={12} /> {readiness.error}
              </div>
            )}
          </StatusCard>

          {/* System Info */}
          <StatusCard title="Información de Sistema" icon={Server} status={systemInfo.status}>
            {systemInfo.status === 'loading' && (
              <div className="flex items-center gap-2 text-yellow-400 text-xs">
                <Loader2 size={12} className="animate-spin" /> Verificando…
              </div>
            )}
            {systemInfo.status === 'ok' && systemInfo.data && (
              <div className="space-y-0">
                <InfoRow label="Aplicación"   value={systemInfo.data.app} />
                <InfoRow label="Versión"      value={systemInfo.data.version} mono />
                <InfoRow label="Entorno"      value={systemInfo.data.environment} />
                <InfoRow label="Uptime"       value={systemInfo.data.uptime_human} mono />
              </div>
            )}
            {systemInfo.status === 'error' && (
              <div className="flex items-center gap-2 text-red-400 text-xs">
                <XCircle size={12} /> {systemInfo.error}
              </div>
            )}
          </StatusCard>

        </div>

        {/* ── Observability Panel (P39) ───────────────────────────────── */}
        {obsSummary.status !== 'error' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">

            {/* Process CPU */}
            <StatusCard title="CPU del Proceso" icon={Cpu} status={obsSummary.status}>
              {obsSummary.status === 'loading' && (
                <div className="flex items-center gap-2 text-yellow-400 text-xs"><Loader2 size={12} className="animate-spin" /> Cargando…</div>
              )}
              {obsSummary.data && (
                <div className="space-y-0">
                  <InfoRow label="CPU %" value={`${obsSummary.data.process.cpu_percent}%`} mono />
                  <InfoRow label="Mem RSS" value={`${obsSummary.data.process.memory_rss_mb} MB`} mono />
                  <InfoRow label="Mem VMS" value={`${obsSummary.data.process.memory_vms_mb} MB`} mono />
                  <InfoRow label="PID" value={obsSummary.data.process.pid} mono />
                </div>
              )}
            </StatusCard>

            {/* Database counts */}
            <StatusCard title="Base de Datos" icon={Database} status={obsSummary.status}>
              {obsSummary.status === 'loading' && (
                <div className="flex items-center gap-2 text-yellow-400 text-xs"><Loader2 size={12} className="animate-spin" /> Cargando…</div>
              )}
              {obsSummary.data && (
                <div className="space-y-0">
                  <InfoRow label="Estado DB" value={obsSummary.data.database.ok ? 'Conectada' : 'Error'} />
                  <InfoRow label="Alertas total" value={obsSummary.data.database.alerts_total.toLocaleString()} mono />
                  <InfoRow label="Eventos total" value={obsSummary.data.database.events_total.toLocaleString()} mono />
                </div>
              )}
            </StatusCard>

            {/* Active agents */}
            <StatusCard title="Agentes SPECTER" icon={Bot} status={obsSummary.status}>
              {obsSummary.status === 'loading' && (
                <div className="flex items-center gap-2 text-yellow-400 text-xs"><Loader2 size={12} className="animate-spin" /> Cargando…</div>
              )}
              {obsSummary.data && (
                <div className="space-y-0">
                  <InfoRow label="Activos (5 min)" value={obsSummary.data.agents.active_last_5min} mono />
                  <div className="mt-3">
                    <div className={`inline-flex items-center gap-1 text-xs px-2 py-1 rounded-full ${
                      obsSummary.data.agents.active_last_5min > 0
                        ? 'bg-green-400/10 text-green-400'
                        : 'bg-gray-700 text-gray-500'
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${obsSummary.data.agents.active_last_5min > 0 ? 'bg-green-400' : 'bg-gray-500'}`} />
                      {obsSummary.data.agents.active_last_5min > 0 ? 'Fleet activa' : 'Sin agentes activos'}
                    </div>
                  </div>
                </div>
              )}
            </StatusCard>

            {/* Prometheus scrape */}
            <StatusCard title="Prometheus" icon={BarChart3} status={obsSummary.status}>
              {obsSummary.status === 'loading' && (
                <div className="flex items-center gap-2 text-yellow-400 text-xs"><Loader2 size={12} className="animate-spin" /> Cargando…</div>
              )}
              {obsSummary.data && (
                <div className="space-y-0">
                  <InfoRow label="Endpoint" value={obsSummary.data.prometheus.metrics_endpoint} />
                  <InfoRow
                    label="Scrape token"
                    value={obsSummary.data.prometheus.scrape_token_configured ? 'Configurado' : 'No configurado'}
                  />
                  <div className="mt-3">
                    <a
                      href={obsSummary.data.prometheus.metrics_endpoint}
                      className="text-xs text-cyan-400 hover:underline"
                      target="_blank" rel="noopener noreferrer"
                    >
                      Ver métricas →
                    </a>
                  </div>
                </div>
              )}
            </StatusCard>

          </div>
        )}

        {/* Last updated footer */}
        {(liveness.lastUpdated || readiness.lastUpdated || systemInfo.lastUpdated) && (
          <div className="flex items-center gap-2 text-gray-600 text-xs">
            <Clock size={11} />
            Última actualización: {new Date(
              liveness.lastUpdated ?? readiness.lastUpdated ?? systemInfo.lastUpdated!
            ).toLocaleTimeString('es', { hour12: false })}
            &nbsp;· Auto-refresh cada 30 segundos
          </div>
        )}

      </main>
    </div>
  )
}
