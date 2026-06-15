'use client'
import { useEffect, useState, useCallback, useRef } from 'react'
import { useAuthGuard } from '@/lib/auth-guard'
import { getRole } from '@/lib/auth'
import {
  listApiKeys,
  getApiKeyRateLimitStatus,
  resetApiKeyRateLimit,
  APIKeyResponse,
  RateLimitStatus,
} from '@/lib/api'
import { RefreshCw, Activity, AlertTriangle, CheckCircle, Server, RotateCcw } from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface KeyWithStatus {
  key: APIKeyResponse
  status: RateLimitStatus | null
  loading: boolean
  error: string | null
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function usagePct(count: number, limit: number): number {
  if (limit === 0) return 0
  return Math.min(100, Math.round((count / limit) * 100))
}

function barColor(pct: number): string {
  if (pct >= 90) return 'bg-red-500'
  if (pct >= 70) return 'bg-yellow-400'
  return 'bg-cyan-400'
}

function statusLabel(pct: number): 'healthy' | 'warning' | 'critical' {
  if (pct >= 90) return 'critical'
  if (pct >= 70) return 'warning'
  return 'healthy'
}

function fmt(n: number): string {
  return n.toLocaleString()
}

// ── Sub-components ────────────────────────────────────────────────────────────

function BackendBadge({ mode }: { mode: string }) {
  const isRedis = mode === 'redis'
  return (
    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-mono ${
      isRedis ? 'bg-green-400/10 text-green-400 border border-green-400/30' : 'bg-yellow-400/10 text-yellow-400 border border-yellow-400/30'
    }`}>
      <Server size={10} />
      {mode}
    </span>
  )
}

function UsageBar({ count, limit, window: win }: { count: number; limit: number; window: string }) {
  const pct = usagePct(count, limit)
  const color = barColor(pct)
  return (
    <div className="space-y-0.5">
      <div className="flex justify-between text-xs text-gray-400">
        <span>{win}</span>
        <span className={pct >= 90 ? 'text-red-400' : pct >= 70 ? 'text-yellow-400' : 'text-gray-300'}>
          {fmt(count)}/{fmt(limit)}
        </span>
      </div>
      <div className="h-1.5 bg-navy-700 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}

function StatusBadge({ pct }: { pct: number }) {
  const label = statusLabel(pct)
  const styles = {
    healthy: 'bg-green-400/10 text-green-400',
    warning: 'bg-yellow-400/10 text-yellow-400',
    critical: 'bg-red-400/10 text-red-400',
  }
  const icons = {
    healthy: <CheckCircle size={10} />,
    warning: <AlertTriangle size={10} />,
    critical: <AlertTriangle size={10} />,
  }
  return (
    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full ${styles[label]}`}>
      {icons[label]}
      {label}
    </span>
  )
}

function ScopeBadge({ scope }: { scope: string }) {
  const s = {
    read: 'bg-blue-400/10 text-blue-400',
    write: 'bg-yellow-400/10 text-yellow-400',
    admin: 'bg-purple-400/10 text-purple-400',
  }[scope] ?? 'bg-gray-400/10 text-gray-400'
  return <span className={`text-xs px-1.5 py-0.5 rounded font-mono ${s}`}>{scope}</span>
}

// ── KPI strip ─────────────────────────────────────────────────────────────────

function KpiStrip({
  entries,
}: {
  entries: KeyWithStatus[]
}) {
  const loaded = entries.filter(e => e.status !== null)
  const pcts = loaded.map(e => usagePct(e.status!.count_minute, e.status!.limit_per_minute))
  const critical = pcts.filter(p => p >= 90).length
  const warning = pcts.filter(p => p >= 70 && p < 90).length
  const healthy = pcts.filter(p => p < 70).length

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      {[
        { label: 'Keys monitored', value: entries.length, color: 'text-white' },
        { label: 'Healthy', value: healthy, color: 'text-green-400' },
        { label: 'Near limit', value: warning, color: 'text-yellow-400' },
        { label: 'Critical', value: critical, color: 'text-red-400' },
      ].map(({ label, value, color }) => (
        <div key={label} className="bg-navy-800 border border-navy-700 rounded-lg px-4 py-3">
          <p className="text-xs text-gray-400 mb-1">{label}</p>
          <p className={`text-2xl font-bold ${color}`}>{value}</p>
        </div>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function RateLimitsPage() {
  useAuthGuard()

  const [entries, setEntries] = useState<KeyWithStatus[]>([])
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [globalBackend, setGlobalBackend] = useState<string>('—')
  const [resetConfirm, setResetConfirm] = useState<string | null>(null)
  const [role, setRole] = useState<string | null>(null)
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const showToast = (msg: string, ok = true) => {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 3500)
  }

  const loadStatuses = useCallback(async () => {
    setRefreshing(true)
    try {
      const keys = await listApiKeys()
      const base: KeyWithStatus[] = keys.map(k => ({
        key: k,
        status: null,
        loading: true,
        error: null,
      }))
      setEntries(base)

      const updated = await Promise.all(
        keys.map(async k => {
          try {
            const status = await getApiKeyRateLimitStatus(k.id)
            if (status.backend) setGlobalBackend(status.backend)
            return { key: k, status, loading: false, error: null }
          } catch {
            return { key: k, status: null, loading: false, error: 'Error al cargar' }
          }
        })
      )
      setEntries(updated)
      setLastRefresh(new Date())
    } finally {
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    setRole(getRole())
    loadStatuses()
    intervalRef.current = setInterval(loadStatuses, 30_000)
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [loadStatuses])

  const handleReset = async (keyId: string, keyName: string) => {
    try {
      await resetApiKeyRateLimit(keyId)
      showToast(`Contadores de "${keyName}" reiniciados`)
      await loadStatuses()
    } catch {
      showToast('Error al reiniciar contadores', false)
    }
    setResetConfirm(null)
  }

  return (
    <div className="p-6 min-h-screen bg-navy-900 text-white">
      {/* Toast */}
      {toast && (
        <div className={`fixed top-4 right-4 z-50 px-4 py-2 rounded-lg text-sm font-medium shadow-lg ${
          toast.ok ? 'bg-green-500/20 border border-green-500/40 text-green-300' : 'bg-red-500/20 border border-red-500/40 text-red-300'
        }`}>
          {toast.msg}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Activity size={24} className="text-cyan-400" />
            Rate Limit Monitor
          </h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Uso de ventanas de rate limiting por API Key — auto-refresh 30s
          </p>
        </div>
        <div className="flex items-center gap-3">
          <BackendBadge mode={globalBackend} />
          {lastRefresh && (
            <span className="text-xs text-gray-500">
              Actualizado: {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={loadStatuses}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-navy-700 hover:bg-navy-600 text-sm text-gray-300 transition-colors disabled:opacity-50"
          >
            <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* KPI strip */}
      <KpiStrip entries={entries} />

      {/* Table */}
      {entries.length === 0 && !refreshing ? (
        <div className="text-center py-16 text-gray-500">
          <Activity size={40} className="mx-auto mb-3 opacity-30" />
          <p>No hay API Keys registradas.</p>
          <p className="text-xs mt-1">Crea una desde la sección API Keys.</p>
        </div>
      ) : (
        <div className="bg-navy-800 border border-navy-700 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-navy-700 text-xs text-gray-400 uppercase tracking-wide">
                <th className="text-left px-4 py-3">Nombre / Prefix</th>
                <th className="text-left px-4 py-3">Scope</th>
                <th className="text-left px-4 py-3 w-56">Ventana /min</th>
                <th className="text-left px-4 py-3 w-56">Ventana /hora</th>
                <th className="text-left px-4 py-3">Estado</th>
                {role === 'admin' && <th className="text-left px-4 py-3">Acciones</th>}
              </tr>
            </thead>
            <tbody>
              {entries.map(({ key, status, loading, error }) => {
                const pctM = status ? usagePct(status.count_minute, status.limit_per_minute) : 0
                const pctH = status ? usagePct(status.count_hour, status.limit_per_hour) : 0
                const worstPct = Math.max(pctM, pctH)
                return (
                  <tr key={key.id} className="border-b border-navy-700/50 hover:bg-navy-700/30 transition-colors">
                    <td className="px-4 py-3">
                      <p className="font-medium text-white">{key.name}</p>
                      <p className="text-xs text-gray-500 font-mono">asc_{key.key_prefix}…</p>
                    </td>
                    <td className="px-4 py-3">
                      <ScopeBadge scope={key.scopes[0] ?? 'read'} />
                    </td>
                    <td className="px-4 py-3">
                      {loading && <div className="h-4 bg-navy-700 rounded animate-pulse w-full" />}
                      {error && <span className="text-xs text-red-400">{error}</span>}
                      {status && (
                        <UsageBar
                          count={status.count_minute}
                          limit={status.limit_per_minute}
                          window="minuto"
                        />
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {loading && <div className="h-4 bg-navy-700 rounded animate-pulse w-full" />}
                      {error && <span className="text-xs text-red-400">{error}</span>}
                      {status && (
                        <UsageBar
                          count={status.count_hour}
                          limit={status.limit_per_hour}
                          window="hora"
                        />
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {status && <StatusBadge pct={worstPct} />}
                      {loading && <span className="text-xs text-gray-500">cargando…</span>}
                    </td>
                    {role === 'admin' && (
                      <td className="px-4 py-3">
                        <button
                          onClick={() => setResetConfirm(key.id)}
                          className="flex items-center gap-1 text-xs px-2 py-1 rounded bg-orange-500/10 text-orange-400 hover:bg-orange-500/20 border border-orange-500/20 transition-colors"
                        >
                          <RotateCcw size={11} />
                          Reset
                        </button>
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Info note */}
      <div className="mt-6 p-3 rounded-lg bg-navy-800 border border-navy-700 text-xs text-gray-400">
        <span className="text-cyan-400 font-semibold">Toque Premos: </span>
        Los contadores usan ventana deslizante (sliding window). Los valores se actualizan cada 30s.
        Backend <span className="font-mono text-cyan-400">{globalBackend}</span>
        {globalBackend === 'memory' && ' — modo single-worker, sin persistencia entre reinicios.'}
        {globalBackend === 'redis' && ' — modo multi-worker, contadores compartidos entre workers.'}
      </div>

      {/* Reset confirm modal */}
      {resetConfirm && (() => {
        const target = entries.find(e => e.key.id === resetConfirm)
        if (!target) return null
        return (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
            <div className="bg-navy-800 border border-navy-700 rounded-xl p-6 w-full max-w-sm shadow-2xl">
              <h3 className="text-lg font-semibold text-white mb-2">Confirmar reset</h3>
              <p className="text-sm text-gray-400 mb-4">
                ¿Reiniciar contadores de rate limit para{' '}
                <span className="text-white font-medium">{target.key.name}</span>?
                Los contadores de minuto y hora serán limpiados inmediatamente.
              </p>
              <div className="flex gap-3 justify-end">
                <button
                  onClick={() => setResetConfirm(null)}
                  className="px-4 py-2 rounded bg-navy-700 text-gray-300 text-sm hover:bg-navy-600 transition-colors"
                >
                  Cancelar
                </button>
                <button
                  onClick={() => handleReset(target.key.id, target.key.name)}
                  className="px-4 py-2 rounded bg-orange-500 text-white text-sm font-medium hover:bg-orange-600 transition-colors"
                >
                  Reiniciar
                </button>
              </div>
            </div>
          </div>
        )
      })()}
    </div>
  )
}
