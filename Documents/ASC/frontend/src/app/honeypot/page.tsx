'use client'

import { useEffect, useState, useCallback } from 'react'
import { Flame, RefreshCw, ShieldCheck, ShieldX, ChevronDown, ChevronUp, X, ExternalLink } from 'lucide-react'
import {
  listHoneypotTokens,
  getHoneypotToken,
  listEvidenceReports,
  getEvidenceReport,
  CanaryToken,
  CanaryAccess,
  EvidenceReportSummary,
  EvidenceReportFull,
} from '@/lib/api'
import { useAuthGuard } from '@/lib/auth-guard'

// ── Pure helpers (exported for unit tests) ────────────────────────────────────

export function formatTs(ts: string | null | undefined): string {
  if (!ts) return '—'
  try {
    return new Date(ts).toLocaleString()
  } catch {
    return ts
  }
}

export function truncateId(id: string, len = 12): string {
  return id.length > len ? `${id.slice(0, len)}…` : id
}

export function severityClasses(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical': return 'bg-red-600/20 text-red-400 border border-red-700'
    case 'high':     return 'bg-orange-600/20 text-orange-400 border border-orange-700'
    case 'medium':   return 'bg-yellow-600/20 text-yellow-400 border border-yellow-700'
    case 'low':      return 'bg-green-600/20 text-green-400 border border-green-700'
    default:         return 'bg-gray-700 text-gray-300 border border-gray-600'
  }
}

export function accessCountClasses(count: number): string {
  if (count === 0) return 'text-gray-500'
  if (count >= 5)  return 'text-red-400 font-semibold'
  if (count >= 2)  return 'text-orange-400 font-semibold'
  return 'text-yellow-400'
}

export function endpointLabel(endpoint: string): string {
  if (endpoint.includes('probe'))  return 'PROBE'
  if (endpoint.includes('dump'))   return 'DUMP'
  if (endpoint.includes('export')) return 'EXPORT'
  return endpoint.toUpperCase()
}

export function endpointClasses(endpoint: string): string {
  if (endpoint.includes('probe'))  return 'bg-blue-900/30 text-blue-300 border border-blue-800'
  if (endpoint.includes('dump'))   return 'bg-purple-900/30 text-purple-300 border border-purple-800'
  if (endpoint.includes('export')) return 'bg-red-900/30 text-red-300 border border-red-800'
  return 'bg-gray-800 text-gray-400 border border-gray-700'
}

export function totalAccesses(tokens: CanaryToken[]): number {
  return tokens.reduce((sum, t) => sum + t.access_count, 0)
}

export function uniqueIps(tokens: CanaryToken[]): number {
  const ips = new Set<string>()
  for (const t of tokens) {
    for (const a of t.accesses) {
      if (a.client_ip) ips.add(a.client_ip)
    }
  }
  return ips.size
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function MetricCard({ label, value, sub, accent = false }: {
  label: string
  value: string | number
  sub?: string
  accent?: boolean
}) {
  return (
    <div className={`rounded-lg border p-4 ${accent ? 'border-cyan-700 bg-cyan-900/10' : 'border-gray-700 bg-gray-800'}`}>
      <p className="text-xs text-gray-400 mb-1">{label}</p>
      <p className={`text-2xl font-bold ${accent ? 'text-cyan-400' : 'text-white'}`}>{value}</p>
      {sub && <p className="text-xs text-gray-500 mt-0.5">{sub}</p>}
    </div>
  )
}

function AccessRow({ access }: { access: CanaryAccess }) {
  return (
    <div className="text-xs border-b border-gray-700 last:border-0 py-2 space-y-0.5">
      <div className="flex items-center gap-2">
        <span className="text-orange-400 font-mono font-semibold">{access.client_ip}</span>
        <span className="text-gray-500">{formatTs(access.ts)}</span>
      </div>
      <p className="text-gray-400 truncate" title={access.user_agent}>{access.user_agent || '—'}</p>
      {access.referer && (
        <p className="text-gray-600 truncate">ref: {access.referer}</p>
      )}
    </div>
  )
}

function TokenRow({
  token,
  selected,
  onClick,
}: {
  token: CanaryToken
  selected: boolean
  onClick: () => void
}) {
  const hasAccesses = token.access_count > 0
  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-lg border p-3 transition ${
        selected
          ? 'border-cyan-600 bg-cyan-900/15'
          : hasAccesses
            ? 'border-orange-800 bg-orange-900/10 hover:border-orange-600'
            : 'border-gray-700 bg-gray-800 hover:border-gray-500'
      }`}
    >
      <div className="flex items-center justify-between mb-1.5">
        <span className="font-mono text-xs text-gray-300">{truncateId(token.token_id, 16)}</span>
        <div className="flex items-center gap-2">
          <span className={`text-xs px-1.5 py-0.5 rounded ${endpointClasses(token.endpoint)}`}>
            {endpointLabel(token.endpoint)}
          </span>
          {selected ? <ChevronUp size={12} className="text-gray-400" /> : <ChevronDown size={12} className="text-gray-400" />}
        </div>
      </div>
      <div className="flex items-center gap-3 text-xs text-gray-400">
        <span>
          Accesos:{' '}
          <span className={accessCountClasses(token.access_count)}>{token.access_count}</span>
        </span>
        <span className="text-gray-600">·</span>
        <span className="truncate">{token.label}</span>
      </div>
      {token.last_access && (
        <p className="text-xs text-gray-600 mt-1">Último: {formatTs(token.last_access)}</p>
      )}
    </button>
  )
}

function ReportRow({
  report,
  selected,
  onClick,
}: {
  report: EvidenceReportSummary
  selected: boolean
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-lg border p-3 transition ${
        selected
          ? 'border-cyan-600 bg-cyan-900/15'
          : 'border-gray-700 bg-gray-800 hover:border-gray-500'
      }`}
    >
      <div className="flex items-center justify-between mb-1.5">
        <span className="font-mono text-xs text-gray-300">{truncateId(report.report_id)}</span>
        <span className={`text-xs px-1.5 py-0.5 rounded ${severityClasses(report.severity)}`}>
          {report.severity}
        </span>
      </div>
      <div className="flex items-center gap-2 text-xs">
        <span className="text-orange-400 font-mono">{report.attacker_ip}</span>
        <span className="text-gray-600">·</span>
        <span className="text-gray-400">{report.event_type.replace(/_/g, ' ')}</span>
      </div>
      <div className="flex items-center justify-between mt-1 text-xs text-gray-600">
        <span>{formatTs(report.generated_at)}</span>
        {report.canary_accesses > 0 && (
          <span className="text-orange-400">{report.canary_accesses} acceso{report.canary_accesses !== 1 ? 's' : ''}</span>
        )}
      </div>
    </button>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function HoneypotPage() {
  useAuthGuard()

  const [tokens, setTokens]               = useState<CanaryToken[]>([])
  const [reports, setReports]             = useState<EvidenceReportSummary[]>([])
  const [selectedToken, setSelectedToken] = useState<CanaryToken | null>(null)
  const [selectedReport, setSelectedReport] = useState<EvidenceReportFull | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [loading, setLoading]             = useState(true)
  const [error, setError]                 = useState<string | null>(null)
  const [autoRefresh, setAutoRefresh]     = useState(true)
  const [lastRefresh, setLastRefresh]     = useState<Date | null>(null)

  const load = useCallback(async () => {
    try {
      const [tokensResp, reportsResp] = await Promise.all([
        listHoneypotTokens(),
        listEvidenceReports(),
      ])
      setTokens(tokensResp.tokens)
      setReports(reportsResp.reports)
      setLastRefresh(new Date())
      setError(null)
    } catch {
      setError('Error cargando datos del honeypot. Verifica que tienes rol admin.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    if (!autoRefresh) return
    const interval = setInterval(load, 30_000)
    return () => clearInterval(interval)
  }, [load, autoRefresh])

  const handleSelectToken = useCallback(async (token: CanaryToken) => {
    if (selectedToken?.token_id === token.token_id) {
      setSelectedToken(null)
      return
    }
    setDetailLoading(true)
    setSelectedReport(null)
    try {
      const full = await getHoneypotToken(token.token_id)
      setSelectedToken(full)
    } catch {
      setSelectedToken(token)
    } finally {
      setDetailLoading(false)
    }
  }, [selectedToken])

  const handleSelectReport = useCallback(async (report: EvidenceReportSummary) => {
    if (selectedReport?.report_id === report.report_id) {
      setSelectedReport(null)
      return
    }
    setDetailLoading(true)
    setSelectedToken(null)
    try {
      const full = await getEvidenceReport(report.report_id)
      setSelectedReport(full)
    } catch {
      setSelectedReport(null)
    } finally {
      setDetailLoading(false)
    }
  }, [selectedReport])

  // Derived metrics
  const totalAccessCount = totalAccesses(tokens)
  const uniqueIpCount    = uniqueIps(tokens)
  const activeTokens     = tokens.filter(t => t.access_count > 0).length
  const criticalReports  = reports.filter(r => r.severity === 'high' || r.severity === 'critical').length

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-64">
        <span className="text-gray-400 text-sm">Cargando SPECTER Honeypot…</span>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6">

      {/* ── Header ── */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-orange-900/40 border border-orange-700 flex items-center justify-center">
            <Flame size={18} className="text-orange-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight">SPECTER Honeypot</h1>
            <p className="text-gray-400 text-xs mt-0.5">
              Inteligencia de amenazas pasiva · Canary tokens · Evidencia firmada
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {lastRefresh && (
            <span className="text-xs text-gray-600">
              {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={() => setAutoRefresh(v => !v)}
            className={`text-xs px-2 py-1 rounded border transition ${
              autoRefresh
                ? 'border-cyan-700 text-cyan-400 bg-cyan-900/20'
                : 'border-gray-600 text-gray-400'
            }`}
          >
            Auto {autoRefresh ? 'ON' : 'OFF'}
          </button>
          <button
            onClick={load}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-gray-700 hover:bg-gray-600 text-gray-200 rounded border border-gray-600 transition"
          >
            <RefreshCw size={12} />
            Actualizar
          </button>
        </div>
      </div>

      {/* ── Error banner ── */}
      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-3 text-red-300 text-sm">
          {error}
        </div>
      )}

      {/* ── Metric cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Canary Tokens Activos"
          value={tokens.length}
          sub={`${activeTokens} con accesos`}
          accent
        />
        <MetricCard
          label="Total de Accesos"
          value={totalAccessCount}
          sub={totalAccessCount === 0 ? 'Sin actividad' : 'Triggers registrados'}
        />
        <MetricCard
          label="IPs Únicas de Atacantes"
          value={uniqueIpCount}
          sub={uniqueIpCount > 0 ? 'Identificadas' : 'Ninguna detectada'}
        />
        <MetricCard
          label="Reportes de Evidencia"
          value={reports.length}
          sub={criticalReports > 0 ? `${criticalReports} alta severidad` : 'Sin incidentes críticos'}
        />
      </div>

      {/* ── Main grid ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* ── Left: Canary Tokens ── */}
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-300">Canary Tokens</h2>
            <span className="text-xs text-gray-500">{tokens.length} tokens</span>
          </div>

          {tokens.length === 0 ? (
            <div className="border border-dashed border-gray-700 rounded-lg p-8 text-center">
              <Flame size={24} className="text-gray-600 mx-auto mb-2" />
              <p className="text-gray-500 text-sm">Sin canary tokens aún.</p>
              <p className="text-gray-600 text-xs mt-1">
                Actívanse cuando un atacante accede a /probe, /dump o /export.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {tokens.map(token => (
                <div key={token.token_id}>
                  <TokenRow
                    token={token}
                    selected={selectedToken?.token_id === token.token_id}
                    onClick={() => handleSelectToken(token)}
                  />

                  {/* Inline expand: access log */}
                  {selectedToken?.token_id === token.token_id && (
                    <div className="mt-1 ml-2 rounded-lg border border-cyan-800 bg-gray-900 p-3">
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-xs text-cyan-400 font-semibold">Registro de Accesos</p>
                        <button
                          onClick={() => setSelectedToken(null)}
                          className="text-gray-500 hover:text-gray-300"
                        >
                          <X size={12} />
                        </button>
                      </div>

                      {detailLoading ? (
                        <p className="text-xs text-gray-500">Cargando…</p>
                      ) : selectedToken.accesses.length === 0 ? (
                        <p className="text-xs text-gray-500">Sin accesos registrados.</p>
                      ) : (
                        <div className="max-h-52 overflow-y-auto space-y-0">
                          {selectedToken.accesses.map((a, i) => (
                            <AccessRow key={i} access={a} />
                          ))}
                        </div>
                      )}

                      {/* Token metadata */}
                      <div className="mt-3 pt-2 border-t border-gray-800 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                        <InfoRow label="Token ID" value={truncateId(selectedToken.token_id, 20)} mono />
                        <InfoRow label="Endpoint"  value={selectedToken.endpoint} />
                        <InfoRow label="Label"     value={selectedToken.label || '—'} />
                        <InfoRow label="Creado"    value={formatTs(selectedToken.created_at)} />
                        <InfoRow label="1er acceso" value={formatTs(selectedToken.first_access)} />
                        <InfoRow label="Últ. acceso" value={formatTs(selectedToken.last_access)} />
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>

        {/* ── Right: Evidence Reports ── */}
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-300">Reportes de Evidencia</h2>
            <span className="text-xs text-gray-500">{reports.length} reportes</span>
          </div>

          {reports.length === 0 ? (
            <div className="border border-dashed border-gray-700 rounded-lg p-8 text-center">
              <ShieldCheck size={24} className="text-gray-600 mx-auto mb-2" />
              <p className="text-gray-500 text-sm">Sin reportes generados.</p>
              <p className="text-gray-600 text-xs mt-1">
                Se generan automáticamente al disparar un canary token.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {reports.map(report => (
                <div key={report.report_id}>
                  <ReportRow
                    report={report}
                    selected={selectedReport?.report_id === report.report_id}
                    onClick={() => handleSelectReport(report)}
                  />

                  {/* Inline expand: full signed report */}
                  {selectedReport?.report_id === report.report_id && (
                    <div className="mt-1 ml-2 rounded-lg border border-cyan-800 bg-gray-900 p-3 space-y-3">
                      <div className="flex items-center justify-between">
                        <p className="text-xs text-cyan-400 font-semibold">Reporte Firmado</p>
                        <button
                          onClick={() => setSelectedReport(null)}
                          className="text-gray-500 hover:text-gray-300"
                        >
                          <X size={12} />
                        </button>
                      </div>

                      {detailLoading ? (
                        <p className="text-xs text-gray-500">Cargando…</p>
                      ) : (
                        <>
                          {/* Incident Summary */}
                          <div>
                            <p className="text-xs text-gray-400 font-semibold mb-1">Resumen del Incidente</p>
                            <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                              <InfoRow label="Severidad"   value={selectedReport.report.incident_summary.severity} />
                              <InfoRow label="IP Atacante" value={selectedReport.report.incident_summary.attacker_ip} mono />
                              <InfoRow label="Timestamp"   value={formatTs(selectedReport.report.incident_summary.attack_ts)} />
                              <InfoRow label="X-Fwd-For"  value={selectedReport.report.incident_summary.x_forwarded_for || '—'} mono />
                            </div>
                          </div>

                          {/* Fingerprint */}
                          <div>
                            <p className="text-xs text-gray-400 font-semibold mb-1">Fingerprint del Atacante</p>
                            <div className="grid grid-cols-1 gap-y-1 text-xs">
                              <InfoRow label="User-Agent" value={selectedReport.report.attacker_fingerprint.user_agent} />
                              <InfoRow label="Idioma"     value={selectedReport.report.attacker_fingerprint.accept_language || '—'} />
                              <InfoRow label="Hash"       value={truncateId(selectedReport.report.attacker_fingerprint.fingerprint_hash, 20)} mono />
                            </div>
                          </div>

                          {/* IP Reputation */}
                          {Object.keys(selectedReport.report.ip_reputation).length > 0 && (
                            <div>
                              <p className="text-xs text-gray-400 font-semibold mb-1">Reputación IP</p>
                              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                                {['country', 'city', 'isp', 'is_proxy', 'abuse_confidence_score'].map(k => {
                                  const v = selectedReport.report.ip_reputation[k]
                                  if (v === null || v === undefined) return null
                                  return <InfoRow key={k} label={k} value={String(v)} />
                                })}
                              </div>
                            </div>
                          )}

                          {/* Canary Evidence */}
                          {selectedReport.report.canary_evidence && (
                            <div>
                              <p className="text-xs text-gray-400 font-semibold mb-1">Evidencia Canary</p>
                              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                                <InfoRow label="Endpoint"  value={selectedReport.report.canary_evidence.endpoint || '—'} />
                                <InfoRow label="Accesos"   value={String(selectedReport.report.canary_evidence.access_count)} />
                                <InfoRow label="1er acc."  value={formatTs(selectedReport.report.canary_evidence.first_access)} />
                                <InfoRow label="Últ. acc." value={formatTs(selectedReport.report.canary_evidence.last_access)} />
                              </div>
                            </div>
                          )}

                          {/* Signature status */}
                          <div className="flex items-center gap-2 pt-1 border-t border-gray-800">
                            <ShieldCheck size={12} className="text-cyan-400 shrink-0" />
                            <p className="text-xs text-gray-400">Reporte HMAC-SHA256 firmado</p>
                            <code className="ml-auto text-xs font-mono text-gray-600 truncate max-w-[120px]">
                              {selectedReport.signature.slice(0, 12)}…
                            </code>
                          </div>

                          {/* Reporting guidelines */}
                          <div>
                            <p className="text-xs text-gray-500 mb-1">Canales de denuncia:</p>
                            <div className="flex flex-wrap gap-2">
                              {Object.entries(selectedReport.report.reporting_guidelines).map(([key, url]) => (
                                <a
                                  key={key}
                                  href={url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="flex items-center gap-1 text-xs text-cyan-500 hover:text-cyan-300 underline"
                                >
                                  {key} <ExternalLink size={10} />
                                </a>
                              ))}
                            </div>
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* ── Legend / Info bar ── */}
      <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-4">
        <div className="flex flex-wrap gap-6 text-xs text-gray-500">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-orange-400 shrink-0" />
            Token con accesos — atacante detectado
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-gray-600 shrink-0" />
            Token sin accesos — trampa activa
          </div>
          <div className="flex items-center gap-2">
            <ShieldCheck size={12} className="text-cyan-400" />
            Reportes firmados HMAC-SHA256 — admisibles ante autoridades
          </div>
          <div className="flex items-center gap-2">
            <ShieldX size={12} className="text-gray-500" />
            Todos los datos capturados de forma pasiva — sin código enviado al atacante
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Shared sub-component ──────────────────────────────────────────────────────

function InfoRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-1 min-w-0">
      <span className="text-gray-500 shrink-0 w-24">{label}</span>
      <span className={`truncate ${mono ? 'font-mono text-gray-300' : 'text-gray-300'}`}>{value}</span>
    </div>
  )
}
