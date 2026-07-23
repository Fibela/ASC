'use client'

import { useEffect, useState, useCallback } from 'react'
import {
  ScrollText, Shield, CheckCircle, XCircle, Clock,
  RefreshCw, AlertTriangle, BarChart3, Lock, Eye,
} from 'lucide-react'
import clsx from 'clsx'
import {
  getReportingSummary, listExecutiveReports, generateExecutiveReport,
  verifyExecutiveReport, deleteExecutiveReport,
  ExecutiveReport, ReportingSummary, VerifyReportResult,
} from '@/lib/api'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtMins(m: number | null) {
  if (m === null || m === undefined) return '—'
  if (m < 60) return `${m}m`
  return `${Math.floor(m / 60)}h ${m % 60}m`
}

function truncHash(h: string, n = 20) {
  return h ? h.slice(0, n) + '…' : '—'
}

const REPORT_TYPE_LABELS: Record<string, string> = {
  period_kpi:    'KPI por Período',
  campaign_brief:'Resumen Campañas',
  sla_breach:    'SLA Breach',
  full_executive:'Ejecutivo Completo',
}

const PERIOD_LABELS: Record<string, string> = {
  daily: 'Diario', weekly: 'Semanal', monthly: 'Mensual',
  quarterly: 'Trimestral', custom: 'Personalizado',
}

function SigBadge({ valid }: { valid: boolean }) {
  return valid
    ? <span className="flex items-center gap-1 text-xs text-green-400"><CheckCircle size={12} />Firmado</span>
    : <span className="flex items-center gap-1 text-xs text-orange-400"><AlertTriangle size={12} />Sin firma</span>
}

function KpiCard({ icon: Icon, label, value, sub, accent }: {
  icon: React.ElementType; label: string; value: string | number; sub?: string; accent?: string
}) {
  return (
    <div className="bg-navy-800 rounded-lg p-4 border border-navy-700 flex items-start gap-3">
      <div className={clsx('mt-0.5 p-2 rounded', accent ?? 'bg-cyan-400/10')}>
        <Icon size={16} className="text-cyan-400" />
      </div>
      <div>
        <p className="text-2xl font-bold text-white">{value}</p>
        <p className="text-xs text-gray-400 mt-0.5">{label}</p>
        {sub && <p className="text-xs text-gray-600 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

// ── Report Row ────────────────────────────────────────────────────────────────

function ReportRow({
  report, selected, onSelect,
}: {
  report: ExecutiveReport; selected: boolean; onSelect: () => void
}) {
  return (
    <div
      onClick={onSelect}
      className={clsx(
        'p-3 rounded-lg border cursor-pointer transition-colors',
        selected
          ? 'bg-cyan-400/10 border-cyan-400/30'
          : 'bg-navy-800 border-navy-700 hover:border-navy-600',
      )}
    >
      <div className="flex items-center justify-between gap-2 mb-1">
        <span className="text-xs font-semibold text-cyan-400">
          {REPORT_TYPE_LABELS[report.report_type] ?? report.report_type}
        </span>
        <SigBadge valid={report.signature_valid} />
      </div>
      <p className="text-sm font-medium text-white truncate">{report.title}</p>
      <div className="flex items-center gap-3 mt-1">
        <span className="text-xs text-gray-500">
          {PERIOD_LABELS[report.period] ?? report.period}
        </span>
        <span className="text-xs text-gray-600">
          {report.created_at ? new Date(report.created_at).toLocaleDateString() : '—'}
        </span>
        <span className="text-xs text-gray-600 ml-auto font-mono">
          {truncHash(report.hash_sha3_512, 12)}
        </span>
      </div>
    </div>
  )
}

// ── Report Detail ─────────────────────────────────────────────────────────────

function ReportDetail({
  report, onClose, onVerified,
}: {
  report: ExecutiveReport
  onClose: () => void
  onVerified: (r: VerifyReportResult) => void
}) {
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState<VerifyReportResult | null>(null)
  const [showPayload, setShowPayload] = useState(false)

  async function doVerify() {
    setVerifying(true)
    try {
      const r = await verifyExecutiveReport(report.id)
      setVerifyResult(r)
      onVerified(r)
    } catch { /* noop */ }
    finally { setVerifying(false) }
  }

  const incData = report.canonical_data?.incidents as any
  const campData = report.canonical_data?.campaigns as any
  const huntData = report.canonical_data?.hunting as any
  const soarData = report.canonical_data?.soar as any

  return (
    <div className="bg-navy-800 border border-navy-700 rounded-lg p-5 space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-cyan-400/10 text-cyan-400 border border-cyan-400/20">
              {REPORT_TYPE_LABELS[report.report_type] ?? report.report_type}
            </span>
            <span className="text-xs text-gray-500">{PERIOD_LABELS[report.period]}</span>
            <SigBadge valid={report.signature_valid} />
          </div>
          <h2 className="text-white font-bold text-lg leading-tight">{report.title}</h2>
          <p className="text-xs text-gray-500 mt-1">
            {report.period_start ? new Date(report.period_start).toLocaleDateString() : '—'}
            {' → '}
            {report.period_end ? new Date(report.period_end).toLocaleDateString() : '—'}
          </p>
        </div>
        <button onClick={onClose} className="text-gray-600 hover:text-gray-300 shrink-0">
          <XCircle size={20} />
        </button>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-navy-900 rounded p-3 text-center">
          <p className="text-xl font-bold text-white">{report.total_incidents}</p>
          <p className="text-xs text-gray-500">Incidentes</p>
        </div>
        <div className="bg-navy-900 rounded p-3 text-center">
          <p className="text-xl font-bold text-orange-400">{report.sla_breach_count}</p>
          <p className="text-xs text-gray-500">SLA Breach</p>
        </div>
        <div className="bg-navy-900 rounded p-3 text-center">
          <p className="text-xl font-bold text-red-400">{report.campaign_count}</p>
          <p className="text-xs text-gray-500">Campañas</p>
        </div>
        <div className="bg-navy-900 rounded p-3 text-center">
          <p className="text-xl font-bold text-green-400">{report.closed_incidents}</p>
          <p className="text-xs text-gray-500">Cerrados</p>
        </div>
      </div>

      {/* MTTX */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'MTTD', val: report.avg_mttd_minutes },
          { label: 'MTTC', val: report.avg_mttc_minutes },
          { label: 'MTTR', val: report.avg_mttr_minutes },
        ].map(({ label, val }) => (
          <div key={label} className="bg-navy-900 rounded p-3 text-center">
            <p className="text-lg font-bold text-white">{fmtMins(val)}</p>
            <p className="text-xs text-gray-500">{label} promedio</p>
          </div>
        ))}
      </div>

      {/* Domain sub-KPIs */}
      {(campData || huntData || soarData) && (
        <div className="grid grid-cols-3 gap-3">
          {campData && (
            <div className="bg-navy-900 rounded p-3">
              <p className="text-xs text-gray-500 mb-1">Campañas activas</p>
              <p className="text-lg font-bold text-red-400">{campData.active_campaigns ?? '—'}</p>
              <p className="text-xs text-gray-600">{campData.critical_clusters ?? 0} clusters críticos</p>
            </div>
          )}
          {huntData && (
            <div className="bg-navy-900 rounded p-3">
              <p className="text-xs text-gray-500 mb-1">Hunts / Hallazgos</p>
              <p className="text-lg font-bold text-yellow-400">{huntData.confirmed_findings ?? '—'}</p>
              <p className="text-xs text-gray-600">{huntData.critical_findings ?? 0} críticos</p>
            </div>
          )}
          {soarData && (
            <div className="bg-navy-900 rounded p-3">
              <p className="text-xs text-gray-500 mb-1">SOAR disparado</p>
              <p className="text-lg font-bold text-blue-400">{soarData.soar_triggers_fired ?? '—'}</p>
              <p className="text-xs text-gray-600">{soarData.alerts_in_period ?? 0} alertas</p>
            </div>
          )}
        </div>
      )}

      {/* PIIL Seal */}
      <div className="bg-navy-900 rounded-lg p-4 space-y-2 border border-cyan-900/30">
        <div className="flex items-center gap-2 mb-2">
          <Lock size={14} className="text-cyan-400" />
          <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wide">PIIL Forensic Seal</span>
        </div>
        <div className="grid grid-cols-1 gap-1 text-xs font-mono">
          <div className="flex gap-2">
            <span className="text-gray-600 shrink-0">SHA3-512:</span>
            <span className="text-gray-400 break-all">{truncHash(report.hash_sha3_512, 32)}</span>
          </div>
          <div className="flex gap-2">
            <span className="text-gray-600 shrink-0">Ed25519:</span>
            <span className="text-gray-400 break-all">{truncHash(report.signature_ed25519, 24)}</span>
          </div>
          <div className="flex gap-2">
            <span className="text-gray-600 shrink-0">PubKey FP:</span>
            <span className="text-gray-400">{report.pubkey_fingerprint}</span>
          </div>
        </div>

        {verifyResult && (
          <div className={clsx(
            'mt-2 px-3 py-2 rounded text-xs font-semibold flex items-center gap-2',
            verifyResult.overall_valid
              ? 'bg-green-900/30 text-green-400 border border-green-700/30'
              : 'bg-red-900/30 text-red-400 border border-red-700/30'
          )}>
            {verifyResult.overall_valid
              ? <><CheckCircle size={12} /> Firma válida — Hash íntegro</>
              : <><XCircle size={12} /> Verificación fallida</>
            }
          </div>
        )}

        <button
          onClick={doVerify}
          disabled={verifying}
          className="mt-2 px-3 py-1.5 text-xs bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded hover:bg-cyan-500/20 disabled:opacity-40"
        >
          {verifying ? 'Verificando…' : 'Verificar firma PIIL'}
        </button>
      </div>

      {/* Canonical payload toggle */}
      <div>
        <button
          onClick={() => setShowPayload(v => !v)}
          className="flex items-center gap-2 text-xs text-gray-500 hover:text-gray-300"
        >
          <Eye size={12} />
          {showPayload ? 'Ocultar' : 'Ver'} payload canónico
        </button>
        {showPayload && (
          <pre className="mt-2 bg-navy-900 rounded p-3 text-xs text-gray-400 overflow-auto max-h-64 border border-navy-700">
            {JSON.stringify(report.canonical_data, null, 2)}
          </pre>
        )}
      </div>

      {/* Meta */}
      <div className="text-xs text-gray-500 border-t border-navy-700 pt-3 flex justify-between">
        <span>Generado por: {report.generated_by}</span>
        <span>{report.created_at ? new Date(report.created_at).toLocaleString() : '—'}</span>
      </div>
    </div>
  )
}

// ── Generate Form ─────────────────────────────────────────────────────────────

function GenerateForm({ onGenerated }: { onGenerated: () => void }) {
  const now = new Date()
  const firstOfMonth = new Date(now.getFullYear(), now.getMonth(), 1)

  const [form, setForm] = useState({
    report_type: 'full_executive',
    period: 'monthly',
    period_start: firstOfMonth.toISOString().slice(0, 10),
    period_end: now.toISOString().slice(0, 10),
    title: '',
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function submit() {
    setSaving(true)
    setError('')
    try {
      await generateExecutiveReport({
        ...form,
        period_start: new Date(form.period_start).toISOString(),
        period_end: new Date(form.period_end + 'T23:59:59Z').toISOString(),
        title: form.title || undefined,
      })
      onGenerated()
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'Error al generar reporte')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="bg-navy-800 border border-navy-700 rounded-lg p-5 space-y-4">
      <h3 className="text-white font-semibold text-sm flex items-center gap-2">
        <ScrollText size={14} className="text-cyan-400" />
        Generar Reporte Ejecutivo (PIIL)
      </h3>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Tipo de Reporte</label>
          <select
            className="w-full bg-navy-900 border border-navy-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
            value={form.report_type}
            onChange={e => setForm(f => ({ ...f, report_type: e.target.value }))}
          >
            {Object.entries(REPORT_TYPE_LABELS).map(([v, l]) => (
              <option key={v} value={v}>{l}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Período</label>
          <select
            className="w-full bg-navy-900 border border-navy-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
            value={form.period}
            onChange={e => setForm(f => ({ ...f, period: e.target.value }))}
          >
            {Object.entries(PERIOD_LABELS).map(([v, l]) => (
              <option key={v} value={v}>{l}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        {['period_start', 'period_end'].map(field => (
          <div key={field}>
            <label className="text-xs text-gray-500 mb-1 block">
              {field === 'period_start' ? 'Desde' : 'Hasta'}
            </label>
            <input
              type="date"
              className="w-full bg-navy-900 border border-navy-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
              value={form[field as keyof typeof form]}
              onChange={e => setForm(f => ({ ...f, [field]: e.target.value }))}
            />
          </div>
        ))}
      </div>

      <div>
        <label className="text-xs text-gray-500 mb-1 block">Título (opcional)</label>
        <input
          className="w-full bg-navy-900 border border-navy-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
          placeholder="PremosCorp ASC — Reporte Mensual Junio 2026"
          value={form.title}
          onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
        />
      </div>

      {error && <p className="text-red-400 text-xs">{error}</p>}

      <button
        onClick={submit}
        disabled={saving}
        className="w-full py-2 bg-cyan-500 hover:bg-cyan-400 text-navy-900 font-bold text-sm rounded disabled:opacity-40"
      >
        {saving ? 'Generando…' : 'Generar y Sellar (PIIL)'}
      </button>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ExecutiveReportsPage() {
  const { isReady } = useAuthGuard()

  const [summary, setSummary] = useState<ReportingSummary | null>(null)
  const [reports, setReports] = useState<ExecutiveReport[]>([])
  const [selected, setSelected] = useState<ExecutiveReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [showGenerate, setShowGenerate] = useState(false)
  const [filterType, setFilterType] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [sumR, repR] = await Promise.all([
        getReportingSummary(),
        listExecutiveReports({ report_type: filterType || undefined, limit: 100 }),
      ])
      setSummary(sumR)
      setReports(repR.items)
    } finally {
      setLoading(false)
    }
  }, [filterType])

  useEffect(() => {
    if (!isReady) return
    load()
    const id = setInterval(load, 30_000)  // tiempo real (S118.1)
    return () => clearInterval(id)
  }, [load, isReady])

  if (!isReady) return <AuthLoader />

  function onVerified(r: VerifyReportResult) {
    // Update signature_valid in the list
    setReports(prev => prev.map(rep =>
      rep.id === r.report_id ? { ...rep, signature_valid: r.overall_valid } : rep
    ))
    if (selected?.id === r.report_id) {
      setSelected(prev => prev ? { ...prev, signature_valid: r.overall_valid } : prev)
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-400/10 rounded">
            <ScrollText size={20} className="text-cyan-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Reportes Ejecutivos</h1>
            <p className="text-xs text-gray-500">
              PIIL — SHA3-512 + Ed25519 · Autenticidad Premos garantizada
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowGenerate(v => !v)}
            className="px-3 py-1.5 text-sm bg-cyan-500 hover:bg-cyan-400 text-navy-900 font-semibold rounded"
          >
            + Generar
          </button>
          <button
            onClick={load}
            disabled={loading}
            className="p-1.5 text-gray-400 hover:text-white disabled:opacity-40"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Generate form */}
      {showGenerate && (
        <GenerateForm onGenerated={() => { setShowGenerate(false); load() }} />
      )}

      {/* KPI strip */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <KpiCard icon={ScrollText}     label="Total Reportes"    value={summary.total_reports} />
          <KpiCard icon={AlertTriangle}  label="Sin Firma PIIL"    value={summary.unsigned_reports} accent="bg-orange-400/10" />
          <KpiCard icon={BarChart3}      label="Tipos distintos"   value={Object.keys(summary.by_type).length} />
          <KpiCard icon={Clock}          label="Último generado"   value={summary.last_generated_at ? new Date(summary.last_generated_at).toLocaleDateString() : '—'} />
        </div>
      )}

      {/* Type filter */}
      <div className="flex gap-3">
        <select
          className="bg-navy-800 border border-navy-700 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-cyan-500"
          value={filterType}
          onChange={e => setFilterType(e.target.value)}
        >
          <option value="">Todos los tipos</option>
          {Object.entries(REPORT_TYPE_LABELS).map(([v, l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </select>
      </div>

      {/* Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-5 gap-5">
        {/* List */}
        <div className="lg:col-span-1 xl:col-span-2 space-y-2">
          {loading && reports.length === 0 ? (
            <div className="flex justify-center py-12">
              <RefreshCw size={20} className="text-cyan-400 animate-spin" />
            </div>
          ) : reports.length === 0 ? (
            <div className="bg-navy-800 border border-navy-700 rounded-lg p-8 text-center">
              <ScrollText size={32} className="text-gray-600 mx-auto mb-3" />
              <p className="text-gray-500 text-sm">No hay reportes ejecutivos</p>
              <p className="text-gray-700 text-xs mt-1">Genera uno con el botón "+ Generar"</p>
            </div>
          ) : (
            reports.map(r => (
              <ReportRow
                key={r.id}
                report={r}
                selected={selected?.id === r.id}
                onSelect={() => setSelected(r)}
              />
            ))
          )}
        </div>

        {/* Detail */}
        <div className="xl:col-span-3">
          {selected ? (
            <ReportDetail
              report={selected}
              onClose={() => setSelected(null)}
              onVerified={onVerified}
            />
          ) : (
            <div className="bg-navy-800 border border-dashed border-navy-600 rounded-lg p-12 text-center">
              <Shield size={40} className="text-gray-700 mx-auto mb-3" />
              <p className="text-gray-500 text-sm">Selecciona un reporte para ver el detalle</p>
              <p className="text-gray-600 text-xs mt-1">
                Cada reporte incluye sello PIIL verificable offline
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
