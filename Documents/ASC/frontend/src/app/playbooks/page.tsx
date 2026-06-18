'use client'
import { useState, useEffect, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { Semaphore } from '@/components/dashboard/Semaphore'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'
import {
  getPlaybookCatalog, getPlaybookRuns, getPlaybookRun,
  triggerPlaybook, approvePlaybookRun, abortPlaybookRun,
  PlaybookDef, PlaybookRun, StepLog,
} from '@/lib/api'
import {
  BookOpen, Play, CheckCircle, XCircle, Clock, AlertTriangle,
  ChevronRight, RefreshCw, Shield, Zap, Eye, type LucideIcon,
} from 'lucide-react'

type Tab = 'catalog' | 'runs' | 'detail'

// ─── Helpers ─────────────────────────────────────────────────────────────────

const SEMAPHORE_COLOR: Record<string, string> = {
  green:  'text-[#3FD175] bg-[rgba(45,184,99,0.08)]  border-[rgba(45,184,99,0.3)]',
  yellow: 'text-[#F2C205] bg-[rgba(242,194,5,0.08)]  border-[rgba(242,194,5,0.3)]',
  red:    'text-[#E8526E] bg-[rgba(192,21,46,0.1)]   border-[rgba(192,21,46,0.3)]',
}

const STATUS_COLOR: Record<string, string> = {
  pending:           'text-[#5A5A5A]',
  running:           'text-[#E85D04]',
  awaiting_approval: 'text-[#F2C205]',
  completed:         'text-[#3FD175]',
  failed:            'text-[#E8526E]',
  aborted:           'text-[#FF7A25]',
}

const STATUS_LABEL: Record<string, string> = {
  pending:           'Pendiente',
  running:           'Ejecutando',
  awaiting_approval: 'Esperando Aprobación',
  completed:         'Completado',
  failed:            'Fallido',
  aborted:           'Abortado',
}

const STEP_ICON: Record<string, LucideIcon> = {
  ok:               CheckCircle,
  awaiting_approval: Clock,
  warning:          AlertTriangle,
  error:            XCircle,
}

function SemaphoreBadge({ level }: { level: string }) {
  const cls = SEMAPHORE_COLOR[level] ?? 'text-gray-400 bg-gray-400/10 border-gray-400/30'
  return (
    <span className={`border rounded px-2 py-0.5 text-xs font-semibold uppercase ${cls}`}>
      {level}
    </span>
  )
}

function StatusBadge({ status }: { status: PlaybookRun['status'] }) {
  return (
    <span className={`text-xs font-semibold ${STATUS_COLOR[status] ?? 'text-gray-400'}`}>
      {STATUS_LABEL[status] ?? status}
    </span>
  )
}

function fmtTs(iso: string | null | undefined) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'medium' })
}

function fmtRisk(n: number) {
  return (n * 100).toFixed(0) + '%'
}

// ─── Trigger form (per-playbook) ──────────────────────────────────────────────

function TriggerForm({ pb, onDone }: { pb: PlaybookDef; onDone: (run: PlaybookRun) => void }) {
  const [open, setOpen] = useState(false)
  const [host, setHost] = useState('')
  const [dstIp, setDstIp] = useState('')
  const [dstDomain, setDstDomain] = useState('')
  const [process, setProcess] = useState('')
  const [risk, setRisk] = useState(String(((pb.min_risk + pb.max_risk) / 2).toFixed(2)))
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true); setErr('')
    try {
      const run = await triggerPlaybook({
        playbook_id: pb.id,
        semaphore:   pb.semaphore,
        risk_score:  parseFloat(risk),
        host:        host || undefined,
        dst_ip:      dstIp || undefined,
        dst_domain:  dstDomain || undefined,
        process_name: process || undefined,
      })
      setOpen(false)
      onDone(run)
    } catch (e: any) {
      setErr(e?.response?.data?.detail || e.message || 'Error al disparar')
    } finally {
      setLoading(false)
    }
  }

  if (!open) {
    return (
      <button onClick={() => setOpen(true)}
        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all"
        style={{
          background: 'rgba(232,93,4,0.08)',
          color:      '#E85D04',
          border:     '1px solid rgba(232,93,4,0.2)',
        }}
      >
        <Play size={12} /> Disparar
      </button>
    )
  }

  return (
    <form onSubmit={submit}
      className="mt-3 rounded-xl p-4 space-y-3"
      style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)' }}
    >
      <p className="text-xs font-semibold" style={{ color: '#A0A0A0' }}>Parámetros del trigger</p>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs mb-1" style={{ color: '#5A5A5A' }}>Host</label>
          <input value={host} onChange={e => setHost(e.target.value)} placeholder="PREMOS-WS-01"
            className="input-asc text-xs" />
        </div>
        <div>
          <label className="block text-xs mb-1" style={{ color: '#5A5A5A' }}>Risk Score</label>
          <input value={risk} onChange={e => setRisk(e.target.value)} type="number" step="0.01" min={pb.min_risk} max={pb.max_risk}
            className="input-asc text-xs" />
        </div>
        <div>
          <label className="block text-xs mb-1" style={{ color: '#5A5A5A' }}>IP Destino</label>
          <input value={dstIp} onChange={e => setDstIp(e.target.value)} placeholder="10.0.0.1"
            className="input-asc text-xs" />
        </div>
        <div>
          <label className="block text-xs mb-1" style={{ color: '#5A5A5A' }}>Dominio Destino</label>
          <input value={dstDomain} onChange={e => setDstDomain(e.target.value)} placeholder="evil.com"
            className="input-asc text-xs" />
        </div>
        <div className="col-span-2">
          <label className="block text-xs mb-1" style={{ color: '#5A5A5A' }}>Proceso</label>
          <input value={process} onChange={e => setProcess(e.target.value)} placeholder="acord32.exe"
            className="input-asc text-xs" />
        </div>
      </div>
      {err && (
        <p className="text-xs rounded-lg px-2 py-1" style={{ background: 'rgba(192,21,46,0.08)', color: '#E8526E' }}>
          {err}
        </p>
      )}
      <div className="flex gap-2">
        <button type="submit" disabled={loading}
          className="flex-1 btn-primary text-xs py-1.5 disabled:opacity-50">
          {loading ? 'Disparando...' : 'Confirmar'}
        </button>
        <button type="button" onClick={() => { setOpen(false); setErr('') }}
          className="btn-secondary text-xs px-3 py-1.5">
          Cancelar
        </button>
      </div>
    </form>
  )
}

// ─── Catalog tab ──────────────────────────────────────────────────────────────

function CatalogTab({ onRunCreated }: { onRunCreated: (run: PlaybookRun) => void }) {
  const [catalog, setCatalog] = useState<PlaybookDef[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')

  useEffect(() => {
    getPlaybookCatalog()
      .then(setCatalog)
      .catch(() => setErr('No se pudo cargar el catálogo'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <p className="text-gray-500 text-sm">Cargando catálogo...</p>
  if (err)     return <p className="text-red-400 text-sm">{err}</p>

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
      {catalog.map(pb => (
        <div key={pb.id} className="card">
          <div className="flex items-start justify-between mb-3">
            <div>
              <span className="font-mono text-xs text-gray-500">{pb.id}</span>
              <h3 className="font-bold text-white text-sm mt-0.5">{pb.name}</h3>
            </div>
            <div className="flex items-center gap-2">
              <SemaphoreBadge level={pb.semaphore} />
              {pb.requires_approval && (
                <span className="text-xs bg-yellow-400/10 border border-yellow-400/30 text-yellow-400 px-2 py-0.5 rounded">
                  HitL
                </span>
              )}
            </div>
          </div>

          <p className="text-gray-400 text-xs mb-3">{pb.description}</p>

          <div className="flex items-center gap-4 text-xs text-gray-500 mb-4">
            <span>Risk: <span className="text-cyan-400">{fmtRisk(pb.min_risk)}–{fmtRisk(pb.max_risk)}</span></span>
            <span>{pb.step_count} pasos</span>
            <span className={pb.requires_approval ? 'text-yellow-400' : 'text-green-400'}>
              {pb.requires_approval ? 'Aprobación manual' : 'Automático'}
            </span>
          </div>

          {/* Steps list */}
          <div className="space-y-1 mb-4">
            {pb.steps.map((s, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <span className="text-gray-700 w-4 text-right">{i + 1}.</span>
                <span className="font-mono text-gray-500">{s.action}</span>
                <ChevronRight size={10} className="text-gray-700" />
                <span className="text-gray-400">{s.name}</span>
              </div>
            ))}
          </div>

          <TriggerForm pb={pb} onDone={run => { onRunCreated(run) }} />
        </div>
      ))}
    </div>
  )
}

// ─── Approval modal ───────────────────────────────────────────────────────────

function ApproveModal({ run, onClose, onDone }: {
  run: PlaybookRun
  onClose: () => void
  onDone: () => void
}) {
  const [token, setToken] = useState('')
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true); setErr('')
    try {
      await approvePlaybookRun(run.id, token.trim())
      onDone()
      onClose()
    } catch (e: any) {
      setErr(e?.response?.data?.detail || 'Token inválido o ejecución no disponible')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-navy-800 rounded-lg p-6 w-full max-w-md border border-navy-600">
        <h3 className="text-white font-bold mb-1">Aprobar Ejecución</h3>
        <p className="text-gray-500 text-xs mb-4">Run: <span className="font-mono text-gray-400">{run.id.slice(0, 8)}…</span> — {run.playbook_name}</p>
        <form onSubmit={submit} className="space-y-3">
          <div>
            <label className="block text-xs text-gray-400 mb-1">Token de Aprobación (UUID)</label>
            <input
              value={token}
              onChange={e => setToken(e.target.value)}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              className="w-full bg-navy-900 border border-navy-700 rounded px-3 py-2 text-white font-mono text-xs outline-none focus:border-cyan-400"
              autoFocus
            />
          </div>
          {err && <p className="text-red-400 text-xs bg-red-400/10 rounded px-2 py-1">{err}</p>}
          <div className="flex gap-2">
            <button type="submit" disabled={loading || !token.trim()}
              className="flex-1 py-2 rounded bg-green-400 text-navy-900 font-bold text-sm hover:bg-green-300 disabled:opacity-50 transition-colors">
              {loading ? 'Aprobando...' : 'Aprobar y Continuar'}
            </button>
            <button type="button" onClick={onClose}
              className="px-4 py-2 rounded bg-navy-700 text-gray-400 text-sm hover:text-white transition-colors">
              Cancelar
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Runs tab ─────────────────────────────────────────────────────────────────

function RunsTab({ onViewDetail, refresh }: {
  onViewDetail: (run: PlaybookRun) => void
  refresh: number
}) {
  const [runs, setRuns] = useState<PlaybookRun[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('')
  const [approveTarget, setApproveTarget] = useState<PlaybookRun | null>(null)
  const [page, setPage] = useState(0)
  const PAGE_SIZE = 10

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await getPlaybookRuns({
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
        status: statusFilter || undefined,
      })
      setRuns(res.runs)
      setTotal(res.total)
    } catch {
      // silently swallow — the table stays empty
    } finally {
      setLoading(false)
    }
  }, [statusFilter, page, refresh])

  useEffect(() => { load() }, [load])

  async function abort(run: PlaybookRun) {
    if (!confirm(`¿Abortar ejecución ${run.id.slice(0, 8)}?`)) return
    try {
      await abortPlaybookRun(run.id)
      load()
    } catch (e: any) {
      alert(e?.response?.data?.detail || 'No se pudo abortar')
    }
  }

  const STATUS_OPTS = ['', 'pending', 'running', 'awaiting_approval', 'completed', 'failed', 'aborted']

  return (
    <div>
      {approveTarget && (
        <ApproveModal run={approveTarget} onClose={() => setApproveTarget(null)} onDone={load} />
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(0) }}
          className="input-asc text-xs" style={{ width: 'auto', minWidth: 180 }}>
          {STATUS_OPTS.map(s => (
            <option key={s} value={s}>{s ? STATUS_LABEL[s] : 'Todos los estados'}</option>
          ))}
        </select>
        <button onClick={() => load()}
          className="btn-secondary flex items-center gap-1 text-xs py-1.5 px-3">
          <RefreshCw size={12} /> Actualizar
        </button>
        <span className="ml-auto text-xs" style={{ color: '#3A3A3A' }}>{total} ejecucion{total !== 1 ? 'es' : ''}</span>
      </div>

      {loading && <p className="text-gray-500 text-sm">Cargando ejecuciones...</p>}

      {!loading && runs.length === 0 && (
        <div className="card text-center py-10">
          <BookOpen className="text-gray-700 mx-auto mb-2" size={32} />
          <p className="text-gray-500 text-sm">Sin ejecuciones registradas</p>
          <p className="text-gray-700 text-xs mt-1">Dispara un playbook desde la pestaña Catálogo</p>
        </div>
      )}

      {!loading && runs.length > 0 && (
        <div className="card overflow-x-auto">
          <table className="table-asc">
            <thead>
              <tr>
                <th className="px-4 py-2 text-left font-medium">Run ID</th>
                <th className="px-4 py-2 text-left font-medium">Playbook</th>
                <th className="px-4 py-2 text-left font-medium">Semáforo</th>
                <th className="px-4 py-2 text-left font-medium">Risk</th>
                <th className="px-4 py-2 text-left font-medium">Estado</th>
                <th className="px-4 py-2 text-left font-medium">Inicio</th>
                <th className="px-4 py-2 text-left font-medium">Iniciado por</th>
                <th className="px-4 py-2 text-right font-medium pr-4">Acciones</th>
              </tr>
            </thead>
            <tbody>
              {runs.map(run => (
                <tr key={run.id}>
                  <td className="px-4 py-2.5 font-mono text-gray-500">{run.id.slice(0, 8)}…</td>
                  <td className="px-4 py-2.5">
                    <span className="text-gray-400">{run.playbook_id}</span>
                    <span className="text-gray-600 ml-1 hidden md:inline">· {run.playbook_name.slice(0, 20)}</span>
                  </td>
                  <td className="px-4 py-2.5"><SemaphoreBadge level={run.semaphore} /></td>
                  <td className="px-4 py-2.5 font-mono font-bold text-xs" style={{ color: '#E85D04' }}>{fmtRisk(run.risk_score)}</td>
                  <td className="px-4 py-2.5"><StatusBadge status={run.status} /></td>
                  <td className="px-4 py-2.5 text-gray-600">{fmtTs(run.started_at)}</td>
                  <td className="px-4 py-2.5 text-gray-500 font-mono">{run.initiated_by.slice(0, 8)}…</td>
                  <td className="px-4 py-2.5 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button onClick={() => onViewDetail(run)}
                        className="flex items-center gap-1 px-2 py-1 rounded bg-navy-700 text-gray-400 hover:text-white text-xs transition-colors">
                        <Eye size={11} /> Ver
                      </button>
                      {run.status === 'awaiting_approval' && (
                        <button onClick={() => setApproveTarget(run)}
                          className="flex items-center gap-1 px-2 py-1 rounded bg-green-400/10 border border-green-400/30 text-green-400 hover:bg-green-400/20 text-xs transition-colors">
                          <CheckCircle size={11} /> Aprobar
                        </button>
                      )}
                      {(run.status === 'pending' || run.status === 'awaiting_approval') && (
                        <button onClick={() => abort(run)}
                          className="flex items-center gap-1 px-2 py-1 rounded bg-red-400/10 border border-red-400/30 text-red-400 hover:bg-red-400/20 text-xs transition-colors">
                          <XCircle size={11} /> Abortar
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Pagination */}
          {total > PAGE_SIZE && (
            <div
              className="flex items-center justify-between px-4 py-3"
              style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}
            >
              <button disabled={page === 0} onClick={() => setPage(p => p - 1)}
                className="text-xs disabled:opacity-40 transition-colors"
                style={{ color: '#5A5A5A' }}>
                ← Anterior
              </button>
              <span className="text-xs" style={{ color: '#3A3A3A' }}>
                Pág. {page + 1} / {Math.ceil(total / PAGE_SIZE)}
              </span>
              <button disabled={(page + 1) * PAGE_SIZE >= total} onClick={() => setPage(p => p + 1)}
                className="text-xs disabled:opacity-40 transition-colors"
                style={{ color: '#5A5A5A' }}>
                Siguiente →
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Detail tab ───────────────────────────────────────────────────────────────

function DetailTab({ run, onRefresh }: { run: PlaybookRun | null; onRefresh: () => void }) {
  const [detail, setDetail] = useState<PlaybookRun | null>(run)
  const [loading, setLoading] = useState(false)

  useEffect(() => { setDetail(run) }, [run])

  async function refresh() {
    if (!detail) return
    setLoading(true)
    try {
      setDetail(await getPlaybookRun(detail.id))
      onRefresh()
    } finally {
      setLoading(false)
    }
  }

  if (!detail) {
    return (
      <div className="card text-center py-16">
        <Eye className="text-gray-700 mx-auto mb-2" size={36} />
        <p className="text-gray-500 text-sm">Selecciona una ejecución en la pestaña Ejecuciones</p>
        <p className="text-gray-700 text-xs mt-1">Haz clic en "Ver" para abrir el detalle aquí</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header card */}
      <div className="card p-5">
        <div className="flex items-start justify-between mb-4 flex-wrap gap-3">
          <div>
            <p className="font-mono text-xs mb-0.5" style={{ color: '#5A5A5A' }}>Run ID: {detail.id}</p>
            <h2 className="font-bold text-lg" style={{ color: '#EAEAEA' }}>{detail.playbook_name}</h2>
            <p className="text-xs" style={{ color: '#5A5A5A' }}>{detail.playbook_id} · Trigger: {detail.trigger_source}</p>
          </div>
          <div className="flex items-center gap-3">
            <SemaphoreBadge level={detail.semaphore} />
            <StatusBadge status={detail.status} />
            <button onClick={refresh} disabled={loading}
              className="flex items-center gap-1 px-3 py-1.5 rounded bg-navy-800 border border-navy-700 text-gray-400 hover:text-white text-xs transition-colors disabled:opacity-50">
              <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> Refrescar
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Risk Score', value: fmtRisk(detail.risk_score), cls: 'text-cyan-400' },
            { label: 'Inicio',     value: fmtTs(detail.started_at),   cls: 'text-gray-300' },
            { label: 'Fin',        value: fmtTs(detail.completed_at), cls: 'text-gray-300' },
            { label: 'Iniciado por', value: detail.initiated_by.slice(0, 12) + '…', cls: 'text-gray-400 font-mono' },
          ].map(({ label, value, cls }) => (
            <div key={label} className="bg-navy-900 rounded p-3">
              <p className="text-xs text-gray-600 mb-1">{label}</p>
              <p className={`text-sm font-semibold ${cls}`}>{value}</p>
            </div>
          ))}
        </div>

        {detail.status === 'awaiting_approval' && (
          <div className="mt-4 bg-yellow-400/10 border border-yellow-400/30 rounded p-3">
            <p className="text-yellow-400 text-sm font-semibold flex items-center gap-2">
              <Clock size={14} /> Esperando aprobación Human-in-the-Loop
            </p>
            {detail.approval_token && (
              <p className="text-xs text-gray-400 mt-1">
                Token: <span className="font-mono text-yellow-300">{detail.approval_token}</span>
              </p>
            )}
          </div>
        )}

        {detail.approved_by && (
          <div className="mt-4 bg-green-400/10 border border-green-400/30 rounded p-3 text-xs">
            <p className="text-green-400 font-semibold">Aprobado</p>
            <p className="text-gray-400 mt-0.5">
              Por: <span className="font-mono">{detail.approved_by}</span> ·  {fmtTs(detail.approved_at)}
            </p>
          </div>
        )}

        {detail.error && (
          <div className="mt-4 bg-red-400/10 border border-red-400/30 rounded p-3 text-xs">
            <p className="text-red-400 font-semibold mb-0.5">Error</p>
            <p className="text-gray-400 font-mono">{detail.error}</p>
          </div>
        )}
      </div>

      {/* Steps timeline */}
      <div className="card p-5">
        <h3 className="font-semibold mb-4 text-sm" style={{ color: '#E85D04' }}>Timeline de Pasos</h3>
        {detail.steps_log.length === 0 && (
          <p className="text-gray-600 text-sm">Sin pasos registrados aún</p>
        )}
        <div className="space-y-3">
          {detail.steps_log.map((step: StepLog, i: number) => {
            const Icon = STEP_ICON[step.status] ?? AlertTriangle
            const iconCls = {
              ok:               'text-green-400',
              awaiting_approval: 'text-yellow-400',
              warning:          'text-orange-400',
              error:            'text-red-400',
            }[step.status] ?? 'text-gray-400'

            return (
              <div key={i} className="flex gap-3">
                {/* Line connector */}
                <div className="flex flex-col items-center">
                  <Icon size={16} className={iconCls} />
                  {i < detail.steps_log.length - 1 && (
                    <div className="w-px flex-1 bg-navy-700 mt-1" />
                  )}
                </div>

                <div className="flex-1 pb-3">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-gray-500 text-xs">#{step.step_index + 1}</span>
                    <span className="font-mono text-xs text-gray-500">{step.action}</span>
                    <span className="text-white text-xs font-semibold">{step.name}</span>
                    <span className="ml-auto text-xs text-gray-600">{fmtTs(step.ts)}</span>
                  </div>
                  {step.detail && (
                    <p className="text-gray-500 text-xs ml-1">{step.detail}</p>
                  )}
                  {step.alert_id && (
                    <p className="text-xs text-cyan-400 ml-1 mt-0.5">
                      Alert ID: <span className="font-mono">{step.alert_id}</span>
                    </p>
                  )}
                  {step.neutralizer_details && (
                    <details className="mt-1">
                      <summary className="text-xs text-gray-600 cursor-pointer hover:text-gray-400">Detalles del neutralizador</summary>
                      <pre className="text-xs font-mono text-gray-500 mt-1 bg-navy-900 rounded p-2 overflow-x-auto">
                        {JSON.stringify(step.neutralizer_details, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Trigger data */}
      {detail.trigger_data && Object.keys(detail.trigger_data).length > 0 && (
        <div className="card">
          <details>
            <summary className="text-gray-500 text-xs cursor-pointer hover:text-gray-300 font-medium">
              Datos del Trigger (JSON)
            </summary>
            <pre className="text-xs font-mono text-gray-400 mt-3 bg-navy-900 rounded p-3 overflow-x-auto max-h-48">
              {JSON.stringify(detail.trigger_data, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function PlaybooksPage() {
  const { isReady } = useAuthGuard()
  const [tab, setTab]               = useState<Tab>('catalog')
  const [selectedRun, setSelectedRun] = useState<PlaybookRun | null>(null)
  const [runsRefresh, setRunsRefresh] = useState(0)

  function handleRunCreated(run: PlaybookRun) {
    setSelectedRun(run)
    setTab('detail')
    setRunsRefresh(n => n + 1)
  }

  function handleViewDetail(run: PlaybookRun) {
    setSelectedRun(run)
    setTab('detail')
  }

  const TABS: { id: Tab; label: string; icon: LucideIcon }[] = [
    { id: 'catalog', label: 'Catálogo',    icon: BookOpen },
    { id: 'runs',    label: 'Ejecuciones', icon: Shield },
    { id: 'detail',  label: 'Detalle',     icon: Zap },
  ]

  if (!isReady) return <AuthLoader />

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6 overflow-auto">
        {/* Sticky header */}
        <div
          className="sticky top-0 z-20 px-6 py-3 flex items-center justify-between"
          style={{
            background:     'rgba(10,10,10,0.92)',
            borderBottom:   '1px solid rgba(255,255,255,0.05)',
            backdropFilter: 'blur(12px)',
          }}
        >
          <div className="flex items-center gap-3">
            <BookOpen size={18} style={{ color: '#E85D04' }} />
            <div>
              <h1 className="text-sm font-bold leading-none" style={{ color: '#EAEAEA' }}>Playbooks SOC</h1>
              <p className="text-xs mt-0.5" style={{ color: '#3A3A3A' }}>
                PB-001 Verde · PB-002 Amarillo · PB-003 Rojo · PB-004 Targeted — HitL activo
              </p>
            </div>
          </div>
        </div>

        <div className="p-6 space-y-5 animate-fade-in">

        {/* Tabs */}
        <div className="flex gap-2 flex-wrap">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all"
              style={tab === id ? {
                background: 'rgba(232,93,4,0.15)',
                border:     '1px solid rgba(232,93,4,0.35)',
                color:      '#FF7A25',
              } : {
                background: 'rgba(255,255,255,0.03)',
                border:     '1px solid rgba(255,255,255,0.06)',
                color:      '#5A5A5A',
              }}
            >
              <Icon size={14} />{label}
              {id === 'detail' && selectedRun && (
                <span className="ml-1 font-mono text-xs opacity-70">
                  {selectedRun.id.slice(0, 6)}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {tab === 'catalog' && <CatalogTab onRunCreated={handleRunCreated} />}
        {tab === 'runs'    && <RunsTab onViewDetail={handleViewDetail} refresh={runsRefresh} />}
        {tab === 'detail'  && <DetailTab run={selectedRun} onRefresh={() => setRunsRefresh(n => n + 1)} />}
        </div>
      </main>
    </div>
  )
}
