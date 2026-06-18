'use client'
import { useCallback, useEffect, useRef, useState } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'
import {
  requestNeutralizeAction,
  approveNeutralizeAction,
  rejectNeutralizeAction,
  getPendingApprovals,
  getNeutralizeHistory,
  getNeutralizeCommands,
  requestRollback,
  subscribeToNotifications,
  NeutralizeAction,
  NeutralizeActionType,
  NeutralizeSeverity,
  DispatchMode,
  SprecterCommandSummary,
  PanlNotification,
} from '@/lib/api'
import {
  Zap, Clock, CheckCircle, XCircle, AlertTriangle,
  ShieldAlert, UserCheck, UserX, Timer, Radio, Cpu, FlaskConical,
  RotateCcw, Bell, BellRing, Shield, GitBranch,
} from 'lucide-react'

// ── Pure helper functions (exported for unit tests) ───────────────────────────

export function statusColor(status: string): string {
  const map: Record<string, string> = {
    pending_approval: 'text-yellow-400',
    approved:         'text-blue-400',
    executing:        'text-blue-300',
    completed:        'text-green-400',
    failed:           'text-red-400',
    rejected:         'text-gray-400',
    escalated:        'text-orange-400',
  }
  return map[status] ?? 'text-gray-400'
}

export function statusLabel(status: string): string {
  const map: Record<string, string> = {
    pending_approval: 'Pendiente Aprobación',
    approved:         'Aprobada',
    executing:        'Ejecutando',
    completed:        'Completada',
    failed:           'Fallida',
    rejected:         'Rechazada',
    escalated:        'Escalada',
  }
  return map[status] ?? status
}

export function severityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: 'text-red-400 bg-red-400/10 border-red-400/30',
    high:     'text-orange-400 bg-orange-400/10 border-orange-400/30',
    medium:   'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
    low:      'text-gray-400 bg-gray-400/10 border-gray-400/30',
  }
  return map[severity] ?? 'text-gray-400 bg-gray-400/10 border-gray-400/30'
}

export function dispatchModeLabel(mode: DispatchMode | string): string {
  const map: Record<string, string> = {
    specter:    'SPECTER Agente',
    broadcast:  'SPECTER Broadcast',
    simulation: 'Simulación',
  }
  return map[mode] ?? mode
}

export function dispatchModeClasses(mode: DispatchMode | string): string {
  const map: Record<string, string> = {
    specter:    'text-cyan-400 bg-cyan-400/10 border-cyan-400/30',
    broadcast:  'text-purple-400 bg-purple-400/10 border-purple-400/30',
    simulation: 'text-gray-400 bg-gray-400/10 border-gray-400/30',
  }
  return map[mode] ?? 'text-gray-400 bg-gray-400/10 border-gray-400/30'
}

export function commandStatusColor(status: string): string {
  const map: Record<string, string> = {
    pending:   'text-yellow-400',
    delivered: 'text-blue-400',
    executing: 'text-blue-300',
    completed: 'text-green-400',
    failed:    'text-red-400',
    cancelled: 'text-gray-400',
  }
  return map[status] ?? 'text-gray-400'
}

export function requiresApproval(actionType: string, severity: string): boolean {
  const alwaysApprove = new Set(['isolate_endpoint', 'disable_account'])
  const approvalSeverities = new Set(['critical', 'high'])
  return alwaysApprove.has(actionType) || approvalSeverities.has(severity)
}

export function multiSigLabel(received: number, required: number): string {
  if (required <= 1) return ''
  return `${received}/${required} firmas`
}

export function multiSigColor(received: number, required: number): string {
  if (received >= required) return 'text-green-400'
  if (received > 0) return 'text-amber-400'
  return 'text-gray-400'
}

export function rollbackActionLabel(actionType: string): string {
  const map: Record<string, string> = {
    unisolate_endpoint: 'Revertir Aislamiento',
    unblock_ip:         'Desbloquear IP',
    unblock_domain:     'Desbloquear Dominio',
    restore_file:       'Restaurar Archivo',
  }
  return map[actionType] ?? actionType
}

export function minutesRemaining(expiresAt: string | null): number {
  if (!expiresAt) return 0
  const diff = new Date(expiresAt).getTime() - Date.now()
  return Math.max(0, Math.floor(diff / 60000))
}

export function formatTs(ts: string | null | undefined): string {
  if (!ts) return '—'
  return ts.slice(0, 16).replace('T', ' ')
}

// ── Constants ─────────────────────────────────────────────────────────────────

const ACTIONS: { value: NeutralizeActionType; label: string; icon: string }[] = [
  { value: 'isolate_endpoint',   label: 'Aislar Endpoint',          icon: '🔒' },
  { value: 'block_ip',           label: 'Bloquear IP',              icon: '🚫' },
  { value: 'block_domain',       label: 'Bloquear Dominio',         icon: '🌐' },
  { value: 'kill_process',       label: 'Terminar Proceso',         icon: '⛔' },
  { value: 'quarantine_file',    label: 'Cuarentena de Archivo',    icon: '📦' },
  { value: 'remove_persistence', label: 'Eliminar Persistencia',    icon: '🗑️' },
  { value: 'disable_account',    label: 'Deshabilitar Cuenta',      icon: '👤' },
]

const SEVERITIES: NeutralizeSeverity[] = ['critical', 'high', 'medium', 'low']

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const color = statusColor(status)
  const label = statusLabel(status)
  const icons: Record<string, React.ReactNode> = {
    pending_approval: <Clock size={11} />,
    approved:         <UserCheck size={11} />,
    executing:        <Zap size={11} />,
    completed:        <CheckCircle size={11} />,
    failed:           <XCircle size={11} />,
    rejected:         <UserX size={11} />,
    escalated:        <AlertTriangle size={11} />,
  }
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${color}`}>
      {icons[status] ?? <Clock size={11} />}
      {label}
    </span>
  )
}

function PendingCard({
  action,
  currentUser,
  onApprove,
  onReject,
}: {
  action: NeutralizeAction
  currentUser: string
  onApprove: (id: string) => Promise<void>
  onReject: (id: string, reason: string) => Promise<void>
}) {
  const [rejecting, setRejecting] = useState(false)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const mins = minutesRemaining(action.expires_at)
  const isSelf = action.initiated_by === currentUser

  async function handleApprove() {
    setBusy(true); setErr('')
    try { await onApprove(action.id) }
    catch (e: any) { setErr(e?.response?.data?.detail || e.message) }
    finally { setBusy(false) }
  }

  async function handleReject() {
    if (!reason.trim()) { setErr('La razón de rechazo es obligatoria'); return }
    setBusy(true); setErr('')
    try { await onReject(action.id, reason) }
    catch (e: any) { setErr(e?.response?.data?.detail || e.message) }
    finally { setBusy(false) }
  }

  return (
    <div className="border border-yellow-400/25 rounded-lg p-4 bg-yellow-400/5 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="text-white text-sm font-semibold font-mono">
            {ACTIONS.find(a => a.value === action.action_type)?.icon}{' '}
            {ACTIONS.find(a => a.value === action.action_type)?.label ?? action.action_type}
          </p>
          <p className="text-gray-400 text-xs mt-0.5">
            Target: <span className="text-gray-200 font-mono">{action.target}</span>
          </p>
          <p className="text-gray-500 text-xs">
            Solicitado por: <span className="text-gray-300">{action.initiated_by ?? '—'}</span>
          </p>
        </div>
        <div className="text-right shrink-0">
          <span className={`inline-block text-xs font-bold border rounded px-2 py-0.5 ${severityColor(action.severity)}`}>
            {action.severity.toUpperCase()}
          </span>
          <p className="text-xs mt-1 flex items-center gap-1 justify-end">
            <Timer size={10} className={mins < 5 ? 'text-red-400' : 'text-gray-500'} />
            <span className={mins < 5 ? 'text-red-400' : 'text-gray-500'}>{mins} min restantes</span>
          </p>
        </div>
      </div>

      {/* PANL severity adaptation badge */}
      {action.severity_adapted && action.original_severity && (
        <p className="text-purple-400 text-xs bg-purple-400/10 border border-purple-400/30 rounded px-2 py-1.5 flex items-center gap-1.5">
          <Shield size={11} /> PANL: Severidad elevada de{' '}
          <strong>{action.original_severity.toUpperCase()}</strong> a{' '}
          <strong>{action.severity.toUpperCase()}</strong> por contexto adaptativo
        </p>
      )}

      {/* PANL multi-sig progress */}
      {action.required_approvals > 1 && (
        <div className="bg-navy-900 border border-navy-700 rounded px-3 py-2 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400 flex items-center gap-1">
              <GitBranch size={11} /> Multi-firma (CRITICAL)
            </span>
            <span className={`text-xs font-bold ${multiSigColor(action.approvals_received, action.required_approvals)}`}>
              {multiSigLabel(action.approvals_received, action.required_approvals)}
            </span>
          </div>
          <div className="w-full bg-navy-700 rounded-full h-1">
            <div
              className="bg-amber-400 h-1 rounded-full transition-all"
              style={{ width: `${(action.approvals_received / action.required_approvals) * 100}%` }}
            />
          </div>
          {action.approvals_log.map((entry, i) => (
            <p key={i} className="text-xs text-gray-500">
              Firma {i + 1}: <span className="text-gray-300">{entry.approved_by}</span>
            </p>
          ))}
        </div>
      )}

      {isSelf && (
        <p className="text-amber-400 text-xs bg-amber-400/10 border border-amber-400/30 rounded px-2 py-1.5 flex items-center gap-1.5">
          <AlertTriangle size={12} /> No puedes aprobar tu propia acción (auto-aprobación bloqueada)
        </p>
      )}

      {err && <p className="text-red-400 text-xs bg-red-400/10 rounded px-2 py-1">{err}</p>}

      {rejecting ? (
        <div className="space-y-2">
          <textarea
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="Motivo del rechazo (obligatorio)..."
            rows={2}
            className="w-full bg-navy-900 border border-navy-700 rounded px-3 py-2 text-white text-xs outline-none focus:border-red-400 resize-none"
          />
          <div className="flex gap-2">
            <button
              onClick={handleReject}
              disabled={busy}
              className="text-xs px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded font-semibold disabled:opacity-50 transition-colors"
            >
              {busy ? 'Rechazando...' : 'Confirmar Rechazo'}
            </button>
            <button
              onClick={() => { setRejecting(false); setReason(''); setErr('') }}
              className="text-xs px-3 py-1.5 bg-navy-700 text-gray-300 rounded hover:bg-navy-600 transition-colors"
            >
              Cancelar
            </button>
          </div>
        </div>
      ) : (
        <div className="flex gap-2">
          <button
            onClick={handleApprove}
            disabled={busy || isSelf}
            className="flex-1 text-xs px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white rounded font-semibold disabled:opacity-50 transition-colors flex items-center justify-center gap-1"
          >
            <UserCheck size={12} /> Aprobar y Ejecutar
          </button>
          <button
            onClick={() => { setRejecting(true); setErr('') }}
            disabled={busy}
            className="flex-1 text-xs px-3 py-1.5 bg-red-600/80 hover:bg-red-700 text-white rounded font-semibold disabled:opacity-50 transition-colors flex items-center justify-center gap-1"
          >
            <UserX size={12} /> Rechazar
          </button>
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function NeutralizePage() {
  const { isReady } = useAuthGuard()

  const mountedRef = useRef(true)
  useEffect(() => { return () => { mountedRef.current = false } }, [])

  const [specterCmds, setSprecterCmds] = useState<SprecterCommandSummary[]>([])
  const [cmdsMode, setCmdsMode]         = useState<string>('')

  const currentUser = 'analyst@premos.com' // replaced by JWT context in P16.3

  const [pending, setPending]     = useState<NeutralizeAction[]>([])
  const [history, setHistory]     = useState<NeutralizeAction[]>([])
  const [loadingPending, setLP]   = useState(true)
  const [loadingHistory, setLH]   = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult]       = useState<NeutralizeAction | null>(null)
  const [formError, setFormError] = useState('')
  const [confirm, setConfirm]     = useState(false)

  // PANL: live notifications (SSE)
  const [liveNotif, setLiveNotif] = useState<PanlNotification | null>(null)
  const [rollbackBusy, setRollbackBusy] = useState<string | null>(null)

  const [form, setForm] = useState({
    action_type:  'block_ip' as NeutralizeActionType,
    severity:     'high' as NeutralizeSeverity,
    target:       '',
    target_type:  'ip',
    reason:       '',
  })

  const willRequireApproval = requiresApproval(form.action_type, form.severity)

  const loadPending = useCallback(async () => {
    try {
      const res = await getPendingApprovals()
      if (mountedRef.current) setPending(res.actions)
    } catch { /* non-critical */ }
    finally { if (mountedRef.current) setLP(false) }
  }, [])

  const loadHistory = useCallback(async () => {
    try {
      const res = await getNeutralizeHistory(30)
      if (mountedRef.current) setHistory(res.actions)
    } catch { /* non-critical */ }
    finally { if (mountedRef.current) setLH(false) }
  }, [])

  useEffect(() => {
    if (!isReady) return
    loadPending()
    loadHistory()
  }, [loadPending, loadHistory, isReady])

  // PANL: SSE subscription — auto-refresh on state changes
  useEffect(() => {
    if (!isReady) return
    const unsub = subscribeToNotifications(
      (notif) => {
        if (!mountedRef.current) return
        setLiveNotif(notif)
        // Auto-clear the toast after 5 seconds
        setTimeout(() => { if (mountedRef.current) setLiveNotif(null) }, 5000)
        // Refresh data on relevant events
        if ([
          'pending_approval_created',
          'action_approved',
          'action_rejected',
          'action_escalated',
          'action_completed',
          'action_failed',
          'rollback_requested',
        ].includes(notif.event)) {
          loadPending()
          loadHistory()
        }
      },
      () => { /* SSE error — silently ignore, polling still works */ }
    )
    return unsub
  }, [loadPending, loadHistory, isReady])

  async function handleApprove(actionId: string) {
    await approveNeutralizeAction(actionId)
    await loadPending()
    await loadHistory()
  }

  async function handleReject(actionId: string, reason: string) {
    await rejectNeutralizeAction(actionId, reason)
    await loadPending()
    await loadHistory()
  }

  async function handleRollback(actionId: string) {
    setRollbackBusy(actionId)
    try {
      const rollback = await requestRollback(actionId)
      if (mountedRef.current) {
        await loadPending()
        await loadHistory()
        setResult(rollback)
      }
    } catch (e: any) {
      alert(e?.response?.data?.detail || e.message)
    } finally {
      if (mountedRef.current) setRollbackBusy(null)
    }
  }

  async function handleSubmit() {
    if (!confirm) { setConfirm(true); return }
    setSubmitting(true); setFormError(''); setResult(null)
    try {
      const data = await requestNeutralizeAction({
        action_type: form.action_type,
        severity:    form.severity,
        target:      form.target,
        target_type: form.target_type,
        params:      buildParams(),
      })
      if (!mountedRef.current) return
      setResult(data)
      setConfirm(false)
      await loadPending()
      await loadHistory()
      // Load SPECTER command status if action was dispatched
      if (data.status === 'completed' || data.status === 'failed') {
        try {
          const cmds = await getNeutralizeCommands(data.id)
          if (mountedRef.current) {
            setSprecterCmds(cmds.commands)
            setCmdsMode(cmds.dispatch_mode)
          }
        } catch { /* non-critical */ }
      }
    } catch (e: any) {
      if (!mountedRef.current) return
      setFormError(e?.response?.data?.detail || e.message)
      setConfirm(false)
    } finally {
      if (mountedRef.current) setSubmitting(false)
    }
  }

  function buildParams(): Record<string, unknown> {
    const base: Record<string, unknown> = {}
    if (form.action_type === 'isolate_endpoint') base.host = form.target
    if (form.action_type === 'block_ip') { base.ip = form.target; base.direction = 'both' }
    if (form.action_type === 'block_domain') base.domain = form.target
    if (form.action_type === 'kill_process') { base.host = form.target }
    if (form.action_type === 'quarantine_file') { base.host = form.target_type; base.file_path = form.target }
    if (form.action_type === 'remove_persistence') { base.host = form.target; base.persistence_type = 'registry'; base.target = form.reason }
    if (form.action_type === 'disable_account') { base.username = form.target; base.domain = 'LOCAL' }
    return base
  }

  const selectedDef = ACTIONS.find(a => a.value === form.action_type)

  if (!isReady) return <AuthLoader />

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6 overflow-auto">
        <div className="flex items-start justify-between mb-1">
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Zap className="text-cyan-400" size={22} />
            Neutralización de Amenazas
            <span className="text-xs font-normal bg-purple-400/10 border border-purple-400/30 text-purple-400 rounded px-2 py-0.5 ml-1">
              PANL
            </span>
          </h1>
          <div className="flex items-center gap-2">
            {liveNotif ? (
              <div className="flex items-center gap-1.5 text-xs bg-cyan-400/10 border border-cyan-400/30 text-cyan-400 rounded px-2 py-1 animate-pulse">
                <BellRing size={11} />
                <span>{liveNotif.event.replace(/_/g, ' ')}</span>
              </div>
            ) : (
              <div className="flex items-center gap-1 text-xs text-gray-600">
                <Bell size={11} /> SSE activo
              </div>
            )}
          </div>
        </div>
        <p className="text-gray-500 text-xs mb-6">
          PANL: Severidad Adaptativa · Multi-firma CRITICAL · Rollback Forense · Fleet-aware Dispatch · Throttle de Comportamiento
        </p>

        <div className="grid grid-cols-12 gap-6">

          {/* ── Col-left: form ── */}
          <div className="col-span-12 lg:col-span-5 space-y-4">

            {/* Action form */}
            <div className="card">
              <h3 className="text-cyan-400 font-semibold mb-4 flex items-center gap-2">
                <Zap size={16} /> Solicitar Acción
              </h3>

              {/* Action selector */}
              <div className="grid grid-cols-1 gap-2 mb-4">
                {ACTIONS.map(a => (
                  <button key={a.value}
                    onClick={() => { setForm(f => ({ ...f, action_type: a.value })); setConfirm(false) }}
                    className={`flex items-center gap-3 px-3 py-2.5 rounded text-sm transition-colors text-left ${
                      form.action_type === a.value
                        ? 'bg-cyan-400/10 border border-cyan-400/40 text-cyan-400'
                        : 'bg-navy-900 border border-navy-700 text-gray-400 hover:text-white hover:border-navy-600'
                    }`}>
                    <span>{a.icon}</span>
                    <span className="flex-1 font-medium">{a.label}</span>
                    {(a.value === 'isolate_endpoint' || a.value === 'disable_account') && (
                      <span className="text-xs text-red-400 font-mono">SIEMPRE APROBACIÓN</span>
                    )}
                  </button>
                ))}
              </div>

              {/* Severity */}
              <div className="border-t border-navy-700 pt-4 space-y-3">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Severidad</label>
                  <div className="flex gap-2">
                    {SEVERITIES.map(s => (
                      <button key={s}
                        onClick={() => setForm(f => ({ ...f, severity: s }))}
                        className={`flex-1 text-xs py-1.5 rounded border font-semibold uppercase transition-colors ${
                          form.severity === s ? severityColor(s) : 'border-navy-700 text-gray-500 bg-navy-900'
                        }`}>
                        {s}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Target */}
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Target</label>
                  <input
                    value={form.target}
                    onChange={e => setForm(f => ({ ...f, target: e.target.value }))}
                    placeholder={
                      form.action_type === 'block_ip' ? '185.220.101.45' :
                      form.action_type === 'block_domain' ? 'evil-c2.ru' :
                      form.action_type === 'disable_account' ? 'jdoe' :
                      'PREMOS-WS-01'
                    }
                    className="w-full bg-navy-900 border border-navy-700 rounded px-3 py-2 text-white text-sm font-mono outline-none focus:border-cyan-400"
                  />
                </div>

                <div>
                  <label className="block text-xs text-gray-400 mb-1">Justificación</label>
                  <textarea
                    value={form.reason}
                    onChange={e => setForm(f => ({ ...f, reason: e.target.value }))}
                    placeholder="Descripción del incidente que motiva esta acción..."
                    rows={2}
                    className="w-full bg-navy-900 border border-navy-700 rounded px-3 py-2 text-white text-sm outline-none focus:border-cyan-400 resize-none"
                  />
                </div>
              </div>

              {/* HitL indicator */}
              <div className={`mt-3 rounded px-3 py-2 text-xs flex items-center gap-2 ${
                willRequireApproval
                  ? 'bg-yellow-400/10 border border-yellow-400/25 text-yellow-400'
                  : 'bg-green-400/10 border border-green-400/25 text-green-400'
              }`}>
                {willRequireApproval
                  ? <><ShieldAlert size={12} /> Esta acción requiere aprobación de un segundo analista antes de ejecutarse.</>
                  : <><Zap size={12} /> Esta acción se ejecutará inmediatamente (severidad MEDIUM/LOW, no es destructiva).</>
                }
              </div>

              {formError && (
                <p className="text-red-400 text-xs mt-3 bg-red-400/10 rounded px-3 py-2">{formError}</p>
              )}

              <div className="mt-4">
                {confirm ? (
                  <div className="bg-red-400/10 border border-red-400/30 rounded p-3 mb-3">
                    <p className="text-red-400 text-sm font-semibold mb-1 flex items-center gap-2">
                      <AlertTriangle size={14} /> Confirmar Solicitud
                    </p>
                    <p className="text-gray-400 text-xs">
                      ¿Solicitar <strong className="text-white">{selectedDef?.label}</strong> sobre{' '}
                      <strong className="text-white font-mono">{form.target || '(sin especificar)'}</strong>?
                      {willRequireApproval && ' Quedará en cola hasta que un segundo analista apruebe.'}
                    </p>
                    <div className="flex gap-2 mt-3">
                      <button onClick={handleSubmit} disabled={submitting}
                        className="bg-red-600 hover:bg-red-700 text-white text-sm px-4 py-2 rounded font-semibold disabled:opacity-50 transition-colors">
                        {submitting ? 'Enviando...' : 'Confirmar'}
                      </button>
                      <button onClick={() => setConfirm(false)}
                        className="bg-navy-700 text-gray-300 text-sm px-4 py-2 rounded hover:bg-navy-600 transition-colors">
                        Cancelar
                      </button>
                    </div>
                  </div>
                ) : (
                  <button
                    onClick={handleSubmit}
                    disabled={!form.target || submitting}
                    className="btn-danger w-full flex items-center justify-center gap-2 text-sm disabled:opacity-50">
                    <Zap size={14} />
                    {willRequireApproval ? 'Solicitar Aprobación' : 'Ejecutar Acción'}
                  </button>
                )}
              </div>

              {result && (
                <div className={`mt-4 border rounded p-3 space-y-2 ${
                  result.status === 'pending_approval'
                    ? 'bg-yellow-400/10 border-yellow-400/25'
                    : result.status === 'completed'
                    ? 'bg-green-400/10 border-green-400/20'
                    : 'bg-red-400/10 border-red-400/20'
                }`}>
                  <div className="flex items-center gap-2 flex-wrap">
                    <StatusBadge status={result.status} />
                    {result.result?.dispatch_mode != null && (
                      <span className={`text-xs font-semibold border rounded px-2 py-0.5 ${
                        dispatchModeClasses(result.result.dispatch_mode as string)
                      }`}>
                        {result.result.dispatch_mode === 'specter'
                          ? <><Cpu size={10} className="inline mr-1" /></>
                          : result.result.dispatch_mode === 'broadcast'
                          ? <><Radio size={10} className="inline mr-1" /></>
                          : <><FlaskConical size={10} className="inline mr-1" /></>
                        }
                        {dispatchModeLabel(result.result.dispatch_mode as string)}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-gray-400">
                    ID: <span className="font-mono text-gray-200">{result.id}</span>
                  </p>
                  {result.status === 'pending_approval' && (
                    <p className="text-yellow-400 text-xs">
                      Expira en {minutesRemaining(result.expires_at)} min — pendiente en cola de aprobación.
                    </p>
                  )}
                  {specterCmds.length > 0 && (
                    <div className="border-t border-gray-700 pt-2">
                      <p className="text-xs text-gray-500 mb-1.5">Comandos SPECTER emitidos:</p>
                      {specterCmds.map(c => (
                        <div key={c.id} className="flex items-center justify-between text-xs gap-2 py-0.5">
                          <span className="font-mono text-gray-400">{c.id.slice(0, 12)}…</span>
                          <span className="text-gray-500">{c.command_type}</span>
                          <span className={commandStatusColor(c.status)}>{c.status}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* ── Col-right: pending + history ── */}
          <div className="col-span-12 lg:col-span-7 space-y-4">

            {/* Pending approvals queue */}
            <div className="card">
              <h3 className="text-yellow-400 font-semibold mb-4 flex items-center gap-2">
                <ShieldAlert size={16} />
                Cola de Aprobación
                {pending.length > 0 && (
                  <span className="ml-auto bg-yellow-400 text-black text-xs font-bold px-2 py-0.5 rounded-full">
                    {pending.length}
                  </span>
                )}
              </h3>
              {loadingPending ? (
                <p className="text-gray-500 text-sm">Cargando cola...</p>
              ) : pending.length === 0 ? (
                <p className="text-gray-600 text-sm flex items-center gap-2">
                  <CheckCircle size={14} className="text-green-500" /> Sin acciones pendientes de aprobación.
                </p>
              ) : (
                <div className="space-y-3">
                  {pending.map(a => (
                    <PendingCard
                      key={a.id}
                      action={a}
                      currentUser={currentUser}
                      onApprove={handleApprove}
                      onReject={handleReject}
                    />
                  ))}
                </div>
              )}
            </div>

            {/* History */}
            <div className="card">
              <h3 className="text-cyan-400 font-semibold mb-4 flex items-center gap-2">
                <Clock size={16} /> Historial de Acciones
              </h3>
              {loadingHistory ? (
                <p className="text-gray-400 text-sm">Cargando historial...</p>
              ) : history.length === 0 ? (
                <p className="text-gray-500 text-sm">Sin acciones registradas.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="table-asc">
                    <thead>
                      <tr>
                        <th>Acción</th>
                        <th>Target</th>
                        <th>Severidad</th>
                        <th>Estado</th>
                        <th>Aprobado por</th>
                        <th>Fecha</th>
                        <th>PANL</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((h, i) => (
                        <tr key={h.id ?? i}>
                          <td className="font-mono text-xs text-cyan-400">
                            {h.is_rollback && <RotateCcw size={10} className="inline mr-1 text-purple-400" />}
                            {ACTIONS.find(a => a.value === h.action_type)?.icon}{' '}
                            {ACTIONS.find(a => a.value === h.action_type)?.label ?? h.action_type}
                          </td>
                          <td className="text-gray-200 text-xs font-mono">{h.target}</td>
                          <td>
                            <span className={`text-xs font-bold uppercase ${statusColor(h.severity)}`}>
                              {h.severity}
                            </span>
                            {h.severity_adapted && (
                              <span className="ml-1 text-purple-400" title={`Elevado de ${h.original_severity}`}>↑</span>
                            )}
                          </td>
                          <td><StatusBadge status={h.status} /></td>
                          <td className="text-gray-400 text-xs">{h.approved_by ?? h.initiated_by ?? '—'}</td>
                          <td className="text-gray-600 text-xs">{formatTs(h.created_at)}</td>
                          <td>
                            {h.rollback_available && (
                              <button
                                onClick={() => handleRollback(h.id)}
                                disabled={rollbackBusy === h.id}
                                className="text-xs px-2 py-0.5 rounded border border-purple-400/40 text-purple-400 hover:bg-purple-400/10 transition-colors disabled:opacity-50 flex items-center gap-1"
                                title="Solicitar rollback forense"
                              >
                                <RotateCcw size={9} />
                                {rollbackBusy === h.id ? '...' : 'Rollback'}
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

          </div>
        </div>
      </main>
    </div>
  )
}
