'use client'
import { useState, useEffect, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import {
  listSOARTriggers, createSOARTrigger, deleteSOARTrigger, toggleSOARTrigger, testSOARTrigger,
  listScheduledReports, createScheduledReport, deleteScheduledReport, toggleScheduledReport, deliverScheduledReport,
  SOARTrigger, ScheduledReport,
} from '@/lib/api'
import {
  Zap, Plus, Trash2, ToggleLeft, ToggleRight, Play,
  Clock, Mail, CheckCircle, XCircle, AlertTriangle, RefreshCw,
} from 'lucide-react'

type Tab = 'triggers' | 'reports'

const CONDITION_TYPES = [
  'pcdi_score', 'finding_severity', 'hunt_priority', 'panl_status', 'identity_group', 'iam_event',
  'incident_status_change', 'incident_sla_breach', 'incident_severity',
]
const OPERATORS       = ['gte', 'lte', 'eq', 'contains']
const PLAYBOOKS       = [
  { id: 'PB-001', label: 'PB-001 — Monitoreo Verde' },
  { id: 'PB-002', label: 'PB-002 — Respuesta Amarilla' },
  { id: 'PB-003', label: 'PB-003 — Respuesta Roja Crítica' },
  { id: 'PB-004', label: 'PB-004 — Ataque Dirigido' },
  { id: 'PB-005', label: 'PB-005 — PIDS Identity Response' },
]
const FREQUENCIES = ['daily', 'weekly']
const FORMATS     = ['json', 'pdf']

function fmtTs(iso: string | null | undefined) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'short' })
}

function Badge({ children, cls }: { children: React.ReactNode; cls: string }) {
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${cls}`}>{children}</span>
}

// ── Trigger create form ───────────────────────────────────────────────────────

function CreateTriggerForm({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState({
    playbook_id: 'PB-002',
    playbook_name: 'Respuesta Amarilla — Actividad Sospechosa',
    condition_type: 'pcdi_score',
    condition_operator: 'gte',
    condition_value: '80',
    hunt_id_filter: '',
  })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  async function submit() {
    setSaving(true); setErr(null)
    try {
      await createSOARTrigger({
        ...form,
        hunt_id_filter: form.hunt_id_filter.trim() || null,
      })
      setOpen(false); onCreated()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setErr(msg || 'Error al crear trigger')
    } finally {
      setSaving(false)
    }
  }

  if (!open) return (
    <button onClick={() => setOpen(true)}
      className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg text-sm font-semibold transition-colors">
      <Plus className="w-4 h-4" /> Nuevo Trigger
    </button>
  )

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-5 space-y-4">
      <h3 className="text-sm font-semibold text-cyan-300">Crear Trigger SOAR</h3>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Playbook</label>
          <select className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm"
            value={form.playbook_id}
            onChange={e => {
              const pb = PLAYBOOKS.find(p => p.id === e.target.value)
              setForm(f => ({ ...f, playbook_id: e.target.value, playbook_name: pb?.label.split('— ')[1] ?? '' }))
            }}>
            {PLAYBOOKS.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Tipo de Condición</label>
          <select className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm"
            value={form.condition_type}
            onChange={e => setForm(f => ({ ...f, condition_type: e.target.value }))}>
            {CONDITION_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Operador</label>
          <select className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm"
            value={form.condition_operator}
            onChange={e => setForm(f => ({ ...f, condition_operator: e.target.value }))}>
            {OPERATORS.map(o => <option key={o} value={o}>{o}</option>)}
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Valor</label>
          <input className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm"
            placeholder="80 / critical / critical,high"
            value={form.condition_value}
            onChange={e => setForm(f => ({ ...f, condition_value: e.target.value }))} />
        </div>
        <div className="col-span-2">
          <label className="text-xs text-gray-400 mb-1 block">Hunt UUID (opcional — vacío = global)</label>
          <input className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm font-mono"
            placeholder="Dejar vacío para aplicar a todos los hunts"
            value={form.hunt_id_filter}
            onChange={e => setForm(f => ({ ...f, hunt_id_filter: e.target.value }))} />
        </div>
      </div>

      {err && <p className="text-xs text-red-400">{err}</p>}

      <div className="flex gap-2">
        <button onClick={submit} disabled={saving}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded text-sm font-semibold transition-colors">
          {saving ? 'Guardando…' : 'Crear'}
        </button>
        <button onClick={() => { setOpen(false); setErr(null) }}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm transition-colors">
          Cancelar
        </button>
      </div>
    </div>
  )
}

// ── Trigger row ───────────────────────────────────────────────────────────────

function TriggerRow({ t, onRefresh }: { t: SOARTrigger; onRefresh: () => void }) {
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<string | null>(null)

  async function handleToggle() {
    await toggleSOARTrigger(t.id, !t.enabled)
    onRefresh()
  }
  async function handleDelete() {
    if (!confirm(`Eliminar trigger ${t.condition_type} ${t.condition_operator} ${t.condition_value}?`)) return
    await deleteSOARTrigger(t.id)
    onRefresh()
  }
  async function handleTest() {
    setTesting(true); setTestResult(null)
    const ctx: Record<string, unknown> = {}
    if (t.condition_type === 'pcdi_score')      ctx.pcdi_score = 85
    if (t.condition_type === 'finding_severity') ctx.severity = 'critical'
    if (t.condition_type === 'hunt_priority')    ctx.hunt_priority = 'critical'
    if (t.condition_type === 'panl_status')      ctx.panl_status = t.condition_value
    try {
      const r = await testSOARTrigger(t.id, ctx)
      setTestResult(r.matched ? '✓ Coincide — dispararía' : '✗ No coincide')
    } catch { setTestResult('Error en test') }
    finally { setTesting(false) }
  }

  return (
    <div className="bg-gray-800/60 border border-gray-700 rounded-lg p-4 space-y-2">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono bg-indigo-900/40 text-indigo-300 px-2 py-0.5 rounded">{t.playbook_id}</span>
            <span className="text-xs text-gray-400">{t.condition_type}</span>
            <span className="text-xs text-cyan-400 font-semibold">{t.condition_operator}</span>
            <span className="text-xs font-mono text-white">{t.condition_value}</span>
            {t.hunt_id_filter && <span className="text-xs text-yellow-400">hunt:{t.hunt_id_filter.slice(0,8)}…</span>}
          </div>
          <p className="text-xs text-gray-500 mt-1">{t.playbook_name}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Badge cls={t.enabled ? 'bg-green-900/40 text-green-300' : 'bg-gray-700 text-gray-400'}>
            {t.enabled ? 'Activo' : 'Inactivo'}
          </Badge>
        </div>
      </div>

      <div className="flex items-center gap-3 text-xs text-gray-500">
        <span>Disparos: <span className="text-white">{t.trigger_count}</span></span>
        <span>Último: <span className="text-white">{fmtTs(t.last_triggered_at)}</span></span>
        <span>Creado: {fmtTs(t.created_at)}</span>
      </div>

      {testResult && (
        <p className={`text-xs font-semibold ${testResult.startsWith('✓') ? 'text-green-400' : 'text-red-400'}`}>
          {testResult}
        </p>
      )}

      <div className="flex items-center gap-2 pt-1">
        <button onClick={handleTest} disabled={testing}
          className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-xs transition-colors">
          <Play className="w-3 h-3" /> {testing ? 'Probando…' : 'Test'}
        </button>
        <button onClick={handleToggle}
          className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-xs transition-colors">
          {t.enabled ? <ToggleRight className="w-3 h-3 text-green-400" /> : <ToggleLeft className="w-3 h-3 text-gray-400" />}
          {t.enabled ? 'Desactivar' : 'Activar'}
        </button>
        <button onClick={handleDelete}
          className="flex items-center gap-1 px-3 py-1.5 bg-red-900/30 hover:bg-red-900/60 text-red-400 rounded text-xs transition-colors">
          <Trash2 className="w-3 h-3" /> Eliminar
        </button>
      </div>
    </div>
  )
}

// ── Scheduled reports form ────────────────────────────────────────────────────

function CreateReportForm({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState({
    hunt_id: '', hunt_name: '', recipient_email: '', frequency: 'daily', format: 'json',
  })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  async function submit() {
    setSaving(true); setErr(null)
    try {
      await createScheduledReport({ ...form, hunt_name: form.hunt_name || undefined })
      setOpen(false); onCreated()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setErr(msg || 'Error al crear informe')
    } finally { setSaving(false) }
  }

  if (!open) return (
    <button onClick={() => setOpen(true)}
      className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg text-sm font-semibold transition-colors">
      <Plus className="w-4 h-4" /> Nuevo Informe
    </button>
  )

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-5 space-y-4">
      <h3 className="text-sm font-semibold text-cyan-300">Crear Informe Programado</h3>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Hunt UUID</label>
          <input className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm font-mono"
            value={form.hunt_id} onChange={e => setForm(f => ({ ...f, hunt_id: e.target.value }))} />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Nombre (opcional)</label>
          <input className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm"
            value={form.hunt_name} onChange={e => setForm(f => ({ ...f, hunt_name: e.target.value }))} />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Destinatario (email)</label>
          <input type="email" className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm"
            value={form.recipient_email} onChange={e => setForm(f => ({ ...f, recipient_email: e.target.value }))} />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Frecuencia</label>
          <select className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm"
            value={form.frequency} onChange={e => setForm(f => ({ ...f, frequency: e.target.value }))}>
            {FREQUENCIES.map(fr => <option key={fr} value={fr}>{fr}</option>)}
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Formato</label>
          <select className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm"
            value={form.format} onChange={e => setForm(f => ({ ...f, format: e.target.value }))}>
            {FORMATS.map(fr => <option key={fr} value={fr}>{fr}</option>)}
          </select>
        </div>
      </div>
      {err && <p className="text-xs text-red-400">{err}</p>}
      <div className="flex gap-2">
        <button onClick={submit} disabled={saving}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded text-sm font-semibold">
          {saving ? 'Guardando…' : 'Crear'}
        </button>
        <button onClick={() => { setOpen(false); setErr(null) }}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm">Cancelar</button>
      </div>
    </div>
  )
}

// ── Report row ────────────────────────────────────────────────────────────────

function ReportRow({ r, onRefresh }: { r: ScheduledReport; onRefresh: () => void }) {
  const [delivering, setDelivering] = useState(false)

  async function handleToggle() {
    await toggleScheduledReport(r.id, !r.enabled); onRefresh()
  }
  async function handleDelete() {
    if (!confirm(`Eliminar informe para ${r.recipient_email}?`)) return
    await deleteScheduledReport(r.id); onRefresh()
  }
  async function handleDeliver() {
    setDelivering(true)
    try { await deliverScheduledReport(r.id); onRefresh() }
    catch { /* swallow — delivery logs to server */ }
    finally { setDelivering(false) }
  }

  return (
    <div className="bg-gray-800/60 border border-gray-700 rounded-lg p-4 space-y-2">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <Mail className="w-4 h-4 text-cyan-400 shrink-0" />
            <span className="text-sm text-white">{r.recipient_email}</span>
            <Badge cls="bg-indigo-900/40 text-indigo-300">{r.frequency}</Badge>
            <Badge cls="bg-gray-700 text-gray-300">{r.format.toUpperCase()}</Badge>
            <Badge cls={r.enabled ? 'bg-green-900/40 text-green-300' : 'bg-gray-700 text-gray-400'}>
              {r.enabled ? 'Activo' : 'Inactivo'}
            </Badge>
          </div>
          <p className="text-xs text-gray-500 mt-1 font-mono">Hunt: {r.hunt_id}</p>
          {r.hunt_name && <p className="text-xs text-gray-400">{r.hunt_name}</p>}
        </div>
      </div>

      <div className="flex items-center gap-3 text-xs text-gray-500">
        <span>Enviados: <span className="text-white">{r.send_count}</span></span>
        <span>Último: <span className="text-white">{fmtTs(r.last_sent_at)}</span></span>
        {r.last_error && (
          <span className="text-red-400 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> {r.last_error.slice(0, 60)}
          </span>
        )}
      </div>

      <div className="flex items-center gap-2 pt-1">
        <button onClick={handleDeliver} disabled={delivering}
          className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-xs transition-colors">
          <RefreshCw className={`w-3 h-3 ${delivering ? 'animate-spin' : ''}`} />
          {delivering ? 'Enviando…' : 'Enviar ahora'}
        </button>
        <button onClick={handleToggle}
          className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-xs transition-colors">
          {r.enabled ? <ToggleRight className="w-3 h-3 text-green-400" /> : <ToggleLeft className="w-3 h-3 text-gray-400" />}
          {r.enabled ? 'Desactivar' : 'Activar'}
        </button>
        <button onClick={handleDelete}
          className="flex items-center gap-1 px-3 py-1.5 bg-red-900/30 hover:bg-red-900/60 text-red-400 rounded text-xs transition-colors">
          <Trash2 className="w-3 h-3" /> Eliminar
        </button>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function SOARPage() {
  useAuthGuard()

  const [tab, setTab]             = useState<Tab>('triggers')
  const [triggers, setTriggers]   = useState<SOARTrigger[]>([])
  const [reports, setReports]     = useState<ScheduledReport[]>([])
  const [loading, setLoading]     = useState(false)
  const [error, setError]         = useState<string | null>(null)

  const loadTriggers = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const r = await listSOARTriggers()
      setTriggers(r.triggers)
    } catch { setError('Error al cargar triggers') }
    finally { setLoading(false) }
  }, [])

  const loadReports = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const r = await listScheduledReports()
      setReports(r.reports)
    } catch { setError('Error al cargar informes') }
    finally { setLoading(false) }
  }, [])

  useEffect(() => {
    if (tab === 'triggers') loadTriggers()
    else loadReports()
  }, [tab, loadTriggers, loadReports])

  const enabledTriggers  = triggers.filter(t => t.enabled).length
  const enabledReports   = reports.filter(r => r.enabled).length
  const totalFired       = triggers.reduce((a, t) => a + t.trigger_count, 0)

  return (
    <div className="flex min-h-screen bg-gray-950 text-white">
      <Sidebar />
      <main className="flex-1 p-8 space-y-6 overflow-y-auto">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Zap className="w-6 h-6 text-cyan-400" /> SOAR Automation
            </h1>
            <p className="text-sm text-gray-400 mt-1">
              Triggers automáticos de playbooks e informes programados
            </p>
          </div>
        </div>

        {/* KPI strip */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'Triggers activos', value: enabledTriggers, icon: Zap, color: 'text-cyan-400' },
            { label: 'Total triggers',   value: triggers.length, icon: CheckCircle, color: 'text-green-400' },
            { label: 'Disparos totales', value: totalFired,      icon: Play,        color: 'text-indigo-400' },
            { label: 'Informes activos', value: enabledReports,  icon: Mail,        color: 'text-yellow-400' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="bg-gray-800/50 border border-gray-700 rounded-xl p-4">
              <Icon className={`w-5 h-5 ${color} mb-2`} />
              <p className="text-2xl font-bold">{value}</p>
              <p className="text-xs text-gray-400 mt-1">{label}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-2 border-b border-gray-700 pb-0">
          {(['triggers', 'reports'] as Tab[]).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-4 py-2 text-sm font-medium rounded-t transition-colors ${
                tab === t ? 'bg-gray-800 text-white border-t border-l border-r border-gray-700 -mb-px' : 'text-gray-400 hover:text-white'
              }`}>
              {t === 'triggers' ? `Triggers (${triggers.length})` : `Informes (${reports.length})`}
            </button>
          ))}
        </div>

        {error && (
          <div className="flex items-center gap-2 p-3 bg-red-900/20 border border-red-800 rounded-lg text-red-300 text-sm">
            <XCircle className="w-4 h-4 shrink-0" /> {error}
          </div>
        )}

        {/* Triggers tab */}
        {tab === 'triggers' && (
          <div className="space-y-4">
            <CreateTriggerForm onCreated={loadTriggers} />
            {loading ? (
              <p className="text-sm text-gray-400">Cargando…</p>
            ) : triggers.length === 0 ? (
              <div className="text-center py-16 text-gray-500">
                <Zap className="w-10 h-10 mx-auto mb-3 opacity-30" />
                <p>No hay triggers configurados.</p>
                <p className="text-xs mt-1">Crea uno para automatizar la respuesta ante incidentes.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {triggers.map(t => <TriggerRow key={t.id} t={t} onRefresh={loadTriggers} />)}
              </div>
            )}
          </div>
        )}

        {/* Reports tab */}
        {tab === 'reports' && (
          <div className="space-y-4">
            <CreateReportForm onCreated={loadReports} />
            {loading ? (
              <p className="text-sm text-gray-400">Cargando…</p>
            ) : reports.length === 0 ? (
              <div className="text-center py-16 text-gray-500">
                <Clock className="w-10 h-10 mx-auto mb-3 opacity-30" />
                <p>No hay informes programados.</p>
                <p className="text-xs mt-1">Crea uno para recibir resúmenes periódicos de un hunt.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {reports.map(r => <ReportRow key={r.id} r={r} onRefresh={loadReports} />)}
              </div>
            )}
          </div>
        )}

      </main>
    </div>
  )
}
