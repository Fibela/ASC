'use client'

import { useEffect, useState, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'
import {
  listWebhooks, createWebhook, updateWebhook, deleteWebhook, testWebhook,
  WebhookResponse, WebhookCreated, WebhookTestResult, VALID_WEBHOOK_EVENTS,
} from '@/lib/api'
import {
  Webhook, Plus, Trash2, Play, ToggleLeft, ToggleRight, CheckCircle2,
  XCircle, AlertTriangle, RefreshCw, Copy, Clock, Activity, ShieldAlert,
  ExternalLink, ChevronDown, ChevronUp, Pencil,
} from 'lucide-react'

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtTs(iso: string | null | undefined) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'short' })
}

function fmtLatency(ms: number) {
  return ms < 1000 ? `${ms.toFixed(0)} ms` : `${(ms / 1000).toFixed(2)} s`
}

function StatusBadge({ active }: { active: boolean }) {
  return active
    ? <span className="inline-flex items-center gap-1 text-xs text-green-400 bg-green-400/10 border border-green-700/50 px-2 py-0.5 rounded"><CheckCircle2 size={10} /> Activo</span>
    : <span className="inline-flex items-center gap-1 text-xs text-gray-500 bg-gray-700/50 border border-gray-600/50 px-2 py-0.5 rounded"><XCircle size={10} /> Inactivo</span>
}

function FailureBadge({ count }: { count: number }) {
  if (count === 0) return <span className="text-xs text-green-400">0</span>
  if (count < 3) return <span className="text-xs text-yellow-400">{count}</span>
  return (
    <span className="inline-flex items-center gap-1 text-xs text-red-400 font-semibold">
      <AlertTriangle size={10} /> {count}
    </span>
  )
}

function Toast({ msg, ok, onClose }: { msg: string; ok: boolean; onClose: () => void }) {
  return (
    <div className={`flex items-center gap-2 rounded p-3 text-xs border mb-4 ${
      ok ? 'bg-green-900/20 border-green-700/50 text-green-400'
         : 'bg-red-900/20 border-red-700/50 text-red-400'
    }`}>
      {ok ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
      <span className="flex-1">{msg}</span>
      <button onClick={onClose} className="ml-2 hover:opacity-70"><XCircle size={12} /></button>
    </div>
  )
}

// ── Secret reveal panel ───────────────────────────────────────────────────────

function SecretReveal({ secret, signingNote, onDismiss }: {
  secret: string
  signingNote: string
  onDismiss: () => void
}) {
  const [copied, setCopied] = useState(false)

  function copy() {
    navigator.clipboard.writeText(secret)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="border border-cyan-700/60 bg-cyan-900/10 rounded-lg p-4 mb-4">
      <div className="flex items-center gap-2 mb-2">
        <ShieldAlert size={16} className="text-cyan-400" />
        <span className="text-cyan-400 font-semibold text-sm">Secreto de firma — guárdalo ahora</span>
      </div>
      <p className="text-xs text-gray-400 mb-3">
        Este secreto se muestra <strong className="text-white">una sola vez</strong>.
        Úsalo para verificar la firma <code className="text-cyan-300">X-ASC-Signature</code> en cada entrega.
      </p>
      <div className="flex items-center gap-2 bg-navy-800 border border-navy-600 rounded p-2 font-mono text-xs text-gray-200 mb-2">
        <span className="flex-1 break-all">{secret}</span>
        <button
          onClick={copy}
          className="shrink-0 text-cyan-400 hover:text-cyan-300 transition-colors"
          title="Copiar secreto"
        >
          {copied ? <CheckCircle2 size={14} /> : <Copy size={14} />}
        </button>
      </div>
      <p className="text-xs text-gray-500 italic mb-3">{signingNote}</p>
      <button
        onClick={onDismiss}
        className="text-xs bg-cyan-500/20 text-cyan-300 border border-cyan-700/50 hover:bg-cyan-500/30 px-3 py-1 rounded transition-colors"
      >
        Entendido, guardé el secreto
      </button>
    </div>
  )
}

// ── Test result panel ─────────────────────────────────────────────────────────

function TestResultPanel({ result, onClose }: { result: WebhookTestResult; onClose: () => void }) {
  return (
    <div className={`rounded border p-3 text-xs mb-3 ${
      result.success
        ? 'bg-green-900/20 border-green-700/50'
        : 'bg-red-900/20 border-red-700/50'
    }`}>
      <div className="flex items-center justify-between mb-1">
        <span className={`font-semibold ${result.success ? 'text-green-400' : 'text-red-400'}`}>
          {result.success ? '✓ Entrega exitosa' : '✗ Entrega fallida'}
        </span>
        <button onClick={onClose} className="text-gray-500 hover:text-gray-300"><XCircle size={12} /></button>
      </div>
      <div className="flex gap-4 text-gray-400">
        {result.status_code && <span>HTTP {result.status_code}</span>}
        <span>Latencia: {fmtLatency(result.latency_ms)}</span>
        {result.error && <span className="text-red-400">Error: {result.error}</span>}
      </div>
    </div>
  )
}

// ── Create / Edit modal ───────────────────────────────────────────────────────

function WebhookFormModal({
  initial,
  onSave,
  onClose,
}: {
  initial?: Partial<WebhookResponse>
  onSave: (payload: { url: string; events: string[]; description: string | null }) => Promise<void>
  onClose: () => void
}) {
  const [url, setUrl]           = useState(initial?.url ?? '')
  const [events, setEvents]     = useState<string[]>(initial?.events ?? [])
  const [desc, setDesc]         = useState(initial?.description ?? '')
  const [saving, setSaving]     = useState(false)
  const [error, setError]       = useState<string | null>(null)

  function toggleEvent(ev: string) {
    setEvents(prev => prev.includes(ev) ? prev.filter(e => e !== ev) : [...prev, ev])
  }

  async function submit() {
    setError(null)
    if (!url.trim()) { setError('La URL es requerida'); return }
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      setError('La URL debe empezar con http:// o https://'); return
    }
    if (events.length === 0) { setError('Selecciona al menos un evento'); return }
    setSaving(true)
    try {
      await onSave({ url: url.trim(), events, description: desc.trim() || null })
      onClose()
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error guardando webhook'
      const detail = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(detail ?? msg)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-navy-900 border border-navy-600 rounded-xl shadow-2xl w-full max-w-lg mx-4 p-6">
        <h2 className="text-white font-semibold text-base mb-4">
          {initial?.id ? 'Editar Webhook' : 'Nuevo Webhook'}
        </h2>

        {error && (
          <div className="bg-red-900/20 border border-red-700/50 text-red-400 text-xs rounded p-2 mb-3">
            {error}
          </div>
        )}

        {/* URL */}
        <label className="block text-xs text-gray-400 mb-1">URL de destino *</label>
        <input
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="https://mi-servidor.com/webhook"
          className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500 mb-3"
        />

        {/* Description */}
        <label className="block text-xs text-gray-400 mb-1">Descripción (opcional)</label>
        <input
          value={desc}
          onChange={e => setDesc(e.target.value)}
          placeholder="ej. Notificaciones de incidentes al SIEM"
          className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500 mb-3"
        />

        {/* Events */}
        <label className="block text-xs text-gray-400 mb-2">Eventos a suscribir *</label>
        <div className="grid grid-cols-2 gap-1.5 mb-4">
          {VALID_WEBHOOK_EVENTS.map(ev => (
            <label
              key={ev}
              className={`flex items-center gap-2 px-2.5 py-1.5 rounded border cursor-pointer text-xs transition-colors ${
                events.includes(ev)
                  ? 'bg-cyan-500/15 border-cyan-600/60 text-cyan-300'
                  : 'border-navy-600 text-gray-400 hover:border-gray-500'
              }`}
            >
              <input
                type="checkbox"
                checked={events.includes(ev)}
                onChange={() => toggleEvent(ev)}
                className="accent-cyan-400"
              />
              {ev}
            </label>
          ))}
        </div>

        <div className="flex gap-2 justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-sm text-gray-400 hover:text-white transition-colors"
          >
            Cancelar
          </button>
          <button
            onClick={submit}
            disabled={saving}
            className="px-4 py-1.5 text-sm bg-cyan-500 text-navy-900 font-semibold rounded hover:bg-cyan-400 disabled:opacity-50 transition-colors"
          >
            {saving ? 'Guardando…' : initial?.id ? 'Guardar cambios' : 'Crear webhook'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Webhook row ───────────────────────────────────────────────────────────────

function WebhookRow({
  wh,
  onToggle,
  onTest,
  onEdit,
  onDelete,
}: {
  wh: WebhookResponse
  onToggle: () => void
  onTest: () => void
  onEdit: () => void
  onDelete: () => void
}) {
  const [expanded, setExpanded]     = useState(false)
  const [testing, setTesting]       = useState(false)
  const [testResult, setTestResult] = useState<WebhookTestResult | null>(null)
  const [toggling, setToggling]     = useState(false)

  async function handleTest() {
    setTesting(true)
    setTestResult(null)
    try {
      const r = await testWebhook(wh.id)
      setTestResult(r)
      onTest()
    } finally {
      setTesting(false)
    }
  }

  async function handleToggle() {
    setToggling(true)
    try { await onToggle() } finally { setToggling(false) }
  }

  return (
    <div className="border border-navy-700 rounded-lg bg-navy-800/40 mb-2 overflow-hidden">
      {/* Main row */}
      <div className="flex items-center gap-3 px-4 py-3">
        {/* Toggle */}
        <button
          onClick={handleToggle}
          disabled={toggling}
          className="shrink-0 text-gray-400 hover:text-cyan-400 disabled:opacity-40 transition-colors"
          title={wh.is_active ? 'Desactivar' : 'Activar'}
        >
          {wh.is_active ? <ToggleRight size={20} className="text-cyan-400" /> : <ToggleLeft size={20} />}
        </button>

        {/* URL + events */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <a
              href={wh.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-white hover:text-cyan-300 truncate font-mono"
            >
              {wh.url}
            </a>
            <ExternalLink size={11} className="text-gray-600 shrink-0" />
          </div>
          <div className="flex flex-wrap gap-1">
            {wh.events.map(ev => (
              <span key={ev} className="text-xs text-gray-500 bg-navy-700/60 border border-navy-600/60 px-1.5 py-0.5 rounded">
                {ev}
              </span>
            ))}
          </div>
        </div>

        {/* Status */}
        <div className="shrink-0 hidden sm:block">
          <StatusBadge active={wh.is_active} />
        </div>

        {/* Failures */}
        <div className="shrink-0 w-12 text-center hidden sm:block">
          <FailureBadge count={wh.failure_count} />
        </div>

        {/* Last triggered */}
        <div className="shrink-0 text-xs text-gray-500 hidden md:block w-36 text-right">
          <Clock size={10} className="inline mr-1" />
          {fmtTs(wh.last_triggered_at)}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={handleTest}
            disabled={testing}
            className="p-1.5 text-gray-500 hover:text-cyan-400 disabled:opacity-40 transition-colors"
            title="Enviar entrega de prueba"
          >
            {testing ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />}
          </button>
          <button
            onClick={onEdit}
            className="p-1.5 text-gray-500 hover:text-yellow-400 transition-colors"
            title="Editar"
          >
            <Pencil size={14} />
          </button>
          <button
            onClick={onDelete}
            className="p-1.5 text-gray-500 hover:text-red-400 transition-colors"
            title="Eliminar"
          >
            <Trash2 size={14} />
          </button>
          <button
            onClick={() => setExpanded(e => !e)}
            className="p-1.5 text-gray-600 hover:text-gray-300 transition-colors"
          >
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="border-t border-navy-700 px-4 py-3 bg-navy-900/40">
          {testResult && (
            <TestResultPanel result={testResult} onClose={() => setTestResult(null)} />
          )}
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs text-gray-400">
            <span><span className="text-gray-600">ID:</span> <span className="font-mono text-gray-500">{wh.id}</span></span>
            <span><span className="text-gray-600">Usuario:</span> {wh.user_id}</span>
            <span><span className="text-gray-600">Creado:</span> {fmtTs(wh.created_at)}</span>
            <span><span className="text-gray-600">Último disparo:</span> {fmtTs(wh.last_triggered_at)}</span>
            <span><span className="text-gray-600">Fallos acumulados:</span> <FailureBadge count={wh.failure_count} /></span>
            <span><span className="text-gray-600">Estado activo:</span> <StatusBadge active={wh.is_active} /></span>
            {wh.description && (
              <span className="col-span-2"><span className="text-gray-600">Descripción:</span> {wh.description}</span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function WebhooksPage() {
  const { isReady } = useAuthGuard()

  const [webhooks, setWebhooks]     = useState<WebhookResponse[]>([])
  const [loading, setLoading]       = useState(true)
  const [error, setError]           = useState<string | null>(null)
  const [toast, setToast]           = useState<{ msg: string; ok: boolean } | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [editTarget, setEditTarget] = useState<WebhookResponse | null>(null)
  const [newSecret, setNewSecret]   = useState<{ secret: string; note: string } | null>(null)
  const [delConfirm, setDelConfirm] = useState<string | null>(null)

  const showToast = (msg: string, ok: boolean) => {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 4000)
  }

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try { setWebhooks(await listWebhooks()) }
    catch (e: unknown) { setError(e instanceof Error ? e.message : 'Error cargando webhooks') }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { if (!isReady) return; load() }, [load, isReady])

  async function handleCreate(payload: { url: string; events: string[]; description: string | null }) {
    const created: WebhookCreated = await createWebhook(payload)
    setNewSecret({ secret: created.secret, note: created.signing_note })
    await load()
    showToast('Webhook creado', true)
  }

  async function handleEdit(wh: WebhookResponse, payload: { url: string; events: string[]; description: string | null }) {
    await updateWebhook(wh.id, payload)
    await load()
    showToast('Webhook actualizado', true)
  }

  async function handleToggle(wh: WebhookResponse) {
    try {
      await updateWebhook(wh.id, { is_active: !wh.is_active })
      await load()
      showToast(`Webhook ${!wh.is_active ? 'activado' : 'desactivado'}`, true)
    } catch {
      showToast('Error cambiando estado', false)
    }
  }

  async function handleDelete(id: string) {
    try {
      await deleteWebhook(id)
      setDelConfirm(null)
      await load()
      showToast('Webhook eliminado', true)
    } catch {
      showToast('Error eliminando webhook', false)
    }
  }

  // Stats
  const total   = webhooks.length
  const active  = webhooks.filter(w => w.is_active).length
  const failed  = webhooks.filter(w => w.failure_count > 0).length
  const healthy = active - failed < 0 ? 0 : active - failed

  if (!isReady) return <AuthLoader />

  return (
    <div className="flex min-h-screen bg-navy-950 text-gray-100">
      <Sidebar />
      <main className="flex-1 p-6 overflow-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Webhook size={22} className="text-cyan-400" />
            <div>
              <h1 className="text-xl font-bold text-white">Webhooks</h1>
              <p className="text-xs text-gray-500">Entrega de eventos en tiempo real a tus endpoints</p>
            </div>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 bg-cyan-500 text-navy-900 font-semibold text-sm px-4 py-2 rounded-lg hover:bg-cyan-400 transition-colors"
          >
            <Plus size={16} /> Nuevo webhook
          </button>
        </div>

        {/* KPI strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          {[
            { label: 'Total', value: total,   icon: Webhook,       color: 'text-gray-400' },
            { label: 'Activos', value: active, icon: Activity,     color: 'text-green-400' },
            { label: 'Con fallos', value: failed, icon: AlertTriangle, color: failed > 0 ? 'text-red-400' : 'text-gray-500' },
            { label: 'Saludables', value: healthy, icon: CheckCircle2, color: 'text-cyan-400' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="bg-navy-800 border border-navy-700 rounded-lg p-4 flex items-center gap-3">
              <Icon size={20} className={color} />
              <div>
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
                <p className="text-xs text-gray-500">{label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Toast */}
        {toast && <Toast msg={toast.msg} ok={toast.ok} onClose={() => setToast(null)} />}

        {/* One-time secret reveal */}
        {newSecret && (
          <SecretReveal
            secret={newSecret.secret}
            signingNote={newSecret.note}
            onDismiss={() => setNewSecret(null)}
          />
        )}

        {/* Content */}
        {loading ? (
          <div className="flex items-center gap-2 text-gray-500 text-sm py-8">
            <RefreshCw size={14} className="animate-spin" /> Cargando webhooks…
          </div>
        ) : error ? (
          <div className="bg-red-900/20 border border-red-700/50 text-red-400 rounded p-4 text-sm">{error}</div>
        ) : webhooks.length === 0 ? (
          <div className="text-center py-16 text-gray-600">
            <Webhook size={40} className="mx-auto mb-3 opacity-30" />
            <p className="text-sm">No tienes webhooks registrados.</p>
            <p className="text-xs mt-1">Crea uno para recibir eventos del SOC en tu endpoint.</p>
            <button
              onClick={() => setShowCreate(true)}
              className="mt-4 text-sm text-cyan-400 hover:text-cyan-300 underline"
            >
              Crear primer webhook
            </button>
          </div>
        ) : (
          <>
            {/* Column headers */}
            <div className="flex items-center gap-3 px-4 mb-1 text-xs text-gray-600 select-none">
              <div className="w-5 shrink-0" />
              <div className="flex-1">URL / Eventos</div>
              <div className="w-20 hidden sm:block text-center">Estado</div>
              <div className="w-12 hidden sm:block text-center">Fallos</div>
              <div className="w-36 hidden md:block text-right">Último disparo</div>
              <div className="w-24 text-right">Acciones</div>
            </div>

            {/* Webhook rows */}
            {webhooks.map(wh => (
              <WebhookRow
                key={wh.id}
                wh={wh}
                onToggle={() => handleToggle(wh)}
                onTest={() => load()}
                onEdit={() => setEditTarget(wh)}
                onDelete={() => setDelConfirm(wh.id)}
              />
            ))}
          </>
        )}

        {/* Delete confirm dialog */}
        {delConfirm && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
            <div className="bg-navy-900 border border-red-800/60 rounded-xl shadow-2xl w-full max-w-sm mx-4 p-6">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle size={18} className="text-red-400" />
                <h2 className="text-white font-semibold">Confirmar eliminación</h2>
              </div>
              <p className="text-sm text-gray-400 mb-4">
                Esta acción es irreversible. El webhook y su secreto de firma serán eliminados permanentemente.
              </p>
              <div className="flex gap-3 justify-end">
                <button
                  onClick={() => setDelConfirm(null)}
                  className="px-4 py-1.5 text-sm text-gray-400 hover:text-white transition-colors"
                >
                  Cancelar
                </button>
                <button
                  onClick={() => handleDelete(delConfirm)}
                  className="px-4 py-1.5 text-sm bg-red-600 text-white font-semibold rounded hover:bg-red-500 transition-colors"
                >
                  Eliminar
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Create modal */}
        {showCreate && (
          <WebhookFormModal
            onSave={handleCreate}
            onClose={() => setShowCreate(false)}
          />
        )}

        {/* Edit modal */}
        {editTarget && (
          <WebhookFormModal
            initial={editTarget}
            onSave={p => handleEdit(editTarget, p)}
            onClose={() => setEditTarget(null)}
          />
        )}
      </main>
    </div>
  )
}
