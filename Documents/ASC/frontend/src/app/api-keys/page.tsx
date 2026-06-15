'use client'

import { useEffect, useState, useCallback, useRef } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import {
  listApiKeys, createApiKey, revokeApiKey, rotateApiKey, updateApiKey,
  getApiKeyRateLimitStatus,
  APIKeyResponse, APIKeyCreated, RateLimitStatus,
} from '@/lib/api'
import {
  Key, Plus, Trash2, RotateCcw, Copy, CheckCircle2, XCircle, AlertTriangle,
  RefreshCw, Clock, ShieldCheck, Activity, Eye, EyeOff, ToggleLeft,
  ToggleRight, Pencil, ChevronDown, ChevronUp, Gauge, Info,
} from 'lucide-react'

// ── Constants ─────────────────────────────────────────────────────────────────

const SCOPE_OPTIONS = ['read', 'write', 'admin'] as const
type Scope = typeof SCOPE_OPTIONS[number]

const SCOPE_COLORS: Record<Scope, string> = {
  read:  'bg-blue-400/10 text-blue-300 border-blue-700/60',
  write: 'bg-yellow-400/10 text-yellow-300 border-yellow-700/60',
  admin: 'bg-purple-400/10 text-purple-300 border-purple-700/60',
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtTs(ts: string | null | undefined) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'short' })
}

function isExpired(key: APIKeyResponse) {
  if (!key.expires_at) return false
  return new Date(key.expires_at) < new Date()
}

function ScopeBadge({ scope }: { scope: string }) {
  const cls = SCOPE_COLORS[scope as Scope] ?? 'bg-gray-700 text-gray-400 border-gray-600'
  return <span className={`px-1.5 py-0.5 rounded text-xs border ${cls}`}>{scope}</span>
}

function StatusBadge({ k }: { k: APIKeyResponse }) {
  if (isExpired(k)) return (
    <span className="inline-flex items-center gap-1 text-xs text-orange-400 bg-orange-400/10 border border-orange-700/50 px-2 py-0.5 rounded">
      <Clock size={10} /> Expirada
    </span>
  )
  if (!k.is_active) return (
    <span className="inline-flex items-center gap-1 text-xs text-gray-500 bg-gray-700/50 border border-gray-600/50 px-2 py-0.5 rounded">
      <XCircle size={10} /> Inactiva
    </span>
  )
  return (
    <span className="inline-flex items-center gap-1 text-xs text-green-400 bg-green-400/10 border border-green-700/50 px-2 py-0.5 rounded">
      <CheckCircle2 size={10} /> Activa
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

// ── Rate Limit Bar ────────────────────────────────────────────────────────────

function RateLimitBar({ label, count, limit, color }: {
  label: string; count: number; limit: number; color: string
}) {
  const pct = limit > 0 ? Math.min((count / limit) * 100, 100) : 0
  const barColor = pct >= 90 ? 'bg-red-500' : pct >= 70 ? 'bg-yellow-500' : 'bg-cyan-500'
  return (
    <div>
      <div className="flex justify-between text-xs mb-0.5">
        <span className={color}>{label}</span>
        <span className="text-gray-400 font-mono">{count} / {limit}</span>
      </div>
      <div className="h-1.5 bg-navy-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${barColor}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

// ── Key Reveal Panel (one-time — Toque Premos) ────────────────────────────────

function KeyRevealPanel({ result, label, onDismiss }: {
  result: APIKeyCreated
  label: string
  onDismiss: () => void
}) {
  const [copied, setCopied] = useState(false)
  const [countdown, setCountdown] = useState(90)
  const [show, setShow] = useState(false)

  useEffect(() => {
    if (countdown <= 0) { onDismiss(); return }
    const t = setInterval(() => setCountdown(c => c - 1), 1000)
    return () => clearInterval(t)
  }, [countdown, onDismiss])

  function copy() {
    navigator.clipboard.writeText(result.raw_key)
    setCopied(true)
    setTimeout(() => setCopied(false), 2500)
  }

  const urgency = countdown <= 20 ? 'text-red-400' : countdown <= 45 ? 'text-yellow-400' : 'text-gray-400'
  const borderColor = countdown <= 20 ? 'border-red-700/60' : 'border-yellow-700/60'

  return (
    <div className={`border rounded-lg p-4 mb-4 ${borderColor} bg-yellow-900/10`}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <AlertTriangle size={15} className="text-yellow-400" />
          <span className="text-yellow-300 font-semibold text-sm">{label} — copia ahora</span>
        </div>
        <span className={`font-mono text-sm tabular-nums ${urgency}`}>{countdown}s</span>
      </div>
      <p className="text-xs text-gray-400 mb-3">
        Esta llave se muestra <strong className="text-white">una sola vez</strong>.
        Guárdala en un gestor de secretos. No podrás recuperarla.
      </p>
      <div className="flex items-center gap-2 bg-navy-900 border border-navy-600 rounded p-2 font-mono text-xs mb-2">
        <span className="flex-1 break-all text-gray-200">
          {show ? result.raw_key : result.raw_key.slice(0, 8) + '•'.repeat(40)}
        </span>
        <button onClick={() => setShow(s => !s)} className="shrink-0 text-gray-500 hover:text-gray-300">
          {show ? <EyeOff size={13} /> : <Eye size={13} />}
        </button>
        <button onClick={copy} className="shrink-0 text-cyan-400 hover:text-cyan-300">
          {copied ? <CheckCircle2 size={13} /> : <Copy size={13} />}
        </button>
      </div>
      <div className="flex justify-between items-center text-xs text-gray-500">
        <span>Prefijo: <code className="text-cyan-300">{result.key_prefix}</code></span>
        <button
          onClick={onDismiss}
          className="text-xs bg-yellow-600/20 text-yellow-300 border border-yellow-700/50 hover:bg-yellow-600/30 px-3 py-1 rounded transition-colors"
        >
          Guardé la llave
        </button>
      </div>
      {/* Countdown progress bar */}
      <div className="mt-2 h-0.5 bg-navy-700 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${countdown <= 20 ? 'bg-red-500' : countdown <= 45 ? 'bg-yellow-500' : 'bg-cyan-500'}`}
          style={{ width: `${(countdown / 90) * 100}%` }}
        />
      </div>
    </div>
  )
}

// ── Create / Edit modal ───────────────────────────────────────────────────────

function KeyFormModal({
  initial,
  onSave,
  onClose,
}: {
  initial?: APIKeyResponse
  onSave: (payload: { name: string; scopes: string[]; expires_at: string | null }) => Promise<void>
  onClose: () => void
}) {
  const [name, setName]       = useState(initial?.name ?? '')
  const [scopes, setScopes]   = useState<string[]>(initial?.scopes ?? ['read'])
  const [expiresAt, setExpiresAt] = useState<string>(
    initial?.expires_at ? initial.expires_at.slice(0, 10) : ''
  )
  const [saving, setSaving]   = useState(false)
  const [error, setError]     = useState<string | null>(null)

  function toggleScope(s: string) {
    setScopes(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])
  }

  async function submit() {
    setError(null)
    if (!name.trim()) { setError('El nombre es obligatorio'); return }
    if (scopes.length === 0) { setError('Selecciona al menos un scope'); return }
    setSaving(true)
    try {
      await onSave({
        name: name.trim(),
        scopes,
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
      })
      onClose()
    } catch (e: unknown) {
      const detail = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(detail ?? (e instanceof Error ? e.message : 'Error guardando la llave'))
    } finally { setSaving(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-navy-900 border border-navy-600 rounded-xl shadow-2xl w-full max-w-md mx-4 p-6">
        <h2 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
          <Key size={15} className="text-cyan-400" />
          {initial ? 'Editar API Key' : 'Nueva API Key'}
        </h2>

        {error && (
          <div className="bg-red-900/20 border border-red-700/50 text-red-400 text-xs rounded p-2 mb-3">{error}</div>
        )}

        <label className="block text-xs text-gray-400 mb-1">Nombre *</label>
        <input
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="ej. CI/CD pipeline, Prometheus scraper"
          className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500 mb-3"
        />

        <label className="block text-xs text-gray-400 mb-2">Scopes *</label>
        <div className="flex gap-2 mb-3">
          {SCOPE_OPTIONS.map(s => (
            <button
              key={s}
              onClick={() => toggleScope(s)}
              className={`flex-1 py-1.5 rounded text-xs border transition-colors ${
                scopes.includes(s)
                  ? `${SCOPE_COLORS[s]} border-opacity-100`
                  : 'border-navy-600 text-gray-500 hover:border-gray-500'
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        <label className="block text-xs text-gray-400 mb-1">Fecha de expiración (opcional)</label>
        <input
          type="date"
          value={expiresAt}
          onChange={e => setExpiresAt(e.target.value)}
          className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 mb-4"
        />

        <div className="flex gap-2 justify-end">
          <button onClick={onClose} className="px-4 py-1.5 text-sm text-gray-400 hover:text-white transition-colors">
            Cancelar
          </button>
          <button
            onClick={submit}
            disabled={saving}
            className="px-4 py-1.5 text-sm bg-cyan-500 text-navy-900 font-semibold rounded hover:bg-cyan-400 disabled:opacity-50 transition-colors"
          >
            {saving ? 'Guardando…' : initial ? 'Guardar cambios' : 'Crear llave'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Key Row ───────────────────────────────────────────────────────────────────

function KeyRow({
  k,
  onToggle,
  onRotate,
  onEdit,
  onRevoke,
}: {
  k: APIKeyResponse
  onToggle: () => Promise<void>
  onRotate: () => Promise<APIKeyCreated>
  onEdit: () => void
  onRevoke: () => void
}) {
  const [expanded, setExpanded]     = useState(false)
  const [toggling, setToggling]     = useState(false)
  const [rotating, setRotating]     = useState(false)
  const [rlStatus, setRlStatus]     = useState<RateLimitStatus | null>(null)
  const [loadingRl, setLoadingRl]   = useState(false)
  const [rotated, setRotated]       = useState<APIKeyCreated | null>(null)

  async function handleToggle() {
    setToggling(true)
    try { await onToggle() } finally { setToggling(false) }
  }

  async function handleRotate() {
    setRotating(true)
    try {
      const result = await onRotate()
      setRotated(result)
    } finally { setRotating(false) }
  }

  async function loadRlStatus() {
    if (rlStatus) return
    setLoadingRl(true)
    try { setRlStatus(await getApiKeyRateLimitStatus(k.id)) }
    catch { /* rate limit endpoint may not be available in dev */ }
    finally { setLoadingRl(false) }
  }

  function handleExpand() {
    setExpanded(e => !e)
    if (!expanded) loadRlStatus()
  }

  const expired = isExpired(k)

  return (
    <div className={`border rounded-lg mb-2 overflow-hidden ${
      expired ? 'border-orange-800/50' : k.is_active ? 'border-navy-700' : 'border-gray-700/50'
    } bg-navy-800/40`}>
      {/* Main row */}
      <div className="flex items-center gap-3 px-4 py-3">
        {/* Toggle */}
        <button
          onClick={handleToggle}
          disabled={toggling || expired}
          className="shrink-0 text-gray-400 hover:text-cyan-400 disabled:opacity-40 transition-colors"
          title={k.is_active ? 'Desactivar' : 'Activar'}
        >
          {k.is_active
            ? <ToggleRight size={20} className="text-cyan-400" />
            : <ToggleLeft size={20} />}
        </button>

        {/* Name + prefix + scopes */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-sm text-white font-medium truncate">{k.name}</span>
            <code className="text-xs text-gray-500 bg-navy-700/60 px-1.5 py-0.5 rounded font-mono">
              {k.key_prefix}••••
            </code>
          </div>
          <div className="flex flex-wrap gap-1">
            {k.scopes.map(s => <ScopeBadge key={s} scope={s} />)}
          </div>
        </div>

        {/* Status badge */}
        <div className="shrink-0 hidden sm:block">
          <StatusBadge k={k} />
        </div>

        {/* Last used */}
        <div className="shrink-0 text-xs text-gray-500 hidden md:block w-32 text-right">
          <Clock size={10} className="inline mr-1" />
          {fmtTs(k.last_used_at)}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={handleRotate}
            disabled={rotating}
            className="p-1.5 text-gray-500 hover:text-cyan-400 disabled:opacity-40 transition-colors"
            title="Rotar llave (nueva raw key, mismo ID y scopes)"
          >
            {rotating ? <RefreshCw size={14} className="animate-spin" /> : <RotateCcw size={14} />}
          </button>
          <button
            onClick={onEdit}
            className="p-1.5 text-gray-500 hover:text-yellow-400 transition-colors"
            title="Editar nombre / scopes / expiración"
          >
            <Pencil size={14} />
          </button>
          <button
            onClick={onRevoke}
            className="p-1.5 text-gray-500 hover:text-red-400 transition-colors"
            title="Revocar permanentemente"
          >
            <Trash2 size={14} />
          </button>
          <button
            onClick={handleExpand}
            className="p-1.5 text-gray-600 hover:text-gray-300 transition-colors"
          >
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {/* Rotate reveal */}
      {rotated && (
        <div className="border-t border-navy-700 px-4 py-3 bg-navy-900/40">
          <KeyRevealPanel
            result={rotated}
            label="Llave rotada"
            onDismiss={() => setRotated(null)}
          />
        </div>
      )}

      {/* Expanded details + rate limit */}
      {expanded && (
        <div className="border-t border-navy-700 px-4 py-3 bg-navy-900/40">
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs text-gray-400 mb-3">
            <span><span className="text-gray-600">ID:</span> <span className="font-mono text-gray-500">{k.id}</span></span>
            <span><span className="text-gray-600">Prefijo:</span> <code className="text-cyan-300">{k.key_prefix}</code></span>
            <span><span className="text-gray-600">Creada:</span> {fmtTs(k.created_at)}</span>
            <span><span className="text-gray-600">Último uso:</span> {fmtTs(k.last_used_at)}</span>
            <span><span className="text-gray-600">Expira:</span> {fmtTs(k.expires_at)}</span>
            <span><span className="text-gray-600">Estado:</span> <StatusBadge k={k} /></span>
          </div>

          {/* Rate limit section */}
          <div className="border-t border-navy-700/50 pt-3">
            <div className="flex items-center gap-2 mb-2">
              <Gauge size={13} className="text-cyan-400" />
              <span className="text-xs text-gray-400 font-medium">Uso de Rate Limit</span>
              {loadingRl && <RefreshCw size={11} className="animate-spin text-gray-500" />}
            </div>
            {rlStatus ? (
              <div className="space-y-2">
                <RateLimitBar
                  label="Por minuto"
                  count={rlStatus.count_minute}
                  limit={rlStatus.limit_per_minute}
                  color="text-gray-400"
                />
                <RateLimitBar
                  label="Por hora"
                  count={rlStatus.count_hour}
                  limit={rlStatus.limit_per_hour}
                  color="text-gray-400"
                />
                <p className="text-xs text-gray-600">
                  Backend: <span className="text-gray-500">{rlStatus.backend}</span>
                  {' · '}Restante min: <span className="text-cyan-400">{rlStatus.remaining_minute}</span>
                  {' · '}Restante hora: <span className="text-cyan-400">{rlStatus.remaining_hour}</span>
                </p>
              </div>
            ) : !loadingRl ? (
              <p className="text-xs text-gray-600 flex items-center gap-1">
                <Info size={11} /> Estado de rate limit no disponible para esta llave
              </p>
            ) : null}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ApiKeysPage() {
  useAuthGuard()

  const [keys, setKeys]           = useState<APIKeyResponse[]>([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState<string | null>(null)
  const [toast, setToast]         = useState<{ msg: string; ok: boolean } | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [editTarget, setEditTarget] = useState<APIKeyResponse | null>(null)
  const [newKey, setNewKey]       = useState<APIKeyCreated | null>(null)
  const [revokeConfirm, setRevokeConfirm] = useState<APIKeyResponse | null>(null)
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const showToast = (msg: string, ok: boolean) => {
    if (toastTimer.current) clearTimeout(toastTimer.current)
    setToast({ msg, ok })
    toastTimer.current = setTimeout(() => setToast(null), 4500)
  }

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try { setKeys(await listApiKeys()) }
    catch (e: unknown) { setError(e instanceof Error ? e.message : 'Error cargando API keys') }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleCreate(payload: { name: string; scopes: string[]; expires_at: string | null }) {
    const created = await createApiKey({ name: payload.name, scopes: payload.scopes, expires_at: payload.expires_at })
    setNewKey(created)
    await load()
    showToast('API Key creada', true)
  }

  async function handleEdit(k: APIKeyResponse, payload: { name: string; scopes: string[]; expires_at: string | null }) {
    await updateApiKey(k.id, { name: payload.name, expires_at: payload.expires_at })
    await load()
    showToast('API Key actualizada', true)
  }

  async function handleToggle(k: APIKeyResponse) {
    try {
      await updateApiKey(k.id, { is_active: !k.is_active })
      await load()
      showToast(`Llave ${!k.is_active ? 'activada' : 'desactivada'}`, true)
    } catch {
      showToast('Error cambiando estado', false)
    }
  }

  async function handleRotate(k: APIKeyResponse): Promise<APIKeyCreated> {
    const result = await rotateApiKey(k.id)
    await load()
    showToast('Llave rotada — nueva raw key generada', true)
    return result
  }

  async function handleRevoke(k: APIKeyResponse) {
    try {
      await revokeApiKey(k.id)
      setRevokeConfirm(null)
      await load()
      showToast('Llave revocada permanentemente', true)
    } catch {
      showToast('Error revocando la llave', false)
    }
  }

  // Stats
  const total    = keys.length
  const active   = keys.filter(k => k.is_active && !isExpired(k)).length
  const inactive = keys.filter(k => !k.is_active).length
  const expired  = keys.filter(k => isExpired(k)).length
  const cap = 20

  return (
    <div className="flex min-h-screen bg-navy-950 text-gray-100">
      <Sidebar />
      <main className="flex-1 p-6 overflow-auto">

        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Key size={22} className="text-cyan-400" />
            <div>
              <h1 className="text-xl font-bold text-white">API Keys</h1>
              <p className="text-xs text-gray-500">Autenticación programática via <code className="text-cyan-300">X-API-Key</code> header</p>
            </div>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            disabled={total >= cap}
            className="flex items-center gap-2 bg-cyan-500 text-navy-900 font-semibold text-sm px-4 py-2 rounded-lg hover:bg-cyan-400 disabled:opacity-50 transition-colors"
            title={total >= cap ? `Límite de ${cap} llaves alcanzado` : ''}
          >
            <Plus size={16} /> Nueva API Key
          </button>
        </div>

        {/* KPI strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          {[
            { label: 'Total', value: total,    icon: Key,        color: 'text-gray-400' },
            { label: 'Activas', value: active, icon: ShieldCheck, color: 'text-green-400' },
            { label: 'Inactivas', value: inactive, icon: XCircle, color: inactive > 0 ? 'text-yellow-400' : 'text-gray-500' },
            { label: 'Expiradas', value: expired, icon: Clock,   color: expired > 0 ? 'text-orange-400' : 'text-gray-500' },
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

        {/* Cap warning */}
        {total >= cap * 0.8 && (
          <div className={`flex items-center gap-2 rounded p-3 text-xs border mb-4 ${
            total >= cap
              ? 'bg-red-900/20 border-red-700/50 text-red-400'
              : 'bg-yellow-900/20 border-yellow-700/50 text-yellow-400'
          }`}>
            <AlertTriangle size={14} />
            {total >= cap
              ? `Límite de ${cap} API keys alcanzado. Revoca llaves inactivas para crear nuevas.`
              : `${total}/${cap} llaves utilizadas. Límite próximo.`}
          </div>
        )}

        {/* Toast */}
        {toast && <Toast msg={toast.msg} ok={toast.ok} onClose={() => setToast(null)} />}

        {/* New key reveal */}
        {newKey && (
          <KeyRevealPanel
            result={newKey}
            label="Nueva API Key creada"
            onDismiss={() => setNewKey(null)}
          />
        )}

        {/* Security note */}
        <div className="flex items-start gap-2 text-xs text-gray-500 bg-navy-800/50 border border-navy-700/50 rounded p-3 mb-5">
          <Info size={13} className="text-cyan-400 mt-0.5 shrink-0" />
          <p>
            Usa el header <code className="text-cyan-300">X-API-Key: {'<tu-llave>'}</code> para autenticarte.
            Las llaves HMAC-SHA256 nunca se almacenan en texto plano — solo se guarda el hash.
            Puedes revocar una llave comprometida sin afectar otras.
          </p>
        </div>

        {/* Content */}
        {loading ? (
          <div className="flex items-center gap-2 text-gray-500 text-sm py-8">
            <RefreshCw size={14} className="animate-spin" /> Cargando API keys…
          </div>
        ) : error ? (
          <div className="bg-red-900/20 border border-red-700/50 text-red-400 rounded p-4 text-sm">{error}</div>
        ) : keys.length === 0 ? (
          <div className="text-center py-16 text-gray-600">
            <Key size={40} className="mx-auto mb-3 opacity-30" />
            <p className="text-sm">No tienes API keys registradas.</p>
            <p className="text-xs mt-1">Crea una para autenticarte programáticamente sin credenciales de usuario.</p>
            <button
              onClick={() => setShowCreate(true)}
              className="mt-4 text-sm text-cyan-400 hover:text-cyan-300 underline"
            >
              Crear primera API Key
            </button>
          </div>
        ) : (
          <>
            {/* Column headers */}
            <div className="flex items-center gap-3 px-4 mb-1 text-xs text-gray-600 select-none">
              <div className="w-5 shrink-0" />
              <div className="flex-1">Nombre / Prefijo / Scopes</div>
              <div className="w-20 hidden sm:block text-center">Estado</div>
              <div className="w-32 hidden md:block text-right">Último uso</div>
              <div className="w-24 text-right">Acciones</div>
            </div>

            {keys.map(k => (
              <KeyRow
                key={k.id}
                k={k}
                onToggle={() => handleToggle(k)}
                onRotate={() => handleRotate(k)}
                onEdit={() => setEditTarget(k)}
                onRevoke={() => setRevokeConfirm(k)}
              />
            ))}
          </>
        )}

        {/* Revoke confirm */}
        {revokeConfirm && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
            <div className="bg-navy-900 border border-red-800/60 rounded-xl shadow-2xl w-full max-w-sm mx-4 p-6">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle size={18} className="text-red-400" />
                <h2 className="text-white font-semibold text-sm">Confirmar revocación</h2>
              </div>
              <p className="text-sm text-gray-400 mb-1">
                ¿Revocar <strong className="text-white">{revokeConfirm.name}</strong>?
              </p>
              <p className="text-xs text-gray-500 mb-4">
                Prefijo: <code className="text-cyan-300">{revokeConfirm.key_prefix}</code> ·
                Esta acción es <strong className="text-red-400">irreversible</strong>.
                Cualquier cliente que use esta llave dejará de funcionar inmediatamente.
              </p>
              <div className="flex gap-3 justify-end">
                <button
                  onClick={() => setRevokeConfirm(null)}
                  className="px-4 py-1.5 text-sm text-gray-400 hover:text-white transition-colors"
                >
                  Cancelar
                </button>
                <button
                  onClick={() => handleRevoke(revokeConfirm)}
                  className="px-4 py-1.5 text-sm bg-red-600 text-white font-semibold rounded hover:bg-red-500 transition-colors"
                >
                  Revocar
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Create modal */}
        {showCreate && (
          <KeyFormModal
            onSave={handleCreate}
            onClose={() => setShowCreate(false)}
          />
        )}

        {/* Edit modal */}
        {editTarget && (
          <KeyFormModal
            initial={editTarget}
            onSave={p => handleEdit(editTarget, p)}
            onClose={() => setEditTarget(null)}
          />
        )}

      </main>
    </div>
  )
}
