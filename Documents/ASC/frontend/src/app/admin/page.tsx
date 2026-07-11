'use client'

import { useEffect, useState, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'
import {
  listAdminUsers, unlockAdminUser, updateAdminUser, AdminUser,
  listApiKeys, createApiKey, revokeApiKey, rotateApiKey, APIKeyResponse, APIKeyCreated,
} from '@/lib/api'
import {
  Users, Unlock, RefreshCw, ShieldAlert, CheckCircle2, XCircle, Clock, Lock,
  Key, Plus, Trash2, RotateCcw, Copy, AlertTriangle, ChevronDown,
} from 'lucide-react'

// ── Shared helpers ─────────────────────────────────────────────────────────────

function formatTs(ts: string | null | undefined): string {
  if (!ts) return '—'
  try { return new Date(ts).toLocaleString() } catch { return ts }
}

function Toast({ toast, onClose }: { toast: { msg: string; ok: boolean } | null; onClose: () => void }) {
  if (!toast) return null
  return (
    <div className={`mb-4 flex items-center gap-2 rounded p-3 text-xs border ${
      toast.ok
        ? 'bg-green-900/20 border-green-700/50 text-green-400'
        : 'bg-red-900/20 border-red-700/50 text-red-400'
    }`}>
      {toast.ok ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
      <span className="flex-1">{toast.msg}</span>
      <button onClick={onClose} className="ml-2 hover:opacity-70"><XCircle size={12} /></button>
    </div>
  )
}

// ── Users tab ─────────────────────────────────────────────────────────────────

function RoleBadge({ role }: { role: string }) {
  const cls = {
    admin:   'bg-purple-400/10 text-purple-300 border-purple-700',
    analyst: 'bg-blue-400/10 text-blue-300 border-blue-700',
    viewer:  'bg-gray-700 text-gray-400 border-gray-600',
  }[role] ?? 'bg-gray-700 text-gray-400 border-gray-600'
  return (
    <span className={`px-1.5 py-0.5 rounded text-xs border ${cls}`}>
      {role}
    </span>
  )
}

const ROLE_OPTIONS = ['admin', 'analyst', 'viewer'] as const
type Role = typeof ROLE_OPTIONS[number]

function RoleSelect({
  user,
  currentUserId,
  onRoleChange,
  changing,
}: {
  user: AdminUser
  currentUserId: string | null
  onRoleChange: (user: AdminUser, newRole: string) => void
  changing: string | null
}) {
  const isSelf = user.id === currentUserId
  const cls: Record<string, string> = {
    admin:   'bg-purple-400/10 text-purple-300 border-purple-700',
    analyst: 'bg-blue-400/10 text-blue-300 border-blue-700',
    viewer:  'bg-gray-700 text-gray-400 border-gray-600',
  }
  const base = cls[user.role] ?? cls.viewer
  const isChanging = changing === user.id

  if (isSelf) {
    return (
      <span className={`px-1.5 py-0.5 rounded text-xs border ${base}`} title="No puedes cambiar tu propio rol">
        {user.role}
      </span>
    )
  }

  return (
    <div className="relative inline-block">
      <select
        value={user.role}
        onChange={e => {
          const newRole = e.target.value
          if (newRole !== user.role) onRoleChange(user, newRole)
        }}
        disabled={isChanging}
        className={`appearance-none pl-1.5 pr-5 py-0.5 rounded text-xs border cursor-pointer transition-colors hover:opacity-80 disabled:opacity-40 ${base}`}
        title="Cambiar rol"
      >
        {ROLE_OPTIONS.map(r => (
          <option key={r} value={r} className="bg-navy-800 text-gray-200">{r}</option>
        ))}
      </select>
      <ChevronDown size={10} className="absolute right-1 top-1/2 -translate-y-1/2 pointer-events-none opacity-60" />
    </div>
  )
}

function LockedBadge({ user }: { user: AdminUser }) {
  if (!user.is_locked) {
    return <span className="flex items-center gap-1 text-xs text-green-400"><CheckCircle2 size={12} /> Activo</span>
  }
  const until = user.locked_until ? new Date(user.locked_until) : null
  const expired = until && until < new Date()
  return (
    <span className={`flex items-center gap-1 text-xs ${expired ? 'text-yellow-400' : 'text-red-400'}`}>
      <Lock size={12} />
      {expired ? 'Expirado' : 'Bloqueado'}
      {until && !expired && <span className="text-gray-500">hasta {formatTs(user.locked_until)}</span>}
    </span>
  )
}

function UsersTab({ showToast }: { showToast: (msg: string, ok: boolean) => void }) {
  const [users, setUsers]     = useState<AdminUser[]>([])
  const [loading, setLoading] = useState(true)
  const [unlocking, setUnlocking] = useState<string | null>(null)
  const [elevating, setElevating] = useState<string | null>(null)
  const [error, setError]     = useState<string | null>(null)
  const [search, setSearch]   = useState('')
  const [roleFilter, setRoleFilter] = useState<string>('all')
  const [currentUserId, setCurrentUserId] = useState<string | null>(null)

  // Derive current user id from the stored JWT so we can disable self-role-change
  useEffect(() => {
    try {
      const token = localStorage.getItem('asc_token') ?? sessionStorage.getItem('asc_token') ?? ''
      if (token) {
        const payload = JSON.parse(atob(token.split('.')[1]))
        setCurrentUserId(payload.sub ?? null)
      }
    } catch { /* token not available or malformed — self-guard skipped */ }
  }, [])

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try { setUsers(await listAdminUsers()) }
    catch (e: unknown) { setError(e instanceof Error ? e.message : 'Error cargando usuarios') }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleRoleChange(user: AdminUser, newRole: string) {
    if (!confirm(`¿Cambiar rol de ${user.email} de "${user.role}" a "${newRole}"?`)) return
    setElevating(user.id)
    try {
      const updated = await updateAdminUser(user.id, { role: newRole })
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, role: updated.role } : u))
      showToast(`Rol de ${user.email} cambiado a ${newRole}`, true)
    } catch (e: unknown) {
      showToast(e instanceof Error ? e.message : 'Error al cambiar rol', false)
    } finally { setElevating(null) }
  }

  async function handleUnlock(user: AdminUser) {
    setUnlocking(user.id)
    try {
      await unlockAdminUser(user.id)
      setUsers(prev => prev.map(u => u.id === user.id
        ? { ...u, is_locked: false, locked_until: null, failed_login_attempts: 0 } : u))
      showToast(`Usuario ${user.email} desbloqueado correctamente`, true)
    } catch (e: unknown) {
      showToast(e instanceof Error ? e.message : 'Error al desbloquear', false)
    } finally { setUnlocking(null) }
  }

  const filtered = users.filter(u => {
    const matchSearch = !search || u.email.toLowerCase().includes(search.toLowerCase())
      || (u.full_name ?? '').toLowerCase().includes(search.toLowerCase())
    const matchRole = roleFilter === 'all' || u.role === roleFilter
    return matchSearch && matchRole
  })

  const lockedCount   = users.filter(u => u.is_locked).length
  const inactiveCount = users.filter(u => !u.is_active).length

  return (
    <>
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-3">
          <Users size={20} className="text-cyan-400" />
          <div>
            <h2 className="text-base font-bold text-white">Usuarios IAM</h2>
            <p className="text-xs text-gray-400">Bloqueos · Intentos fallidos · Roles</p>
          </div>
        </div>
        <button onClick={load} disabled={loading}
          className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-cyan-400 transition-colors disabled:opacity-40">
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Actualizar
        </button>
      </div>

      {lockedCount > 0 && (
        <div className="mb-4 bg-red-900/20 border border-red-700/50 rounded-lg p-3 flex items-center gap-2 text-xs text-red-400">
          <ShieldAlert size={14} />
          <span><strong>{lockedCount}</strong> {lockedCount === 1 ? 'usuario bloqueado' : 'usuarios bloqueados'} — verifique la actividad antes de desbloquear</span>
        </div>
      )}

      {error && <div className="mb-4 bg-red-900/20 border border-red-700/50 rounded p-3 text-xs text-red-400">{error}</div>}

      <div className="grid grid-cols-3 gap-3 mb-5">
        {[
          { label: 'Total usuarios', value: users.length, color: 'text-white' },
          { label: 'Bloqueados', value: lockedCount, color: lockedCount > 0 ? 'text-red-400' : 'text-green-400' },
          { label: 'Inactivos', value: inactiveCount, color: inactiveCount > 0 ? 'text-yellow-400' : 'text-gray-400' },
        ].map(s => (
          <div key={s.label} className="bg-navy-800 border border-navy-700 rounded-lg p-3 text-center">
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            <p className="text-xs text-gray-400 mt-0.5">{s.label}</p>
          </div>
        ))}
      </div>

      <div className="flex gap-3 mb-4">
        <input type="text" placeholder="Buscar por email o nombre…" value={search}
          onChange={e => setSearch(e.target.value)}
          className="flex-1 bg-navy-800 border border-navy-700 rounded px-3 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-700" />
        <select value={roleFilter} onChange={e => setRoleFilter(e.target.value)}
          className="bg-navy-800 border border-navy-700 rounded px-2 py-1.5 text-xs text-gray-300">
          <option value="all">Todos los roles</option>
          <option value="admin">admin</option>
          <option value="analyst">analyst</option>
          <option value="viewer">viewer</option>
        </select>
      </div>

      <div className="bg-navy-800 border border-navy-700 rounded-lg overflow-x-auto">
        {loading ? (
          <p className="text-center text-gray-500 text-sm py-10">Cargando usuarios…</p>
        ) : filtered.length === 0 ? (
          <p className="text-center text-gray-500 text-sm py-10">Sin resultados</p>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-navy-700 text-gray-400">
                <th className="px-4 py-3 text-left">Email</th>
                <th className="px-4 py-3 text-left">Nombre</th>
                <th className="px-4 py-3 text-left">Rol</th>
                <th className="px-4 py-3 text-left">Estado</th>
                <th className="px-4 py-3 text-center">Intentos</th>
                <th className="px-4 py-3 text-left">Bloqueado hasta</th>
                <th className="px-4 py-3 text-left">Último login</th>
                <th className="px-4 py-3 text-left">Acciones</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(user => (
                <tr key={user.id}
                  className={`border-b border-navy-700/50 hover:bg-navy-700/30 transition-colors ${user.is_locked ? 'bg-red-950/10' : ''}`}>
                  <td className="px-4 py-2 text-gray-200 max-w-[180px] truncate" title={user.email}>{user.email}</td>
                  <td className="px-4 py-2 text-gray-400">{user.full_name ?? <span className="text-gray-600">—</span>}</td>
                  <td className="px-4 py-2">
                    <RoleSelect
                      user={user}
                      currentUserId={currentUserId}
                      onRoleChange={handleRoleChange}
                      changing={elevating}
                    />
                  </td>
                  <td className="px-4 py-2"><LockedBadge user={user} /></td>
                  <td className="px-4 py-2 text-center">
                    <span className={`font-semibold ${user.failed_login_attempts >= 4 ? 'text-red-400' : user.failed_login_attempts >= 2 ? 'text-yellow-400' : 'text-gray-400'}`}>
                      {user.failed_login_attempts}
                    </span>
                    <span className="text-gray-600"> / 5</span>
                  </td>
                  <td className="px-4 py-2 text-gray-400 whitespace-nowrap">
                    {user.locked_until ? <span className="flex items-center gap-1"><Clock size={11} /> {formatTs(user.locked_until)}</span> : <span className="text-gray-600">—</span>}
                  </td>
                  <td className="px-4 py-2 text-gray-400 whitespace-nowrap">{formatTs(user.last_login)}</td>
                  <td className="px-4 py-2">
                    {user.is_locked ? (
                      <button onClick={() => handleUnlock(user)} disabled={unlocking === user.id}
                        className="flex items-center gap-1 px-2 py-1 rounded text-xs border border-cyan-700 text-cyan-400 hover:bg-cyan-400/10 transition-colors disabled:opacity-40">
                        <Unlock size={11} />{unlocking === user.id ? '…' : 'Desbloquear'}
                      </button>
                    ) : <span className="text-xs text-gray-600">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <p className="mt-3 text-xs text-gray-600">{filtered.length} de {users.length} usuario(s) mostrado(s)</p>
    </>
  )
}

// ── API Keys tab ──────────────────────────────────────────────────────────────

function ScopeBadge({ scope }: { scope: string }) {
  const cls = scope === 'admin' ? 'bg-purple-400/10 text-purple-300 border-purple-700'
    : scope === 'write' ? 'bg-yellow-400/10 text-yellow-300 border-yellow-700'
    : 'bg-blue-400/10 text-blue-300 border-blue-700'
  return <span className={`px-1.5 py-0.5 rounded text-xs border ${cls}`}>{scope}</span>
}

interface NewKeyDialogProps {
  onCreated: (key: APIKeyCreated) => void
  onCancel: () => void
}

function NewKeyDialog({ onCreated, onCancel }: NewKeyDialogProps) {
  const [name, setName] = useState('')
  const [scopes, setScopes] = useState<string[]>(['read'])
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const SCOPE_OPTIONS = ['read', 'write', 'admin']

  function toggleScope(s: string) {
    setScopes(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])
  }

  async function submit() {
    if (!name.trim()) { setErr('El nombre es obligatorio'); return }
    if (scopes.length === 0) { setErr('Selecciona al menos un scope'); return }
    setSaving(true); setErr(null)
    try {
      const result = await createApiKey({ name: name.trim(), scopes })
      onCreated(result)
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : 'Error al crear la llave')
    } finally { setSaving(false) }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-navy-800 border border-navy-700 rounded-xl p-6 w-full max-w-md shadow-2xl">
        <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2"><Key size={16} className="text-cyan-400" /> Nueva API Key</h3>
        {err && <div className="mb-3 bg-red-900/20 border border-red-700/50 rounded p-2 text-xs text-red-400">{err}</div>}
        <div className="space-y-4">
          <div>
            <label className="block text-xs text-gray-400 mb-1">Nombre *</label>
            <input type="text" value={name} onChange={e => setName(e.target.value)} placeholder="ej. Prometheus scraper"
              className="w-full bg-navy-900 border border-navy-600 rounded px-3 py-2 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-700" />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-2">Scopes</label>
            <div className="flex gap-2">
              {SCOPE_OPTIONS.map(s => (
                <button key={s} onClick={() => toggleScope(s)}
                  className={`px-3 py-1.5 rounded text-xs border transition-colors ${
                    scopes.includes(s) ? 'border-cyan-600 bg-cyan-900/30 text-cyan-300' : 'border-navy-600 text-gray-500 hover:border-gray-500'
                  }`}>
                  {s}
                </button>
              ))}
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-2 mt-6">
          <button onClick={onCancel} className="px-4 py-1.5 text-xs text-gray-400 hover:text-white border border-navy-600 rounded transition-colors">Cancelar</button>
          <button onClick={submit} disabled={saving}
            className="px-4 py-1.5 text-xs bg-cyan-600 hover:bg-cyan-500 text-white rounded transition-colors disabled:opacity-40 flex items-center gap-1.5">
            <Plus size={12} />{saving ? 'Creando…' : 'Crear llave'}
          </button>
        </div>
      </div>
    </div>
  )
}

function RevealKeyDialog({ result, onClose }: { result: APIKeyCreated; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  const [countdown, setCountdown] = useState(90)

  // One-time reveal countdown — auto-closes after 90 seconds (Toque Premos)
  useEffect(() => {
    if (countdown <= 0) { onClose(); return }
    const t = setInterval(() => setCountdown(c => c - 1), 1000)
    return () => clearInterval(t)
  }, [countdown, onClose])

  function copy() {
    navigator.clipboard.writeText(result.raw_key)
    setCopied(true)
    setTimeout(() => setCopied(false), 2500)
  }

  const urgency = countdown <= 20 ? 'text-red-400' : countdown <= 45 ? 'text-yellow-400' : 'text-gray-400'

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 backdrop-blur-sm">
      <div className="bg-navy-800 border border-yellow-700/60 rounded-xl p-6 w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <AlertTriangle size={16} className="text-yellow-400" />
            <h3 className="text-sm font-bold text-yellow-300">Guarda esta llave ahora</h3>
          </div>
          <span className={`text-xs font-mono tabular-nums ${urgency}`}>
            {countdown}s
          </span>
        </div>

        <p className="text-xs text-gray-400 mb-1">
          Esta ventana se cierra automáticamente y la llave <strong className="text-white">nunca volverá a mostrarse</strong>.
          Solo se almacena el hash HMAC-SHA256 — Toque Premos garantiza autenticidad forense.
        </p>

        {/* Countdown bar */}
        <div className="w-full h-0.5 bg-navy-700 rounded mb-4 overflow-hidden">
          <div
            className={`h-full rounded transition-all duration-1000 ${countdown <= 20 ? 'bg-red-500' : countdown <= 45 ? 'bg-yellow-500' : 'bg-cyan-500'}`}
            style={{ width: `${(countdown / 90) * 100}%` }}
          />
        </div>

        <div className="bg-navy-900 border border-navy-600 rounded p-3 font-mono text-xs text-cyan-300 break-all mb-4 select-all cursor-text">
          {result.raw_key}
        </div>

        <div className="mb-3 bg-navy-900/60 border border-navy-700 rounded p-2.5 text-xs text-gray-500 space-y-0.5">
          <div><span className="text-gray-400">Nombre:</span> {result.name}</div>
          <div><span className="text-gray-400">Prefijo:</span> <code className="text-cyan-500">asc_{result.key_prefix}…</code></div>
          <div><span className="text-gray-400">Scopes:</span> {result.scopes.join(', ')}</div>
        </div>

        <div className="flex justify-between items-center">
          <button onClick={copy}
            className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-cyan-400 border border-navy-600 hover:border-cyan-700 rounded px-3 py-1.5 transition-colors">
            <Copy size={12} />{copied ? '¡Copiada!' : 'Copiar llave'}
          </button>
          <button onClick={onClose}
            className="px-4 py-1.5 text-xs bg-cyan-600 hover:bg-cyan-500 text-white rounded transition-colors font-medium">
            He guardado la llave
          </button>
        </div>
      </div>
    </div>
  )
}

function ApiKeysTab({ showToast }: { showToast: (msg: string, ok: boolean) => void }) {
  const [keys, setKeys]     = useState<APIKeyResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState<string | null>(null)
  const [showNew, setShowNew] = useState(false)
  const [revealResult, setRevealResult] = useState<APIKeyCreated | null>(null)
  const [actioning, setActioning] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try { setKeys(await listApiKeys()) }
    catch (e: unknown) { setError(e instanceof Error ? e.message : 'Error cargando llaves') }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleRevoke(key: APIKeyResponse) {
    if (!confirm(`¿Revocar la llave "${key.name}" (prefijo: ${key.key_prefix}…)? Esta acción es irreversible.`)) return
    setActioning(key.id)
    try {
      await revokeApiKey(key.id)
      setKeys(prev => prev.filter(k => k.id !== key.id))
      showToast(`Llave "${key.name}" revocada`, true)
    } catch (e: unknown) {
      showToast(e instanceof Error ? e.message : 'Error al revocar', false)
    } finally { setActioning(null) }
  }

  async function handleRotate(key: APIKeyResponse) {
    if (!confirm(`¿Rotar la llave "${key.name}"? La llave actual dejará de funcionar inmediatamente.`)) return
    setActioning(key.id)
    try {
      const result = await rotateApiKey(key.id)
      setKeys(prev => prev.map(k => k.id === key.id ? result : k))
      setRevealResult(result)
    } catch (e: unknown) {
      showToast(e instanceof Error ? e.message : 'Error al rotar', false)
    } finally { setActioning(null) }
  }

  function handleCreated(result: APIKeyCreated) {
    setShowNew(false)
    setKeys(prev => [result, ...prev])
    setRevealResult(result)
  }

  const activeCount   = keys.filter(k => k.is_active).length
  const expiredCount  = keys.filter(k => k.expires_at && new Date(k.expires_at) < new Date()).length

  return (
    <>
      {showNew && <NewKeyDialog onCreated={handleCreated} onCancel={() => setShowNew(false)} />}
      {revealResult && <RevealKeyDialog result={revealResult} onClose={() => setRevealResult(null)} />}

      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-3">
          <Key size={20} className="text-cyan-400" />
          <div>
            <h2 className="text-base font-bold text-white">API Keys</h2>
            <p className="text-xs text-gray-400">Autenticación programática · Scopes · Rotación</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} disabled={loading}
            className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-cyan-400 transition-colors disabled:opacity-40">
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Actualizar
          </button>
          <button onClick={() => setShowNew(true)}
            className="flex items-center gap-1.5 text-xs bg-cyan-700 hover:bg-cyan-600 text-white px-3 py-1.5 rounded transition-colors">
            <Plus size={13} /> Nueva llave
          </button>
        </div>
      </div>

      {error && <div className="mb-4 bg-red-900/20 border border-red-700/50 rounded p-3 text-xs text-red-400">{error}</div>}

      <div className="grid grid-cols-3 gap-3 mb-5">
        {[
          { label: 'Total llaves', value: keys.length, color: 'text-white' },
          { label: 'Activas', value: activeCount, color: activeCount > 0 ? 'text-green-400' : 'text-gray-400' },
          { label: 'Expiradas', value: expiredCount, color: expiredCount > 0 ? 'text-red-400' : 'text-gray-400' },
        ].map(s => (
          <div key={s.label} className="bg-navy-800 border border-navy-700 rounded-lg p-3 text-center">
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            <p className="text-xs text-gray-400 mt-0.5">{s.label}</p>
          </div>
        ))}
      </div>

      <div className="bg-navy-800 border border-navy-700 rounded-lg overflow-x-auto">
        {loading ? (
          <p className="text-center text-gray-500 text-sm py-10">Cargando llaves…</p>
        ) : keys.length === 0 ? (
          <div className="text-center py-12">
            <Key size={32} className="text-gray-700 mx-auto mb-3" />
            <p className="text-gray-500 text-sm">No hay API keys. Crea una para empezar.</p>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-navy-700 text-gray-400">
                <th className="px-4 py-3 text-left">Nombre</th>
                <th className="px-4 py-3 text-left">Prefijo</th>
                <th className="px-4 py-3 text-left">Scopes</th>
                <th className="px-4 py-3 text-left">Estado</th>
                <th className="px-4 py-3 text-left">Último uso</th>
                <th className="px-4 py-3 text-left">Expira</th>
                <th className="px-4 py-3 text-left">Creada</th>
                <th className="px-4 py-3 text-left">Acciones</th>
              </tr>
            </thead>
            <tbody>
              {keys.map(key => {
                const expired = key.expires_at && new Date(key.expires_at) < new Date()
                return (
                  <tr key={key.id} className={`border-b border-navy-700/50 hover:bg-navy-700/30 transition-colors ${!key.is_active || expired ? 'opacity-50' : ''}`}>
                    <td className="px-4 py-2 text-gray-200 font-medium">{key.name}</td>
                    <td className="px-4 py-2">
                      <code className="bg-navy-900 px-1.5 py-0.5 rounded text-cyan-400 text-xs">asc_{key.key_prefix}…</code>
                    </td>
                    <td className="px-4 py-2">
                      <div className="flex gap-1 flex-wrap">
                        {key.scopes.map(s => <ScopeBadge key={s} scope={s} />)}
                      </div>
                    </td>
                    <td className="px-4 py-2">
                      {expired ? (
                        <span className="text-red-400 flex items-center gap-1"><XCircle size={11} /> Expirada</span>
                      ) : key.is_active ? (
                        <span className="text-green-400 flex items-center gap-1"><CheckCircle2 size={11} /> Activa</span>
                      ) : (
                        <span className="text-gray-500 flex items-center gap-1"><XCircle size={11} /> Revocada</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-gray-400">{formatTs(key.last_used_at)}</td>
                    <td className="px-4 py-2 text-gray-400">
                      {key.expires_at
                        ? <span className={expired ? 'text-red-400' : ''}>{formatTs(key.expires_at)}</span>
                        : <span className="text-gray-600">Sin expiración</span>}
                    </td>
                    <td className="px-4 py-2 text-gray-500">{formatTs(key.created_at)}</td>
                    <td className="px-4 py-2">
                      <div className="flex gap-1">
                        <button onClick={() => handleRotate(key)} disabled={actioning === key.id}
                          title="Rotar llave"
                          className="flex items-center gap-1 px-2 py-1 rounded text-xs border border-yellow-700 text-yellow-400 hover:bg-yellow-400/10 transition-colors disabled:opacity-40">
                          <RotateCcw size={10} />{actioning === key.id ? '…' : 'Rotar'}
                        </button>
                        <button onClick={() => handleRevoke(key)} disabled={actioning === key.id}
                          title="Revocar llave"
                          className="flex items-center gap-1 px-2 py-1 rounded text-xs border border-red-700 text-red-400 hover:bg-red-400/10 transition-colors disabled:opacity-40">
                          <Trash2 size={10} />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
      <p className="mt-3 text-xs text-gray-600">{keys.length} llave(s) registrada(s)</p>
    </>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

type Tab = 'users' | 'api-keys'

export default function AdminPage() {
  const { isReady } = useAuthGuard('admin')

  const [activeTab, setActiveTab] = useState<Tab>('users')
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null)

  function showToast(msg: string, ok: boolean) { setToast({ msg, ok }) }

  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 3500)
    return () => clearTimeout(t)
  }, [toast])

  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: 'users',    label: 'Usuarios',  icon: <Users size={14} /> },
    { id: 'api-keys', label: 'API Keys',  icon: <Key size={14} /> },
  ]

  if (!isReady) return <AuthLoader />

  return (
    <div className="flex min-h-screen bg-navy-900 text-white">
      <Sidebar />
      <main className="flex-1 p-6 overflow-y-auto">
        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <ShieldAlert size={22} className="text-cyan-400" />
          <div>
            <h1 className="text-xl font-bold text-white">Administración</h1>
            <p className="text-xs text-gray-400">IAM · API Keys · Seguridad</p>
          </div>
        </div>

        <Toast toast={toast} onClose={() => setToast(null)} />

        {/* Tabs */}
        <div className="flex gap-1 mb-6 border-b border-navy-700">
          {tabs.map(tab => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-t transition-colors ${
                activeTab === tab.id
                  ? 'bg-navy-800 text-cyan-400 border border-b-navy-800 border-navy-700 -mb-px'
                  : 'text-gray-500 hover:text-gray-300'
              }`}>
              {tab.icon}{tab.label}
            </button>
          ))}
        </div>

        {activeTab === 'users'    && <UsersTab showToast={showToast} />}
        {activeTab === 'api-keys' && <ApiKeysTab showToast={showToast} />}
      </main>
    </div>
  )
}
