'use client'
import { useState, useEffect, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'
import {
  listAdapters, testAdapterStatus,
  elkPushAlert, elkPushEvent, elkPullEvents,
  wazuhPullAlerts, wazuhGetAgents,
  thehiveCreateCase, thehiveAddObservable, thehiveGetCase,
  firewallBlockIP, firewallUnblockIP, firewallBlockDomain, firewallUnblockDomain,
  identityDisableAccount, identityEnableAccount,
  identityForcePasswordReset, identityQuarantineAccount,
  AdapterInfo,
} from '@/lib/api'
import {
  Network, CheckCircle2, XCircle, RefreshCw, Activity,
  ArrowDownCircle, ArrowUpCircle, Server, Users,
  Briefcase, Eye, Plus, Loader2, AlertTriangle, type LucideIcon,
  Shield, ShieldOff, Globe, GlobeIcon, UserX, UserCheck, KeyRound, MapPin,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type AdapterTab = 'elk' | 'wazuh' | 'thehive' | 'firewall' | 'identity'

interface OpResult {
  op: string
  ts: string
  ok: boolean
  data: unknown
}

// ─── Constants ────────────────────────────────────────────────────────────────

const TYPE_STYLE: Record<string, string> = {
  SIEM:      'text-blue-400   bg-blue-400/10   border-blue-400/30',
  'EDR/HIDS':'text-orange-400 bg-orange-400/10 border-orange-400/30',
  SOAR:      'text-purple-400 bg-purple-400/10 border-purple-400/30',
  Firewall:  'text-red-400    bg-red-400/10    border-red-400/30',
  IAM:       'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
}

const ADAPTER_TABS: { id: AdapterTab; label: string }[] = [
  { id: 'elk',      label: 'ELK / Elasticsearch' },
  { id: 'wazuh',    label: 'Wazuh'               },
  { id: 'thehive',  label: 'TheHive'              },
  { id: 'firewall', label: 'Firewall'             },
  { id: 'identity', label: 'Identidad / AD'       },
]

// ─── Sub-components ───────────────────────────────────────────────────────────

function TypeBadge({ type }: { type: string }) {
  const cls = TYPE_STYLE[type] ?? 'text-gray-400 bg-gray-400/10 border-gray-400/30'
  return (
    <span className={`border rounded px-2 py-0.5 text-xs font-semibold ${cls}`}>
      {type}
    </span>
  )
}

function ConfigBadge({ configured }: { configured: boolean }) {
  return configured ? (
    <span className="flex items-center gap-1 text-green-400 text-xs font-medium">
      <CheckCircle2 size={13} /> Configurado
    </span>
  ) : (
    <span className="flex items-center gap-1 text-gray-500 text-xs font-medium">
      <XCircle size={13} /> No configurado
    </span>
  )
}

// Each operation lives in a card with a title, description, inputs, and action button.
function OpCard({
  icon: Icon,
  title,
  description,
  children,
}: {
  icon: LucideIcon
  title: string
  description: string
  children: React.ReactNode
}) {
  return (
    <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
      <div className="flex items-center gap-2 mb-1">
        <Icon size={15} className="text-cyan-400" />
        <h4 className="text-sm font-semibold text-white">{title}</h4>
      </div>
      <p className="text-xs text-gray-500 mb-3">{description}</p>
      {children}
    </div>
  )
}

function Input({
  value, onChange, placeholder, className = '',
}: {
  value: string | number
  onChange: (v: string) => void
  placeholder?: string
  className?: string
}) {
  return (
    <input
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      className={`bg-navy-900 border border-navy-700 text-sm text-gray-200 rounded px-3 py-1.5 outline-none focus:border-cyan-400 placeholder-gray-600 ${className}`}
    />
  )
}

function NumInput({
  value, onChange, min = 1, className = '',
}: {
  value: number
  onChange: (v: number) => void
  min?: number
  className?: string
}) {
  return (
    <input
      type="number"
      value={value}
      min={min}
      onChange={e => onChange(Math.max(min, Number(e.target.value)))}
      className={`bg-navy-900 border border-navy-700 text-sm text-gray-200 rounded px-3 py-1.5 outline-none focus:border-cyan-400 w-20 ${className}`}
    />
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function AdaptersPage() {
  const { isReady } = useAuthGuard()

  const [adapters, setAdapters]   = useState<AdapterInfo[]>([])
  const [loading, setLoading]     = useState(true)
  const [activeTab, setActiveTab] = useState<AdapterTab>('elk')
  const [operating, setOperating] = useState(false)
  const [result, setResult]       = useState<OpResult | null>(null)

  // Test-connection state per adapter
  const [testing, setTesting]     = useState<string | null>(null)
  const [testRes, setTestRes]     = useState<Record<string, { ok: boolean; msg: string }>>({})

  // ELK form
  const [elkAlertId, setElkAlertId] = useState('')
  const [elkEventId, setElkEventId] = useState('')
  const [elkHours,   setElkHours]   = useState(1)
  const [elkSize,    setElkSize]    = useState(100)

  // Wazuh form
  const [wzHours,  setWzHours]  = useState(1)
  const [wzLimit,  setWzLimit]  = useState(100)
  const [wzStatus, setWzStatus] = useState('active')

  // TheHive form
  const [hiveAlertId,  setHiveAlertId]  = useState('')
  const [hiveCaseId,   setHiveCaseId]   = useState('')
  const [hiveIocId,    setHiveIocId]    = useState('')
  const [hiveLookupId, setHiveLookupId] = useState('')

  // Firewall form (shared IP and Domain + per-op reason)
  const [fwIp,        setFwIp]        = useState('')
  const [fwIpReason,  setFwIpReason]  = useState('')
  const [fwDomain,    setFwDomain]    = useState('')
  const [fwDomReason, setFwDomReason] = useState('')

  // Identity / Active Directory form
  const [idUsername, setIdUsername] = useState('')
  const [idDomain,   setIdDomain]   = useState('')
  const [idReason,   setIdReason]   = useState('')

  // ── Data loading ──────────────────────────────────────────────────────────

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await listAdapters()
      setAdapters(res.adapters)
    } catch {
      setAdapters([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { if (!isReady) return; load() }, [load, isReady])

  // ── Test connection ───────────────────────────────────────────────────────

  async function testConnection(name: string) {
    setTesting(name)
    try {
      const res = await testAdapterStatus(name)
      const latency = (res.latency_ms as number | undefined)
      setTestRes(prev => ({
        ...prev,
        [name]: { ok: true, msg: latency !== undefined ? `OK · ${latency}ms` : 'OK' },
      }))
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setTestRes(prev => ({
        ...prev,
        [name]: { ok: false, msg: detail ?? 'Sin conexión' },
      }))
    } finally {
      setTesting(null)
    }
  }

  // ── Generic operation executor ────────────────────────────────────────────

  async function callOp(opName: string, fn: () => Promise<unknown>) {
    setOperating(true)
    setResult(null)
    try {
      const data = await fn()
      setResult({ op: opName, ts: new Date().toISOString(), ok: true, data })
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
        ?? (err as Error)?.message
        ?? 'Error desconocido'
      setResult({ op: opName, ts: new Date().toISOString(), ok: false, data: { error: detail } })
    } finally {
      setOperating(false)
    }
  }

  // ─────────────────────────────────────────────────────────────────────────

  if (!isReady) return <AuthLoader />

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6 space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Integraciones — SIEM · EDR · SOAR · Firewall · IAM</h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Estado de adaptadores y operaciones de ingesta, bloqueo e identidad
            </p>
          </div>
          <button
            onClick={load}
            disabled={loading}
            className="btn-primary flex items-center gap-2 text-sm py-1.5"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Refrescar
          </button>
        </div>

        {/* Adapter status cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {loading ? (
            <div className="col-span-3 text-gray-400 text-sm">Cargando adaptadores…</div>
          ) : adapters.length === 0 ? (
            <div className="col-span-3 text-gray-500 text-sm">Sin adaptadores disponibles.</div>
          ) : adapters.map(adapter => (
            <div
              key={adapter.name}
              className={`card border rounded-lg p-4 transition-colors ${
                activeTab === adapter.name
                  ? 'border-cyan-400/40'
                  : 'border-navy-700'
              }`}
            >
              <div className="flex items-start justify-between mb-2">
                <div>
                  <p className="text-white font-semibold text-sm">{adapter.label}</p>
                  <div className="flex items-center gap-2 mt-1">
                    <TypeBadge type={adapter.type} />
                    <ConfigBadge configured={adapter.configured} />
                  </div>
                </div>
                <Network size={20} className="text-navy-600 mt-0.5" />
              </div>

              <p className="text-xs text-gray-500 mb-3 leading-relaxed">{adapter.description}</p>

              <div className="flex items-center justify-between">
                <button
                  onClick={() => testConnection(adapter.name)}
                  disabled={testing === adapter.name || !adapter.configured}
                  className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border border-navy-600 text-gray-300 hover:border-cyan-400 hover:text-cyan-400 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {testing === adapter.name
                    ? <Loader2 size={12} className="animate-spin" />
                    : <Activity size={12} />
                  }
                  Test Conexión
                </button>

                {testRes[adapter.name] && (
                  <span className={`text-xs font-medium flex items-center gap-1 ${
                    testRes[adapter.name].ok ? 'text-green-400' : 'text-red-400'
                  }`}>
                    {testRes[adapter.name].ok
                      ? <CheckCircle2 size={12} />
                      : <XCircle size={12} />
                    }
                    {testRes[adapter.name].msg}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Operations panel */}
        <div className="card border border-navy-700 rounded-lg overflow-hidden">

          {/* Tab bar */}
          <div className="flex border-b border-navy-700">
            {ADAPTER_TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-5 py-3 text-sm font-medium transition-colors border-b-2 ${
                  activeTab === tab.id
                    ? 'border-cyan-400 text-cyan-400'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="p-5 space-y-4">

            {/* ── ELK Tab ─────────────────────────────────────────────────── */}
            {activeTab === 'elk' && (
              <>
                <OpCard
                  icon={ArrowUpCircle}
                  title="Push Alerta → Elasticsearch"
                  description="Indexa una alerta de ASC en Elasticsearch para búsqueda y correlación en ELK."
                >
                  <div className="flex items-center gap-2">
                    <Input
                      value={elkAlertId}
                      onChange={setElkAlertId}
                      placeholder="Alert ID (UUID)"
                      className="flex-1"
                    />
                    <button
                      onClick={() => callOp('elk_push_alert', () => elkPushAlert(elkAlertId))}
                      disabled={operating || !elkAlertId.trim()}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <ArrowUpCircle size={12} />}
                      Push
                    </button>
                  </div>
                </OpCard>

                <OpCard
                  icon={ArrowUpCircle}
                  title="Push Evento → Elasticsearch"
                  description="Indexa un evento de ASC en Elasticsearch para análisis histórico."
                >
                  <div className="flex items-center gap-2">
                    <Input
                      value={elkEventId}
                      onChange={setElkEventId}
                      placeholder="Event ID (UUID)"
                      className="flex-1"
                    />
                    <button
                      onClick={() => callOp('elk_push_event', () => elkPushEvent(elkEventId))}
                      disabled={operating || !elkEventId.trim()}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <ArrowUpCircle size={12} />}
                      Push
                    </button>
                  </div>
                </OpCard>

                <OpCard
                  icon={ArrowDownCircle}
                  title="Pull Eventos ← Elasticsearch"
                  description="Importa eventos desde ELK hacia ASC para enriquecer el contexto de detección."
                >
                  <div className="flex items-center gap-3 flex-wrap">
                    <label className="flex items-center gap-2 text-xs text-gray-400">
                      Últimas
                      <NumInput value={elkHours} onChange={setElkHours} />
                      horas
                    </label>
                    <label className="flex items-center gap-2 text-xs text-gray-400">
                      Límite
                      <NumInput value={elkSize} onChange={setElkSize} />
                      eventos
                    </label>
                    <button
                      onClick={() => callOp('elk_pull_events', () => elkPullEvents(elkHours, elkSize))}
                      disabled={operating}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <ArrowDownCircle size={12} />}
                      Importar
                    </button>
                  </div>
                </OpCard>
              </>
            )}

            {/* ── Wazuh Tab ───────────────────────────────────────────────── */}
            {activeTab === 'wazuh' && (
              <>
                <OpCard
                  icon={ArrowDownCircle}
                  title="Pull Alertas Wazuh → ASC"
                  description="Importa alertas HIDS de Wazuh Manager y las convierte en eventos de ASC para correlación."
                >
                  <div className="flex items-center gap-3 flex-wrap">
                    <label className="flex items-center gap-2 text-xs text-gray-400">
                      Últimas
                      <NumInput value={wzHours} onChange={setWzHours} />
                      horas
                    </label>
                    <label className="flex items-center gap-2 text-xs text-gray-400">
                      Límite
                      <NumInput value={wzLimit} onChange={setWzLimit} />
                      alertas
                    </label>
                    <button
                      onClick={() => callOp('wazuh_pull_alerts', () => wazuhPullAlerts(wzHours, wzLimit))}
                      disabled={operating}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <ArrowDownCircle size={12} />}
                      Importar Alertas
                    </button>
                  </div>
                </OpCard>

                <OpCard
                  icon={Users}
                  title="Inventario de Agentes Wazuh"
                  description="Lista los agentes registrados en Wazuh Manager con su estado, IP y versión."
                >
                  <div className="flex items-center gap-3 flex-wrap">
                    <label className="flex items-center gap-2 text-xs text-gray-400">
                      Estado
                      <select
                        value={wzStatus}
                        onChange={e => setWzStatus(e.target.value)}
                        className="bg-navy-900 border border-navy-700 text-sm text-gray-300 rounded px-2 py-1.5 outline-none focus:border-cyan-400"
                      >
                        {['active', 'disconnected', 'pending', 'never_connected'].map(s => (
                          <option key={s} value={s}>{s}</option>
                        ))}
                      </select>
                    </label>
                    <button
                      onClick={() => callOp('wazuh_get_agents', () => wazuhGetAgents(wzStatus))}
                      disabled={operating}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <Server size={12} />}
                      Listar Agentes
                    </button>
                  </div>
                </OpCard>
              </>
            )}

            {/* ── Firewall Tab ─────────────────────────────────────────────── */}
            {activeTab === 'firewall' && (
              <>
                <p className="text-xs text-gray-500 -mt-1 mb-2">
                  Las operaciones usan PAN-OS si está configurado, Fortinet como fallback.
                </p>

                <OpCard
                  icon={Shield}
                  title="Bloquear IP"
                  description="Crea un objeto de dirección en el firewall activo y lo agrega al grupo ASC-Blocked-IPs."
                >
                  <div className="flex flex-col gap-2">
                    <div className="flex gap-2">
                      <Input value={fwIp} onChange={setFwIp} placeholder="IP (ej. 203.0.113.5)" className="flex-1" />
                      <Input value={fwIpReason} onChange={setFwIpReason} placeholder="Motivo (opcional)" className="flex-1" />
                    </div>
                    <div className="flex justify-end">
                      <button
                        onClick={() => callOp('firewall_block_ip', () => firewallBlockIP(fwIp, fwIpReason))}
                        disabled={operating || !fwIp.trim()}
                        className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40"
                      >
                        {operating ? <Loader2 size={12} className="animate-spin" /> : <Shield size={12} />}
                        Bloquear
                      </button>
                    </div>
                  </div>
                </OpCard>

                <OpCard
                  icon={ShieldOff}
                  title="Desbloquear IP"
                  description="Elimina la IP del grupo ASC-Blocked-IPs y borra el objeto de dirección del firewall."
                >
                  <div className="flex items-center gap-2">
                    <Input value={fwIp} onChange={setFwIp} placeholder="IP (ej. 203.0.113.5)" className="flex-1" />
                    <button
                      onClick={() => callOp('firewall_unblock_ip', () => firewallUnblockIP(fwIp))}
                      disabled={operating || !fwIp.trim()}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <ShieldOff size={12} />}
                      Desbloquear
                    </button>
                  </div>
                </OpCard>

                <OpCard
                  icon={Globe}
                  title="Bloquear Dominio"
                  description="Agrega el dominio a la categoría personalizada ASC-Blocked-Domains en el firewall activo."
                >
                  <div className="flex flex-col gap-2">
                    <div className="flex gap-2">
                      <Input value={fwDomain} onChange={setFwDomain} placeholder="Dominio (ej. evil.example.com)" className="flex-1" />
                      <Input value={fwDomReason} onChange={setFwDomReason} placeholder="Motivo (opcional)" className="flex-1" />
                    </div>
                    <div className="flex justify-end">
                      <button
                        onClick={() => callOp('firewall_block_domain', () => firewallBlockDomain(fwDomain, fwDomReason))}
                        disabled={operating || !fwDomain.trim()}
                        className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40"
                      >
                        {operating ? <Loader2 size={12} className="animate-spin" /> : <Globe size={12} />}
                        Bloquear
                      </button>
                    </div>
                  </div>
                </OpCard>

                <OpCard
                  icon={GlobeIcon}
                  title="Desbloquear Dominio"
                  description="Elimina el dominio de ASC-Blocked-Domains en el firewall activo."
                >
                  <div className="flex items-center gap-2">
                    <Input value={fwDomain} onChange={setFwDomain} placeholder="Dominio (ej. evil.example.com)" className="flex-1" />
                    <button
                      onClick={() => callOp('firewall_unblock_domain', () => firewallUnblockDomain(fwDomain))}
                      disabled={operating || !fwDomain.trim()}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <GlobeIcon size={12} />}
                      Desbloquear
                    </button>
                  </div>
                </OpCard>
              </>
            )}

            {/* ── Identity Tab ──────────────────────────────────────────────── */}
            {activeTab === 'identity' && (
              <>
                <p className="text-xs text-gray-500 -mt-1 mb-2">
                  Requiere adaptador de Active Directory configurado (AD_* en variables de entorno).
                </p>

                {/* Shared identity fields */}
                <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
                  <p className="text-xs text-gray-400 mb-2 font-medium">Cuenta objetivo</p>
                  <div className="flex gap-2 flex-wrap">
                    <Input value={idUsername} onChange={setIdUsername} placeholder="Usuario (sAMAccountName)" className="flex-1 min-w-36" />
                    <Input value={idDomain}   onChange={setIdDomain}   placeholder="Dominio (ej. corp.local)"  className="flex-1 min-w-36" />
                    <Input value={idReason}   onChange={setIdReason}   placeholder="Motivo (opcional)"          className="flex-1 min-w-36" />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <OpCard
                    icon={UserX}
                    title="Deshabilitar Cuenta"
                    description="Activa el flag UF_ACCOUNTDISABLE en userAccountControl. El usuario no podrá iniciar sesión."
                  >
                    <button
                      onClick={() => callOp('identity_disable', () => identityDisableAccount(idUsername, idDomain, idReason))}
                      disabled={operating || !idUsername.trim() || !idDomain.trim()}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40 w-full justify-center"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <UserX size={12} />}
                      Deshabilitar
                    </button>
                  </OpCard>

                  <OpCard
                    icon={UserCheck}
                    title="Habilitar Cuenta"
                    description="Limpia UF_ACCOUNTDISABLE y restaura el acceso del usuario al dominio."
                  >
                    <button
                      onClick={() => callOp('identity_enable', () => identityEnableAccount(idUsername, idDomain))}
                      disabled={operating || !idUsername.trim() || !idDomain.trim()}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40 w-full justify-center"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <UserCheck size={12} />}
                      Habilitar
                    </button>
                  </OpCard>

                  <OpCard
                    icon={KeyRound}
                    title="Forzar Reset de Contraseña"
                    description="Establece pwdLastSet = 0; el usuario debe cambiar su contraseña en el próximo inicio de sesión."
                  >
                    <button
                      onClick={() => callOp('identity_force_reset', () => identityForcePasswordReset(idUsername, idDomain))}
                      disabled={operating || !idUsername.trim() || !idDomain.trim()}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40 w-full justify-center"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <KeyRound size={12} />}
                      Forzar Reset
                    </button>
                  </OpCard>

                  <OpCard
                    icon={MapPin}
                    title="Mover a OU de Cuarentena"
                    description="Mueve la cuenta a AD_QUARANTINE_OU mediante LDAP modifyDN para aislarla del dominio principal."
                  >
                    <button
                      onClick={() => callOp('identity_quarantine', () => identityQuarantineAccount(idUsername, idDomain))}
                      disabled={operating || !idUsername.trim() || !idDomain.trim()}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40 w-full justify-center"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <MapPin size={12} />}
                      Cuarentena
                    </button>
                  </OpCard>
                </div>
              </>
            )}

            {/* ── TheHive Tab ─────────────────────────────────────────────── */}
            {activeTab === 'thehive' && (
              <>
                <OpCard
                  icon={Briefcase}
                  title="Crear Caso TheHive desde Alerta ASC"
                  description="Escala una alerta de ASC a TheHive como caso de investigación SOAR."
                >
                  <div className="flex items-center gap-2">
                    <Input
                      value={hiveAlertId}
                      onChange={setHiveAlertId}
                      placeholder="Alert ID (UUID) de ASC"
                      className="flex-1"
                    />
                    <button
                      onClick={() => callOp('thehive_create_case', () => thehiveCreateCase(hiveAlertId))}
                      disabled={operating || !hiveAlertId.trim()}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <Plus size={12} />}
                      Crear Caso
                    </button>
                  </div>
                </OpCard>

                <OpCard
                  icon={Plus}
                  title="Añadir Observable (IoC) a Caso"
                  description="Agrega un IoC de ASC como observable a un caso existente de TheHive."
                >
                  <div className="flex flex-col gap-2">
                    <div className="flex gap-2">
                      <Input
                        value={hiveCaseId}
                        onChange={setHiveCaseId}
                        placeholder="Case ID de TheHive"
                        className="flex-1"
                      />
                      <Input
                        value={hiveIocId}
                        onChange={setHiveIocId}
                        placeholder="IoC ID (UUID) de ASC"
                        className="flex-1"
                      />
                    </div>
                    <div className="flex justify-end">
                      <button
                        onClick={() => callOp('thehive_add_observable', () => thehiveAddObservable(hiveCaseId, hiveIocId))}
                        disabled={operating || !hiveCaseId.trim() || !hiveIocId.trim()}
                        className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40"
                      >
                        {operating ? <Loader2 size={12} className="animate-spin" /> : <Plus size={12} />}
                        Añadir Observable
                      </button>
                    </div>
                  </div>
                </OpCard>

                <OpCard
                  icon={Eye}
                  title="Consultar Estado de Caso"
                  description="Obtiene el estado actual, descripción y observables de un caso TheHive por su ID."
                >
                  <div className="flex items-center gap-2">
                    <Input
                      value={hiveLookupId}
                      onChange={setHiveLookupId}
                      placeholder="Case ID de TheHive"
                      className="flex-1"
                    />
                    <button
                      onClick={() => callOp('thehive_get_case', () => thehiveGetCase(hiveLookupId))}
                      disabled={operating || !hiveLookupId.trim()}
                      className="btn-primary text-xs py-1.5 px-4 flex items-center gap-1.5 disabled:opacity-40"
                    >
                      {operating ? <Loader2 size={12} className="animate-spin" /> : <Eye size={12} />}
                      Consultar
                    </button>
                  </div>
                </OpCard>
              </>
            )}
          </div>
        </div>

        {/* Result panel */}
        {result && (
          <div className={`card border rounded-lg overflow-hidden ${
            result.ok ? 'border-green-400/30' : 'border-red-400/30'
          }`}>
            {/* Result header */}
            <div className={`flex items-center justify-between px-4 py-2.5 border-b ${
              result.ok
                ? 'bg-green-400/5 border-green-400/20'
                : 'bg-red-400/5 border-red-400/20'
            }`}>
              <div className="flex items-center gap-2">
                {result.ok
                  ? <CheckCircle2 size={14} className="text-green-400" />
                  : <AlertTriangle size={14} className="text-red-400" />
                }
                <span className={`text-sm font-semibold ${result.ok ? 'text-green-400' : 'text-red-400'}`}>
                  {result.ok ? 'Éxito' : 'Error'}
                </span>
                <span className="text-gray-500 text-xs font-mono">
                  · {result.op}
                </span>
              </div>
              <span className="text-xs text-gray-600 font-mono">
                {new Date(result.ts).toLocaleTimeString('es', { hour12: false })}
              </span>
            </div>

            {/* JSON response */}
            <pre className="p-4 text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-72">
              {JSON.stringify(result.data, null, 2)}
            </pre>
          </div>
        )}

      </main>
    </div>
  )
}
