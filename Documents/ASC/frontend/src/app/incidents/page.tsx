'use client'

import { useEffect, useState, useCallback } from 'react'
import {
  ClipboardList, Shield, AlertTriangle, Clock, CheckCircle,
  XCircle, RefreshCw, ChevronDown, ChevronUp, Activity,
  Link2, FileText, User, BarChart3, Zap, ShieldAlert, Lock,
  Wifi, WifiOff,
} from 'lucide-react'
import clsx from 'clsx'
import { useSSENotifications } from '@/lib/useSSENotifications'
import {
  getIncidentSummary, listIncidents, createIncident, getIncident,
  transitionIncidentStatus, addIncidentNote, closeIncident, dismissIncident,
  getIncidentTimeline, listIncidentLinks, addIncidentLink,
  getPiilBinding, getSoarEvents,
  Incident, IncidentSummary, IncidentTimelineEntry, IncidentLink, ForensicEntry,
} from '@/lib/api'

// ── Constants & helpers ───────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/30',
  high:     'text-orange-400 bg-orange-400/10 border-orange-400/30',
  medium:   'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  low:      'text-cyan-400 bg-cyan-400/10 border-cyan-400/30',
  info:     'text-gray-400 bg-gray-400/10 border-gray-400/30',
}

const STATUS_COLORS: Record<string, string> = {
  detected:      'text-red-400 bg-red-400/10',
  triaged:       'text-orange-400 bg-orange-400/10',
  contained:     'text-yellow-400 bg-yellow-400/10',
  eradicated:    'text-lime-400 bg-lime-400/10',
  recovered:     'text-green-400 bg-green-400/10',
  post_incident: 'text-blue-400 bg-blue-400/10',
  closed:        'text-gray-400 bg-gray-400/10',
  dismissed:     'text-gray-600 bg-gray-800',
}

const NIST_PHASES = [
  { key: 'detection_analysis',    label: 'Detection & Analysis' },
  { key: 'containment',           label: 'Containment' },
  { key: 'eradication',           label: 'Eradication' },
  { key: 'recovery',              label: 'Recovery' },
  { key: 'post_incident_activity', label: 'Post-Incident' },
]

const NIST_STATUS_MAP: Record<string, string> = {
  detected:      'detection_analysis',
  triaged:       'detection_analysis',
  contained:     'containment',
  eradicated:    'eradication',
  recovered:     'recovery',
  post_incident: 'post_incident_activity',
  closed:        'post_incident_activity',
  dismissed:     'post_incident_activity',
}

const VALID_TRANSITIONS: Record<string, string[]> = {
  detected:      ['triaged', 'dismissed'],
  triaged:       ['contained', 'dismissed'],
  contained:     ['eradicated', 'triaged'],
  eradicated:    ['recovered', 'contained'],
  recovered:     ['post_incident', 'eradicated'],
  post_incident: ['closed'],
  closed:        [],
  dismissed:     [],
}

const INCIDENT_TYPES = [
  'malware', 'ransomware', 'phishing', 'data_breach', 'insider_threat',
  'apt', 'ddos', 'credential_abuse', 'lateral_movement',
  'supply_chain', 'vulnerability_exploit', 'other',
]

function fmtMins(mins: number | null): string {
  if (mins === null || mins === undefined) return '—'
  if (mins < 60) return `${mins}m`
  const h = Math.floor(mins / 60)
  const m = mins % 60
  return m > 0 ? `${h}h ${m}m` : `${h}h`
}

function SevBadge({ sev }: { sev: string }) {
  return (
    <span className={clsx('text-xs font-semibold px-2 py-0.5 rounded border', SEV_COLORS[sev] ?? SEV_COLORS.info)}>
      {sev.toUpperCase()}
    </span>
  )
}

function StatusBadge({ st }: { st: string }) {
  return (
    <span className={clsx('text-xs font-semibold px-2 py-0.5 rounded', STATUS_COLORS[st] ?? 'text-gray-400 bg-gray-800')}>
      {st.replace('_', ' ').toUpperCase()}
    </span>
  )
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

// ── NIST Phase Progress Bar ───────────────────────────────────────────────────

function NistPhaseBar({ status }: { status: string }) {
  const currentPhase = NIST_STATUS_MAP[status] ?? ''
  const isDismissed = status === 'dismissed'
  const isClosed = status === 'closed'
  const phaseIdx = NIST_PHASES.findIndex(p => p.key === currentPhase)

  return (
    <div className="flex gap-1 items-center">
      {NIST_PHASES.map((phase, idx) => {
        const done = idx < phaseIdx || isClosed
        const active = idx === phaseIdx && !isClosed && !isDismissed
        return (
          <div key={phase.key} className="flex-1 text-center">
            <div className={clsx(
              'h-1.5 rounded-full mb-1',
              isDismissed ? 'bg-gray-700' :
              done ? 'bg-green-500' :
              active ? 'bg-cyan-400' : 'bg-navy-700'
            )} />
            <p className={clsx(
              'text-[9px] leading-tight hidden sm:block',
              active ? 'text-cyan-400 font-semibold' : 'text-gray-600'
            )}>{phase.label}</p>
          </div>
        )
      })}
    </div>
  )
}

// ── Timeline ──────────────────────────────────────────────────────────────────

function TimelinePanel({ incidentId }: { incidentId: string }) {
  const [entries, setEntries] = useState<IncidentTimelineEntry[]>([])
  const [note, setNote] = useState('')
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)

  const load = useCallback(async () => {
    try {
      const r = await getIncidentTimeline(incidentId)
      setEntries(r.items)
    } finally {
      setLoading(false)
    }
  }, [incidentId])

  useEffect(() => { load() }, [load])

  async function submitNote() {
    if (!note.trim()) return
    setSubmitting(true)
    try {
      await addIncidentNote(incidentId, note.trim())
      setNote('')
      await load()
    } catch { /* noop */ }
    finally { setSubmitting(false) }
  }

  const TL_ICONS: Record<string, React.ElementType> = {
    created:          Shield,
    status_change:    Activity,
    assignment:       User,
    link_added:       Link2,
    note_added:       FileText,
    closed:           CheckCircle,
    soar_triggered:   Zap,
    sla_warning:      ShieldAlert,
  }

  const TL_ACCENT: Record<string, string> = {
    soar_triggered: 'bg-purple-500/20 text-purple-400',
    sla_warning:    'bg-red-500/20 text-red-400',
  }

  return (
    <div className="space-y-3">
      {loading ? (
        <p className="text-gray-500 text-sm">Cargando...</p>
      ) : entries.length === 0 ? (
        <p className="text-gray-600 text-sm">Sin eventos aún.</p>
      ) : (
        <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
          {entries.map(e => {
            const Icon = TL_ICONS[e.event_type] ?? Activity
            const accent = TL_ACCENT[e.event_type]
            const isSoar = e.event_type === 'soar_triggered'
            const isSla  = e.event_type === 'sla_warning'
            return (
              <div key={e.id} className={clsx(
                'flex items-start gap-2 text-sm rounded',
                (isSoar || isSla) && 'bg-navy-900/50 px-2 py-1 border-l-2',
                isSoar && 'border-purple-500/50',
                isSla  && 'border-red-500/50',
              )}>
                <div className={clsx('p-1 rounded mt-0.5', accent ?? 'bg-navy-700')}>
                  <Icon size={12} className={accent ? '' : 'text-cyan-400'} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={clsx(
                      'font-medium text-xs',
                      isSoar ? 'text-purple-300' : isSla ? 'text-red-300' : 'text-white'
                    )}>
                      {e.event_type.replace(/_/g, ' ')}
                    </span>
                    {isSoar && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400 font-semibold">
                        SOAR
                      </span>
                    )}
                    {isSla && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 font-semibold">
                        SLA
                      </span>
                    )}
                    <span className="text-gray-600 text-xs">{e.actor}</span>
                    <span className="text-gray-700 text-xs ml-auto">
                      {e.created_at ? new Date(e.created_at).toLocaleString() : '—'}
                    </span>
                  </div>
                  {e.event_type === 'note_added' && (
                    <p className="text-gray-400 text-xs mt-0.5">{(e.detail as any).text}</p>
                  )}
                  {e.event_type === 'status_change' && (
                    <p className="text-gray-500 text-xs">
                      {(e.detail as any).from} → {(e.detail as any).to}
                    </p>
                  )}
                  {isSoar && (e.detail as any).trigger_name && (
                    <p className="text-purple-400/70 text-xs mt-0.5">
                      Trigger: {(e.detail as any).trigger_name}
                      {(e.detail as any).playbook_id && ` · Playbook: ${(e.detail as any).playbook_id}`}
                    </p>
                  )}
                  {isSla && (
                    <p className="text-red-400/70 text-xs mt-0.5">
                      SLA excedido — {(e.detail as any).sla_minutes ?? '—'}m límite
                    </p>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
      <div className="flex gap-2 mt-2">
        <input
          className="flex-1 bg-navy-900 border border-navy-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500"
          placeholder="Agregar nota de analista…"
          value={note}
          onChange={e => setNote(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') submitNote() }}
        />
        <button
          onClick={submitNote}
          disabled={submitting || !note.trim()}
          className="px-3 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-navy-900 font-semibold text-sm rounded disabled:opacity-40"
        >
          Enviar
        </button>
      </div>
    </div>
  )
}

// ── Incident Detail Panel ─────────────────────────────────────────────────────

function IncidentDetail({
  incident, onRefresh, onClose,
}: {
  incident: Incident
  onRefresh: () => void
  onClose: () => void
}) {
  const [transitioning, setTransitioning] = useState(false)
  const [dismissing, setDismissing] = useState(false)
  const [closing, setClosing] = useState(false)
  const [closingForm, setClosingForm] = useState({ lessons_learned: '', root_cause: '', executive_summary: '' })
  const [showClose, setShowClose] = useState(false)
  const [tab, setTab] = useState<'timeline' | 'links' | 'piil'>('timeline')
  const [links, setLinks] = useState<IncidentLink[]>([])
  const [loadingLinks, setLoadingLinks] = useState(false)
  const [piilEntries, setPiilEntries] = useState<ForensicEntry[]>([])
  const [loadingPiil, setLoadingPiil] = useState(false)

  const transitions = VALID_TRANSITIONS[incident.status] ?? []
  const canClose = ['recovered', 'eradicated', 'post_incident'].includes(incident.status)
  const canDismiss = ['detected', 'triaged'].includes(incident.status)

  async function doTransition(s: string) {
    setTransitioning(true)
    try {
      await transitionIncidentStatus(incident.id, s)
      onRefresh()
    } catch { /* noop */ }
    finally { setTransitioning(false) }
  }

  async function doDismiss() {
    setDismissing(true)
    try {
      await dismissIncident(incident.id)
      onRefresh()
    } catch { /* noop */ }
    finally { setDismissing(false) }
  }

  async function doClose() {
    setClosing(true)
    try {
      await closeIncident(incident.id, {
        lessons_learned: closingForm.lessons_learned || undefined,
        root_cause: closingForm.root_cause || undefined,
        executive_summary: closingForm.executive_summary || undefined,
      })
      setShowClose(false)
      onRefresh()
    } catch { /* noop */ }
    finally { setClosing(false) }
  }

  async function loadLinks() {
    setLoadingLinks(true)
    try {
      const r = await listIncidentLinks(incident.id)
      setLinks(r.items)
    } finally {
      setLoadingLinks(false)
    }
  }

  async function loadPiil() {
    setLoadingPiil(true)
    try {
      const r = await getPiilBinding(incident.id)
      setPiilEntries(r.items)
    } finally {
      setLoadingPiil(false)
    }
  }

  useEffect(() => {
    if (tab === 'links') loadLinks()
    if (tab === 'piil') loadPiil()
  }, [tab])

  return (
    <div className="bg-navy-800 border border-navy-700 rounded-lg p-5 space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <SevBadge sev={incident.severity} />
            <StatusBadge st={incident.status} />
            {incident.sla_breach && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-red-900 text-red-300 border border-red-700">
                SLA BREACH
              </span>
            )}
            <span className="text-xs text-gray-600 ml-auto">ID: {incident.id.slice(0, 8)}…</span>
          </div>
          <h2 className="text-white font-bold text-lg leading-tight">{incident.title}</h2>
          {incident.description && (
            <p className="text-gray-400 text-sm mt-1">{incident.description}</p>
          )}
        </div>
        <button onClick={onClose} className="text-gray-600 hover:text-gray-300 shrink-0">
          <XCircle size={20} />
        </button>
      </div>

      {/* NIST Phase Bar */}
      <div>
        <p className="text-xs text-gray-500 mb-2 font-semibold uppercase tracking-wide">Fase NIST 800-61</p>
        <NistPhaseBar status={incident.status} />
      </div>

      {/* KPI metrics */}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-navy-900 rounded p-3 text-center">
          <p className="text-lg font-bold text-white">{fmtMins(incident.mttd_minutes)}</p>
          <p className="text-xs text-gray-500">MTTD</p>
        </div>
        <div className="bg-navy-900 rounded p-3 text-center">
          <p className="text-lg font-bold text-white">{fmtMins(incident.mttc_minutes)}</p>
          <p className="text-xs text-gray-500">MTTC</p>
        </div>
        <div className="bg-navy-900 rounded p-3 text-center">
          <p className="text-lg font-bold text-white">{fmtMins(incident.mttr_minutes)}</p>
          <p className="text-xs text-gray-500">MTTR</p>
        </div>
      </div>

      {/* Meta */}
      <div className="grid grid-cols-2 gap-2 text-xs text-gray-400">
        <div><span className="text-gray-600">Tipo: </span>{incident.incident_type}</div>
        <div><span className="text-gray-600">Creado por: </span>{incident.created_by}</div>
        <div><span className="text-gray-600">Asignado a: </span>{incident.assigned_to ?? '—'}</div>
        <div><span className="text-gray-600">SLA: </span>{incident.sla_minutes}m</div>
        {incident.mitre_tactics.length > 0 && (
          <div className="col-span-2">
            <span className="text-gray-600">MITRE Tactics: </span>
            {incident.mitre_tactics.join(', ')}
          </div>
        )}
        {incident.forensic_hash && (
          <div className="col-span-2 font-mono text-[10px] text-gray-700 break-all">
            Hash: {incident.forensic_hash.slice(0, 32)}…
          </div>
        )}
      </div>

      {/* Status transitions */}
      {transitions.filter(t => t !== 'dismissed').length > 0 && (
        <div className="flex flex-wrap gap-2">
          <span className="text-xs text-gray-500 self-center">Transicionar:</span>
          {transitions.filter(t => t !== 'dismissed').map(t => (
            <button
              key={t}
              onClick={() => doTransition(t)}
              disabled={transitioning}
              className="px-3 py-1 text-xs rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 disabled:opacity-40"
            >
              → {t.replace('_', ' ')}
            </button>
          ))}
        </div>
      )}

      {/* Close / Dismiss */}
      <div className="flex gap-2">
        {canDismiss && (
          <button
            onClick={doDismiss}
            disabled={dismissing}
            className="px-3 py-1.5 text-xs rounded bg-red-900/30 text-red-400 border border-red-700/30 hover:bg-red-900/50 disabled:opacity-40"
          >
            Descartar (FP)
          </button>
        )}
        {canClose && !showClose && (
          <button
            onClick={() => setShowClose(true)}
            className="px-3 py-1.5 text-xs rounded bg-green-900/30 text-green-400 border border-green-700/30 hover:bg-green-900/50"
          >
            Cerrar Incidente
          </button>
        )}
      </div>

      {/* Close form */}
      {showClose && (
        <div className="bg-navy-900 rounded-lg p-4 space-y-3 border border-green-700/20">
          <p className="text-xs font-semibold text-green-400 uppercase tracking-wide">Datos Post-Incidente</p>
          {(['executive_summary', 'root_cause', 'lessons_learned'] as const).map(field => (
            <div key={field}>
              <label className="text-xs text-gray-500 mb-1 block">
                {field.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())}
              </label>
              <textarea
                className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white placeholder-gray-700 focus:outline-none focus:border-green-500 min-h-[60px]"
                value={closingForm[field]}
                onChange={e => setClosingForm(f => ({ ...f, [field]: e.target.value }))}
              />
            </div>
          ))}
          <div className="flex gap-2">
            <button
              onClick={doClose}
              disabled={closing}
              className="px-4 py-1.5 text-sm bg-green-600 hover:bg-green-500 text-white rounded font-semibold disabled:opacity-40"
            >
              Confirmar Cierre
            </button>
            <button
              onClick={() => setShowClose(false)}
              className="px-4 py-1.5 text-sm bg-navy-700 text-gray-400 rounded hover:text-white"
            >
              Cancelar
            </button>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div>
        <div className="flex border-b border-navy-700 mb-3">
          {([
            { key: 'timeline', label: 'Línea de Tiempo' },
            { key: 'links',    label: 'Entidades' },
            { key: 'piil',     label: 'PIIL Binding' },
          ] as const).map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setTab(key)}
              className={clsx(
                'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
                tab === key
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-gray-500 hover:text-gray-300'
              )}
            >
              {key === 'piil' ? (
                <span className="flex items-center gap-1">
                  <Lock size={11} />
                  {label}
                </span>
              ) : label}
            </button>
          ))}
        </div>

        {tab === 'timeline' && <TimelinePanel incidentId={incident.id} />}

        {tab === 'links' && (
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {loadingLinks ? (
              <p className="text-gray-500 text-sm">Cargando...</p>
            ) : links.length === 0 ? (
              <p className="text-gray-600 text-sm">Sin entidades vinculadas.</p>
            ) : (
              links.map(l => (
                <div key={l.id} className="flex items-center gap-2 bg-navy-900 rounded p-2">
                  <Link2 size={12} className="text-cyan-400 shrink-0" />
                  <span className="text-xs text-gray-400">{l.entity_type}</span>
                  <span className="text-xs font-mono text-gray-300">{l.entity_id}</span>
                  {l.notes && <span className="text-xs text-gray-600 ml-auto">{l.notes}</span>}
                </div>
              ))
            )}
          </div>
        )}

        {tab === 'piil' && (
          <div className="space-y-2 max-h-72 overflow-y-auto">
            {loadingPiil ? (
              <p className="text-gray-500 text-sm">Cargando...</p>
            ) : piilEntries.length === 0 ? (
              <div className="text-center py-6">
                <Lock size={24} className="text-gray-700 mx-auto mb-2" />
                <p className="text-gray-600 text-sm">Sin registros PIIL para este incidente.</p>
                <p className="text-gray-700 text-xs mt-1">Los registros aparecen cuando SOAR dispara triggers durante transiciones.</p>
              </div>
            ) : (
              piilEntries.map(e => (
                <div key={e.id} className="bg-navy-900 border border-purple-500/20 rounded p-3 space-y-1.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400 font-semibold">PIIL</span>
                    <span className="text-xs text-gray-400 font-mono truncate flex-1">{e.target}</span>
                    <span className={clsx(
                      'text-[10px] px-1.5 py-0.5 rounded font-semibold',
                      e.verified ? 'bg-green-500/20 text-green-400' : 'bg-gray-700 text-gray-500'
                    )}>
                      {e.verified ? 'VERIFIED' : 'UNSIGNED'}
                    </span>
                  </div>
                  <div className="font-mono text-[10px] text-gray-600 break-all">
                    SHA3-512: {e.hash_sha3_512.slice(0, 32)}…
                  </div>
                  {e.canonical_data && (
                    <div className="text-[10px] text-gray-600 space-y-0.5">
                      {(e.canonical_data as any).triggers_fired !== undefined && (
                        <span className="text-purple-400/70">
                          Triggers: {(e.canonical_data as any).triggers_fired}
                          {(e.canonical_data as any).trigger_names?.length > 0 && (
                            <span className="text-gray-600"> ({(e.canonical_data as any).trigger_names.join(', ')})</span>
                          )}
                        </span>
                      )}
                    </div>
                  )}
                  <div className="text-[10px] text-gray-700">
                    {e.signed_by_email} · {e.signed_at ? new Date(e.signed_at).toLocaleString() : '—'}
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Create Incident Form ──────────────────────────────────────────────────────

function CreateForm({ onCreated }: { onCreated: () => void }) {
  const [form, setForm] = useState({
    title: '', incident_type: 'other', severity: 'medium', description: '',
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function submit() {
    if (!form.title.trim()) { setError('El título es requerido'); return }
    setSaving(true)
    setError('')
    try {
      await createIncident({ ...form, description: form.description || undefined })
      setForm({ title: '', incident_type: 'other', severity: 'medium', description: '' })
      onCreated()
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'Error al crear incidente')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="bg-navy-800 border border-navy-700 rounded-lg p-5 space-y-4">
      <h3 className="text-white font-semibold text-sm">Nuevo Incidente</h3>

      <div>
        <label className="text-xs text-gray-500 mb-1 block">Título *</label>
        <input
          className="w-full bg-navy-900 border border-navy-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
          value={form.title}
          onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
          placeholder="Descripción breve del incidente"
        />
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Tipo</label>
          <select
            className="w-full bg-navy-900 border border-navy-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
            value={form.incident_type}
            onChange={e => setForm(f => ({ ...f, incident_type: e.target.value }))}
          >
            {INCIDENT_TYPES.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Severidad</label>
          <select
            className="w-full bg-navy-900 border border-navy-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
            value={form.severity}
            onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
          >
            {['critical', 'high', 'medium', 'low', 'info'].map(s => (
              <option key={s} value={s}>{s.toUpperCase()}</option>
            ))}
          </select>
        </div>
      </div>

      <div>
        <label className="text-xs text-gray-500 mb-1 block">Descripción</label>
        <textarea
          className="w-full bg-navy-900 border border-navy-600 rounded px-3 py-2 text-sm text-white placeholder-gray-700 focus:outline-none focus:border-cyan-500 min-h-[80px]"
          value={form.description}
          onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
          placeholder="Contexto inicial del incidente…"
        />
      </div>

      {error && <p className="text-red-400 text-xs">{error}</p>}

      <button
        onClick={submit}
        disabled={saving}
        className="w-full py-2 bg-cyan-500 hover:bg-cyan-400 text-navy-900 font-bold text-sm rounded disabled:opacity-40"
      >
        {saving ? 'Creando…' : 'Crear Incidente'}
      </button>
    </div>
  )
}

// ── Incident Row ──────────────────────────────────────────────────────────────

function IncidentRow({
  incident,
  selected,
  onSelect,
}: {
  incident: Incident
  selected: boolean
  onSelect: () => void
}) {
  return (
    <div
      onClick={onSelect}
      className={clsx(
        'flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-colors',
        selected
          ? 'bg-cyan-400/10 border border-cyan-400/30'
          : 'bg-navy-800 border border-navy-700 hover:border-navy-600',
      )}
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap mb-0.5">
          <SevBadge sev={incident.severity} />
          <StatusBadge st={incident.status} />
          {incident.sla_breach && (
            <span className="text-[10px] text-red-400 font-bold">SLA!</span>
          )}
        </div>
        <p className="text-sm font-medium text-white truncate">{incident.title}</p>
        <p className="text-xs text-gray-600 mt-0.5">
          {incident.incident_type} · {incident.created_at ? new Date(incident.created_at).toLocaleDateString() : '—'}
        </p>
      </div>
      <div className="text-xs text-gray-600 shrink-0 text-right">
        <p>MTTD {fmtMins(incident.mttd_minutes)}</p>
        <p>MTTR {fmtMins(incident.mttr_minutes)}</p>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function IncidentsPage() {
  const [summary, setSummary] = useState<IncidentSummary | null>(null)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [selected, setSelected] = useState<Incident | null>(null)
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)

  // Filters
  const [filterStatus, setFilterStatus] = useState('')
  const [filterSev, setFilterSev] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [sumR, incR] = await Promise.all([
        getIncidentSummary(),
        listIncidents({
          status: filterStatus || undefined,
          severity: filterSev || undefined,
          limit: 100,
        }),
      ])
      setSummary(sumR)
      setIncidents(incR.items)
    } finally {
      setLoading(false)
    }
  }, [filterStatus, filterSev])

  const { connected } = useSSENotifications({
    onEvent: (evt) => {
      if (['incident_created', 'incident_updated', 'incident_status_changed'].includes(evt.type)) load()
    },
  })

  useEffect(() => { load() }, [load])

  async function refreshSelected() {
    await load()
    if (selected) {
      const fresh = await getIncident(selected.id)
      setSelected(fresh)
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-400/10 rounded">
            <ClipboardList size={20} className="text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white">Incident Response</h1>
              <span title={connected ? 'SSE conectado — actualizaciones en tiempo real' : 'SSE desconectado'}
                className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border ${connected ? 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10' : 'text-gray-500 border-gray-700 bg-gray-800'}`}>
                {connected ? <Wifi size={11} /> : <WifiOff size={11} />}
                {connected ? 'live' : 'offline'}
              </span>
            </div>
            <p className="text-xs text-gray-500">NIST 800-61 — Gestión formal de incidentes de seguridad</p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowCreate(v => !v)}
            className="px-3 py-1.5 text-sm bg-cyan-500 hover:bg-cyan-400 text-navy-900 font-semibold rounded"
          >
            + Nuevo
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

      {/* Create form */}
      {showCreate && (
        <CreateForm onCreated={() => { setShowCreate(false); load() }} />
      )}

      {/* KPI Strip */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
          <KpiCard icon={ClipboardList} label="Total Incidentes" value={summary.total} />
          <KpiCard icon={Activity}      label="Abiertos"         value={summary.open} accent="bg-orange-400/10" />
          <KpiCard icon={AlertTriangle} label="SLA Breach"       value={summary.sla_breach_count} accent="bg-red-400/10" />
          <KpiCard icon={Clock}         label="MTTD Prom."       value={fmtMins(summary.avg_mttd_minutes)} sub="detect→triage" />
          <KpiCard icon={Clock}         label="MTTC Prom."       value={fmtMins(summary.avg_mttc_minutes)} sub="detect→contain" />
          <KpiCard icon={Clock}         label="MTTR Prom."       value={fmtMins(summary.avg_mttr_minutes)} sub="detect→recover" />
          <KpiCard icon={CheckCircle}   label="Cerrados"         value={summary.by_status?.closed ?? 0} accent="bg-green-400/10" />
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <select
          className="bg-navy-800 border border-navy-700 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-cyan-500"
          value={filterStatus}
          onChange={e => setFilterStatus(e.target.value)}
        >
          <option value="">Todos los estados</option>
          {['detected', 'triaged', 'contained', 'eradicated', 'recovered', 'post_incident', 'closed', 'dismissed'].map(s => (
            <option key={s} value={s}>{s.replace('_', ' ')}</option>
          ))}
        </select>
        <select
          className="bg-navy-800 border border-navy-700 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-cyan-500"
          value={filterSev}
          onChange={e => setFilterSev(e.target.value)}
        >
          <option value="">Todas las severidades</option>
          {['critical', 'high', 'medium', 'low', 'info'].map(s => (
            <option key={s} value={s}>{s.toUpperCase()}</option>
          ))}
        </select>
      </div>

      {/* Main layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-5 gap-5">
        {/* List */}
        <div className="lg:col-span-1 xl:col-span-2 space-y-2">
          {loading && incidents.length === 0 ? (
            <div className="flex justify-center py-12">
              <RefreshCw size={20} className="text-cyan-400 animate-spin" />
            </div>
          ) : incidents.length === 0 ? (
            <div className="bg-navy-800 border border-navy-700 rounded-lg p-8 text-center">
              <ClipboardList size={32} className="text-gray-600 mx-auto mb-3" />
              <p className="text-gray-500 text-sm">No hay incidentes</p>
              <p className="text-gray-700 text-xs mt-1">Crea uno con el botón "+ Nuevo"</p>
            </div>
          ) : (
            incidents.map(i => (
              <IncidentRow
                key={i.id}
                incident={i}
                selected={selected?.id === i.id}
                onSelect={() => setSelected(i)}
              />
            ))
          )}
        </div>

        {/* Detail */}
        <div className="xl:col-span-3">
          {selected ? (
            <IncidentDetail
              incident={selected}
              onRefresh={refreshSelected}
              onClose={() => setSelected(null)}
            />
          ) : (
            <div className="bg-navy-800 border border-dashed border-navy-600 rounded-lg p-12 text-center">
              <Shield size={40} className="text-gray-700 mx-auto mb-3" />
              <p className="text-gray-500 text-sm">Selecciona un incidente para ver el detalle</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
