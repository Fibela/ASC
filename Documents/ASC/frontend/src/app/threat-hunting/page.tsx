'use client'

import { useCallback, useEffect, useState } from 'react'
import {
  Search, Plus, ChevronRight, ChevronDown, Shield, Target, Eye, CheckCircle2,
  XCircle, Clock, Archive, AlertTriangle, Activity, BarChart3, Crosshair, FileSearch,
  RefreshCw, Trash2, BookOpen, Database, Play, Zap, FileText, Brain, Lock, Link,
} from 'lucide-react'
import {
  getHuntStats, listHunts, createHunt, updateHunt, archiveHunt,
  listFindings, addFinding, setFindingVerdict, listQueries, saveQuery,
  executeHuntQuery, enrichFinding, getHuntReport, signHuntReport,
  getPCDIScore, getPCDICorrelation,
  Hunt, HuntFinding, HuntQuery, HuntStats, HuntReport,
  PCDIScore, PCDICorrelation, PCDISignedReport,
} from '@/lib/api'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'
import { getRole } from '@/lib/auth'
import { Sidebar } from '@/components/dashboard/Sidebar'

// ── MITRE ATT&CK — curated common techniques ──────────────────────────────────
const MITRE_TECHNIQUES: { id: string; name: string; tactic: string }[] = [
  { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'execution' },
  { id: 'T1055', name: 'Process Injection', tactic: 'defense-evasion' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'initial-access' },
  { id: 'T1003', name: 'OS Credential Dumping', tactic: 'credential-access' },
  { id: 'T1021', name: 'Remote Services', tactic: 'lateral-movement' },
  { id: 'T1566', name: 'Phishing', tactic: 'initial-access' },
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initial-access' },
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact' },
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'command-and-control' },
  { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'defense-evasion' },
  { id: 'T1140', name: 'Deobfuscate/Decode Files or Information', tactic: 'defense-evasion' },
  { id: 'T1082', name: 'System Information Discovery', tactic: 'discovery' },
  { id: 'T1083', name: 'File and Directory Discovery', tactic: 'discovery' },
  { id: 'T1057', name: 'Process Discovery', tactic: 'discovery' },
  { id: 'T1016', name: 'System Network Configuration Discovery', tactic: 'discovery' },
  { id: 'T1033', name: 'System Owner/User Discovery', tactic: 'discovery' },
  { id: 'T1087', name: 'Account Discovery', tactic: 'discovery' },
  { id: 'T1069', name: 'Permission Groups Discovery', tactic: 'discovery' },
  { id: 'T1135', name: 'Network Share Discovery', tactic: 'discovery' },
  { id: 'T1489', name: 'Service Stop', tactic: 'impact' },
  { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'impact' },
  { id: 'T1562', name: 'Impair Defenses', tactic: 'defense-evasion' },
  { id: 'T1070', name: 'Indicator Removal', tactic: 'defense-evasion' },
  { id: 'T1112', name: 'Modify Registry', tactic: 'defense-evasion' },
  { id: 'T1218', name: 'System Binary Proxy Execution', tactic: 'defense-evasion' },
  { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'command-and-control' },
  { id: 'T1095', name: 'Non-Application Layer Protocol', tactic: 'command-and-control' },
  { id: 'T1572', name: 'Protocol Tunneling', tactic: 'command-and-control' },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'exfiltration' },
  { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'exfiltration' },
]

// ── Badge helpers ──────────────────────────────────────────────────────────────
function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    draft:     'bg-[rgba(90,90,90,0.15)]         text-[#5A5A5A]',
    active:    'bg-[rgba(232,93,4,0.12)]  text-[#FF7A25]  border border-[rgba(232,93,4,0.3)]',
    completed: 'bg-[rgba(45,184,99,0.1)]  text-[#3FD175]',
    archived:  'bg-[rgba(58,58,58,0.3)]   text-[#3A3A3A]',
  }
  const icons: Record<string, React.ReactNode> = {
    draft: <Clock size={11} />,
    active: <Activity size={11} />,
    completed: <CheckCircle2 size={11} />,
    archived: <Archive size={11} />,
  }
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${map[status] ?? 'bg-gray-700 text-gray-300'}`}>
      {icons[status]}
      {status}
    </span>
  )
}

function PriorityBadge({ priority }: { priority: string }) {
  const map: Record<string, string> = {
    critical: 'bg-[rgba(192,21,46,0.1)]  text-[#E8526E]',
    high:     'bg-[rgba(232,93,4,0.1)]   text-[#FF7A25]',
    medium:   'bg-[rgba(242,194,5,0.1)]  text-[#F2C205]',
    low:      'bg-[rgba(45,184,99,0.1)]  text-[#3FD175]',
  }
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${map[priority] ?? 'bg-gray-700 text-gray-300'}`}>
      {priority}
    </span>
  )
}

function SevBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: 'bg-[#C0152E] text-white',
    high:     'bg-[#E85D04] text-white',
    medium:   'bg-[rgba(242,194,5,0.15)] text-[#F2C205]',
    low:      'bg-[rgba(45,184,99,0.1)] text-[#3FD175]',
    info:     'bg-[rgba(90,90,90,0.15)] text-[#5A5A5A]',
  }
  return (
    <span className={`px-1.5 py-0.5 rounded text-xs font-bold uppercase ${map[sev] ?? 'bg-gray-600 text-gray-300'}`}>
      {sev}
    </span>
  )
}

// ── Create Hunt Modal ──────────────────────────────────────────────────────────
function CreateHuntModal({
  onClose, onCreated,
}: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({
    name: '', description: '', hypothesis: '',
    mitre_technique: '', mitre_tactic: '',
    scope: 'all', priority: 'medium',
    assigned_to: '', tags: '',
  })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')

  const selectedTech = MITRE_TECHNIQUES.find(t => t.id === form.mitre_technique)

  const submit = async () => {
    if (!form.name.trim()) { setErr('El nombre es requerido'); return }
    setSaving(true); setErr('')
    try {
      await createHunt({
        name: form.name.trim(),
        description: form.description || undefined,
        hypothesis: form.hypothesis || undefined,
        mitre_technique: form.mitre_technique || undefined,
        mitre_tactic: selectedTech?.tactic || form.mitre_tactic || undefined,
        scope: form.scope,
        priority: form.priority,
        assigned_to: form.assigned_to || undefined,
        tags: form.tags ? form.tags.split(',').map(t => t.trim()).filter(Boolean) : [],
      })
      onCreated()
    } catch {
      setErr('Error al crear el hunt')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
      <div
        className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl"
        style={{ background: '#0A0A0A', border: '1px solid rgba(255,255,255,0.08)' }}
      >
        <div className="flex items-center justify-between p-4" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <h2 className="font-semibold flex items-center gap-2 text-sm" style={{ color: '#EAEAEA' }}>
            <Crosshair size={16} style={{ color: '#E85D04' }} /> Nueva Sesión de Hunting
          </h2>
          <button onClick={onClose} style={{ color: '#5A5A5A' }}>✕</button>
        </div>
        <div className="p-4 space-y-3">
          {err && <p className="text-sm" style={{ color: '#E8526E' }}>{err}</p>}
          <div>
            <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Nombre *</label>
            <input className="input-asc"
              value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Hunt name" />
          </div>
          <div>
            <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Descripción</label>
            <textarea rows={2} className="input-asc resize-none"
              value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          </div>
          <div>
            <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Hipótesis</label>
            <textarea rows={2} className="input-asc resize-none"
              value={form.hypothesis} onChange={e => setForm(f => ({ ...f, hypothesis: e.target.value }))}
              placeholder="Sospechamos que..." />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Técnica MITRE ATT&CK</label>
              <select className="input-asc"
                value={form.mitre_technique} onChange={e => setForm(f => ({ ...f, mitre_technique: e.target.value }))}>
                <option value="">— Seleccionar —</option>
                {MITRE_TECHNIQUES.map(t => (
                  <option key={t.id} value={t.id}>{t.id} — {t.name}</option>
                ))}
              </select>
              {selectedTech && (
                <p className="text-xs mt-1" style={{ color: '#E85D04' }}>Táctica: {selectedTech.tactic}</p>
              )}
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Alcance</label>
              <select className="input-asc"
                value={form.scope} onChange={e => setForm(f => ({ ...f, scope: e.target.value }))}>
                <option value="all">all</option>
                <option value="host">host</option>
                <option value="network">network</option>
                <option value="cloud">cloud</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Prioridad</label>
              <select className="input-asc"
                value={form.priority} onChange={e => setForm(f => ({ ...f, priority: e.target.value }))}>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
              </select>
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Asignado a</label>
              <input className="input-asc"
                value={form.assigned_to} onChange={e => setForm(f => ({ ...f, assigned_to: e.target.value }))}
                placeholder="email@asc.local" />
            </div>
          </div>
          <div>
            <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Tags (separados por coma)</label>
            <input className="input-asc"
              value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))}
              placeholder="ransomware, apt, lateral-movement" />
          </div>
        </div>
        <div className="flex gap-2 justify-end p-4" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
          <button onClick={onClose} className="btn-secondary text-xs px-4 py-2">Cancelar</button>
          <button onClick={submit} disabled={saving}
            className="btn-primary text-xs px-4 py-2 disabled:opacity-50">
            {saving ? 'Creando...' : 'Crear Hunt'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Add Finding Modal ──────────────────────────────────────────────────────────
function AddFindingModal({ huntId, onClose, onAdded }: { huntId: string; onClose: () => void; onAdded: () => void }) {
  const [form, setForm] = useState({
    title: '', description: '', severity: 'medium',
    indicator_value: '', indicator_type: '',
    affected_host: '', affected_user: '',
    data_source: 'elk',
    mitre_technique: '', analyst_notes: '',
  })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')

  const submit = async () => {
    if (!form.title.trim()) { setErr('El título es requerido'); return }
    setSaving(true); setErr('')
    try {
      await addFinding(huntId, {
        title: form.title.trim(),
        description: form.description || undefined,
        severity: form.severity,
        indicator_value: form.indicator_value || undefined,
        indicator_type: form.indicator_type || undefined,
        affected_host: form.affected_host || undefined,
        affected_user: form.affected_user || undefined,
        data_source: form.data_source || undefined,
        mitre_technique: form.mitre_technique || undefined,
        analyst_notes: form.analyst_notes || undefined,
      })
      onAdded()
    } catch {
      setErr('Error al agregar el hallazgo')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
      <div
        className="w-full max-w-xl rounded-2xl"
        style={{ background: '#0A0A0A', border: '1px solid rgba(255,255,255,0.08)' }}
      >
        <div className="flex items-center justify-between p-4" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <h2 className="font-semibold text-sm" style={{ color: '#EAEAEA' }}>Agregar Hallazgo</h2>
          <button onClick={onClose} style={{ color: '#5A5A5A' }}>✕</button>
        </div>
        <div className="p-4 space-y-3">
          {err && <p className="text-sm" style={{ color: '#E8526E' }}>{err}</p>}
          <div>
            <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Título *</label>
            <input className="input-asc"
              value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Severidad</label>
              <select className="input-asc"
                value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}>
                {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Fuente de datos</label>
              <select className="input-asc"
                value={form.data_source} onChange={e => setForm(f => ({ ...f, data_source: e.target.value }))}>
                {['elk','wazuh','specter_agent','manual'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Valor indicador</label>
              <input className="input-asc"
                value={form.indicator_value} onChange={e => setForm(f => ({ ...f, indicator_value: e.target.value }))}
                placeholder="1.2.3.4 / evil.com / hash..." />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Tipo indicador</label>
              <select className="input-asc"
                value={form.indicator_type} onChange={e => setForm(f => ({ ...f, indicator_type: e.target.value }))}>
                <option value="">— Tipo —</option>
                {['ip','domain','url','hash_sha256','hash_md5','file_path','other'].map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Host afectado</label>
              <input className="input-asc"
                value={form.affected_host} onChange={e => setForm(f => ({ ...f, affected_host: e.target.value }))} />
            </div>
            <div>
              <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Usuario afectado</label>
              <input className="input-asc"
                value={form.affected_user} onChange={e => setForm(f => ({ ...f, affected_user: e.target.value }))} />
            </div>
          </div>
          <div>
            <label className="block text-xs mb-1" style={{ color: '#A0A0A0' }}>Notas del analista</label>
            <textarea rows={2} className="input-asc resize-none"
              value={form.analyst_notes} onChange={e => setForm(f => ({ ...f, analyst_notes: e.target.value }))} />
          </div>
        </div>
        <div className="flex gap-2 justify-end p-4" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
          <button onClick={onClose} className="btn-secondary text-xs px-4 py-2">Cancelar</button>
          <button onClick={submit} disabled={saving}
            className="btn-primary text-xs px-4 py-2 disabled:opacity-50">
            {saving ? 'Guardando...' : 'Agregar Hallazgo'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Hunt Detail Panel ──────────────────────────────────────────────────────────
function HuntDetail({
  hunt, onClose, onRefresh, isAdmin,
}: {
  hunt: Hunt; onClose: () => void; onRefresh: () => void; isAdmin: boolean
}) {
  const [findings, setFindings] = useState<HuntFinding[]>([])
  const [queries, setQueries] = useState<HuntQuery[]>([])
  const [tab, setTab] = useState<'findings' | 'queries' | 'info' | 'report' | 'pcdi'>('findings')
  const [showAddFinding, setShowAddFinding] = useState(false)
  const [showAddQuery, setShowAddQuery] = useState(false)
  const [queryForm, setQueryForm] = useState({ name: '', query_text: '', data_source: 'elk', description: '' })
  const [savingQuery, setSavingQuery] = useState(false)
  const [statusChanging, setStatusChanging] = useState(false)
  const [toast, setToast] = useState('')
  const [executing, setExecuting] = useState<Record<string, boolean>>({})
  const [queryResults, setQueryResults] = useState<Record<string, { result_count: number; success: boolean; error?: string | null; note?: string; truncated?: boolean; execution_ms?: number }>>({})
  const [enriching, setEnriching] = useState<Record<string, boolean>>({})
  const [report, setReport] = useState<HuntReport | null>(null)
  const [reportLoading, setReportLoading] = useState(false)
  // PCDI state
  const [pcdiScores, setPcdiScores] = useState<Record<string, PCDIScore>>({})
  const [scoringId, setScoringId] = useState('')
  const [correlation, setCorrelation] = useState<PCDICorrelation | null>(null)
  const [correlating, setCorrelating] = useState(false)
  const [signedReport, setSignedReport] = useState<PCDISignedReport | null>(null)
  const [signing, setSigning] = useState(false)

  const loadFindings = useCallback(async () => {
    try {
      const r = await listFindings(hunt.id)
      setFindings(r.findings)
    } catch { /* noop */ }
  }, [hunt.id])

  const loadQueries = useCallback(async () => {
    try {
      const r = await listQueries(hunt.id)
      setQueries(r.queries)
    } catch { /* noop */ }
  }, [hunt.id])

  useEffect(() => {
    loadFindings()
    loadQueries()
  }, [loadFindings, loadQueries])

  const showToast = (msg: string) => {
    setToast(msg)
    setTimeout(() => setToast(''), 3000)
  }

  const handleVerdict = async (fid: string, confirmed: boolean) => {
    try {
      await setFindingVerdict(hunt.id, fid, { is_confirmed: confirmed, is_false_positive: !confirmed })
      await loadFindings()
      onRefresh()
      showToast(confirmed ? 'Hallazgo confirmado como True Positive' : 'Marcado como False Positive')
    } catch {
      showToast('Error al actualizar veredicto')
    }
  }

  const handleStatusChange = async (newStatus: string) => {
    setStatusChanging(true)
    try {
      await updateHunt(hunt.id, { status: newStatus })
      onRefresh()
      showToast(`Estado actualizado a ${newStatus}`)
    } catch {
      showToast('No se puede cambiar el estado')
    } finally {
      setStatusChanging(false)
    }
  }

  const handleSaveQuery = async () => {
    if (!queryForm.name.trim() || !queryForm.query_text.trim()) return
    setSavingQuery(true)
    try {
      await saveQuery(hunt.id, {
        name: queryForm.name, query_text: queryForm.query_text,
        data_source: queryForm.data_source, description: queryForm.description || undefined,
      })
      setQueryForm({ name: '', query_text: '', data_source: 'elk', description: '' })
      setShowAddQuery(false)
      await loadQueries()
      showToast('Query guardada')
    } catch {
      showToast('Error al guardar query')
    } finally {
      setSavingQuery(false)
    }
  }

  const handleExecuteQuery = async (queryId: string) => {
    setExecuting(e => ({ ...e, [queryId]: true }))
    try {
      const r = await executeHuntQuery(hunt.id, queryId)
      setQueryResults(qr => ({ ...qr, [queryId]: r }))
      await loadQueries()
      showToast(r.success
        ? `Ejecutada: ${r.result_count} resultado(s) en ${r.execution_ms}ms`
        : `Error: ${r.error}`)
    } catch {
      showToast('Error al ejecutar la query')
    } finally {
      setExecuting(e => ({ ...e, [queryId]: false }))
    }
  }

  const handleEnrichFinding = async (findingId: string) => {
    setEnriching(e => ({ ...e, [findingId]: true }))
    try {
      const r = await enrichFinding(hunt.id, findingId)
      await loadFindings()
      if (r.enriched) {
        showToast(r.is_known_bad
          ? `IOC malicioso (${r.max_severity}): ${r.match_count} match(es) en TI`
          : `Enriquecido: ${r.match_count} coincidencia(s) en TI`)
      } else {
        showToast(r.note ?? 'Sin coincidencias en Threat Intelligence')
      }
    } catch {
      showToast('Error al enriquecer el hallazgo')
    } finally {
      setEnriching(e => ({ ...e, [findingId]: false }))
    }
  }

  const loadReport = useCallback(async () => {
    setReportLoading(true)
    try {
      const r = await getHuntReport(hunt.id)
      setReport(r)
    } catch {
      showToast('Error al generar el reporte')
    } finally {
      setReportLoading(false)
    }
  }, [hunt.id])

  const handleComputeScore = async (findingId: string) => {
    setScoringId(findingId)
    try {
      const score = await getPCDIScore(findingId)
      setPcdiScores(s => ({ ...s, [findingId]: score }))
      showToast(`PCDI Score: ${score.adaptive_score}/100 (${score.adapted_severity})${score.severity_escalated ? ' ⬆ ESCALADO' : ''}`)
    } catch {
      showToast('Error al calcular score PCDI')
    } finally {
      setScoringId('')
    }
  }

  const handleCorrelate = async () => {
    setCorrelating(true)
    try {
      const c = await getPCDICorrelation(hunt.id)
      setCorrelation(c)
      showToast(`Correlación: ${c.total_panl_matches} PANL · ${c.total_ti_matches} TI`)
    } catch {
      showToast('Error al correlacionar con PANL/TI')
    } finally {
      setCorrelating(false)
    }
  }

  const handleSignReport = async () => {
    setSigning(true)
    try {
      const sr = await signHuntReport(hunt.id)
      setSignedReport(sr)
      showToast(`Reporte firmado: ${sr.hash_prefix}`)
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      showToast(msg ?? 'Error al firmar el reporte (¿tiene clave Ed25519 registrada?)')
    } finally {
      setSigning(false)
    }
  }

  const nextStatusOptions: Record<string, string[]> = {
    draft: ['active'],
    active: ['completed'],
    completed: [],
    archived: [],
  }
  const nextOptions = nextStatusOptions[hunt.status] ?? []

  return (
    <div className="fixed inset-0 bg-black/70 z-40 flex items-start justify-end p-4">
      <div
        className="w-full max-w-2xl h-full max-h-[95vh] flex flex-col rounded-2xl"
        style={{ background: '#0A0A0A', border: '1px solid rgba(255,255,255,0.08)' }}
      >
        {/* Header */}
        <div className="p-4 flex-shrink-0" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <StatusBadge status={hunt.status} />
                <PriorityBadge priority={hunt.priority} />
                {hunt.mitre_technique && (
                  <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-xs font-mono">
                    {hunt.mitre_technique}
                  </span>
                )}
              </div>
              <h2 className="font-semibold mt-1 truncate text-sm" style={{ color: '#EAEAEA' }}>{hunt.name}</h2>
              <p className="text-xs mt-0.5" style={{ color: '#5A5A5A' }}>
                {hunt.findings_count} hallazgos · {hunt.true_positive_count} TP · creado por {hunt.created_by}
              </p>
            </div>
            <button onClick={onClose} className="flex-shrink-0" style={{ color: '#5A5A5A' }}>✕</button>
          </div>

          {/* Status workflow */}
          {nextOptions.length > 0 && (
            <div className="mt-3 flex gap-2">
              {nextOptions.map(s => (
                <button key={s} onClick={() => handleStatusChange(s)} disabled={statusChanging}
                  className="px-3 py-1 text-xs rounded disabled:opacity-50"
                  style={{
                    background: 'rgba(232,93,4,0.08)',
                    border: '1px solid rgba(232,93,4,0.3)',
                    color: '#FF7A25',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'rgba(232,93,4,0.15)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'rgba(232,93,4,0.08)')}
                >
                  {statusChanging ? '...' : `→ ${s}`}
                </button>
              ))}
              {isAdmin && hunt.status !== 'archived' && (
                <button onClick={async () => { await archiveHunt(hunt.id); onRefresh(); onClose() }}
                  className="btn-secondary px-3 py-1 text-xs flex items-center gap-1">
                  <Archive size={11} /> Archivar
                </button>
              )}
            </div>
          )}
        </div>

        {/* Tabs */}
        <div className="flex flex-shrink-0" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          {(['findings', 'queries', 'info', 'report', 'pcdi'] as const).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className="px-3 py-2 text-xs capitalize transition-colors flex items-center gap-1"
              style={tab === t
                ? { color: '#FF7A25', borderBottom: '2px solid #E85D04' }
                : { color: '#5A5A5A' }
              }
            >
              {t === 'pcdi' && <Brain size={11} />}
              {t === 'findings' ? `Hallazgos (${findings.length})` : t === 'queries' ? `Queries (${queries.length})` : t === 'report' ? 'Reporte' : t === 'pcdi' ? 'PCDI' : 'Info'}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-4">
          {/* Toast */}
          {toast && (
            <div
              className="mb-3 px-3 py-2 rounded text-sm"
              style={{
                background: 'rgba(232,93,4,0.10)',
                border: '1px solid rgba(232,93,4,0.3)',
                color: '#FF7A25',
              }}
            >{toast}</div>
          )}

          {/* Findings tab */}
          {tab === 'findings' && (
            <div className="space-y-2">
              <button
                onClick={() => setShowAddFinding(true)}
                className="flex items-center gap-1 text-xs mb-3"
                style={{ color: '#E85D04' }}
              >
                <Plus size={12} /> Agregar hallazgo
              </button>
              {findings.length === 0 && (
                <p className="text-sm text-center py-8" style={{ color: '#3A3A3A' }}>Sin hallazgos registrados</p>
              )}
              {findings.map(f => (
                <div
                  key={f.id}
                  className="border rounded-xl p-3 space-y-1"
                  style={
                    f.is_confirmed
                      ? { border: '1px solid rgba(192,21,46,0.3)', background: 'rgba(192,21,46,0.05)' }
                      : f.is_false_positive
                        ? { border: '1px solid rgba(90,90,90,0.3)', background: 'rgba(90,90,90,0.05)' }
                        : { border: '1px solid rgba(255,255,255,0.05)', background: 'rgba(255,255,255,0.02)' }
                  }
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SevBadge sev={f.severity} />
                      <span className="text-sm font-medium" style={{ color: '#EAEAEA' }}>{f.title}</span>
                    </div>
                    <div className="flex gap-1 flex-shrink-0 items-center">
                      {/* PCDI Adaptive Score */}
                      <button onClick={() => handleComputeScore(f.id)} disabled={scoringId === f.id}
                        className="p-1 text-purple-400 hover:text-purple-300 disabled:opacity-40" title="Calcular PCDI Score">
                        <Brain size={13} />
                      </button>
                      {pcdiScores[f.id] && (
                        <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${pcdiScores[f.id].adaptive_score >= 80 ? 'bg-red-600 text-white' : pcdiScores[f.id].adaptive_score >= 60 ? 'bg-orange-500 text-white' : pcdiScores[f.id].adaptive_score >= 40 ? 'bg-yellow-500 text-black' : 'bg-gray-600 text-gray-200'}`}
                          title={pcdiScores[f.id].recommendation}>
                          {pcdiScores[f.id].adaptive_score}
                          {pcdiScores[f.id].severity_escalated && ' ⬆'}
                        </span>
                      )}
                      {f.indicator_value && (
                        <button onClick={() => handleEnrichFinding(f.id)} disabled={enriching[f.id]}
                          className="p-1 text-yellow-500 hover:text-yellow-400 disabled:opacity-40" title="Enriquecer con TI">
                          <Zap size={14} />
                        </button>
                      )}
                      {!f.is_confirmed && !f.is_false_positive && (
                        <>
                          <button onClick={() => handleVerdict(f.id, true)}
                            className="p-1 text-green-500 hover:text-green-400" title="Confirmar TP">
                            <CheckCircle2 size={14} />
                          </button>
                          <button onClick={() => handleVerdict(f.id, false)}
                            className="p-1 text-gray-500 hover:text-gray-400" title="Marcar FP">
                            <XCircle size={14} />
                          </button>
                        </>
                      )}
                      {f.is_confirmed && <span className="text-xs text-green-400 font-medium">TP</span>}
                      {f.is_false_positive && <span className="text-xs text-gray-500 font-medium">FP</span>}
                    </div>
                  </div>
                  {f.indicator_value && (
                    <p className="text-xs text-gray-400 font-mono">{f.indicator_type && `[${f.indicator_type}] `}{f.indicator_value}</p>
                  )}
                  {(f.affected_host || f.affected_user) && (
                    <p className="text-xs text-gray-500">
                      {f.affected_host && `Host: ${f.affected_host}`}
                      {f.affected_host && f.affected_user && ' · '}
                      {f.affected_user && `User: ${f.affected_user}`}
                    </p>
                  )}
                  {f.mitre_technique && (
                    <span className="inline-block text-xs text-purple-400 font-mono">{f.mitre_technique}</span>
                  )}
                  {f.analyst_notes && (
                    <p className="text-xs text-gray-400 italic">"{f.analyst_notes}"</p>
                  )}
                  <p className="text-xs text-gray-600">{f.data_source} · {new Date(f.created_at).toLocaleString()}</p>
                </div>
              ))}
            </div>
          )}

          {/* Queries tab */}
          {tab === 'queries' && (
            <div className="space-y-3">
              <button
                onClick={() => setShowAddQuery(v => !v)}
                className="flex items-center gap-1 text-xs"
                style={{ color: '#E85D04' }}
              >
                <Plus size={12} /> {showAddQuery ? 'Cancelar' : 'Guardar query'}
              </button>
              {showAddQuery && (
                <div
                  className="rounded-xl p-3 space-y-2"
                  style={{ border: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.3)' }}
                >
                  <input className="input-asc"
                    placeholder="Nombre de la query" value={queryForm.name}
                    onChange={e => setQueryForm(f => ({ ...f, name: e.target.value }))} />
                  <select className="input-asc"
                    value={queryForm.data_source} onChange={e => setQueryForm(f => ({ ...f, data_source: e.target.value }))}>
                    {['elk','wazuh','specter_agent','manual'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                  <textarea rows={4} className="input-asc font-mono resize-none"
                    placeholder="query DSL / KQL / SQL / notas..." value={queryForm.query_text}
                    onChange={e => setQueryForm(f => ({ ...f, query_text: e.target.value }))} />
                  <button onClick={handleSaveQuery} disabled={savingQuery}
                    className="btn-primary text-xs px-4 py-1.5 disabled:opacity-50">
                    {savingQuery ? 'Guardando...' : 'Guardar'}
                  </button>
                </div>
              )}
              {queries.length === 0 && !showAddQuery && (
                <p className="text-sm text-center py-8" style={{ color: '#3A3A3A' }}>Sin queries guardadas</p>
              )}
              {queries.map(q => (
                <div
                  key={q.id}
                  className="rounded-xl p-3"
                  style={{ border: '1px solid rgba(255,255,255,0.05)', background: 'rgba(255,255,255,0.02)' }}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium" style={{ color: '#EAEAEA' }}>{q.name}</span>
                    <div className="flex items-center gap-2">
                      <span
                        className="text-xs px-2 py-0.5 rounded"
                        style={{ background: 'rgba(90,90,90,0.2)', color: '#5A5A5A' }}
                      >{q.data_source}</span>
                      <button onClick={() => handleExecuteQuery(q.id)} disabled={executing[q.id]}
                        className="flex items-center gap-1 text-xs text-green-400 hover:text-green-300 disabled:opacity-40 px-2 py-0.5 bg-green-500/10 border border-green-500/30 rounded">
                        <Play size={10} /> {executing[q.id] ? '...' : 'Ejecutar'}
                      </button>
                    </div>
                  </div>
                  <pre className="text-xs text-gray-300 font-mono bg-black/30 rounded p-2 overflow-x-auto whitespace-pre-wrap">{q.query_text}</pre>
                  {queryResults[q.id] && (
                    <div className={`mt-1.5 text-xs px-2 py-1 rounded ${queryResults[q.id].success ? 'text-green-400 bg-green-500/10 border border-green-500/20' : 'text-red-400 bg-red-500/10 border border-red-500/20'}`}>
                      {queryResults[q.id].success
                        ? `${queryResults[q.id].result_count} resultado(s) · ${queryResults[q.id].execution_ms}ms${queryResults[q.id].truncated ? ' · truncado' : ''}${queryResults[q.id].note ? ` — ${queryResults[q.id].note}` : ''}`
                        : `Error: ${queryResults[q.id].error}`}
                    </div>
                  )}
                  {q.last_executed_at && (
                    <p className="text-xs text-gray-600 mt-1">
                      Última ejecución: {new Date(q.last_executed_at).toLocaleString()}
                      {q.last_result_count !== null && ` · ${q.last_result_count} resultados`}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Report tab */}
          {tab === 'report' && (
            <div className="space-y-4">
              <div className="flex gap-2 flex-wrap">
                <button onClick={loadReport} disabled={reportLoading}
                  className="btn-secondary flex items-center gap-2 text-xs px-3 py-1.5 disabled:opacity-50">
                  <FileText size={12} className={reportLoading ? 'animate-pulse' : ''} />
                  {reportLoading ? 'Generando...' : report ? 'Regenerar Reporte' : 'Generar Reporte'}
                </button>
                {report && (
                  <button onClick={handleSignReport} disabled={signing}
                    className="flex items-center gap-1 px-3 py-1.5 text-xs bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 border border-purple-500/40 rounded disabled:opacity-50"
                    title="Firma criptográfica SHA3-512 + Ed25519 (requiere clave de analista)">
                    <Lock size={11} /> {signing ? 'Firmando...' : 'Firmar Reporte (PCDI)'}
                  </button>
                )}
              </div>
              {signedReport && (
                <div className="p-3 bg-purple-500/10 border border-purple-500/30 rounded text-xs">
                  <p className="text-purple-400 font-semibold mb-1 flex items-center gap-1"><Lock size={10} /> Reporte firmado — PCDI v{signedReport.pcdi_version}</p>
                  <p className="text-gray-400">SHA3-512: <span className="font-mono text-gray-300">{signedReport.hash_prefix}</span></p>
                  <p className="text-gray-400">Firmado por: <span className="text-gray-300">{signedReport.signed_by_email}</span></p>
                  <p className="text-gray-500">ID: {signedReport.id}</p>
                </div>
              )}
              {report && (
                <div className="space-y-4 text-sm">
                  <div className="text-xs text-gray-500">
                    Generado: {new Date(report.report_generated_at).toLocaleString()}
                  </div>
                  <div
                    className="p-3 rounded-xl"
                    style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.05)' }}
                  >
                    <p className="text-xs uppercase tracking-wider mb-1" style={{ color: '#5A5A5A' }}>Resumen ejecutivo</p>
                    <p style={{ color: '#A0A0A0' }}>{report.executive_summary}</p>
                  </div>
                  {report.hypothesis && (
                    <div>
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Hipótesis</p>
                      <p className="text-gray-300 italic">"{report.hypothesis}"</p>
                    </div>
                  )}
                  {report.conclusion && (
                    <div>
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Conclusión</p>
                      <p className="text-gray-300">{report.conclusion}</p>
                    </div>
                  )}
                  <div>
                    <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">
                      Hallazgos por severidad ({report.findings_total} total)
                    </p>
                    {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => {
                      const list = report.findings_by_severity[sev] ?? []
                      if (!list.length) return null
                      return (
                        <div key={sev} className="mb-2">
                          <p className="text-xs text-gray-400 mb-1 flex items-center gap-1">
                            <SevBadge sev={sev} /> {list.length} hallazgo(s)
                          </p>
                          {list.map((f: HuntFinding) => (
                            <div key={f.id} className="ml-2 text-xs py-0.5 pl-2" style={{ color: '#5A5A5A', borderLeft: '1px solid rgba(255,255,255,0.06)' }}>
                              {f.title}{f.indicator_value ? ` — ${f.indicator_value}` : ''}
                              {f.is_confirmed && <span className="ml-1 text-green-400">TP</span>}
                              {f.is_false_positive && <span className="ml-1 text-gray-500">FP</span>}
                            </div>
                          ))}
                        </div>
                      )
                    })}
                  </div>
                  {report.timeline.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Línea de tiempo</p>
                      <div className="space-y-1">
                        {report.timeline.map((e, i) => (
                          <div key={i} className="flex gap-2 text-xs">
                            <span className="text-gray-600 w-36 flex-shrink-0">{new Date(e.ts).toLocaleString()}</span>
                            <span className={`${e.confirmed ? 'text-green-400' : e.false_positive ? 'text-gray-500' : 'text-gray-300'}`}>
                              {e.event}{e.note ? ` — ${e.note}` : ''}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {report.queries_used.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Queries utilizadas ({report.queries_used.length})</p>
                      {report.queries_used.map((q: HuntQuery) => (
                        <p key={q.id} className="text-xs text-gray-400 ml-2">· {q.name} [{q.data_source}]</p>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* PCDI tab */}
          {tab === 'pcdi' && (
            <div className="space-y-4 text-sm">
              <div className="flex items-center gap-2 mb-2">
                <Brain size={14} className="text-purple-400" />
                <span className="text-xs text-gray-500 uppercase tracking-wider">Premos Cross-Domain Intelligence</span>
              </div>

              {/* Correlation button */}
              <button onClick={handleCorrelate} disabled={correlating}
                className="flex items-center gap-2 px-3 py-1.5 text-xs bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 border border-purple-500/40 rounded disabled:opacity-50">
                <Link size={11} /> {correlating ? 'Correlacionando...' : correlation ? 'Recalcular Correlación' : 'Ejecutar Correlación PANL + TI'}
              </button>

              {/* Correlation results */}
              {correlation && (
                <div className="space-y-3">
                  <div className="grid grid-cols-3 gap-2">
                    <div className="rounded-xl p-2 text-center" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                      <p className="text-xs" style={{ color: '#5A5A5A' }}>Hallazgos</p>
                      <p className="text-lg font-bold" style={{ color: '#EAEAEA' }}>{correlation.findings_analyzed}</p>
                    </div>
                    <div className="rounded-xl p-2 text-center" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(232,93,4,0.25)' }}>
                      <p className="text-xs" style={{ color: '#5A5A5A' }}>Acciones PANL</p>
                      <p className="text-lg font-bold" style={{ color: '#FF7A25' }}>{correlation.total_panl_matches}</p>
                    </div>
                    <div className="rounded-xl p-2 text-center" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(192,21,46,0.25)' }}>
                      <p className="text-xs" style={{ color: '#5A5A5A' }}>Indicadores TI</p>
                      <p className="text-lg font-bold" style={{ color: '#E8526E' }}>{correlation.total_ti_matches}</p>
                    </div>
                  </div>

                  {/* PANL correlations */}
                  {correlation.panl_correlations.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Acciones PANL correlacionadas</p>
                      <div className="space-y-1">
                        {correlation.panl_correlations.map(a => (
                          <div key={a.action_id} className="flex items-center gap-2 text-xs rounded-lg px-2 py-1" style={{ border: '1px solid rgba(255,255,255,0.05)' }}>
                            <span className={`px-1.5 rounded font-medium ${a.status === 'completed' ? 'bg-green-500/20 text-green-400' : a.status === 'failed' ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'}`}>{a.status}</span>
                            <span className="text-gray-400">{a.action_type}</span>
                            <span className="font-mono text-gray-300 truncate">{a.target}</span>
                            {a.match_count > 0 && <span className="ml-auto text-purple-400">{a.match_count} hallazgo(s)</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* TI correlations */}
                  {correlation.ti_correlations.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Indicadores TI correlacionados</p>
                      <div className="space-y-1">
                        {correlation.ti_correlations.map(ti => (
                          <div key={ti.indicator_id} className="flex items-center gap-2 text-xs rounded-lg px-2 py-1" style={{ border: '1px solid rgba(255,255,255,0.05)' }}>
                            <span className="text-gray-500">[{ti.type}]</span>
                            <span className="font-mono text-gray-300 truncate">{ti.value}</span>
                            <span className={`ml-auto px-1.5 rounded font-bold text-xs ${ti.severity === 'critical' ? 'bg-red-600 text-white' : ti.severity === 'high' ? 'bg-orange-500 text-white' : 'bg-yellow-500 text-black'}`}>{ti.severity}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {correlation.total_panl_matches === 0 && correlation.total_ti_matches === 0 && (
                    <p className="text-gray-500 text-xs text-center py-4">Sin correlaciones encontradas en PANL ni TI para los indicadores de este hunt.</p>
                  )}

                  <p className="text-xs text-gray-600">Calculado: {new Date(correlation.correlated_at).toLocaleString()}</p>
                </div>
              )}

              {/* PCDI scores summary */}
              {Object.keys(pcdiScores).length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Scores PCDI calculados ({Object.keys(pcdiScores).length})</p>
                  <div className="space-y-1">
                    {Object.values(pcdiScores).map(s => (
                      <div key={s.finding_id} className="flex items-center gap-2 text-xs rounded-lg px-2 py-1" style={{ border: '1px solid rgba(255,255,255,0.05)' }}>
                        <span className={`w-8 text-center font-bold rounded px-1 ${s.adaptive_score >= 80 ? 'bg-red-600 text-white' : s.adaptive_score >= 60 ? 'bg-orange-500 text-white' : s.adaptive_score >= 40 ? 'bg-yellow-500 text-black' : 'bg-gray-600 text-gray-200'}`}>{s.adaptive_score}</span>
                        <span className="text-gray-400">{s.original_severity} → <span className="font-medium text-gray-300">{s.adapted_severity}</span></span>
                        {s.severity_escalated && <span className="text-orange-400 text-xs">⬆ escalado</span>}
                        <span className="ml-auto text-gray-600 truncate max-w-[140px]">{s.indicator_value ?? s.finding_id.slice(0, 8)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <p className="text-xs pt-2" style={{ color: '#3A3A3A', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                PCDI combina Threat Intelligence, historial PANL y contexto del hunt para calcular scores adaptativos y correlaciones cross-dominio.
              </p>
            </div>
          )}

          {/* Info tab */}
          {tab === 'info' && (
            <div className="space-y-4 text-sm">
              {hunt.hypothesis && (
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Hipótesis</p>
                  <p className="text-gray-300 italic">"{hunt.hypothesis}"</p>
                </div>
              )}
              {hunt.description && (
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Descripción</p>
                  <p className="text-gray-300">{hunt.description}</p>
                </div>
              )}
              {hunt.conclusion && (
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Conclusión</p>
                  <p className="text-gray-300">{hunt.conclusion}</p>
                </div>
              )}
              <div className="grid grid-cols-2 gap-2 text-xs">
                {[
                  ['Alcance', hunt.scope],
                  ['Prioridad', hunt.priority],
                  ['Asignado a', hunt.assigned_to ?? '—'],
                  ['Técnica MITRE', hunt.mitre_technique ?? '—'],
                  ['Táctica', hunt.mitre_tactic ?? '—'],
                  ['Iniciado', hunt.started_at ? new Date(hunt.started_at).toLocaleString() : '—'],
                  ['Completado', hunt.completed_at ? new Date(hunt.completed_at).toLocaleString() : '—'],
                  ['Creado', new Date(hunt.created_at).toLocaleString()],
                ].map(([label, value]) => (
                  <div key={label}>
                    <p className="text-gray-500">{label}</p>
                    <p className="text-gray-300">{value}</p>
                  </div>
                ))}
              </div>
              {hunt.tags.length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Tags</p>
                  <div className="flex flex-wrap gap-1">
                    {hunt.tags.map(tag => (
                      <span key={tag} className="px-2 py-0.5 rounded text-xs" style={{ background: 'rgba(90,90,90,0.15)', color: '#A0A0A0' }}>{tag}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {showAddFinding && (
        <AddFindingModal huntId={hunt.id} onClose={() => setShowAddFinding(false)}
          onAdded={async () => { setShowAddFinding(false); await loadFindings(); onRefresh() }} />
      )}
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────
const PAGE_SIZE = 25

export default function ThreatHuntingPage() {
  const { isReady } = useAuthGuard()

  const [stats, setStats] = useState<HuntStats | null>(null)
  const [hunts, setHunts] = useState<Hunt[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [priorityFilter, setPriorityFilter] = useState('')
  const [selectedHunt, setSelectedHunt] = useState<Hunt | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [isAdmin] = useState(() => getRole() === 'admin')
  const [err, setErr] = useState('')

  const load = useCallback(async () => {
    setLoading(true); setErr('')
    try {
      const [s, h] = await Promise.all([
        getHuntStats(),
        listHunts({
          status: statusFilter || undefined,
          priority: priorityFilter || undefined,
          limit: PAGE_SIZE,
          offset,
        }),
      ])
      setStats(s)
      setHunts(h.hunts)
      setTotal(h.total)
    } catch {
      setErr('Error al cargar datos de Threat Hunting')
    } finally {
      setLoading(false)
    }
  }, [statusFilter, priorityFilter, offset])

  useEffect(() => { if (!isReady) return; load() }, [load, isReady])

  const filtered = search
    ? hunts.filter(h =>
        h.name.toLowerCase().includes(search.toLowerCase()) ||
        h.mitre_technique?.includes(search.toUpperCase()) ||
        h.tags.some(t => t.includes(search.toLowerCase()))
      )
    : hunts

  const pages = Math.ceil(total / PAGE_SIZE)
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1

  if (!isReady) return <AuthLoader />

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 overflow-auto">
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
          <Crosshair size={18} style={{ color: '#E85D04' }} />
          <div>
            <h1 className="text-sm font-bold leading-none" style={{ color: '#EAEAEA' }}>Threat Hunting</h1>
            <p className="text-xs mt-0.5" style={{ color: '#3A3A3A' }}>
              Cazería proactiva — análisis pasivo de logs y eventos
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} className="btn-secondary p-1.5">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
          <button onClick={() => setShowCreate(true)}
            className="btn-primary flex items-center gap-2 text-xs py-1.5 px-3">
            <Plus size={14} /> Nueva Hunt
          </button>
        </div>
      </div>
      <div className="p-6 space-y-5 animate-fade-in">

      {err && <div className="px-4 py-3 bg-red-500/20 border border-red-500/40 rounded text-red-400 text-sm">{err}</div>}

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {[
            { label: 'Hunts totales',  value: stats.total_hunts,       icon: <Crosshair  size={16} />, color: '#E85D04' },
            { label: 'Activas',        value: stats.active_hunts,       icon: <Activity   size={16} />, color: '#3FD175' },
            { label: 'Completadas',    value: stats.completed_hunts,    icon: <CheckCircle2 size={16} />, color: '#4A90D9' },
            { label: 'Total Hallazgos', value: stats.total_findings,    icon: <Target     size={16} />, color: '#FF7A25' },
            { label: 'True Positives', value: stats.confirmed_findings, icon: <AlertTriangle size={16} />, color: '#E8526E' },
            { label: 'Tasa FP',        value: `${(stats.false_positive_rate * 100).toFixed(0)}%`, icon: <Eye size={16} />, color: '#A0A0A0' },
          ].map(({ label, value, icon, color }) => (
            <div
              key={label}
              className="rounded-xl p-4"
              style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}
            >
              <div className="mb-2" style={{ color }}>{icon}</div>
              <p className="text-2xl font-bold" style={{ color: '#EAEAEA' }}>{value}</p>
              <p className="text-xs mt-1" style={{ color: '#5A5A5A' }}>{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Top techniques */}
      {stats && stats.top_techniques.length > 0 && (
        <div
          className="rounded-xl p-4"
          style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}
        >
          <h3 className="text-sm font-medium mb-3 flex items-center gap-2" style={{ color: '#A0A0A0' }}>
            <BarChart3 size={14} style={{ color: '#A06CE8' }} /> Técnicas más investigadas
          </h3>
          <div className="flex flex-wrap gap-2">
            {stats.top_techniques.map(t => (
              <div key={t.technique} className="flex items-center gap-1.5 px-2 py-1 bg-purple-500/10 border border-purple-500/30 rounded">
                <span className="text-xs font-mono text-purple-400">{t.technique}</span>
                <span className="text-xs text-gray-500">×{t.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters + Search */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-48">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#5A5A5A' }} />
          <input
            className="input-asc pl-9"
            placeholder="Buscar por nombre, técnica, tag..."
            value={search} onChange={e => setSearch(e.target.value)}
          />
        </div>
        <select className="input-asc" style={{ width: 'auto', minWidth: 160 }}
          value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setOffset(0) }}>
          <option value="">Todos los estados</option>
          {['draft','active','completed','archived'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input-asc" style={{ width: 'auto', minWidth: 160 }}
          value={priorityFilter} onChange={e => { setPriorityFilter(e.target.value); setOffset(0) }}>
          <option value="">Todas las prioridades</option>
          {['critical','high','medium','low'].map(p => <option key={p} value={p}>{p}</option>)}
        </select>
      </div>

      {/* Hunt List */}
      <div
        className="rounded-xl overflow-hidden"
        style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}
      >
        <div
          className="px-4 py-3 flex items-center justify-between"
          style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}
        >
          <span className="text-sm" style={{ color: '#5A5A5A' }}>
            {total} hunt{total !== 1 ? 's' : ''} · página {currentPage}/{pages || 1}
          </span>
        </div>
        {loading ? (
          <div className="p-8 text-center text-sm" style={{ color: '#3A3A3A' }}>
            <RefreshCw size={20} className="mx-auto mb-2 animate-spin" style={{ color: '#E85D04' }} />
            Cargando...
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-8 text-center" style={{ color: '#3A3A3A' }}>
            <Crosshair size={32} className="mx-auto mb-2 opacity-20" style={{ color: '#E85D04' }} />
            <p className="text-sm">Sin hunts registradas</p>
          </div>
        ) : (
          <div>
            {filtered.map((hunt, idx) => (
              <div
                key={hunt.id}
                className="px-4 py-3 cursor-pointer transition-colors"
                style={{
                  borderTop: idx > 0 ? '1px solid rgba(255,255,255,0.04)' : undefined,
                }}
                onClick={() => setSelectedHunt(hunt)}
                onMouseEnter={e => (e.currentTarget.style.background = 'rgba(232,93,4,0.04)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                <div className="flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3 min-w-0">
                    <Crosshair size={14} style={{
                      color: hunt.status === 'active' ? '#E85D04'
                           : hunt.status === 'completed' ? '#3FD175'
                           : hunt.status === 'archived' ? '#3A3A3A'
                           : '#5A5A5A'
                    }} />
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate" style={{ color: '#EAEAEA' }}>{hunt.name}</p>
                      <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                        <StatusBadge status={hunt.status} />
                        <PriorityBadge priority={hunt.priority} />
                        {hunt.mitre_technique && (
                          <span className="text-xs font-mono text-purple-400">{hunt.mitre_technique}</span>
                        )}
                        {hunt.tags.slice(0, 2).map(tag => (
                          <span key={tag} className="text-xs px-1.5 py-0.5 rounded" style={{ background: 'rgba(90,90,90,0.15)', color: '#5A5A5A' }}>{tag}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 flex-shrink-0 text-right">
                    <div>
                      <p className="text-sm font-medium" style={{ color: '#EAEAEA' }}>{hunt.findings_count}</p>
                      <p className="text-xs" style={{ color: '#5A5A5A' }}>hallazgos</p>
                    </div>
                    {hunt.true_positive_count > 0 && (
                      <div>
                        <p className="text-sm font-medium" style={{ color: '#E8526E' }}>{hunt.true_positive_count}</p>
                        <p className="text-xs" style={{ color: '#5A5A5A' }}>TP</p>
                      </div>
                    )}
                    <p className="text-xs hidden md:block" style={{ color: '#3A3A3A' }}>
                      {new Date(hunt.created_at).toLocaleDateString()}
                    </p>
                    <ChevronRight size={14} style={{ color: '#3A3A3A' }} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
        {/* Pagination */}
        {pages > 1 && (
          <div
            className="px-4 py-3 flex justify-between items-center"
            style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}
          >
            <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0}
              className="text-sm disabled:opacity-40 transition-colors"
              style={{ color: '#5A5A5A' }}
              onMouseEnter={e => { if (offset > 0) e.currentTarget.style.color = '#E85D04' }}
              onMouseLeave={e => (e.currentTarget.style.color = '#5A5A5A')}
            >← Anterior</button>
            <span className="text-sm" style={{ color: '#3A3A3A' }}>{currentPage} / {pages}</span>
            <button onClick={() => setOffset(offset + PAGE_SIZE)} disabled={offset + PAGE_SIZE >= total}
              className="text-sm disabled:opacity-40 transition-colors"
              style={{ color: '#5A5A5A' }}
              onMouseEnter={e => { if (offset + PAGE_SIZE < total) e.currentTarget.style.color = '#E85D04' }}
              onMouseLeave={e => (e.currentTarget.style.color = '#5A5A5A')}
            >Siguiente →</button>
          </div>
        )}
      </div>

      {/* Modals */}
      {showCreate && (
        <CreateHuntModal onClose={() => setShowCreate(false)} onCreated={() => { setShowCreate(false); load() }} />
      )}
      {selectedHunt && (
        <HuntDetail hunt={selectedHunt} isAdmin={isAdmin} onClose={() => setSelectedHunt(null)}
          onRefresh={() => { load(); setSelectedHunt(null) }} />
      )}
      </div>
      </main>
    </div>
  )
}
