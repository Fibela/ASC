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
import { getRole } from '@/lib/auth'

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
    draft: 'bg-gray-700 text-gray-300',
    active: 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40',
    completed: 'bg-green-500/20 text-green-400',
    archived: 'bg-gray-600/30 text-gray-500',
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
    critical: 'bg-red-500/20 text-red-400',
    high: 'bg-orange-500/20 text-orange-400',
    medium: 'bg-yellow-500/20 text-yellow-400',
    low: 'bg-green-500/20 text-green-400',
  }
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${map[priority] ?? 'bg-gray-700 text-gray-300'}`}>
      {priority}
    </span>
  )
}

function SevBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-500 text-black',
    low: 'bg-blue-500 text-white',
    info: 'bg-gray-600 text-gray-300',
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
      <div className="bg-navy-900 border border-navy-700 rounded-lg w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-navy-700">
          <h2 className="text-white font-semibold flex items-center gap-2"><Crosshair size={18} className="text-cyan-400" /> Nueva Sesión de Hunting</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white">✕</button>
        </div>
        <div className="p-4 space-y-3">
          {err && <p className="text-red-400 text-sm">{err}</p>}
          <div>
            <label className="block text-xs text-gray-400 mb-1">Nombre *</label>
            <input className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
              value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Hunt name" />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Descripción</label>
            <textarea rows={2} className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white resize-none"
              value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Hipótesis</label>
            <textarea rows={2} className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white resize-none"
              value={form.hypothesis} onChange={e => setForm(f => ({ ...f, hypothesis: e.target.value }))}
              placeholder="Sospechamos que..." />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Técnica MITRE ATT&CK</label>
              <select className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
                value={form.mitre_technique} onChange={e => setForm(f => ({ ...f, mitre_technique: e.target.value }))}>
                <option value="">— Seleccionar —</option>
                {MITRE_TECHNIQUES.map(t => (
                  <option key={t.id} value={t.id}>{t.id} — {t.name}</option>
                ))}
              </select>
              {selectedTech && (
                <p className="text-xs text-cyan-400 mt-1">Táctica: {selectedTech.tactic}</p>
              )}
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Alcance</label>
              <select className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
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
              <label className="block text-xs text-gray-400 mb-1">Prioridad</label>
              <select className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
                value={form.priority} onChange={e => setForm(f => ({ ...f, priority: e.target.value }))}>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Asignado a</label>
              <input className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
                value={form.assigned_to} onChange={e => setForm(f => ({ ...f, assigned_to: e.target.value }))}
                placeholder="email@asc.local" />
            </div>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Tags (separados por coma)</label>
            <input className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
              value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))}
              placeholder="ransomware, apt, lateral-movement" />
          </div>
        </div>
        <div className="flex gap-2 justify-end p-4 border-t border-navy-700">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-white">Cancelar</button>
          <button onClick={submit} disabled={saving}
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-black text-sm font-medium rounded disabled:opacity-50">
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
      <div className="bg-navy-900 border border-navy-700 rounded-lg w-full max-w-xl">
        <div className="flex items-center justify-between p-4 border-b border-navy-700">
          <h2 className="text-white font-semibold">Agregar Hallazgo</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white">✕</button>
        </div>
        <div className="p-4 space-y-3">
          {err && <p className="text-red-400 text-sm">{err}</p>}
          <div>
            <label className="block text-xs text-gray-400 mb-1">Título *</label>
            <input className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
              value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Severidad</label>
              <select className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
                value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}>
                {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Fuente de datos</label>
              <select className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
                value={form.data_source} onChange={e => setForm(f => ({ ...f, data_source: e.target.value }))}>
                {['elk','wazuh','specter_agent','manual'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Valor indicador</label>
              <input className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
                value={form.indicator_value} onChange={e => setForm(f => ({ ...f, indicator_value: e.target.value }))}
                placeholder="1.2.3.4 / evil.com / hash..." />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Tipo indicador</label>
              <select className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
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
              <label className="block text-xs text-gray-400 mb-1">Host afectado</label>
              <input className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
                value={form.affected_host} onChange={e => setForm(f => ({ ...f, affected_host: e.target.value }))} />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Usuario afectado</label>
              <input className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white"
                value={form.affected_user} onChange={e => setForm(f => ({ ...f, affected_user: e.target.value }))} />
            </div>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Notas del analista</label>
            <textarea rows={2} className="w-full bg-navy-800 border border-navy-600 rounded px-3 py-2 text-sm text-white resize-none"
              value={form.analyst_notes} onChange={e => setForm(f => ({ ...f, analyst_notes: e.target.value }))} />
          </div>
        </div>
        <div className="flex gap-2 justify-end p-4 border-t border-navy-700">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-white">Cancelar</button>
          <button onClick={submit} disabled={saving}
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-black text-sm font-medium rounded disabled:opacity-50">
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
      <div className="bg-navy-900 border border-navy-700 rounded-lg w-full max-w-2xl h-full max-h-[95vh] flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-navy-700 flex-shrink-0">
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
              <h2 className="text-white font-semibold mt-1 truncate">{hunt.name}</h2>
              <p className="text-xs text-gray-500 mt-0.5">
                {hunt.findings_count} hallazgos · {hunt.true_positive_count} TP · creado por {hunt.created_by}
              </p>
            </div>
            <button onClick={onClose} className="text-gray-500 hover:text-white flex-shrink-0">✕</button>
          </div>

          {/* Status workflow */}
          {nextOptions.length > 0 && (
            <div className="mt-3 flex gap-2">
              {nextOptions.map(s => (
                <button key={s} onClick={() => handleStatusChange(s)} disabled={statusChanging}
                  className="px-3 py-1 text-xs bg-cyan-500/20 hover:bg-cyan-500/40 text-cyan-400 border border-cyan-500/40 rounded disabled:opacity-50">
                  {statusChanging ? '...' : `→ ${s}`}
                </button>
              ))}
              {isAdmin && hunt.status !== 'archived' && (
                <button onClick={async () => { await archiveHunt(hunt.id); onRefresh(); onClose() }}
                  className="px-3 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-400 rounded flex items-center gap-1">
                  <Archive size={11} /> Archivar
                </button>
              )}
            </div>
          )}
        </div>

        {/* Tabs */}
        <div className="flex border-b border-navy-700 flex-shrink-0">
          {(['findings', 'queries', 'info', 'report', 'pcdi'] as const).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-3 py-2 text-sm capitalize transition-colors flex items-center gap-1 ${tab === t ? 'text-cyan-400 border-b-2 border-cyan-400' : 'text-gray-400 hover:text-white'}`}>
              {t === 'pcdi' && <Brain size={11} />}
              {t === 'findings' ? `Hallazgos (${findings.length})` : t === 'queries' ? `Queries (${queries.length})` : t === 'report' ? 'Reporte' : t === 'pcdi' ? 'PCDI' : 'Info'}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-4">
          {/* Toast */}
          {toast && (
            <div className="mb-3 px-3 py-2 bg-cyan-500/20 border border-cyan-500/30 rounded text-cyan-400 text-sm">{toast}</div>
          )}

          {/* Findings tab */}
          {tab === 'findings' && (
            <div className="space-y-2">
              <button onClick={() => setShowAddFinding(true)}
                className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 mb-3">
                <Plus size={12} /> Agregar hallazgo
              </button>
              {findings.length === 0 && (
                <p className="text-gray-500 text-sm text-center py-8">Sin hallazgos registrados</p>
              )}
              {findings.map(f => (
                <div key={f.id} className={`border rounded p-3 space-y-1 ${f.is_confirmed ? 'border-red-500/40 bg-red-500/5' : f.is_false_positive ? 'border-gray-600 bg-gray-800/30' : 'border-navy-600 bg-navy-800/50'}`}>
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SevBadge sev={f.severity} />
                      <span className="text-white text-sm font-medium">{f.title}</span>
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
              <button onClick={() => setShowAddQuery(v => !v)}
                className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300">
                <Plus size={12} /> {showAddQuery ? 'Cancelar' : 'Guardar query'}
              </button>
              {showAddQuery && (
                <div className="border border-navy-600 rounded p-3 space-y-2 bg-navy-800/50">
                  <input className="w-full bg-navy-700 border border-navy-600 rounded px-3 py-2 text-sm text-white"
                    placeholder="Nombre de la query" value={queryForm.name}
                    onChange={e => setQueryForm(f => ({ ...f, name: e.target.value }))} />
                  <select className="w-full bg-navy-700 border border-navy-600 rounded px-3 py-2 text-sm text-white"
                    value={queryForm.data_source} onChange={e => setQueryForm(f => ({ ...f, data_source: e.target.value }))}>
                    {['elk','wazuh','specter_agent','manual'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                  <textarea rows={4} className="w-full bg-navy-700 border border-navy-600 rounded px-3 py-2 text-sm text-white font-mono resize-none"
                    placeholder="query DSL / KQL / SQL / notas..." value={queryForm.query_text}
                    onChange={e => setQueryForm(f => ({ ...f, query_text: e.target.value }))} />
                  <button onClick={handleSaveQuery} disabled={savingQuery}
                    className="px-4 py-1.5 bg-cyan-500 hover:bg-cyan-600 text-black text-sm rounded disabled:opacity-50">
                    {savingQuery ? 'Guardando...' : 'Guardar'}
                  </button>
                </div>
              )}
              {queries.length === 0 && !showAddQuery && (
                <p className="text-gray-500 text-sm text-center py-8">Sin queries guardadas</p>
              )}
              {queries.map(q => (
                <div key={q.id} className="border border-navy-600 rounded p-3 bg-navy-800/50">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-white text-sm font-medium">{q.name}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-500 bg-navy-700 px-2 py-0.5 rounded">{q.data_source}</span>
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
                  className="flex items-center gap-2 px-3 py-1.5 text-xs bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 border border-cyan-500/40 rounded disabled:opacity-50">
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
                  <div className="p-3 bg-navy-800 border border-navy-600 rounded">
                    <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Resumen ejecutivo</p>
                    <p className="text-gray-300">{report.executive_summary}</p>
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
                            <div key={f.id} className="ml-2 text-xs text-gray-400 py-0.5 border-l border-navy-600 pl-2">
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
                    <div className="bg-navy-800 border border-navy-600 rounded p-2 text-center">
                      <p className="text-xs text-gray-500">Hallazgos</p>
                      <p className="text-lg font-bold text-white">{correlation.findings_analyzed}</p>
                    </div>
                    <div className="bg-navy-800 border border-orange-500/30 rounded p-2 text-center">
                      <p className="text-xs text-gray-500">Acciones PANL</p>
                      <p className="text-lg font-bold text-orange-400">{correlation.total_panl_matches}</p>
                    </div>
                    <div className="bg-navy-800 border border-red-500/30 rounded p-2 text-center">
                      <p className="text-xs text-gray-500">Indicadores TI</p>
                      <p className="text-lg font-bold text-red-400">{correlation.total_ti_matches}</p>
                    </div>
                  </div>

                  {/* PANL correlations */}
                  {correlation.panl_correlations.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Acciones PANL correlacionadas</p>
                      <div className="space-y-1">
                        {correlation.panl_correlations.map(a => (
                          <div key={a.action_id} className="flex items-center gap-2 text-xs border border-navy-600 rounded px-2 py-1">
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
                          <div key={ti.indicator_id} className="flex items-center gap-2 text-xs border border-navy-600 rounded px-2 py-1">
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
                      <div key={s.finding_id} className="flex items-center gap-2 text-xs border border-navy-600 rounded px-2 py-1">
                        <span className={`w-8 text-center font-bold rounded px-1 ${s.adaptive_score >= 80 ? 'bg-red-600 text-white' : s.adaptive_score >= 60 ? 'bg-orange-500 text-white' : s.adaptive_score >= 40 ? 'bg-yellow-500 text-black' : 'bg-gray-600 text-gray-200'}`}>{s.adaptive_score}</span>
                        <span className="text-gray-400">{s.original_severity} → <span className="font-medium text-gray-300">{s.adapted_severity}</span></span>
                        {s.severity_escalated && <span className="text-orange-400 text-xs">⬆ escalado</span>}
                        <span className="ml-auto text-gray-600 truncate max-w-[140px]">{s.indicator_value ?? s.finding_id.slice(0, 8)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <p className="text-xs text-gray-600 border-t border-navy-700 pt-2">
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
                      <span key={tag} className="px-2 py-0.5 bg-navy-700 text-gray-300 rounded text-xs">{tag}</span>
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
  useAuthGuard()

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

  useEffect(() => { load() }, [load])

  const filtered = search
    ? hunts.filter(h =>
        h.name.toLowerCase().includes(search.toLowerCase()) ||
        h.mitre_technique?.includes(search.toUpperCase()) ||
        h.tags.some(t => t.includes(search.toLowerCase()))
      )
    : hunts

  const pages = Math.ceil(total / PAGE_SIZE)
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Crosshair className="text-cyan-400" size={24} />
            Threat Hunting
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Cazería proactiva de amenazas — análisis pasivo de logs y eventos recolectados
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="p-2 text-gray-400 hover:text-white transition-colors" title="Recargar">
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
          <button onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-black text-sm font-medium rounded">
            <Plus size={16} /> Nueva Hunt
          </button>
        </div>
      </div>

      {err && <div className="px-4 py-3 bg-red-500/20 border border-red-500/40 rounded text-red-400 text-sm">{err}</div>}

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          {[
            { label: 'Hunts totales', value: stats.total_hunts, icon: <Crosshair size={18} />, color: 'text-cyan-400' },
            { label: 'Activas', value: stats.active_hunts, icon: <Activity size={18} />, color: 'text-green-400' },
            { label: 'Completadas', value: stats.completed_hunts, icon: <CheckCircle2 size={18} />, color: 'text-blue-400' },
            { label: 'Total Hallazgos', value: stats.total_findings, icon: <Target size={18} />, color: 'text-orange-400' },
            { label: 'True Positives', value: stats.confirmed_findings, icon: <AlertTriangle size={18} />, color: 'text-red-400' },
            { label: 'Tasa FP', value: `${(stats.false_positive_rate * 100).toFixed(0)}%`, icon: <Eye size={18} />, color: 'text-purple-400' },
          ].map(({ label, value, icon, color }) => (
            <div key={label} className="bg-navy-800 border border-navy-700 rounded-lg p-4">
              <div className={`${color} mb-2`}>{icon}</div>
              <p className="text-2xl font-bold text-white">{value}</p>
              <p className="text-xs text-gray-400 mt-1">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Top techniques */}
      {stats && stats.top_techniques.length > 0 && (
        <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
          <h3 className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
            <BarChart3 size={14} className="text-purple-400" /> Técnicas más investigadas
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
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input className="w-full bg-navy-800 border border-navy-700 rounded pl-9 pr-3 py-2 text-sm text-white placeholder-gray-500"
            placeholder="Buscar por nombre, técnica, tag..."
            value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <select className="bg-navy-800 border border-navy-700 rounded px-3 py-2 text-sm text-gray-300"
          value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setOffset(0) }}>
          <option value="">Todos los estados</option>
          {['draft','active','completed','archived'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="bg-navy-800 border border-navy-700 rounded px-3 py-2 text-sm text-gray-300"
          value={priorityFilter} onChange={e => { setPriorityFilter(e.target.value); setOffset(0) }}>
          <option value="">Todas las prioridades</option>
          {['critical','high','medium','low'].map(p => <option key={p} value={p}>{p}</option>)}
        </select>
      </div>

      {/* Hunt List */}
      <div className="bg-navy-800 border border-navy-700 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-navy-700 flex items-center justify-between">
          <span className="text-sm text-gray-400">
            {total} hunt{total !== 1 ? 's' : ''} · página {currentPage}/{pages || 1}
          </span>
        </div>
        {loading ? (
          <div className="p-8 text-center text-gray-500">Cargando...</div>
        ) : filtered.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            <Crosshair size={32} className="mx-auto mb-2 opacity-30" />
            Sin hunts registradas
          </div>
        ) : (
          <div className="divide-y divide-navy-700">
            {filtered.map(hunt => (
              <div key={hunt.id}
                className="px-4 py-3 hover:bg-navy-700/50 cursor-pointer transition-colors"
                onClick={() => setSelectedHunt(hunt)}>
                <div className="flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3 min-w-0">
                    <Crosshair size={14} className={
                      hunt.status === 'active' ? 'text-cyan-400' :
                      hunt.status === 'completed' ? 'text-green-400' :
                      hunt.status === 'archived' ? 'text-gray-600' : 'text-gray-500'
                    } />
                    <div className="min-w-0">
                      <p className="text-white text-sm font-medium truncate">{hunt.name}</p>
                      <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                        <StatusBadge status={hunt.status} />
                        <PriorityBadge priority={hunt.priority} />
                        {hunt.mitre_technique && (
                          <span className="text-xs font-mono text-purple-400">{hunt.mitre_technique}</span>
                        )}
                        {hunt.tags.slice(0, 2).map(tag => (
                          <span key={tag} className="text-xs text-gray-500 bg-navy-700 px-1.5 py-0.5 rounded">{tag}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 flex-shrink-0 text-right">
                    <div>
                      <p className="text-white text-sm font-medium">{hunt.findings_count}</p>
                      <p className="text-xs text-gray-500">hallazgos</p>
                    </div>
                    {hunt.true_positive_count > 0 && (
                      <div>
                        <p className="text-red-400 text-sm font-medium">{hunt.true_positive_count}</p>
                        <p className="text-xs text-gray-500">TP</p>
                      </div>
                    )}
                    <p className="text-xs text-gray-600 hidden md:block">
                      {new Date(hunt.created_at).toLocaleDateString()}
                    </p>
                    <ChevronRight size={14} className="text-gray-600" />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
        {/* Pagination */}
        {pages > 1 && (
          <div className="px-4 py-3 border-t border-navy-700 flex justify-between items-center">
            <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0}
              className="text-sm text-gray-400 hover:text-white disabled:opacity-40">← Anterior</button>
            <span className="text-sm text-gray-500">{currentPage} / {pages}</span>
            <button onClick={() => setOffset(offset + PAGE_SIZE)} disabled={offset + PAGE_SIZE >= total}
              className="text-sm text-gray-400 hover:text-white disabled:opacity-40">Siguiente →</button>
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
  )
}
