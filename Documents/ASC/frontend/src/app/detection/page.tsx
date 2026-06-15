'use client'
import { useState, useEffect } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import { Semaphore } from '@/components/dashboard/Semaphore'
import { useAuthGuard } from '@/lib/auth-guard'
import { evaluateEvent, evaluateBulkEvents, fingerprintArtifact, getDetectionRules } from '@/lib/api'
import { ScanSearch, Cpu, Shield, AlertTriangle, CheckCircle } from 'lucide-react'

type Tab = 'event' | 'bulk' | 'fingerprint' | 'rules'

const EMPTY_EVENT = `{
  "host": "PREMOS-WS-01",
  "process": "acord32.exe",
  "args": "/s /o",
  "api_call": "",
  "registry_key": "",
  "category": "process"
}`

const BULK_EXAMPLE = `{
  "events": [
    { "host": "PREMOS-WS-01", "process": "acord32.exe", "args": "/s /o" },
    { "host": "PREMOS-WS-02", "api_call": "SetWindowsHookExW" }
  ]
}`

export default function DetectionPage() {
  useAuthGuard()
  const [tab, setTab]       = useState<Tab>('event')
  const [input, setInput]   = useState(EMPTY_EVENT)
  const [bulkInput, setBulkInput] = useState(BULK_EXAMPLE)
  const [fpFilename, setFpFilename] = useState('sample.exe')
  const [fpHex, setFpHex]   = useState('50524546d6f73436f72700050524f50524520686f73743a5052454d4f532d57532d30310a')
  const [result, setResult] = useState<any>(null)
  const [rules, setRules]   = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]   = useState('')

  useEffect(() => {
    if (tab === 'rules' && !rules) {
      getDetectionRules().then(setRules).catch(console.error)
    }
  }, [tab, rules])

  async function submit() {
    setLoading(true); setError(''); setResult(null)
    try {
      if (tab === 'event') {
        const payload = JSON.parse(input)
        setResult(await evaluateEvent(payload))
      } else if (tab === 'bulk') {
        const payload = JSON.parse(bulkInput)
        setResult(await evaluateBulkEvents(payload.events, payload.original_analysis_ts))
      } else if (tab === 'fingerprint') {
        setResult(await fingerprintArtifact(fpFilename, fpHex))
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Error al procesar')
    } finally {
      setLoading(false)
    }
  }

  const TABS: [Tab, string, any][] = [
    ['event',       'Evento Individual', Shield],
    ['bulk',        'Lote de Eventos',   AlertTriangle],
    ['fingerprint', 'Fingerprinting',    Cpu],
    ['rules',       'Reglas Activas',    ScanSearch],
  ]

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6 overflow-auto">
        <h1 className="text-2xl font-bold text-white mb-1 flex items-center gap-2">
          <ScanSearch className="text-cyan-400" size={22} />
          Módulo de Detección
        </h1>
        <p className="text-gray-500 text-xs mb-6">Reglas DET-001–004 · MITRE ATT&CK · Environmental Keying</p>

        {/* Tabs */}
        <div className="flex gap-2 mb-6 flex-wrap">
          {TABS.map(([t, label, Icon]) => (
            <button key={t} onClick={() => { setTab(t); setResult(null); setError('') }}
              className={`flex items-center gap-2 px-4 py-2 rounded text-sm font-medium transition-colors ${
                tab === t ? 'bg-cyan-400 text-navy-900' : 'bg-navy-800 text-gray-400 hover:text-white'
              }`}>
              <Icon size={14} />{label}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-12 gap-6">
          {/* Input panel */}
          <div className="col-span-12 lg:col-span-5">
            {tab === 'event' && (
              <div className="card">
                <p className="text-xs text-gray-500 mb-2">Evento JSON (formato ECS)</p>
                <textarea
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  rows={12}
                  className="w-full bg-navy-900 border border-navy-700 rounded px-3 py-2 text-green-400 font-mono text-xs outline-none focus:border-cyan-400 resize-none"
                />
              </div>
            )}
            {tab === 'bulk' && (
              <div className="card">
                <p className="text-xs text-gray-500 mb-2">Lote de eventos (JSON)</p>
                <textarea
                  value={bulkInput}
                  onChange={e => setBulkInput(e.target.value)}
                  rows={12}
                  className="w-full bg-navy-900 border border-navy-700 rounded px-3 py-2 text-green-400 font-mono text-xs outline-none focus:border-cyan-400 resize-none"
                />
              </div>
            )}
            {tab === 'fingerprint' && (
              <div className="card space-y-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Nombre del artefacto</label>
                  <input value={fpFilename} onChange={e => setFpFilename(e.target.value)}
                    className="w-full bg-navy-900 border border-navy-700 rounded px-3 py-2 text-white text-sm outline-none focus:border-cyan-400" />
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Bytes del artefacto (hex)</label>
                  <textarea
                    value={fpHex}
                    onChange={e => setFpHex(e.target.value)}
                    rows={8}
                    placeholder="Bytes del archivo en hexadecimal..."
                    className="w-full bg-navy-900 border border-navy-700 rounded px-3 py-2 text-green-400 font-mono text-xs outline-none focus:border-cyan-400 resize-none"
                  />
                </div>
                <p className="text-xs text-gray-600">Máx 64 KB (128 000 caracteres hex). Para archivos mayores usar /analyze/file.</p>
              </div>
            )}
            {tab === 'rules' && (
              <div className="card">
                <p className="text-xs text-gray-400">Consultando catálogo de reglas activas...</p>
              </div>
            )}

            {tab !== 'rules' && (
              <div className="mt-3">
                <button onClick={submit} disabled={loading}
                  className="btn-primary w-full flex items-center justify-center gap-2 disabled:opacity-50">
                  {loading ? 'Procesando...' : 'Evaluar'}
                </button>
                {error && (
                  <p className="text-red-400 text-xs mt-2 bg-red-400/10 rounded px-3 py-2">{error}</p>
                )}
              </div>
            )}
          </div>

          {/* Results panel */}
          <div className="col-span-12 lg:col-span-7">

            {/* Rules catalog */}
            {tab === 'rules' && rules && (
              <div className="card">
                <h3 className="text-cyan-400 font-semibold mb-4">Reglas de Detección</h3>
                <div className="space-y-3">
                  {rules.rules?.map((r: any) => (
                    <div key={r.rule_id} className="bg-navy-900 rounded p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-xs text-cyan-400">{r.rule_id}</span>
                        <span className="text-xs text-gray-300 font-semibold">{r.name}</span>
                        <span className="ml-auto text-xs font-mono text-orange-400">{r.mitre_ttp}</span>
                      </div>
                      <p className="text-xs text-gray-500">{r.description}</p>
                    </div>
                  ))}
                </div>
                <h3 className="text-cyan-400 font-semibold mt-6 mb-3">Checks de Fingerprinting</h3>
                <div className="flex flex-wrap gap-2">
                  {rules.fingerprint_checks?.map((c: string) => (
                    <span key={c} className="bg-navy-900 text-gray-400 text-xs px-2 py-1 rounded font-mono">{c}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Detection results */}
            {result && (tab === 'event' || tab === 'bulk') && (
              <div className="card">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-cyan-400 font-semibold">Resultados de Detección</h3>
                  <div className="flex items-center gap-2">
                    {result.total > 0
                      ? <AlertTriangle size={16} className="text-red-400" />
                      : <CheckCircle size={16} className="text-green-400" />
                    }
                    <span className={`font-bold text-sm ${result.total > 0 ? 'text-red-400' : 'text-green-400'}`}>
                      {result.total} deteccion{result.total !== 1 ? 'es' : ''}
                    </span>
                  </div>
                </div>

                {result.total === 0 && (
                  <div className="flex items-center gap-3 bg-green-400/10 border border-green-400/20 rounded p-4">
                    <CheckCircle className="text-green-400" size={20} />
                    <p className="text-green-400 text-sm">Sin detecciones — evento limpio</p>
                  </div>
                )}

                {result.results?.map((r: any, i: number) => (
                  <div key={i} className="bg-navy-900 rounded p-4 mb-3">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <span className="font-mono text-xs text-gray-500">{r.rule_id}</span>
                        <p className="font-semibold text-white text-sm">{r.rule_name}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={r.severity} />
                        <Semaphore posture={r.semaphore === 'red' ? 'CRITICAL' : r.semaphore === 'yellow' ? 'ELEVATED' : 'NORMAL'} size="sm" />
                      </div>
                    </div>
                    <p className="text-gray-400 text-xs mb-2">{r.description}</p>
                    <div className="flex items-center gap-4 text-xs">
                      <span className="text-orange-400 font-mono">{r.mitre_ttp}</span>
                      <span className="text-cyan-400">Risk: {Number(r.risk_score).toFixed(2)}</span>
                      <span className="text-gray-600">{r.detected_at?.slice(0, 19).replace('T', ' ')}</span>
                    </div>
                    {r.evidence && Object.keys(r.evidence).length > 0 && (
                      <details className="mt-2">
                        <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-300">Evidencia</summary>
                        <pre className="text-xs text-gray-400 font-mono mt-1 bg-navy-900 p-2 rounded overflow-x-auto">
                          {JSON.stringify(r.evidence, null, 2)}
                        </pre>
                      </details>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Fingerprint result */}
            {result && tab === 'fingerprint' && (
              <div className="card">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-cyan-400 font-semibold">Resultado Fingerprinting</h3>
                  <Semaphore
                    posture={result.environmental_keying_detected ? (result.confidence >= 0.8 ? 'CRITICAL' : 'ELEVATED') : 'NORMAL'}
                    size="md"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3 mb-4">
                  <div className="bg-navy-900 rounded p-3">
                    <p className="text-xs text-gray-500 mb-1">Environmental Keying</p>
                    <p className={`text-lg font-bold ${result.environmental_keying_detected ? 'text-red-400' : 'text-green-400'}`}>
                      {result.environmental_keying_detected ? 'DETECTADO' : 'NO DETECTADO'}
                    </p>
                  </div>
                  <div className="bg-navy-900 rounded p-3">
                    <p className="text-xs text-gray-500 mb-1">Confianza</p>
                    <p className="text-2xl font-bold text-cyan-400">{(result.confidence * 100).toFixed(0)}%</p>
                  </div>
                  <div className="bg-navy-900 rounded p-3">
                    <p className="text-xs text-gray-500 mb-1">Risk Score</p>
                    <p className="text-xl font-bold text-orange-400">{Number(result.risk_score).toFixed(3)}</p>
                  </div>
                  <div className="bg-navy-900 rounded p-3">
                    <p className="text-xs text-gray-500 mb-1">Triggers Activados</p>
                    <p className="text-xl font-bold text-cyan-400">{result.triggers?.length ?? 0}</p>
                  </div>
                </div>

                {result.triggers?.length > 0 && (
                  <div className="mb-4">
                    <p className="text-xs text-gray-500 mb-2">Checks disparados:</p>
                    <div className="flex flex-wrap gap-2">
                      {result.triggers.map((t: string) => (
                        <span key={t} className="bg-red-500/20 border border-red-500/30 text-red-400 text-xs px-2 py-1 rounded font-mono">{t}</span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="bg-navy-900 rounded p-3 border border-navy-700">
                  <p className="text-xs text-gray-500 mb-1">Recomendación</p>
                  <p className="text-sm text-gray-300">{result.recommendation}</p>
                </div>

                {result.details?.length > 0 && (
                  <details className="mt-3">
                    <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-300">
                      {result.details.length} hallazgos detallados
                    </summary>
                    <pre className="text-xs text-gray-400 font-mono mt-2 bg-navy-900 p-2 rounded overflow-x-auto max-h-48">
                      {JSON.stringify(result.details, null, 2)}
                    </pre>
                  </details>
                )}
              </div>
            )}

          </div>
        </div>
      </main>
    </div>
  )
}
