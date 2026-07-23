'use client'
import React, { useState, useEffect } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import { Semaphore } from '@/components/dashboard/Semaphore'
import { useAuthGuard } from '@/lib/auth-guard'
import { evaluateEvent, evaluateBulkEvents, fingerprintArtifact, getDetectionRules, DetectionRulesResponse } from '@/lib/api'
import { ScanSearch, Cpu, Shield, AlertTriangle, CheckCircle, Loader } from 'lucide-react'

type Tab = 'event' | 'bulk' | 'fingerprint' | 'rules'

const EMPTY_EVENT = `{
  "host": "PREMOS-WS-01",
  "process": "powershell.exe",
  "command_line": "powershell -nop -w hidden -enc SQBFAFgAIABOAGUAdwAtAE8AYgBq",
  "category": "process"
}`

const BULK_EXAMPLE = `{
  "events": [
    { "host": "PREMOS-WS-01", "process": "powershell.exe", "command_line": "powershell -enc SQBFAFgA" },
    { "host": "PREMOS-WS-02", "process": "rundll32.exe", "command_line": "rundll32 comsvcs.dll MiniDump 640 lsass.dmp full" }
  ]
}`

const TABS: [Tab, string, React.ComponentType<{ size?: number | string }>][] = [
  ['event',       'Evento Individual', Shield],
  ['bulk',        'Lote de Eventos',   AlertTriangle],
  ['fingerprint', 'Fingerprinting',    Cpu],
  ['rules',       'Reglas Activas',    ScanSearch],
]

function DetectionLoader() {
  return (
    <div className="flex min-h-screen items-center justify-center" style={{ background: '#0A0A0A' }}>
      <div className="w-5 h-5 rounded-full border-2 animate-spin"
        style={{ borderColor: 'rgba(232,93,4,0.2)', borderTopColor: '#E85D04' }} />
    </div>
  )
}

export default function DetectionPage() {
  const { isReady }              = useAuthGuard()
  const [tab, setTab]            = useState<Tab>('event')
  const [input, setInput]        = useState(EMPTY_EVENT)
  const [bulkInput, setBulkInput]   = useState(BULK_EXAMPLE)
  const [fpFilename, setFpFilename] = useState('sample.exe')
  const [fpHex, setFpHex]           = useState('50524546d6f73436f72700050524f50524520686f73743a5052454d4f532d57532d30310a')
  const [result, setResult]      = useState<Record<string, any> | null>(null)
  const [rules, setRules]        = useState<DetectionRulesResponse | null>(null)
  const [loading, setLoading]    = useState(false)
  const [error, setError]        = useState('')

  useEffect(() => {
    if (!isReady || tab !== 'rules' || rules) return
    getDetectionRules()
      .then(setRules)
      .catch((e: unknown) => {
        const msg = e instanceof Error ? e.message : 'Error desconocido'
        setError(`No se pudieron cargar las reglas. ${msg}`)
      })
  }, [isReady, tab, rules])

  if (!isReady) return <DetectionLoader />

  async function submit() {
    setLoading(true); setError(''); setResult(null)
    try {
      if (tab === 'event') {
        setResult(await evaluateEvent(JSON.parse(input)))
      } else if (tab === 'bulk') {
        const p = JSON.parse(bulkInput)
        setResult(await evaluateBulkEvents(p.events, p.original_analysis_ts))
      } else if (tab === 'fingerprint') {
        setResult(await fingerprintArtifact(fpFilename, fpHex))
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || 'Error al procesar')
    } finally {
      setLoading(false)
    }
  }

  const textareaStyle = {
    background: 'rgba(0,0,0,0.4)',
    border:     '1px solid rgba(255,255,255,0.08)',
    borderRadius: 12,
    color:      '#4ade80',
    fontFamily: 'var(--font-mono, monospace)',
    fontSize:   12,
    lineHeight: 1.6,
    resize:     'none' as const,
    outline:    'none',
    width:      '100%',
    padding:    '12px 14px',
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 overflow-auto">

        {/* Header */}
        <div
          className="sticky top-0 z-20 px-6 py-3 flex items-center gap-3"
          style={{
            background:   'rgba(10,10,10,0.92)',
            borderBottom: '1px solid rgba(255,255,255,0.05)',
            backdropFilter: 'blur(12px)',
          }}
        >
          <ScanSearch size={18} style={{ color: '#E85D04' }} />
          <div>
            <h1 className="text-sm font-bold leading-none" style={{ color: '#EAEAEA' }}>
              Módulo de Detección
            </h1>
            <p className="text-xs mt-0.5" style={{ color: '#3A3A3A' }}>
              14 reglas MITRE ATT&CK · motor editable
            </p>
          </div>
        </div>

        <div className="p-6 space-y-5 animate-fade-in">

          {/* Tab bar */}
          <div className="flex gap-2 flex-wrap">
            {TABS.map(([t, label, Icon]) => {
              const active = tab === t
              return (
                <button
                  key={t}
                  onClick={() => { setTab(t); setResult(null); setError('') }}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all duration-150"
                  style={
                    active
                      ? { background: 'rgba(232,93,4,0.15)', border: '1px solid rgba(232,93,4,0.35)', color: '#FF7A25' }
                      : { background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', color: '#5A5A5A' }
                  }
                  onMouseEnter={e => { if (!active) (e.currentTarget.style.color = '#A0A0A0') }}
                  onMouseLeave={e => { if (!active) (e.currentTarget.style.color = '#5A5A5A') }}
                >
                  <Icon size={14} />
                  {label}
                </button>
              )
            })}
          </div>

          <div className="grid grid-cols-12 gap-5">
            {/* ── Input panel ──────────────────────────────────── */}
            <div className="col-span-12 lg:col-span-5 space-y-4">

              {tab === 'event' && (
                <div className="card p-5">
                  <p className="text-xs font-semibold uppercase tracking-widest mb-3" style={{ color: '#5A5A5A' }}>
                    Evento JSON — formato ECS
                  </p>
                  <textarea value={input} onChange={e => setInput(e.target.value)} rows={12}
                    style={textareaStyle}
                    onFocus={e => (e.currentTarget.style.borderColor = 'rgba(232,93,4,0.45)')}
                    onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
                  />
                </div>
              )}

              {tab === 'bulk' && (
                <div className="card p-5">
                  <p className="text-xs font-semibold uppercase tracking-widest mb-3" style={{ color: '#5A5A5A' }}>
                    Lote de eventos — JSON
                  </p>
                  <textarea value={bulkInput} onChange={e => setBulkInput(e.target.value)} rows={12}
                    style={textareaStyle}
                    onFocus={e => (e.currentTarget.style.borderColor = 'rgba(232,93,4,0.45)')}
                    onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
                  />
                </div>
              )}

              {tab === 'fingerprint' && (
                <div className="card p-5 space-y-4">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-widest mb-2"
                      style={{ color: '#5A5A5A' }}>
                      Nombre del artefacto
                    </label>
                    <input value={fpFilename} onChange={e => setFpFilename(e.target.value)}
                      className="input-asc" />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-widest mb-2"
                      style={{ color: '#5A5A5A' }}>
                      Bytes del artefacto (hex)
                    </label>
                    <textarea value={fpHex} onChange={e => setFpHex(e.target.value)} rows={8}
                      placeholder="Bytes del archivo en hexadecimal..."
                      style={textareaStyle}
                      onFocus={e => (e.currentTarget.style.borderColor = 'rgba(232,93,4,0.45)')}
                      onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
                    />
                    <p className="text-xs mt-2" style={{ color: '#3A3A3A' }}>
                      Máx 64 KB (128 000 chars hex)
                    </p>
                  </div>
                </div>
              )}

              {tab === 'rules' && (
                <div className="card p-5">
                  <p className="text-xs" style={{ color: '#5A5A5A' }}>
                    Selecciona "Reglas Activas" para ver el catálogo completo →
                  </p>
                </div>
              )}

              {tab !== 'rules' && (
                <div className="space-y-2">
                  <button onClick={submit} disabled={loading}
                    className="btn-primary w-full flex items-center justify-center gap-2">
                    {loading
                      ? <><Loader size={14} className="animate-spin" /> Procesando...</>
                      : 'Evaluar'
                    }
                  </button>
                  {error && (
                    <div
                      className="flex items-start gap-2 px-3 py-2.5 rounded-xl text-xs"
                      style={{
                        background: 'rgba(192,21,46,0.1)',
                        border:     '1px solid rgba(192,21,46,0.3)',
                        color:      '#E8526E',
                      }}
                    >
                      <AlertTriangle size={13} className="flex-shrink-0 mt-0.5" />
                      {error}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* ── Results panel ──────────────────────────────── */}
            <div className="col-span-12 lg:col-span-7">

              {/* Rules catalog */}
              {tab === 'rules' && rules && (
                <div className="card p-5 space-y-4">
                  <h3 className="text-sm font-semibold" style={{ color: '#EAEAEA' }}>
                    Reglas de Detección Activas
                  </h3>
                  <div className="space-y-2">
                    {rules.rules?.map((r: any) => (
                      <div key={r.rule_id}
                        className="rounded-xl p-4"
                        style={{
                          background: 'rgba(0,0,0,0.3)',
                          border: '1px solid rgba(255,255,255,0.06)',
                        }}>
                        <div className="flex items-center gap-3 mb-1">
                          <span className="font-mono text-xs chip-orange">{r.rule_id}</span>
                          <span className="text-sm font-semibold" style={{ color: '#EAEAEA' }}>{r.name}</span>
                          <span className="ml-auto text-xs font-mono chip-orange">{r.mitre_ttp}</span>
                        </div>
                        <p className="text-xs" style={{ color: '#5A5A5A' }}>{r.description}</p>
                      </div>
                    ))}
                  </div>

                </div>
              )}

              {/* Detection results */}
              {result && (tab === 'event' || tab === 'bulk') && (
                <div className="card p-5">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-sm font-semibold" style={{ color: '#EAEAEA' }}>
                      Resultados de Detección
                    </h3>
                    <div className="flex items-center gap-2">
                      {result.total > 0
                        ? <AlertTriangle size={15} style={{ color: '#C0152E' }} />
                        : <CheckCircle size={15} style={{ color: '#3FD175' }} />
                      }
                      <span className="font-bold text-sm"
                        style={{ color: result.total > 0 ? '#E8526E' : '#3FD175' }}>
                        {result.total} deteccion{result.total !== 1 ? 'es' : ''}
                      </span>
                    </div>
                  </div>

                  {result.total === 0 && (
                    <div
                      className="flex items-center gap-3 rounded-xl p-4"
                      style={{
                        background: 'rgba(45,184,99,0.08)',
                        border: '1px solid rgba(45,184,99,0.2)',
                      }}>
                      <CheckCircle style={{ color: '#3FD175' }} size={18} />
                      <p className="text-sm" style={{ color: '#3FD175' }}>
                        Sin detecciones — evento limpio
                      </p>
                    </div>
                  )}

                  <div className="space-y-3 mt-3">
                    {result.results?.map((r: any, i: number) => (
                      <div key={i}
                        className="rounded-xl p-4"
                        style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)' }}>
                        <div className="flex items-start justify-between mb-2">
                          <div>
                            <span className="font-mono text-[10px]" style={{ color: '#5A5A5A' }}>
                              {r.rule_id}
                            </span>
                            <p className="font-semibold text-sm mt-0.5" style={{ color: '#EAEAEA' }}>
                              {r.rule_name}
                            </p>
                          </div>
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={r.severity} />
                            <Semaphore
                              posture={r.semaphore === 'red' ? 'CRITICAL' : r.semaphore === 'yellow' ? 'ELEVATED' : 'NORMAL'}
                              size="sm"
                            />
                          </div>
                        </div>
                        <p className="text-xs mb-2" style={{ color: '#5A5A5A' }}>{r.description}</p>
                        <div className="flex items-center gap-4 text-xs">
                          <span className="chip-orange font-mono">{r.mitre_ttp}</span>
                          <span style={{ color: '#E85D04' }}>Risk: {Number(r.risk_score).toFixed(2)}</span>
                          <span style={{ color: '#3A3A3A' }}>{r.detected_at?.slice(0, 19).replace('T', ' ')}</span>
                        </div>
                        {r.evidence && Object.keys(r.evidence).length > 0 && (
                          <details className="mt-3">
                            <summary className="text-xs cursor-pointer hover:opacity-80" style={{ color: '#5A5A5A' }}>
                              Evidencia
                            </summary>
                            <pre
                              className="text-xs font-mono mt-2 p-3 rounded-xl overflow-x-auto"
                              style={{ background: 'rgba(0,0,0,0.4)', color: '#A0A0A0' }}>
                              {JSON.stringify(r.evidence, null, 2)}
                            </pre>
                          </details>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Fingerprint result */}
              {result && tab === 'fingerprint' && (
                <div className="card p-5">
                  <div className="flex items-center justify-between mb-5">
                    <h3 className="text-sm font-semibold" style={{ color: '#EAEAEA' }}>
                      Resultado Fingerprinting
                    </h3>
                    <Semaphore
                      posture={
                        result.environmental_keying_detected
                          ? (result.confidence >= 0.8 ? 'CRITICAL' : 'ELEVATED')
                          : 'NORMAL'
                      }
                      size="md"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3 mb-4">
                    {[
                      {
                        label: 'Environmental Keying',
                        value: result.environmental_keying_detected ? 'DETECTADO' : 'NO DETECTADO',
                        color: result.environmental_keying_detected ? '#E8526E' : '#3FD175',
                      },
                      {
                        label: 'Confianza',
                        value: `${(result.confidence * 100).toFixed(0)}%`,
                        color: '#E85D04',
                      },
                      {
                        label: 'Risk Score',
                        value: Number(result.risk_score).toFixed(3),
                        color: '#E85D04',
                      },
                      {
                        label: 'Triggers Activados',
                        value: result.triggers?.length ?? 0,
                        color: '#EAEAEA',
                      },
                    ].map(({ label, value, color }) => (
                      <div key={label}
                        className="rounded-xl p-4"
                        style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)' }}>
                        <p className="text-xs mb-1" style={{ color: '#5A5A5A' }}>{label}</p>
                        <p className="text-xl font-bold font-mono" style={{ color }}>{value}</p>
                      </div>
                    ))}
                  </div>

                  {result.triggers?.length > 0 && (
                    <div className="mb-4">
                      <p className="text-xs mb-2" style={{ color: '#5A5A5A' }}>Checks disparados:</p>
                      <div className="flex flex-wrap gap-2">
                        {result.triggers.map((t: string) => (
                          <span key={t} className="chip-red font-mono text-xs">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div
                    className="rounded-xl p-4"
                    style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <p className="text-xs mb-1" style={{ color: '#5A5A5A' }}>Recomendación</p>
                    <p className="text-sm" style={{ color: '#A0A0A0' }}>{result.recommendation}</p>
                  </div>

                  {result.details?.length > 0 && (
                    <details className="mt-3">
                      <summary className="text-xs cursor-pointer hover:opacity-80" style={{ color: '#5A5A5A' }}>
                        {result.details.length} hallazgos detallados
                      </summary>
                      <pre
                        className="text-xs font-mono mt-2 p-3 rounded-xl overflow-x-auto max-h-48"
                        style={{ background: 'rgba(0,0,0,0.4)', color: '#A0A0A0' }}>
                        {JSON.stringify(result.details, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              )}

            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
