'use client'

import { useEffect, useState, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'
import {
  forensicGetLedger, forensicVerifyProof,
  ForensicEntry, ForensicLedger, ForensicVerifyResult,
} from '@/lib/api'
import {
  Lock, CheckCircle2, XCircle, RefreshCw, ShieldCheck,
  ChevronLeft, ChevronRight,
} from 'lucide-react'

function trunc(s: string, n = 16): string {
  return s.length > n ? `${s.slice(0, n)}…` : s
}

function formatTs(ts: string | null | undefined): string {
  if (!ts) return '—'
  try { return new Date(ts).toLocaleString() } catch { return ts }
}

function VerifiedBadge({ v }: { v: boolean | null }) {
  if (v === null) return <span className="text-xs" style={{ color: '#5A5A5A' }}>No verificada</span>
  return v
    ? (
      <span className="flex items-center gap-1 text-xs font-semibold" style={{ color: '#3FD175' }}>
        <CheckCircle2 size={12} /> Válida
      </span>
    ) : (
      <span className="flex items-center gap-1 text-xs font-semibold" style={{ color: '#E8526E' }}>
        <XCircle size={12} /> Inválida
      </span>
    )
}

const PAGE_SIZE = 20

export default function ForensicPage() {
  const { isReady } = useAuthGuard()

  const [entries, setEntries]       = useState<ForensicEntry[]>([])
  const [total, setTotal]           = useState(0)
  const [page, setPage]             = useState(0)
  const [loading, setLoading]       = useState(true)
  const [verifying, setVerifying]   = useState<string | null>(null)
  const [verifyResults, setVerifyResults] = useState<Record<string, ForensicVerifyResult>>({})
  const [error, setError]           = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res: ForensicLedger = await forensicGetLedger({ limit: PAGE_SIZE, offset: page * PAGE_SIZE })
      setEntries(res.entries)
      setTotal(res.total)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Error cargando ledger forense')
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => { if (!isReady) return; load() }, [load, isReady])

  async function handleVerify(entry: ForensicEntry) {
    setVerifying(entry.id)
    try {
      const result = await forensicVerifyProof(entry.action_id)
      setVerifyResults(prev => ({ ...prev, [entry.id]: result }))
      setEntries(prev => prev.map(e => e.id === entry.id ? { ...e, verified: result.valid } : e))
    } catch {
      setVerifyResults(prev => ({
        ...prev,
        [entry.id]: {
          action_id: entry.action_id, entry_id: entry.id, valid: false,
          hash_sha3_512: '', signed_by: '', signed_at: null, verified_at: null,
          message: 'Error al verificar',
        } satisfies ForensicVerifyResult,
      }))
    } finally {
      setVerifying(null)
    }
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)

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
            <Lock size={18} style={{ color: '#E85D04' }} />
            <div>
              <h1 className="text-sm font-bold leading-none" style={{ color: '#EAEAEA' }}>
                Ledger Forense PFN
              </h1>
              <p className="text-xs mt-0.5" style={{ color: '#3A3A3A' }}>
                Registro inmutable de neutralizaciones · Ed25519 + SHA3-512
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs" style={{ color: '#3A3A3A' }}>{total} entradas</span>
            <button
              onClick={load}
              disabled={loading}
              className="btn-secondary flex items-center gap-1.5 text-xs py-1.5 px-3"
            >
              <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
              Actualizar
            </button>
          </div>
        </div>

        <div className="p-6 space-y-5 animate-fade-in">

          {error && (
            <div
              className="rounded-xl p-3 text-xs"
              style={{ background: 'rgba(192,21,46,0.08)', border: '1px solid rgba(192,21,46,0.25)', color: '#E8526E' }}
            >
              {error}
            </div>
          )}

          {/* Ledger table */}
          <div className="card overflow-x-auto">
            {loading ? (
              <div className="flex items-center justify-center gap-3 py-16" style={{ color: '#3A3A3A' }}>
                <RefreshCw size={18} className="animate-spin" style={{ color: '#E85D04' }} />
                <span className="text-sm">Cargando ledger…</span>
              </div>
            ) : entries.length === 0 ? (
              <div className="text-center py-16">
                <ShieldCheck size={32} className="mx-auto mb-3 opacity-20" style={{ color: '#3FD175' }} />
                <p className="text-sm" style={{ color: '#5A5A5A' }}>Sin entradas forenses registradas</p>
                <p className="text-xs mt-1" style={{ color: '#3A3A3A' }}>
                  Las entradas se crean al ejecutar neutralizaciones aprobadas con clave de firma activa
                </p>
              </div>
            ) : (
              <table className="table-asc">
                <thead>
                  <tr>
                    <th>Acción ID</th>
                    <th>Tipo</th>
                    <th>Target</th>
                    <th>Firmado por</th>
                    <th>Firmado</th>
                    <th>Hash SHA3-512</th>
                    <th>Estado</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map(entry => {
                    const vr = verifyResults[entry.id]
                    const verified = vr ? vr.valid : (entry.verified ? true : null)
                    return (
                      <tr key={entry.id}>
                        <td className="font-mono text-xs" style={{ color: '#E85D04' }} title={entry.action_id}>
                          {trunc(entry.action_id, 12)}
                        </td>
                        <td className="text-xs" style={{ color: '#EAEAEA' }}>{entry.action_type}</td>
                        <td
                          className="text-xs max-w-[160px] truncate"
                          style={{ color: '#A0A0A0' }}
                          title={entry.target}
                        >
                          {entry.target}
                        </td>
                        <td
                          className="text-xs max-w-[140px] truncate"
                          style={{ color: '#A0A0A0' }}
                          title={entry.signed_by_email}
                        >
                          {entry.signed_by_email}
                        </td>
                        <td className="text-xs whitespace-nowrap" style={{ color: '#5A5A5A' }}>
                          {formatTs(entry.signed_at)}
                        </td>
                        <td className="font-mono text-xs" style={{ color: '#3A3A3A' }} title={entry.hash_sha3_512}>
                          {trunc(entry.hash_sha3_512, 20)}
                        </td>
                        <td><VerifiedBadge v={verified} /></td>
                        <td>
                          <button
                            onClick={() => handleVerify(entry)}
                            disabled={verifying === entry.id}
                            className="px-2 py-1 rounded-lg text-xs font-medium transition-all disabled:opacity-40"
                            style={{
                              border:   '1px solid rgba(232,93,4,0.3)',
                              color:    '#E85D04',
                              background: 'rgba(232,93,4,0.06)',
                            }}
                            onMouseEnter={e => (e.currentTarget.style.background = 'rgba(232,93,4,0.14)')}
                            onMouseLeave={e => (e.currentTarget.style.background = 'rgba(232,93,4,0.06)')}
                          >
                            {verifying === entry.id ? <RefreshCw size={11} className="animate-spin" /> : 'Verificar'}
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>

          {/* Verification result panels */}
          {Object.keys(verifyResults).length > 0 && (
            <div className="space-y-2">
              {Object.entries(verifyResults).map(([entryId, vr]) => (
                <div
                  key={entryId}
                  className="rounded-xl p-4 text-xs"
                  style={{
                    background: vr.valid ? 'rgba(45,184,99,0.05)'  : 'rgba(192,21,46,0.06)',
                    border:     vr.valid ? '1px solid rgba(45,184,99,0.25)' : '1px solid rgba(192,21,46,0.25)',
                  }}
                >
                  <div className="flex items-center gap-2 mb-3">
                    {vr.valid
                      ? <CheckCircle2 size={14} style={{ color: '#3FD175' }} />
                      : <XCircle     size={14} style={{ color: '#E8526E' }} />
                    }
                    <span className="font-semibold" style={{ color: vr.valid ? '#3FD175' : '#E8526E' }}>
                      Entrada {trunc(entryId, 12)} — {vr.valid ? 'Firma criptográfica válida ✓' : 'FIRMA INVÁLIDA — posible manipulación ✗'}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-x-6 gap-y-1" style={{ color: '#5A5A5A' }}>
                    <span>Hash SHA3-512:</span>
                    <span className="font-mono truncate" style={{ color: '#A0A0A0' }} title={vr.hash_sha3_512}>
                      {trunc(vr.hash_sha3_512, 36)}
                    </span>
                    <span>Firmado por:</span>
                    <span style={{ color: '#A0A0A0' }}>{vr.signed_by}</span>
                    {vr.verified_at && (
                      <>
                        <span>Verificado en:</span>
                        <span style={{ color: '#5A5A5A' }}>{formatTs(vr.verified_at)}</span>
                      </>
                    )}
                    <span>Mensaje:</span>
                    <span style={{ color: vr.valid ? '#3FD175' : '#E8526E' }}>{vr.message}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-4">
              <button
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                className="flex items-center gap-1 text-sm transition-colors disabled:opacity-30"
                style={{ color: '#5A5A5A' }}
                onMouseEnter={e => { if (page > 0) e.currentTarget.style.color = '#E85D04' }}
                onMouseLeave={e => (e.currentTarget.style.color = '#5A5A5A')}
              >
                <ChevronLeft size={14} /> Anterior
              </button>
              <span className="text-sm" style={{ color: '#3A3A3A' }}>
                Pág {page + 1} / {totalPages}
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="flex items-center gap-1 text-sm transition-colors disabled:opacity-30"
                style={{ color: '#5A5A5A' }}
                onMouseEnter={e => { if (page < totalPages - 1) e.currentTarget.style.color = '#E85D04' }}
                onMouseLeave={e => (e.currentTarget.style.color = '#5A5A5A')}
              >
                Siguiente <ChevronRight size={14} />
              </button>
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
