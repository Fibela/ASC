'use client'

import { useEffect, useState, useCallback } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { useAuthGuard } from '@/lib/auth-guard'
import {
  forensicGetLedger, forensicVerifyProof,
  ForensicEntry, ForensicLedger, ForensicVerifyResult,
} from '@/lib/api'
import {
  Lock, CheckCircle2, XCircle, RefreshCw, ShieldCheck, ChevronLeft, ChevronRight,
} from 'lucide-react'

// ── Helpers ───────────────────────────────────────────────────────────────────

function trunc(s: string, n = 16): string {
  return s.length > n ? `${s.slice(0, n)}…` : s
}

function formatTs(ts: string | null | undefined): string {
  if (!ts) return '—'
  try { return new Date(ts).toLocaleString() } catch { return ts }
}

function VerifiedBadge({ v }: { v: boolean | null }) {
  if (v === null) return <span className="text-xs text-gray-500">No verificada</span>
  return v
    ? <span className="flex items-center gap-1 text-xs text-green-400"><CheckCircle2 size={12} /> Válida</span>
    : <span className="flex items-center gap-1 text-xs text-red-400"><XCircle size={12} /> Inválida</span>
}

// ── Page ──────────────────────────────────────────────────────────────────────

const PAGE_SIZE = 20

export default function ForensicPage() {
  useAuthGuard()

  const [entries, setEntries] = useState<ForensicEntry[]>([])
  const [total, setTotal]     = useState(0)
  const [page, setPage]       = useState(0)
  const [loading, setLoading] = useState(true)
  const [verifying, setVerifying] = useState<string | null>(null)
  const [verifyResults, setVerifyResults] = useState<Record<string, ForensicVerifyResult>>({})
  const [error, setError]     = useState<string | null>(null)

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

  useEffect(() => { load() }, [load])

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

  return (
    <div className="flex min-h-screen bg-navy-900 text-white">
      <Sidebar />
      <main className="flex-1 p-6 overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Lock size={22} className="text-cyan-400" />
            <div>
              <h1 className="text-xl font-bold text-white">Ledger Forense PFN</h1>
              <p className="text-xs text-gray-400">Registro inmutable de neutralizaciones · Ed25519 + SHA3-512</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-gray-500">{total} entradas</span>
            <button
              onClick={load}
              disabled={loading}
              className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-cyan-400 transition-colors disabled:opacity-40"
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
              Actualizar
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-4 bg-red-900/20 border border-red-700/50 rounded p-3 text-xs text-red-400">
            {error}
          </div>
        )}

        {/* Table */}
        <div className="bg-navy-800 border border-navy-700 rounded-lg overflow-x-auto">
          {loading ? (
            <p className="text-center text-gray-500 text-sm py-10">Cargando ledger…</p>
          ) : entries.length === 0 ? (
            <div className="text-center py-16">
              <ShieldCheck size={32} className="mx-auto text-gray-600 mb-3" />
              <p className="text-gray-500 text-sm">Sin entradas forenses registradas</p>
              <p className="text-xs text-gray-600 mt-1">
                Las entradas se crean al ejecutar neutralizaciones aprobadas con clave de firma activa
              </p>
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-navy-700 text-gray-400">
                  <th className="px-4 py-3 text-left">Acción ID</th>
                  <th className="px-4 py-3 text-left">Tipo</th>
                  <th className="px-4 py-3 text-left">Target</th>
                  <th className="px-4 py-3 text-left">Firmado por</th>
                  <th className="px-4 py-3 text-left">Firmado</th>
                  <th className="px-4 py-3 text-left">Hash SHA3-512</th>
                  <th className="px-4 py-3 text-left">Estado</th>
                  <th className="px-4 py-3 text-left"></th>
                </tr>
              </thead>
              <tbody>
                {entries.map(entry => {
                  const vr = verifyResults[entry.id]
                  const verified = vr ? vr.valid : (entry.verified ? true : null)
                  return (
                    <tr key={entry.id} className="border-b border-navy-700/50 hover:bg-navy-700/30 transition-colors">
                      <td className="px-4 py-2 font-mono text-cyan-300" title={entry.action_id}>
                        {trunc(entry.action_id, 12)}
                      </td>
                      <td className="px-4 py-2 text-gray-200">{entry.action_type}</td>
                      <td className="px-4 py-2 text-gray-300 max-w-[160px] truncate" title={entry.target}>
                        {entry.target}
                      </td>
                      <td className="px-4 py-2 text-gray-300 max-w-[140px] truncate" title={entry.signed_by_email}>
                        {entry.signed_by_email}
                      </td>
                      <td className="px-4 py-2 text-gray-400 whitespace-nowrap">{formatTs(entry.signed_at)}</td>
                      <td className="px-4 py-2 font-mono text-gray-500" title={entry.hash_sha3_512}>
                        {trunc(entry.hash_sha3_512, 20)}
                      </td>
                      <td className="px-4 py-2">
                        <VerifiedBadge v={verified} />
                      </td>
                      <td className="px-4 py-2">
                        <button
                          onClick={() => handleVerify(entry)}
                          disabled={verifying === entry.id}
                          className="px-2 py-1 rounded text-xs border border-cyan-700 text-cyan-400 hover:bg-cyan-400/10 transition-colors disabled:opacity-40 whitespace-nowrap"
                        >
                          {verifying === entry.id ? '…' : 'Verificar'}
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
          <div className="mt-4 space-y-2">
            {Object.entries(verifyResults).map(([entryId, vr]) => (
              <div
                key={entryId}
                className={`rounded-lg border p-3 text-xs ${
                  vr.valid
                    ? 'bg-green-900/10 border-green-700/50'
                    : 'bg-red-900/10 border-red-700/50'
                }`}
              >
                <div className="flex items-center gap-2 mb-2">
                  {vr.valid
                    ? <CheckCircle2 size={14} className="text-green-400" />
                    : <XCircle size={14} className="text-red-400" />
                  }
                  <span className={`font-semibold ${vr.valid ? 'text-green-400' : 'text-red-400'}`}>
                    Entrada {trunc(entryId, 12)} — {vr.valid ? 'Firma criptográfica válida ✓' : 'FIRMA INVÁLIDA — posible manipulación ✗'}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-gray-400">
                  <span>Hash SHA3-512:</span>
                  <span className="font-mono text-gray-300 truncate" title={vr.hash_sha3_512}>
                    {trunc(vr.hash_sha3_512, 36)}
                  </span>
                  <span>Firmado por:</span>
                  <span className="text-gray-300">{vr.signed_by}</span>
                  {vr.verified_at && (
                    <>
                      <span>Verificado en:</span>
                      <span className="text-gray-400">{formatTs(vr.verified_at)}</span>
                    </>
                  )}
                  <span>Mensaje:</span>
                  <span className={vr.valid ? 'text-green-400' : 'text-red-400'}>{vr.message}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-center gap-3 mt-4 text-sm">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="flex items-center gap-1 text-gray-400 hover:text-white disabled:opacity-30"
            >
              <ChevronLeft size={16} /> Anterior
            </button>
            <span className="text-gray-500">Pág {page + 1} / {totalPages}</span>
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="flex items-center gap-1 text-gray-400 hover:text-white disabled:opacity-30"
            >
              Siguiente <ChevronRight size={16} />
            </button>
          </div>
        )}
      </main>
    </div>
  )
}
