'use client'
import { useState, useEffect, useCallback } from 'react'
import { ShieldCheck, User, Clock, Hash, CheckCircle, XCircle, AlertTriangle, RefreshCw } from 'lucide-react'
import { listIdentityActions, verifyIdentityAction, getPidsSummary, IdentityAction } from '@/lib/api'

const ACTION_TYPE_LABELS: Record<string, string> = {
  disable_account: 'Deshabilitar cuenta',
  enable_account: 'Habilitar cuenta',
  force_password_reset: 'Forzar reset de contraseña',
  quarantine_account: 'Cuarentena de cuenta',
  enrich_user: 'Enriquecimiento de identidad',
}

const ACTION_TYPE_COLORS: Record<string, string> = {
  disable_account: 'text-red-400',
  enable_account: 'text-green-400',
  force_password_reset: 'text-yellow-400',
  quarantine_account: 'text-orange-400',
  enrich_user: 'text-cyan-400',
}

function KPICard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="bg-navy-800 border border-navy-700 rounded-lg p-4">
      <p className="text-xs text-gray-400 mb-1">{label}</p>
      <p className="text-2xl font-bold text-white">{value}</p>
      {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
    </div>
  )
}

function ActionRow({ action, onVerify }: { action: IdentityAction; onVerify: (id: string) => void }) {
  const labelColor = ACTION_TYPE_COLORS[action.action_type] ?? 'text-gray-300'
  return (
    <tr className="border-b border-navy-700 hover:bg-navy-750">
      <td className="px-4 py-3">
        <span className={`text-sm font-medium ${labelColor}`}>
          {ACTION_TYPE_LABELS[action.action_type] ?? action.action_type}
        </span>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <User size={12} className="text-gray-500" />
          <span className="text-sm text-white">{action.username}</span>
          <span className="text-xs text-gray-500">@{action.domain}</span>
        </div>
      </td>
      <td className="px-4 py-3">
        {action.success ? (
          <span className="flex items-center gap-1 text-green-400 text-xs">
            <CheckCircle size={12} /> OK
          </span>
        ) : (
          <span className="flex items-center gap-1 text-red-400 text-xs">
            <XCircle size={12} /> Falló
          </span>
        )}
      </td>
      <td className="px-4 py-3 text-xs text-gray-400 max-w-xs truncate">{action.reason}</td>
      <td className="px-4 py-3">
        {action.hash_sha3_512 ? (
          <span className="flex items-center gap-1 text-cyan-400 text-xs font-mono">
            <Hash size={10} />
            {action.hash_sha3_512.slice(0, 12)}…
          </span>
        ) : (
          <span className="text-gray-600 text-xs">sin hash</span>
        )}
      </td>
      <td className="px-4 py-3 text-xs text-gray-500">
        {action.executed_at ? new Date(action.executed_at).toLocaleString('es') : '—'}
      </td>
      <td className="px-4 py-3 text-xs text-gray-400">{action.initiated_by}</td>
      <td className="px-4 py-3">
        <button
          onClick={() => onVerify(action.id)}
          className="px-2 py-1 rounded text-xs bg-navy-700 hover:bg-cyan-400/10 text-gray-300 hover:text-cyan-400 transition-colors"
        >
          Verificar
        </button>
      </td>
    </tr>
  )
}

function VerifyModal({ result, onClose }: { result: Record<string, unknown>; onClose: () => void }) {
  const hashMatch = result.hash_match as boolean
  const sigOk = result.signature_ok as boolean | null
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div
        className="bg-navy-800 border border-navy-600 rounded-xl p-6 max-w-lg w-full mx-4 space-y-4"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-3">
          <ShieldCheck size={20} className={hashMatch ? 'text-green-400' : 'text-red-400'} />
          <h3 className="text-white font-semibold">Verificación forense PIDS</h3>
        </div>

        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-400">Hash SHA3-512</span>
            <span className={hashMatch ? 'text-green-400' : 'text-red-400'}>
              {hashMatch ? '✓ Íntegro' : '✗ Alterado'}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">Firma Ed25519</span>
            <span className={sigOk === true ? 'text-green-400' : sigOk === false ? 'text-red-400' : 'text-gray-500'}>
              {sigOk === true ? '✓ Válida' : sigOk === false ? '✗ Inválida' : 'No configurada'}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">Firmado por</span>
            <span className="text-white">{result.signed_by as string}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">Tipo de acción</span>
            <span className="text-cyan-400">{result.action_type as string}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">Usuario objetivo</span>
            <span className="text-white">{result.username as string}</span>
          </div>
        </div>

        <div className="bg-navy-900 rounded p-3 font-mono text-xs text-gray-400 break-all">
          {(result.stored_hash as string)?.slice(0, 64)}…
        </div>

        <button
          onClick={onClose}
          className="w-full py-2 rounded bg-navy-700 text-sm text-gray-300 hover:bg-navy-600 transition-colors"
        >
          Cerrar
        </button>
      </div>
    </div>
  )
}

export default function PIDSPage() {
  const [actions, setActions] = useState<IdentityAction[]>([])
  const [summary, setSummary] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [filterType, setFilterType] = useState('')
  const [filterSuccess, setFilterSuccess] = useState<'all' | 'true' | 'false'>('all')
  const [verifyResult, setVerifyResult] = useState<Record<string, unknown> | null>(null)
  const [verifyError, setVerifyError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, unknown> = { limit: 200 }
      if (filterType) params.action_type = filterType
      if (filterSuccess !== 'all') params.success = filterSuccess === 'true'
      const [res, summ] = await Promise.all([
        listIdentityActions(params as Parameters<typeof listIdentityActions>[0]),
        getPidsSummary(),
      ])
      setActions(res.actions)
      setSummary(summ)
    } finally {
      setLoading(false)
    }
  }, [filterType, filterSuccess])

  useEffect(() => { load() }, [load])

  const handleVerify = async (actionId: string) => {
    setVerifyError('')
    try {
      const result = await verifyIdentityAction(actionId)
      setVerifyResult(result as unknown as Record<string, unknown>)
    } catch {
      setVerifyError('Error verificando token forense')
    }
  }

  return (
    <div className="flex-1 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldCheck size={20} className="text-cyan-400" />
            PIDS — Premos Identity-Driven SOAR
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Acciones de identidad con token forense Ed25519 + SHA3-512 — P26
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-2 rounded bg-navy-700 text-sm text-gray-300 hover:bg-navy-600 transition-colors disabled:opacity-50"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          Actualizar
        </button>
      </div>

      {/* KPI strip */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <KPICard label="Total acciones" value={summary.total_actions as number} />
          <KPICard label="Exitosas" value={summary.successful_actions as number} />
          <KPICard label="Fallidas" value={summary.failed_actions as number} />
          <KPICard
            label="Tasa de éxito"
            value={`${summary.success_rate_pct as number}%`}
          />
          <KPICard
            label="Últimas 24h"
            value={summary.actions_24h as number}
            sub="acciones recientes"
          />
        </div>
      )}

      {verifyError && (
        <div className="flex items-center gap-2 p-3 bg-red-900/30 border border-red-700 rounded text-red-300 text-sm">
          <AlertTriangle size={14} />
          {verifyError}
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <select
          value={filterType}
          onChange={e => setFilterType(e.target.value)}
          className="bg-navy-800 border border-navy-600 rounded px-3 py-1.5 text-sm text-gray-200 focus:outline-none"
        >
          <option value="">Todos los tipos</option>
          {Object.entries(ACTION_TYPE_LABELS).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
        <select
          value={filterSuccess}
          onChange={e => setFilterSuccess(e.target.value as 'all' | 'true' | 'false')}
          className="bg-navy-800 border border-navy-600 rounded px-3 py-1.5 text-sm text-gray-200 focus:outline-none"
        >
          <option value="all">Todos los resultados</option>
          <option value="true">Solo exitosas</option>
          <option value="false">Solo fallidas</option>
        </select>
        <span className="text-xs text-gray-500">{actions.length} acciones</span>
      </div>

      {/* Table */}
      <div className="bg-navy-800 border border-navy-700 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-navy-900 border-b border-navy-700">
              <tr>
                {['Tipo', 'Usuario', 'Resultado', 'Razón', 'Hash forense', 'Ejecutado', 'Iniciado por', ''].map(h => (
                  <th key={h} className="px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wide">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-gray-500 text-sm">
                    Cargando acciones PIDS…
                  </td>
                </tr>
              ) : actions.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-gray-500 text-sm">
                    No hay acciones de identidad registradas
                  </td>
                </tr>
              ) : (
                actions.map(a => (
                  <ActionRow key={a.id} action={a} onVerify={handleVerify} />
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {verifyResult && (
        <VerifyModal
          result={verifyResult}
          onClose={() => setVerifyResult(null)}
        />
      )}
    </div>
  )
}
