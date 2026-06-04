'use client'
import { useState } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { analyzeFile, analyzeDomain, analyzeIP } from '@/lib/api'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import { Upload, Globe, Network } from 'lucide-react'

type Tab = 'file' | 'domain' | 'ip'

export default function AnalyzePage() {
  const [tab, setTab]       = useState<Tab>('file')
  const [file, setFile]     = useState<File | null>(null)
  const [domain, setDomain] = useState('')
  const [ip, setIp]         = useState('')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]   = useState('')

  async function submit() {
    setLoading(true); setError(''); setResult(null)
    try {
      if (tab === 'file' && file)   setResult(await analyzeFile(file))
      if (tab === 'domain' && domain) setResult(await analyzeDomain(domain))
      if (tab === 'ip' && ip)       setResult(await analyzeIP(ip))
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  const verdict = result?.verdict ?? ''
  const verdictColor = { malicious: 'text-red-400', suspicious: 'text-orange-400', clean: 'text-green-400' }[verdict] ?? 'text-cyan-400'

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6">
        <h1 className="text-2xl font-bold text-white mb-6">Análisis de Artefactos</h1>

        {/* Tabs */}
        <div className="flex gap-2 mb-6">
          {([['file', 'Archivo', Upload], ['domain', 'Dominio', Globe], ['ip', 'IP', Network]] as const).map(([t, label, Icon]) => (
            <button key={t} onClick={() => setTab(t)}
              className={`flex items-center gap-2 px-4 py-2 rounded text-sm font-medium transition-colors ${tab === t ? 'bg-cyan-400 text-navy-900' : 'bg-navy-800 text-gray-400 hover:text-white'}`}>
              <Icon size={14} />{label}
            </button>
          ))}
        </div>

        {/* Input */}
        <div className="card max-w-lg mb-6">
          {tab === 'file' && (
            <div>
              <label className="block text-sm text-gray-400 mb-2">Seleccionar archivo sospechoso</label>
              <input type="file" onChange={e => setFile(e.target.files?.[0] ?? null)}
                className="block w-full text-sm text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:bg-cyan-400/20 file:text-cyan-400 cursor-pointer" />
            </div>
          )}
          {tab === 'domain' && (
            <div>
              <label className="block text-sm text-gray-400 mb-2">Dominio a analizar</label>
              <input value={domain} onChange={e => setDomain(e.target.value)} placeholder="e.g. malware-domain.xyz"
                className="w-full bg-navy-900 border border-navy-700 rounded px-3 py-2 text-white text-sm outline-none focus:border-cyan-400" />
            </div>
          )}
          {tab === 'ip' && (
            <div>
              <label className="block text-sm text-gray-400 mb-2">Dirección IP</label>
              <input value={ip} onChange={e => setIp(e.target.value)} placeholder="e.g. 192.168.1.100"
                className="w-full bg-navy-900 border border-navy-700 rounded px-3 py-2 text-white text-sm outline-none focus:border-cyan-400" />
            </div>
          )}
          <button onClick={submit} disabled={loading}
            className="btn-primary mt-4 w-full flex items-center justify-center gap-2 disabled:opacity-50">
            {loading ? 'Analizando...' : 'Analizar'}
          </button>
          {error && <p className="text-red-400 text-sm mt-2">{error}</p>}
        </div>

        {/* Result */}
        {result && (
          <div className="card max-w-2xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Resultado del Análisis</h2>
              <span className={`text-2xl font-black uppercase ${verdictColor}`}>{verdict}</span>
            </div>
            <div className="grid grid-cols-2 gap-3 mb-4">
              <div className="bg-navy-900 rounded p-3">
                <p className="text-xs text-gray-500 mb-1">Risk Score</p>
                <p className="text-2xl font-bold text-cyan-400">{Number(result.risk_score).toFixed(3)}</p>
              </div>
              {result.hashes && (
                <div className="bg-navy-900 rounded p-3">
                  <p className="text-xs text-gray-500 mb-1">SHA256</p>
                  <p className="font-mono text-xs text-gray-300 break-all">{result.hashes.sha256}</p>
                </div>
              )}
            </div>
            {result.signature_hits?.length > 0 && (
              <div>
                <p className="text-sm font-semibold text-orange-400 mb-2">Firmas detectadas:</p>
                <div className="space-y-1">
                  {result.signature_hits.map((h: any, i: number) => (
                    <div key={i} className="flex items-center justify-between bg-navy-900 rounded px-3 py-2">
                      <span className="text-sm font-mono text-gray-200">{h.rule}</span>
                      <SeverityBadge severity={h.severity} />
                    </div>
                  ))}
                </div>
              </div>
            )}
            {result.flags?.length > 0 && (
              <div className="mt-3">
                <p className="text-sm font-semibold text-yellow-400 mb-2">Indicadores:</p>
                <div className="flex flex-wrap gap-2">
                  {result.flags.map((f: string) => (
                    <span key={f} className="bg-navy-900 text-yellow-400 text-xs px-2 py-0.5 rounded font-mono">{f}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}
