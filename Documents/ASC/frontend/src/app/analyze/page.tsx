'use client'
import { useState } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { analyzeFile, analyzeDomain, analyzeIP } from '@/lib/api'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import { useAuthGuard } from '@/lib/auth-guard'
import { AuthLoader } from '@/components/AuthLoader'
import { Upload, Globe, Network, Info, AlertTriangle, ShieldCheck } from 'lucide-react'
import { MAX_FILE_MB, fmtBytes, errMessage, validateFileSize } from '@/lib/analyze-format'

type Tab = 'file' | 'domain' | 'ip'

// Contenido educativo por pestaña: qué analiza, qué lo hace peligroso, limitaciones.
const TAB_INFO: Record<Tab, { analiza: string; peligroso: string; limita: string }> = {
  file: {
    analiza:
      'Hashes (MD5/SHA-1/SHA-256), tipo real del archivo, firmas de malware conocidas, imports de la cabecera PE (APIs de Windows), strings legibles, candidatos a mutex y un puntaje de riesgo agregado.',
    peligroso:
      'APIs de inyección de código o persistencia, mutexes de familias de malware conocidas, coincidencia con firmas, y URLs/strings sospechosas elevan el riesgo.',
    limita:
      'Análisis ESTÁTICO — no ejecuta el archivo ni usa sandbox dinámico. Máximo ~4 MB por el límite de la plataforma serverless; los binarios grandes no se pueden subir aquí. El enriquecimiento con VirusTotal/AbuseIPDB requiere clave configurada.',
  },
  domain: {
    analiza: 'Reputación, señales de riesgo y categorización del dominio con los feeds disponibles.',
    peligroso:
      'Dominios recién registrados, en listas de bloqueo, con patrones DGA o asociados a C2/phishing elevan el riesgo.',
    limita:
      'El enriquecimiento con feeds externos requiere claves configuradas; sin ellas, el veredicto es limitado a heurísticas locales.',
  },
  ip: {
    analiza: 'Reputación de la IP, reportes de abuso y señales de riesgo con los feeds disponibles.',
    peligroso:
      'IPs en listas de bloqueo, con historial de abuso reciente o asociadas a infraestructura maliciosa elevan el riesgo.',
    limita:
      'El enriquecimiento con AbuseIPDB/feeds requiere claves configuradas; sin ellas, el veredicto es limitado a heurísticas locales.',
  },
}

export default function AnalyzePage() {
  const { isReady } = useAuthGuard()
  const [tab, setTab]       = useState<Tab>('file')
  const [file, setFile]     = useState<File | null>(null)
  const [domain, setDomain] = useState('')
  const [ip, setIp]         = useState('')
  const [result, setResult] = useState<Record<string, any> | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]   = useState('')

  function onPickFile(f: File | null) {
    setError(''); setResult(null)
    if (f) {
      const msg = validateFileSize(f)
      if (msg) { setFile(null); setError(msg); return }
    }
    setFile(f)
  }

  async function submit() {
    setLoading(true); setError(''); setResult(null)
    try {
      if (tab === 'file' && file)      setResult(await analyzeFile(file))
      else if (tab === 'domain' && domain) setResult(await analyzeDomain(domain))
      else if (tab === 'ip' && ip)     setResult(await analyzeIP(ip))
    } catch (e: unknown) {
      setError(errMessage(e))
    } finally {
      setLoading(false)
    }
  }

  const verdict = (result?.verdict as string) ?? ''
  const verdictColor: Record<string, string> = { malicious: '#C0152E', suspicious: '#E85D04', clean: '#3ECF8E' }
  const vColor = verdictColor[verdict] ?? '#A0A0A0'
  const pe = result?.pe_analysis as { is_pe?: boolean; arch?: string; suspicious_apis?: string[] } | undefined
  const mtx = result?.mutex_analysis as { known_malware?: { value: string; family: string; severity: string }[]; candidates_count?: number } | undefined
  const info = TAB_INFO[tab]

  if (!isReady) return <AuthLoader />

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6" style={{ background: 'transparent' }}>
        <div className="flex items-center gap-3 mb-1">
          <ShieldCheck size={20} style={{ color: '#E85D04' }} />
          <h1 className="text-2xl font-bold" style={{ color: '#EAEAEA' }}>Análisis de Artefactos</h1>
        </div>
        <p className="text-sm mb-6" style={{ color: '#5A5A5A' }}>Análisis estático de archivos, dominios e IPs · PremosCorp ASC</p>

        {/* Tabs */}
        <div className="flex gap-2 mb-5">
          {([['file', 'Archivo', Upload], ['domain', 'Dominio', Globe], ['ip', 'IP', Network]] as const).map(([t, label, Icon]) => (
            <button key={t} onClick={() => { setTab(t); setResult(null); setError('') }}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
              style={tab === t
                ? { background: '#E85D04', color: '#fff' }
                : { background: '#141414', color: '#8A8A8A', border: '1px solid #262626' }}>
              <Icon size={14} />{label}
            </button>
          ))}
        </div>

        {/* Panel educativo */}
        <div className="rounded-xl p-4 mb-5 max-w-3xl" style={{ background: 'rgba(232,93,4,0.05)', border: '1px solid rgba(232,93,4,0.16)' }}>
          <div className="grid gap-3 sm:grid-cols-3">
            <div>
              <p className="flex items-center gap-1.5 text-xs font-semibold mb-1" style={{ color: '#E85D04' }}><Info size={12} /> Qué analiza</p>
              <p className="text-xs leading-relaxed" style={{ color: '#9A9A9A' }}>{info.analiza}</p>
            </div>
            <div>
              <p className="flex items-center gap-1.5 text-xs font-semibold mb-1" style={{ color: '#E85D04' }}><AlertTriangle size={12} /> Qué lo hace peligroso</p>
              <p className="text-xs leading-relaxed" style={{ color: '#9A9A9A' }}>{info.peligroso}</p>
            </div>
            <div>
              <p className="flex items-center gap-1.5 text-xs font-semibold mb-1" style={{ color: '#8A8A8A' }}><ShieldCheck size={12} /> Limitaciones</p>
              <p className="text-xs leading-relaxed" style={{ color: '#7A7A7A' }}>{info.limita}</p>
            </div>
          </div>
        </div>

        {/* Input */}
        <div className="card max-w-lg mb-6">
          {tab === 'file' && (
            <div>
              <label className="block text-sm mb-2" style={{ color: '#A0A0A0' }}>Seleccionar archivo sospechoso (máx {MAX_FILE_MB} MB)</label>
              <input type="file" onChange={e => onPickFile(e.target.files?.[0] ?? null)}
                className="block w-full text-sm cursor-pointer" style={{ color: '#9A9A9A' }} />
              {file && <p className="text-xs mt-2" style={{ color: '#5A5A5A' }}>{file.name} · {fmtBytes(file.size)}</p>}
            </div>
          )}
          {tab === 'domain' && (
            <div>
              <label className="block text-sm mb-2" style={{ color: '#A0A0A0' }}>Dominio a analizar</label>
              <input value={domain} onChange={e => setDomain(e.target.value)} placeholder="ej. dominio-malicioso.xyz"
                className="w-full rounded px-3 py-2 text-white text-sm outline-none" style={{ background: '#0F0F0F', border: '1px solid #262626' }} />
            </div>
          )}
          {tab === 'ip' && (
            <div>
              <label className="block text-sm mb-2" style={{ color: '#A0A0A0' }}>Dirección IP</label>
              <input value={ip} onChange={e => setIp(e.target.value)} placeholder="ej. 185.220.101.1"
                className="w-full rounded px-3 py-2 text-white text-sm outline-none" style={{ background: '#0F0F0F', border: '1px solid #262626' }} />
            </div>
          )}
          <button onClick={submit} disabled={loading || (tab === 'file' && !file)}
            className="btn-primary mt-4 w-full flex items-center justify-center gap-2 disabled:opacity-50">
            {loading ? 'Analizando…' : 'Analizar'}
          </button>
          {error && (
            <div className="mt-3 rounded-lg p-2.5 text-xs" style={{ background: 'rgba(192,21,46,0.1)', border: '1px solid rgba(192,21,46,0.3)', color: '#F2A0A0' }}>
              {error}
            </div>
          )}
        </div>

        {/* Result */}
        {result && (
          <div className="card max-w-2xl space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold" style={{ color: '#EAEAEA' }}>Resultado del Análisis</h2>
              {verdict && <span className="text-xl font-black uppercase" style={{ color: vColor }}>{verdict}</span>}
            </div>

            <div className="grid grid-cols-2 gap-3">
              {result.risk_score != null && (
                <div className="rounded p-3" style={{ background: '#0F0F0F' }}>
                  <p className="text-xs mb-1" style={{ color: '#5A5A5A' }}>Puntaje de riesgo</p>
                  <p className="text-2xl font-bold" style={{ color: vColor }}>{Number(result.risk_score).toFixed(3)}</p>
                </div>
              )}
              {(result.file_type || result.size_bytes != null) && (
                <div className="rounded p-3" style={{ background: '#0F0F0F' }}>
                  <p className="text-xs mb-1" style={{ color: '#5A5A5A' }}>Archivo</p>
                  <p className="text-sm" style={{ color: '#EAEAEA' }}>{result.file_type ?? '—'}</p>
                  <p className="text-xs" style={{ color: '#5A5A5A' }}>{fmtBytes(result.size_bytes)}</p>
                </div>
              )}
            </div>

            {result.hashes?.sha256 && (
              <div className="rounded p-3" style={{ background: '#0F0F0F' }}>
                <p className="text-xs mb-1" style={{ color: '#5A5A5A' }}>SHA-256</p>
                <p className="font-mono text-xs break-all" style={{ color: '#A0A0A0' }}>{result.hashes.sha256}</p>
              </div>
            )}

            {Array.isArray(result.ttps) && result.ttps.length > 0 && (
              <div>
                <p className="text-sm font-semibold mb-2" style={{ color: '#E85D04' }}>Técnicas MITRE ATT&CK</p>
                <div className="flex flex-wrap gap-2">
                  {result.ttps.map((t: string) => (
                    <span key={t} className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'rgba(232,93,4,0.1)', color: '#E85D04' }}>{t}</span>
                  ))}
                </div>
              </div>
            )}

            {pe?.is_pe && (
              <div className="rounded p-3" style={{ background: '#0F0F0F' }}>
                <p className="text-sm font-semibold mb-2" style={{ color: '#EAEAEA' }}>Cabecera PE · {pe.arch}</p>
                {pe.suspicious_apis && pe.suspicious_apis.length > 0
                  ? <div className="flex flex-wrap gap-1.5">
                      {pe.suspicious_apis.map(a => <span key={a} className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'rgba(232,93,4,0.08)', color: '#F2A0A0' }}>{a}</span>)}
                    </div>
                  : <p className="text-xs" style={{ color: '#5A5A5A' }}>Sin APIs sospechosas destacadas</p>}
              </div>
            )}

            {mtx?.known_malware && mtx.known_malware.length > 0 && (
              <div>
                <p className="text-sm font-semibold mb-2" style={{ color: '#C0152E' }}>Mutex de malware conocido</p>
                <div className="space-y-1">
                  {mtx.known_malware.map((m, i) => (
                    <div key={i} className="flex items-center justify-between rounded px-3 py-2" style={{ background: '#0F0F0F' }}>
                      <span className="text-xs font-mono" style={{ color: '#EAEAEA' }}>{m.value} <span style={{ color: '#C0152E' }}>({m.family})</span></span>
                      <SeverityBadge severity={m.severity} />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {Array.isArray(result.signature_hits) && result.signature_hits.length > 0 && (
              <div>
                <p className="text-sm font-semibold mb-2" style={{ color: '#E85D04' }}>Firmas detectadas</p>
                <div className="space-y-1">
                  {result.signature_hits.map((h: any, i: number) => (
                    <div key={i} className="flex items-center justify-between rounded px-3 py-2" style={{ background: '#0F0F0F' }}>
                      <span className="text-sm font-mono" style={{ color: '#EAEAEA' }}>{h.rule ?? h.name ?? String(h)}</span>
                      {h.severity && <SeverityBadge severity={h.severity} />}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.strings_count != null && (
              <p className="text-xs" style={{ color: '#5A5A5A' }}>
                {result.strings_count} strings extraídas · {mtx?.candidates_count ?? 0} candidatos a mutex
              </p>
            )}
          </div>
        )}
      </main>
    </div>
  )
}
