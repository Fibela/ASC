'use client'
import { useState } from 'react'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { FileText, Download } from 'lucide-react'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

export default function ReportsPage() {
  const [hours, setHours]     = useState(24)
  const [analyst, setAnalyst] = useState('SOC Analyst')

  function download(format: 'pdf' | 'html') {
    const url = `${API_URL}/api/v1/reports/${format}?hours=${hours}&analyst=${encodeURIComponent(analyst)}`
    window.open(url, '_blank')
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6">
        <h1 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
          <FileText className="text-cyan-400" size={22} />
          Generación de Reportes
        </h1>

        <div className="card max-w-md">
          <h2 className="text-lg font-semibold text-cyan-400 mb-4">Configurar Reporte</h2>

          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Período (horas)</label>
              <select value={hours} onChange={e => setHours(Number(e.target.value))}
                className="w-full bg-navy-900 border border-navy-700 text-sm text-gray-300 rounded px-3 py-2 outline-none focus:border-cyan-400">
                {[6, 12, 24, 48, 72, 168].map(h => (
                  <option key={h} value={h}>{h}h {h === 168 ? '(1 semana)' : h === 24 ? '(24h - default)' : ''}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-1">Analista firmante</label>
              <input value={analyst} onChange={e => setAnalyst(e.target.value)}
                className="w-full bg-navy-900 border border-navy-700 text-sm text-gray-300 rounded px-3 py-2 outline-none focus:border-cyan-400" />
            </div>

            <div className="flex gap-3 pt-2">
              <button onClick={() => download('pdf')}
                className="btn-primary flex items-center gap-2 flex-1 justify-center">
                <Download size={14} /> Descargar PDF
              </button>
              <button onClick={() => download('html')}
                className="bg-navy-700 text-cyan-400 border border-cyan-400/30 font-semibold px-4 py-2 rounded hover:bg-navy-600 flex items-center gap-2 flex-1 justify-center text-sm">
                <FileText size={14} /> Ver HTML
              </button>
            </div>
          </div>
        </div>

        <div className="mt-6 card max-w-md">
          <h3 className="text-sm font-semibold text-gray-400 mb-3">El reporte incluye:</h3>
          <ul className="space-y-1 text-sm text-gray-300">
            {['Resumen ejecutivo con postura de riesgo', 'KPIs: MTTD, MTTR, tasa de FP', 'Tabla de alertas clasificadas por severidad', 'Cobertura de IoCs', 'Branding PremosCorp certificado', 'Marca CONFIDENCIAL'].map(item => (
              <li key={item} className="flex items-start gap-2">
                <span className="text-cyan-400 mt-0.5">•</span>{item}
              </li>
            ))}
          </ul>
        </div>
      </main>
    </div>
  )
}
