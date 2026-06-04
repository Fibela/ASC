'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import clsx from 'clsx'
import {
  LayoutDashboard, ShieldAlert, Activity, Database,
  Zap, BarChart3, FileText, Settings, Radar
} from 'lucide-react'

const NAV = [
  { href: '/',            label: 'Dashboard',      icon: LayoutDashboard },
  { href: '/alerts',      label: 'Alertas',        icon: ShieldAlert },
  { href: '/events',      label: 'Eventos',        icon: Activity },
  { href: '/iocs',        label: 'IoCs',           icon: Database },
  { href: '/analyze',     label: 'Análisis',       icon: Radar },
  { href: '/neutralize',  label: 'Neutralización', icon: Zap },
  { href: '/metrics',     label: 'Métricas SOC',   icon: BarChart3 },
  { href: '/reports',     label: 'Reportes',       icon: FileText },
]

export function Sidebar() {
  const path = usePathname()
  return (
    <aside className="w-56 min-h-screen bg-navy-900 border-r border-navy-700 flex flex-col">
      {/* Brand */}
      <div className="px-4 py-5 border-b border-navy-700">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-cyan-400 rounded flex items-center justify-center text-navy-900 font-black text-sm">ASC</div>
          <div>
            <p className="text-cyan-400 font-bold text-sm leading-none">PremosCorp</p>
            <p className="text-gray-500 text-xs">Security Center</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 px-2 space-y-0.5">
        {NAV.map(({ href, label, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className={clsx(
              'flex items-center gap-3 px-3 py-2 rounded text-sm transition-colors',
              path === href
                ? 'bg-cyan-400/10 text-cyan-400 font-semibold'
                : 'text-gray-400 hover:text-white hover:bg-navy-700'
            )}
          >
            <Icon size={16} />
            {label}
          </Link>
        ))}
      </nav>

      <div className="px-4 py-3 border-t border-navy-700 text-xs text-gray-600">
        ASC v1.0.0
      </div>
    </aside>
  )
}
