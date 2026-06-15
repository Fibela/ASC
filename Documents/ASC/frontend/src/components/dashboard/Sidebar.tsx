'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useState, useEffect } from 'react'
import clsx from 'clsx'
import {
  LayoutDashboard, ShieldAlert, Activity, Database,
  Zap, BarChart3, FileText, Radar, ScanSearch, LogOut, User, BookOpen, Network, Server, Bot, Flame,
  MonitorDot, Lock, Users, Globe, Crosshair, ShieldCheck, GitBranch, ClipboardList, ScrollText, Webhook, KeyRound, Gauge,
} from 'lucide-react'
import { logout, getRole } from '@/lib/auth'

const NAV = [
  { href: '/',           label: 'Dashboard',        icon: LayoutDashboard },
  { href: '/ops',        label: 'Ops Dashboard',    icon: MonitorDot },
  { href: '/detection',  label: 'Detecciones',      icon: ScanSearch },
  { href: '/playbooks',  label: 'Playbooks',        icon: BookOpen },
  { href: '/alerts',     label: 'Alertas',          icon: ShieldAlert },
  { href: '/events',     label: 'Eventos',          icon: Activity },
  { href: '/iocs',       label: 'IoCs',             icon: Database },
  { href: '/analyze',    label: 'Análisis',         icon: Radar },
  { href: '/neutralize', label: 'Neutralización',   icon: Zap },
  { href: '/agents',     label: 'Agentes SPECTER',  icon: Bot },
  { href: '/honeypot',   label: 'Honeypot',         icon: Flame },
  { href: '/adapters',   label: 'Adaptadores',      icon: Network },
  { href: '/forensic',      label: 'Ledger Forense',   icon: Lock },
  { href: '/threat-intel',  label: 'Threat Intel',     icon: Globe },
  { href: '/threat-hunting', label: 'Threat Hunting',  icon: Crosshair },
  { href: '/soar',           label: 'SOAR',             icon: Zap },
  { href: '/pids',           label: 'PIDS Identity',    icon: ShieldCheck },
  { href: '/correlation',    label: 'Correlación',      icon: GitBranch },
  { href: '/incidents',      label: 'Incidentes',       icon: ClipboardList },
  { href: '/reports/executive', label: 'Rep. Ejecutivos', icon: ScrollText },
  { href: '/metrics',    label: 'Métricas SOC',     icon: BarChart3 },
  { href: '/reports',    label: 'Reportes',         icon: FileText },
  { href: '/webhooks',   label: 'Webhooks',         icon: Webhook },
  { href: '/api-keys',     label: 'API Keys',         icon: KeyRound },
  { href: '/rate-limits', label: 'Rate Limits',      icon: Gauge },
  { href: '/status',      label: 'Estado Sistema',   icon: Server },
  { href: '/admin',      label: 'Admin Usuarios',   icon: Users,  adminOnly: true },
]

export function Sidebar() {
  const path = usePathname()
  const [role, setRole] = useState<string | null>(null)

  useEffect(() => {
    setRole(getRole())
  }, [])

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
      <nav className="flex-1 py-4 px-2 space-y-0.5 overflow-y-auto">
        {NAV.filter(item => !('adminOnly' in item) || !item.adminOnly || role === 'admin').map(({ href, label, icon: Icon }) => (
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

      {/* User + Logout */}
      <div className="border-t border-navy-700 px-3 py-3">
        <div className="flex items-center gap-2 mb-2 px-1">
          <User size={14} className="text-gray-500" />
          <span className="text-xs text-gray-400 capitalize">{role ?? '…'}</span>
        </div>
        <button
          onClick={() => logout()}
          className="flex items-center gap-2 w-full px-3 py-1.5 rounded text-xs text-gray-400 hover:text-red-400 hover:bg-red-400/10 transition-colors"
        >
          <LogOut size={14} />
          Cerrar sesión
        </button>
        <p className="text-center text-xs text-gray-700 mt-2">ASC v1.0.0</p>
      </div>
    </aside>
  )
}
