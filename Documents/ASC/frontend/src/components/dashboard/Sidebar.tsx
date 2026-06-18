'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useState, useEffect } from 'react'
import clsx from 'clsx'
import {
  LayoutDashboard, MonitorDot, ScanSearch, ShieldAlert, Activity, Database,
  Zap, BookOpen, ClipboardList, Globe, Crosshair, Radar, GitBranch,
  Bot, Flame, ShieldCheck, Network, Lock, ScrollText,
  BarChart3, FileText, Webhook, KeyRound, Gauge, Server,
  Users, LogOut, User, ChevronLeft, ChevronRight,
} from 'lucide-react'
import { logout, getRole } from '@/lib/auth'

// ── Navigation structure (grouped) ───────────────────────────────
const NAV_GROUPS = [
  {
    label: 'Centro de Control',
    items: [
      { href: '/',    label: 'Dashboard',     icon: LayoutDashboard },
      { href: '/ops', label: 'Ops Dashboard', icon: MonitorDot },
    ],
  },
  {
    label: 'Detección & Alertas',
    items: [
      { href: '/detection',   label: 'Detecciones',  icon: ScanSearch },
      { href: '/alerts',      label: 'Alertas',      icon: ShieldAlert },
      { href: '/events',      label: 'Eventos',      icon: Activity },
      { href: '/iocs',        label: 'IoCs',         icon: Database },
      { href: '/correlation', label: 'Correlación',  icon: GitBranch },
    ],
  },
  {
    label: 'Respuesta',
    items: [
      { href: '/neutralize', label: 'Neutralización', icon: Zap },
      { href: '/playbooks',  label: 'Playbooks',      icon: BookOpen },
      { href: '/soar',       label: 'SOAR',           icon: Zap },
      { href: '/incidents',  label: 'Incidentes',     icon: ClipboardList },
    ],
  },
  {
    label: 'Inteligencia',
    items: [
      { href: '/threat-intel',   label: 'Threat Intel',    icon: Globe },
      { href: '/threat-hunting', label: 'Threat Hunting',  icon: Crosshair },
      { href: '/analyze',        label: 'Análisis',        icon: Radar },
    ],
  },
  {
    label: 'SPECTER & Identidad',
    items: [
      { href: '/agents',   label: 'Agentes SPECTER', icon: Bot },
      { href: '/honeypot', label: 'Honeypot',        icon: Flame },
      { href: '/pids',     label: 'PIDS Identity',   icon: ShieldCheck },
      { href: '/adapters', label: 'Adaptadores',     icon: Network },
    ],
  },
  {
    label: 'Forense & Reportes',
    items: [
      { href: '/forensic',          label: 'Ledger Forense',   icon: Lock },
      { href: '/reports/executive', label: 'Rep. Ejecutivos',  icon: ScrollText },
      { href: '/metrics',           label: 'Métricas SOC',     icon: BarChart3 },
      { href: '/reports',           label: 'Reportes',         icon: FileText },
    ],
  },
  {
    label: 'Plataforma',
    items: [
      { href: '/webhooks',   label: 'Webhooks',       icon: Webhook },
      { href: '/api-keys',   label: 'API Keys',       icon: KeyRound },
      { href: '/rate-limits',label: 'Rate Limits',    icon: Gauge },
      { href: '/status',     label: 'Estado Sistema', icon: Server },
    ],
  },
  {
    label: 'Administración',
    items: [
      { href: '/admin', label: 'Admin Usuarios', icon: Users, adminOnly: true },
    ],
  },
]

export function Sidebar() {
  const path        = usePathname()
  const [role, setRole]         = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState(false)

  useEffect(() => { setRole(getRole()) }, [])

  const isActive = (href: string) =>
    href === '/' ? path === '/' : path.startsWith(href)

  return (
    <aside
      className={clsx(
        'relative flex flex-col min-h-screen transition-all duration-300 ease-in-out flex-shrink-0',
        collapsed ? 'w-[60px]' : 'w-[220px]'
      )}
      style={{
        background: 'linear-gradient(180deg, #0D0D0D 0%, #0A0A0A 100%)',
        borderRight: '1px solid rgba(255,255,255,0.06)',
      }}
    >
      {/* ── Brand ────────────────────────────────────────────── */}
      <div
        className="flex items-center gap-3 px-4 py-4 flex-shrink-0"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}
      >
        {/* Logo mark */}
        <div
          className="flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center font-black text-xs text-white"
          style={{
            background: 'linear-gradient(135deg, #C44D03 0%, #E85D04 100%)',
            boxShadow: '0 0 12px rgba(232,93,4,0.4)',
          }}
        >
          ASC
        </div>

        {!collapsed && (
          <div className="overflow-hidden">
            <p className="text-sm font-bold leading-none tracking-wide text-white">
              Premos<span style={{ color: '#E85D04' }}>Corp</span>
            </p>
            <p className="text-xs mt-0.5" style={{ color: '#5A5A5A' }}>
              Security Center
            </p>
          </div>
        )}
      </div>

      {/* ── Collapse toggle ───────────────────────────────────── */}
      <button
        onClick={() => setCollapsed(v => !v)}
        className="absolute -right-3 top-14 z-10 w-6 h-6 rounded-full flex items-center justify-center
                   transition-all duration-200 hover:scale-110"
        style={{
          background: '#1A1A1A',
          border: '1px solid rgba(232,93,4,0.3)',
          color: '#E85D04',
          boxShadow: '0 0 8px rgba(232,93,4,0.2)',
        }}
        title={collapsed ? 'Expandir sidebar' : 'Colapsar sidebar'}
      >
        {collapsed
          ? <ChevronRight size={12} />
          : <ChevronLeft  size={12} />
        }
      </button>

      {/* ── Navigation ───────────────────────────────────────── */}
      <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-4">
        {NAV_GROUPS.map(group => {
          const visibleItems = group.items.filter(
            item => !('adminOnly' in item) || !item.adminOnly || role === 'admin'
          )
          if (visibleItems.length === 0) return null

          return (
            <div key={group.label}>
              {/* Group label */}
              {!collapsed && (
                <p className="px-3 mb-1 text-[10px] font-semibold uppercase tracking-widest"
                   style={{ color: '#3A3A3A' }}>
                  {group.label}
                </p>
              )}

              {/* Items */}
              <div className="space-y-0.5">
                {visibleItems.map(({ href, label, icon: Icon }) => {
                  const active = isActive(href)
                  return (
                    <Link
                      key={href}
                      href={href}
                      title={collapsed ? label : undefined}
                      className={clsx(
                        'flex items-center rounded-lg text-sm transition-all duration-150 group relative',
                        collapsed ? 'justify-center px-0 py-2.5' : 'gap-3 px-3 py-2',
                        active
                          ? 'text-white font-semibold'
                          : 'font-normal hover:text-white'
                      )}
                      style={
                        active
                          ? {
                              background: 'rgba(232,93,4,0.12)',
                              borderLeft: collapsed ? 'none' : '2px solid #E85D04',
                              color: '#FF7A25',
                              paddingLeft: collapsed ? undefined : '10px',
                            }
                          : { color: '#5A5A5A' }
                      }
                      onMouseEnter={e => {
                        if (!active) {
                          (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.04)'
                          ;(e.currentTarget as HTMLElement).style.color = '#A0A0A0'
                        }
                      }}
                      onMouseLeave={e => {
                        if (!active) {
                          (e.currentTarget as HTMLElement).style.background = ''
                          ;(e.currentTarget as HTMLElement).style.color = '#5A5A5A'
                        }
                      }}
                    >
                      <Icon
                        size={15}
                        className="flex-shrink-0"
                        style={{ color: active ? '#E85D04' : 'inherit' }}
                      />
                      {!collapsed && (
                        <span className="truncate leading-none">{label}</span>
                      )}

                      {/* Collapsed tooltip */}
                      {collapsed && (
                        <span
                          className="absolute left-full ml-2 px-2 py-1 rounded-md text-xs font-medium
                                     whitespace-nowrap pointer-events-none opacity-0 group-hover:opacity-100
                                     transition-opacity duration-150 z-50"
                          style={{
                            background: 'rgba(20,20,20,0.98)',
                            border: '1px solid rgba(232,93,4,0.2)',
                            color: '#EAEAEA',
                          }}
                        >
                          {label}
                        </span>
                      )}
                    </Link>
                  )
                })}
              </div>
            </div>
          )
        })}
      </nav>

      {/* ── User / Logout ─────────────────────────────────────── */}
      <div
        className="flex-shrink-0 px-2 py-3 space-y-1"
        style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
      >
        {/* Role badge */}
        {!collapsed && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
               style={{ background: 'rgba(232,93,4,0.06)' }}>
            <User size={12} style={{ color: '#E85D04' }} />
            <span className="text-xs font-medium capitalize" style={{ color: '#E85D04' }}>
              {role ?? '…'}
            </span>
          </div>
        )}

        {/* Logout */}
        <button
          onClick={() => logout()}
          className={clsx(
            'flex items-center w-full rounded-lg text-xs transition-all duration-150',
            collapsed ? 'justify-center py-2.5 px-0' : 'gap-2 px-3 py-2'
          )}
          style={{ color: '#5A5A5A' }}
          onMouseEnter={e => {
            (e.currentTarget as HTMLElement).style.background = 'rgba(192,21,46,0.1)'
            ;(e.currentTarget as HTMLElement).style.color = '#E8526E'
          }}
          onMouseLeave={e => {
            (e.currentTarget as HTMLElement).style.background = ''
            ;(e.currentTarget as HTMLElement).style.color = '#5A5A5A'
          }}
          title={collapsed ? 'Cerrar sesión' : undefined}
        >
          <LogOut size={14} className="flex-shrink-0" />
          {!collapsed && <span>Cerrar sesión</span>}
        </button>

        {/* Version */}
        {!collapsed && (
          <p className="text-center text-[10px] pt-1" style={{ color: '#2A2A2A' }}>
            ASC v1.0.0
          </p>
        )}
      </div>
    </aside>
  )
}
