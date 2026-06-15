'use client'

import { useEffect, useState, useCallback } from 'react'
import {
  GitBranch, Shield, AlertTriangle, Activity, RefreshCw, Eye,
  CheckCircle, XCircle, Clock, ChevronRight, Layers, Target,
} from 'lucide-react'
import clsx from 'clsx'
import {
  getCorrelationSummary, listCorrelationClusters, listCorrelationRules,
  updateClusterStatus, getClusterGraph, triggerCorrelationSweep,
  CorrelationCluster, CorrelationSummary, CorrelationRule, CorrelationGraph,
} from '@/lib/api'

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/30',
  high:     'text-orange-400 bg-orange-400/10 border-orange-400/30',
  medium:   'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  low:      'text-cyan-400 bg-cyan-400/10 border-cyan-400/30',
  info:     'text-gray-400 bg-gray-400/10 border-gray-400/30',
}

const STATUS_COLORS: Record<string, string> = {
  active:    'text-green-400 bg-green-400/10',
  resolved:  'text-gray-400 bg-gray-400/10',
  dismissed: 'text-gray-600 bg-gray-800',
}

const PIVOT_LABELS: Record<string, string> = {
  host_pivot:     'Host',
  identity_pivot: 'Identity',
  ip_pivot:       'IP',
  domain_pivot:   'Domain',
  ttp_pivot:      'TTP',
}

function SevBadge({ sev }: { sev: string }) {
  return (
    <span className={clsx('text-xs font-semibold px-2 py-0.5 rounded border', SEV_COLORS[sev] ?? SEV_COLORS.info)}>
      {sev.toUpperCase()}
    </span>
  )
}

function KpiCard({ icon: Icon, label, value, sub, color }: {
  icon: React.ElementType; label: string; value: number | string; sub?: string; color?: string
}) {
  return (
    <div className="bg-navy-800 rounded-lg p-4 border border-navy-700 flex items-start gap-3">
      <div className={clsx('mt-0.5 p-2 rounded', color ?? 'bg-cyan-400/10')}>
        <Icon size={16} className={color ? 'text-current' : 'text-cyan-400'} />
      </div>
      <div>
        <p className="text-2xl font-bold text-white">{value}</p>
        <p className="text-xs text-gray-400 mt-0.5">{label}</p>
        {sub && <p className="text-xs text-gray-600 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

// ── Graph Viewer ──────────────────────────────────────────────────────────────

function GraphViewer({ graph }: { graph: CorrelationGraph }) {
  const nodeColors: Record<string, string> = {
    cluster:         '#22d3ee',
    event:           '#a78bfa',
    alert:           '#f87171',
    finding:         '#fb923c',
    identity_action: '#34d399',
    panl_action:     '#f59e0b',
    ti_indicator:    '#60a5fa',
    agent_command:   '#e879f9',
  }

  return (
    <div className="bg-navy-900 rounded-lg border border-navy-700 p-4 overflow-auto max-h-96">
      <div className="flex items-center gap-2 mb-4">
        <GitBranch size={14} className="text-cyan-400" />
        <span className="text-sm font-semibold text-white">
          Graph — {graph.pivot_type.replace('_pivot', '')} / {graph.pivot_value}
        </span>
        {graph.is_campaign && (
          <span className="ml-2 text-xs font-bold px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-400/30">
            CAMPAIGN
          </span>
        )}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-2 mb-4">
        {Object.entries(nodeColors).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1.5 text-xs text-gray-400">
            <div className="w-2 h-2 rounded-full" style={{ background: color }} />
            {type.replace('_', ' ')}
          </div>
        ))}
      </div>

      {/* Simple table-based graph representation */}
      <div className="space-y-2">
        {/* Central cluster node */}
        <div className="flex items-center gap-2 px-3 py-2 rounded bg-cyan-400/10 border border-cyan-400/30">
          <div className="w-3 h-3 rounded-full bg-cyan-400" />
          <span className="text-xs font-bold text-cyan-400">CLUSTER: {graph.pivot_value}</span>
          <SevBadge sev={graph.nodes.find(n => n.type === 'cluster')?.severity ?? 'low'} />
        </div>

        {/* Signal nodes */}
        <div className="ml-6 space-y-1.5 border-l border-navy-700 pl-4">
          {graph.nodes.filter(n => n.type !== 'cluster').map(node => (
            <div key={node.id}
              className="flex items-center gap-2 px-3 py-1.5 rounded bg-navy-800 border border-navy-700 text-xs"
            >
              <div
                className="w-2 h-2 rounded-full flex-shrink-0"
                style={{ background: nodeColors[node.type] ?? '#6b7280' }}
              />
              <span className="text-gray-300 font-mono truncate max-w-xs">{node.label}</span>
              <SevBadge sev={node.severity} />
              {node.ts && (
                <span className="text-gray-600 ml-auto flex-shrink-0">
                  {new Date(node.ts).toLocaleTimeString()}
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      <p className="text-xs text-gray-600 mt-3">
        {graph.nodes.length - 1} signals · {graph.edges.length} edges
      </p>
    </div>
  )
}

// ── Cluster Row ───────────────────────────────────────────────────────────────

function ClusterRow({
  cluster, onExpand, onStatusChange,
}: {
  cluster: CorrelationCluster
  onExpand: (id: string) => void
  onStatusChange: (id: string, status: string) => void
}) {
  return (
    <tr className="border-t border-navy-700 hover:bg-navy-700/30 transition-colors">
      <td className="px-4 py-3">
        <div className="flex flex-col gap-0.5">
          <span className="font-mono text-sm text-white truncate max-w-xs">{cluster.cluster_key}</span>
          <span className="text-xs text-gray-500">{PIVOT_LABELS[cluster.cluster_type] ?? cluster.cluster_type}</span>
        </div>
      </td>
      <td className="px-4 py-3">
        <SevBadge sev={cluster.severity} />
      </td>
      <td className="px-4 py-3 text-sm text-gray-300">{cluster.signal_count}</td>
      <td className="px-4 py-3">
        <span className={clsx('text-xs px-2 py-0.5 rounded font-semibold', STATUS_COLORS[cluster.status])}>
          {cluster.status.toUpperCase()}
        </span>
      </td>
      <td className="px-4 py-3">
        {cluster.is_campaign ? (
          <span className="text-xs font-bold px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-400/30">
            CAMPAIGN
          </span>
        ) : (
          <span className="text-xs text-gray-600">—</span>
        )}
      </td>
      <td className="px-4 py-3 text-xs text-gray-400">
        {new Date(cluster.last_seen).toLocaleString()}
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-1">
          <button
            onClick={() => onExpand(cluster.id)}
            className="p-1 rounded hover:bg-cyan-400/10 text-gray-400 hover:text-cyan-400 transition-colors"
            title="View graph"
          >
            <Eye size={14} />
          </button>
          {cluster.status === 'active' && (
            <>
              <button
                onClick={() => onStatusChange(cluster.id, 'resolved')}
                className="p-1 rounded hover:bg-green-400/10 text-gray-400 hover:text-green-400 transition-colors"
                title="Mark resolved"
              >
                <CheckCircle size={14} />
              </button>
              <button
                onClick={() => onStatusChange(cluster.id, 'dismissed')}
                className="p-1 rounded hover:bg-gray-400/10 text-gray-400 hover:text-gray-300 transition-colors"
                title="Dismiss"
              >
                <XCircle size={14} />
              </button>
            </>
          )}
        </div>
      </td>
    </tr>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function CorrelationPage() {
  const [summary, setSummary] = useState<CorrelationSummary | null>(null)
  const [clusters, setClusters] = useState<CorrelationCluster[]>([])
  const [rules, setRules] = useState<CorrelationRule[]>([])
  const [graph, setGraph] = useState<CorrelationGraph | null>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [sweeping, setSweeping] = useState(false)
  const [filterStatus, setFilterStatus] = useState<string>('')
  const [filterType, setFilterType] = useState<string>('')
  const [campaignsOnly, setCampaignsOnly] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [s, c, r] = await Promise.all([
        getCorrelationSummary(),
        listCorrelationClusters({
          status: filterStatus || undefined,
          cluster_type: filterType || undefined,
          campaigns_only: campaignsOnly || undefined,
          limit: 100,
        }),
        listCorrelationRules(),
      ])
      setSummary(s)
      setClusters(c)
      setRules(r)
    } catch (err) {
      console.error('Correlation load error', err)
    } finally {
      setLoading(false)
    }
  }, [filterStatus, filterType, campaignsOnly])

  useEffect(() => { load() }, [load])

  const handleExpand = useCallback(async (id: string) => {
    if (expandedId === id) {
      setExpandedId(null)
      setGraph(null)
      return
    }
    setExpandedId(id)
    try {
      const g = await getClusterGraph(id)
      setGraph(g)
    } catch {
      setGraph(null)
    }
  }, [expandedId])

  const handleStatusChange = useCallback(async (id: string, newStatus: string) => {
    try {
      await updateClusterStatus(id, { status: newStatus })
      await load()
    } catch (err) {
      console.error('Status update error', err)
    }
  }, [load])

  const handleSweep = useCallback(async () => {
    setSweeping(true)
    try {
      await triggerCorrelationSweep()
      await load()
    } catch (err) {
      console.error('Sweep error', err)
    } finally {
      setSweeping(false)
    }
  }, [load])

  return (
    <div className="min-h-screen bg-navy-950 text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <GitBranch size={20} className="text-cyan-400" />
            Correlation Engine
          </h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Cross-domain threat cluster detection — P27-B
          </p>
        </div>
        <button
          onClick={handleSweep}
          disabled={sweeping}
          className="flex items-center gap-2 px-4 py-2 rounded bg-cyan-500/10 border border-cyan-400/30 text-cyan-400 hover:bg-cyan-400/20 transition-colors text-sm disabled:opacity-50"
        >
          <RefreshCw size={14} className={sweeping ? 'animate-spin' : ''} />
          {sweeping ? 'Sweeping…' : 'Run Sweep'}
        </button>
      </div>

      {/* KPI Strip */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <KpiCard icon={Layers} label="Total Clusters" value={summary.total_clusters} />
          <KpiCard icon={Activity} label="Active Clusters" value={summary.active_clusters} color="bg-green-400/10 text-green-400" />
          <KpiCard icon={Target} label="Campaigns" value={summary.campaigns_detected} color="bg-red-400/10 text-red-400" />
          <KpiCard icon={AlertTriangle} label="Critical" value={summary.critical_clusters} color="bg-orange-400/10 text-orange-400" />
          <KpiCard icon={ChevronRight} label="Total Signals" value={summary.total_signals} />
          <KpiCard icon={Shield} label="Active Rules" value={summary.active_rules} />
        </div>
      )}

      {/* Active Rules Summary */}
      <div className="bg-navy-800 rounded-lg border border-navy-700 p-4">
        <h2 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <Shield size={14} className="text-cyan-400" />
          Correlation Rules ({rules.filter(r => r.enabled).length} enabled)
        </h2>
        <div className="flex flex-wrap gap-2">
          {rules.map(r => (
            <div
              key={r.id}
              className={clsx(
                'text-xs px-3 py-1.5 rounded-full border flex items-center gap-1.5',
                r.enabled
                  ? 'bg-cyan-400/10 border-cyan-400/30 text-cyan-300'
                  : 'bg-gray-800 border-gray-700 text-gray-500'
              )}
            >
              <span className={clsx('w-1.5 h-1.5 rounded-full', r.enabled ? 'bg-green-400' : 'bg-gray-600')} />
              {r.name}
              <span className="text-gray-500 ml-1">
                ({PIVOT_LABELS[r.pivot_type] ?? r.pivot_type} · ≥{r.min_signals}s · {r.time_window_minutes}m)
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <select
          value={filterStatus}
          onChange={e => setFilterStatus(e.target.value)}
          className="bg-navy-800 border border-navy-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:border-cyan-400"
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="resolved">Resolved</option>
          <option value="dismissed">Dismissed</option>
        </select>
        <select
          value={filterType}
          onChange={e => setFilterType(e.target.value)}
          className="bg-navy-800 border border-navy-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:border-cyan-400"
        >
          <option value="">All pivot types</option>
          {Object.entries(PIVOT_LABELS).map(([val, label]) => (
            <option key={val} value={val}>{label}</option>
          ))}
        </select>
        <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
          <input
            type="checkbox"
            checked={campaignsOnly}
            onChange={e => setCampaignsOnly(e.target.checked)}
            className="accent-cyan-400"
          />
          Campaigns only
        </label>
        <button
          onClick={load}
          className="ml-auto flex items-center gap-2 text-xs text-gray-500 hover:text-gray-300 transition-colors"
        >
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {/* Clusters Table */}
      <div className="bg-navy-800 rounded-lg border border-navy-700 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-navy-900">
            <tr>
              {['Pivot Value / Type', 'Severity', 'Signals', 'Status', 'Campaign', 'Last Seen', 'Actions'].map(h => (
                <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wide">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center text-gray-500 text-sm">
                  <RefreshCw size={16} className="animate-spin inline mr-2" />
                  Loading clusters…
                </td>
              </tr>
            ) : clusters.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center text-gray-500 text-sm">
                  No clusters found. Run a sweep or adjust filters.
                </td>
              </tr>
            ) : (
              clusters.map(cluster => (
                <>
                  <ClusterRow
                    key={cluster.id}
                    cluster={cluster}
                    onExpand={handleExpand}
                    onStatusChange={handleStatusChange}
                  />
                  {expandedId === cluster.id && graph && (
                    <tr key={`${cluster.id}-graph`} className="bg-navy-900">
                      <td colSpan={7} className="px-4 py-4">
                        <GraphViewer graph={graph} />
                        {cluster.forensic_hash && (
                          <div className="mt-2 text-xs text-gray-600 font-mono truncate">
                            Forensic SHA3-512: {cluster.forensic_hash}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
