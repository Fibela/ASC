'use client'

import { useEffect, useState, useCallback } from 'react'
import {
  listAgents,
  getAgentTimeline,
  getCommandHistory,
  issueAgentCommand,
  setAgentThreatLevel,
  deregisterAgent,
  SprecterAgent,
  AgentCommand,
  AgentEvent,
} from '@/lib/api'

// ── Helpers ────────────────────────────────────────────────────────────────────

export function agentStatusColor(status: SprecterAgent['status']): string {
  switch (status) {
    case 'active':      return 'text-green-400'
    case 'inactive':    return 'text-gray-400'
    case 'isolated':    return 'text-yellow-400'
    case 'compromised': return 'text-red-500'
    default:            return 'text-gray-400'
  }
}

export function threatBadgeColor(level: SprecterAgent['threat_level']): string {
  switch (level) {
    case 'critical': return 'bg-red-600 text-white'
    case 'elevated': return 'bg-yellow-500 text-black'
    case 'normal':   return 'bg-green-700 text-white'
    default:         return 'bg-gray-600 text-white'
  }
}

export function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'text-red-500'
    case 'high':     return 'text-orange-400'
    case 'medium':   return 'text-yellow-400'
    case 'low':      return 'text-blue-400'
    default:         return 'text-gray-300'
  }
}

function cmdStatusColor(s: AgentCommand['status']): string {
  switch (s) {
    case 'completed': return 'text-green-400'
    case 'failed':    return 'text-red-400'
    case 'delivered':
    case 'executing': return 'text-yellow-400'
    case 'cancelled': return 'text-gray-500'
    default:          return 'text-blue-400'   // pending
  }
}

export function formatTs(ts: string): string {
  try { return new Date(ts).toLocaleString() } catch { return ts }
}

// ── Command definitions ────────────────────────────────────────────────────────

const COMMANDS = [
  { type: 'kill_process',    label: 'Kill Process',      group: 'process',  danger: false },
  { type: 'block_ip',        label: 'Block IP',          group: 'network',  danger: false },
  { type: 'unblock_ip',      label: 'Unblock IP',        group: 'network',  danger: false },
  { type: 'unblock_domain',  label: 'Unblock Domain',    group: 'network',  danger: false },
  { type: 'isolate_endpoint',label: 'Isolate Endpoint',  group: 'isolation',danger: true  },
  { type: 'unisolate',       label: 'Unisolate',         group: 'isolation',danger: false },
  { type: 'log_query',       label: 'Log Query',         group: 'hunt',     danger: false },
] as const

type CommandType = typeof COMMANDS[number]['type']

// ── Command param forms ────────────────────────────────────────────────────────

interface CommandFormProps {
  commandType: CommandType
  onParamsChange: (params: Record<string, unknown>) => void
}

function CommandParamForm({ commandType, onParamsChange }: CommandFormProps) {
  const [pid, setPid]                     = useState(0)
  const [ip, setIp]                       = useState('')
  const [unblockDir, setUnblockDir]       = useState<'both' | 'inbound' | 'outbound'>('both')
  const [domain, setDomain]               = useState('')
  const [ascIp, setAscIp]                 = useState('')
  const [ascPort, setAscPort]             = useState(443)
  const [dryRun, setDryRun]               = useState(false)
  const [pattern, setPattern]             = useState('')
  const [dataSource, setDataSource]       = useState<'system' | 'auth' | 'syslog' | 'file'>('system')
  const [logPath, setLogPath]             = useState('')
  const [sinceMinutes, setSinceMinutes]   = useState(60)
  const [isRegex, setIsRegex]             = useState(false)

  // Rebuild params whenever any field changes
  useEffect(() => {
    switch (commandType) {
      case 'kill_process':     return onParamsChange({ pid })
      case 'block_ip':         return onParamsChange({ ip })
      case 'unblock_ip':       return onParamsChange({ ip, direction: unblockDir })
      case 'unblock_domain':   return onParamsChange({ domain })
      case 'isolate_endpoint': return onParamsChange({ asc_server_ip: ascIp, asc_server_port: ascPort })
      case 'unisolate':        return onParamsChange({ dry_run: dryRun })
      case 'log_query': {
        const p: Record<string, unknown> = {
          pattern,
          read_only: true,
          data_source: dataSource,
          since_minutes: sinceMinutes,
          is_regex: isRegex,
        }
        if (dataSource === 'file' && logPath) p.log_path = logPath
        return onParamsChange(p)
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [commandType, pid, ip, unblockDir, domain, ascIp, ascPort, dryRun, pattern, dataSource, logPath, sinceMinutes, isRegex])

  const inputCls = 'w-full bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded px-2 py-1.5 focus:outline-none focus:border-blue-500'
  const labelCls = 'text-xs text-gray-400 mb-1'
  const Field = ({ label, children }: { label: string; children: React.ReactNode }) => (
    <div>
      <p className={labelCls}>{label}</p>
      {children}
    </div>
  )

  switch (commandType) {
    case 'kill_process':
      return (
        <Field label="PID (process ID)">
          <input type="number" className={inputCls} value={pid}
            onChange={e => setPid(Number(e.target.value))} min={1} />
        </Field>
      )

    case 'block_ip':
      return (
        <Field label="IP address to block">
          <input type="text" className={inputCls} value={ip}
            onChange={e => setIp(e.target.value)} placeholder="203.0.113.42" />
        </Field>
      )

    case 'unblock_ip':
      return (
        <div className="space-y-2">
          <Field label="IP address to unblock">
            <input type="text" className={inputCls} value={ip}
              onChange={e => setIp(e.target.value)} placeholder="203.0.113.42" />
          </Field>
          <Field label="Direction">
            <select className={inputCls} value={unblockDir}
              onChange={e => setUnblockDir(e.target.value as typeof unblockDir)}>
              <option value="both">Both (inbound + outbound)</option>
              <option value="inbound">Inbound only</option>
              <option value="outbound">Outbound only</option>
            </select>
          </Field>
        </div>
      )

    case 'unblock_domain':
      return (
        <Field label="Domain to unblock">
          <input type="text" className={inputCls} value={domain}
            onChange={e => setDomain(e.target.value)} placeholder="evil.com" />
        </Field>
      )

    case 'isolate_endpoint':
      return (
        <div className="space-y-2">
          <div className="text-xs text-red-400 bg-red-900/20 border border-red-800 rounded p-2">
            ⚠ This will block ALL network traffic except the ASC backend connection.
            Ensure the correct ASC IP is set before proceeding.
          </div>
          <Field label="ASC Server IP (preserved channel)">
            <input type="text" className={inputCls} value={ascIp}
              onChange={e => setAscIp(e.target.value)} placeholder="10.0.0.10" />
          </Field>
          <Field label="ASC Server Port (default 443)">
            <input type="number" className={inputCls} value={ascPort}
              onChange={e => setAscPort(Number(e.target.value))} min={1} max={65535} />
          </Field>
        </div>
      )

    case 'unisolate':
      return (
        <div className="flex items-center gap-2">
          <input type="checkbox" id="dry_run" checked={dryRun}
            onChange={e => setDryRun(e.target.checked)}
            className="accent-blue-500" />
          <label htmlFor="dry_run" className="text-xs text-gray-300">
            Dry run — report what would be removed without acting
          </label>
        </div>
      )

    case 'log_query':
      return (
        <div className="space-y-2">
          <Field label="Search pattern">
            <input type="text" className={inputCls} value={pattern}
              onChange={e => setPattern(e.target.value)} placeholder="sshd failed" />
          </Field>
          <div className="grid grid-cols-2 gap-2">
            <Field label="Data source">
              <select className={inputCls} value={dataSource}
                onChange={e => setDataSource(e.target.value as typeof dataSource)}>
                <option value="system">System (journalctl)</option>
                <option value="auth">Auth log</option>
                <option value="syslog">Syslog</option>
                <option value="file">Custom file</option>
              </select>
            </Field>
            <Field label="Look back (minutes)">
              <input type="number" className={inputCls} value={sinceMinutes}
                onChange={e => setSinceMinutes(Number(e.target.value))} min={1} max={1440} />
            </Field>
          </div>
          {dataSource === 'file' && (
            <Field label="Log file path">
              <input type="text" className={inputCls} value={logPath}
                onChange={e => setLogPath(e.target.value)} placeholder="/var/log/app.log" />
            </Field>
          )}
          <div className="flex items-center gap-2">
            <input type="checkbox" id="is_regex" checked={isRegex}
              onChange={e => setIsRegex(e.target.checked)}
              className="accent-blue-500" />
            <label htmlFor="is_regex" className="text-xs text-gray-300">Regex pattern</label>
          </div>
          <p className="text-xs text-gray-500">read_only is always enforced — this command never modifies logs.</p>
        </div>
      )
  }
}

// ── Log query result viewer ────────────────────────────────────────────────────

function LogQueryResults({ cmd }: { cmd: AgentCommand }) {
  if (cmd.command_type !== 'log_query' || cmd.status !== 'completed') return null
  const result = cmd.result as Record<string, unknown> | null
  if (!result?.matches) return null

  const matches = result.matches as string[]
  return (
    <div className="mt-2 bg-gray-900 border border-gray-700 rounded p-2">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-gray-400">
          {result.match_count as number} match{(result.match_count as number) !== 1 ? 'es' : ''} from {result.source as string}
          {result.truncated ? ' (truncated at 500)' : ''}
        </span>
      </div>
      <div className="max-h-48 overflow-y-auto space-y-0.5">
        {matches.slice(0, 200).map((line, i) => (
          <p key={i} className="text-xs font-mono text-green-300 whitespace-pre-wrap break-all">{line}</p>
        ))}
      </div>
    </div>
  )
}

// ── Command history panel ──────────────────────────────────────────────────────

function CommandHistoryPanel({ agentId }: { agentId: string }) {
  const [commands, setCommands]   = useState<AgentCommand[]>([])
  const [loading, setLoading]     = useState(true)
  const [expanded, setExpanded]   = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const resp = await getCommandHistory(agentId, { limit: 20 })
      setCommands(resp.commands)
    } catch {
      // keep stale
    } finally {
      setLoading(false)
    }
  }, [agentId])

  useEffect(() => {
    load()
    const id = setInterval(load, 10000)   // poll every 10s for result updates
    return () => clearInterval(id)
  }, [load])

  if (loading) return <p className="text-xs text-gray-500">Loading command history…</p>
  if (commands.length === 0) return <p className="text-xs text-gray-500">No commands issued to this agent yet.</p>

  return (
    <div className="space-y-1 max-h-72 overflow-y-auto">
      {commands.map(cmd => (
        <div key={cmd.id} className="border border-gray-700 rounded p-2 bg-gray-900/50">
          <div
            className="flex items-center justify-between cursor-pointer"
            onClick={() => setExpanded(expanded === cmd.id ? null : cmd.id)}
          >
            <div className="flex items-center gap-2 min-w-0">
              <span className="text-xs font-mono text-gray-200 shrink-0">{cmd.command_type}</span>
              <span className={`text-xs ${cmdStatusColor(cmd.status)} shrink-0`}>{cmd.status}</span>
              {cmd.error && (
                <span className="text-xs text-red-400 truncate">{cmd.error}</span>
              )}
            </div>
            <span className="text-xs text-gray-500 shrink-0 ml-2">{formatTs(cmd.issued_at)}</span>
          </div>
          {expanded === cmd.id && (
            <div className="mt-2 text-xs space-y-1">
              <p className="text-gray-500 font-mono">ID: {cmd.id}</p>
              <p className="text-gray-400">Params: <span className="font-mono text-gray-300">{JSON.stringify(cmd.params)}</span></p>
              {cmd.completed_at && <p className="text-gray-500">Completed: {formatTs(cmd.completed_at)}</p>}
              <LogQueryResults cmd={cmd} />
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function AgentsPage() {
  const [agents, setAgents]             = useState<SprecterAgent[]>([])
  const [selected, setSelected]         = useState<SprecterAgent | null>(null)
  const [timeline, setTimeline]         = useState<AgentEvent[]>([])
  const [anomaliesOnly, setAnomaliesOnly] = useState(false)
  const [loading, setLoading]           = useState(true)
  const [timelineLoading, setTimelineLoading] = useState(false)
  const [error, setError]               = useState<string | null>(null)
  const [activeTab, setActiveTab]       = useState<'command' | 'history' | 'timeline'>('command')

  const [commandType, setCommandType]   = useState<CommandType>('kill_process')
  const [commandParams, setCommandParams] = useState<Record<string, unknown>>({ pid: 0 })
  const [cmdStatus, setCmdStatus]       = useState<string | null>(null)
  const [issuing, setIssuing]           = useState(false)
  const [confirmIsolate, setConfirmIsolate] = useState(false)

  const loadAgents = useCallback(async () => {
    try {
      const resp = await listAgents({ limit: 100 })
      setAgents(resp.agents)
      setError(null)
    } catch {
      setError('Failed to load agents')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadAgents()
    const id = setInterval(loadAgents, 15000)
    return () => clearInterval(id)
  }, [loadAgents])

  const loadTimeline = useCallback(async (agentId: string, onlyAnomalies: boolean) => {
    setTimelineLoading(true)
    try {
      const resp = await getAgentTimeline(agentId, { limit: 50, anomalies_only: onlyAnomalies })
      setTimeline(resp.events)
    } catch {
      setTimeline([])
    } finally {
      setTimelineLoading(false)
    }
  }, [])

  const selectAgent = (agent: SprecterAgent) => {
    setSelected(agent)
    setCmdStatus(null)
    setConfirmIsolate(false)
    setActiveTab('command')
    loadTimeline(agent.id, anomaliesOnly)
  }

  const toggleAnomalies = () => {
    const next = !anomaliesOnly
    setAnomaliesOnly(next)
    if (selected) loadTimeline(selected.id, next)
  }

  const handleSetThreat = async (level: 'normal' | 'elevated' | 'critical') => {
    if (!selected) return
    try {
      const resp = await setAgentThreatLevel(selected.id, level)
      setAgents(prev => prev.map(a => a.id === selected.id
        ? { ...a, threat_level: resp.threat_level as SprecterAgent['threat_level'], poll_interval: resp.poll_interval }
        : a))
      setSelected(prev => prev ? { ...prev, threat_level: level, poll_interval: resp.poll_interval } : null)
      setCmdStatus(`Threat level set to ${level}`)
    } catch {
      setCmdStatus('Failed to set threat level')
    }
  }

  const handleIssueCommand = async () => {
    if (!selected) return
    if (commandType === 'isolate_endpoint' && !confirmIsolate) {
      setConfirmIsolate(true)
      return
    }
    setIssuing(true)
    setConfirmIsolate(false)
    try {
      await issueAgentCommand(selected.id, commandType, commandParams)
      setCmdStatus(`Command "${commandType}" queued — check Command History for results`)
      setActiveTab('history')
    } catch (e) {
      setCmdStatus(`Error: ${e instanceof Error ? e.message : 'Server error'}`)
    } finally {
      setIssuing(false)
    }
  }

  const handleDeregister = async () => {
    if (!selected) return
    if (!confirm(`Deregister agent ${selected.hostname}? This cannot be undone.`)) return
    try {
      await deregisterAgent(selected.id)
      setAgents(prev => prev.filter(a => a.id !== selected.id))
      setSelected(null)
      setTimeline([])
    } catch {
      setCmdStatus('Failed to deregister agent')
    }
  }

  const cmdDef = COMMANDS.find(c => c.type === commandType)!

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <span className="text-gray-400 text-sm">Loading SPECTER agents…</span>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">SPECTER Agents</h1>
          <p className="text-gray-400 text-sm mt-1">
            {agents.length} endpoint{agents.length !== 1 ? 's' : ''} registered
          </p>
        </div>
        <button
          onClick={loadAgents}
          className="px-3 py-1.5 text-xs bg-gray-700 hover:bg-gray-600 text-gray-200 rounded transition"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded p-3 text-red-300 text-sm">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Agent list */}
        <div className="lg:col-span-1 space-y-2">
          {agents.length === 0 && (
            <p className="text-gray-500 text-sm">No agents registered yet.</p>
          )}
          {agents.map(agent => (
            <button
              key={agent.id}
              onClick={() => selectAgent(agent)}
              className={`w-full text-left rounded-lg border p-3 transition ${
                selected?.id === agent.id
                  ? 'border-blue-500 bg-blue-900/20'
                  : 'border-gray-700 bg-gray-800 hover:border-gray-500'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-white text-sm font-medium truncate">{agent.hostname}</span>
                <span className={`text-xs px-1.5 py-0.5 rounded ${threatBadgeColor(agent.threat_level)}`}>
                  {agent.threat_level}
                </span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className={agentStatusColor(agent.status)}>{agent.status}</span>
                <span className="text-gray-500">·</span>
                <span className="text-gray-400">{agent.os_type} {agent.arch}</span>
              </div>
              <div className="text-xs text-gray-500 mt-1 truncate">{agent.ip_address}</div>
            </button>
          ))}
        </div>

        {/* Agent detail + controls */}
        {selected ? (
          <div className="lg:col-span-2 space-y-4">
            {/* Detail card */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h2 className="text-lg font-semibold text-white">{selected.hostname}</h2>
                  <p className="text-gray-400 text-xs">{selected.id}</p>
                </div>
                <button
                  onClick={handleDeregister}
                  className="text-xs text-red-400 hover:text-red-300 border border-red-800 hover:border-red-600 px-2 py-1 rounded transition"
                >
                  Deregister
                </button>
              </div>
              <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs">
                <Row label="OS"          value={`${selected.os_type} ${selected.os_version}`} />
                <Row label="Arch"        value={selected.arch} />
                <Row label="IP"          value={selected.ip_address} />
                <Row label="SPECTER"     value={selected.specter_version} />
                <Row label="Poll"        value={`${selected.poll_interval}s`} />
                <Row label="Events"      value={String(selected.total_events)} />
                <Row label="First seen"  value={formatTs(selected.first_seen)} />
                <Row label="Last seen"   value={formatTs(selected.last_seen)} />
              </div>
            </div>

            {/* Threat level controls */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-300 mb-3">Threat Level</h3>
              <div className="flex gap-2">
                {(['normal', 'elevated', 'critical'] as const).map(level => (
                  <button
                    key={level}
                    onClick={() => handleSetThreat(level)}
                    className={`flex-1 py-1.5 text-xs rounded border transition ${
                      selected.threat_level === level
                        ? threatBadgeColor(level) + ' border-transparent'
                        : 'border-gray-600 text-gray-300 hover:border-gray-400'
                    }`}
                  >
                    {level}
                  </button>
                ))}
              </div>
            </div>

            {/* Tabs: Command / History / Timeline */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
              <div className="flex border-b border-gray-700">
                {(['command', 'history', 'timeline'] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`flex-1 py-2 text-xs capitalize transition ${
                      activeTab === tab
                        ? 'text-blue-400 border-b-2 border-blue-500 bg-gray-700/40'
                        : 'text-gray-400 hover:text-gray-200'
                    }`}
                  >
                    {tab === 'command' ? 'Issue Command' : tab === 'history' ? 'Command History' : 'Event Timeline'}
                  </button>
                ))}
              </div>

              <div className="p-4">
                {/* ── Issue Command tab ── */}
                {activeTab === 'command' && (
                  <div className="space-y-3">
                    {/* Command type selector by group */}
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Command type</p>
                      <select
                        value={commandType}
                        onChange={e => {
                          setCommandType(e.target.value as CommandType)
                          setCmdStatus(null)
                          setConfirmIsolate(false)
                        }}
                        className="w-full bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded px-2 py-1.5 focus:outline-none focus:border-blue-500"
                      >
                        <optgroup label="Process">
                          <option value="kill_process">kill_process — Terminate by PID</option>
                        </optgroup>
                        <optgroup label="Network">
                          <option value="block_ip">block_ip — Block outbound/inbound IP</option>
                          <option value="unblock_ip">unblock_ip — Remove IP block</option>
                          <option value="unblock_domain">unblock_domain — Remove domain block</option>
                        </optgroup>
                        <optgroup label="Isolation">
                          <option value="isolate_endpoint">isolate_endpoint — Full network isolation ⚠</option>
                          <option value="unisolate">unisolate — Lift isolation</option>
                        </optgroup>
                        <optgroup label="Hunt">
                          <option value="log_query">log_query — Search system logs (read-only)</option>
                        </optgroup>
                      </select>
                    </div>

                    {/* Dynamic param form */}
                    <CommandParamForm
                      commandType={commandType}
                      onParamsChange={setCommandParams}
                    />

                    {/* Isolation confirmation */}
                    {confirmIsolate && (
                      <div className="bg-red-900/30 border border-red-700 rounded p-3 text-xs text-red-300">
                        <p className="font-semibold mb-1">Confirm: Isolate {selected.hostname}?</p>
                        <p>All network traffic will be blocked except the ASC backend IP you provided.
                           This is reversible via the unisolate command.</p>
                        <div className="flex gap-2 mt-2">
                          <button
                            onClick={handleIssueCommand}
                            className="px-3 py-1 bg-red-700 hover:bg-red-600 text-white rounded text-xs"
                          >
                            Confirm Isolate
                          </button>
                          <button
                            onClick={() => setConfirmIsolate(false)}
                            className="px-3 py-1 border border-gray-600 text-gray-300 hover:text-white rounded text-xs"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Issue button */}
                    {!confirmIsolate && (
                      <button
                        onClick={handleIssueCommand}
                        disabled={issuing}
                        className={`w-full py-1.5 text-xs rounded transition ${
                          cmdDef.danger
                            ? 'bg-red-800 hover:bg-red-700 text-white'
                            : 'bg-blue-700 hover:bg-blue-600 text-white'
                        } disabled:opacity-50`}
                      >
                        {issuing ? 'Queuing…' : cmdDef.danger ? `Queue ${cmdDef.label} ⚠` : `Queue ${cmdDef.label}`}
                      </button>
                    )}

                    {cmdStatus && (
                      <p className={`text-xs ${cmdStatus.startsWith('Error') ? 'text-red-400' : 'text-green-400'}`}>
                        {cmdStatus}
                      </p>
                    )}
                  </div>
                )}

                {/* ── Command History tab ── */}
                {activeTab === 'history' && (
                  <CommandHistoryPanel agentId={selected.id} />
                )}

                {/* ── Event Timeline tab ── */}
                {activeTab === 'timeline' && (
                  <div className="space-y-2">
                    <div className="flex items-center justify-end">
                      <button
                        onClick={toggleAnomalies}
                        className={`text-xs px-2 py-1 rounded border transition ${
                          anomaliesOnly
                            ? 'border-yellow-500 text-yellow-400'
                            : 'border-gray-600 text-gray-400 hover:border-gray-400'
                        }`}
                      >
                        {anomaliesOnly ? 'Anomalies only' : 'All events'}
                      </button>
                    </div>
                    {timelineLoading ? (
                      <p className="text-gray-500 text-xs">Loading events…</p>
                    ) : timeline.length === 0 ? (
                      <p className="text-gray-500 text-xs">No events recorded yet.</p>
                    ) : (
                      <div className="space-y-1 max-h-64 overflow-y-auto">
                        {timeline.map(ev => (
                          <div
                            key={ev.id}
                            className={`flex items-start gap-2 text-xs py-1 border-b border-gray-700 last:border-0 ${
                              ev.is_anomaly ? 'bg-yellow-900/10' : ''
                            }`}
                          >
                            <span className={`shrink-0 font-mono ${severityColor(ev.severity)}`}>
                              {ev.event_type}
                            </span>
                            {ev.is_anomaly && <span className="shrink-0 text-yellow-400">⚠</span>}
                            <span className="text-gray-500 ml-auto shrink-0">{formatTs(ev.ts)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="lg:col-span-2 flex items-center justify-center h-48 border border-dashed border-gray-700 rounded-lg">
            <p className="text-gray-500 text-sm">Select an agent to view details and issue commands</p>
          </div>
        )}
      </div>
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-1">
      <span className="text-gray-500 w-24 shrink-0">{label}</span>
      <span className="text-gray-200 truncate">{value}</span>
    </div>
  )
}
