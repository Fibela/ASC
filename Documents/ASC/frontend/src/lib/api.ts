import axios from 'axios'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

export const api = axios.create({
  baseURL: `${API_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000,
})

// --- Admin: User management ---

export interface AdminUser {
  id: string
  email: string
  full_name: string | null
  role: string
  is_active: boolean
  is_locked: boolean
  locked_until: string | null
  failed_login_attempts: number
  force_password_reset: boolean
  last_login: string | null
  created_at: string | null
}

export async function listAdminUsers(): Promise<AdminUser[]> {
  const { data } = await api.get('/auth/users')
  return data
}

export async function unlockAdminUser(userId: string): Promise<{ message: string; user: AdminUser }> {
  const { data } = await api.post(`/auth/users/${userId}/unlock`)
  return data
}

export async function updateAdminUser(
  userId: string,
  payload: { role?: string; full_name?: string; force_password_reset?: boolean }
): Promise<AdminUser> {
  const { data } = await api.patch(`/auth/users/${userId}`, payload)
  return data
}

// --- API Keys (P40) ---

export interface APIKeyResponse {
  id: string
  name: string
  key_prefix: string
  user_id: string
  scopes: string[]
  expires_at: string | null
  last_used_at: string | null
  is_active: boolean
  created_at: string
}

export interface APIKeyCreated extends APIKeyResponse {
  raw_key: string
}

export async function listApiKeys(): Promise<APIKeyResponse[]> {
  const { data } = await api.get('/api-keys/')
  return data
}

export async function createApiKey(payload: {
  name: string
  scopes?: string[]
  expires_at?: string | null
}): Promise<APIKeyCreated> {
  const { data } = await api.post('/api-keys/', payload)
  return data
}

export async function revokeApiKey(keyId: string): Promise<void> {
  await api.delete(`/api-keys/${keyId}`)
}

export async function rotateApiKey(keyId: string): Promise<APIKeyCreated> {
  const { data } = await api.post(`/api-keys/${keyId}/rotate`)
  return data
}

export async function updateApiKey(
  keyId: string,
  payload: { name?: string; is_active?: boolean; expires_at?: string | null }
): Promise<APIKeyResponse> {
  const { data } = await api.patch(`/api-keys/${keyId}`, payload)
  return data
}

export interface RateLimitStatus {
  key_prefix: string
  limit_per_minute: number
  limit_per_hour: number
  count_minute: number
  count_hour: number
  remaining_minute: number
  remaining_hour: number
  backend: string
}

export async function getApiKeyRateLimitStatus(keyId: string): Promise<RateLimitStatus> {
  const { data } = await api.get(`/api-keys/${keyId}/rate-limit-status`)
  return data
}

export async function adminListAllApiKeys(): Promise<APIKeyResponse[]> {
  const { data } = await api.get('/api-keys/admin/all')
  return data
}

export async function resetApiKeyRateLimit(keyId: string): Promise<void> {
  await api.post(`/api-keys/${keyId}/rate-limit-reset`)
}

// --- Metrics ---
export async function getSocMetrics(hours = 24) {
  const { data } = await api.get('/metrics/soc', { params: { hours } })
  return data
}

export async function getTimeline(hours = 24) {
  const { data } = await api.get('/metrics/timeline', { params: { hours } })
  return data
}

// --- Alerts ---
export async function getAlerts(params?: { severity?: string; status?: string; limit?: number }) {
  const { data } = await api.get('/alerts/', { params })
  return data
}

export async function getAlertStats() {
  const { data } = await api.get('/alerts/stats/summary')
  return data
}

export async function updateAlert(id: string, payload: Record<string, unknown>) {
  const { data } = await api.patch(`/alerts/${id}`, payload)
  return data
}

// --- Events ---
export async function getEvents(params?: { severity?: string; limit?: number }) {
  const { data } = await api.get('/events/', { params })
  return data
}

export async function ingestEvent(payload: Record<string, unknown>) {
  const { data } = await api.post('/events/ingest', payload)
  return data
}

// --- IoCs ---
export async function getIoCs(params?: { ioc_type?: string; limit?: number }) {
  const { data } = await api.get('/iocs/', { params })
  return data
}

export async function createIoC(payload: Record<string, unknown>) {
  const { data } = await api.post('/iocs/', payload)
  return data
}

// --- Analysis ---
export async function analyzeFile(file: File) {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post('/analyze/file', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

export async function analyzeDomain(domain: string) {
  const { data } = await api.post('/analyze/domain', null, { params: { domain } })
  return data
}

export async function analyzeIP(ip: string) {
  const { data } = await api.post('/analyze/ip', null, { params: { ip } })
  return data
}

// --- Neutralization (P16.1 HitL) ---

export type NeutralizeStatus =
  | 'pending_approval'
  | 'approved'
  | 'executing'
  | 'completed'
  | 'failed'
  | 'rejected'
  | 'escalated'

export type NeutralizeSeverity = 'critical' | 'high' | 'medium' | 'low'

export type NeutralizeActionType =
  | 'isolate_endpoint'
  | 'block_ip'
  | 'block_domain'
  | 'kill_process'
  | 'quarantine_file'
  | 'remove_persistence'
  | 'disable_account'

// PANL rollback inverse types (read-only — created by POST /neutralize/{id}/rollback)
export type NeutralizeRollbackType =
  | 'unisolate_endpoint'
  | 'unblock_ip'
  | 'unblock_domain'
  | 'restore_file'

// PANL adaptive context — optional, enriches severity calculation
export interface AdaptiveContext {
  endpoint_is_critical_infrastructure?: boolean
  active_threat_intel_match?: boolean
  multiple_recent_alerts?: boolean
  known_lateral_movement?: boolean
  ransomware_indicator?: boolean
  agent_labels?: string[]
}

export interface ApprovalLogEntry {
  approved_by: string
  approved_at: string
}

export interface NeutralizeAction {
  id: string
  action_type: NeutralizeActionType | NeutralizeRollbackType
  severity: NeutralizeSeverity
  // PANL adaptive severity
  original_severity: NeutralizeSeverity | null
  severity_adapted: boolean
  target: string
  target_type: string
  status: NeutralizeStatus
  automated: boolean
  alert_id: string | null
  initiated_by: string | null
  approval_required: boolean
  // PANL multi-sig
  required_approvals: number
  approvals_received: number
  approvals_log: ApprovalLogEntry[]
  timeout_minutes: number
  expires_at: string | null
  approved_by: string | null
  approved_at: string | null
  rejected_by: string | null
  rejected_at: string | null
  rejection_reason: string | null
  escalated_at: string | null
  escalation_reason: string | null
  result: Record<string, unknown>
  error_message: string | null
  // PANL rollback
  rollback_available: boolean
  is_rollback: boolean
  rollback_of: string | null
  rollback_action_id: string | null
  created_at: string
  executed_at: string | null
}

export interface NeutralizeHistoryResponse {
  total: number
  actions: NeutralizeAction[]
}

export interface NeutralizeRequest {
  action_type: NeutralizeActionType
  target: string
  target_type: string
  severity?: NeutralizeSeverity
  params?: Record<string, unknown>
  alert_id?: string
  automated?: boolean
  // PANL adaptive context
  adaptive_context?: AdaptiveContext
}

// PANL SSE notification types
export type PanlEventType =
  | 'pending_approval_created'
  | 'action_partial_approved'
  | 'action_approved'
  | 'action_rejected'
  | 'action_escalated'
  | 'action_completed'
  | 'action_failed'
  | 'rollback_requested'

export interface PanlNotification {
  event: PanlEventType
  data: Record<string, unknown>
  ts: string
}

export async function requestNeutralizeAction(payload: NeutralizeRequest): Promise<NeutralizeAction> {
  const { data } = await api.post('/neutralize/', payload)
  return data
}

export async function getPendingApprovals(): Promise<{ total: number; actions: NeutralizeAction[] }> {
  const { data } = await api.get('/neutralize/pending')
  return data
}

export async function approveNeutralizeAction(actionId: string): Promise<NeutralizeAction> {
  const { data } = await api.post(`/neutralize/${actionId}/approve`)
  return data
}

export async function rejectNeutralizeAction(actionId: string, reason: string): Promise<NeutralizeAction> {
  const { data } = await api.post(`/neutralize/${actionId}/reject`, { reason })
  return data
}

export async function getNeutralizeAction(actionId: string): Promise<NeutralizeAction> {
  const { data } = await api.get(`/neutralize/${actionId}`)
  return data
}

export async function getNeutralizeHistory(limit = 20): Promise<NeutralizeHistoryResponse> {
  const { data } = await api.get('/neutralize/history', { params: { limit } })
  return data
}

/** @deprecated use requestNeutralizeAction */
export async function executeAction(payload: Record<string, unknown>) {
  return requestNeutralizeAction(payload as unknown as NeutralizeRequest)
}

// ── SPECTER Command status (P16.2) ────────────────────────────────────────────

export type SprecterCommandStatus =
  | 'pending'
  | 'delivered'
  | 'executing'
  | 'completed'
  | 'failed'
  | 'cancelled'

export type DispatchMode = 'specter' | 'broadcast' | 'simulation'

export interface SprecterCommandSummary {
  id: string
  agent_id: string
  command_type: string
  params: Record<string, unknown>
  status: SprecterCommandStatus
  issued_by: string
  issued_at: string
  delivered_at: string | null
  completed_at: string | null
  result: Record<string, unknown> | null
  error: string | null
}

export interface NeutralizeCommandsResponse {
  action_id: string
  dispatch_mode: DispatchMode
  commands: SprecterCommandSummary[]
}

export async function getNeutralizeCommands(actionId: string): Promise<NeutralizeCommandsResponse> {
  const { data } = await api.get(`/neutralize/${actionId}/commands`)
  return data
}

// PANL: Request forensic rollback of a completed reversible action
export async function requestRollback(actionId: string): Promise<NeutralizeAction> {
  const { data } = await api.post(`/neutralize/${actionId}/rollback`)
  return data
}

// PANL: Subscribe to real-time approval queue notifications via SSE
export function subscribeToNotifications(
  onEvent: (notification: PanlNotification) => void,
  onError?: (err: Event) => void
): () => void {
  const token = typeof window !== 'undefined'
    ? localStorage.getItem('token') ?? ''
    : ''
  const url = `${API_URL}/api/v1/notifications/stream`
  const es = new EventSource(`${url}?token=${encodeURIComponent(token)}`)

  es.onmessage = (e) => {
    try {
      const parsed = JSON.parse(e.data) as PanlNotification
      onEvent(parsed)
    } catch {
      // ignore malformed events
    }
  }

  if (onError) {
    es.onerror = onError
  }

  // Return unsubscribe function
  return () => es.close()
}

// --- Detection ---
export async function evaluateEvent(event: Record<string, unknown>, original_analysis_ts?: string) {
  const params = original_analysis_ts ? { original_analysis_ts } : {}
  const { data } = await api.post('/detection/evaluate', event, { params })
  return data
}

export async function evaluateBulkEvents(events: Record<string, unknown>[], original_analysis_ts?: string) {
  const { data } = await api.post('/detection/evaluate/bulk', { events, original_analysis_ts })
  return data
}

export async function fingerprintArtifact(filename: string, data_hex: string) {
  const { data } = await api.post('/detection/fingerprint', { filename, data_hex })
  return data
}

export async function getDetectionRules() {
  const { data } = await api.get('/detection/rules')
  return data
}

// --- Playbooks ---
export async function getPlaybookCatalog() {
  const { data } = await api.get('/playbooks/')
  return data as PlaybookDef[]
}

export async function triggerPlaybook(payload: TriggerPayload) {
  const { data } = await api.post('/playbooks/trigger', payload)
  return data as PlaybookRun
}

export async function autoTriggerPlaybook(payload: AutoTriggerPayload) {
  const { data } = await api.post('/playbooks/auto-trigger', payload)
  return data as PlaybookRun
}

export async function getPlaybookRuns(params?: { limit?: number; offset?: number; status?: string }) {
  const { data } = await api.get('/playbooks/runs', { params })
  return data as { runs: PlaybookRun[]; total: number; offset: number; limit: number }
}

export async function getPlaybookRun(runId: string) {
  const { data } = await api.get(`/playbooks/runs/${runId}`)
  return data as PlaybookRun
}

export async function approvePlaybookRun(runId: string, approvalToken: string) {
  const { data } = await api.post(`/playbooks/runs/${runId}/approve`, { approval_token: approvalToken })
  return data as PlaybookRun
}

export async function abortPlaybookRun(runId: string) {
  const { data } = await api.post(`/playbooks/runs/${runId}/abort`)
  return data as PlaybookRun
}

// --- Playbook type definitions ---
export interface PlaybookDef {
  id: string
  name: string
  description: string
  semaphore: 'green' | 'yellow' | 'red'
  requires_approval: boolean
  min_risk: number
  max_risk: number
  step_count: number
  steps: { action: string; name: string }[]
}

export interface StepLog {
  step_index: number
  action: string
  name: string
  status: 'ok' | 'awaiting_approval' | 'warning' | 'error'
  ts: string
  detail?: string
  success?: boolean
  alert_id?: string
  neutralizer_details?: Record<string, unknown>
}

export interface PlaybookRun {
  id: string
  playbook_id: string
  playbook_name: string
  trigger_source: string
  semaphore: string
  risk_score: number
  status: 'pending' | 'running' | 'awaiting_approval' | 'completed' | 'failed' | 'aborted'
  steps_log: StepLog[]
  alert_id: string | null
  approval_token: string | null
  approved_by: string | null
  approved_at: string | null
  initiated_by: string
  started_at: string
  completed_at: string | null
  error: string | null
  trigger_data?: Record<string, unknown>
}

export interface TriggerPayload {
  playbook_id: string
  semaphore: string
  risk_score: number
  host?: string
  dst_ip?: string
  dst_domain?: string
  process_name?: string
  ttps?: string[]
  trigger_data?: Record<string, unknown>
}

export interface AutoTriggerPayload {
  semaphore: string
  risk_score: number
  trigger_source?: string
  host?: string
  dst_ip?: string
  dst_domain?: string
  process_name?: string
  ttps?: string[]
  fingerprint_confidence?: number
  fingerprint_triggers?: string[]
  trigger_data?: Record<string, unknown>
}

// --- Adapters (SIEM / EDR / SOAR) ---

export interface AdapterInfo {
  name: string
  label: string
  type: string
  configured: boolean
  description: string
}

export async function listAdapters(): Promise<{ adapters: AdapterInfo[] }> {
  const { data } = await api.get('/adapters/')
  return data
}

export async function testAdapterStatus(adapter: string): Promise<Record<string, unknown>> {
  const { data } = await api.get(`/adapters/${adapter}/status`)
  return data
}

// --- SPECTER Agents ---

export interface SprecterAgent {
  id: string
  hostname: string
  os_type: string
  os_version: string
  arch: string
  ip_address: string
  specter_version: string
  status: 'active' | 'inactive' | 'isolated' | 'compromised'
  threat_level: 'normal' | 'elevated' | 'critical'
  poll_interval: number
  first_seen: string
  last_seen: string
  labels: Record<string, string>
  total_events: number
}

export interface AgentCommand {
  id: string
  agent_id: string
  command_type: string
  params: Record<string, unknown>
  signature: string
  status: 'pending' | 'delivered' | 'executing' | 'completed' | 'failed' | 'cancelled'
  issued_by: string
  issued_at: string
  delivered_at: string | null
  completed_at: string | null
  result?: Record<string, unknown> | null
  error?: string | null
}

export interface AgentEvent {
  id: string
  event_type: string
  severity: string
  data: Record<string, unknown>
  signature_valid: boolean
  is_anomaly: boolean
  ts: string
  received_at: string
}

export async function listAgents(params?: {
  status_filter?: string
  threat_filter?: string
  limit?: number
}): Promise<{ agents: SprecterAgent[]; total: number }> {
  const { data } = await api.get('/agents/', { params })
  return data
}

export async function getAgent(agentId: string): Promise<SprecterAgent> {
  const { data } = await api.get(`/agents/${agentId}`)
  return data
}

export async function deregisterAgent(agentId: string): Promise<{ detail: string }> {
  const { data } = await api.delete(`/agents/${agentId}`)
  return data
}

export async function issueAgentCommand(
  agentId: string,
  commandType: string,
  params: Record<string, unknown>
): Promise<AgentCommand> {
  const { data } = await api.post(`/agents/${agentId}/command`, {
    command_type: commandType,
    params,
  })
  return data
}

export async function setAgentThreatLevel(
  agentId: string,
  threatLevel: 'normal' | 'elevated' | 'critical'
): Promise<{ agent_id: string; threat_level: string; poll_interval: number }> {
  const { data } = await api.patch(`/agents/${agentId}/threat`, { threat_level: threatLevel })
  return data
}

export async function getAgentTimeline(
  agentId: string,
  params?: { limit?: number; anomalies_only?: boolean }
): Promise<{ agent_id: string; hostname: string; events: AgentEvent[] }> {
  const { data } = await api.get(`/agents/${agentId}/timeline`, { params })
  return data
}

export async function getCommandHistory(
  agentId: string,
  params?: { limit?: number; status_filter?: string }
): Promise<{ agent_id: string; hostname: string; commands: AgentCommand[]; total: number }> {
  const { data } = await api.get(`/agents/${agentId}/command-history`, { params })
  return data
}

// ELK / Elasticsearch
export async function elkPushAlert(alertId: string): Promise<Record<string, unknown>> {
  const { data } = await api.post(`/adapters/elk/push/alert/${alertId}`)
  return data
}

export async function elkPushEvent(eventId: string): Promise<Record<string, unknown>> {
  const { data } = await api.post(`/adapters/elk/push/event/${eventId}`)
  return data
}

export async function elkPullEvents(sinceHours: number, size: number): Promise<Record<string, unknown>> {
  const { data } = await api.post('/adapters/elk/pull/events', { since_hours: sinceHours, size })
  return data
}

// Wazuh
export async function wazuhPullAlerts(sinceHours: number, limit: number): Promise<Record<string, unknown>> {
  const { data } = await api.post('/adapters/wazuh/pull/alerts', { since_hours: sinceHours, limit })
  return data
}

export async function wazuhGetAgents(status = 'active'): Promise<Record<string, unknown>> {
  const { data } = await api.get('/adapters/wazuh/agents', { params: { status } })
  return data
}

// TheHive
export async function thehiveCreateCase(alertId: string): Promise<Record<string, unknown>> {
  const { data } = await api.post('/adapters/thehive/cases', { alert_id: alertId })
  return data
}

export async function thehiveAddObservable(caseId: string, iocId: string): Promise<Record<string, unknown>> {
  const { data } = await api.post(`/adapters/thehive/cases/${caseId}/observables`, null, {
    params: { ioc_id: iocId },
  })
  return data
}

export async function thehiveGetCase(caseId: string): Promise<Record<string, unknown>> {
  const { data } = await api.get(`/adapters/thehive/cases/${caseId}`)
  return data
}

// Firewall — PAN-OS preferred, Fortinet fallback (F1/F2)
export async function firewallBlockIP(ip: string, reason = ''): Promise<Record<string, unknown>> {
  const { data } = await api.post('/adapters/firewall/block/ip', { ip, reason })
  return data
}

export async function firewallUnblockIP(ip: string): Promise<Record<string, unknown>> {
  const { data } = await api.post('/adapters/firewall/unblock/ip', { ip, reason: '' })
  return data
}

export async function firewallBlockDomain(domain: string, reason = ''): Promise<Record<string, unknown>> {
  const { data } = await api.post('/adapters/firewall/block/domain', { domain, reason })
  return data
}

export async function firewallUnblockDomain(domain: string): Promise<Record<string, unknown>> {
  const { data } = await api.post('/adapters/firewall/unblock/domain', { domain, reason: '' })
  return data
}

// Identity — Active Directory (F1/F2)
export async function identityDisableAccount(username: string, domain: string, reason = ''): Promise<Record<string, unknown>> {
  const { data } = await api.post('/adapters/identity/disable', { username, domain, reason })
  return data
}

export async function identityEnableAccount(username: string, domain: string): Promise<Record<string, unknown>> {
  const { data } = await api.post('/adapters/identity/enable', { username, domain, reason: '' })
  return data
}

export async function identityForcePasswordReset(username: string, domain: string): Promise<Record<string, unknown>> {
  const { data } = await api.post('/adapters/identity/force-reset', { username, domain, reason: '' })
  return data
}

export async function identityQuarantineAccount(username: string, domain: string): Promise<Record<string, unknown>> {
  const { data } = await api.post('/adapters/identity/quarantine', { username, domain, reason: '' })
  return data
}

// --- SPECTER Honeypot (P15) ---

export interface CanaryAccess {
  ts: string
  client_ip: string
  user_agent: string
  referer: string
  headers_snapshot?: Record<string, string>
}

export interface CanaryToken {
  token_id: string
  endpoint: string
  label: string
  created_at: string
  access_count: number
  first_access: string | null
  last_access: string | null
  accesses: CanaryAccess[]
}

export interface CanaryTokensResponse {
  total: number
  tokens: CanaryToken[]
}

export interface EvidenceReportSummary {
  report_id: string
  event_type: string
  attacker_ip: string
  severity: string
  generated_at: string
  canary_accesses: number
  signature: string
}

export interface EvidenceReportsResponse {
  total: number
  reports: EvidenceReportSummary[]
}

export interface EvidenceReportFull {
  report_id: string
  report: {
    report_id: string
    generated_at: string
    generated_by: string
    event_type: string
    incident_summary: {
      description: string
      severity: string
      attacker_ip: string
      x_forwarded_for: string | null
      attack_ts: string
    }
    attacker_fingerprint: {
      client_ip: string
      user_agent: string
      accept_language: string
      accept_encoding: string
      referer: string
      x_forwarded_for: string
      fingerprint_hash: string
      timestamp: string
    }
    ip_reputation: Record<string, unknown>
    canary_evidence: {
      token_id: string | null
      endpoint: string | null
      label: string | null
      access_count: number
      first_access: string | null
      last_access: string | null
    } | null
    legal_notice: string
    reporting_guidelines: Record<string, string>
  }
  signature: string
}

export async function listHoneypotTokens(): Promise<CanaryTokensResponse> {
  const { data } = await api.get('/honeypot/tokens')
  return data
}

export async function getHoneypotToken(tokenId: string): Promise<CanaryToken> {
  const { data } = await api.get(`/honeypot/token/${tokenId}`)
  return data
}

export async function listEvidenceReports(): Promise<EvidenceReportsResponse> {
  const { data } = await api.get('/honeypot/reports')
  return data
}

export async function getEvidenceReport(reportId: string): Promise<EvidenceReportFull> {
  const { data } = await api.get(`/honeypot/report/${reportId}`)
  return data
}

// --- Public (no auth) ---
export async function getPublicMetrics() {
  const { data } = await api.get('/metrics/public')
  return data
}

// --- Health & Observability (P12) ---

export interface HealthLiveness {
  status: 'alive'
  ts: string
}

export interface HealthCheck {
  ok: boolean
  detail: string
}

export interface HealthReadiness {
  status: 'ready' | 'degraded'
  checks: Record<string, HealthCheck>
  ts: string
}

export interface HealthSystem {
  app: string
  version: string
  environment: 'production' | 'development'
  uptime_seconds: number
  uptime_human: string
  process?: {
    pid: number
    cpu_percent: number
    memory_rss_mb: number
    memory_vms_mb: number
  }
  ts: string
}

export interface ObservabilitySummary {
  ts: string
  process: {
    cpu_percent: number
    memory_rss_mb: number
    memory_vms_mb: number
    pid: number
  }
  database: {
    ok: boolean
    alerts_total: number
    events_total: number
  }
  agents: {
    active_last_5min: number
  }
  prometheus: {
    metrics_endpoint: string
    scrape_token_configured: boolean
  }
}

export async function getSystemLiveness(): Promise<HealthLiveness> {
  const { data } = await api.get('/health/liveness')
  return data
}

export async function getSystemReadiness(): Promise<HealthReadiness> {
  const { data } = await api.get('/health/readiness')
  return data
}

export async function getSystemInfo(): Promise<HealthSystem> {
  const { data } = await api.get('/health/system')
  return data
}

export async function getObservabilitySummary(): Promise<ObservabilitySummary> {
  const { data } = await api.get('/observability/summary')
  return data
}

// --- Operational Dashboard (P20) ---

export interface FleetSummary {
  total_agents: number
  by_status: Record<string, number>
  by_threat_level: Record<string, number>
  connectivity: { online_5m: number; online_1h: number; offline: number }
  at_risk: number
  ts: string
}

export interface LatencyStats {
  samples: number
  min_ms?: number
  max_ms?: number
  avg_ms?: number
  p50_ms?: number
  p95_ms?: number
}

export interface CommandMetrics {
  window_hours: number
  total_commands: number
  by_status: Record<string, number>
  by_type: Record<string, number>
  latency: LatencyStats
  success_rate_pct: number | null
  ts: string
}

export interface InflightCommand {
  id: string
  agent_id: string
  command_type: string
  status: string
  issued_by: string
  issued_at: string | null
  age_seconds: number | null
  params: Record<string, unknown>
}

export interface InflightCommandsResponse {
  total_inflight: number
  commands: InflightCommand[]
  ts: string
}

export interface EscalationSummary {
  id: string
  action_type: string
  severity: string
  target: string
  initiated_by: string | null
  escalated_at: string | null
}

export interface NeutralizationMetrics {
  window_hours: number
  total_actions: number
  by_status: Record<string, number>
  by_type: Record<string, number>
  by_severity: Record<string, number>
  approval_rate_pct: number | null
  escalations: EscalationSummary[]
  escalation_count: number
  ts: string
}

export async function getFleetSummary(): Promise<FleetSummary> {
  const { data } = await api.get('/ops/fleet/summary')
  return data
}

export async function getCommandMetrics(hours = 24): Promise<CommandMetrics> {
  const { data } = await api.get('/ops/commands/metrics', { params: { hours } })
  return data
}

export async function getInflightCommands(limit = 100): Promise<InflightCommandsResponse> {
  const { data } = await api.get('/ops/commands/inflight', { params: { limit } })
  return data
}

export async function getNeutralizationMetrics(hours = 24): Promise<NeutralizationMetrics> {
  const { data } = await api.get('/ops/neutralizations/metrics', { params: { hours } })
  return data
}

export interface CrossDomainMetrics {
  window_hours: number
  ts: string
  fleet: {
    total_agents: number
    active_agents: number
    online_5m: number
    at_risk_agents: number
    commands_in_window: number
    command_success_rate_pct: number | null
  }
  hunting: {
    active_hunts: number
    critical_priority_hunts: number
    total_hunts: number
    completed_in_window: number
    true_positives_in_window: number
    high_severity_findings: number
    active_hunt_ids: string[]
  }
  panl: {
    actions_in_window: number
    pending_approval: number
    by_status: Record<string, number>
    approval_rate_pct: number | null
  }
  threat_intel: {
    total_indicators: number
    by_severity: Record<string, number>
    by_type: Record<string, number>
    new_in_window: number
  }
  pcdi: {
    total_signed_reports: number
    high_score_reports: number
    avg_adaptive_score: number | null
    active_critical_hunts: number
    top_reports: Array<{
      report_id: string
      hunt_id: string
      hunt_name: string | null
      adaptive_score: number
      signed_at: string | null
    }>
  }
}

export async function getCrossDomainMetrics(hours = 24): Promise<CrossDomainMetrics> {
  const { data } = await api.get('/ops/cross-domain', { params: { hours } })
  return data
}

// --- Premos Forensic Neutralization (PFN — P19.3) ---

export interface ForensicEntry {
  id: string
  action_id: string
  action_type: string
  target: string
  hash_sha3_512: string
  signature_ed25519: string
  signed_by_email: string
  signed_by_user_id: string
  signed_at: string | null
  verified: boolean
  last_verified_at: string | null
  canonical_data: Record<string, unknown>
}

export interface ForensicVerifyResult {
  action_id: string
  entry_id: string
  valid: boolean
  hash_sha3_512: string
  signed_by: string
  signed_at: string | null
  verified_at: string | null
  message: string
}

export interface ForensicLedger {
  total: number
  limit: number
  offset: number
  entries: ForensicEntry[]
}

export async function forensicGetProof(actionId: string): Promise<ForensicEntry> {
  const { data } = await api.get(`/forensic/actions/${actionId}`)
  return data
}

export async function forensicVerifyProof(actionId: string): Promise<ForensicVerifyResult> {
  const { data } = await api.post(`/forensic/actions/${actionId}/verify`)
  return data
}

export async function forensicGetLedger(params?: { limit?: number; offset?: number }): Promise<ForensicLedger> {
  const { data } = await api.get('/forensic/ledger', { params })
  return data
}

// --- Threat Intelligence (P21-F1) ---

export interface ThreatIntelIndicator {
  id: string
  indicator_type: string
  value: string
  severity: string
  confidence: number
  threat_actor: string | null
  malware_family: string | null
  campaign: string | null
  ttps: string[]
  tags: string[]
  source: string
  description: string | null
  hit_count: number
  first_seen: string | null
  last_seen: string | null
}

export interface ThreatIntelStats {
  total: number
  active: number
  inactive: number
  by_type: Record<string, number>
  by_severity: Record<string, number>
  top_hits: ThreatIntelIndicator[]
}

export interface ThreatIntelListResponse {
  total: number
  limit: number
  offset: number
  indicators: ThreatIntelIndicator[]
}

export interface EnrichResult {
  value: string
  indicator_type: string | null
  matches: ThreatIntelIndicator[]
  match_count: number
  is_known_bad: boolean
  max_severity: string | null
}

export interface AdapterHealthResult {
  adapter: string
  status: 'reachable' | 'unreachable' | 'not_configured'
  detail: string
}

export interface AdapterHealthResponse {
  total_adapters: number
  configured: number
  reachable: number
  unreachable: number
  adapters: AdapterHealthResult[]
  ts: string
}

export async function getTIStats(): Promise<ThreatIntelStats> {
  const { data } = await api.get('/threat-intel/stats')
  return data
}

export async function listTIIndicators(params?: {
  indicator_type?: string
  severity?: string
  active_only?: boolean
  limit?: number
  offset?: number
}): Promise<ThreatIntelListResponse> {
  const { data } = await api.get('/threat-intel/', { params })
  return data
}

export async function createTIIndicator(payload: {
  indicator_type: string
  value: string
  severity?: string
  confidence?: number
  source?: string
  threat_actor?: string
  malware_family?: string
  campaign?: string
  ttps?: string[]
  tags?: string[]
  description?: string
}): Promise<ThreatIntelIndicator> {
  const { data } = await api.post('/threat-intel/', payload)
  return data
}

export async function bulkImportTI(indicators: Record<string, unknown>[]): Promise<{
  created: number; updated: number; skipped: number; total: number
}> {
  const { data } = await api.post('/threat-intel/bulk', { indicators })
  return data
}

export async function enrichTI(value: string, indicator_type?: string): Promise<EnrichResult> {
  const { data } = await api.post('/threat-intel/enrich', { value, indicator_type })
  return data
}

export async function deleteTIIndicator(indicatorId: string): Promise<{ message: string }> {
  const { data } = await api.delete(`/threat-intel/${indicatorId}`)
  return data
}

export async function getAdapterHealth(): Promise<AdapterHealthResponse> {
  const { data } = await api.get('/health/adapters')
  return data
}

// ── Threat Hunting — P22 ─────────────────────────────────────────────────────

export interface Hunt {
  id: string
  name: string
  description: string | null
  hypothesis: string | null
  status: 'draft' | 'active' | 'completed' | 'archived'
  mitre_technique: string | null
  mitre_tactic: string | null
  scope: string
  priority: string
  created_by: string
  assigned_to: string | null
  created_at: string
  started_at: string | null
  completed_at: string | null
  updated_at: string
  conclusion: string | null
  findings_count: number
  true_positive_count: number
  tags: string[]
}

export interface HuntFinding {
  id: string
  hunt_id: string
  title: string
  description: string | null
  severity: string
  indicator_value: string | null
  indicator_type: string | null
  affected_host: string | null
  affected_user: string | null
  data_source: string | null
  mitre_technique: string | null
  mitre_tactic: string | null
  evidence: Record<string, unknown> | null
  is_confirmed: boolean
  is_false_positive: boolean
  analyst_notes: string | null
  created_by: string
  created_at: string
  updated_at: string
}

export interface HuntQuery {
  id: string
  hunt_id: string
  name: string
  query_text: string
  data_source: string
  description: string | null
  last_executed_at: string | null
  last_result_count: number | null
  last_execution_ms: number | null
  created_by: string
  created_at: string
}

export interface HuntStats {
  total_hunts: number
  by_status: Record<string, number>
  by_priority: Record<string, number>
  active_hunts: number
  completed_hunts: number
  total_findings: number
  confirmed_findings: number
  false_positive_rate: number
  findings_by_severity: Record<string, number>
  top_techniques: { technique: string; count: number }[]
}

export async function getHuntStats(): Promise<HuntStats> {
  const { data } = await api.get('/hunt/stats')
  return data
}

export async function listHunts(params?: {
  status?: string
  priority?: string
  scope?: string
  limit?: number
  offset?: number
}): Promise<{ hunts: Hunt[]; total: number; limit: number; offset: number }> {
  const { data } = await api.get('/hunt/', { params })
  return data
}

export async function createHunt(payload: {
  name: string
  description?: string
  hypothesis?: string
  mitre_technique?: string
  mitre_tactic?: string
  scope?: string
  priority?: string
  assigned_to?: string
  tags?: string[]
}): Promise<Hunt> {
  const { data } = await api.post('/hunt/', payload)
  return data
}

export async function getHunt(huntId: string, includeRelations = false): Promise<Hunt & {
  findings?: HuntFinding[]
  queries?: HuntQuery[]
}> {
  const { data } = await api.get(`/hunt/${huntId}`, {
    params: { include_relations: includeRelations },
  })
  return data
}

export async function updateHunt(huntId: string, updates: Partial<{
  name: string
  description: string
  hypothesis: string
  mitre_technique: string
  mitre_tactic: string
  scope: string
  priority: string
  assigned_to: string
  conclusion: string
  tags: string[]
  status: string
}>): Promise<Hunt> {
  const { data } = await api.put(`/hunt/${huntId}`, updates)
  return data
}

export async function archiveHunt(huntId: string): Promise<void> {
  await api.delete(`/hunt/${huntId}`)
}

export async function listFindings(huntId: string, params?: {
  severity?: string
  confirmed_only?: boolean
}): Promise<{ findings: HuntFinding[]; total: number }> {
  const { data } = await api.get(`/hunt/${huntId}/findings`, { params })
  return data
}

export async function addFinding(huntId: string, payload: {
  title: string
  description?: string
  severity?: string
  indicator_value?: string
  indicator_type?: string
  affected_host?: string
  affected_user?: string
  data_source?: string
  mitre_technique?: string
  mitre_tactic?: string
  evidence?: Record<string, unknown>
  analyst_notes?: string
}): Promise<HuntFinding> {
  const { data } = await api.post(`/hunt/${huntId}/findings`, payload)
  return data
}

export async function setFindingVerdict(huntId: string, findingId: string, payload: {
  is_confirmed: boolean
  is_false_positive?: boolean
  analyst_notes?: string
}): Promise<HuntFinding> {
  const { data } = await api.post(`/hunt/${huntId}/findings/${findingId}/verdict`, payload)
  return data
}

export async function listQueries(huntId: string): Promise<{ queries: HuntQuery[]; total: number }> {
  const { data } = await api.get(`/hunt/${huntId}/queries`)
  return data
}

export async function saveQuery(huntId: string, payload: {
  name: string
  query_text: string
  data_source?: string
  description?: string
}): Promise<HuntQuery> {
  const { data } = await api.post(`/hunt/${huntId}/queries`, payload)
  return data
}

export async function deleteQuery(huntId: string, queryId: string): Promise<void> {
  await api.delete(`/hunt/${huntId}/queries/${queryId}`)
}

// ── Threat Hunting — P23 ─────────────────────────────────────────────────────

export async function createHuntFromAlert(alertId: string): Promise<Hunt> {
  const { data } = await api.post(`/hunt/from-alert/${alertId}`)
  return data
}

export async function executeHuntQuery(huntId: string, queryId: string): Promise<{
  query_id: string; hunt_id: string; data_source: string
  result_count: number; total: number; truncated: boolean
  execution_ms: number; results: Record<string, unknown>[]
  success: boolean; error: string | null; executed_at: string; note?: string
}> {
  const { data } = await api.post(`/hunt/${huntId}/queries/${queryId}/execute`)
  return data
}

export async function enrichFinding(huntId: string, findingId: string): Promise<{
  finding_id: string; hunt_id: string; indicator_value: string | null
  indicator_type: string | null; enriched: boolean; match_count: number
  matches: ThreatIntelIndicator[]; is_known_bad: boolean; max_severity: string | null; note?: string
}> {
  const { data } = await api.post(`/hunt/${huntId}/findings/${findingId}/enrich`)
  return data
}

export interface HuntReport {
  report_generated_at: string
  hunt: Hunt
  executive_summary: string
  hypothesis: string | null
  conclusion: string | null
  findings_by_severity: Record<string, HuntFinding[]>
  findings_total: number
  queries_used: HuntQuery[]
  timeline: { event: string; ts: string; note?: string; confirmed?: boolean; false_positive?: boolean }[]
  tags: string[]
}

export async function getHuntReport(huntId: string): Promise<HuntReport> {
  const { data } = await api.get(`/hunt/${huntId}/report`)
  return data
}

// ── PCDI — Premos Cross-Domain Intelligence (P24) ─────────────────────────────

export interface PCDIScore {
  finding_id: string
  hunt_id: string
  indicator_value: string | null
  original_severity: string
  adaptive_score: number
  adapted_severity: string
  severity_escalated: boolean
  recommendation: string
  signals: { source: string; value: unknown; contribution: number }[]
  ti_matches: { indicator_id: string; value: string; severity: string; source: string; contribution: number }[]
  panl_correlations: { action_id: string; action_type: string; status: string; target: string; contribution: number }[]
  scored_at: string
}

export interface PCDICorrelation {
  hunt_id: string
  hunt_name: string
  findings_analyzed: number
  target_values_searched: number
  panl_correlations: {
    action_id: string
    action_type: string
    status: string
    severity: string
    target: string
    target_type: string
    executed_at: string | null
    matched_finding_ids: string[]
    match_count: number
  }[]
  panl_action_summary: Record<string, number>
  ti_correlations: {
    indicator_id: string
    value: string
    type: string
    severity: string
    source: string
    matched_finding_ids: string[]
  }[]
  total_panl_matches: number
  total_ti_matches: number
  correlated_at: string
}

export interface PCDISignedReport {
  id: string
  hunt_id: string
  hunt_name: string | null
  hash_sha3_512: string
  hash_prefix: string
  signature_ed25519: string
  signed_by_email: string
  signed_by_user_id: string | null
  signed_at: string | null
  verified: boolean
  last_verified_at: string | null
  pcdi_version: string
  adaptive_score: number | null
}

export interface PCDIVerifyResult {
  report_id: string
  hunt_id: string
  verified: boolean
  hash_valid: boolean
  signature_valid: boolean
  signed_by: string
  signed_at: string
  verified_at: string
  details: {
    stored_hash_prefix: string
    recomputed_hash_prefix: string
    hash_match: boolean
  }
}

export async function getPCDIScore(findingId: string): Promise<PCDIScore> {
  const { data } = await api.post(`/pcdi/score/${findingId}`)
  return data
}

export async function getPCDICorrelation(huntId: string): Promise<PCDICorrelation> {
  const { data } = await api.get(`/pcdi/correlate/${huntId}`)
  return data
}

export async function signHuntReport(
  huntId: string,
  opts?: { report_data?: Record<string, unknown>; adaptive_score?: number }
): Promise<PCDISignedReport> {
  const { data } = await api.post(`/pcdi/sign-report/${huntId}`, opts ?? {})
  return data
}

export async function listSignedReports(
  huntId?: string,
  limit = 50
): Promise<{ total: number; reports: PCDISignedReport[] }> {
  const { data } = await api.get('/pcdi/signed-reports', {
    params: { hunt_id: huntId, limit },
  })
  return data
}

export async function getSignedReport(reportId: string): Promise<PCDISignedReport> {
  const { data } = await api.get(`/pcdi/signed-reports/${reportId}`)
  return data
}

export async function verifySignedReport(
  reportId: string,
  publicKeyB64: string
): Promise<PCDIVerifyResult> {
  const { data } = await api.post(`/pcdi/signed-reports/${reportId}/verify`, {
    public_key_b64: publicKeyB64,
  })
  return data
}

export interface ForensicTimelineEvent {
  event_type: string
  ts: string
  actor: string
  data: Record<string, unknown>
  sequence: number
  prev_hash: string
  entry_hash: string
}

export interface ForensicTimeline {
  hunt_id: string
  hunt_name: string
  event_count: number
  chain_root_hash: string
  chain_root_prefix: string
  genesis_seed: string
  timeline: ForensicTimelineEvent[]
  built_at: string
}

export async function getForensicTimeline(huntId: string): Promise<ForensicTimeline> {
  const { data } = await api.get(`/pcdi/forensic-timeline/${huntId}`)
  return data
}

// ── SOAR — P25 ───────────────────────────────────────────────────────────────

export interface SOARTrigger {
  id: string
  playbook_id: string
  playbook_name: string
  condition_type: string
  condition_operator: string
  condition_value: string
  hunt_id_filter: string | null
  priority: number
  rate_limit_per_hour: number
  dedup_window_minutes: number
  enabled: boolean
  trigger_count: number
  last_triggered_at: string | null
  last_triggered_context: string | null
  created_by: string
  created_at: string | null
}

export interface ScheduledReport {
  id: string
  hunt_id: string
  hunt_name: string | null
  recipient_email: string
  frequency: string
  format: string
  enabled: boolean
  last_sent_at: string | null
  send_count: number
  last_error: string | null
  created_by: string
  created_at: string | null
}

export async function listSOARTriggers(params?: {
  playbook_id?: string
  condition_type?: string
  enabled_only?: boolean
}): Promise<{ count: number; triggers: SOARTrigger[] }> {
  const { data } = await api.get('/soar/triggers', { params })
  return data
}

export async function createSOARTrigger(payload: {
  playbook_id: string
  playbook_name: string
  condition_type: string
  condition_operator: string
  condition_value: string
  hunt_id_filter?: string | null
}): Promise<SOARTrigger> {
  const { data } = await api.post('/soar/triggers', payload)
  return data
}

export async function getSOARTrigger(triggerId: string): Promise<SOARTrigger> {
  const { data } = await api.get(`/soar/triggers/${triggerId}`)
  return data
}

export async function deleteSOARTrigger(triggerId: string): Promise<void> {
  await api.delete(`/soar/triggers/${triggerId}`)
}

export async function toggleSOARTrigger(triggerId: string, enabled: boolean): Promise<SOARTrigger> {
  const { data } = await api.patch(`/soar/triggers/${triggerId}/toggle`, { enabled })
  return data
}

export async function testSOARTrigger(triggerId: string, context: Record<string, unknown>): Promise<{
  trigger_id: string; playbook_id: string; condition_type: string
  condition_operator: string; condition_value: string
  context: Record<string, unknown>; matched: boolean; would_fire: boolean; note: string
}> {
  const { data } = await api.post(`/soar/triggers/${triggerId}/test`, { context })
  return data
}

export async function evaluateSOARContext(context: Record<string, unknown>, dryRun = true): Promise<{
  dry_run: boolean; context: Record<string, unknown>
  matched_count?: number; matches?: unknown[]
  fired_count?: number; fired?: unknown[]
}> {
  const { data } = await api.post('/soar/evaluate', { context, dry_run: dryRun })
  return data
}

export async function listScheduledReports(params?: {
  hunt_id?: string
  enabled_only?: boolean
}): Promise<{ count: number; reports: ScheduledReport[] }> {
  const { data } = await api.get('/soar/reports', { params })
  return data
}

export async function createScheduledReport(payload: {
  hunt_id: string
  hunt_name?: string
  recipient_email: string
  frequency: string
  format: string
}): Promise<ScheduledReport> {
  const { data } = await api.post('/soar/reports', payload)
  return data
}

export async function deleteScheduledReport(reportId: string): Promise<void> {
  await api.delete(`/soar/reports/${reportId}`)
}

export async function toggleScheduledReport(reportId: string, enabled: boolean): Promise<ScheduledReport> {
  const { data } = await api.patch(`/soar/reports/${reportId}/toggle`, { enabled })
  return data
}

export async function deliverScheduledReport(reportId: string): Promise<{
  report_id: string; summary: Record<string, unknown>; error: string | null
}> {
  const { data } = await api.post(`/soar/reports/${reportId}/deliver`)
  return data
}

export async function exportHuntToTheHive(huntId: string, includeUnconfirmed = false): Promise<{
  success: boolean; hunt_id: string; hunt_name?: string; case_id?: string
  case_number?: number; observables_added?: number; errors?: string[]
  exported_at?: string; error?: string
}> {
  const { data } = await api.post(`/adapters/thehive/hunt/${huntId}`, null, {
    params: { include_unconfirmed: includeUnconfirmed },
  })
  return data
}

export async function searchADUser(username: string): Promise<{
  success: boolean; username: string; dn?: string; display_name?: string
  email?: string; enabled?: boolean; department?: string; title?: string
  groups?: string[]; group_count?: number; error?: string
}> {
  const { data } = await api.get('/adapters/identity/search', { params: { username } })
  return data
}

export async function listADGroupMembers(groupName: string): Promise<{
  success: boolean; group: string; group_dn?: string; member_count?: number
  members?: { username: string; display_name: string; email: string | null; enabled: boolean; dn: string }[]
  error?: string
}> {
  const { data } = await api.get(`/adapters/identity/groups/${groupName}/members`)
  return data
}

// ── PIDS — P26 ───────────────────────────────────────────────────────────────

export interface IdentityAction {
  id: string
  action_type: string
  username: string
  domain: string
  reason: string
  hunt_id: string | null
  finding_id: string | null
  trigger_id: string | null
  playbook_run_id: string | null
  success: boolean
  result_detail: string | null
  hash_sha3_512: string | null
  signature_ed25519: string | null
  signed_at: string | null
  signed_by_email: string
  initiated_by: string
  executed_at: string | null
}

export async function listIdentityActions(params?: {
  username?: string
  action_type?: string
  hunt_id?: string
  success?: boolean
  limit?: number
}): Promise<{ count: number; actions: IdentityAction[] }> {
  const { data } = await api.get('/pids/actions', { params })
  return data
}

export async function createIdentityAction(payload: {
  action_type: string
  username: string
  domain?: string
  reason: string
  hunt_id?: string
  finding_id?: string
  trigger_id?: string
  playbook_run_id?: string
  success?: boolean
  result_detail?: string
}): Promise<IdentityAction> {
  const { data } = await api.post('/pids/actions', payload)
  return data
}

export async function getIdentityAction(actionId: string): Promise<IdentityAction> {
  const { data } = await api.get(`/pids/actions/${actionId}`)
  return data
}

export async function verifyIdentityAction(actionId: string): Promise<{
  action_id: string; verified: boolean; hash_match: boolean
  signature_ok: boolean | null; stored_hash: string; computed_hash: string
  signed_at: string | null; signed_by: string; action_type: string; username: string
}> {
  const { data } = await api.post(`/pids/actions/${actionId}/verify`)
  return data
}

export async function getIdentityTimeline(huntId: string): Promise<{
  hunt_id: string; count: number; timeline: IdentityAction[]
}> {
  const { data } = await api.get(`/pids/timeline/${huntId}`)
  return data
}

export async function getPidsSummary(huntId?: string): Promise<{
  hunt_id: string | null; total_actions: number; successful_actions: number
  failed_actions: number; success_rate_pct: number; actions_24h: number
}> {
  const url = huntId ? `/pids/summary/${huntId}` : '/pids/summary'
  const { data } = await api.get(url)
  return data
}

// ── Correlation Engine — P27-B ────────────────────────────────────────────────

export interface CorrelationRule {
  id: string
  name: string
  description: string | null
  pivot_type: string
  min_signals: number
  time_window_minutes: number
  severity_threshold: string
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface CorrelationCluster {
  id: string
  rule_id: string
  cluster_key: string
  cluster_type: string
  signal_count: number
  severity: string
  confidence_score: number
  first_seen: string
  last_seen: string
  status: 'active' | 'resolved' | 'dismissed'
  is_campaign: boolean
  campaign_name: string | null
  distinct_signal_domains: number
  analyst_notes: string | null
  assigned_to: string | null
  forensic_hash: string | null
  meta: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface CorrelationSignal {
  id: string
  cluster_id: string
  signal_type: string
  signal_id: string
  pivot_value: string
  severity: string
  timestamp: string
  meta: Record<string, unknown>
  created_at: string
}

export interface CorrelationGraph {
  cluster_id: string
  pivot_type: string
  pivot_value: string
  is_campaign: boolean
  campaign_name: string | null
  nodes: {
    id: string; type: string; label: string; severity: string
    ts: string | null; meta?: Record<string, unknown>; is_campaign?: boolean; status?: string
  }[]
  edges: { source: string; target: string; pivot: string; pivot_type: string }[]
}

export interface CorrelationSummary {
  total_clusters: number
  active_clusters: number
  campaigns_detected: number
  critical_clusters: number
  total_signals: number
  active_rules: number
}

export async function getCorrelationSummary(): Promise<CorrelationSummary> {
  const { data } = await api.get('/correlation/summary')
  return data
}

export async function listCorrelationRules(): Promise<CorrelationRule[]> {
  const { data } = await api.get('/correlation/rules')
  return data
}

export async function createCorrelationRule(payload: {
  name: string; pivot_type: string; min_signals?: number
  time_window_minutes?: number; severity_threshold?: string; description?: string
}): Promise<CorrelationRule> {
  const { data } = await api.post('/correlation/rules', payload)
  return data
}

export async function updateCorrelationRule(
  ruleId: string,
  payload: Partial<Pick<CorrelationRule, 'name' | 'pivot_type' | 'min_signals' | 'time_window_minutes' | 'severity_threshold' | 'description' | 'enabled'>>
): Promise<CorrelationRule> {
  const { data } = await api.patch(`/correlation/rules/${ruleId}`, payload)
  return data
}

export async function deleteCorrelationRule(ruleId: string): Promise<void> {
  await api.delete(`/correlation/rules/${ruleId}`)
}

export async function listCorrelationClusters(params?: {
  status?: string; cluster_type?: string; campaigns_only?: boolean; limit?: number; offset?: number
}): Promise<CorrelationCluster[]> {
  const { data } = await api.get('/correlation/clusters', { params })
  return data
}

export async function getCorrelationCluster(clusterId: string): Promise<CorrelationCluster> {
  const { data } = await api.get(`/correlation/clusters/${clusterId}`)
  return data
}

export async function updateClusterStatus(clusterId: string, payload: {
  status: string; analyst_notes?: string; assigned_to?: string
}): Promise<CorrelationCluster> {
  const { data } = await api.patch(`/correlation/clusters/${clusterId}/status`, payload)
  return data
}

// ── Webhooks (P42 / P44) ──────────────────────────────────────────────────────

export const VALID_WEBHOOK_EVENTS = [
  'incident.created',
  'incident.updated',
  'incident.resolved',
  'alert.critical',
  'alert.high',
  'playbook.executed',
  'api_key.rate_limited',
  'test',
] as const

export type WebhookEvent = typeof VALID_WEBHOOK_EVENTS[number]

export interface WebhookResponse {
  id: string
  url: string
  events: string[]
  description: string | null
  is_active: boolean
  user_id: string
  created_at: string
  last_triggered_at: string | null
  failure_count: number
}

export interface WebhookCreated extends WebhookResponse {
  secret: string
  signing_note: string
}

export interface WebhookTestResult {
  success: boolean
  status_code: number | null
  latency_ms: number
  error: string | null
}

export async function listWebhooks(): Promise<WebhookResponse[]> {
  const { data } = await api.get('/webhooks/')
  return data
}

export async function getWebhook(webhookId: string): Promise<WebhookResponse> {
  const { data } = await api.get(`/webhooks/${webhookId}`)
  return data
}

export async function createWebhook(payload: {
  url: string
  events: string[]
  description?: string | null
}): Promise<WebhookCreated> {
  const { data } = await api.post('/webhooks/', payload)
  return data
}

export async function updateWebhook(
  webhookId: string,
  payload: { url?: string; events?: string[]; is_active?: boolean; description?: string | null }
): Promise<WebhookResponse> {
  const { data } = await api.patch(`/webhooks/${webhookId}`, payload)
  return data
}

export async function deleteWebhook(webhookId: string): Promise<void> {
  await api.delete(`/webhooks/${webhookId}`)
}

export async function testWebhook(webhookId: string): Promise<WebhookTestResult> {
  const { data } = await api.post(`/webhooks/${webhookId}/test`)
  return data
}

export async function adminListAllWebhooks(): Promise<WebhookResponse[]> {
  const { data } = await api.get('/webhooks/admin/all')
  return data
}

export async function getClusterSignals(clusterId: string): Promise<CorrelationSignal[]> {
  const { data } = await api.get(`/correlation/clusters/${clusterId}/signals`)
  return data
}

export async function getClusterGraph(clusterId: string): Promise<CorrelationGraph> {
  const { data } = await api.get(`/correlation/clusters/${clusterId}/graph`)
  return data
}

export async function triggerCorrelationSweep(): Promise<{ status: string; task_id?: string; stats?: CorrelationSummary }> {
  const { data } = await api.post('/correlation/sweep')
  return data
}

// ── Incident Response — P28-B ─────────────────────────────────────────────────

export interface Incident {
  id: string
  title: string
  description: string | null
  incident_type: string
  status: string
  nist_phase: string
  severity: string
  risk_score: number
  created_by: string
  assigned_to: string | null
  mitre_tactics: string[]
  mitre_techniques: string[]
  tags: string[]
  executive_summary: string | null
  lessons_learned: string | null
  root_cause: string | null
  false_positive: boolean
  sla_minutes: number
  sla_breach: boolean
  detected_at: string | null
  triaged_at: string | null
  contained_at: string | null
  eradicated_at: string | null
  recovered_at: string | null
  closed_at: string | null
  mttd_minutes: number | null
  mttc_minutes: number | null
  mttr_minutes: number | null
  forensic_hash: string | null
  created_at: string | null
  updated_at: string | null
}

export interface IncidentLink {
  id: string
  incident_id: string
  entity_type: string
  entity_id: string
  notes: string | null
  added_by: string
  created_at: string | null
}

export interface IncidentTimelineEntry {
  id: string
  incident_id: string
  event_type: string
  actor: string
  detail: Record<string, unknown>
  created_at: string | null
}

export interface IncidentSummary {
  total: number
  open: number
  by_status: Record<string, number>
  by_severity: Record<string, number>
  sla_breach_count: number
  avg_mttd_minutes: number | null
  avg_mttc_minutes: number | null
  avg_mttr_minutes: number | null
  generated_at: string
}

export async function getIncidentSummary(): Promise<IncidentSummary> {
  const { data } = await api.get('/incidents/summary')
  return data
}

export async function listIncidents(params?: {
  status?: string; severity?: string; incident_type?: string
  assigned_to?: string; sla_breach?: boolean; limit?: number; offset?: number
}): Promise<{ items: Incident[]; count: number; limit: number; offset: number }> {
  const { data } = await api.get('/incidents', { params })
  return data
}

export async function createIncident(payload: {
  title: string; incident_type: string; severity: string
  description?: string; assigned_to?: string
  mitre_tactics?: string[]; mitre_techniques?: string[]; tags?: string[]
  risk_score?: number
  linked_entity_type?: string; linked_entity_id?: string; linked_entity_notes?: string
}): Promise<Incident> {
  const { data } = await api.post('/incidents', payload)
  return data
}

export async function getIncident(incidentId: string): Promise<Incident> {
  const { data } = await api.get(`/incidents/${incidentId}`)
  return data
}

export async function transitionIncidentStatus(
  incidentId: string,
  newStatus: string,
): Promise<Incident> {
  const { data } = await api.patch(`/incidents/${incidentId}/status`, { new_status: newStatus })
  return data
}

export async function assignIncident(incidentId: string, assignedTo: string): Promise<Incident> {
  const { data } = await api.patch(`/incidents/${incidentId}/assign`, { assigned_to: assignedTo })
  return data
}

export async function updateIncidentMitre(
  incidentId: string,
  payload: { mitre_tactics?: string[]; mitre_techniques?: string[] },
): Promise<Incident> {
  const { data } = await api.patch(`/incidents/${incidentId}/mitre`, payload)
  return data
}

export async function addIncidentLink(
  incidentId: string,
  payload: { entity_type: string; entity_id: string; notes?: string },
): Promise<IncidentLink> {
  const { data } = await api.post(`/incidents/${incidentId}/links`, payload)
  return data
}

export async function listIncidentLinks(incidentId: string): Promise<{ items: IncidentLink[]; count: number }> {
  const { data } = await api.get(`/incidents/${incidentId}/links`)
  return data
}

export async function removeIncidentLink(incidentId: string, linkId: string): Promise<void> {
  await api.delete(`/incidents/${incidentId}/links/${linkId}`)
}

export async function getIncidentTimeline(
  incidentId: string,
): Promise<{ items: IncidentTimelineEntry[]; count: number }> {
  const { data } = await api.get(`/incidents/${incidentId}/timeline`)
  return data
}

export async function addIncidentNote(incidentId: string, text: string): Promise<IncidentTimelineEntry> {
  const { data } = await api.post(`/incidents/${incidentId}/notes`, { text })
  return data
}

export async function closeIncident(
  incidentId: string,
  payload: { lessons_learned?: string; root_cause?: string; executive_summary?: string; false_positive?: boolean },
): Promise<Incident> {
  const { data } = await api.post(`/incidents/${incidentId}/close`, payload)
  return data
}

export async function dismissIncident(incidentId: string, reason?: string): Promise<Incident> {
  const { data } = await api.post(`/incidents/${incidentId}/dismiss`, { reason })
  return data
}

export async function getPiilBinding(
  incidentId: string,
  limit = 50,
): Promise<{ incident_id: string; items: ForensicEntry[]; count: number }> {
  const { data } = await api.get(`/incidents/${incidentId}/piil-binding`, { params: { limit } })
  return data
}

export async function getSoarEvents(
  incidentId: string,
  limit = 100,
): Promise<{ incident_id: string; items: IncidentTimelineEntry[]; count: number }> {
  const { data } = await api.get(`/incidents/${incidentId}/soar-events`, { params: { limit } })
  return data
}

// ── Executive Reports / PIIL — P29-B ─────────────────────────────────────────

export interface ExecutiveReport {
  id: string
  report_type: string
  period: string
  title: string
  generated_by: string
  period_start: string
  period_end: string
  total_incidents: number
  closed_incidents: number
  sla_breach_count: number
  campaign_count: number
  avg_mttd_minutes: number | null
  avg_mttc_minutes: number | null
  avg_mttr_minutes: number | null
  hash_sha3_512: string
  signature_ed25519: string
  pubkey_fingerprint: string
  signature_valid: boolean
  last_verified_at: string | null
  created_at: string | null
  canonical_data?: Record<string, unknown>
}

export interface ReportingSummary {
  total_reports: number
  unsigned_reports: number
  by_type: Record<string, number>
  last_generated_at: string | null
  last_report_id: string | null
}

export interface VerifyReportResult {
  report_id: string
  hash_valid: boolean
  signature_valid: boolean
  overall_valid: boolean
  pubkey_fingerprint: string
  verified_at: string
}

export async function getReportingSummary(): Promise<ReportingSummary> {
  const { data } = await api.get('/reports/executive/summary')
  return data
}

export async function listExecutiveReports(params?: {
  report_type?: string; limit?: number; offset?: number
}): Promise<{ items: ExecutiveReport[]; count: number; limit: number; offset: number }> {
  const { data } = await api.get('/reports/executive', { params })
  return data
}

export async function generateExecutiveReport(payload: {
  report_type: string
  period: string
  period_start: string
  period_end: string
  title?: string
}): Promise<ExecutiveReport> {
  const { data } = await api.post('/reports/executive/generate', payload)
  return data
}

export async function getExecutiveReport(reportId: string): Promise<ExecutiveReport> {
  const { data } = await api.get(`/reports/executive/${reportId}`)
  return data
}

export async function verifyExecutiveReport(reportId: string): Promise<VerifyReportResult> {
  const { data } = await api.post(`/reports/executive/${reportId}/verify`)
  return data
}

export async function deleteExecutiveReport(reportId: string): Promise<void> {
  await api.delete(`/reports/executive/${reportId}`)
}
