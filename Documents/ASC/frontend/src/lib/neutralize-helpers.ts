import type { DispatchMode } from '@/lib/api'

export function statusColor(status: string): string {
  const map: Record<string, string> = {
    pending_approval: 'text-yellow-400',
    approved:         'text-blue-400',
    executing:        'text-blue-300',
    completed:        'text-green-400',
    failed:           'text-red-400',
    rejected:         'text-gray-400',
    escalated:        'text-orange-400',
  }
  return map[status] ?? 'text-gray-400'
}

export function statusLabel(status: string): string {
  const map: Record<string, string> = {
    pending_approval: 'Pendiente Aprobación',
    approved:         'Aprobada',
    executing:        'Ejecutando',
    completed:        'Completada',
    failed:           'Fallida',
    rejected:         'Rechazada',
    escalated:        'Escalada',
  }
  return map[status] ?? status
}

export function severityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: 'text-red-400 bg-red-400/10 border-red-400/30',
    high:     'text-orange-400 bg-orange-400/10 border-orange-400/30',
    medium:   'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
    low:      'text-gray-400 bg-gray-400/10 border-gray-400/30',
  }
  return map[severity] ?? 'text-gray-400 bg-gray-400/10 border-gray-400/30'
}

export function dispatchModeLabel(mode: DispatchMode | string): string {
  const map: Record<string, string> = {
    specter:    'SPECTER Agente',
    broadcast:  'SPECTER Broadcast',
    simulation: 'Simulación',
  }
  return map[mode] ?? mode
}

export function dispatchModeClasses(mode: DispatchMode | string): string {
  const map: Record<string, string> = {
    specter:    'text-cyan-400 bg-cyan-400/10 border-cyan-400/30',
    broadcast:  'text-purple-400 bg-purple-400/10 border-purple-400/30',
    simulation: 'text-gray-400 bg-gray-400/10 border-gray-400/30',
  }
  return map[mode] ?? 'text-gray-400 bg-gray-400/10 border-gray-400/30'
}

export function commandStatusColor(status: string): string {
  const map: Record<string, string> = {
    pending:   'text-yellow-400',
    delivered: 'text-blue-400',
    executing: 'text-blue-300',
    completed: 'text-green-400',
    failed:    'text-red-400',
    cancelled: 'text-gray-400',
  }
  return map[status] ?? 'text-gray-400'
}

export function requiresApproval(actionType: string, severity: string): boolean {
  const alwaysApprove = new Set(['isolate_endpoint', 'disable_account'])
  const approvalSeverities = new Set(['critical', 'high'])
  return alwaysApprove.has(actionType) || approvalSeverities.has(severity)
}

export function multiSigLabel(received: number, required: number): string {
  if (required <= 1) return ''
  return `${received}/${required} firmas`
}

export function multiSigColor(received: number, required: number): string {
  if (received >= required) return 'text-green-400'
  if (received > 0) return 'text-amber-400'
  return 'text-gray-400'
}

export function rollbackActionLabel(actionType: string): string {
  const map: Record<string, string> = {
    unisolate_endpoint: 'Revertir Aislamiento',
    unblock_ip:         'Desbloquear IP',
    unblock_domain:     'Desbloquear Dominio',
    restore_file:       'Restaurar Archivo',
  }
  return map[actionType] ?? actionType
}

export function minutesRemaining(expiresAt: string | null): number {
  if (!expiresAt) return 0
  const diff = new Date(expiresAt).getTime() - Date.now()
  return Math.max(0, Math.floor(diff / 60000))
}

export function formatTs(ts: string | null | undefined): string {
  if (!ts) return '—'
  return ts.slice(0, 16).replace('T', ' ')
}
