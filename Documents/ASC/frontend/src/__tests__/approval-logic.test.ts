/**
 * P16.1 Human-in-the-Loop — Frontend pure-function unit tests
 * Tests every exported helper from src/app/neutralize/page.tsx
 */

import {
  statusColor,
  statusLabel,
  severityColor,
  requiresApproval,
  minutesRemaining,
  formatTs,
} from '../app/neutralize/page'

// ── statusColor ───────────────────────────────────────────────────────────────

describe('statusColor', () => {
  test('pending_approval → yellow', () => {
    expect(statusColor('pending_approval')).toBe('text-yellow-400')
  })

  test('completed → green', () => {
    expect(statusColor('completed')).toBe('text-green-400')
  })

  test('failed → red', () => {
    expect(statusColor('failed')).toBe('text-red-400')
  })

  test('rejected → gray', () => {
    expect(statusColor('rejected')).toBe('text-gray-400')
  })

  test('escalated → orange', () => {
    expect(statusColor('escalated')).toBe('text-orange-400')
  })

  test('approved → blue', () => {
    expect(statusColor('approved')).toBe('text-blue-400')
  })

  test('executing → blue-300', () => {
    expect(statusColor('executing')).toBe('text-blue-300')
  })

  test('unknown status → fallback gray', () => {
    expect(statusColor('whatever')).toBe('text-gray-400')
  })
})

// ── statusLabel ───────────────────────────────────────────────────────────────

describe('statusLabel', () => {
  test('pending_approval → español', () => {
    expect(statusLabel('pending_approval')).toBe('Pendiente Aprobación')
  })

  test('rejected → Rechazada', () => {
    expect(statusLabel('rejected')).toBe('Rechazada')
  })

  test('escalated → Escalada', () => {
    expect(statusLabel('escalated')).toBe('Escalada')
  })

  test('completed → Completada', () => {
    expect(statusLabel('completed')).toBe('Completada')
  })

  test('unknown → raw value', () => {
    expect(statusLabel('some_state')).toBe('some_state')
  })
})

// ── severityColor ─────────────────────────────────────────────────────────────

describe('severityColor', () => {
  test('critical → red classes', () => {
    expect(severityColor('critical')).toContain('red-400')
  })

  test('high → orange classes', () => {
    expect(severityColor('high')).toContain('orange-400')
  })

  test('medium → yellow classes', () => {
    expect(severityColor('medium')).toContain('yellow-400')
  })

  test('low → gray classes', () => {
    expect(severityColor('low')).toContain('gray-400')
  })

  test('unknown → fallback gray classes', () => {
    expect(severityColor('cosmic')).toContain('gray-400')
  })
})

// ── requiresApproval ──────────────────────────────────────────────────────────

describe('requiresApproval', () => {
  test('critical + block_ip → true', () => {
    expect(requiresApproval('block_ip', 'critical')).toBe(true)
  })

  test('high + block_domain → true', () => {
    expect(requiresApproval('block_domain', 'high')).toBe(true)
  })

  test('medium + block_domain → false', () => {
    expect(requiresApproval('block_domain', 'medium')).toBe(false)
  })

  test('low + block_ip → false', () => {
    expect(requiresApproval('block_ip', 'low')).toBe(false)
  })

  test('isolate_endpoint + low → true (always approve)', () => {
    expect(requiresApproval('isolate_endpoint', 'low')).toBe(true)
  })

  test('isolate_endpoint + medium → true (always approve)', () => {
    expect(requiresApproval('isolate_endpoint', 'medium')).toBe(true)
  })

  test('disable_account + low → true (always approve)', () => {
    expect(requiresApproval('disable_account', 'low')).toBe(true)
  })

  test('disable_account + medium → true (always approve)', () => {
    expect(requiresApproval('disable_account', 'medium')).toBe(true)
  })

  test('kill_process + medium → false', () => {
    expect(requiresApproval('kill_process', 'medium')).toBe(false)
  })

  test('quarantine_file + critical → true', () => {
    expect(requiresApproval('quarantine_file', 'critical')).toBe(true)
  })
})

// ── minutesRemaining ──────────────────────────────────────────────────────────

describe('minutesRemaining', () => {
  test('null → 0', () => {
    expect(minutesRemaining(null)).toBe(0)
  })

  test('past timestamp → 0 (floor at 0)', () => {
    const past = new Date(Date.now() - 60_000).toISOString()
    expect(minutesRemaining(past)).toBe(0)
  })

  test('30 minutes in the future → approximately 30', () => {
    const future = new Date(Date.now() + 30 * 60_000).toISOString()
    const result = minutesRemaining(future)
    expect(result).toBeGreaterThanOrEqual(29)
    expect(result).toBeLessThanOrEqual(30)
  })

  test('15 minutes in the future → approximately 15', () => {
    const future = new Date(Date.now() + 15 * 60_000).toISOString()
    const result = minutesRemaining(future)
    expect(result).toBeGreaterThanOrEqual(14)
    expect(result).toBeLessThanOrEqual(15)
  })

  test('1 minute remaining → 1 or 0', () => {
    const future = new Date(Date.now() + 90_000).toISOString()
    const result = minutesRemaining(future)
    expect(result).toBeGreaterThanOrEqual(1)
    expect(result).toBeLessThanOrEqual(1)
  })
})

// ── formatTs ──────────────────────────────────────────────────────────────────

describe('formatTs', () => {
  test('null → em-dash', () => {
    expect(formatTs(null)).toBe('—')
  })

  test('undefined → em-dash', () => {
    expect(formatTs(undefined)).toBe('—')
  })

  test('empty string → em-dash', () => {
    expect(formatTs('')).toBe('—')
  })

  test('ISO string → YYYY-MM-DD HH:MM', () => {
    expect(formatTs('2026-06-09T14:35:00Z')).toBe('2026-06-09 14:35')
  })

  test('ISO string with millis → truncated correctly', () => {
    expect(formatTs('2026-06-09T08:00:59.999Z')).toBe('2026-06-09 08:00')
  })

  test('strips seconds and sub-second precision', () => {
    const result = formatTs('2026-01-15T23:59:45.123456Z')
    expect(result).toBe('2026-01-15 23:59')
  })
})
