/**
 * PANL Frontend Helpers — Unit Tests
 * Tests for all exported pure functions added in P16 PANL phase:
 *   multiSigLabel, multiSigColor, rollbackActionLabel
 * Plus regression checks for existing P16.1/P16.2 helpers.
 */

import {
  multiSigLabel,
  multiSigColor,
  rollbackActionLabel,
  statusColor,
  statusLabel,
  severityColor,
  requiresApproval,
  minutesRemaining,
  formatTs,
} from '../app/neutralize/page'

// ── multiSigLabel ─────────────────────────────────────────────────────────────

describe('multiSigLabel', () => {
  test('0/1 → empty string (single-sig, no label needed)', () => {
    expect(multiSigLabel(0, 1)).toBe('')
  })

  test('1/1 → empty string (single-sig complete)', () => {
    expect(multiSigLabel(1, 1)).toBe('')
  })

  test('0/2 → "0/2 firmas"', () => {
    expect(multiSigLabel(0, 2)).toBe('0/2 firmas')
  })

  test('1/2 → "1/2 firmas" (partial)', () => {
    expect(multiSigLabel(1, 2)).toBe('1/2 firmas')
  })

  test('2/2 → "2/2 firmas" (complete)', () => {
    expect(multiSigLabel(2, 2)).toBe('2/2 firmas')
  })

  test('zero required → empty string', () => {
    expect(multiSigLabel(0, 0)).toBe('')
  })
})

// ── multiSigColor ─────────────────────────────────────────────────────────────

describe('multiSigColor', () => {
  test('0/2 → gray (no approvals yet)', () => {
    expect(multiSigColor(0, 2)).toBe('text-gray-400')
  })

  test('1/2 → amber (partial)', () => {
    expect(multiSigColor(1, 2)).toBe('text-amber-400')
  })

  test('2/2 → green (complete)', () => {
    expect(multiSigColor(2, 2)).toBe('text-green-400')
  })

  test('received > required → green (over-approved edge case)', () => {
    expect(multiSigColor(3, 2)).toBe('text-green-400')
  })

  test('1/1 → green (single-sig satisfied)', () => {
    expect(multiSigColor(1, 1)).toBe('text-green-400')
  })
})

// ── rollbackActionLabel ───────────────────────────────────────────────────────

describe('rollbackActionLabel', () => {
  test('unisolate_endpoint', () => {
    expect(rollbackActionLabel('unisolate_endpoint')).toBe('Revertir Aislamiento')
  })

  test('unblock_ip', () => {
    expect(rollbackActionLabel('unblock_ip')).toBe('Desbloquear IP')
  })

  test('unblock_domain', () => {
    expect(rollbackActionLabel('unblock_domain')).toBe('Desbloquear Dominio')
  })

  test('restore_file', () => {
    expect(rollbackActionLabel('restore_file')).toBe('Restaurar Archivo')
  })

  test('unknown action → returns raw string', () => {
    expect(rollbackActionLabel('kill_process')).toBe('kill_process')
  })

  test('empty string → empty string', () => {
    expect(rollbackActionLabel('')).toBe('')
  })
})

// ── requiresApproval — PANL severity coverage ─────────────────────────────────

describe('requiresApproval — PANL scenarios', () => {
  test('critical always requires approval (multi-sig path)', () => {
    expect(requiresApproval('block_ip', 'critical')).toBe(true)
  })

  test('high requires approval', () => {
    expect(requiresApproval('kill_process', 'high')).toBe(true)
  })

  test('medium + non-sensitive does NOT require', () => {
    expect(requiresApproval('block_ip', 'medium')).toBe(false)
  })

  test('low + sensitive always requires (isolate_endpoint)', () => {
    expect(requiresApproval('isolate_endpoint', 'low')).toBe(true)
  })

  test('rollback action type at critical → true', () => {
    // Rollback actions can be submitted at any severity, critical → must approve
    expect(requiresApproval('block_ip', 'critical')).toBe(true)
  })
})

// ── statusColor regression ────────────────────────────────────────────────────

describe('statusColor regression — no PANL regressions', () => {
  test('pending_approval → yellow', () => {
    expect(statusColor('pending_approval')).toBe('text-yellow-400')
  })

  test('escalated → orange', () => {
    expect(statusColor('escalated')).toBe('text-orange-400')
  })

  test('completed → green', () => {
    expect(statusColor('completed')).toBe('text-green-400')
  })

  test('failed → red', () => {
    expect(statusColor('failed')).toBe('text-red-400')
  })
})

// ── statusLabel regression ────────────────────────────────────────────────────

describe('statusLabel regression', () => {
  test('pending_approval', () => {
    expect(statusLabel('pending_approval')).toBe('Pendiente Aprobación')
  })

  test('escalated', () => {
    expect(statusLabel('escalated')).toBe('Escalada')
  })

  test('unknown → raw value', () => {
    expect(statusLabel('unknown_state')).toBe('unknown_state')
  })
})

// ── minutesRemaining ──────────────────────────────────────────────────────────

describe('minutesRemaining', () => {
  test('null → 0', () => {
    expect(minutesRemaining(null)).toBe(0)
  })

  test('future time → positive', () => {
    const future = new Date(Date.now() + 10 * 60 * 1000).toISOString()
    expect(minutesRemaining(future)).toBeGreaterThan(0)
  })

  test('past time → 0', () => {
    const past = new Date(Date.now() - 60 * 1000).toISOString()
    expect(minutesRemaining(past)).toBe(0)
  })
})

// ── formatTs ─────────────────────────────────────────────────────────────────

describe('formatTs', () => {
  test('null → em-dash', () => {
    expect(formatTs(null)).toBe('—')
  })

  test('ISO string → short format', () => {
    expect(formatTs('2024-06-09T14:30:00Z')).toBe('2024-06-09 14:30')
  })
})
