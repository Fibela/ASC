/**
 * P16.2 SPECTER Bridge — Frontend pure-function unit tests
 * Tests every new exported helper from src/app/neutralize/page.tsx
 */

import {
  dispatchModeLabel,
  dispatchModeClasses,
  commandStatusColor,
  requiresApproval,
  statusColor,
  statusLabel,
} from '../lib/neutralize-helpers'

// ── dispatchModeLabel ─────────────────────────────────────────────────────────

describe('dispatchModeLabel', () => {
  test('specter → SPECTER Agente', () => {
    expect(dispatchModeLabel('specter')).toBe('SPECTER Agente')
  })

  test('broadcast → SPECTER Broadcast', () => {
    expect(dispatchModeLabel('broadcast')).toBe('SPECTER Broadcast')
  })

  test('simulation → Simulación', () => {
    expect(dispatchModeLabel('simulation')).toBe('Simulación')
  })

  test('unknown → raw value', () => {
    expect(dispatchModeLabel('quantum')).toBe('quantum')
  })
})

// ── dispatchModeClasses ───────────────────────────────────────────────────────

describe('dispatchModeClasses', () => {
  test('specter → cyan classes', () => {
    expect(dispatchModeClasses('specter')).toContain('cyan-400')
  })

  test('broadcast → purple classes', () => {
    expect(dispatchModeClasses('broadcast')).toContain('purple-400')
  })

  test('simulation → gray classes', () => {
    expect(dispatchModeClasses('simulation')).toContain('gray-400')
  })

  test('unknown → fallback gray', () => {
    expect(dispatchModeClasses('unknown')).toContain('gray-400')
  })
})

// ── commandStatusColor ────────────────────────────────────────────────────────

describe('commandStatusColor', () => {
  test('pending → yellow', () => {
    expect(commandStatusColor('pending')).toBe('text-yellow-400')
  })

  test('delivered → blue', () => {
    expect(commandStatusColor('delivered')).toBe('text-blue-400')
  })

  test('executing → blue-300', () => {
    expect(commandStatusColor('executing')).toBe('text-blue-300')
  })

  test('completed → green', () => {
    expect(commandStatusColor('completed')).toBe('text-green-400')
  })

  test('failed → red', () => {
    expect(commandStatusColor('failed')).toBe('text-red-400')
  })

  test('cancelled → gray', () => {
    expect(commandStatusColor('cancelled')).toBe('text-gray-400')
  })

  test('unknown → fallback gray', () => {
    expect(commandStatusColor('rogue_state')).toBe('text-gray-400')
  })
})

// ── requiresApproval (extended from P16.1) ────────────────────────────────────

describe('requiresApproval — P16.2 action types', () => {
  test('block_domain + medium → false (broadcast but no approval gate)', () => {
    expect(requiresApproval('block_domain', 'medium')).toBe(false)
  })

  test('block_domain + critical → true (critical always requires approval)', () => {
    expect(requiresApproval('block_domain', 'critical')).toBe(true)
  })

  test('remove_persistence + high → true', () => {
    expect(requiresApproval('remove_persistence', 'high')).toBe(true)
  })

  test('remove_persistence + low → false', () => {
    expect(requiresApproval('remove_persistence', 'low')).toBe(false)
  })

  test('quarantine_file + medium → false', () => {
    expect(requiresApproval('quarantine_file', 'medium')).toBe(false)
  })

  test('kill_process + high → true', () => {
    expect(requiresApproval('kill_process', 'high')).toBe(true)
  })

  test('kill_process + low → false', () => {
    expect(requiresApproval('kill_process', 'low')).toBe(false)
  })
})

// ── statusColor + statusLabel (regression — should still work) ────────────────

describe('statusColor regression', () => {
  test('completed still green', () => {
    expect(statusColor('completed')).toBe('text-green-400')
  })

  test('escalated still orange', () => {
    expect(statusColor('escalated')).toBe('text-orange-400')
  })
})

describe('statusLabel regression', () => {
  test('pending_approval still correct', () => {
    expect(statusLabel('pending_approval')).toBe('Pendiente Aprobación')
  })

  test('escalated still correct', () => {
    expect(statusLabel('escalated')).toBe('Escalada')
  })
})
