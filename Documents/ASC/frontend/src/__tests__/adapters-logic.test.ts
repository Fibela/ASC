/**
 * Unit tests — Pure logic extracted from app/adapters/page.tsx
 * All functions are replicated inline here — no imports from page files.
 * Covers: TYPE_STYLE mapping, ADAPTER_TABS config, NumInput min enforcement,
 * callOp error extraction, testConnection message building, button guards,
 * and OpResult shape invariants.
 */

// ── Mirrored constants (from adapters/page.tsx) ────────────────────────────

const TYPE_STYLE: Record<string, string> = {
  SIEM:       'text-blue-400   bg-blue-400/10   border-blue-400/30',
  'EDR/HIDS': 'text-orange-400 bg-orange-400/10 border-orange-400/30',
  SOAR:       'text-purple-400 bg-purple-400/10 border-purple-400/30',
}

const ADAPTER_TABS: { id: string; label: string }[] = [
  { id: 'elk',     label: 'ELK / Elasticsearch' },
  { id: 'wazuh',   label: 'Wazuh'               },
  { id: 'thehive', label: 'TheHive'              },
]

// ── Mirrored helper logic (from adapters/page.tsx) ─────────────────────────

function resolveTypeCls(type: string): string {
  return TYPE_STYLE[type] ?? 'text-gray-400 bg-gray-400/10 border-gray-400/30'
}

function enforceMin(raw: string, min: number): number {
  return Math.max(min, Number(raw))
}

function extractCallOpErrorDetail(err: unknown): string {
  return (
    (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
    (err as Error)?.message ??
    'Error desconocido'
  )
}

function buildLatencyMsg(latency: number | undefined): string {
  return latency !== undefined ? `OK · ${latency}ms` : 'OK'
}

function buildConnectionErrorMsg(err: unknown): string {
  const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
  return detail ?? 'Sin conexión'
}

function isEmptyId(id: string): boolean {
  return !id.trim()
}

// ─────────────────────────────────────────────────────────────────────────────

describe('TYPE_STYLE — adapter type color mapping', () => {
  it('maps SIEM to blue-400 styles', () => {
    const cls = resolveTypeCls('SIEM')
    expect(cls).toContain('blue-400')
    expect(cls).toContain('text-blue-400')
  })

  it('maps EDR/HIDS to orange-400 styles', () => {
    const cls = resolveTypeCls('EDR/HIDS')
    expect(cls).toContain('orange-400')
    expect(cls).toContain('text-orange-400')
  })

  it('maps SOAR to purple-400 styles', () => {
    const cls = resolveTypeCls('SOAR')
    expect(cls).toContain('purple-400')
    expect(cls).toContain('text-purple-400')
  })

  it('falls back to gray-400 for unknown type', () => {
    const cls = resolveTypeCls('UNKNOWN_TYPE')
    expect(cls).toContain('gray-400')
    expect(cls).toContain('text-gray-400')
  })

  it('falls back to gray-400 for empty string', () => {
    const cls = resolveTypeCls('')
    expect(cls).toContain('gray-400')
  })

  it('covers exactly 3 known adapter types', () => {
    expect(Object.keys(TYPE_STYLE)).toHaveLength(3)
  })

  it('includes all three adapter type keys', () => {
    expect(TYPE_STYLE).toHaveProperty('SIEM')
    expect(TYPE_STYLE).toHaveProperty('EDR/HIDS')
    expect(TYPE_STYLE).toHaveProperty('SOAR')
  })

  it('each type has background opacity variant', () => {
    Object.values(TYPE_STYLE).forEach(cls => {
      expect(cls).toMatch(/bg-\w+-400\/10/)
    })
  })

  it('each type has border opacity variant', () => {
    Object.values(TYPE_STYLE).forEach(cls => {
      expect(cls).toMatch(/border-\w+-400\/30/)
    })
  })
})

describe('ADAPTER_TABS — tab configuration', () => {
  it('has exactly 3 tabs', () => {
    expect(ADAPTER_TABS).toHaveLength(3)
  })

  it('elk is first tab with correct label', () => {
    expect(ADAPTER_TABS[0].id).toBe('elk')
    expect(ADAPTER_TABS[0].label).toBe('ELK / Elasticsearch')
  })

  it('wazuh is second tab with correct label', () => {
    expect(ADAPTER_TABS[1].id).toBe('wazuh')
    expect(ADAPTER_TABS[1].label).toBe('Wazuh')
  })

  it('thehive is third tab with correct label', () => {
    expect(ADAPTER_TABS[2].id).toBe('thehive')
    expect(ADAPTER_TABS[2].label).toBe('TheHive')
  })

  it('all tab IDs are unique', () => {
    const ids = ADAPTER_TABS.map(t => t.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('all tabs have non-empty labels', () => {
    ADAPTER_TABS.forEach(tab => {
      expect(tab.label.trim().length).toBeGreaterThan(0)
    })
  })
})

describe('NumInput — min value enforcement', () => {
  it('returns raw value when above minimum', () => {
    expect(enforceMin('10', 1)).toBe(10)
    expect(enforceMin('100', 1)).toBe(100)
    expect(enforceMin('5', 5)).toBe(5)
  })

  it('clamps to min when value is below minimum', () => {
    expect(enforceMin('0', 1)).toBe(1)
    expect(enforceMin('-10', 1)).toBe(1)
    expect(enforceMin('3', 5)).toBe(5)
  })

  it('returns min when value equals minimum', () => {
    expect(enforceMin('1', 1)).toBe(1)
    expect(enforceMin('50', 50)).toBe(50)
  })

  it('empty string is treated as 0, clamped to min', () => {
    // Number('') === 0, so Math.max(1, 0) === 1
    expect(enforceMin('', 1)).toBe(1)
    expect(enforceMin('', 5)).toBe(5)
  })

  it('non-numeric string produces NaN which propagates through Math.max', () => {
    // Math.max(1, NaN) === NaN — the component receives numeric input from <input type="number">
    expect(isNaN(enforceMin('abc', 1))).toBe(true)
  })

  it('uses default min of 1 concept: value 0 is clamped to 1', () => {
    expect(enforceMin('0', 1)).toBe(1)
  })

  it('floating point values are accepted', () => {
    expect(enforceMin('1.5', 1)).toBe(1.5)
    expect(enforceMin('0.5', 1)).toBe(1)
  })
})

describe('callOp — error detail extraction', () => {
  it('extracts response.data.detail (axios error)', () => {
    const err = { response: { data: { detail: 'ELK cluster unreachable' } } }
    expect(extractCallOpErrorDetail(err)).toBe('ELK cluster unreachable')
  })

  it('falls back to err.message when no response.data.detail', () => {
    const err = new Error('Network timeout')
    expect(extractCallOpErrorDetail(err)).toBe('Network timeout')
  })

  it('falls back to "Error desconocido" for empty object', () => {
    expect(extractCallOpErrorDetail({})).toBe('Error desconocido')
  })

  it('falls back to "Error desconocido" for null', () => {
    expect(extractCallOpErrorDetail(null)).toBe('Error desconocido')
  })

  it('falls back to "Error desconocido" for undefined', () => {
    expect(extractCallOpErrorDetail(undefined)).toBe('Error desconocido')
  })

  it('prefers response.data.detail over err.message', () => {
    const err = {
      response: { data: { detail: 'Backend error' } },
      message: 'Request failed',
    }
    expect(extractCallOpErrorDetail(err)).toBe('Backend error')
  })

  it('handles nested null response gracefully', () => {
    const err = { response: { data: null } }
    expect(extractCallOpErrorDetail(err)).toBe('Error desconocido')
  })
})

describe('testConnection — latency message building', () => {
  it('formats "OK · Nms" when latency_ms is provided', () => {
    expect(buildLatencyMsg(42)).toBe('OK · 42ms')
    expect(buildLatencyMsg(150)).toBe('OK · 150ms')
    expect(buildLatencyMsg(1)).toBe('OK · 1ms')
  })

  it('uses exactly 0 as latency when latency_ms is 0', () => {
    expect(buildLatencyMsg(0)).toBe('OK · 0ms')
  })

  it('returns plain "OK" when latency_ms is undefined', () => {
    expect(buildLatencyMsg(undefined)).toBe('OK')
  })

  it('does not show undefined in the message', () => {
    expect(buildLatencyMsg(undefined)).not.toContain('undefined')
  })
})

describe('testConnection — error message building', () => {
  it('extracts response.data.detail', () => {
    const err = { response: { data: { detail: 'Wazuh token expired' } } }
    expect(buildConnectionErrorMsg(err)).toBe('Wazuh token expired')
  })

  it('falls back to "Sin conexión" for plain Error', () => {
    expect(buildConnectionErrorMsg(new Error('ECONNREFUSED'))).toBe('Sin conexión')
  })

  it('falls back to "Sin conexión" for empty object', () => {
    expect(buildConnectionErrorMsg({})).toBe('Sin conexión')
  })

  it('falls back to "Sin conexión" for null', () => {
    expect(buildConnectionErrorMsg(null)).toBe('Sin conexión')
  })

  it('falls back to "Sin conexión" when response has no detail', () => {
    const err = { response: { data: {} } }
    expect(buildConnectionErrorMsg(err)).toBe('Sin conexión')
  })
})

describe('Button disabled guard — empty ID validation', () => {
  it('returns true for empty string (button disabled)', () => {
    expect(isEmptyId('')).toBe(true)
  })

  it('returns true for whitespace-only (button disabled)', () => {
    expect(isEmptyId('   ')).toBe(true)
    expect(isEmptyId('\t')).toBe(true)
    expect(isEmptyId('\n')).toBe(true)
  })

  it('returns false for valid non-empty ID (button enabled)', () => {
    expect(isEmptyId('uuid-1234-5678')).toBe(false)
  })

  it('returns false for ID with surrounding spaces (trim allows it)', () => {
    expect(isEmptyId('  some-id  ')).toBe(false)
  })

  it('returns false for single character ID', () => {
    expect(isEmptyId('a')).toBe(false)
  })
})

describe('OpResult — shape invariants', () => {
  it('successful result has ok=true and data payload', () => {
    const data = { indexed: true, document_id: 'doc-001' }
    const result = {
      op: 'elk_push_alert',
      ts: new Date().toISOString(),
      ok: true,
      data,
    }
    expect(result.ok).toBe(true)
    expect(result.op).toBe('elk_push_alert')
    expect(result.data).toEqual({ indexed: true, document_id: 'doc-001' })
    expect(result.ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)
  })

  it('failed result has ok=false and error wrapped in data', () => {
    const errorMsg = 'ELK cluster unreachable'
    const result = {
      op: 'elk_push_alert',
      ts: new Date().toISOString(),
      ok: false,
      data: { error: errorMsg },
    }
    expect(result.ok).toBe(false)
    expect(result.data).toEqual({ error: 'ELK cluster unreachable' })
  })

  it('ts is a valid ISO 8601 timestamp', () => {
    const ts = new Date().toISOString()
    const result = { op: 'test_op', ts, ok: true, data: {} }
    expect(new Date(result.ts).getTime()).not.toBeNaN()
  })

  it('op name matches the operation key convention', () => {
    const ops = [
      'elk_push_alert',
      'elk_push_event',
      'elk_pull_events',
      'wazuh_pull_alerts',
      'wazuh_get_agents',
      'thehive_create_case',
      'thehive_add_observable',
      'thehive_get_case',
    ]
    ops.forEach(op => {
      expect(op).toMatch(/^[a-z][a-z0-9_]+$/)
    })
  })
})

describe('ConfigBadge — configured state logic', () => {
  function configuredLabel(configured: boolean): string {
    return configured ? 'Configurado' : 'No configurado'
  }

  function configuredColor(configured: boolean): string {
    return configured ? 'text-green-400' : 'text-gray-500'
  }

  it('shows "Configurado" when configured is true', () => {
    expect(configuredLabel(true)).toBe('Configurado')
  })

  it('shows "No configurado" when configured is false', () => {
    expect(configuredLabel(false)).toBe('No configurado')
  })

  it('uses green color for configured state', () => {
    expect(configuredColor(true)).toBe('text-green-400')
  })

  it('uses gray color for not-configured state', () => {
    expect(configuredColor(false)).toBe('text-gray-500')
  })
})
