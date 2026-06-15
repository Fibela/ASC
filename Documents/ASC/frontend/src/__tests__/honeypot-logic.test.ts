/**
 * P15 — SPECTER Honeypot Dashboard logic tests.
 *
 * Tests pure functions mirrored from honeypot/page.tsx:
 *
 *   formatTs              (5 tests)  — timestamp formatting
 *   truncateId            (4 tests)  — token ID truncation
 *   severityClasses       (5 tests)  — severity CSS class mapping
 *   accessCountClasses    (5 tests)  — access count CSS color coding
 *   endpointLabel         (4 tests)  — endpoint name display
 *   endpointClasses       (4 tests)  — endpoint CSS class mapping
 *   totalAccesses         (4 tests)  — aggregate access count
 *   uniqueIps             (5 tests)  — unique IP deduplication
 *
 * Total: 36 tests
 */
export {}  // make this a module to avoid global-scope collisions with other test files

// ── Mirror pure helpers from honeypot/page.tsx ────────────────────────────────
// (Mirrors allow testing without needing Next.js/React environment)

interface CanaryAccess {
  ts: string
  client_ip: string
  user_agent: string
  referer: string
}

interface CanaryToken {
  token_id: string
  endpoint: string
  label: string
  created_at: string
  access_count: number
  first_access: string | null
  last_access: string | null
  accesses: CanaryAccess[]
}

function formatTs(ts: string | null | undefined): string {
  if (!ts) return '—'
  try {
    return new Date(ts).toLocaleString()
  } catch {
    return ts
  }
}

function truncateId(id: string, len = 12): string {
  return id.length > len ? `${id.slice(0, len)}…` : id
}

function severityClasses(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical': return 'bg-red-600/20 text-red-400 border border-red-700'
    case 'high':     return 'bg-orange-600/20 text-orange-400 border border-orange-700'
    case 'medium':   return 'bg-yellow-600/20 text-yellow-400 border border-yellow-700'
    case 'low':      return 'bg-green-600/20 text-green-400 border border-green-700'
    default:         return 'bg-gray-700 text-gray-300 border border-gray-600'
  }
}

function accessCountClasses(count: number): string {
  if (count === 0) return 'text-gray-500'
  if (count >= 5)  return 'text-red-400 font-semibold'
  if (count >= 2)  return 'text-orange-400 font-semibold'
  return 'text-yellow-400'
}

function endpointLabel(endpoint: string): string {
  if (endpoint.includes('probe'))  return 'PROBE'
  if (endpoint.includes('dump'))   return 'DUMP'
  if (endpoint.includes('export')) return 'EXPORT'
  return endpoint.toUpperCase()
}

function endpointClasses(endpoint: string): string {
  if (endpoint.includes('probe'))  return 'bg-blue-900/30 text-blue-300 border border-blue-800'
  if (endpoint.includes('dump'))   return 'bg-purple-900/30 text-purple-300 border border-purple-800'
  if (endpoint.includes('export')) return 'bg-red-900/30 text-red-300 border border-red-800'
  return 'bg-gray-800 text-gray-400 border border-gray-700'
}

function totalAccesses(tokens: CanaryToken[]): number {
  return tokens.reduce((sum, t) => sum + t.access_count, 0)
}

function uniqueIps(tokens: CanaryToken[]): number {
  const ips = new Set<string>()
  for (const t of tokens) {
    for (const a of t.accesses) {
      if (a.client_ip) ips.add(a.client_ip)
    }
  }
  return ips.size
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeToken(overrides: Partial<CanaryToken> = {}): CanaryToken {
  return {
    token_id:     'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
    endpoint:     '/agents/probe',
    label:        'probe-diagnostics-link',
    created_at:   '2026-06-08T10:00:00Z',
    access_count: 0,
    first_access: null,
    last_access:  null,
    accesses:     [],
    ...overrides,
  }
}

function makeAccess(ip: string): CanaryAccess {
  return {
    ts:         '2026-06-08T10:05:00Z',
    client_ip:  ip,
    user_agent: 'Mozilla/5.0',
    referer:    '',
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  formatTs
// ══════════════════════════════════════════════════════════════════════════════

describe('formatTs', () => {
  it('returns em-dash for null', () => {
    expect(formatTs(null)).toBe('—')
  })

  it('returns em-dash for undefined', () => {
    expect(formatTs(undefined)).toBe('—')
  })

  it('returns em-dash for empty string', () => {
    expect(formatTs('')).toBe('—')
  })

  it('formats a valid ISO string to a non-empty string', () => {
    const result = formatTs('2026-06-08T12:00:00.000Z')
    expect(typeof result).toBe('string')
    expect(result.length).toBeGreaterThan(0)
    expect(result).not.toBe('—')
  })

  it('does not throw on invalid date string', () => {
    expect(() => formatTs('not-a-date')).not.toThrow()
    expect(typeof formatTs('not-a-date')).toBe('string')
  })
})

// ══════════════════════════════════════════════════════════════════════════════
//  truncateId
// ══════════════════════════════════════════════════════════════════════════════

describe('truncateId', () => {
  it('does not truncate short IDs', () => {
    expect(truncateId('abc123', 12)).toBe('abc123')
  })

  it('truncates long IDs and appends ellipsis', () => {
    const id = 'a1b2c3d4e5f6g7h8'
    const result = truncateId(id, 12)
    expect(result.endsWith('…')).toBe(true)
    expect(result.length).toBe(13) // 12 chars + ellipsis
  })

  it('returns exact length when id equals len', () => {
    const id = 'abcdefghijkl' // exactly 12 chars
    expect(truncateId(id, 12)).toBe('abcdefghijkl')
  })

  it('uses default len=12 when not specified', () => {
    const id = 'a1b2c3d4e5f6a1b2c3d4' // > 12 chars
    const result = truncateId(id)
    expect(result.endsWith('…')).toBe(true)
    expect(result.length).toBe(13)
  })
})

// ══════════════════════════════════════════════════════════════════════════════
//  severityClasses
// ══════════════════════════════════════════════════════════════════════════════

describe('severityClasses', () => {
  it('critical → red classes', () => {
    expect(severityClasses('critical')).toContain('red')
  })

  it('high → orange classes', () => {
    expect(severityClasses('high')).toContain('orange')
  })

  it('medium → yellow classes', () => {
    expect(severityClasses('medium')).toContain('yellow')
  })

  it('low → green classes', () => {
    expect(severityClasses('low')).toContain('green')
  })

  it('unknown → gray classes', () => {
    expect(severityClasses('unknown')).toContain('gray')
  })
})

// ══════════════════════════════════════════════════════════════════════════════
//  accessCountClasses
// ══════════════════════════════════════════════════════════════════════════════

describe('accessCountClasses', () => {
  it('0 accesses → gray (no activity)', () => {
    expect(accessCountClasses(0)).toBe('text-gray-500')
  })

  it('1 access → yellow (first hit)', () => {
    expect(accessCountClasses(1)).toBe('text-yellow-400')
  })

  it('2 accesses → orange semibold (suspicious)', () => {
    expect(accessCountClasses(2)).toContain('orange')
    expect(accessCountClasses(2)).toContain('font-semibold')
  })

  it('4 accesses → orange semibold', () => {
    expect(accessCountClasses(4)).toContain('orange')
  })

  it('5+ accesses → red semibold (critical)', () => {
    expect(accessCountClasses(5)).toContain('red')
    expect(accessCountClasses(5)).toContain('font-semibold')
    expect(accessCountClasses(99)).toContain('red')
  })
})

// ══════════════════════════════════════════════════════════════════════════════
//  endpointLabel
// ══════════════════════════════════════════════════════════════════════════════

describe('endpointLabel', () => {
  it('probe endpoint → PROBE', () => {
    expect(endpointLabel('/agents/probe')).toBe('PROBE')
  })

  it('dump endpoint → DUMP', () => {
    expect(endpointLabel('/agents/dump')).toBe('DUMP')
  })

  it('export endpoint → EXPORT', () => {
    expect(endpointLabel('/agents/export')).toBe('EXPORT')
  })

  it('unknown endpoint → uppercase', () => {
    expect(endpointLabel('/agents/unknown')).toBe('/AGENTS/UNKNOWN')
  })
})

// ══════════════════════════════════════════════════════════════════════════════
//  endpointClasses
// ══════════════════════════════════════════════════════════════════════════════

describe('endpointClasses', () => {
  it('probe endpoint → blue theme', () => {
    expect(endpointClasses('/agents/probe')).toContain('blue')
  })

  it('dump endpoint → purple theme', () => {
    expect(endpointClasses('/agents/dump')).toContain('purple')
  })

  it('export endpoint → red theme', () => {
    expect(endpointClasses('/agents/export')).toContain('red')
  })

  it('unknown endpoint → gray theme', () => {
    expect(endpointClasses('/agents/other')).toContain('gray')
  })
})

// ══════════════════════════════════════════════════════════════════════════════
//  totalAccesses
// ══════════════════════════════════════════════════════════════════════════════

describe('totalAccesses', () => {
  it('returns 0 for empty token list', () => {
    expect(totalAccesses([])).toBe(0)
  })

  it('returns 0 when all tokens have no accesses', () => {
    expect(totalAccesses([makeToken(), makeToken()])).toBe(0)
  })

  it('sums access counts across tokens', () => {
    const tokens = [
      makeToken({ access_count: 3 }),
      makeToken({ access_count: 7 }),
    ]
    expect(totalAccesses(tokens)).toBe(10)
  })

  it('handles single token correctly', () => {
    expect(totalAccesses([makeToken({ access_count: 5 })])).toBe(5)
  })
})

// ══════════════════════════════════════════════════════════════════════════════
//  uniqueIps
// ══════════════════════════════════════════════════════════════════════════════

describe('uniqueIps', () => {
  it('returns 0 for empty token list', () => {
    expect(uniqueIps([])).toBe(0)
  })

  it('returns 0 when tokens have no accesses', () => {
    expect(uniqueIps([makeToken()])).toBe(0)
  })

  it('counts distinct IPs across tokens', () => {
    const tokens = [
      makeToken({ accesses: [makeAccess('1.2.3.4'), makeAccess('5.6.7.8')] }),
      makeToken({ accesses: [makeAccess('9.0.1.2')] }),
    ]
    expect(uniqueIps(tokens)).toBe(3)
  })

  it('deduplicates same IP appearing multiple times', () => {
    const tokens = [
      makeToken({ accesses: [makeAccess('1.2.3.4'), makeAccess('1.2.3.4')] }),
      makeToken({ accesses: [makeAccess('1.2.3.4')] }),
    ]
    expect(uniqueIps(tokens)).toBe(1)
  })

  it('deduplicates same IP across different tokens', () => {
    const tokens = [
      makeToken({ accesses: [makeAccess('10.0.0.1')] }),
      makeToken({ accesses: [makeAccess('10.0.0.1'), makeAccess('10.0.0.2')] }),
    ]
    expect(uniqueIps(tokens)).toBe(2)
  })
})
