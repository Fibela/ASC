/**
 * Unit tests — Pure logic from app/status/page.tsx
 * All functions mirrored inline — no imports from page files.
 * Covers: status color/border/dot mapping, check label, error extraction,
 * overall posture calculation, auto-refresh interval constant, and
 * API type shape invariants for HealthReadiness / HealthSystem.
 */

// ── Mirrored helpers (from status/page.tsx) ────────────────────────────────

type FetchStatus = 'loading' | 'ok' | 'error'

function statusColor(status: FetchStatus): string {
  switch (status) {
    case 'ok':    return 'text-green-400'
    case 'error': return 'text-red-400'
    default:      return 'text-yellow-400'
  }
}

function statusBorderColor(status: FetchStatus): string {
  switch (status) {
    case 'ok':    return 'border-green-400/30'
    case 'error': return 'border-red-400/30'
    default:      return 'border-yellow-400/30'
  }
}

function statusDot(status: FetchStatus): string {
  switch (status) {
    case 'ok':    return 'bg-green-400'
    case 'error': return 'bg-red-400'
    default:      return 'bg-yellow-400 animate-pulse'
  }
}

function checkStatusLabel(ready: { status: string }): string {
  return ready.status === 'ready' ? 'Listo' : 'Degradado'
}

function extractErrorMsg(err: unknown): string {
  return (
    (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
    (err as Error)?.message ??
    'Sin conexión'
  )
}

function overallStatus(
  liveness: FetchStatus,
  readiness: FetchStatus,
  systemInfo: FetchStatus,
): FetchStatus {
  if (liveness === 'ok' && readiness === 'ok' && systemInfo === 'ok') return 'ok'
  if (liveness === 'error' || readiness === 'error' || systemInfo === 'error') return 'error'
  return 'loading'
}

const AUTO_REFRESH_MS = 30_000

// ─────────────────────────────────────────────────────────────────────────────

describe('statusColor — text class mapping', () => {
  it('maps ok to green', () => {
    expect(statusColor('ok')).toBe('text-green-400')
  })

  it('maps error to red', () => {
    expect(statusColor('error')).toBe('text-red-400')
  })

  it('maps loading to yellow', () => {
    expect(statusColor('loading')).toBe('text-yellow-400')
  })
})

describe('statusBorderColor — border class mapping', () => {
  it('maps ok to green border', () => {
    expect(statusBorderColor('ok')).toBe('border-green-400/30')
  })

  it('maps error to red border', () => {
    expect(statusBorderColor('error')).toBe('border-red-400/30')
  })

  it('maps loading to yellow border', () => {
    expect(statusBorderColor('loading')).toBe('border-yellow-400/30')
  })
})

describe('statusDot — dot class mapping', () => {
  it('ok dot is solid green', () => {
    expect(statusDot('ok')).toBe('bg-green-400')
  })

  it('error dot is solid red', () => {
    expect(statusDot('error')).toBe('bg-red-400')
  })

  it('loading dot is animated yellow', () => {
    const cls = statusDot('loading')
    expect(cls).toContain('bg-yellow-400')
    expect(cls).toContain('animate-pulse')
  })
})

describe('checkStatusLabel — readiness label', () => {
  it('returns "Listo" when status is ready', () => {
    expect(checkStatusLabel({ status: 'ready' })).toBe('Listo')
  })

  it('returns "Degradado" when status is degraded', () => {
    expect(checkStatusLabel({ status: 'degraded' })).toBe('Degradado')
  })

  it('returns "Degradado" for any non-ready status', () => {
    expect(checkStatusLabel({ status: 'error' })).toBe('Degradado')
    expect(checkStatusLabel({ status: '' })).toBe('Degradado')
  })
})

describe('extractErrorMsg — error message extraction', () => {
  it('extracts response.data.detail', () => {
    const err = { response: { data: { detail: 'DB unreachable' } } }
    expect(extractErrorMsg(err)).toBe('DB unreachable')
  })

  it('falls back to err.message', () => {
    expect(extractErrorMsg(new Error('timeout'))).toBe('timeout')
  })

  it('falls back to "Sin conexión" for empty object', () => {
    expect(extractErrorMsg({})).toBe('Sin conexión')
  })

  it('falls back to "Sin conexión" for null', () => {
    expect(extractErrorMsg(null)).toBe('Sin conexión')
  })
})

describe('overallStatus — composite posture', () => {
  it('returns ok when all three are ok', () => {
    expect(overallStatus('ok', 'ok', 'ok')).toBe('ok')
  })

  it('returns error when liveness is error', () => {
    expect(overallStatus('error', 'ok', 'ok')).toBe('error')
  })

  it('returns error when readiness is error', () => {
    expect(overallStatus('ok', 'error', 'ok')).toBe('error')
  })

  it('returns error when systemInfo is error', () => {
    expect(overallStatus('ok', 'ok', 'error')).toBe('error')
  })

  it('returns error when multiple are error', () => {
    expect(overallStatus('error', 'error', 'error')).toBe('error')
  })

  it('returns loading when any is loading and none is error', () => {
    expect(overallStatus('loading', 'ok', 'ok')).toBe('loading')
    expect(overallStatus('ok', 'loading', 'ok')).toBe('loading')
    expect(overallStatus('loading', 'loading', 'loading')).toBe('loading')
  })

  it('error takes priority over loading', () => {
    expect(overallStatus('loading', 'error', 'ok')).toBe('error')
  })
})

describe('AUTO_REFRESH_MS — constant value', () => {
  it('is exactly 30 seconds in milliseconds', () => {
    expect(AUTO_REFRESH_MS).toBe(30_000)
  })

  it('is greater than zero', () => {
    expect(AUTO_REFRESH_MS).toBeGreaterThan(0)
  })
})

describe('HealthReadiness — data shape invariants', () => {
  it('ready state has checks.database with ok and detail fields', () => {
    const readiness = {
      status: 'ready' as const,
      checks: {
        database: { ok: true, detail: 'ok' },
      },
      ts: new Date().toISOString(),
    }
    expect(readiness.checks.database.ok).toBe(true)
    expect(readiness.checks.database.detail).toBe('ok')
  })

  it('degraded state has checks.database.ok = false', () => {
    const readiness = {
      status: 'degraded' as const,
      checks: {
        database: { ok: false, detail: 'Connection refused' },
      },
      ts: new Date().toISOString(),
    }
    expect(readiness.status).toBe('degraded')
    expect(readiness.checks.database.ok).toBe(false)
    expect(readiness.checks.database.detail).not.toBe('ok')
  })
})

describe('HealthSystem — data shape invariants', () => {
  it('has all required fields', () => {
    const sys = {
      app: 'ASC PremosCorp',
      version: '1.0.0',
      environment: 'production' as const,
      uptime_seconds: 3600,
      uptime_human: '1h 0s',
      ts: new Date().toISOString(),
    }
    expect(sys.app).toBeTruthy()
    expect(sys.version).toBeTruthy()
    expect(['production', 'development']).toContain(sys.environment)
    expect(sys.uptime_seconds).toBeGreaterThanOrEqual(0)
    expect(sys.uptime_human).toBeTruthy()
  })
})
