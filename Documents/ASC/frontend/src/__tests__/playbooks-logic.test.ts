/**
 * Unit tests — Playbooks page logic (pure functions, no DOM)
 *
 * Tests:
 * - Semaphore badge color mapping
 * - Status label/color mapping
 * - Risk score formatting
 * - Timestamp formatting
 * - Playbook selector (select_playbook_id) logic mirror
 * - Approval token validation
 * - Step status icon mapping
 * - Trigger payload construction
 * - Pagination logic
 * - Run filter logic
 */

// ─── Semaphore badge colors ───────────────────────────────────────────────────

describe('Playbook semaphore badge color mapping', () => {
  const SEMAPHORE_COLOR: Record<string, string> = {
    green:  'text-green-400 bg-green-400/10 border-green-400/30',
    yellow: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
    red:    'text-red-400 bg-red-400/10 border-red-400/30',
  }

  it('green semaphore uses green color classes', () => {
    expect(SEMAPHORE_COLOR['green']).toContain('text-green-400')
  })

  it('yellow semaphore uses yellow color classes', () => {
    expect(SEMAPHORE_COLOR['yellow']).toContain('text-yellow-400')
  })

  it('red semaphore uses red color classes', () => {
    expect(SEMAPHORE_COLOR['red']).toContain('text-red-400')
  })

  it('unknown semaphore returns undefined (handled by fallback in component)', () => {
    expect(SEMAPHORE_COLOR['purple']).toBeUndefined()
  })
})

// ─── Status label mapping ────────────────────────────────────────────────────

describe('Playbook run status label mapping', () => {
  const STATUS_LABEL: Record<string, string> = {
    pending:           'Pendiente',
    running:           'Ejecutando',
    awaiting_approval: 'Esperando Aprobación',
    completed:         'Completado',
    failed:            'Fallido',
    aborted:           'Abortado',
  }

  it('pending maps to "Pendiente"', () => expect(STATUS_LABEL['pending']).toBe('Pendiente'))
  it('running maps to "Ejecutando"', () => expect(STATUS_LABEL['running']).toBe('Ejecutando'))
  it('awaiting_approval maps to "Esperando Aprobación"', () =>
    expect(STATUS_LABEL['awaiting_approval']).toBe('Esperando Aprobación'))
  it('completed maps to "Completado"', () => expect(STATUS_LABEL['completed']).toBe('Completado'))
  it('failed maps to "Fallido"', () => expect(STATUS_LABEL['failed']).toBe('Fallido'))
  it('aborted maps to "Abortado"', () => expect(STATUS_LABEL['aborted']).toBe('Abortado'))

  it('covers all expected statuses', () => {
    const expected = ['pending', 'running', 'awaiting_approval', 'completed', 'failed', 'aborted']
    expected.forEach(s => expect(STATUS_LABEL[s]).toBeDefined())
  })
})

// ─── Status color mapping ────────────────────────────────────────────────────

describe('Playbook run status color classes', () => {
  const STATUS_COLOR: Record<string, string> = {
    pending:           'text-gray-400',
    running:           'text-cyan-400',
    awaiting_approval: 'text-yellow-400',
    completed:         'text-green-400',
    failed:            'text-red-400',
    aborted:           'text-orange-400',
  }

  it('completed is green', () => expect(STATUS_COLOR['completed']).toBe('text-green-400'))
  it('failed is red', () => expect(STATUS_COLOR['failed']).toBe('text-red-400'))
  it('awaiting_approval is yellow (HitL)', () => expect(STATUS_COLOR['awaiting_approval']).toBe('text-yellow-400'))
  it('running is cyan', () => expect(STATUS_COLOR['running']).toBe('text-cyan-400'))
  it('aborted is orange', () => expect(STATUS_COLOR['aborted']).toBe('text-orange-400'))
})

// ─── Risk score formatting ────────────────────────────────────────────────────

describe('Risk score percentage formatting', () => {
  function fmtRisk(n: number): string {
    return (n * 100).toFixed(0) + '%'
  }

  it('formats 0.85 as "85%"', () => expect(fmtRisk(0.85)).toBe('85%'))
  it('formats 0.0 as "0%"', () => expect(fmtRisk(0.0)).toBe('0%'))
  it('formats 1.0 as "100%"', () => expect(fmtRisk(1.0)).toBe('100%'))
  it('formats 0.401 as "40%"', () => expect(fmtRisk(0.401)).toBe('40%'))
  it('rounds 0.999 to "100%"', () => expect(fmtRisk(0.999)).toBe('100%'))
  it('rounds 0.394 to "39%"', () => expect(fmtRisk(0.394)).toBe('39%'))
})

// ─── Timestamp formatting ─────────────────────────────────────────────────────

describe('Timestamp display formatting', () => {
  function fmtTs(iso: string | null | undefined): string {
    if (!iso) return '—'
    return new Date(iso).toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'medium' })
  }

  it('returns "—" for null', () => expect(fmtTs(null)).toBe('—'))
  it('returns "—" for undefined', () => expect(fmtTs(undefined)).toBe('—'))
  it('returns "—" for empty string', () => expect(fmtTs('')).toBe('—'))
  it('parses valid ISO timestamp', () => {
    const ts = '2026-06-05T12:00:00Z'
    const result = fmtTs(ts)
    expect(result).not.toBe('—')
    expect(typeof result).toBe('string')
    expect(result.length).toBeGreaterThan(5)
  })
  it('includes date and time components', () => {
    const ts = '2026-06-05T15:30:45Z'
    const result = fmtTs(ts)
    // Both date and time parts should be present
    expect(result).toMatch(/\d/)
  })
})

// ─── Playbook selection logic (mirrors backend select_playbook_id) ─────────────

describe('Playbook auto-select logic', () => {
  type Context = {
    risk_score: number
    fingerprint_confidence?: number
  }

  function selectPlaybookId(ctx: Context): string {
    if ((ctx.fingerprint_confidence ?? 0) >= 0.30) return 'PB-004'
    if (ctx.risk_score >= 0.85) return 'PB-003'
    if (ctx.risk_score >= 0.40) return 'PB-002'
    return 'PB-001'
  }

  it('selects PB-001 for risk < 0.40', () => {
    expect(selectPlaybookId({ risk_score: 0.20 })).toBe('PB-001')
  })

  it('selects PB-001 at exactly risk = 0.0', () => {
    expect(selectPlaybookId({ risk_score: 0.0 })).toBe('PB-001')
  })

  it('selects PB-002 at exactly risk = 0.40', () => {
    expect(selectPlaybookId({ risk_score: 0.40 })).toBe('PB-002')
  })

  it('selects PB-002 for risk in [0.40, 0.85)', () => {
    expect(selectPlaybookId({ risk_score: 0.60 })).toBe('PB-002')
    expect(selectPlaybookId({ risk_score: 0.84 })).toBe('PB-002')
  })

  it('selects PB-003 at exactly risk = 0.85', () => {
    expect(selectPlaybookId({ risk_score: 0.85 })).toBe('PB-003')
  })

  it('selects PB-003 for risk >= 0.85 without fingerprint', () => {
    expect(selectPlaybookId({ risk_score: 0.95 })).toBe('PB-003')
    expect(selectPlaybookId({ risk_score: 1.0 })).toBe('PB-003')
  })

  it('selects PB-004 for fingerprint_confidence >= 0.30 regardless of risk', () => {
    expect(selectPlaybookId({ risk_score: 0.10, fingerprint_confidence: 0.30 })).toBe('PB-004')
    expect(selectPlaybookId({ risk_score: 0.95, fingerprint_confidence: 0.80 })).toBe('PB-004')
  })

  it('does not select PB-004 for fingerprint_confidence < 0.30', () => {
    expect(selectPlaybookId({ risk_score: 0.95, fingerprint_confidence: 0.29 })).toBe('PB-003')
  })

  it('does not select PB-004 when fingerprint_confidence absent', () => {
    expect(selectPlaybookId({ risk_score: 0.40 })).toBe('PB-002')
  })

  it('PB-004 takes priority over PB-003 (highest-risk scenario)', () => {
    // Even max risk + max fingerprint → PB-004 wins (targeted > mass response)
    expect(selectPlaybookId({ risk_score: 1.0, fingerprint_confidence: 1.0 })).toBe('PB-004')
  })
})

// ─── Approval token validation ────────────────────────────────────────────────

describe('Approval token UUID validation', () => {
  const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

  function isValidApprovalToken(token: string): boolean {
    return UUID_REGEX.test(token.trim())
  }

  it('accepts a valid lowercase UUID', () => {
    expect(isValidApprovalToken('550e8400-e29b-41d4-a716-446655440000')).toBe(true)
  })

  it('accepts a valid uppercase UUID', () => {
    expect(isValidApprovalToken('550E8400-E29B-41D4-A716-446655440000')).toBe(true)
  })

  it('strips whitespace before validation', () => {
    expect(isValidApprovalToken('  550e8400-e29b-41d4-a716-446655440000  ')).toBe(true)
  })

  it('rejects empty string', () => {
    expect(isValidApprovalToken('')).toBe(false)
  })

  it('rejects non-UUID string', () => {
    expect(isValidApprovalToken('not-a-uuid')).toBe(false)
  })

  it('rejects UUID without dashes', () => {
    expect(isValidApprovalToken('550e8400e29b41d4a716446655440000')).toBe(false)
  })

  it('rejects too-short UUID', () => {
    expect(isValidApprovalToken('550e8400-e29b-41d4')).toBe(false)
  })
})

// ─── Cannable run actions (abort/approve conditions) ─────────────────────────

describe('Run action availability conditions', () => {
  type RunStatus = 'pending' | 'running' | 'awaiting_approval' | 'completed' | 'failed' | 'aborted'

  function canApprove(status: RunStatus): boolean {
    return status === 'awaiting_approval'
  }

  function canAbort(status: RunStatus): boolean {
    return status === 'pending' || status === 'awaiting_approval'
  }

  it('only awaiting_approval can be approved', () => {
    expect(canApprove('awaiting_approval')).toBe(true)
    expect(canApprove('pending')).toBe(false)
    expect(canApprove('running')).toBe(false)
    expect(canApprove('completed')).toBe(false)
    expect(canApprove('failed')).toBe(false)
    expect(canApprove('aborted')).toBe(false)
  })

  it('pending and awaiting_approval can be aborted', () => {
    expect(canAbort('pending')).toBe(true)
    expect(canAbort('awaiting_approval')).toBe(true)
  })

  it('terminal statuses cannot be aborted', () => {
    expect(canAbort('completed')).toBe(false)
    expect(canAbort('failed')).toBe(false)
    expect(canAbort('aborted')).toBe(false)
  })

  it('running cannot be aborted via UI (only pending/awaiting)', () => {
    // Backend may support it but UI restricts to safe states
    expect(canAbort('running')).toBe(false)
  })
})

// ─── Pagination logic ────────────────────────────────────────────────────────

describe('Playbook runs pagination', () => {
  const PAGE_SIZE = 10

  function totalPages(total: number): number {
    return Math.ceil(total / PAGE_SIZE)
  }

  function hasNextPage(page: number, total: number): boolean {
    return (page + 1) * PAGE_SIZE < total
  }

  function hasPrevPage(page: number): boolean {
    return page > 0
  }

  it('0 items = 0 pages', () => expect(totalPages(0)).toBe(0))
  it('1 item = 1 page', () => expect(totalPages(1)).toBe(1))
  it('10 items = 1 page', () => expect(totalPages(10)).toBe(1))
  it('11 items = 2 pages', () => expect(totalPages(11)).toBe(2))
  it('100 items = 10 pages', () => expect(totalPages(100)).toBe(10))
  it('101 items = 11 pages', () => expect(totalPages(101)).toBe(11))

  it('page 0 has no previous', () => expect(hasPrevPage(0)).toBe(false))
  it('page 1 has previous', () => expect(hasPrevPage(1)).toBe(true))

  it('page 0 with 11 items has next', () => expect(hasNextPage(0, 11)).toBe(true))
  it('page 0 with 10 items has no next', () => expect(hasNextPage(0, 10)).toBe(false))
  it('page 1 with 20 items has no next', () => expect(hasNextPage(1, 20)).toBe(false))
  it('page 1 with 21 items has next', () => expect(hasNextPage(1, 21)).toBe(true))
})

// ─── Trigger payload construction ────────────────────────────────────────────

describe('Trigger payload construction', () => {
  interface TriggerPayload {
    playbook_id: string
    semaphore: string
    risk_score: number
    host?: string
    dst_ip?: string
    dst_domain?: string
    process_name?: string
  }

  function buildTriggerPayload(
    pbId: string,
    semaphore: string,
    risk: string,
    host: string,
    dstIp: string,
    dstDomain: string,
    process: string
  ): TriggerPayload {
    return {
      playbook_id:  pbId,
      semaphore,
      risk_score:   parseFloat(risk),
      host:         host || undefined,
      dst_ip:       dstIp || undefined,
      dst_domain:   dstDomain || undefined,
      process_name: process || undefined,
    }
  }

  it('builds minimal payload with required fields only', () => {
    const p = buildTriggerPayload('PB-001', 'green', '0.25', '', '', '', '')
    expect(p.playbook_id).toBe('PB-001')
    expect(p.semaphore).toBe('green')
    expect(p.risk_score).toBe(0.25)
    expect(p.host).toBeUndefined()
    expect(p.dst_ip).toBeUndefined()
  })

  it('includes optional fields when provided', () => {
    const p = buildTriggerPayload('PB-003', 'red', '0.90', 'PREMOS-WS-01', '10.0.0.1', 'evil.com', 'malware.exe')
    expect(p.host).toBe('PREMOS-WS-01')
    expect(p.dst_ip).toBe('10.0.0.1')
    expect(p.dst_domain).toBe('evil.com')
    expect(p.process_name).toBe('malware.exe')
  })

  it('converts risk string to float', () => {
    const p = buildTriggerPayload('PB-002', 'yellow', '0.62', '', '', '', '')
    expect(typeof p.risk_score).toBe('number')
    expect(p.risk_score).toBeCloseTo(0.62)
  })

  it('handles risk with trailing zeros', () => {
    const p = buildTriggerPayload('PB-001', 'green', '0.400', '', '', '', '')
    expect(p.risk_score).toBe(0.4)
  })

  it('empty string host becomes undefined (not sent to API)', () => {
    // '' is falsy → host || undefined → undefined
    const p = buildTriggerPayload('PB-001', 'green', '0.10', '', '', '', '')
    expect(p.host).toBeUndefined()
  })

  it('whitespace-only host is truthy and passes through (trimming is the component responsibility)', () => {
    const p = buildTriggerPayload('PB-001', 'green', '0.10', '  ', '', '', '')
    expect(p.host).toBe('  ')
  })
})

// ─── Step status display mapping ─────────────────────────────────────────────

describe('Step status display', () => {
  type StepStatus = 'ok' | 'awaiting_approval' | 'warning' | 'error'

  const iconCls: Record<StepStatus, string> = {
    ok:               'text-green-400',
    awaiting_approval: 'text-yellow-400',
    warning:          'text-orange-400',
    error:            'text-red-400',
  }

  it('ok steps are green', () => expect(iconCls['ok']).toBe('text-green-400'))
  it('awaiting_approval steps are yellow', () => expect(iconCls['awaiting_approval']).toBe('text-yellow-400'))
  it('warning steps are orange', () => expect(iconCls['warning']).toBe('text-orange-400'))
  it('error steps are red', () => expect(iconCls['error']).toBe('text-red-400'))

  it('all step statuses have a defined color', () => {
    const statuses: StepStatus[] = ['ok', 'awaiting_approval', 'warning', 'error']
    statuses.forEach(s => expect(iconCls[s]).toBeDefined())
  })
})
