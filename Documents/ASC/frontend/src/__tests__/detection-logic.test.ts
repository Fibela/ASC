/**
 * Unit tests — Detection page logic (pure functions, no DOM)
 * Tests JSON parsing validation, hex validation, fingerprint confidence.
 */

// ─── JSON event parsing ───────────────────────────────────────────────────────

describe('Detection event JSON parsing', () => {
  function parseEventJson(raw: string): { ok: boolean; data?: object; error?: string } {
    try {
      const parsed = JSON.parse(raw)
      if (typeof parsed !== 'object' || Array.isArray(parsed)) {
        return { ok: false, error: 'Expected a JSON object' }
      }
      return { ok: true, data: parsed }
    } catch (e: any) {
      return { ok: false, error: e.message }
    }
  }

  it('parses valid ECS event JSON', () => {
    const raw = JSON.stringify({ host: 'PREMOS-WS-01', process: 'acord32.exe', args: '/s /o' })
    const result = parseEventJson(raw)
    expect(result.ok).toBe(true)
    expect((result.data as any).host).toBe('PREMOS-WS-01')
  })

  it('returns error for invalid JSON', () => {
    const result = parseEventJson('{broken json}')
    expect(result.ok).toBe(false)
    expect(result.error).toBeDefined()
  })

  it('returns error for JSON array', () => {
    const result = parseEventJson('[1, 2, 3]')
    expect(result.ok).toBe(false)
    expect(result.error).toBe('Expected a JSON object')
  })

  it('returns error for JSON string', () => {
    const result = parseEventJson('"just a string"')
    expect(result.ok).toBe(false)
  })

  it('parses empty object', () => {
    const result = parseEventJson('{}')
    expect(result.ok).toBe(true)
  })

  it('preserves nested objects', () => {
    const raw = JSON.stringify({ evidence: { pid: 1234, host: 'H1' } })
    const result = parseEventJson(raw)
    expect(result.ok).toBe(true)
    expect((result.data as any).evidence.pid).toBe(1234)
  })
})

// ─── Hex string validation ────────────────────────────────────────────────────

describe('Fingerprint hex validation', () => {
  function validateHex(hex: string): { ok: boolean; error?: string; bytes?: number } {
    const cleaned = hex.replace(/\s+/g, '')
    if (cleaned.length === 0) {
      return { ok: false, error: 'Hex string is empty' }
    }
    if (cleaned.length % 2 !== 0) {
      return { ok: false, error: 'Hex string has odd length — incomplete byte' }
    }
    if (!/^[0-9a-fA-F]+$/.test(cleaned)) {
      return { ok: false, error: 'Invalid hex characters' }
    }
    if (cleaned.length > 131072) {
      return { ok: false, error: 'Exceeds 64KB limit' }
    }
    return { ok: true, bytes: cleaned.length / 2 }
  }

  it('validates a proper hex string', () => {
    const result = validateHex('deadbeef')
    expect(result.ok).toBe(true)
    expect(result.bytes).toBe(4)
  })

  it('validates uppercase hex', () => {
    expect(validateHex('DEADBEEF').ok).toBe(true)
  })

  it('validates mixed case hex', () => {
    expect(validateHex('DeAdBeEf').ok).toBe(true)
  })

  it('strips whitespace before validation', () => {
    expect(validateHex('de ad be ef').ok).toBe(true)
  })

  it('rejects odd-length hex', () => {
    const result = validateHex('abc')
    expect(result.ok).toBe(false)
    expect(result.error).toContain('odd length')
  })

  it('rejects invalid hex characters', () => {
    // 'xyzw' is 4 chars (even length) so the odd-length check passes,
    // then the invalid-character check fires.
    const result = validateHex('xyzw')
    expect(result.ok).toBe(false)
    expect(result.error).toContain('Invalid hex')
  })

  it('rejects empty string', () => {
    expect(validateHex('').ok).toBe(false)
  })

  it('rejects hex exceeding 64KB', () => {
    const huge = 'ab'.repeat(65537)   // 65537 bytes = 131074 hex chars
    const result = validateHex(huge)
    expect(result.ok).toBe(false)
    expect(result.error).toContain('64KB')
  })

  it('accepts exactly 64KB', () => {
    const max = 'ab'.repeat(65536)    // 65536 bytes = 131072 hex chars (limit)
    const result = validateHex(max)
    expect(result.ok).toBe(true)
    expect(result.bytes).toBe(65536)
  })
})

// ─── Semaphore mapping logic ──────────────────────────────────────────────────

describe('Semaphore posture mapping', () => {
  // Replicates the POSTURE_TO_LEVEL logic in Semaphore.tsx
  function postureToLevel(posture: string): string {
    const map: Record<string, string> = {
      NORMAL: 'green', LOW: 'green',
      ELEVATED: 'yellow', MEDIUM: 'yellow',
      HIGH: 'red', CRITICAL: 'red',
    }
    return map[posture?.toUpperCase()] ?? 'green'
  }

  it('maps NORMAL to green', () => expect(postureToLevel('NORMAL')).toBe('green'))
  it('maps LOW to green',    () => expect(postureToLevel('LOW')).toBe('green'))
  it('maps ELEVATED to yellow', () => expect(postureToLevel('ELEVATED')).toBe('yellow'))
  it('maps MEDIUM to yellow',   () => expect(postureToLevel('MEDIUM')).toBe('yellow'))
  it('maps HIGH to red',        () => expect(postureToLevel('HIGH')).toBe('red'))
  it('maps CRITICAL to red',    () => expect(postureToLevel('CRITICAL')).toBe('red'))
  it('defaults unknown posture to green', () => expect(postureToLevel('UNKNOWN_XYZ')).toBe('green'))
  it('is case insensitive', () => expect(postureToLevel('critical')).toBe('red'))
})

// ─── Detection result semaphore conversion ────────────────────────────────────

describe('Detection semaphore to posture conversion', () => {
  // Replicates the logic used in detection page to convert API semaphore → posture prop
  function semaphoreToPosture(sem: string): string {
    if (sem === 'red')    return 'CRITICAL'
    if (sem === 'yellow') return 'ELEVATED'
    return 'NORMAL'
  }

  it('converts red to CRITICAL', () => expect(semaphoreToPosture('red')).toBe('CRITICAL'))
  it('converts yellow to ELEVATED', () => expect(semaphoreToPosture('yellow')).toBe('ELEVATED'))
  it('converts green to NORMAL',  () => expect(semaphoreToPosture('green')).toBe('NORMAL'))
  it('defaults unknown to NORMAL', () => expect(semaphoreToPosture('blue')).toBe('NORMAL'))
})

// ─── IoC type color mapping ───────────────────────────────────────────────────

describe('IoC type color mapping', () => {
  const TYPE_COLOR: Record<string, string> = {
    hash_md5:     'text-gray-400',
    hash_sha1:    'text-gray-400',
    hash_sha256:  'text-gray-400',
    ip:           'text-orange-400',
    domain:       'text-yellow-400',
    url:          'text-yellow-400',
    mutex:        'text-red-400',
    registry_key: 'text-red-400',
  }

  it('hashes are gray', () => {
    expect(TYPE_COLOR['hash_sha256']).toBe('text-gray-400')
    expect(TYPE_COLOR['hash_md5']).toBe('text-gray-400')
  })

  it('IPs are orange (elevated risk)', () => {
    expect(TYPE_COLOR['ip']).toBe('text-orange-400')
  })

  it('domains and URLs are yellow', () => {
    expect(TYPE_COLOR['domain']).toBe('text-yellow-400')
    expect(TYPE_COLOR['url']).toBe('text-yellow-400')
  })

  it('mutexes and registry keys are red (high risk)', () => {
    expect(TYPE_COLOR['mutex']).toBe('text-red-400')
    expect(TYPE_COLOR['registry_key']).toBe('text-red-400')
  })
})
