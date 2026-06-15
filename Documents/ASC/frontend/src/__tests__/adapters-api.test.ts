/**
 * Unit tests — Adapter API functions in lib/api.ts
 * Verifies each function calls the correct HTTP method, URL, body, and params.
 * Uses jest.spyOn on the exported `api` axios instance to intercept calls.
 */

import {
  api,
  listAdapters,
  testAdapterStatus,
  elkPushAlert,
  elkPushEvent,
  elkPullEvents,
  wazuhPullAlerts,
  wazuhGetAgents,
  thehiveCreateCase,
  thehiveAddObservable,
  thehiveGetCase,
  firewallBlockIP,
  firewallUnblockIP,
  firewallBlockDomain,
  firewallUnblockDomain,
  identityDisableAccount,
  identityEnableAccount,
  identityForcePasswordReset,
  identityQuarantineAccount,
} from '@/lib/api'

describe('Adapter API — listAdapters()', () => {
  let getSpy: jest.SpyInstance

  beforeEach(() => {
    getSpy = jest.spyOn(api, 'get').mockResolvedValue({ data: {} })
  })

  afterEach(() => jest.restoreAllMocks())

  it('calls GET /adapters/', async () => {
    const payload = {
      adapters: [
        { name: 'elk', label: 'ELK / Elasticsearch', type: 'SIEM', configured: true, description: 'SIEM adapter' },
      ],
    }
    getSpy.mockResolvedValueOnce({ data: payload })
    const result = await listAdapters()
    expect(getSpy).toHaveBeenCalledWith('/adapters/')
    expect(result).toEqual(payload)
  })

  it('returns the data payload directly (no nesting)', async () => {
    const payload = { adapters: [] }
    getSpy.mockResolvedValueOnce({ data: payload })
    const result = await listAdapters()
    expect(result).toHaveProperty('adapters')
    expect(Array.isArray(result.adapters)).toBe(true)
  })
})

describe('Adapter API — testAdapterStatus()', () => {
  let getSpy: jest.SpyInstance

  beforeEach(() => {
    getSpy = jest.spyOn(api, 'get').mockResolvedValue({ data: {} })
  })

  afterEach(() => jest.restoreAllMocks())

  it('calls GET /adapters/elk/status', async () => {
    getSpy.mockResolvedValueOnce({ data: { ok: true, latency_ms: 42 } })
    const result = await testAdapterStatus('elk')
    expect(getSpy).toHaveBeenCalledWith('/adapters/elk/status')
    expect(result).toEqual({ ok: true, latency_ms: 42 })
  })

  it('interpolates adapter name correctly for wazuh', async () => {
    getSpy.mockResolvedValueOnce({ data: { ok: true } })
    await testAdapterStatus('wazuh')
    expect(getSpy).toHaveBeenCalledWith('/adapters/wazuh/status')
  })

  it('interpolates adapter name correctly for thehive', async () => {
    getSpy.mockResolvedValueOnce({ data: { ok: false } })
    await testAdapterStatus('thehive')
    expect(getSpy).toHaveBeenCalledWith('/adapters/thehive/status')
  })
})

describe('Adapter API — elkPushAlert()', () => {
  let postSpy: jest.SpyInstance

  beforeEach(() => {
    postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} })
  })

  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/elk/push/alert/<alertId>', async () => {
    postSpy.mockResolvedValueOnce({ data: { indexed: true, document_id: 'doc-001' } })
    const result = await elkPushAlert('alert-uuid-123')
    expect(postSpy).toHaveBeenCalledWith('/adapters/elk/push/alert/alert-uuid-123')
    expect(result).toEqual({ indexed: true, document_id: 'doc-001' })
  })

  it('interpolates alert ID in URL path, not body', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await elkPushAlert('abc-def-ghi')
    const [url] = postSpy.mock.calls[0]
    expect(url).toBe('/adapters/elk/push/alert/abc-def-ghi')
    expect(postSpy.mock.calls[0]).toHaveLength(1)
  })
})

describe('Adapter API — elkPushEvent()', () => {
  let postSpy: jest.SpyInstance

  beforeEach(() => {
    postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} })
  })

  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/elk/push/event/<eventId>', async () => {
    postSpy.mockResolvedValueOnce({ data: { indexed: true } })
    const result = await elkPushEvent('event-uuid-456')
    expect(postSpy).toHaveBeenCalledWith('/adapters/elk/push/event/event-uuid-456')
    expect(result).toEqual({ indexed: true })
  })

  it('interpolates event ID in URL path', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await elkPushEvent('ev-789')
    const [url] = postSpy.mock.calls[0]
    expect(url).toContain('ev-789')
    expect(url).toContain('/adapters/elk/push/event/')
  })
})

describe('Adapter API — elkPullEvents()', () => {
  let postSpy: jest.SpyInstance

  beforeEach(() => {
    postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} })
  })

  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/elk/pull/events with since_hours and size body', async () => {
    postSpy.mockResolvedValueOnce({ data: { imported: 5, events: [] } })
    const result = await elkPullEvents(2, 50)
    expect(postSpy).toHaveBeenCalledWith('/adapters/elk/pull/events', { since_hours: 2, size: 50 })
    expect(result).toEqual({ imported: 5, events: [] })
  })

  it('maps sinceHours → since_hours and size → size in body', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await elkPullEvents(24, 1000)
    const [, body] = postSpy.mock.calls[0]
    expect(body).toEqual({ since_hours: 24, size: 1000 })
  })

  it('does not send size as since_hours (field names are correct)', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await elkPullEvents(6, 200)
    const [, body] = postSpy.mock.calls[0]
    expect(body.since_hours).toBe(6)
    expect(body.size).toBe(200)
  })
})

describe('Adapter API — wazuhPullAlerts()', () => {
  let postSpy: jest.SpyInstance

  beforeEach(() => {
    postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} })
  })

  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/wazuh/pull/alerts with since_hours and limit body', async () => {
    postSpy.mockResolvedValueOnce({ data: { imported: 12, alerts: [] } })
    const result = await wazuhPullAlerts(1, 100)
    expect(postSpy).toHaveBeenCalledWith('/adapters/wazuh/pull/alerts', { since_hours: 1, limit: 100 })
    expect(result).toEqual({ imported: 12, alerts: [] })
  })

  it('uses limit (not size) as field name in body', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await wazuhPullAlerts(3, 50)
    const [, body] = postSpy.mock.calls[0]
    expect(body).toHaveProperty('limit', 50)
    expect(body).not.toHaveProperty('size')
  })
})

describe('Adapter API — wazuhGetAgents()', () => {
  let getSpy: jest.SpyInstance

  beforeEach(() => {
    getSpy = jest.spyOn(api, 'get').mockResolvedValue({ data: {} })
  })

  afterEach(() => jest.restoreAllMocks())

  it('calls GET /adapters/wazuh/agents with default status=active', async () => {
    getSpy.mockResolvedValueOnce({ data: { agents: [], total: 0 } })
    const result = await wazuhGetAgents()
    expect(getSpy).toHaveBeenCalledWith('/adapters/wazuh/agents', { params: { status: 'active' } })
    expect(result).toEqual({ agents: [], total: 0 })
  })

  it('passes custom status param', async () => {
    getSpy.mockResolvedValueOnce({ data: { agents: [] } })
    await wazuhGetAgents('disconnected')
    expect(getSpy).toHaveBeenCalledWith('/adapters/wazuh/agents', { params: { status: 'disconnected' } })
  })

  it('passes status as query param, not body', async () => {
    getSpy.mockResolvedValueOnce({ data: {} })
    await wazuhGetAgents('pending')
    const [, config] = getSpy.mock.calls[0]
    expect(config).toEqual({ params: { status: 'pending' } })
  })
})

describe('Adapter API — thehiveCreateCase()', () => {
  let postSpy: jest.SpyInstance

  beforeEach(() => {
    postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} })
  })

  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/thehive/cases with alert_id in body', async () => {
    postSpy.mockResolvedValueOnce({ data: { case_id: 'C-042', thehive_id: '~123456' } })
    const result = await thehiveCreateCase('alert-abc')
    expect(postSpy).toHaveBeenCalledWith('/adapters/thehive/cases', { alert_id: 'alert-abc' })
    expect(result).toEqual({ case_id: 'C-042', thehive_id: '~123456' })
  })

  it('sends alert_id (not alertId) in body', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await thehiveCreateCase('some-uuid')
    const [, body] = postSpy.mock.calls[0]
    expect(body).toHaveProperty('alert_id', 'some-uuid')
    expect(body).not.toHaveProperty('alertId')
  })
})

describe('Adapter API — thehiveAddObservable()', () => {
  let postSpy: jest.SpyInstance

  beforeEach(() => {
    postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} })
  })

  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/thehive/cases/<caseId>/observables with ioc_id as query param', async () => {
    postSpy.mockResolvedValueOnce({ data: { added: true, observable_id: 'obs-001' } })
    const result = await thehiveAddObservable('C-001', 'ioc-xyz')
    expect(postSpy).toHaveBeenCalledWith(
      '/adapters/thehive/cases/C-001/observables',
      null,
      { params: { ioc_id: 'ioc-xyz' } },
    )
    expect(result).toEqual({ added: true, observable_id: 'obs-001' })
  })

  it('sends null as body (not the ioc_id)', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await thehiveAddObservable('C-002', 'ioc-999')
    const [, body] = postSpy.mock.calls[0]
    expect(body).toBeNull()
  })

  it('sends ioc_id as query param, not in body', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await thehiveAddObservable('C-003', 'ioc-abc')
    const [, body, config] = postSpy.mock.calls[0]
    expect(body).toBeNull()
    expect(config).toEqual({ params: { ioc_id: 'ioc-abc' } })
  })

  it('interpolates caseId in URL path', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await thehiveAddObservable('C-999', 'ioc-x')
    const [url] = postSpy.mock.calls[0]
    expect(url).toBe('/adapters/thehive/cases/C-999/observables')
  })
})

describe('Adapter API — thehiveGetCase()', () => {
  let getSpy: jest.SpyInstance

  beforeEach(() => {
    getSpy = jest.spyOn(api, 'get').mockResolvedValue({ data: {} })
  })

  afterEach(() => jest.restoreAllMocks())

  it('calls GET /adapters/thehive/cases/<caseId>', async () => {
    getSpy.mockResolvedValueOnce({ data: { id: 'C-001', status: 'open', title: 'Suspicious Activity' } })
    const result = await thehiveGetCase('C-001')
    expect(getSpy).toHaveBeenCalledWith('/adapters/thehive/cases/C-001')
    expect(result).toEqual({ id: 'C-001', status: 'open', title: 'Suspicious Activity' })
  })

  it('interpolates case ID in URL path', async () => {
    getSpy.mockResolvedValueOnce({ data: {} })
    await thehiveGetCase('C-9999')
    const [url] = getSpy.mock.calls[0]
    expect(url).toBe('/adapters/thehive/cases/C-9999')
  })
})

// ─── Firewall API (F2) ────────────────────────────────────────────────────────

describe('Adapter API — firewallBlockIP()', () => {
  let postSpy: jest.SpyInstance
  beforeEach(() => { postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} }) })
  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/firewall/block/ip with ip and reason in body', async () => {
    postSpy.mockResolvedValueOnce({ data: { success: true, committed: true } })
    const result = await firewallBlockIP('192.0.2.1', 'C2 server')
    expect(postSpy).toHaveBeenCalledWith('/adapters/firewall/block/ip', { ip: '192.0.2.1', reason: 'C2 server' })
    expect(result).toEqual({ success: true, committed: true })
  })

  it('defaults reason to empty string when not provided', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await firewallBlockIP('10.0.0.1')
    const [, body] = postSpy.mock.calls[0]
    expect(body).toEqual({ ip: '10.0.0.1', reason: '' })
  })
})

describe('Adapter API — firewallUnblockIP()', () => {
  let postSpy: jest.SpyInstance
  beforeEach(() => { postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} }) })
  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/firewall/unblock/ip with ip in body', async () => {
    postSpy.mockResolvedValueOnce({ data: { success: true } })
    await firewallUnblockIP('192.0.2.1')
    expect(postSpy).toHaveBeenCalledWith('/adapters/firewall/unblock/ip', { ip: '192.0.2.1', reason: '' })
  })

  it('sends ip as body field, not as URL segment', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await firewallUnblockIP('10.0.0.99')
    const [url, body] = postSpy.mock.calls[0]
    expect(url).toBe('/adapters/firewall/unblock/ip')
    expect(body).toHaveProperty('ip', '10.0.0.99')
  })
})

describe('Adapter API — firewallBlockDomain()', () => {
  let postSpy: jest.SpyInstance
  beforeEach(() => { postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} }) })
  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/firewall/block/domain with domain and reason', async () => {
    postSpy.mockResolvedValueOnce({ data: { success: true } })
    const result = await firewallBlockDomain('evil.example.com', 'phishing domain')
    expect(postSpy).toHaveBeenCalledWith('/adapters/firewall/block/domain', { domain: 'evil.example.com', reason: 'phishing domain' })
    expect(result).toEqual({ success: true })
  })

  it('defaults reason to empty string', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await firewallBlockDomain('bad.tld')
    const [, body] = postSpy.mock.calls[0]
    expect(body.reason).toBe('')
  })
})

describe('Adapter API — firewallUnblockDomain()', () => {
  let postSpy: jest.SpyInstance
  beforeEach(() => { postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} }) })
  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/firewall/unblock/domain with domain in body', async () => {
    postSpy.mockResolvedValueOnce({ data: { success: true } })
    await firewallUnblockDomain('evil.example.com')
    expect(postSpy).toHaveBeenCalledWith('/adapters/firewall/unblock/domain', { domain: 'evil.example.com', reason: '' })
  })
})

// ─── Identity API (F2) ────────────────────────────────────────────────────────

describe('Adapter API — identityDisableAccount()', () => {
  let postSpy: jest.SpyInstance
  beforeEach(() => { postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} }) })
  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/identity/disable with username, domain, reason', async () => {
    postSpy.mockResolvedValueOnce({ data: { success: true, username: 'jdoe' } })
    const result = await identityDisableAccount('jdoe', 'corp.local', 'compromised account')
    expect(postSpy).toHaveBeenCalledWith('/adapters/identity/disable', {
      username: 'jdoe',
      domain: 'corp.local',
      reason: 'compromised account',
    })
    expect(result).toEqual({ success: true, username: 'jdoe' })
  })

  it('defaults reason to empty string', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await identityDisableAccount('alice', 'corp.local')
    const [, body] = postSpy.mock.calls[0]
    expect(body.reason).toBe('')
  })

  it('sends username and domain as separate body fields (not concatenated)', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await identityDisableAccount('bob', 'ad.corp')
    const [, body] = postSpy.mock.calls[0]
    expect(body).toHaveProperty('username', 'bob')
    expect(body).toHaveProperty('domain', 'ad.corp')
    expect(body).not.toHaveProperty('user')
  })
})

describe('Adapter API — identityEnableAccount()', () => {
  let postSpy: jest.SpyInstance
  beforeEach(() => { postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} }) })
  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/identity/enable with username and domain', async () => {
    postSpy.mockResolvedValueOnce({ data: { success: true } })
    await identityEnableAccount('jdoe', 'corp.local')
    expect(postSpy).toHaveBeenCalledWith('/adapters/identity/enable', {
      username: 'jdoe',
      domain: 'corp.local',
      reason: '',
    })
  })
})

describe('Adapter API — identityForcePasswordReset()', () => {
  let postSpy: jest.SpyInstance
  beforeEach(() => { postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} }) })
  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/identity/force-reset with username and domain', async () => {
    postSpy.mockResolvedValueOnce({ data: { success: true } })
    await identityForcePasswordReset('jdoe', 'corp.local')
    expect(postSpy).toHaveBeenCalledWith('/adapters/identity/force-reset', {
      username: 'jdoe',
      domain: 'corp.local',
      reason: '',
    })
  })

  it('uses force-reset path (not force_reset or reset)', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await identityForcePasswordReset('alice', 'corp')
    const [url] = postSpy.mock.calls[0]
    expect(url).toBe('/adapters/identity/force-reset')
  })
})

describe('Adapter API — identityQuarantineAccount()', () => {
  let postSpy: jest.SpyInstance
  beforeEach(() => { postSpy = jest.spyOn(api, 'post').mockResolvedValue({ data: {} }) })
  afterEach(() => jest.restoreAllMocks())

  it('calls POST /adapters/identity/quarantine with username and domain', async () => {
    postSpy.mockResolvedValueOnce({ data: { success: true, new_dn: 'OU=Q,DC=corp,DC=local' } })
    const result = await identityQuarantineAccount('jdoe', 'corp.local')
    expect(postSpy).toHaveBeenCalledWith('/adapters/identity/quarantine', {
      username: 'jdoe',
      domain: 'corp.local',
      reason: '',
    })
    expect(result).toEqual({ success: true, new_dn: 'OU=Q,DC=corp,DC=local' })
  })

  it('uses quarantine path (not quarantine-ou or move)', async () => {
    postSpy.mockResolvedValueOnce({ data: {} })
    await identityQuarantineAccount('bob', 'ad.corp')
    const [url] = postSpy.mock.calls[0]
    expect(url).toBe('/adapters/identity/quarantine')
  })
})
