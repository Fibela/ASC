/**
 * Unit tests — SSO callback flow (src/app/sso/page.tsx logic)
 *
 * Tests the token persistence, SSO origin marking, and axios header wiring
 * that happen when a user lands on /sso?token=<jwt>&role=<role>.
 *
 * Security invariants verified:
 * - Token stored under correct localStorage key
 * - Role stored correctly
 * - SSO origin flag set (enables re-auth redirect on token expiry)
 * - No raw token exposed beyond localStorage
 */

jest.mock('@/lib/api', () => ({
  api: {
    defaults: { headers: { common: {} } },
    post: jest.fn(),
    interceptors: { response: { use: jest.fn() } },
  },
}))

import {
  markSSOSession,
  getSSOOrigin,
  clearTokens,
  getAccessToken,
  getRole,
} from '@/lib/auth'

const FAKE_TOKEN = 'eyJ.fake.asc.jwt.token'
const FAKE_ROLE  = 'analyst'

beforeEach(() => {
  localStorage.clear()
  const { api } = require('@/lib/api')
  api.defaults.headers.common = {}
})

// ─── markSSOSession ───────────────────────────────────────────────────────────

describe('markSSOSession', () => {
  it('stores premoscorp origin flag in localStorage', () => {
    markSSOSession('premoscorp')
    expect(localStorage.getItem('asc_sso_origin')).toBe('premoscorp')
  })

  it('getSSOOrigin returns null before markSSOSession', () => {
    expect(getSSOOrigin()).toBeNull()
  })

  it('getSSOOrigin returns premoscorp after markSSOSession', () => {
    markSSOSession('premoscorp')
    expect(getSSOOrigin()).toBe('premoscorp')
  })
})

// ─── SSO origin cleared on clearTokens ────────────────────────────────────────

describe('clearTokens — SSO origin', () => {
  it('removes asc_sso_origin on clearTokens', () => {
    markSSOSession('premoscorp')
    expect(localStorage.getItem('asc_sso_origin')).toBe('premoscorp')
    clearTokens()
    expect(localStorage.getItem('asc_sso_origin')).toBeNull()
  })

  it('removes all token keys including sso_origin', () => {
    localStorage.setItem('asc_access_token',  FAKE_TOKEN)
    localStorage.setItem('asc_refresh_token', 'some.refresh.token')
    localStorage.setItem('asc_role',          FAKE_ROLE)
    markSSOSession('premoscorp')

    clearTokens()

    expect(localStorage.getItem('asc_access_token')).toBeNull()
    expect(localStorage.getItem('asc_refresh_token')).toBeNull()
    expect(localStorage.getItem('asc_role')).toBeNull()
    expect(localStorage.getItem('asc_sso_origin')).toBeNull()
  })
})

// ─── SSO token storage simulation ────────────────────────────────────────────
// Mirrors what sso/page.tsx does in its useEffect

describe('SSO callback token persistence', () => {
  function simulateSSOCallback(token: string, role: string) {
    localStorage.setItem('asc_access_token', token)
    localStorage.setItem('asc_role', role)
    markSSOSession('premoscorp')
    const { api } = require('@/lib/api')
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`
  }

  it('access token is retrievable via getAccessToken()', () => {
    simulateSSOCallback(FAKE_TOKEN, FAKE_ROLE)
    expect(getAccessToken()).toBe(FAKE_TOKEN)
  })

  it('role is retrievable via getRole()', () => {
    simulateSSOCallback(FAKE_TOKEN, FAKE_ROLE)
    expect(getRole()).toBe(FAKE_ROLE)
  })

  it('SSO origin flag is set to premoscorp', () => {
    simulateSSOCallback(FAKE_TOKEN, FAKE_ROLE)
    expect(getSSOOrigin()).toBe('premoscorp')
  })

  it('axios Authorization header is wired with Bearer token', () => {
    simulateSSOCallback(FAKE_TOKEN, FAKE_ROLE)
    const { api } = require('@/lib/api')
    expect(api.defaults.headers.common['Authorization']).toBe(`Bearer ${FAKE_TOKEN}`)
  })

  it('raw token is not stored in plain text beyond localStorage keys', () => {
    simulateSSOCallback(FAKE_TOKEN, FAKE_ROLE)
    // Only allowed storage keys
    const allowedKeys = ['asc_access_token', 'asc_refresh_token', 'asc_role', 'asc_sso_origin']
    const allKeys = Object.keys(localStorage)
    const extraKeys = allKeys.filter(k => !allowedKeys.includes(k))
    expect(extraKeys).toHaveLength(0)
  })

  it('admin role is stored correctly', () => {
    simulateSSOCallback(FAKE_TOKEN, 'admin')
    expect(getRole()).toBe('admin')
  })
})

// ─── Security invariants ──────────────────────────────────────────────────────

describe('Security invariants — SSO', () => {
  it('SSO origin key contains no sensitive data (only provider name)', () => {
    markSSOSession('premoscorp')
    const origin = localStorage.getItem('asc_sso_origin') ?? ''
    expect(origin).not.toMatch(/eyJ/)              // no JWT fragments
    expect(origin).not.toMatch(/[A-Za-z0-9]{40,}/) // no long tokens
    expect(origin).toBe('premoscorp')
  })

  it('token is not logged or exposed to window properties', () => {
    localStorage.setItem('asc_access_token', FAKE_TOKEN)
    markSSOSession('premoscorp')
    // Ensure token isn't leaked to any window property (XSS vector)
    const w = window as any
    expect(w.asc_token).toBeUndefined()
    expect(w.token).toBeUndefined()
  })
})
