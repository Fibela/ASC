/**
 * Unit tests — auth.ts utilities
 * Tests token storage helpers in isolation using localStorage mock.
 */

// Mock the api module so initAuth/saveTokens don't try to set axios headers
jest.mock('@/lib/api', () => ({
  api: {
    defaults: { headers: { common: {} } },
    post: jest.fn(),
    interceptors: { response: { use: jest.fn() } },
  },
}))

import {
  saveTokens,
  clearTokens,
  getAccessToken,
  getRole,
  isAuthenticated,
  initAuth,
} from '@/lib/auth'

const MOCK_TOKENS = {
  access_token:  'eyJaccess.fake.token',
  refresh_token: 'eyJrefresh.fake.token',
  token_type:    'bearer',
  expires_in:    28800,
  role:          'analyst',
}

beforeEach(() => {
  localStorage.clear()
  // Reset axios header mock
  const { api } = require('@/lib/api')
  api.defaults.headers.common = {}
})

// ─── saveTokens ───────────────────────────────────────────────────────────────

describe('saveTokens', () => {
  it('stores access_token in localStorage', () => {
    saveTokens(MOCK_TOKENS)
    expect(localStorage.getItem('asc_access_token')).toBe('eyJaccess.fake.token')
  })

  it('stores refresh_token in localStorage', () => {
    saveTokens(MOCK_TOKENS)
    expect(localStorage.getItem('asc_refresh_token')).toBe('eyJrefresh.fake.token')
  })

  it('stores role in localStorage', () => {
    saveTokens(MOCK_TOKENS)
    expect(localStorage.getItem('asc_role')).toBe('analyst')
  })

  it('sets Authorization header on api instance', () => {
    const { api } = require('@/lib/api')
    saveTokens(MOCK_TOKENS)
    expect(api.defaults.headers.common['Authorization']).toBe('Bearer eyJaccess.fake.token')
  })
})

// ─── clearTokens ──────────────────────────────────────────────────────────────

describe('clearTokens', () => {
  it('removes all token keys from localStorage', () => {
    saveTokens(MOCK_TOKENS)
    clearTokens()
    expect(localStorage.getItem('asc_access_token')).toBeNull()
    expect(localStorage.getItem('asc_refresh_token')).toBeNull()
    expect(localStorage.getItem('asc_role')).toBeNull()
  })

  it('removes Authorization header', () => {
    const { api } = require('@/lib/api')
    saveTokens(MOCK_TOKENS)
    clearTokens()
    expect(api.defaults.headers.common['Authorization']).toBeUndefined()
  })
})

// ─── getAccessToken ───────────────────────────────────────────────────────────

describe('getAccessToken', () => {
  it('returns null when no token stored', () => {
    expect(getAccessToken()).toBeNull()
  })

  it('returns token after saveTokens', () => {
    saveTokens(MOCK_TOKENS)
    expect(getAccessToken()).toBe('eyJaccess.fake.token')
  })
})

// ─── getRole ──────────────────────────────────────────────────────────────────

describe('getRole', () => {
  it('returns null when no role stored', () => {
    expect(getRole()).toBeNull()
  })

  it('returns role after saveTokens', () => {
    saveTokens(MOCK_TOKENS)
    expect(getRole()).toBe('analyst')
  })

  it('returns admin when admin token saved', () => {
    saveTokens({ ...MOCK_TOKENS, role: 'admin' })
    expect(getRole()).toBe('admin')
  })
})

// ─── isAuthenticated ──────────────────────────────────────────────────────────

describe('isAuthenticated', () => {
  it('returns false when no token', () => {
    expect(isAuthenticated()).toBe(false)
  })

  it('returns true when token exists', () => {
    saveTokens(MOCK_TOKENS)
    expect(isAuthenticated()).toBe(true)
  })

  it('returns false after clearTokens', () => {
    saveTokens(MOCK_TOKENS)
    clearTokens()
    expect(isAuthenticated()).toBe(false)
  })
})

// ─── initAuth ─────────────────────────────────────────────────────────────────

describe('initAuth', () => {
  it('sets Authorization header if token exists in localStorage', () => {
    localStorage.setItem('asc_access_token', 'already.stored.token')
    const { api } = require('@/lib/api')
    api.defaults.headers.common = {}
    initAuth()
    expect(api.defaults.headers.common['Authorization']).toBe('Bearer already.stored.token')
  })

  it('does not set header if no token', () => {
    const { api } = require('@/lib/api')
    api.defaults.headers.common = {}
    initAuth()
    expect(api.defaults.headers.common['Authorization']).toBeUndefined()
  })
})
