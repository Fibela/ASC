/**
 * Unit tests — useAuthGuard hook (src/lib/auth-guard.tsx)
 *
 * Tests: redirect when unauthenticated, redirect by role mismatch,
 * isReady flag behavior, FOUC prevention invariant.
 *
 * Uses renderHook from @testing-library/react and mocks next/navigation.
 */

jest.mock('@/lib/api', () => ({
  api: {
    defaults: { headers: { common: {} } },
    post: jest.fn(),
    interceptors: { response: { use: jest.fn() } },
  },
}))

const mockReplace = jest.fn()

jest.mock('next/navigation', () => ({
  useRouter: () => ({ replace: mockReplace }),
}))

jest.mock('@/lib/auth', () => ({
  initAuth:        jest.fn(),
  isAuthenticated: jest.fn(),
  getRole:         jest.fn(),
}))

import { renderHook, act } from '@testing-library/react'
import { useAuthGuard } from '@/lib/auth-guard'
import { isAuthenticated, getRole } from '@/lib/auth'

const mockIsAuth = isAuthenticated as jest.Mock
const mockGetRole = getRole as jest.Mock

beforeEach(() => {
  jest.clearAllMocks()
  localStorage.clear()
})

// ─── No auth → redirect /login ────────────────────────────────────────────────

describe('useAuthGuard — unauthenticated', () => {
  it('redirects to /login when not authenticated', async () => {
    mockIsAuth.mockReturnValue(false)
    renderHook(() => useAuthGuard())
    await act(async () => {})
    expect(mockReplace).toHaveBeenCalledWith('/login')
  })

  it('isReady remains false when not authenticated', async () => {
    mockIsAuth.mockReturnValue(false)
    const { result } = renderHook(() => useAuthGuard())
    await act(async () => {})
    expect(result.current.isReady).toBe(false)
  })

  it('does not redirect to /login when authenticated', async () => {
    mockIsAuth.mockReturnValue(true)
    mockGetRole.mockReturnValue('analyst')
    renderHook(() => useAuthGuard())
    await act(async () => {})
    expect(mockReplace).not.toHaveBeenCalledWith('/login')
  })
})

// ─── Authenticated → isReady ──────────────────────────────────────────────────

describe('useAuthGuard — authenticated', () => {
  it('sets isReady to true when authenticated and no role required', async () => {
    mockIsAuth.mockReturnValue(true)
    mockGetRole.mockReturnValue('analyst')
    const { result } = renderHook(() => useAuthGuard())
    await act(async () => {})
    expect(result.current.isReady).toBe(true)
  })

  it('does not call router.replace when authenticated and no role required', async () => {
    mockIsAuth.mockReturnValue(true)
    mockGetRole.mockReturnValue('analyst')
    renderHook(() => useAuthGuard())
    await act(async () => {})
    expect(mockReplace).not.toHaveBeenCalled()
  })
})

// ─── Role-based access ────────────────────────────────────────────────────────

describe('useAuthGuard — role enforcement', () => {
  it('redirects to / when role does not match requiredRole', async () => {
    mockIsAuth.mockReturnValue(true)
    mockGetRole.mockReturnValue('analyst')
    renderHook(() => useAuthGuard('admin'))
    await act(async () => {})
    expect(mockReplace).toHaveBeenCalledWith('/')
  })

  it('isReady is false when role does not match', async () => {
    mockIsAuth.mockReturnValue(true)
    mockGetRole.mockReturnValue('analyst')
    const { result } = renderHook(() => useAuthGuard('admin'))
    await act(async () => {})
    expect(result.current.isReady).toBe(false)
  })

  it('sets isReady when role matches requiredRole', async () => {
    mockIsAuth.mockReturnValue(true)
    mockGetRole.mockReturnValue('admin')
    const { result } = renderHook(() => useAuthGuard('admin'))
    await act(async () => {})
    expect(result.current.isReady).toBe(true)
  })

  it('does not redirect when role matches requiredRole', async () => {
    mockIsAuth.mockReturnValue(true)
    mockGetRole.mockReturnValue('admin')
    renderHook(() => useAuthGuard('admin'))
    await act(async () => {})
    expect(mockReplace).not.toHaveBeenCalled()
  })
})

// ─── FOUC prevention invariant ────────────────────────────────────────────────

describe('useAuthGuard — FOUC prevention', () => {
  it('hook source initialises isReady with useState(false)', () => {
    // RTL runs effects synchronously so we verify the initial value in source
    const src = require('fs').readFileSync(
      require('path').resolve(__dirname, '../lib/auth-guard.tsx'), 'utf8'
    )
    expect(src).toMatch(/useState\s*\(\s*false\s*\)/)
  })

  it('isReady is true after auth passes (authenticated user sees content)', async () => {
    mockIsAuth.mockReturnValue(true)
    const { result } = renderHook(() => useAuthGuard())
    await act(async () => {})
    expect(result.current.isReady).toBe(true)
  })
})
