import { api } from './api'

const ACCESS_KEY     = 'asc_access_token'
const REFRESH_KEY    = 'asc_refresh_token'
const ROLE_KEY       = 'asc_role'
const SSO_ORIGIN_KEY = 'asc_sso_origin'

// localStorage is only available in the browser; guard all access so this
// module can be imported in server-side code (Next.js SSR/SSG) without crashing.
const ls = typeof window !== 'undefined' ? window.localStorage : null

export interface AuthTokens {
  access_token:  string
  refresh_token: string
  token_type:    string
  expires_in:    number
  role:          string
}

// --- Storage ---
export function saveTokens(tokens: AuthTokens) {
  ls?.setItem(ACCESS_KEY,  tokens.access_token)
  ls?.setItem(REFRESH_KEY, tokens.refresh_token)
  ls?.setItem(ROLE_KEY,    tokens.role)
  api.defaults.headers.common['Authorization'] = `Bearer ${tokens.access_token}`
}

export function clearTokens() {
  ls?.removeItem(ACCESS_KEY)
  ls?.removeItem(REFRESH_KEY)
  ls?.removeItem(ROLE_KEY)
  ls?.removeItem(SSO_ORIGIN_KEY)
  delete api.defaults.headers.common['Authorization']
}

/** Mark the current session as originated from an SSO provider.
 *  Used by the /sso callback page to enable transparent re-auth on expiry. */
export function markSSOSession(origin: 'premoscorp') {
  ls?.setItem(SSO_ORIGIN_KEY, origin)
}

export function getSSOOrigin(): string | null {
  return ls?.getItem(SSO_ORIGIN_KEY) ?? null
}

export function getAccessToken(): string | null {
  return ls?.getItem(ACCESS_KEY) ?? null
}

export function getRole(): string | null {
  return ls?.getItem(ROLE_KEY) ?? null
}

export function isAuthenticated(): boolean {
  return !!getAccessToken()
}

export function initAuth() {
  const token = getAccessToken()
  if (token) {
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`
  }
}

// --- API calls ---
export async function login(email: string, password: string): Promise<AuthTokens> {
  const { data } = await api.post<AuthTokens>('/auth/login', { email, password })
  saveTokens(data)
  return data
}

export async function logout() {
  clearTokens()
  window.location.href = '/login'
}

export async function getMe() {
  const { data } = await api.get('/auth/me')
  return data
}

export async function refreshAccessToken(): Promise<boolean> {
  const refresh_token = ls?.getItem(REFRESH_KEY)

  if (!refresh_token) {
    // SSO sessions carry no refresh_token — redirect to portal for seamless re-auth
    // instead of dropping the user on /login with no context.
    const ssoOrigin = typeof window !== 'undefined' ? ls?.getItem(SSO_ORIGIN_KEY) : null
    if (ssoOrigin === 'premoscorp') {
      const portalUrl = process.env.NEXT_PUBLIC_PORTAL_URL ?? 'https://premoscorp.com'
      clearTokens()
      window.location.href = `${portalUrl}/portal/seguridad`
    }
    return false
  }

  try {
    const { data } = await api.post<AuthTokens>('/auth/refresh', { refresh_token })
    saveTokens(data)
    return true
  } catch {
    clearTokens()
    return false
  }
}

// Axios interceptor: auto-refresh on 401
api.interceptors.response.use(
  res => res,
  async err => {
    const original = err.config
    if (err.response?.status === 401 && !original._retry) {
      original._retry = true
      const ok = await refreshAccessToken()
      if (ok) {
        original.headers['Authorization'] = `Bearer ${getAccessToken()}`
        return api(original)
      }
      window.location.href = '/login?expired=1'
    }
    return Promise.reject(err)
  }
)
