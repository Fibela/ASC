import { api } from './api'

const ACCESS_KEY     = 'asc_access_token'
const REFRESH_KEY    = 'asc_refresh_token'
const ROLE_KEY       = 'asc_role'
const SSO_ORIGIN_KEY = 'asc_sso_origin'

export interface AuthTokens {
  access_token:  string
  refresh_token: string
  token_type:    string
  expires_in:    number
  role:          string
}

// --- Storage ---
export function saveTokens(tokens: AuthTokens) {
  localStorage.setItem(ACCESS_KEY,  tokens.access_token)
  localStorage.setItem(REFRESH_KEY, tokens.refresh_token)
  localStorage.setItem(ROLE_KEY,    tokens.role)
  api.defaults.headers.common['Authorization'] = `Bearer ${tokens.access_token}`
}

export function clearTokens() {
  localStorage.removeItem(ACCESS_KEY)
  localStorage.removeItem(REFRESH_KEY)
  localStorage.removeItem(ROLE_KEY)
  localStorage.removeItem(SSO_ORIGIN_KEY)
  delete api.defaults.headers.common['Authorization']
}

/** Mark the current session as originated from an SSO provider.
 *  Used by the /sso callback page to enable transparent re-auth on expiry. */
export function markSSOSession(origin: 'premoscorp') {
  localStorage.setItem(SSO_ORIGIN_KEY, origin)
}

export function getSSOOrigin(): string | null {
  return localStorage.getItem(SSO_ORIGIN_KEY)
}

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_KEY)
}

export function getRole(): string | null {
  return localStorage.getItem(ROLE_KEY)
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
  const refresh_token = localStorage.getItem(REFRESH_KEY)

  if (!refresh_token) {
    // SSO sessions carry no refresh_token — redirect to portal for seamless re-auth
    // instead of dropping the user on /login with no context.
    const ssoOrigin = typeof window !== 'undefined' ? localStorage.getItem(SSO_ORIGIN_KEY) : null
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
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)
