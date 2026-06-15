/**
 * E2E Test Helpers — ASC PremosCorp (P50)
 *
 * Shared utilities for E2E specs:
 * - Mock token constants (clearly labeled as mock/test-only)
 * - Mock API response factories
 * - Auth injection helper (sets localStorage before page load)
 *
 * SECURITY: All tokens here are obviously fake (mock.* prefix).
 * They are NOT valid JWTs and will be rejected by the real backend.
 * Detected by gitleaks allowlist patterns — not real credentials.
 */

import { Page } from '@playwright/test'

// ── Mock auth tokens (clearly fake — not real JWTs) ──────────────────────────

export const MOCK_TOKENS = {
  // Intentionally NOT a real JWT — no eyJ header. Real JWTs are rejected by backend.
  access_token:  'mock-access-token.e2e-test-only.not-a-real-jwt',
  refresh_token: 'mock-refresh-token.e2e-test-only',
  token_type:    'bearer',
  expires_in:    3600,
  role:          'analyst',
}

export const MOCK_TOKENS_ADMIN = {
  ...MOCK_TOKENS,
  role: 'admin',
}

// ── Auth injection (sets localStorage before React hydrates) ─────────────────

export async function injectAuth(page: Page, role: 'analyst' | 'admin' | 'viewer' = 'analyst') {
  await page.addInitScript(([token, r]) => {
    localStorage.setItem('asc_access_token', token)
    localStorage.setItem('asc_role', r)
  }, [MOCK_TOKENS.access_token, role])
}

// ── API mock factories ────────────────────────────────────────────────────────

export const MOCK_API_KEY = {
  id:         'mock-key-id-001',
  name:       'Test API Key',
  prefix:     'asc_test_',
  scopes:     ['read'],
  is_active:  true,
  created_at: '2026-06-14T03:00:00Z',
  expires_at: null,
  last_used_at: null,
  tenant_id:  null,
}

export const MOCK_WEBHOOK = {
  id:          'mock-wh-id-001',
  url:         'https://hooks.example.local/asc',
  description: 'Test webhook',
  events:      ['alert.critical', 'incident.created'],
  is_active:   true,
  fail_count:  0,
  created_at:  '2026-06-14T03:00:00Z',
  tenant_id:   null,
}

export const MOCK_METRICS = {
  total_events:          1234,
  active_alerts:         42,
  neutralizations_today: 7,
  agents_online:         15,
  critical_alerts:       3,
  high_alerts:           12,
}

export const MOCK_RATE_LIMIT_STATUS = {
  key_prefix:        'asc_test_',
  limit_per_minute:  60,
  limit_per_hour:    1000,
  count_minute:      12,
  count_hour:        234,
  remaining_minute:  48,
  remaining_hour:    766,
  backend:           'memory',
}

// ── Catch-all route handler (returns empty success for unmocked endpoints) ────

export async function mockAllApiCalls(page: Page) {
  await page.route('**/api/v1/**', route => {
    const url = route.request().url()
    const method = route.request().method()

    // Auth endpoints
    if (url.includes('/auth/login'))
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_TOKENS) })
    if (url.includes('/auth/me'))
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ id: 'u1', email: 'test@asc.local', role: 'analyst' }) })

    // Metrics
    if (url.includes('/metrics'))
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_METRICS) })

    // API Keys
    if (url.includes('/api-keys'))
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([MOCK_API_KEY]) })

    // Webhooks
    if (url.includes('/webhooks'))
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([MOCK_WEBHOOK]) })

    // Default: empty 200
    const body = method === 'GET' ? '[]' : '{}'
    return route.fulfill({ status: 200, contentType: 'application/json', body })
  })
}
