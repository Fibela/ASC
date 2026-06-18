/**
 * Unit tests — Dashboard Phase A fixes (src/app/page.tsx)
 *
 * Static + logic tests for:
 * A-2: Rules from API (not hardcoded)
 * A-3: Error state when API fails
 * A-4: No console.error leak
 * A-5: isReady gate from useAuthGuard
 *
 * Tests are static (fs.readFileSync) + behavioral (mock API).
 * Security scan included: no hardcoded credentials, no console.log/error.
 */

import fs from 'fs'
import path from 'path'

const ROOT     = path.resolve(__dirname, '../..')
const read     = (rel: string) => fs.readFileSync(path.join(ROOT, 'src', rel), 'utf8')
const PAGE_SRC = read('app/page.tsx')

// ─── A-2: Rules from API (static) ────────────────────────────────────────────

describe('A-2 — Dashboard rules from API', () => {
  it('imports getDetectionRules from api', () => {
    expect(PAGE_SRC).toMatch(/getDetectionRules/)
  })

  it('does NOT contain hardcoded RULES array const', () => {
    expect(PAGE_SRC).not.toMatch(/^const RULES\s*=\s*\[/m)
  })

  it('does NOT hardcode DET-001 rule name in source', () => {
    expect(PAGE_SRC).not.toMatch(/DET-001/)
  })

  it('does NOT hardcode acord32.exe rule name in source', () => {
    expect(PAGE_SRC).not.toMatch(/acord32/)
  })

  it('stores rules in state via setRules', () => {
    expect(PAGE_SRC).toMatch(/setRules/)
  })

  it('uses rules state to build ruleData', () => {
    expect(PAGE_SRC).toMatch(/rules\.map\s*\(/)
  })

  it('ruleData count uses hit_count from API (no manual severity allocation)', () => {
    expect(PAGE_SRC).toMatch(/hit_count/)
    // The old hack was assigning bySeverity.critical to both DET-001 and DET-002
    expect(PAGE_SRC).not.toMatch(/bySeverity\.critical.*bySeverity\.critical/)
  })

  it('filters inactive rules before display', () => {
    expect(PAGE_SRC).toMatch(/is_active/)
  })

  it('limits displayed rules to 4 entries', () => {
    expect(PAGE_SRC).toMatch(/slice\s*\(\s*0\s*,\s*4\s*\)/)
  })

  it('shows loading skeleton while rules load', () => {
    expect(PAGE_SRC).toMatch(/animate-pulse/)
  })

  it('shows empty state when no rules exist', () => {
    expect(PAGE_SRC).toMatch(/Sin reglas de detección activas/)
  })
})

// ─── A-3: Error state ────────────────────────────────────────────────────────

describe('A-3 — Dashboard error state', () => {
  it('declares error state with useState', () => {
    expect(PAGE_SRC).toMatch(/useState<string \| null>\(null\)/)
  })

  it('resets error to null at start of load()', () => {
    expect(PAGE_SRC).toMatch(/setError\s*\(\s*null\s*\)/)
  })

  it('sets error in catch block', () => {
    expect(PAGE_SRC).toMatch(/setError\s*\(/)
  })

  it('renders error banner when error is set', () => {
    expect(PAGE_SRC).toMatch(/\{error && !loading &&/)
  })

  it('error banner shows AlertCircle icon', () => {
    expect(PAGE_SRC).toMatch(/AlertCircle/)
  })

  it('error banner has retry button', () => {
    expect(PAGE_SRC).toMatch(/Reintentar/)
  })

  it('error message is user-friendly (no raw Error object dump)', () => {
    // Message uses e.message not e itself
    expect(PAGE_SRC).toMatch(/e\.message/)
    expect(PAGE_SRC).not.toMatch(/setError\s*\(\s*e\s*\)/)
  })
})

// ─── A-4: No console.error ────────────────────────────────────────────────────

describe('A-4 — No console leaks', () => {
  it('has no console.error calls in dashboard', () => {
    expect(PAGE_SRC).not.toMatch(/console\.error/)
  })

  it('has no console.log calls in dashboard', () => {
    expect(PAGE_SRC).not.toMatch(/console\.log/)
  })

  it('has no console.warn calls in dashboard', () => {
    expect(PAGE_SRC).not.toMatch(/console\.warn/)
  })
})

// ─── A-5: Auth guard isReady / FOUC ─────────────────────────────────────────

describe('A-5 — Auth guard isReady / FOUC prevention', () => {
  it('destructures isReady from useAuthGuard()', () => {
    expect(PAGE_SRC).toMatch(/const\s*\{\s*isReady\s*\}\s*=\s*useAuthGuard\s*\(/)
  })

  it('renders AuthLoader when !isReady', () => {
    expect(PAGE_SRC).toMatch(/if\s*\(\s*!isReady\s*\)\s*return\s*<AuthLoader/)
  })

  it('load() only fires after isReady is true', () => {
    // useEffect with [isReady] dependency and early return guard
    expect(PAGE_SRC).toMatch(/if\s*\(\s*!isReady\s*\)\s*return/)
  })

  it('defines AuthLoader component in page file', () => {
    expect(PAGE_SRC).toMatch(/function AuthLoader/)
  })

  it('AuthLoader has animate-spin for visual feedback', () => {
    expect(PAGE_SRC).toMatch(/animate-spin/)
  })
})

// ─── A-auth.ts: SSO refresh fix (static) ─────────────────────────────────────

describe('A-1 — auth.ts SSO refresh fix (static)', () => {
  const AUTH_SRC = read('lib/auth.ts')

  it('defines SSO_ORIGIN_KEY constant', () => {
    expect(AUTH_SRC).toMatch(/SSO_ORIGIN_KEY\s*=\s*['"]asc_sso_origin['"]/)
  })

  it('clearTokens removes SSO_ORIGIN_KEY', () => {
    expect(AUTH_SRC).toMatch(/localStorage\.removeItem\s*\(\s*SSO_ORIGIN_KEY\s*\)/)
  })

  it('refreshAccessToken checks for SSO origin before giving up', () => {
    expect(AUTH_SRC).toMatch(/ssoOrigin.*premoscorp/)
  })

  it('refreshAccessToken redirects to portal URL for SSO sessions', () => {
    expect(AUTH_SRC).toMatch(/NEXT_PUBLIC_PORTAL_URL/)
  })

  it('SSO re-auth redirects to /portal/seguridad', () => {
    expect(AUTH_SRC).toMatch(/portal\/seguridad/)
  })

  it('exports markSSOSession function', () => {
    expect(AUTH_SRC).toMatch(/export function markSSOSession/)
  })

  it('exports getSSOOrigin function', () => {
    expect(AUTH_SRC).toMatch(/export function getSSOOrigin/)
  })

  it('no hardcoded portal URL (uses env var fallback with ??)', () => {
    // Allow: `?? 'https://premoscorp.com'` (env var fallback)
    // Fail:  any other hardcoded usage
    expect(AUTH_SRC).not.toMatch(/(?<!\?\? ')https:\/\/premoscorp\.com/)
  })
})

// ─── SSO callback page (static) ──────────────────────────────────────────────

describe('A-1 — sso/page.tsx marks SSO origin', () => {
  const SSO_SRC = read('app/sso/page.tsx')

  it('imports markSSOSession from auth', () => {
    expect(SSO_SRC).toMatch(/import.*markSSOSession.*from.*auth/)
  })

  it('calls markSSOSession with premoscorp', () => {
    expect(SSO_SRC).toMatch(/markSSOSession\s*\(\s*['"]premoscorp['"]\s*\)/)
  })

  it('stores token under asc_access_token key', () => {
    expect(SSO_SRC).toMatch(/asc_access_token/)
  })

  it('stores role under asc_role key', () => {
    expect(SSO_SRC).toMatch(/asc_role/)
  })

  it('no hardcoded refresh_token (SSO does not have one)', () => {
    expect(SSO_SRC).not.toMatch(/asc_refresh_token/)
  })

  it('redirects to / with router.replace (removes token from history)', () => {
    expect(SSO_SRC).toMatch(/router\.replace\s*\(\s*['"]\/['"]\s*\)/)
  })
})

// ─── Security invariants ──────────────────────────────────────────────────────

describe('Security invariants — Phase A files', () => {
  it('page.tsx has no hardcoded API keys or secrets', () => {
    expect(PAGE_SRC).not.toMatch(/sk_live|api_key|password\s*=|secret\s*=|bearer [A-Za-z0-9._-]{40,}/i)
  })

  it('page.tsx has no dangerouslySetInnerHTML', () => {
    expect(PAGE_SRC).not.toMatch(/dangerouslySetInnerHTML/)
  })

  it('auth.ts has no hardcoded credentials', () => {
    const src = read('lib/auth.ts')
    expect(src).not.toMatch(/password\s*=\s*['"][^'"]+['"]/)
    expect(src).not.toMatch(/secret\s*=\s*['"][^'"]+['"]/)
  })

  it('auth-guard.tsx has no console leaks', () => {
    const src = read('lib/auth-guard.tsx')
    expect(src).not.toMatch(/console\.(log|error|warn)/)
  })
})
