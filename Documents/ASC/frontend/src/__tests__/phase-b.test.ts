/**
 * Unit tests — Phase B static + behavioral invariants
 *
 * B-3: API types — SocMetrics, TimelinePoint, AlertItem, DetectionRule exported from api.ts
 * B-4: env.ts — single source of truth for NEXT_PUBLIC_API_URL and PORTAL_URL
 * B-alert: alerts/page.tsx — AlertItem type, isReady guard, no console.error
 * B-detection: detection/page.tsx — DetectionRulesResponse type, isReady guard, no console.error
 * B-dashboard: page.tsx — ApiRule replaced with DetectionRule, mitre_ttp used
 */

import fs from 'fs'
import path from 'path'

const ROOT = path.resolve(__dirname, '../..')
const read = (rel: string) => fs.readFileSync(path.join(ROOT, 'src', rel), 'utf8')

const API_SRC       = read('lib/api.ts')
const ENV_SRC       = read('lib/env.ts')
const ALERTS_SRC    = read('app/alerts/page.tsx')
const DETECTION_SRC = read('app/detection/page.tsx')
const DASHBOARD_SRC = read('app/page.tsx')

// ─── B-4: env.ts ─────────────────────────────────────────────────────────────

describe('B-4 — env.ts single source of truth', () => {
  it('exports const env object', () => {
    expect(ENV_SRC).toMatch(/export const env\s*=/)
  })

  it('env contains API_URL key', () => {
    expect(ENV_SRC).toMatch(/API_URL/)
  })

  it('env contains PORTAL_URL key', () => {
    expect(ENV_SRC).toMatch(/PORTAL_URL/)
  })

  it('uses NEXT_PUBLIC_API_URL env var', () => {
    expect(ENV_SRC).toMatch(/NEXT_PUBLIC_API_URL/)
  })

  it('uses NEXT_PUBLIC_PORTAL_URL env var', () => {
    expect(ENV_SRC).toMatch(/NEXT_PUBLIC_PORTAL_URL/)
  })

  it('has runtime guard for localhost in production', () => {
    expect(ENV_SRC).toMatch(/localhost/)
    expect(ENV_SRC).toMatch(/production/)
  })

  it('guard uses console.error not throw (avoids crashing SOC in prod)', () => {
    expect(ENV_SRC).toMatch(/console\.error/)
    expect(ENV_SRC).not.toMatch(/throw new Error.*localhost/)
  })

  it('api.ts imports from env (not process.env directly)', () => {
    expect(API_SRC).toMatch(/import.*env.*from.*['"]\.\/env['"]/)
  })

  it('api.ts uses env.API_URL for baseURL', () => {
    expect(API_SRC).toMatch(/env\.API_URL/)
  })

  it('api.ts does NOT read process.env.NEXT_PUBLIC_API_URL directly', () => {
    expect(API_SRC).not.toMatch(/process\.env\.NEXT_PUBLIC_API_URL/)
  })

  it('useSSENotifications imports from env', () => {
    const SSE_SRC = read('lib/useSSENotifications.ts')
    expect(SSE_SRC).toMatch(/import.*env.*from.*['"]\.\/env['"]/)
    expect(SSE_SRC).toMatch(/env\.API_URL/)
    expect(SSE_SRC).not.toMatch(/process\.env\.NEXT_PUBLIC_API_URL/)
  })
})

// ─── B-3: API interfaces ───────────────────────────────────────────────────

describe('B-3 — SocMetrics interface', () => {
  it('exports SocMetrics interface', () => {
    expect(API_SRC).toMatch(/export interface SocMetrics/)
  })

  it('SocMetrics has risk_posture field', () => {
    expect(API_SRC).toMatch(/risk_posture.*CRITICAL.*HIGH.*ELEVATED.*NORMAL/)
  })

  it('SocMetrics has by_severity field', () => {
    expect(API_SRC).toMatch(/by_severity.*SocSeverityBreakdown/)
  })

  it('SocMetrics has mttd_seconds and mttd_minutes fields', () => {
    expect(API_SRC).toMatch(/mttd_seconds/)
    expect(API_SRC).toMatch(/mttd_minutes/)
  })

  it('exports SocSeverityBreakdown interface', () => {
    expect(API_SRC).toMatch(/export interface SocSeverityBreakdown/)
  })

  it('getSocMetrics returns Promise<SocMetrics>', () => {
    expect(API_SRC).toMatch(/getSocMetrics.*Promise<SocMetrics>/)
  })
})

describe('B-3 — TimelinePoint interface', () => {
  it('exports TimelinePoint interface', () => {
    expect(API_SRC).toMatch(/export interface TimelinePoint/)
  })

  it('TimelinePoint has timestamp field', () => {
    expect(API_SRC).toMatch(/timestamp.*string/)
  })

  it('TimelinePoint has severity count fields', () => {
    expect(API_SRC).toMatch(/critical.*number/)
    expect(API_SRC).toMatch(/high.*number/)
    expect(API_SRC).toMatch(/total.*number/)
  })

  it('getTimeline returns Promise<TimelinePoint[]>', () => {
    expect(API_SRC).toMatch(/getTimeline.*Promise<TimelinePoint\[\]>/)
  })
})

describe('B-3 — AlertItem interface', () => {
  it('exports AlertItem interface', () => {
    expect(API_SRC).toMatch(/export interface AlertItem/)
  })

  it('exports AlertSeverity type', () => {
    expect(API_SRC).toMatch(/export type AlertSeverity/)
  })

  it('exports AlertStatus type', () => {
    expect(API_SRC).toMatch(/export type AlertStatus/)
  })

  it('AlertItem has analyst_notes field', () => {
    expect(API_SRC).toMatch(/analyst_notes/)
  })

  it('AlertItem has detected_at field', () => {
    expect(API_SRC).toMatch(/detected_at/)
  })

  it('getAlerts returns Promise<AlertItem[]>', () => {
    expect(API_SRC).toMatch(/getAlerts.*Promise<AlertItem\[\]>/)
  })
})

describe('B-3 — DetectionRule interface', () => {
  it('exports DetectionRule interface', () => {
    expect(API_SRC).toMatch(/export interface DetectionRule/)
  })

  it('exports DetectionRulesResponse interface', () => {
    expect(API_SRC).toMatch(/export interface DetectionRulesResponse/)
  })

  it('DetectionRule has mitre_ttp field (matches real API)', () => {
    expect(API_SRC).toMatch(/mitre_ttp.*string/)
  })

  it('DetectionRulesResponse wraps rules array', () => {
    expect(API_SRC).toMatch(/rules.*DetectionRule\[\]/)
  })

  it('getDetectionRules returns Promise<DetectionRulesResponse>', () => {
    expect(API_SRC).toMatch(/getDetectionRules.*Promise<DetectionRulesResponse>/)
  })
})

// ─── B-alert: alerts/page.tsx fixes ─────────────────────────────────────────

describe('B-alert — alerts/page.tsx fixes', () => {
  it('imports AlertItem from api', () => {
    expect(ALERTS_SRC).toMatch(/import.*AlertItem.*from.*['"]@\/lib\/api['"]/)
  })

  it('uses AlertItem[] for alerts state (no any[])', () => {
    expect(ALERTS_SRC).toMatch(/useState<AlertItem\[\]>/)
    expect(ALERTS_SRC).not.toMatch(/useState<any\[\]>/)
  })

  it('destructures isReady from useAuthGuard()', () => {
    expect(ALERTS_SRC).toMatch(/const\s*\{\s*isReady\s*\}\s*=\s*useAuthGuard\s*\(/)
  })

  it('guards useEffect with isReady', () => {
    expect(ALERTS_SRC).toMatch(/if\s*\(!isReady\)\s*return/)
  })

  it('renders AlertsLoader when !isReady', () => {
    expect(ALERTS_SRC).toMatch(/if\s*\(!isReady\)\s*return\s*<AlertsLoader/)
  })

  it('has error state with useState<string | null>', () => {
    expect(ALERTS_SRC).toMatch(/useState<string \| null>/)
  })

  it('sets error message on catch (not console.error)', () => {
    expect(ALERTS_SRC).toMatch(/setError\s*\(/)
    expect(ALERTS_SRC).not.toMatch(/console\.error/)
  })

  it('renders error banner in JSX', () => {
    expect(ALERTS_SRC).toMatch(/\{error && !loading &&/)
  })

  it('error banner has Reintentar button', () => {
    expect(ALERTS_SRC).toMatch(/Reintentar/)
  })

  it('catch block uses e.message (not raw Error dump)', () => {
    expect(ALERTS_SRC).toMatch(/e\.message/)
    expect(ALERTS_SRC).not.toMatch(/setError\s*\(\s*e\s*\)/)
  })
})

// ─── B-detection: detection/page.tsx fixes ──────────────────────────────────

describe('B-detection — detection/page.tsx fixes', () => {
  it('imports DetectionRulesResponse from api', () => {
    expect(DETECTION_SRC).toMatch(/DetectionRulesResponse/)
  })

  it('uses DetectionRulesResponse | null for rules state (no any)', () => {
    expect(DETECTION_SRC).toMatch(/useState<DetectionRulesResponse \| null>/)
    expect(DETECTION_SRC).not.toMatch(/useState<any>\(null\)/)
  })

  it('uses explicit generic type for result state (not bare useState<any>)', () => {
    // Record<string, any> or Record<string, unknown> are both acceptable —
    // the key invariant is that the bare `useState<any>(null)` pattern is gone
    expect(DETECTION_SRC).toMatch(/useState<Record<string/)
    expect(DETECTION_SRC).not.toMatch(/= useState<any>\(null\)/)
  })

  it('destructures isReady from useAuthGuard()', () => {
    expect(DETECTION_SRC).toMatch(/const\s*\{\s*isReady\s*\}\s*=\s*useAuthGuard\s*\(/)
  })

  it('renders DetectionLoader when !isReady', () => {
    expect(DETECTION_SRC).toMatch(/if\s*\(!isReady\)\s*return\s*<DetectionLoader/)
  })

  it('useEffect guards with !isReady', () => {
    expect(DETECTION_SRC).toMatch(/!isReady.*tab.*rules.*rules/)
  })

  it('no console.error in detection page', () => {
    expect(DETECTION_SRC).not.toMatch(/console\.error/)
  })

  it('TABS array uses React.ComponentType<...> (no raw any)', () => {
    expect(DETECTION_SRC).toMatch(/React\.ComponentType</)
    expect(DETECTION_SRC).not.toMatch(/\[Tab, string, any\]\[\]/)
  })
})

// ─── B-dashboard: page.tsx type fixes ────────────────────────────────────────

describe('B-dashboard — page.tsx uses canonical types', () => {
  it('imports SocMetrics from api', () => {
    expect(DASHBOARD_SRC).toMatch(/SocMetrics/)
  })

  it('imports AlertItem from api', () => {
    expect(DASHBOARD_SRC).toMatch(/AlertItem/)
  })

  it('imports TimelinePoint from api', () => {
    expect(DASHBOARD_SRC).toMatch(/TimelinePoint/)
  })

  it('imports DetectionRule from api', () => {
    expect(DASHBOARD_SRC).toMatch(/DetectionRule/)
  })

  it('no local ApiRule interface (replaced by canonical DetectionRule)', () => {
    expect(DASHBOARD_SRC).not.toMatch(/interface ApiRule/)
  })

  it('metrics state uses SocMetrics | null (no any)', () => {
    expect(DASHBOARD_SRC).toMatch(/useState<SocMetrics \| null>/)
  })

  it('alerts state uses AlertItem[] (no any[])', () => {
    expect(DASHBOARD_SRC).toMatch(/useState<AlertItem\[\]>/)
  })

  it('timeline state uses TimelinePoint[] (no any[])', () => {
    expect(DASHBOARD_SRC).toMatch(/useState<TimelinePoint\[\]>/)
  })

  it('rules state uses DetectionRule[] (no ApiRule[])', () => {
    expect(DASHBOARD_SRC).toMatch(/useState<DetectionRule\[\]>/)
    expect(DASHBOARD_SRC).not.toMatch(/useState<ApiRule\[\]>/)
  })

  it('ruleData uses mitre_ttp from canonical type', () => {
    expect(DASHBOARD_SRC).toMatch(/mitre_ttp/)
    expect(DASHBOARD_SRC).not.toMatch(/mitre_technique.*mitre_tactic/)
  })

  it('accesses r.rules directly (no Array.isArray fallback needed)', () => {
    expect(DASHBOARD_SRC).toMatch(/r\.rules\.filter/)
    expect(DASHBOARD_SRC).not.toMatch(/Array\.isArray\(r\)/)
  })
})

// ─── B-1: Error Boundaries ────────────────────────────────────────────────────

describe('B-1 — error.tsx route error boundary', () => {
  const ERR_SRC = read('app/error.tsx')

  it('is a use client component', () => {
    expect(ERR_SRC).toMatch(/['"]use client['"]/)
  })

  it('receives error and reset props', () => {
    expect(ERR_SRC).toMatch(/error.*Error/)
    expect(ERR_SRC).toMatch(/reset.*\(\s*\).*=>.*void/)
  })

  it('shows error digest when available', () => {
    expect(ERR_SRC).toMatch(/error\.digest/)
  })

  it('renders reset button with reset prop', () => {
    expect(ERR_SRC).toMatch(/onClick={reset}/)
  })

  it('only logs in development (no production console.error)', () => {
    expect(ERR_SRC).toMatch(/NODE_ENV.*!==.*production/)
    expect(ERR_SRC).toMatch(/console\.error/)
  })

  it('no dangerouslySetInnerHTML', () => {
    expect(ERR_SRC).not.toMatch(/dangerouslySetInnerHTML/)
  })
})

describe('B-1 — global-error.tsx root error boundary', () => {
  const GERR_SRC = read('app/global-error.tsx')

  it('is a use client component', () => {
    expect(GERR_SRC).toMatch(/['"]use client['"]/)
  })

  it('renders own html and body tags (layout unavailable)', () => {
    expect(GERR_SRC).toMatch(/<html/)
    expect(GERR_SRC).toMatch(/<body/)
  })

  it('receives error and reset props', () => {
    expect(GERR_SRC).toMatch(/error.*Error/)
    expect(GERR_SRC).toMatch(/reset.*\(\s*\).*=>.*void/)
  })

  it('renders Recargar button with reset action', () => {
    expect(GERR_SRC).toMatch(/onClick={reset}/)
    expect(GERR_SRC).toMatch(/Recargar/)
  })

  it('only logs in development', () => {
    expect(GERR_SRC).toMatch(/NODE_ENV.*!==.*production/)
  })

  it('no dangerouslySetInnerHTML', () => {
    expect(GERR_SRC).not.toMatch(/dangerouslySetInnerHTML/)
  })
})

// ─── B-2: PageSkeleton ────────────────────────────────────────────────────────

describe('B-2 — PageSkeleton component', () => {
  const SKEL_SRC = read('components/PageSkeleton.tsx')

  it('is a use client component', () => {
    expect(SKEL_SRC).toMatch(/['"]use client['"]/)
  })

  it('exports PageSkeleton function', () => {
    expect(SKEL_SRC).toMatch(/export function PageSkeleton/)
  })

  it('supports table variant', () => {
    expect(SKEL_SRC).toMatch(/variant.*table/)
  })

  it('supports cards variant', () => {
    expect(SKEL_SRC).toMatch(/variant.*cards/)
  })

  it('supports metrics variant', () => {
    expect(SKEL_SRC).toMatch(/variant.*metrics/)
  })

  it('uses animate-pulse for skeleton effect', () => {
    expect(SKEL_SRC).toMatch(/animate-pulse/)
  })

  it('accepts rows prop', () => {
    expect(SKEL_SRC).toMatch(/rows.*number/)
  })

  it('no hardcoded sensitive data', () => {
    expect(SKEL_SRC).not.toMatch(/password|secret|token/i)
  })
})

describe('B-2 — loading.tsx files', () => {
  it('root loading.tsx imports PageSkeleton', () => {
    const src = read('app/loading.tsx')
    expect(src).toMatch(/PageSkeleton/)
  })

  it('alerts loading.tsx imports PageSkeleton with table variant', () => {
    const src = read('app/alerts/loading.tsx')
    expect(src).toMatch(/PageSkeleton/)
    expect(src).toMatch(/table/)
  })

  it('detection loading.tsx imports PageSkeleton with cards variant', () => {
    const src = read('app/detection/loading.tsx')
    expect(src).toMatch(/PageSkeleton/)
    expect(src).toMatch(/cards/)
  })

  it('events loading.tsx exists and uses PageSkeleton', () => {
    const src = read('app/events/loading.tsx')
    expect(src).toMatch(/PageSkeleton/)
  })

  it('incidents loading.tsx exists and uses PageSkeleton', () => {
    const src = read('app/incidents/loading.tsx')
    expect(src).toMatch(/PageSkeleton/)
  })
})

// ─── Security invariants — Phase B files ─────────────────────────────────────

describe('Security invariants — Phase B', () => {
  it('env.ts has no hardcoded API keys or tokens', () => {
    expect(ENV_SRC).not.toMatch(/sk_live|api_key\s*=|bearer [A-Za-z0-9._-]{40,}/i)
  })

  it('env.ts has no dangerouslySetInnerHTML', () => {
    expect(ENV_SRC).not.toMatch(/dangerouslySetInnerHTML/)
  })

  it('api.ts new interfaces have no hardcoded credentials', () => {
    expect(API_SRC).not.toMatch(/password\s*:\s*['"][^'"]{4,}['"]/)
    expect(API_SRC).not.toMatch(/secret\s*:\s*['"][^'"]{4,}['"]/)
  })

  it('error.tsx does not expose raw stack traces in DOM', () => {
    const ERR_SRC = read('app/error.tsx')
    expect(ERR_SRC).not.toMatch(/error\.stack/)
    expect(ERR_SRC).not.toMatch(/error\.message/)
  })

  it('global-error.tsx does not expose raw error details in DOM', () => {
    const GERR_SRC = read('app/global-error.tsx')
    expect(GERR_SRC).not.toMatch(/error\.stack/)
    expect(GERR_SRC).not.toMatch(/error\.message/)
  })

  it('PageSkeleton has no console leaks', () => {
    const SKEL_SRC = read('components/PageSkeleton.tsx')
    expect(SKEL_SRC).not.toMatch(/console\.(log|error|warn)/)
  })
})
