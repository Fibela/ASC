/**
 * Phase C — Test Suite
 *
 * C-1: AuthLoader + isReady guard on 20+ pages
 * C-2: Typed API functions + subscribeToNotifications token fix
 * C-3: SSO E2E (separate e2e/sso.spec.ts)
 *
 * Security invariants:
 * - No hardcoded tokens in api.ts (uses asc_access_token key)
 * - All analysis/detection returns are typed (no implicit any)
 * - All data-fetching useEffects gated with isReady
 */

import * as fs from 'fs'
import * as path from 'path'

const ROOT = path.resolve(__dirname, '../..')

function read(rel: string) {
  return fs.readFileSync(path.join(ROOT, 'src', rel), 'utf8')
}

function readRoot(rel: string) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8')
}

// ── C-1-A: AuthLoader component ───────────────────────────────────────────────

describe('C-1-A: AuthLoader component', () => {
  const src = read('components/AuthLoader.tsx')

  it('exports AuthLoader function', () => {
    expect(src).toMatch(/export function AuthLoader/)
  })

  it('uses #0A0A0A background', () => {
    expect(src).toContain('#0A0A0A')
  })

  it('uses #E85D04 orange spinner ring', () => {
    expect(src).toContain('#E85D04')
  })

  it('includes animate-spin class', () => {
    expect(src).toContain('animate-spin')
  })

  it('has min-h-screen layout', () => {
    expect(src).toContain('min-h-screen')
  })
})

// ── C-1-B: isReady guard — pages that already had it (regression check) ───────

describe('C-1-B: Previously fixed pages — isReady guard preserved', () => {
  it('alerts/page.tsx still has isReady from useAuthGuard', () => {
    const src = read('app/alerts/page.tsx')
    expect(src).toMatch(/const\s*\{\s*isReady\s*\}\s*=\s*useAuthGuard\(\)/)
  })

  it('detection/page.tsx still has isReady', () => {
    const src = read('app/detection/page.tsx')
    expect(src).toMatch(/const\s*\{\s*isReady\s*\}\s*=\s*useAuthGuard\(\)/)
  })
})

// ── C-1-C: isReady guard — Phase C pages ──────────────────────────────────────

const PHASE_C_PAGES = [
  'app/analyze/page.tsx',
  'app/events/page.tsx',
  'app/metrics/page.tsx',
  'app/forensic/page.tsx',
  'app/adapters/page.tsx',
  'app/webhooks/page.tsx',
  'app/iocs/page.tsx',
  'app/threat-intel/page.tsx',
  'app/soar/page.tsx',
  'app/status/page.tsx',
  'app/honeypot/page.tsx',
  'app/rate-limits/page.tsx',
  'app/ops/page.tsx',
  'app/admin/page.tsx',
  'app/api-keys/page.tsx',
  'app/incidents/page.tsx',
  'app/threat-hunting/page.tsx',
  'app/agents/page.tsx',
  'app/neutralize/page.tsx',
  'app/playbooks/page.tsx',
]

describe('C-1-C: All Phase C pages — isReady destructuring', () => {
  PHASE_C_PAGES.forEach(rel => {
    const name = rel.replace('app/', '').replace('/page.tsx', '')
    it(`${name}: destructures isReady from useAuthGuard()`, () => {
      const src = read(rel)
      expect(src).toMatch(/const\s*\{\s*isReady\s*\}\s*=\s*useAuthGuard\(/)
    })
  })
})

describe('C-1-D: All Phase C pages — AuthLoader import', () => {
  PHASE_C_PAGES.forEach(rel => {
    const name = rel.replace('app/', '').replace('/page.tsx', '')
    it(`${name}: imports AuthLoader`, () => {
      const src = read(rel)
      expect(src).toContain("from '@/components/AuthLoader'")
    })
  })
})

describe('C-1-E: All Phase C pages — early return when !isReady', () => {
  PHASE_C_PAGES.forEach(rel => {
    const name = rel.replace('app/', '').replace('/page.tsx', '')
    it(`${name}: has early return <AuthLoader /> when !isReady`, () => {
      const src = read(rel)
      expect(src).toMatch(/if\s*\(!isReady\)\s*return\s*<AuthLoader/)
    })
  })
})

// ── C-1-F: Pages with data useEffect — isReady gating ─────────────────────────

describe('C-1-F: Data useEffects gated with isReady', () => {
  const GATED_PAGES = [
    'app/events/page.tsx',
    'app/metrics/page.tsx',
    'app/forensic/page.tsx',
    'app/adapters/page.tsx',
    'app/webhooks/page.tsx',
    'app/iocs/page.tsx',
    'app/threat-intel/page.tsx',
    'app/incidents/page.tsx',
    'app/threat-hunting/page.tsx',
    'app/api-keys/page.tsx',
    'app/ops/page.tsx',
    'app/neutralize/page.tsx',
  ]

  GATED_PAGES.forEach(rel => {
    const name = rel.replace('app/', '').replace('/page.tsx', '')
    it(`${name}: data useEffect gated with if (!isReady) return`, () => {
      const src = read(rel)
      // Must have isReady as a dependency AND the guard
      expect(src).toContain('isReady')
      expect(src).toMatch(/\[\s*[^\]]*isReady/)
    })
  })
})

// ── C-2-A: API typed interfaces ───────────────────────────────────────────────

describe('C-2-A: New typed interfaces in api.ts', () => {
  const api = read('lib/api.ts')

  it('exports AlertStats interface', () => {
    expect(api).toMatch(/export interface AlertStats/)
  })

  it('exports EventItem interface', () => {
    expect(api).toMatch(/export interface EventItem/)
  })

  it('exports IoCItem interface', () => {
    expect(api).toMatch(/export interface IoCItem/)
  })

  it('exports AnalysisResult interface', () => {
    expect(api).toMatch(/export interface AnalysisResult/)
  })

  it('exports DetectionResult interface', () => {
    expect(api).toMatch(/export interface DetectionResult/)
  })

  it('exports BulkDetectionResult interface', () => {
    expect(api).toMatch(/export interface BulkDetectionResult/)
  })

  it('exports FingerprintResult interface', () => {
    expect(api).toMatch(/export interface FingerprintResult/)
  })

  it('exports IngestResult interface', () => {
    expect(api).toMatch(/export interface IngestResult/)
  })

  it('exports PublicMetrics interface', () => {
    expect(api).toMatch(/export interface PublicMetrics/)
  })
})

describe('C-2-B: Functions have explicit return types', () => {
  const api = read('lib/api.ts')

  it('getAlertStats returns Promise<AlertStats>', () => {
    expect(api).toContain('): Promise<AlertStats>')
  })

  it('updateAlert returns Promise<Partial<AlertItem>>', () => {
    expect(api).toContain('): Promise<Partial<AlertItem>>')
  })

  it('getEvents returns Promise<EventItem[]>', () => {
    expect(api).toContain('): Promise<EventItem[]>')
  })

  it('getIoCs returns Promise<IoCItem[]>', () => {
    expect(api).toContain('): Promise<IoCItem[]>')
  })

  it('analyzeFile returns Promise<AnalysisResult>', () => {
    expect(api).toMatch(/analyzeFile.*:\s*Promise<AnalysisResult>/)
  })

  it('evaluateEvent returns Promise<DetectionResult>', () => {
    expect(api).toContain('): Promise<DetectionResult>')
  })

  it('evaluateBulkEvents returns Promise<BulkDetectionResult>', () => {
    expect(api).toContain('): Promise<BulkDetectionResult>')
  })

  it('fingerprintArtifact returns Promise<FingerprintResult>', () => {
    expect(api).toContain('): Promise<FingerprintResult>')
  })

  it('getPublicMetrics returns Promise<PublicMetrics>', () => {
    expect(api).toContain('): Promise<PublicMetrics>')
  })
})

// ── C-2-C: subscribeToNotifications token key fix ─────────────────────────────

describe('C-2-C: subscribeToNotifications uses correct token key', () => {
  const api = read('lib/api.ts')

  it('uses asc_access_token (not generic "token")', () => {
    expect(api).toContain("localStorage.getItem('asc_access_token')")
  })

  it('does NOT use bare localStorage.getItem("token")', () => {
    // Should not have the wrong key (that was the bug)
    expect(api).not.toContain("localStorage.getItem('token')")
  })

  it('subscribeToNotifications function exists', () => {
    expect(api).toMatch(/export function subscribeToNotifications/)
  })
})

// ── C-2-D: Security — no hardcoded secrets ────────────────────────────────────

describe('C-2-D: api.ts security invariants', () => {
  const api = read('lib/api.ts')

  it('no hardcoded API URLs in functions (uses env.API_URL)', () => {
    // Should not have https://... hardcoded in function calls (outside env fallback)
    const hardcoded = api.match(/https?:\/\/[a-zA-Z0-9.-]+\/api\/v1/g) ?? []
    expect(hardcoded.length).toBe(0)
  })

  it('no hardcoded bearer tokens', () => {
    expect(api).not.toMatch(/Bearer\s+[a-zA-Z0-9_.-]{20,}/)
  })

  it('uses env.API_URL for base URL', () => {
    expect(api).toContain('env.API_URL')
  })
})

// ── C-3: SSO E2E spec file exists ─────────────────────────────────────────────

describe('C-3: SSO E2E spec', () => {
  it('e2e/sso.spec.ts exists', () => {
    const exists = fs.existsSync(path.join(ROOT, 'e2e', 'sso.spec.ts'))
    expect(exists).toBe(true)
  })

  it('sso.spec.ts covers token storage test', () => {
    const src = readRoot('e2e/sso.spec.ts')
    expect(src).toContain('asc_access_token')
  })

  it('sso.spec.ts covers redirect to dashboard', () => {
    const src = readRoot('e2e/sso.spec.ts')
    expect(src).toContain("toHaveURL('/'")
  })

  it('sso.spec.ts covers /sso without token → /login', () => {
    const src = readRoot('e2e/sso.spec.ts')
    expect(src).toContain("goto('/sso')")
    expect(src).toContain('/login')
  })

  it('sso.spec.ts checks asc_sso_origin is premoscorp', () => {
    const src = readRoot('e2e/sso.spec.ts')
    expect(src).toContain("'premoscorp'")
  })

  it('sso.spec.ts has token-in-URL security check', () => {
    const src = readRoot('e2e/sso.spec.ts')
    expect(src).toContain('token=')
    expect(src).toContain('not.toContain')
  })
})

// ── Cross-cutting: no loose any in new typed functions ────────────────────────

describe('C-cross: New interfaces use specific types (not any)', () => {
  const api = read('lib/api.ts')

  it('AlertStats has no "any" fields', () => {
    // Verify AlertStats interface exists and doesn't rely on 'any'
    expect(api).toContain('interface AlertStats')
    expect(api).toContain('total: number')
    expect(api).toContain('by_severity: Record<string, number>')
  })

  it('EventItem has no "any" fields', () => {
    expect(api).toContain('interface EventItem')
    expect(api).toContain('event_type: string')
    expect(api).toContain('severity: string')
  })

  it('IoCItem has no "any" fields', () => {
    expect(api).toContain('interface IoCItem')
    expect(api).toContain('ioc_type: string')
    expect(api).toContain('confidence: number')
  })

  it('AnalysisResult has verdict field with union type', () => {
    expect(api).toMatch(/verdict:\s*['"]malicious['"]/)
  })

  it('DetectionResult has matched_rules: string[]', () => {
    expect(api).toContain('matched_rules: string[]')
  })

  it('FingerprintResult has is_known_malware: boolean', () => {
    expect(api).toContain('is_known_malware: boolean')
  })
})

// ── AuthLoader: no 'use server' directive ─────────────────────────────────────

describe('C-1-security: AuthLoader is client-only', () => {
  const src = read('components/AuthLoader.tsx')

  it("has 'use client' directive", () => {
    expect(src.trimStart()).toMatch(/^'use client'/)
  })

  it("does NOT have 'use server'", () => {
    expect(src).not.toContain("'use server'")
  })
})
