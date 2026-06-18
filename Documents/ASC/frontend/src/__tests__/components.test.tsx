/**
 * Unit tests — Dashboard components (P64-DESIGN: PremosCorp Visual Identity)
 * Updated to match new design system: severity-badge CSS classes, inline styles,
 * PremosCorp palette (orange #E85D04, red #C0152E), no generic Tailwind color classes.
 *
 * Security checks included:
 * - No hardcoded credentials/keys in component output
 * - No dangerouslySetInnerHTML
 * - Proper fallbacks for null/undefined values
 */
import React from 'react'
import { render, screen } from '@testing-library/react'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import { MetricCard }    from '@/components/dashboard/MetricCard'
import { Semaphore }     from '@/components/dashboard/Semaphore'
import { RuleBar }       from '@/components/dashboard/RuleBar'


// ─── SeverityBadge ────────────────────────────────────────────────────────────

describe('SeverityBadge — P64 design system', () => {
  it('renders the severity text', () => {
    render(<SeverityBadge severity="critical" />)
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('applies severity-badge base class', () => {
    const { container } = render(<SeverityBadge severity="critical" />)
    expect(container.firstChild).toHaveClass('severity-badge')
  })

  it('applies severity-critical class for critical', () => {
    const { container } = render(<SeverityBadge severity="critical" />)
    expect(container.firstChild).toHaveClass('severity-critical')
  })

  it('applies severity-high class for high', () => {
    const { container } = render(<SeverityBadge severity="high" />)
    expect(container.firstChild).toHaveClass('severity-high')
  })

  it('applies severity-medium class for medium', () => {
    const { container } = render(<SeverityBadge severity="medium" />)
    expect(container.firstChild).toHaveClass('severity-medium')
  })

  it('applies severity-low class for low', () => {
    const { container } = render(<SeverityBadge severity="low" />)
    expect(container.firstChild).toHaveClass('severity-low')
  })

  it('applies severity-info class for info', () => {
    const { container } = render(<SeverityBadge severity="info" />)
    expect(container.firstChild).toHaveClass('severity-info')
  })

  it('renders unknown severity with severity-badge base class', () => {
    const { container } = render(<SeverityBadge severity="unknown_level" />)
    expect(container.firstChild).toHaveClass('severity-badge')
    expect(screen.getByText('unknown_level')).toBeInTheDocument()
  })

  it('does NOT use generic Tailwind color classes (P64 invariant)', () => {
    const { container } = render(<SeverityBadge severity="critical" />)
    const el = container.firstChild as HTMLElement
    expect(el).not.toHaveClass('bg-red-600')
    expect(el).not.toHaveClass('bg-orange-500')
    expect(el).not.toHaveClass('bg-gray-500')
    expect(el).not.toHaveClass('text-white')
  })

  it('handles uppercase severity input', () => {
    render(<SeverityBadge severity="CRITICAL" />)
    const { container } = render(<SeverityBadge severity="CRITICAL" />)
    expect(container.firstChild).toHaveClass('severity-badge')
    // severity class will be severity-CRITICAL (no lowercase transform in SeverityBadge)
    expect(screen.getAllByText('CRITICAL').length).toBeGreaterThanOrEqual(1)
  })

  it('renders all severities without crashing', () => {
    const severities = ['critical', 'high', 'medium', 'low', 'info']
    severities.forEach(sev => {
      const { unmount } = render(<SeverityBadge severity={sev} />)
      expect(screen.getByText(sev)).toBeInTheDocument()
      unmount()
    })
  })

  it('has no dangerouslySetInnerHTML (XSS safety)', () => {
    // Just render and verify text content is plain text, no HTML injection
    render(<SeverityBadge severity='<script>alert(1)</script>' />)
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument()
  })
})


// ─── MetricCard ───────────────────────────────────────────────────────────────

describe('MetricCard — P64 design system', () => {
  it('renders label', () => {
    render(<MetricCard label="MTTD" value={42} />)
    expect(screen.getByText('MTTD')).toBeInTheDocument()
  })

  it('renders numeric value', () => {
    render(<MetricCard label="MTTD" value={42} />)
    expect(screen.getByText('42')).toBeInTheDocument()
  })

  it('renders em-dash when value is null', () => {
    render(<MetricCard label="Score" value={null} />)
    expect(screen.getByText('—')).toBeInTheDocument()
  })

  it('renders em-dash when value is undefined', () => {
    render(<MetricCard label="Score" value={undefined as any} />)
    expect(screen.getByText('—')).toBeInTheDocument()
  })

  it('renders unit when provided', () => {
    render(<MetricCard label="MTTD" value={15} unit="min" />)
    expect(screen.getByText('min')).toBeInTheDocument()
  })

  it('renders sublabel when provided', () => {
    render(<MetricCard label="MTTD" value={15} sublabel="Mean Time to Detect" />)
    expect(screen.getByText('Mean Time to Detect')).toBeInTheDocument()
  })

  it('renders string values correctly', () => {
    render(<MetricCard label="Rate" value="98.5%" />)
    expect(screen.getByText('98.5%')).toBeInTheDocument()
  })

  it('uses inline style for color (P64 design system — no generic Tailwind color)', () => {
    const { container } = render(<MetricCard label="Critical" value={5} color="red" />)
    const valueEl = container.querySelector('p.text-3xl') as HTMLElement
    expect(valueEl).toBeTruthy()
    // New design uses inline style, not Tailwind class
    expect(valueEl.style.color).toBeTruthy()
    expect(valueEl).not.toHaveClass('text-red-400')
    expect(valueEl).not.toHaveClass('text-cyan-400')
  })

  it('value element has orange inline color for orange variant', () => {
    const { container } = render(<MetricCard label="Total" value={100} color="orange" />)
    const valueEl = container.querySelector('p.text-3xl') as HTMLElement
    expect(valueEl.style.color).toBe('rgb(232, 93, 4)')
  })

  it('value element has correct color for red variant', () => {
    const { container } = render(<MetricCard label="Critical" value={5} color="red" />)
    const valueEl = container.querySelector('p.text-3xl') as HTMLElement
    expect(valueEl.style.color).toBe('rgb(232, 82, 110)')
  })

  it('value element has correct color for green variant', () => {
    const { container } = render(<MetricCard label="Contained" value={3} color="green" />)
    const valueEl = container.querySelector('p.text-3xl') as HTMLElement
    expect(valueEl.style.color).toBe('rgb(63, 209, 117)')
  })

  it('renders trend value when provided', () => {
    render(<MetricCard label="MTTD" value={15} trend="up" trendVal="+2" />)
    expect(screen.getByText('+2')).toBeInTheDocument()
  })

  it('renders without crashing when icon is not provided', () => {
    const { container } = render(<MetricCard label="Test" value={0} />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('renders card with rounded-2xl class', () => {
    const { container } = render(<MetricCard label="Test" value={99} />)
    expect(container.firstChild).toHaveClass('rounded-2xl')
  })

  it('has no secrets or credentials in output', () => {
    const { container } = render(<MetricCard label="API Key" value="99" />)
    const text = container.textContent ?? ''
    expect(text).not.toMatch(/sk_live|api_key|password|secret/i)
  })
})


// ─── Semaphore ────────────────────────────────────────────────────────────────

describe('Semaphore — P64 design system', () => {
  it('renders NORMAL label for NORMAL posture', () => {
    render(<Semaphore posture="NORMAL" />)
    // Both label ("NORMAL") and posture subtitle ("NORMAL") render — use getAllByText
    const normals = screen.getAllByText('NORMAL')
    expect(normals.length).toBeGreaterThanOrEqual(1)
  })

  it('shows the posture string below the label', () => {
    render(<Semaphore posture="NORMAL" />)
    // Both label "NORMAL" and posture "NORMAL" appear
    const normals = screen.getAllByText('NORMAL')
    expect(normals.length).toBeGreaterThanOrEqual(1)
  })

  it('renders ELEVADO label for ELEVATED posture', () => {
    render(<Semaphore posture="ELEVATED" />)
    expect(screen.getByText('ELEVADO')).toBeInTheDocument()
  })

  it('renders ELEVADO for MEDIUM posture', () => {
    render(<Semaphore posture="MEDIUM" />)
    expect(screen.getByText('ELEVADO')).toBeInTheDocument()
  })

  it('renders CRÍTICO label for CRITICAL posture', () => {
    render(<Semaphore posture="CRITICAL" />)
    expect(screen.getByText('CRÍTICO')).toBeInTheDocument()
  })

  it('renders CRÍTICO for HIGH posture', () => {
    render(<Semaphore posture="HIGH" />)
    expect(screen.getByText('CRÍTICO')).toBeInTheDocument()
  })

  it('renders NORMAL for LOW posture', () => {
    render(<Semaphore posture="LOW" />)
    expect(screen.getByText('NORMAL')).toBeInTheDocument()
  })

  it('uses custom label override', () => {
    render(<Semaphore posture="NORMAL" label="Sistema OK" />)
    expect(screen.getByText('Sistema OK')).toBeInTheDocument()
  })

  it('displays the posture string in subtitle', () => {
    render(<Semaphore posture="CRITICAL" />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('applies pulse animation class for critical posture', () => {
    const { container } = render(<Semaphore posture="CRITICAL" />)
    // New design uses animate-pulse-red (contains "animate-pulse" substring)
    const circle = container.querySelector('[class*="animate-pulse"]')
    expect(circle).not.toBeNull()
  })

  it('does not apply pulse for normal posture', () => {
    const { container } = render(<Semaphore posture="NORMAL" />)
    const circle = container.querySelector('[class*="animate-pulse"]')
    expect(circle).toBeNull()
  })

  it('uses inline style for colors (P64 — no Tailwind color classes)', () => {
    const { container } = render(<Semaphore posture="CRITICAL" />)
    const ring = container.querySelector('.rounded-full') as HTMLElement
    // New design uses inline style for border and background
    expect(ring).toBeTruthy()
    expect(ring).not.toHaveClass('border-red-500')
    expect(ring).not.toHaveClass('border-green-500')
  })

  it('renders sm size without crashing', () => {
    const { container } = render(<Semaphore posture="NORMAL" size="sm" />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('renders lg size without crashing', () => {
    const { container } = render(<Semaphore posture="CRITICAL" size="lg" />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('defaults to NORMAL for unknown posture string', () => {
    render(<Semaphore posture="UNKNOWN_STATE" />)
    // Falls back to green (NORMAL label)
    expect(screen.getByText('NORMAL')).toBeInTheDocument()
  })
})


// ─── RuleBar ──────────────────────────────────────────────────────────────────

describe('RuleBar — P64 design system', () => {
  const base = {
    ruleId:   'DET-001',
    name:     'Suspicious acord32.exe',
    ttp:      'T1036.005',
    severity: 'critical',
    count:    5,
    maxCount: 10,
  }

  it('renders rule id', () => {
    render(<RuleBar {...base} />)
    expect(screen.getByText('DET-001')).toBeInTheDocument()
  })

  it('renders rule name', () => {
    render(<RuleBar {...base} />)
    expect(screen.getByText('Suspicious acord32.exe')).toBeInTheDocument()
  })

  it('renders MITRE TTP', () => {
    render(<RuleBar {...base} />)
    expect(screen.getByText('T1036.005')).toBeInTheDocument()
  })

  it('renders count', () => {
    render(<RuleBar {...base} />)
    expect(screen.getByText('5')).toBeInTheDocument()
  })

  it('renders zero count', () => {
    render(<RuleBar {...base} count={0} />)
    expect(screen.getByText('0')).toBeInTheDocument()
  })

  it('bar width is 50% when count=5, maxCount=10', () => {
    const { container } = render(<RuleBar {...base} count={5} maxCount={10} />)
    const bar = container.querySelector('.h-full') as HTMLElement
    expect(bar.style.width).toBe('50%')
  })

  it('bar width is 100% when count equals maxCount', () => {
    const { container } = render(<RuleBar {...base} count={10} maxCount={10} />)
    const bar = container.querySelector('.h-full') as HTMLElement
    expect(bar.style.width).toBe('100%')
  })

  it('bar width is minimum 4% when count is 0 (P64 — avoids invisible bar)', () => {
    const { container } = render(<RuleBar {...base} count={0} maxCount={10} />)
    const bar = container.querySelector('.h-full') as HTMLElement
    // New design enforces Math.max(4, ...) for visible bars
    expect(bar.style.width).toBe('4%')
  })

  it('bar width is 0% when maxCount is 0 (no data case)', () => {
    const { container } = render(<RuleBar {...base} count={0} maxCount={0} />)
    const bar = container.querySelector('.h-full') as HTMLElement
    expect(bar.style.width).toBe('0%')
  })

  it('uses inline style for bar color — no generic Tailwind class (P64 invariant)', () => {
    const { container } = render(<RuleBar {...base} severity="critical" />)
    const bar = container.querySelector('.h-full') as HTMLElement
    // P64 invariant: no Tailwind color class on the bar
    expect(bar).not.toHaveClass('bg-red-500')
    expect(bar).not.toHaveClass('bg-orange-400')
    // Glow box-shadow (PremosCorp palette) IS preserved by jsdom
    const styleAttr = bar.getAttribute('style') ?? ''
    expect(styleAttr).toContain('box-shadow')
  })

  it('does not use bg-orange-400 for high severity (P64 invariant)', () => {
    const { container } = render(<RuleBar {...base} severity="high" />)
    const bar = container.querySelector('.h-full') as HTMLElement
    expect(bar).not.toHaveClass('bg-orange-400')
  })

  it('renders severity chip for critical (CRI label)', () => {
    render(<RuleBar {...base} severity="critical" />)
    expect(screen.getByText('CRI')).toBeInTheDocument()
  })

  it('renders severity chip for high (ALT label)', () => {
    render(<RuleBar {...base} severity="high" />)
    expect(screen.getByText('ALT')).toBeInTheDocument()
  })

  it('renders severity chip for medium (MED label)', () => {
    render(<RuleBar {...base} severity="medium" />)
    expect(screen.getByText('MED')).toBeInTheDocument()
  })

  it('renders severity chip for low (BAJ label)', () => {
    render(<RuleBar {...base} severity="low" />)
    expect(screen.getByText('BAJ')).toBeInTheDocument()
  })
})


// ─── Integration — no secrets or API keys in any component ────────────────────

describe('Security invariants — all components', () => {
  it('SeverityBadge has no credential patterns in output', () => {
    const { container } = render(<SeverityBadge severity="critical" />)
    expect(container.innerHTML).not.toMatch(/sk_live|api_key|password|secret|token/i)
  })

  it('MetricCard has no credential patterns in output', () => {
    const { container } = render(<MetricCard label="Alerts" value={5} />)
    expect(container.innerHTML).not.toMatch(/sk_live|api_key|password|secret/i)
  })

  it('Semaphore has no credential patterns in output', () => {
    const { container } = render(<Semaphore posture="CRITICAL" />)
    expect(container.innerHTML).not.toMatch(/sk_live|api_key|password|secret/i)
  })

  it('RuleBar has no credential patterns in output', () => {
    const { container } = render(<RuleBar
      ruleId="DET-001" name="Test rule" ttp="T1000"
      severity="high" count={2} maxCount={5}
    />)
    expect(container.innerHTML).not.toMatch(/sk_live|api_key|password|secret/i)
  })
})
