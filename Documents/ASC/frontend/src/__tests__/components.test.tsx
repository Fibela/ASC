/**
 * Unit tests — Dashboard components
 * Covers: SeverityBadge, MetricCard, Semaphore, RuleBar
 */
import React from 'react'
import { render, screen } from '@testing-library/react'
import { SeverityBadge } from '@/components/dashboard/SeverityBadge'
import { MetricCard }    from '@/components/dashboard/MetricCard'
import { Semaphore }     from '@/components/dashboard/Semaphore'
import { RuleBar }       from '@/components/dashboard/RuleBar'


// ─── SeverityBadge ────────────────────────────────────────────────────────────

describe('SeverityBadge', () => {
  it('renders critical severity with red background', () => {
    const { container } = render(<SeverityBadge severity="critical" />)
    expect(screen.getByText('critical')).toBeInTheDocument()
    expect(container.firstChild).toHaveClass('bg-red-600')
  })

  it('renders high severity with orange background', () => {
    render(<SeverityBadge severity="high" />)
    expect(screen.getByText('high')).toHaveClass('bg-orange-500')
  })

  it('renders medium severity with yellow background', () => {
    render(<SeverityBadge severity="medium" />)
    expect(screen.getByText('medium')).toHaveClass('bg-yellow-400')
  })

  it('renders low severity with green background', () => {
    render(<SeverityBadge severity="low" />)
    expect(screen.getByText('low')).toHaveClass('bg-green-500')
  })

  it('falls back to gray for unknown severity', () => {
    const { container } = render(<SeverityBadge severity="unknown_level" />)
    expect(container.firstChild).toHaveClass('bg-gray-500')
    expect(screen.getByText('unknown_level')).toBeInTheDocument()
  })

  it('displays severity text in uppercase style', () => {
    render(<SeverityBadge severity="critical" />)
    expect(screen.getByText('critical')).toHaveClass('uppercase')
  })
})


// ─── MetricCard ───────────────────────────────────────────────────────────────

describe('MetricCard', () => {
  it('renders label and value', () => {
    render(<MetricCard label="MTTD" value={42} />)
    expect(screen.getByText('MTTD')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
  })

  it('renders — when value is null', () => {
    render(<MetricCard label="Score" value={null} />)
    expect(screen.getByText('—')).toBeInTheDocument()
  })

  it('renders — when value is undefined', () => {
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

  it('applies red color class for color=red', () => {
    const { container } = render(<MetricCard label="Critical" value={5} color="red" />)
    const valueEl = container.querySelector('p.text-3xl')
    expect(valueEl).toHaveClass('text-red-400')
  })

  it('applies cyan color by default', () => {
    const { container } = render(<MetricCard label="Total" value={100} />)
    const valueEl = container.querySelector('p.text-3xl')
    expect(valueEl).toHaveClass('text-cyan-400')
  })

  it('renders string values correctly', () => {
    render(<MetricCard label="Rate" value="98.5%" />)
    expect(screen.getByText('98.5%')).toBeInTheDocument()
  })
})


// ─── Semaphore ────────────────────────────────────────────────────────────────

describe('Semaphore', () => {
  it('renders green for NORMAL posture', () => {
    const { container } = render(<Semaphore posture="NORMAL" />)
    expect(container.firstChild).toBeDefined()
    // Component renders "NORMAL" in two <p> elements (label + subtitle)
    expect(screen.getAllByText('NORMAL').length).toBeGreaterThanOrEqual(1)
  })

  it('renders NORMAL label for green level', () => {
    render(<Semaphore posture="NORMAL" />)
    const elements = screen.getAllByText('NORMAL')
    expect(elements.length).toBeGreaterThanOrEqual(1)
  })

  it('renders ELEVADO label for ELEVATED posture', () => {
    render(<Semaphore posture="ELEVATED" />)
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

  it('renders green for LOW posture', () => {
    render(<Semaphore posture="LOW" />)
    expect(screen.getByText('NORMAL')).toBeInTheDocument()
  })

  it('accepts custom label override', () => {
    render(<Semaphore posture="NORMAL" label="Sistema OK" />)
    expect(screen.getByText('Sistema OK')).toBeInTheDocument()
  })

  it('renders posture text below label', () => {
    render(<Semaphore posture="CRITICAL" />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('renders red circle for critical posture (animate-pulse class)', () => {
    const { container } = render(<Semaphore posture="CRITICAL" />)
    const circle = container.querySelector('div[class*="animate-pulse"]')
    expect(circle).not.toBeNull()
  })

  it('does not pulse for normal posture', () => {
    const { container } = render(<Semaphore posture="NORMAL" />)
    const circle = container.querySelector('div[class*="animate-pulse"]')
    expect(circle).toBeNull()
  })
})


// ─── RuleBar ──────────────────────────────────────────────────────────────────

describe('RuleBar', () => {
  const base = {
    ruleId:   'DET-001',
    name:     'Suspicious acord32.exe',
    ttp:      'T1036.005',
    severity: 'critical',
    count:    5,
    maxCount: 10,
  }

  it('renders rule id, name and ttp', () => {
    render(<RuleBar {...base} />)
    expect(screen.getByText('DET-001')).toBeInTheDocument()
    expect(screen.getByText('Suspicious acord32.exe')).toBeInTheDocument()
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
    const { container } = render(<RuleBar {...base} />)
    const bar = container.querySelector('div.h-full')
    expect(bar).toHaveStyle('width: 50%')
  })

  it('bar width is 100% when count equals maxCount', () => {
    const { container } = render(<RuleBar {...base} count={10} maxCount={10} />)
    const bar = container.querySelector('div.h-full')
    expect(bar).toHaveStyle('width: 100%')
  })

  it('bar width is 0% when count is 0', () => {
    const { container } = render(<RuleBar {...base} count={0} maxCount={10} />)
    const bar = container.querySelector('div.h-full')
    expect(bar).toHaveStyle('width: 0%')
  })

  it('applies red color for critical severity', () => {
    const { container } = render(<RuleBar {...base} severity="critical" />)
    const bar = container.querySelector('div.h-full')
    expect(bar).toHaveClass('bg-red-500')
  })

  it('applies orange color for high severity', () => {
    const { container } = render(<RuleBar {...base} severity="high" />)
    const bar = container.querySelector('div.h-full')
    expect(bar).toHaveClass('bg-orange-400')
  })
})
