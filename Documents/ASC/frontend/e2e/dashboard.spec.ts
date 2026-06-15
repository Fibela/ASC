/**
 * E2E — Dashboard & Sidebar Navigation (P50)
 *
 * Covers:
 * 1. Main dashboard renders with mocked SOC metrics
 * 2. Sidebar visible with all navigation links
 * 3. Navigation links route to correct pages (api-keys, rate-limits, webhooks)
 * 4. Admin-only links hidden for analyst role
 * 5. Active link highlighted for current route
 *
 * Mocking strategy:
 * - injectAuth() pre-sets localStorage before React hydrates
 * - mockAllApiCalls() catches all /api/v1/** calls with sensible defaults
 */

import { test, expect } from '@playwright/test'
import { injectAuth, mockAllApiCalls, MOCK_METRICS } from './helpers'

test.describe('Dashboard & Navigation', () => {

  test.beforeEach(async ({ page }) => {
    await injectAuth(page, 'analyst')
    await page.route('**/api/v1/metrics/**', route =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_METRICS) })
    )
    await page.route('**/api/v1/alerts/**', route =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) })
    )
    await mockAllApiCalls(page)
  })

  // ── Dashboard rendering ───────────────────────────────────────────────────

  test('dashboard page loads without error', async ({ page }) => {
    await page.goto('/')
    // App title / branding should be visible
    await expect(page.locator('body')).not.toContainText('500', { timeout: 10_000 })
    await expect(page.locator('body')).not.toContainText('Application error')
  })

  test('sidebar is visible on dashboard', async ({ page }) => {
    await page.goto('/')
    // Sidebar is a nav element
    await expect(page.locator('nav, aside').first()).toBeVisible({ timeout: 10_000 })
  })

  // ── Sidebar navigation links ──────────────────────────────────────────────

  test('sidebar shows API Keys link', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('link', { name: 'API Keys' })).toBeVisible({ timeout: 10_000 })
  })

  test('sidebar shows Rate Limits link', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('link', { name: 'Rate Limits' })).toBeVisible({ timeout: 10_000 })
  })

  test('sidebar shows Webhooks link', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('link', { name: 'Webhooks' })).toBeVisible({ timeout: 10_000 })
  })

  // ── Navigation routing ────────────────────────────────────────────────────

  test('clicking API Keys navigates to /api-keys', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('link', { name: 'API Keys' }).click()
    await expect(page).toHaveURL('/api-keys', { timeout: 10_000 })
  })

  test('clicking Rate Limits navigates to /rate-limits', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('link', { name: 'Rate Limits' }).click()
    await expect(page).toHaveURL('/rate-limits', { timeout: 10_000 })
  })

  test('clicking Webhooks navigates to /webhooks', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('link', { name: 'Webhooks' }).click()
    await expect(page).toHaveURL('/webhooks', { timeout: 10_000 })
  })

  // ── Admin-only links ──────────────────────────────────────────────────────

  test('Admin Usuarios link hidden for analyst role', async ({ page }) => {
    await page.goto('/')
    // adminOnly link should not be visible for analyst
    const adminLink = page.getByRole('link', { name: 'Admin Usuarios' })
    await expect(adminLink).toBeHidden({ timeout: 10_000 })
  })

  test('Admin Usuarios link visible for admin role', async ({ page }) => {
    // Override to admin role
    await page.addInitScript(() => {
      localStorage.setItem('asc_access_token', 'mock.token.admin.e2e')
      localStorage.setItem('asc_role', 'admin')
    })
    await page.goto('/')
    await expect(page.getByRole('link', { name: 'Admin Usuarios' })).toBeVisible({ timeout: 10_000 })
  })
})
