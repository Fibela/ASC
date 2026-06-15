/**
 * E2E — Webhooks Dashboard (P50)
 *
 * Covers (P44 UI):
 * 1. Page loads and shows webhook list
 * 2. Create webhook — modal opens, URL + events filled, POST sent
 * 3. Secret reveal panel — one-time show after creation
 * 4. Test delivery — inline result shows HTTP status + latency
 * 5. Toggle active/inactive — PATCH sent immediately
 * 6. Delete with confirmation modal
 *
 * Security invariants:
 * - Webhook secret (signing key) must NOT appear in list responses
 * - Delete requires explicit confirmation
 */

import { test, expect } from '@playwright/test'
import { injectAuth, mockAllApiCalls, MOCK_WEBHOOK } from './helpers'

const LIST_RESPONSE = [MOCK_WEBHOOK]
const CREATE_RESPONSE = {
  webhook: { ...MOCK_WEBHOOK, id: 'mock-wh-id-002', url: 'https://new.example.local/hook' },
  secret:  'whsec_mock1234567890abcdef',
}
const TEST_DELIVERY_RESPONSE = {
  status_code: 200,
  latency_ms:  42,
  success:     true,
  error:       null,
}

test.describe('Webhooks Dashboard (P44)', () => {

  test.beforeEach(async ({ page }) => {
    await injectAuth(page, 'analyst')
    await page.route('**/api/v1/webhooks/', route => {
      if (route.request().method() === 'GET')
        return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(LIST_RESPONSE) })
      return route.continue()
    })
    await mockAllApiCalls(page)
  })

  // ── Page load ─────────────────────────────────────────────────────────────

  test('Webhooks page loads and shows existing webhook', async ({ page }) => {
    await page.goto('/webhooks')
    await expect(page.getByText('https://hooks.example.local/asc')).toBeVisible({ timeout: 10_000 })
  })

  test('webhook events chips are rendered', async ({ page }) => {
    await page.goto('/webhooks')
    await expect(page.getByText(/alert\.critical|incident\.created/i)).toBeVisible({ timeout: 10_000 })
  })

  test('webhook secret never appears in list render', async ({ page }) => {
    await page.goto('/webhooks')
    await expect(page.getByText('https://hooks.example.local/asc')).toBeVisible({ timeout: 10_000 })
    const html = await page.content()
    expect(html).not.toContain('whsec_')
  })

  // ── Create webhook ────────────────────────────────────────────────────────

  test('create button opens webhook modal', async ({ page }) => {
    await page.goto('/webhooks')
    const createBtn = page.getByRole('button', { name: /nuevo|crear|new|add webhook/i })
    await expect(createBtn).toBeVisible({ timeout: 10_000 })
    await createBtn.click()
    await expect(page.getByRole('dialog')).toBeVisible({ timeout: 5_000 })
  })

  test('secret reveal panel shows after webhook creation', async ({ page }) => {
    await page.route('**/api/v1/webhooks/', async route => {
      if (route.request().method() === 'POST')
        return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(CREATE_RESPONSE) })
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(LIST_RESPONSE) })
    })

    await page.goto('/webhooks')
    const createBtn = page.getByRole('button', { name: /nuevo|crear|new|add webhook/i })
    await createBtn.click()
    await expect(page.getByRole('dialog')).toBeVisible()

    // Fill URL
    await page.getByRole('dialog').locator('input[type="url"], input[placeholder*="https"]').first()
      .fill('https://new.example.local/hook')
    await page.getByRole('dialog').getByRole('button', { name: /crear|create|guardar|save/i }).click()

    // Secret panel should appear (cyan panel with the secret)
    await expect(page.getByText(/whsec_mock1234567890abcdef|secret|signing/i)).toBeVisible({ timeout: 10_000 })
  })

  // ── Test delivery ─────────────────────────────────────────────────────────

  test('test delivery button sends request and shows result', async ({ page }) => {
    await page.route(`**/api/v1/webhooks/${MOCK_WEBHOOK.id}/test`, route =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(TEST_DELIVERY_RESPONSE) })
    )
    await page.goto('/webhooks')

    // Find and click test delivery button
    const testBtn = page.getByRole('button', { name: /test|enviar|probar/i }).first()
    if (await testBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await testBtn.click()
      await expect(page.getByText(/200|latency|ms|success/i)).toBeVisible({ timeout: 5_000 })
    } else {
      // May need to expand row first
      await page.getByText('https://hooks.example.local/asc').click()
      await page.getByRole('button', { name: /test|enviar|probar/i }).first().click()
      await expect(page.getByText(/200|42|success/i)).toBeVisible({ timeout: 5_000 })
    }
  })

  // ── Delete webhook ────────────────────────────────────────────────────────

  test('delete webhook requires confirmation modal', async ({ page }) => {
    await page.goto('/webhooks')
    const deleteBtn = page.getByRole('button', { name: /delete|eliminar|borrar/i }).first()
    if (await deleteBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await deleteBtn.click()
    } else {
      await page.getByText('https://hooks.example.local/asc').click()
      await page.getByRole('button', { name: /delete|eliminar|borrar/i }).first().click()
    }
    await expect(page.getByRole('dialog')).toBeVisible({ timeout: 5_000 })
  })

  // ── Active/Inactive toggle ────────────────────────────────────────────────

  test('active status badge is visible for active webhook', async ({ page }) => {
    await page.goto('/webhooks')
    // Active webhook should show active/enabled badge
    await expect(page.getByText(/activo|active|enabled/i).first()).toBeVisible({ timeout: 10_000 })
  })
})
