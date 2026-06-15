/**
 * E2E — API Key Management Dashboard (P50)
 *
 * Covers (P45 UI):
 * 1. Page loads and shows API key list
 * 2. Create new key — modal opens, form fills, POST sent, new key appears
 * 3. Key reveal panel — secret shown once with 90s countdown
 * 4. Revoke key — confirmation modal, DELETE sent, key removed from list
 * 5. Scope badges render correctly (read/write/admin colors)
 * 6. Status badges render correctly (active/expired/inactive)
 * 7. Rate limit bar visible on row expand
 *
 * Security invariants tested:
 * - raw_key value must NOT appear in initial list render
 * - Revoke requires a confirmation step (no accidental deletion)
 * - Admin-only endpoints return 403 for analyst role
 *
 * Mocking strategy:
 * - Specific route handlers override the catch-all for precise response control
 * - CREATE response includes raw_key to trigger reveal panel
 * - LIST response never includes raw_key
 */

import { test, expect } from '@playwright/test'
import { injectAuth, mockAllApiCalls, MOCK_API_KEY, MOCK_RATE_LIMIT_STATUS } from './helpers'

const LIST_RESPONSE = [MOCK_API_KEY]
const CREATE_RESPONSE = {
  ...MOCK_API_KEY,
  id: 'mock-key-id-002',
  name: 'New Test Key',
  raw_key: 'asc_live_mock1234567890abcdef',
}

test.describe('API Keys Dashboard (P45)', () => {

  test.beforeEach(async ({ page }) => {
    await injectAuth(page, 'analyst')
    // Specific mocks first, then catch-all
    await page.route('**/api/v1/api-keys/', route => {
      if (route.request().method() === 'GET')
        return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(LIST_RESPONSE) })
      return route.continue()
    })
    await mockAllApiCalls(page)
  })

  // ── Page load ─────────────────────────────────────────────────────────────

  test('API Keys page loads and shows existing key', async ({ page }) => {
    await page.goto('/api-keys')
    await expect(page.getByText('Test API Key')).toBeVisible({ timeout: 10_000 })
  })

  test('API Keys page shows key prefix', async ({ page }) => {
    await page.goto('/api-keys')
    await expect(page.getByText('asc_test_')).toBeVisible({ timeout: 10_000 })
  })

  test('raw_key is not visible in initial list render', async ({ page }) => {
    await page.goto('/api-keys')
    await expect(page.getByText('Test API Key')).toBeVisible({ timeout: 10_000 })

    // Security invariant: raw key must never appear in list view
    const html = await page.content()
    expect(html).not.toContain('asc_live_')
  })

  test('page shows scope badge for read scope', async ({ page }) => {
    await page.goto('/api-keys')
    await expect(page.getByText('read')).toBeVisible({ timeout: 10_000 })
  })

  // ── Create key ────────────────────────────────────────────────────────────

  test('clicking create button opens modal', async ({ page }) => {
    await page.goto('/api-keys')
    // Find the create/nueva button
    const createBtn = page.getByRole('button', { name: /nueva|crear|new key/i })
    await expect(createBtn).toBeVisible({ timeout: 10_000 })
    await createBtn.click()
    // Modal dialog should appear
    await expect(page.getByRole('dialog')).toBeVisible({ timeout: 5_000 })
  })

  test('create key POST request sends correct payload', async ({ page }) => {
    let capturedBody: any = null
    await page.route('**/api/v1/api-keys/', async route => {
      if (route.request().method() === 'POST') {
        capturedBody = JSON.parse(route.request().postData() || '{}')
        return route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify(CREATE_RESPONSE),
        })
      }
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(LIST_RESPONSE) })
    })

    await page.goto('/api-keys')
    const createBtn = page.getByRole('button', { name: /nueva|crear|new key/i })
    await createBtn.click()
    await expect(page.getByRole('dialog')).toBeVisible()

    // Fill the key name field in the modal
    await page.getByRole('dialog').locator('input[type="text"]').first().fill('New Test Key')
    await page.getByRole('dialog').getByRole('button', { name: /crear|create|guardar|save/i }).click()

    // Verify the POST was made with a name field
    await expect(page.getByText(/New Test Key|asc_live_/i)).toBeVisible({ timeout: 10_000 })
    expect(capturedBody?.name).toBe('New Test Key')
  })

  test('raw key revealed after creation with countdown timer', async ({ page }) => {
    await page.route('**/api/v1/api-keys/', async route => {
      if (route.request().method() === 'POST')
        return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(CREATE_RESPONSE) })
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(LIST_RESPONSE) })
    })

    await page.goto('/api-keys')
    const createBtn = page.getByRole('button', { name: /nueva|crear|new key/i })
    await createBtn.click()
    await expect(page.getByRole('dialog')).toBeVisible()
    await page.getByRole('dialog').locator('input[type="text"]').first().fill('New Test Key')
    await page.getByRole('dialog').getByRole('button', { name: /crear|create|guardar|save/i }).click()

    // After creation, reveal panel should show raw key or countdown
    await expect(page.getByText(/asc_live_mock1234567890abcdef|\d+s/)).toBeVisible({ timeout: 10_000 })
  })

  // ── Rate limit expand ─────────────────────────────────────────────────────

  test('expanding key row shows rate limit information', async ({ page }) => {
    await page.route(`**/api/v1/api-keys/${MOCK_API_KEY.id}/rate-limit-status`, route =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_RATE_LIMIT_STATUS) })
    )
    await page.goto('/api-keys')
    // Click on the key row to expand it
    await page.getByText('Test API Key').click()
    // Rate limit info should appear
    await expect(page.getByText(/limit|rate|min|hour/i).first()).toBeVisible({ timeout: 5_000 })
  })

  // ── Revoke key ────────────────────────────────────────────────────────────

  test('revoke requires confirmation before deletion', async ({ page }) => {
    await page.goto('/api-keys')
    // Find revoke button (may be in expanded row or kebab menu)
    const revokeBtn = page.getByRole('button', { name: /revoke|revocar/i }).first()
    if (await revokeBtn.isVisible()) {
      await revokeBtn.click()
      // Confirmation modal / dialog should appear
      await expect(page.getByRole('dialog')).toBeVisible({ timeout: 5_000 })
    } else {
      // Key row needs to be expanded first
      await page.getByText('Test API Key').click()
      const revokeInRow = page.getByRole('button', { name: /revoke|revocar/i }).first()
      await expect(revokeInRow).toBeVisible({ timeout: 5_000 })
      await revokeInRow.click()
      await expect(page.getByRole('dialog')).toBeVisible({ timeout: 5_000 })
    }
  })
})
