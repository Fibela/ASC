/**
 * E2E — Authentication Flow (P50)
 *
 * Covers:
 * 1. Login page renders correctly (form elements visible)
 * 2. Successful login → redirect to dashboard
 * 3. Invalid credentials → error message shown, stays on /login
 * 4. Protected route without auth → redirect to /login
 * 5. Authenticated user hits /login → redirect to /
 * 6. Submit button state changes during authentication
 * 7. Password visibility toggle (show/hide)
 *
 * Security invariants:
 * - Login response (access_token) must NOT appear in page HTML
 * - Failed auth must NOT expose backend error details beyond "Credenciales inválidas"
 *
 * Mocking strategy:
 * - All /api/v1/** calls intercepted via page.route() — no real backend required
 * - Auth tokens stored in localStorage: asc_access_token, asc_role
 */

import { test, expect } from '@playwright/test'
import { MOCK_TOKENS, mockAllApiCalls } from './helpers'

const MOCK_EMAIL = 'analyst@premoscorp.local'
const MOCK_PASSWORD = 'ValidPass123!'

test.describe('Authentication — Login / Logout / Guard', () => {

  test.beforeEach(async ({ page }) => {
    // Ensure clean auth state for each test
    await page.addInitScript(() => {
      localStorage.removeItem('asc_access_token')
      localStorage.removeItem('asc_refresh_token')
      localStorage.removeItem('asc_role')
    })
  })

  // ── Rendering ─────────────────────────────────────────────────────────────

  test('login page renders all required elements', async ({ page }) => {
    await page.goto('/login')

    await expect(page.getByText('ASC PremosCorp')).toBeVisible()
    await expect(page.getByText('Analizador de Seguridad Cibernética')).toBeVisible()
    await expect(page.locator('input[type="email"]')).toBeVisible()
    await expect(page.locator('input[type="password"]')).toBeVisible()
    await expect(page.locator('button[type="submit"]')).toContainText('Iniciar sesión')
    await expect(page.getByText('Acceso restringido a personal autorizado')).toBeVisible()
  })

  test('email field has correct placeholder', async ({ page }) => {
    await page.goto('/login')
    const emailInput = page.locator('input[type="email"]')
    await expect(emailInput).toHaveAttribute('placeholder', 'analista@premoscorp.com')
  })

  // ── Successful login ──────────────────────────────────────────────────────

  test('successful login redirects to dashboard', async ({ page }) => {
    await page.route('**/api/v1/auth/login', route =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_TOKENS) })
    )
    await mockAllApiCalls(page)

    await page.goto('/login')
    await page.locator('input[type="email"]').fill(MOCK_EMAIL)
    await page.locator('input[type="password"]').fill(MOCK_PASSWORD)
    await page.locator('button[type="submit"]').click()

    await expect(page).toHaveURL('/', { timeout: 15_000 })
  })

  test('successful login stores token in localStorage', async ({ page }) => {
    await page.route('**/api/v1/auth/login', route =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_TOKENS) })
    )
    await mockAllApiCalls(page)

    await page.goto('/login')
    await page.locator('input[type="email"]').fill(MOCK_EMAIL)
    await page.locator('input[type="password"]').fill(MOCK_PASSWORD)
    await page.locator('button[type="submit"]').click()
    await expect(page).toHaveURL('/', { timeout: 15_000 })

    const token = await page.evaluate(() => localStorage.getItem('asc_access_token'))
    expect(token).toBe(MOCK_TOKENS.access_token)
    const role = await page.evaluate(() => localStorage.getItem('asc_role'))
    expect(role).toBe(MOCK_TOKENS.role)
  })

  test('submit button shows loading state during authentication', async ({ page }) => {
    // Slow down the mock to observe loading state
    await page.route('**/api/v1/auth/login', async route => {
      await new Promise(r => setTimeout(r, 300))
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_TOKENS) })
    })
    await mockAllApiCalls(page)

    await page.goto('/login')
    await page.locator('input[type="email"]').fill(MOCK_EMAIL)
    await page.locator('input[type="password"]').fill(MOCK_PASSWORD)
    await page.locator('button[type="submit"]').click()

    // During request, button shows "Autenticando..."
    await expect(page.locator('button[type="submit"]')).toContainText('Autenticando', { timeout: 2_000 })
  })

  // ── Failed login ──────────────────────────────────────────────────────────

  test('invalid credentials shows error and stays on /login', async ({ page }) => {
    await page.route('**/api/v1/auth/login', route =>
      route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'Credenciales inválidas' }),
      })
    )

    await page.goto('/login')
    await page.locator('input[type="email"]').fill('wrong@example.local')
    await page.locator('input[type="password"]').fill('wrongpassword')
    await page.locator('button[type="submit"]').click()

    await expect(page.getByText('Credenciales inválidas')).toBeVisible({ timeout: 5_000 })
    await expect(page).toHaveURL('/login')
  })

  test('failed login does not store token in localStorage', async ({ page }) => {
    await page.route('**/api/v1/auth/login', route =>
      route.fulfill({ status: 401, body: JSON.stringify({ detail: 'Credenciales inválidas' }) })
    )

    await page.goto('/login')
    await page.locator('input[type="email"]').fill('wrong@example.local')
    await page.locator('input[type="password"]').fill('wrongpassword')
    await page.locator('button[type="submit"]').click()

    await expect(page.getByText('Credenciales inválidas')).toBeVisible({ timeout: 5_000 })
    const token = await page.evaluate(() => localStorage.getItem('asc_access_token'))
    expect(token).toBeNull()
  })

  // ── Route guard ───────────────────────────────────────────────────────────

  test('unauthenticated access to /api-keys redirects to /login', async ({ page }) => {
    await page.goto('/api-keys')
    await expect(page).toHaveURL('/login', { timeout: 10_000 })
  })

  test('unauthenticated access to /webhooks redirects to /login', async ({ page }) => {
    await page.goto('/webhooks')
    await expect(page).toHaveURL('/login', { timeout: 10_000 })
  })

  test('unauthenticated access to /rate-limits redirects to /login', async ({ page }) => {
    await page.goto('/rate-limits')
    await expect(page).toHaveURL('/login', { timeout: 10_000 })
  })

  test('authenticated user visiting /login is redirected to dashboard', async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.setItem('asc_access_token', 'mock.token.already.logged.in')
      localStorage.setItem('asc_role', 'analyst')
    })
    await mockAllApiCalls(page)

    await page.goto('/login')
    await expect(page).toHaveURL('/', { timeout: 10_000 })
  })

  // ── Password visibility toggle ────────────────────────────────────────────

  test('password show/hide toggle changes input type', async ({ page }) => {
    await page.goto('/login')
    const passwordInput = page.locator('input[type="password"]')
    await expect(passwordInput).toBeVisible()

    // Click the show/hide toggle button (type="button" next to password)
    const toggleBtn = page.locator('button[type="button"]')
    await toggleBtn.click()

    // After toggle, input type should change to "text"
    await expect(page.locator('input[type="text"]')).toBeVisible()
  })

  // ── Security invariants ───────────────────────────────────────────────────

  test('access_token value does not appear in rendered HTML', async ({ page }) => {
    await page.route('**/api/v1/auth/login', route =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_TOKENS) })
    )
    await mockAllApiCalls(page)

    await page.goto('/login')
    await page.locator('input[type="email"]').fill(MOCK_EMAIL)
    await page.locator('input[type="password"]').fill(MOCK_PASSWORD)
    await page.locator('button[type="submit"]').click()
    await expect(page).toHaveURL('/', { timeout: 15_000 })

    const html = await page.content()
    expect(html).not.toContain(MOCK_TOKENS.access_token)
  })
})
