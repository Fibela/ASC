import { defineConfig, devices } from '@playwright/test'

/**
 * ASC PremosCorp — Playwright E2E Configuration (P50)
 *
 * All E2E specs live in ./e2e/ and use page.route() to mock backend calls.
 * No live backend is required — the suite is fully self-contained for CI.
 *
 * CI override: PLAYWRIGHT_BASE_URL env var (e.g. http://staging.asc.premoscorp.com)
 * Local dev:   http://localhost:3000 (run `npm run dev` first)
 */
export default defineConfig({
  testDir: './e2e',

  // Fail immediately on .only / .skip leaking into CI
  forbidOnly: !!process.env.CI,

  // Retry on CI to absorb flaky renders; none locally for fast feedback
  retries: process.env.CI ? 2 : 0,

  // Parallelism: 1 worker in CI (avoids port contention + race conditions on Next.js)
  workers: process.env.CI ? 1 : undefined,

  // Reporters: HTML for visual inspection, JUnit for CI integration
  reporter: [
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
    ['junit', { outputFile: 'playwright-results.xml' }],
    ['list'],
  ],

  use: {
    // Base URL — override via PLAYWRIGHT_BASE_URL in CI
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3000',

    // Screenshots: only on failure (keeps artifact size small)
    screenshot: 'only-on-failure',

    // Video: retain on failure for debugging flaky tests
    video: 'retain-on-failure',

    // Trace: on first retry to capture full context for flaky failure debugging
    trace: 'on-first-retry',

    // Action timeout: 10s per click/fill (generous for CI runners)
    actionTimeout: 10_000,

    // Navigation timeout: 30s (Next.js cold start can be slow)
    navigationTimeout: 30_000,

    // Locale: consistent date/time formatting across environments
    locale: 'es-MX',
    timezoneId: 'America/Mexico_City',
  },

  // Test in 3 browsers (P50 closes the pyramid across all major engines)
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
    // Mobile viewports for responsive coverage
    {
      name: 'mobile-chrome',
      use: { ...devices['Pixel 5'] },
    },
  ],

  // Output dirs
  outputDir: 'playwright-artifacts',

  // Dev server — only used in local mode (CI starts the app separately)
  // Uncomment to auto-start Next.js for local `npx playwright test`:
  // webServer: {
  //   command: 'npm run build && npm run start',
  //   port: 3000,
  //   reuseExistingServer: !process.env.CI,
  //   timeout: 120_000,
  // },
})
