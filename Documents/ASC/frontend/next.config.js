/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  },

  // P50 — Security headers applied to all routes
  // Verified by E2E tests in frontend/e2e/security-headers.spec.ts
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          // Prevent MIME-type sniffing attacks
          { key: 'X-Content-Type-Options', value: 'nosniff' },

          // Deny embedding in iframes (clickjacking protection)
          { key: 'X-Frame-Options', value: 'DENY' },

          // Only send origin on cross-origin requests (no full URL leak)
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },

          // Restrict browser feature access — SOC dashboards don't need camera/mic
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },

          // Force HTTPS for all future requests (31536000 = 1 year)
          // Note: only effective over HTTPS — no-op in local HTTP dev
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },

          // Content Security Policy:
          // - default-src 'self': only load resources from same origin
          // - script-src 'self' 'unsafe-eval': Next.js requires unsafe-eval in dev
          // - style-src 'self' 'unsafe-inline': Tailwind + inline styles
          // - img-src 'self' data:: allow inline SVG data URLs
          // - connect-src 'self' + API URL: allow XHR/fetch to backend
          // - frame-ancestors 'none': secondary clickjacking protection (CSP layer)
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data: blob:",
              "font-src 'self'",
              "connect-src 'self' http://localhost:8000 https://*.premoscorp.com",
              "frame-ancestors 'none'",
            ].join('; '),
          },

          // Prevent XSS via reflected content in legacy browsers
          { key: 'X-XSS-Protection', value: '1; mode=block' },
        ],
      },
    ]
  },
}

module.exports = nextConfig
