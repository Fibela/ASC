/** @type {import('next').NextConfig} */

// On Vercel, security headers are served by vercel.json at the CDN edge layer.
// Duplicating them here would cause the browser to receive two CSP headers and
// enforce only the intersection — which blocks API calls to Render.
// On non-Vercel runtimes (Docker, local server) we apply headers here as fallback.
const IS_VERCEL = !!process.env.VERCEL

const nextConfig = {
  // Bake NEXT_PUBLIC_* vars into webpack at build time.
  // Fallbacks are the production URLs — safe to hardcode because they are not secrets.
  // This guarantees the correct URL even if Vercel's env injection has a timing issue
  // on the very first build of a new project (env vars set after the build starts).
  env: {
    NEXT_PUBLIC_API_URL:
      process.env.NEXT_PUBLIC_API_URL || 'https://asc-backend-ona9.onrender.com',
    NEXT_PUBLIC_PORTAL_URL:
      process.env.NEXT_PUBLIC_PORTAL_URL || 'https://premoscorp.com',
  },

  // standalone mode is for Docker / self-hosted servers.
  // Vercel uses its own optimised Next.js output pipeline — this flag is a no-op
  // on Vercel but would bloat the build artefact unnecessarily.
  ...(IS_VERCEL ? {} : { output: 'standalone' }),

  // Security headers — only applied when NOT running on Vercel.
  // On Vercel, vercel.json owns all headers (single source of truth, no duplicates).
  ...(!IS_VERCEL && {
    async headers() {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
      return [
        {
          source: '/(.*)',
          headers: [
            { key: 'X-Content-Type-Options',  value: 'nosniff' },
            { key: 'X-Frame-Options',          value: 'DENY' },
            { key: 'X-XSS-Protection',         value: '1; mode=block' },
            { key: 'Referrer-Policy',           value: 'strict-origin-when-cross-origin' },
            { key: 'Permissions-Policy',        value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()' },
            { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
            {
              key: 'Content-Security-Policy',
              value: [
                "default-src 'self'",
                "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
                "style-src 'self' 'unsafe-inline'",
                "img-src 'self' data: blob:",
                "font-src 'self'",
                `connect-src 'self' ${apiUrl} https://*.onrender.com https://*.premoscorp.com`,
                "frame-ancestors 'none'",
                "base-uri 'self'",
                "form-action 'self'",
                "object-src 'none'",
              ].join('; '),
            },
          ],
        },
      ]
    },
  }),
}

module.exports = nextConfig
