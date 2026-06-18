// Single source of truth for NEXT_PUBLIC_* env vars consumed by the frontend.
// Both api.ts and useSSENotifications.ts import from here instead of reading
// process.env directly, eliminating duplication and providing a single place
// to validate configuration at runtime.

const API_URL    = process.env.NEXT_PUBLIC_API_URL    ?? ''
const PORTAL_URL = process.env.NEXT_PUBLIC_PORTAL_URL ?? 'https://premoscorp.com'

if (typeof window !== 'undefined' && process.env.NODE_ENV === 'production') {
  if (!API_URL || API_URL.includes('localhost')) {
    console.error(
      '[ASC] NEXT_PUBLIC_API_URL no está configurada o apunta a localhost. ' +
      `Valor actual: "${API_URL || '(vacío)'}". ` +
      'Configura NEXT_PUBLIC_API_URL=https://asc-backend-ona9.onrender.com en Vercel.'
    )
  }
}

export const env = { API_URL, PORTAL_URL } as const
