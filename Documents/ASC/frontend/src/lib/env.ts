// Single source of truth for NEXT_PUBLIC_* env vars consumed by the frontend.
// Both api.ts and useSSENotifications.ts import from here instead of reading
// process.env directly, eliminating duplication and providing a single place
// to validate configuration at runtime.

const API_URL    = process.env.NEXT_PUBLIC_API_URL    ?? 'https://asc-backend-ona9.onrender.com'
const PORTAL_URL = process.env.NEXT_PUBLIC_PORTAL_URL ?? 'https://premoscorp.com'

if (typeof window !== 'undefined' && process.env.NODE_ENV === 'production') {
  if (API_URL.includes('localhost')) {
    console.error(
      '[ASC] NEXT_PUBLIC_API_URL apunta a localhost en producción. ' +
      `Valor: "${API_URL}". Revisa las env vars en Vercel.`
    )
  }
}

export const env = { API_URL, PORTAL_URL } as const
