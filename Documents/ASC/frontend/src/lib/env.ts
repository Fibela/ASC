// Single source of truth for NEXT_PUBLIC_* env vars consumed by the frontend.
// Both api.ts and useSSENotifications.ts import from here instead of reading
// process.env directly, eliminating duplication and providing a single place
// to validate configuration at runtime.

const API_URL    = process.env.NEXT_PUBLIC_API_URL    ?? 'http://localhost:8000'
const PORTAL_URL = process.env.NEXT_PUBLIC_PORTAL_URL ?? 'https://premoscorp.com'

// Guard: warn loudly (browser console) if the URL still points to localhost in
// a production build. The app will attempt to connect and fail with CORS/network
// errors — this message surfaces the root cause immediately.
if (
  typeof window !== 'undefined' &&
  process.env.NODE_ENV === 'production' &&
  API_URL.includes('localhost')
) {
  console.error(
    '[ASC] NEXT_PUBLIC_API_URL apunta a localhost en un build de producción. ' +
    `Valor actual: "${API_URL}". ` +
    'Añade NEXT_PUBLIC_API_URL=https://<tu-api>.onrender.com en las variables de entorno de Vercel.'
  )
}

export const env = { API_URL, PORTAL_URL } as const
