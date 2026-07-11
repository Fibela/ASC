'use client'

import { useEffect, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { markSSOSession } from '@/lib/auth'

const ACCESS_KEY = 'asc_access_token'
const ROLE_KEY   = 'asc_role'

function SSOHandler() {
  const router = useRouter()
  const params = useSearchParams()

  useEffect(() => {
    const token = params.get('token')
    const role  = params.get('role') ?? 'analyst'

    if (!token) {
      router.replace('/login')
      return
    }

    // Persist SSO token — same keys used by the rest of the app
    localStorage.setItem(ACCESS_KEY, token)
    localStorage.setItem(ROLE_KEY,   role)

    // Mark session as SSO-originated so the 401 interceptor redirects back
    // to premoscorp.com/portal/seguridad for transparent re-auth on expiry
    markSSOSession('premoscorp')

    async function finalize() {
      // Wire axios header so the first API call after redirect is authenticated
      const { api } = await import('@/lib/api')
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`

      // Check onboarding step — new SSO users land on sso_welcome and need the wizard
      try {
        const { getMe } = await import('@/lib/auth')
        const me = await getMe()
        if (me?.onboarding_step === 'sso_welcome') {
          router.replace('/onboarding')
          return
        }
      } catch {
        // getMe failed (malformed token, network) — continue to dashboard
      }

      // Replace removes the token from browser history (no back-nav exposure)
      router.replace('/')
    }

    finalize()
  }, [router, params])

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center gap-4"
      style={{ background: '#0A0A0A' }}
    >
      <div
        className="w-6 h-6 rounded-full border-2 animate-spin"
        style={{ borderColor: 'rgba(232,93,4,0.2)', borderTopColor: '#E85D04' }}
      />
      <p className="text-sm" style={{ color: '#5A5A5A' }}>
        Iniciando sesión ASC…
      </p>
    </div>
  )
}

export default function SSOPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen" style={{ background: '#0A0A0A' }} />
    }>
      <SSOHandler />
    </Suspense>
  )
}
