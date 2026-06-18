'use client'
import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { isAuthenticated, initAuth, getRole } from './auth'

/** Returns `isReady: true` only after auth check passes.
 *  Callers should render nothing (or a loader) until isReady is true
 *  to prevent a flash of protected content before the redirect fires. */
export function useAuthGuard(requiredRole?: string): { isReady: boolean } {
  const router = useRouter()
  const [isReady, setIsReady] = useState(false)

  useEffect(() => {
    initAuth()
    if (!isAuthenticated()) {
      router.replace('/login')
      return
    }
    if (requiredRole && getRole() !== requiredRole) {
      router.replace('/')
      return
    }
    setIsReady(true)
  }, [router, requiredRole])

  return { isReady }
}
