'use client'
import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { isAuthenticated, initAuth, getRole } from './auth'

export function useAuthGuard(requiredRole?: string) {
  const router = useRouter()
  useEffect(() => {
    initAuth()
    if (!isAuthenticated()) {
      router.replace('/login')
      return
    }
    if (requiredRole && getRole() !== requiredRole) {
      router.replace('/')
    }
  }, [router, requiredRole])
}
