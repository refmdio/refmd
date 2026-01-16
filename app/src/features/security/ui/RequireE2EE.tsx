import { useEffect } from 'react'
import { useNavigate } from '@tanstack/react-router'

import { useE2EE } from '../context/e2ee-context'

import RoutePending from '@/widgets/routes/RoutePending'

interface RequireE2EEProps {
  children: React.ReactNode
}

/**
 * Gate component that ensures E2EE is ready before rendering children.
 * Redirects to /auth/unlock if keys need to be unlocked or restored.
 */
export function RequireE2EE({ children }: RequireE2EEProps) {
  const navigate = useNavigate()
  const { isInitialized, isUnlocked, hasLocalKeys, needsRestore, loading } = useE2EE()

  // Redirect to unlock if E2EE is not ready
  useEffect(() => {
    // Wait for initialization
    if (!isInitialized || loading || hasLocalKeys === null) {
      return
    }

    // If not unlocked, redirect to unlock page
    // This handles both:
    // 1. New device (needsRestore = true, hasLocalKeys = false)
    // 2. Page reload (hasLocalKeys = true, but not unlocked)
    if (!isUnlocked) {
      navigate({ to: '/auth/unlock' })
    }
  }, [isInitialized, isUnlocked, hasLocalKeys, needsRestore, loading, navigate])

  // Show loading while checking E2EE state
  if (!isInitialized || loading || hasLocalKeys === null) {
    return <RoutePending />
  }

  // Show loading while redirecting
  if (!isUnlocked) {
    return <RoutePending />
  }

  return <>{children}</>
}
