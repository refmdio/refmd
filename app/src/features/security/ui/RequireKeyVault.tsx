import { useNavigate } from '@tanstack/react-router'
import { useEffect } from 'react'

import RoutePending from '@/widgets/routes/RoutePending'

import { useKeyVault } from '../context/key-vault-context'


interface RequireKeyVaultProps {
  children: React.ReactNode
}

/**
 * Gate component that ensures KeyVault is ready before rendering children.
 * Redirects to /auth/unlock if keys need to be unlocked or restored.
 */
export function RequireKeyVault({ children }: RequireKeyVaultProps) {
  const navigate = useNavigate()
  const { isInitialized, isUnlocked, hasLocalKeys, needsRestore, loading } = useKeyVault()

  // Redirect to unlock if KeyVault is not ready
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

  // Show loading while checking KeyVault state
  if (!isInitialized || loading || hasLocalKeys === null) {
    return <RoutePending />
  }

  // Show loading while redirecting
  if (!isUnlocked) {
    return <RoutePending />
  }

  return <>{children}</>
}
