/**
 * Session Restore Hook
 *
 * Handles restoring the authenticated session from cached credentials.
 * Extracts session restoration logic from the authenticated layout.
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { useAuthContext } from '@/shared/context'
import { restoreSession, restoreSessionWithPdk } from '../lib/session'
import type { PdkFallbackRequired } from '../lib/session'
import { buildAuthState, buildDeviceState } from '@/shared/model/session-hydration'

interface UseSessionRestoreResult {
  isRestoring: boolean
  pdkFallback: PdkFallbackRequired | null
  handlePdkFallback: (password: string) => Promise<void>
  dismissPdkFallback: () => void
}

export function useSessionRestore(): UseSessionRestoreResult {
  const { auth, isAuthenticated, setFullSession } = useAuthContext()

  const [isRestoring, setIsRestoring] = useState(!isAuthenticated)
  const [pdkFallback, setPdkFallback] = useState<PdkFallbackRequired | null>(null)
  const restorationAttempted = useRef(false)

  useEffect(() => {
    // Only skip restoration if fully authenticated (not partial auth with umk=null)
    if (isAuthenticated && !restorationAttempted.current) {
      setIsRestoring(false)
      return
    }

    if (restorationAttempted.current) return

    restorationAttempted.current = true

    async function tryRestoreSession() {
      try {
        const result = await restoreSession()

        if (result && 'type' in result && result.type === 'pdk_fallback_required') {
          setPdkFallback(result)
          setIsRestoring(false)
          return
        }

        if (result && !('type' in result)) {
          setFullSession(
            buildAuthState(result),
            buildDeviceState(result.deviceData!),
          )
        }
        // If no result, isRestoring will become false and the
        // authenticated layout's safety-net redirect handles navigation.
      } catch {
        // Same: let the layout handle the redirect.
      } finally {
        setIsRestoring(false)
      }
    }

    tryRestoreSession()
  }, [auth, isAuthenticated, setFullSession])

  const handlePdkFallback = useCallback(async (password: string) => {
    if (!pdkFallback) return

    const result = await restoreSessionWithPdk(pdkFallback.email, password)
    if (!result) {
      throw new Error('Failed to restore session. Please check your password.')
    }

    setPdkFallback(null)
    setFullSession(
      buildAuthState(result),
      buildDeviceState(result),
    )
  }, [pdkFallback, setFullSession])

  const dismissPdkFallback = useCallback(() => {
    setPdkFallback(null)
  }, [])

  return {
    isRestoring,
    pdkFallback,
    handlePdkFallback,
    dismissPdkFallback,
  }
}
