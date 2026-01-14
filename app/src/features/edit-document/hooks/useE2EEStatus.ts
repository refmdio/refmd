import * as React from 'react'

import { useAuthContext } from '@/features/auth'
import { getKeyManager, SessionLockedError, useE2EE } from '@/features/e2ee'

function normalizeShareToken(token?: string | null): string | undefined {
  if (typeof token !== 'string') return undefined
  const trimmed = token.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

function resolveShareToken(explicitToken: string | undefined, useUrlFallback: boolean): string | undefined {
  const normalized = normalizeShareToken(explicitToken)
  if (normalized) return normalized

  if (typeof window === 'undefined') return undefined
  if (!useUrlFallback) return undefined

  try {
    const candidate = new URLSearchParams(window.location.search).get('token')
    return normalizeShareToken(candidate)
  } catch {
    return undefined
  }
}

export type UseE2EEStatusOptions = {
  enabled: boolean
  shareToken?: string
  useUrlShareTokenFallback: boolean
}

export type UseE2EEStatusReturn = {
  /** null = checking, true = unlocked or not needed, false = locked */
  e2eeUnlocked: boolean | null
  /** true if user needs to unlock E2EE to continue */
  needsE2EEUnlock: boolean
  /** Call after user unlocks to retry the check */
  retryE2EECheck: () => void
}

/**
 * Hook to check E2EE unlock status before establishing connections.
 * Returns whether E2EE is unlocked or if unlock is required.
 */
export function useE2EEStatus(options: UseE2EEStatusOptions): UseE2EEStatusReturn {
  const { enabled, shareToken, useUrlShareTokenFallback } = options
  const { user, loading: authLoading } = useAuthContext()
  const { needsRestore, loading: e2eeLoading } = useE2EE()

  const [e2eeUnlocked, setE2eeUnlocked] = React.useState<boolean | null>(null)
  const [needsE2EEUnlock, setNeedsE2EEUnlock] = React.useState(false)
  const [e2eeCheckKey, setE2eeCheckKey] = React.useState(0)

  const retryE2EECheck = React.useCallback(() => {
    setE2eeUnlocked(null)
    setNeedsE2EEUnlock(false)
    setE2eeCheckKey((k) => k + 1)
  }, [])

  React.useEffect(() => {
    if (!enabled) {
      setE2eeUnlocked(null)
      setNeedsE2EEUnlock(false)
      return
    }

    // Share token access doesn't require E2EE unlock (share keys handle decryption)
    const token = resolveShareToken(shareToken, useUrlShareTokenFallback)
    if (token) {
      setE2eeUnlocked(true)
      setNeedsE2EEUnlock(false)
      return
    }

    // Wait for auth and E2EE context to load
    if (authLoading || e2eeLoading) {
      setE2eeUnlocked(null)
      setNeedsE2EEUnlock(false)
      return
    }

    // User not authenticated - don't attempt connection
    if (!user) {
      setE2eeUnlocked(null)
      setNeedsE2EEUnlock(false)
      return
    }

    // Reset state to pending before async E2EE check
    setE2eeUnlocked(null)
    setNeedsE2EEUnlock(false)

    let cancelled = false
    ;(async () => {
      try {
        const keyManager = getKeyManager()
        await keyManager.initialize()

        // Check if E2EE is set up for this user
        const hasKeys = await keyManager.hasKeys()

        if (!hasKeys) {
          // No local keys - check if we need to restore from server
          // Skip needsRestore check if this is a retry (e2eeCheckKey > 0)
          // because the user just completed restore and context might not be updated yet
          if (e2eeCheckKey === 0 && needsRestore) {
            // First check and needs restore - show unlock prompt
            if (!cancelled) {
              setE2eeUnlocked(false)
              setNeedsE2EEUnlock(true)
            }
            return
          }
          // E2EE not set up or just restored - allow connection
          if (!cancelled) {
            setE2eeUnlocked(true)
            setNeedsE2EEUnlock(false)
          }
          return
        }

        // E2EE is set up - check if session is unlocked
        if (keyManager.isUnlocked) {
          if (!cancelled) {
            setE2eeUnlocked(true)
            setNeedsE2EEUnlock(false)
          }
        } else {
          // Session locked - need unlock
          if (!cancelled) {
            setE2eeUnlocked(false)
            setNeedsE2EEUnlock(true)
          }
        }
      } catch (err) {
        if (cancelled) return
        if (err instanceof SessionLockedError) {
          setE2eeUnlocked(false)
          setNeedsE2EEUnlock(true)
        } else {
          // Other errors - allow connection attempt
          setE2eeUnlocked(true)
          setNeedsE2EEUnlock(false)
        }
      }
    })()

    return () => {
      cancelled = true
    }
  }, [enabled, shareToken, useUrlShareTokenFallback, authLoading, e2eeLoading, user, needsRestore, e2eeCheckKey])

  return {
    e2eeUnlocked,
    needsE2EEUnlock,
    retryE2EECheck,
  }
}
