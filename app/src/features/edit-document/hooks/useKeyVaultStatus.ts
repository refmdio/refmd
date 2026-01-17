import * as React from 'react'

import { useAuthContext } from '@/features/auth'
import { getKeyManager, SessionLockedError, useKeyVault } from '@/features/security'

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

export type UseKeyVaultStatusOptions = {
  enabled: boolean
  shareToken?: string
  useUrlShareTokenFallback: boolean
}

export type UseKeyVaultStatusReturn = {
  /** null = checking, true = unlocked or not needed, false = locked */
  keyVaultUnlocked: boolean | null
  /** true if user needs to unlock KeyVault to continue */
  needsKeyVaultUnlock: boolean
  /** Call after user unlocks to retry the check */
  retryKeyVaultCheck: () => void
}

/**
 * Hook to check KeyVault unlock status before establishing connections.
 * Returns whether KeyVault is unlocked or if unlock is required.
 */
export function useKeyVaultStatus(options: UseKeyVaultStatusOptions): UseKeyVaultStatusReturn {
  const { enabled, shareToken, useUrlShareTokenFallback } = options
  const { user, loading: authLoading } = useAuthContext()
  const { needsRestore, loading: keyVaultLoading } = useKeyVault()

  const [keyVaultUnlocked, setKeyVaultUnlocked] = React.useState<boolean | null>(null)
  const [needsKeyVaultUnlock, setNeedsKeyVaultUnlock] = React.useState(false)
  const [keyVaultCheckKey, setKeyVaultCheckKey] = React.useState(0)

  const retryKeyVaultCheck = React.useCallback(() => {
    setKeyVaultUnlocked(null)
    setNeedsKeyVaultUnlock(false)
    setKeyVaultCheckKey((k) => k + 1)
  }, [])

  React.useEffect(() => {
    if (!enabled) {
      setKeyVaultUnlocked(null)
      setNeedsKeyVaultUnlock(false)
      return
    }

    // Share token access doesn't require KeyVault unlock (share keys handle decryption)
    const token = resolveShareToken(shareToken, useUrlShareTokenFallback)
    if (token) {
      setKeyVaultUnlocked(true)
      setNeedsKeyVaultUnlock(false)
      return
    }

    // Wait for auth and KeyVault context to load
    if (authLoading || keyVaultLoading) {
      setKeyVaultUnlocked(null)
      setNeedsKeyVaultUnlock(false)
      return
    }

    // User not authenticated - don't attempt connection
    if (!user) {
      setKeyVaultUnlocked(null)
      setNeedsKeyVaultUnlock(false)
      return
    }

    // Reset state to pending before async check
    setKeyVaultUnlocked(null)
    setNeedsKeyVaultUnlock(false)

    let cancelled = false
    ;(async () => {
      try {
        const keyManager = getKeyManager()
        await keyManager.initialize()

        // Check if encryption is set up for this user
        const hasKeys = await keyManager.hasKeys()

        if (!hasKeys) {
          // No local keys - check if we need to restore from server
          // Skip needsRestore check if this is a retry (keyVaultCheckKey > 0)
          // because the user just completed restore and context might not be updated yet
          if (keyVaultCheckKey === 0 && needsRestore) {
            // First check and needs restore - show unlock prompt
            if (!cancelled) {
              setKeyVaultUnlocked(false)
              setNeedsKeyVaultUnlock(true)
            }
            return
          }
          // Encryption not set up or just restored - allow connection
          if (!cancelled) {
            setKeyVaultUnlocked(true)
            setNeedsKeyVaultUnlock(false)
          }
          return
        }

        // Encryption is set up - check if session is unlocked
        if (keyManager.isUnlocked) {
          if (!cancelled) {
            setKeyVaultUnlocked(true)
            setNeedsKeyVaultUnlock(false)
          }
        } else {
          // Session locked - need unlock
          if (!cancelled) {
            setKeyVaultUnlocked(false)
            setNeedsKeyVaultUnlock(true)
          }
        }
      } catch (err) {
        if (cancelled) return
        if (err instanceof SessionLockedError) {
          setKeyVaultUnlocked(false)
          setNeedsKeyVaultUnlock(true)
        } else {
          // Other errors - allow connection attempt
          setKeyVaultUnlocked(true)
          setNeedsKeyVaultUnlock(false)
        }
      }
    })()

    return () => {
      cancelled = true
    }
  }, [enabled, shareToken, useUrlShareTokenFallback, authLoading, keyVaultLoading, user, needsRestore, keyVaultCheckKey])

  return {
    keyVaultUnlocked,
    needsKeyVaultUnlock,
    retryKeyVaultCheck,
  }
}

