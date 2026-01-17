import { useCallback, useEffect, useState, useSyncExternalStore } from 'react'

import { getKeyManager } from '@/features/security'

// External store for KeyManager state
let listeners: Set<() => void> = new Set()
let snapshot = {
  isInitialized: false,
  isUnlocked: false,
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function getSnapshot() {
  return snapshot
}

function updateSnapshot() {
  const km = getKeyManager()
  const newSnapshot = {
    isInitialized: km.isInitialized,
    isUnlocked: km.isUnlocked,
  }
  if (
    newSnapshot.isInitialized !== snapshot.isInitialized ||
    newSnapshot.isUnlocked !== snapshot.isUnlocked
  ) {
    snapshot = newSnapshot
    listeners.forEach((listener) => listener())
  }
}

/**
 * Low-level hook for KeyManager operations that do NOT require rememberMe.
 *
 * For operations that require rememberMe (unlock, setup, restore), use useKeyVault instead.
 * This hook is only for:
 * - changePassphrase: Change the user's passphrase
 * - verifyPassphrase: Verify if a passphrase is correct
 * - hasKeys: Check if keys exist
 * - lock: Lock the session (clear keys from memory only)
 */
export function useKeyManager() {
  const { isInitialized, isUnlocked } = useSyncExternalStore(subscribe, getSnapshot, getSnapshot)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  // Initialize KeyManager on mount
  useEffect(() => {
    const km = getKeyManager()
    if (!km.isInitialized) {
      km.initialize().then(() => {
        updateSnapshot()
      })
    }
  }, [])

  /**
   * Lock the session (clears keys from memory only, not storage).
   */
  const lock = useCallback(() => {
    const km = getKeyManager()
    km.lock()
    updateSnapshot()
  }, [])

  /**
   * Change the passphrase.
   * @returns New recovery key
   */
  const changePassphrase = useCallback(async (newPassphrase: string): Promise<string> => {
    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      const recoveryKey = await km.changePassphrase(newPassphrase)
      return recoveryKey
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Change failed'
      setError(message)
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  /**
   * Verify if a passphrase is correct.
   */
  const verifyPassphrase = useCallback(async (passphrase: string): Promise<boolean> => {
    try {
      const km = getKeyManager()
      return await km.verifyPassphrase(passphrase)
    } catch {
      return false
    }
  }, [])

  /**
   * Check if the user has stored keys.
   */
  const hasKeys = useCallback(async (): Promise<boolean> => {
    const km = getKeyManager()
    return km.hasKeys()
  }, [])

  return {
    isInitialized,
    isUnlocked,
    loading,
    error,
    lock,
    changePassphrase,
    verifyPassphrase,
    hasKeys,
    clearError: () => setError(null),
  }
}
