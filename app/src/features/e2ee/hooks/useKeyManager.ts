import { useCallback, useEffect, useState, useSyncExternalStore } from 'react'

import { getKeyManager, type E2EESetupResult } from '@/features/e2ee'

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
 * Hook to interact with the KeyManager.
 * Provides methods for E2EE setup, unlock, and lock operations.
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
   * Set up E2EE with a new passphrase.
   * @returns Setup result including recovery key
   */
  const setupE2EE = useCallback(async (passphrase: string): Promise<E2EESetupResult> => {
    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      const result = await km.setupE2EE(passphrase)
      updateSnapshot()
      return result
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Setup failed'
      setError(message)
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  /**
   * Unlock the session with a passphrase.
   */
  const unlock = useCallback(async (passphrase: string): Promise<void> => {
    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      await km.unlockWithPassphrase(passphrase)
      updateSnapshot()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unlock failed'
      setError(message)
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  /**
   * Unlock the session with a recovery key.
   */
  const unlockWithRecoveryKey = useCallback(async (mnemonic: string): Promise<void> => {
    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      await km.unlockWithRecoveryKey(mnemonic)
      updateSnapshot()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Recovery failed'
      setError(message)
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  /**
   * Lock the session.
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
    setupE2EE,
    unlock,
    unlockWithRecoveryKey,
    lock,
    changePassphrase,
    verifyPassphrase,
    hasKeys,
    clearError: () => setError(null),
  }
}
