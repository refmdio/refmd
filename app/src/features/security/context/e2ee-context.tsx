import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

import { useAuthContext } from '@/features/auth'

import { getKeyManager, type E2EESetupResult } from '../lib/keys'
import { useSecurityStatus } from '../hooks/useSecurityStatus'
import { useServerBackup, type ServerBackup } from '../hooks/useServerBackup'

export interface E2EEState {
  /** Whether KeyManager is initialized */
  isInitialized: boolean
  /** Whether E2EE setup has been completed on the server */
  isSetupComplete: boolean
  /** Whether the session is unlocked (keys are in memory) */
  isUnlocked: boolean
  /** Whether local keys exist in IndexedDB (null = not yet checked) */
  hasLocalKeys: boolean | null
  /** Whether data is being loaded */
  loading: boolean
  /** Current error message */
  error: string | null
  /** Whether the user needs to complete E2EE setup */
  needsSetup: boolean
  /** Whether the user needs to migrate existing data */
  needsMigration: boolean
  /** Whether keys need to be restored from server (new device) */
  needsRestore: boolean
  /** Server backup data (if available) */
  serverBackup: ServerBackup | null
  /** Unlock the session with a passphrase */
  unlock: (passphrase: string) => Promise<void>
  /** Unlock the session with a recovery key */
  unlockWithRecovery: (mnemonic: string) => Promise<void>
  /** Restore keys from server with passphrase */
  restoreFromServer: (passphrase: string) => Promise<void>
  /** Restore keys from server with recovery key */
  restoreFromServerWithRecoveryKey: (recoveryKey: string) => Promise<void>
  /** Lock the session */
  lock: () => void
  /** Set up E2EE for a new user */
  setupE2EE: (passphrase: string) => Promise<E2EESetupResult>
  /** Clear error state */
  clearError: () => void
}

const E2EEContext = createContext<E2EEState | null>(null)

export function E2EEProvider({ children }: { children: React.ReactNode }) {
  const { user, loading: authLoading } = useAuthContext()
  const { data: securityStatus, isLoading: statusLoading } = useSecurityStatus({ enabled: !!user })
  const { data: serverBackup, isLoading: backupLoading } = useServerBackup({ enabled: !!user })

  const [isInitialized, setIsInitialized] = useState(false)
  const [isUnlocked, setIsUnlocked] = useState(false)
  const [hasLocalKeys, setHasLocalKeys] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Initialize KeyManager when user is authenticated
  useEffect(() => {
    if (!user) {
      setIsInitialized(false)
      setIsUnlocked(false)
      setHasLocalKeys(null)
      return
    }

    const km = getKeyManager()
    km.initialize().then(async () => {
      setIsInitialized(true)
      setIsUnlocked(km.isUnlocked)
      // Check if local keys exist
      const hasKeys = await km.hasKeys()
      setHasLocalKeys(hasKeys)
    })
  }, [user])

  // Lock when user logs out (not during auth loading)
  useEffect(() => {
    // Only lock if auth is done loading AND user is definitely logged out
    if (!authLoading && !user && isUnlocked) {
      const km = getKeyManager()
      km.lock()
      setIsUnlocked(false)
    }
  }, [authLoading, user, isUnlocked])

  // Subscribe to unlock state changes
  useEffect(() => {
    if (!isInitialized) return

    const km = getKeyManager()
    return km.onUnlockChange(() => {
      setIsUnlocked(km.isUnlocked)
    })
  }, [isInitialized])

  const unlock = useCallback(async (passphrase: string) => {
    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      await km.unlockWithPassphrase(passphrase)
      setIsUnlocked(true)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to unlock'
      setError(message)
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const unlockWithRecovery = useCallback(async (mnemonic: string) => {
    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      await km.unlockWithRecoveryKey(mnemonic)
      setIsUnlocked(true)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Recovery failed'
      setError(message)
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const restoreFromServer = useCallback(async (passphrase: string) => {
    if (!serverBackup?.hasBackup || !serverBackup.encryptedKeysBundle || !serverBackup.salt || !serverBackup.kdfType) {
      throw new Error('No server backup available')
    }

    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      await km.restoreFromServer(passphrase, {
        encryptedKeysBundle: serverBackup.encryptedKeysBundle,
        salt: serverBackup.salt,
        kdfType: serverBackup.kdfType,
        kdfParams: serverBackup.kdfParams ?? {},
      })
      setIsUnlocked(true)
      setHasLocalKeys(true)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Restore failed'
      setError(message)
      throw err
    } finally {
      setLoading(false)
    }
  }, [serverBackup])

  const restoreFromServerWithRecoveryKey = useCallback(async (recoveryKey: string) => {
    if (!serverBackup?.hasBackup || !serverBackup.encryptedKeysBundle || !serverBackup.salt || !serverBackup.kdfType) {
      throw new Error('No server backup available')
    }

    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      await km.restoreFromServerWithRecoveryKey(recoveryKey, {
        encryptedKeysBundle: serverBackup.encryptedKeysBundle,
        salt: serverBackup.salt,
        kdfType: serverBackup.kdfType,
        kdfParams: serverBackup.kdfParams ?? {},
      })
      setIsUnlocked(true)
      setHasLocalKeys(true)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Restore failed'
      setError(message)
      throw err
    } finally {
      setLoading(false)
    }
  }, [serverBackup])

  const lock = useCallback(() => {
    const km = getKeyManager()
    km.lock()
    setIsUnlocked(false)
  }, [])

  const setupE2EE = useCallback(async (passphrase: string): Promise<E2EESetupResult> => {
    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      const result = await km.setupE2EE(passphrase)
      setIsUnlocked(true)
      setHasLocalKeys(true) // Mark that local keys now exist
      return result
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Setup failed'
      setError(message)
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const clearError = useCallback(() => {
    setError(null)
  }, [])

  // Determine if restore from server is needed
  // needsRestore = server has E2EE setup + server has backup + local has no keys
  const needsRestore = !!(
    securityStatus?.isSetupComplete &&
    serverBackup?.hasBackup &&
    hasLocalKeys === false
  )

  const value = useMemo<E2EEState>(
    () => ({
      isInitialized,
      isSetupComplete: securityStatus?.isSetupComplete ?? false,
      isUnlocked,
      hasLocalKeys,
      loading: loading || statusLoading || backupLoading,
      error,
      needsSetup: securityStatus ? !securityStatus.isSetupComplete : false,
      needsMigration: securityStatus?.needsMigration ?? false,
      needsRestore,
      serverBackup: serverBackup ?? null,
      unlock,
      unlockWithRecovery,
      restoreFromServer,
      restoreFromServerWithRecoveryKey,
      lock,
      setupE2EE,
      clearError,
    }),
    [
      isInitialized,
      securityStatus,
      isUnlocked,
      hasLocalKeys,
      loading,
      statusLoading,
      backupLoading,
      error,
      needsRestore,
      serverBackup,
      unlock,
      unlockWithRecovery,
      restoreFromServer,
      restoreFromServerWithRecoveryKey,
      lock,
      setupE2EE,
      clearError,
    ]
  )

  return <E2EEContext.Provider value={value}>{children}</E2EEContext.Provider>
}

export function useE2EE(): E2EEState {
  const context = useContext(E2EEContext)
  if (!context) {
    throw new Error('useE2EE must be used within E2EEProvider')
  }
  return context
}
