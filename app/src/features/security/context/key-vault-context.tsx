import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'

import { useAuthContext } from '@/features/auth'

import { useSecurityStatus } from '../hooks/useSecurityStatus'
import { useServerBackup, type ServerBackup } from '../hooks/useServerBackup'
import { getKeyManager, type E2EESetupResult } from '../lib/keys'

/** Result type from setup operation (re-exported for convenience) */
export type SetupResult = E2EESetupResult

export interface KeyVaultState {
  /** Whether KeyManager is initialized */
  isInitialized: boolean
  /** Whether security setup has been completed on the server */
  isSetupComplete: boolean
  /** Whether the session is unlocked (keys are in memory) */
  isUnlocked: boolean
  /** Whether local keys exist in IndexedDB (null = not yet checked) */
  hasLocalKeys: boolean | null
  /** Whether data is being loaded */
  loading: boolean
  /** Current error message */
  error: string | null
  /** Whether the user needs to complete security setup */
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
  /** Lock the session (keeps stored UMK) */
  lock: () => void
  /** Logout - clears keys from memory AND storage */
  logout: () => Promise<void>
  /** Set up encryption for a new user */
  setup: (passphrase: string) => Promise<SetupResult>
  /** Clear error state */
  clearError: () => void
}

const KeyVaultContext = createContext<KeyVaultState | null>(null)

export function KeyVaultProvider({ children }: { children: React.ReactNode }) {
  const { user, loading: authLoading, rememberMe } = useAuthContext()
  const { data: securityStatus, isLoading: statusLoading } = useSecurityStatus({ enabled: !!user })
  const { data: serverBackup, isLoading: backupLoading } = useServerBackup({ enabled: !!user })

  // Use ref to always get the latest rememberMe value in callbacks
  // This avoids stale closure issues where callbacks capture old values
  const rememberMeRef = useRef(rememberMe)
  useEffect(() => {
    rememberMeRef.current = rememberMe
  }, [rememberMe])

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
    // Use ref to get the latest rememberMe value (avoids stale closure)
    const shouldRemember = rememberMeRef.current === true
    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      await km.unlockWithPassphrase(passphrase, { rememberMe: shouldRemember })
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
    const shouldRemember = rememberMeRef.current === true
    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      await km.unlockWithRecoveryKey(mnemonic, { rememberMe: shouldRemember })
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

    const shouldRemember = rememberMeRef.current === true
    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      await km.restoreFromServer(passphrase, {
        encryptedKeysBundle: serverBackup.encryptedKeysBundle,
        salt: serverBackup.salt,
        kdfType: serverBackup.kdfType,
        kdfParams: serverBackup.kdfParams ?? {},
      }, { rememberMe: shouldRemember })
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

    const shouldRemember = rememberMeRef.current === true
    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      await km.restoreFromServerWithRecoveryKey(recoveryKey, {
        encryptedKeysBundle: serverBackup.encryptedKeysBundle,
        salt: serverBackup.salt,
        kdfType: serverBackup.kdfType,
        kdfParams: serverBackup.kdfParams ?? {},
      }, { rememberMe: shouldRemember })
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

  const logout = useCallback(async () => {
    const km = getKeyManager()
    await km.logout()
    setIsUnlocked(false)
    setHasLocalKeys(null) // Reset local keys state
  }, [])

  const setup = useCallback(async (passphrase: string): Promise<SetupResult> => {
    const shouldRemember = rememberMeRef.current === true
    setLoading(true)
    setError(null)
    try {
      const km = getKeyManager()
      const result = await km.setupE2EE(passphrase, { rememberMe: shouldRemember })
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
  // needsRestore = server has setup complete + server has backup + local has no keys
  const needsRestore = !!(
    securityStatus?.isSetupComplete &&
    serverBackup?.hasBackup &&
    hasLocalKeys === false
  )

  const value = useMemo<KeyVaultState>(
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
      logout,
      setup,
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
      logout,
      setup,
      clearError,
    ]
  )

  return <KeyVaultContext.Provider value={value}>{children}</KeyVaultContext.Provider>
}

export function useKeyVault(): KeyVaultState {
  const context = useContext(KeyVaultContext)
  if (!context) {
    throw new Error('useKeyVault must be used within KeyVaultProvider')
  }
  return context
}

