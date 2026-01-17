import { useQuery } from '@tanstack/react-query'

import {
  getMasterKeyBackup,
  getEncryptedPrivateKey,
  type MasterKeyBackupResponse,
  type EncryptedPrivateKeyResponse,
} from '@/entities/user'

import type { EncryptedKeysBundle } from '../lib/keys'

export interface ServerBackup {
  /** Whether server has backup data */
  hasBackup: boolean
  /** Encrypted keys bundle (if available) */
  encryptedKeysBundle: EncryptedKeysBundle | null
  /** Salt for KDF (base64) */
  salt: string | null
  /** KDF type */
  kdfType: 'argon2id' | 'pbkdf2' | null
  /** KDF parameters */
  kdfParams: {
    memory?: number | null
    iterations?: number | null
    parallelism?: number | null
  } | null
}

/**
 * Parse encrypted keys bundle from server response.
 */
function parseKeysBundle(response: EncryptedPrivateKeyResponse): EncryptedKeysBundle | null {
  try {
    // Check if it's our bundle format (nonce is base64 encoded 'bundle-v1')
    const expectedNonce = btoa('bundle-v1')
    if (response.nonce !== expectedNonce) {
      console.warn('[useServerBackup] Unknown nonce format:', response.nonce)
      return null
    }

    // Decode base64 and parse JSON
    const jsonStr = atob(response.encryptedPrivateKey)
    const bundle = JSON.parse(jsonStr) as EncryptedKeysBundle

    // Validate required fields
    if (
      !bundle.encryptedEcdhPrivateKey ||
      !bundle.encryptedEcdhPrivateKeyNonce ||
      !bundle.encryptedSigningPrivateKey ||
      !bundle.encryptedSigningPrivateKeyNonce ||
      !bundle.ecdhPublicKey ||
      !bundle.signingPublicKey
    ) {
      console.warn('[useServerBackup] Invalid bundle format')
      return null
    }

    return bundle
  } catch (err) {
    console.error('[useServerBackup] Failed to parse keys bundle:', err)
    return null
  }
}

/**
 * Hook to fetch server backup data for key restoration.
 */
export function useServerBackup(options?: { enabled?: boolean }) {
  const masterKeyQuery = useQuery({
    queryKey: ['security', 'master-key-backup'],
    queryFn: async () => {
      try {
        return await getMasterKeyBackup()
      } catch (err) {
        // 404 means no backup exists
        if ((err as { status?: number }).status === 404) {
          return null
        }
        throw err
      }
    },
    enabled: options?.enabled ?? true,
    staleTime: 30_000,
    retry: false,
  })

  const encryptedKeyQuery = useQuery({
    queryKey: ['security', 'encrypted-private-key'],
    queryFn: async () => {
      try {
        return await getEncryptedPrivateKey()
      } catch (err) {
        // 404 means no backup exists
        if ((err as { status?: number }).status === 404) {
          return null
        }
        throw err
      }
    },
    enabled: options?.enabled ?? true,
    staleTime: 30_000,
    retry: false,
  })

  const isLoading = masterKeyQuery.isLoading || encryptedKeyQuery.isLoading
  const error = masterKeyQuery.error ?? encryptedKeyQuery.error

  let data: ServerBackup | undefined

  if (!isLoading && masterKeyQuery.data !== undefined && encryptedKeyQuery.data !== undefined) {
    const masterKey = masterKeyQuery.data as MasterKeyBackupResponse | null
    const encryptedKey = encryptedKeyQuery.data as EncryptedPrivateKeyResponse | null

    if (masterKey && encryptedKey) {
      const bundle = parseKeysBundle(encryptedKey)
      data = {
        hasBackup: bundle !== null,
        encryptedKeysBundle: bundle,
        salt: masterKey.salt,
        kdfType: (masterKey.kdfType === 'argon2id' || masterKey.kdfType === 'pbkdf2')
          ? masterKey.kdfType
          : null,
        kdfParams: masterKey.kdfParams,
      }
    } else {
      data = {
        hasBackup: false,
        encryptedKeysBundle: null,
        salt: null,
        kdfType: null,
        kdfParams: null,
      }
    }
  }

  const refetch = () => {
    masterKeyQuery.refetch()
    encryptedKeyQuery.refetch()
  }

  return {
    data,
    isLoading,
    error: error as Error | null,
    refetch,
  }
}
