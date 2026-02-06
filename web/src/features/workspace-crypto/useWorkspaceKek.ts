/**
 * Hook for fetching and caching workspace KEK
 *
 * KEK is encrypted per-device using ECDH shared secret.
 * This provides per-device isolation for security.
 *
 * Uses module-level promise deduplication to prevent race conditions
 * (e.g. React Strict Mode double-mount creating two different KEKs).
 */

import { useState, useEffect, useCallback } from 'react'
import { encryptionApi, ApiError } from '@/shared/api'
import {
  base64UrlDecode,
  base64UrlEncode,
  generateKek,
  encryptKekForDevice,
  decryptKekFromDevice,
} from '@/shared/lib/crypto'
import type { DeviceKeyPair } from '@/shared/lib/crypto'

export interface UseWorkspaceKekResult {
  kek: Uint8Array | null
  isLoading: boolean
  error: Error | null
  refresh: () => Promise<void>
}

// Module-level cache for resolved KEKs (workspace_id -> KEK)
const kekCache = new Map<string, Uint8Array>()

// Module-level promise deduplication to prevent concurrent fetch/create races
const kekInitPromises = new Map<string, Promise<Uint8Array>>()

/**
 * Fetch or create KEK for a workspace (module-level, deduplicated).
 * Only one fetch/create will run per workspace at a time.
 */
async function fetchOrCreateKek(
  workspaceId: string,
  userId: string,
  deviceId: string,
  deviceKeys: DeviceKeyPair
): Promise<Uint8Array> {
  // Check cache first
  const cached = kekCache.get(workspaceId)
  if (cached) {
    return cached
  }

  // Deduplicate: if a fetch is already in-flight, join it
  const existing = kekInitPromises.get(workspaceId)
  if (existing) {
    return existing
  }

  const promise = (async () => {
    try {
      // Try to get existing KEK from server
      const response = await encryptionApi.getWorkspaceKey(workspaceId, deviceId)
      const encryptedKek = base64UrlDecode(response.encrypted_kek)
      const nonce = base64UrlDecode(response.nonce)
      const senderEcdhPublicKey = response.sender_ecdh_public_key
        ? base64UrlDecode(response.sender_ecdh_public_key)
        : deviceKeys.ecdhPublicKey
      const senderDeviceId = response.sender_device_id || deviceId

      const decryptedKek = decryptKekFromDevice(
        encryptedKek,
        nonce,
        deviceKeys.ecdhPrivateKey,
        senderEcdhPublicKey,
        workspaceId,
        userId,
        senderDeviceId,
        deviceId
      )

      kekCache.set(workspaceId, decryptedKek)
      return decryptedKek
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // No KEK exists — create one (workspace creator case)
        const newKek = generateKek()

        const { encryptedKek, nonce } = encryptKekForDevice(
          newKek,
          deviceKeys.ecdhPrivateKey,
          deviceKeys.ecdhPublicKey,
          workspaceId,
          userId,
          deviceId,
          deviceId
        )

        await encryptionApi.saveWorkspaceKey(workspaceId, {
          device_id: deviceId,
          sender_device_id: deviceId,
          encrypted_kek: base64UrlEncode(encryptedKek),
          nonce: base64UrlEncode(nonce),
          is_active: true,
        })

        kekCache.set(workspaceId, newKek)
        return newKek
      }
      throw err
    } finally {
      kekInitPromises.delete(workspaceId)
    }
  })()

  kekInitPromises.set(workspaceId, promise)
  return promise
}

/**
 * Hook to fetch and cache workspace KEK
 *
 * @param workspaceId Workspace ID
 * @param userId User ID (from AuthContext)
 * @param deviceId Current device ID (from AuthContext)
 * @param deviceKeys Current device key pair (from AuthContext)
 */
export function useWorkspaceKek(
  workspaceId: string | null | undefined,
  userId: string | null | undefined,
  deviceId: string | null | undefined,
  deviceKeys: DeviceKeyPair | null | undefined
): UseWorkspaceKekResult {
  const [kek, setKek] = useState<Uint8Array | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  const fetchKek = useCallback(async () => {
    if (!workspaceId || !userId || !deviceId || !deviceKeys) {
      setKek(null)
      return
    }

    // Fast path: already cached
    const cached = kekCache.get(workspaceId)
    if (cached) {
      setKek(cached)
      return
    }

    setIsLoading(true)
    setError(null)

    try {
      const result = await fetchOrCreateKek(workspaceId, userId, deviceId, deviceKeys)
      setKek(result)
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to fetch workspace key'))
    } finally {
      setIsLoading(false)
    }
  }, [workspaceId, userId, deviceId, deviceKeys])

  // Fetch on mount and when dependencies change
  useEffect(() => {
    fetchKek()
  }, [fetchKek])

  return {
    kek,
    isLoading,
    error,
    refresh: fetchKek,
  }
}

/**
 * Clear KEK cache for a workspace (call on logout or workspace change)
 */
export function clearKekCache(workspaceId?: string) {
  if (workspaceId) {
    kekCache.delete(workspaceId)
  } else {
    kekCache.clear()
  }
}
