/**
 * Hook for fetching and caching workspace KEK
 *
 * KEK is encrypted per-device using ECDH shared secret.
 * This provides per-device isolation for security.
 */

import { useState, useEffect, useCallback, useRef } from 'react'
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

// In-memory cache for KEKs (workspace_id -> KEK)
const kekCache = new Map<string, Uint8Array>()

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
  const fetchingRef = useRef(false)

  const fetchKek = useCallback(async () => {
    if (!workspaceId || !userId || !deviceId || !deviceKeys) {
      setKek(null)
      return
    }

    // Check cache first
    const cached = kekCache.get(workspaceId)
    if (cached) {
      setKek(cached)
      return
    }

    // Prevent concurrent fetches
    if (fetchingRef.current) {
      return
    }

    fetchingRef.current = true
    setIsLoading(true)
    setError(null)

    try {
      // Try to get existing KEK from server (device-specific)
      const response = await encryptionApi.getWorkspaceKey(workspaceId, deviceId)
      const encryptedKek = base64UrlDecode(response.encrypted_kek)
      const nonce = base64UrlDecode(response.nonce)
      const senderEcdhPublicKey = response.sender_ecdh_public_key
        ? base64UrlDecode(response.sender_ecdh_public_key)
        : deviceKeys.ecdhPublicKey // Self-wrapped (same device)
      const senderDeviceId = response.sender_device_id || deviceId

      // Decrypt KEK with ECDH shared secret
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

      // Cache and set
      kekCache.set(workspaceId, decryptedKek)
      setKek(decryptedKek)
    } catch (err) {
      // If 404, generate new KEK (workspace creator case)
      if (err instanceof ApiError && err.status === 404) {
        try {
          // Generate new KEK (32 bytes)
          const newKek = generateKek()

          // Wrap with own device ECDH (self-wrapped)
          const { encryptedKek, nonce } = encryptKekForDevice(
            newKek,
            deviceKeys.ecdhPrivateKey,
            deviceKeys.ecdhPublicKey,
            workspaceId,
            userId,
            deviceId,
            deviceId
          )

          // Save to server with device_id
          await encryptionApi.saveWorkspaceKey(workspaceId, {
            device_id: deviceId,
            sender_device_id: deviceId,
            encrypted_kek: base64UrlEncode(encryptedKek),
            nonce: base64UrlEncode(nonce),
            is_active: true,
          })

          // Cache and set
          kekCache.set(workspaceId, newKek)
          setKek(newKek)
        } catch (saveErr) {
          setError(saveErr instanceof Error ? saveErr : new Error('Failed to create workspace key'))
        }
      } else {
        setError(err instanceof Error ? err : new Error('Failed to fetch workspace key'))
      }
    } finally {
      setIsLoading(false)
      fetchingRef.current = false
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
