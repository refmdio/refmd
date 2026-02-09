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
  wrapKekWithUmk,
  unwrapKekWithUmk,
  verifyTofu,
  handleTofuResult,
} from '@/shared/lib/crypto'
import type { DeviceKeyPair } from '@/shared/lib/crypto'
import { checkKeyVersionRollback, pinKeyVersion, getKeyVersionPin } from '@/shared/lib/anti-rollback'

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
 * Backfill UMK-wrapped KEK backup if one doesn't exist yet.
 * Fire-and-forget: failures are logged but don't block KEK usage.
 */
async function backfillKekBackup(
  workspaceId: string,
  userId: string,
  kek: Uint8Array,
  umk: Uint8Array,
  keyVersion: number
): Promise<void> {
  try {
    await encryptionApi.getWorkspaceKekBackup(workspaceId)
    // Backup already exists, nothing to do
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      try {
        const { encryptedKek, nonce } = wrapKekWithUmk(kek, umk, workspaceId, userId, keyVersion)
        await encryptionApi.saveWorkspaceKekBackup(workspaceId, {
          key_version: keyVersion,
          encrypted_kek: base64UrlEncode(encryptedKek),
          nonce: base64UrlEncode(nonce),
        })
      } catch (backfillErr) {
        // Distinguish crypto errors from API errors for debugging
        if (backfillErr instanceof ApiError) {
          console.warn('[KEK Backup] Backfill API error for workspace:', workspaceId, 'status:', backfillErr.status, backfillErr)
        } else {
          console.error('[KEK Backup] Backfill crypto error for workspace:', workspaceId, backfillErr)
        }
      }
    } else {
      // Non-404 error (API failure, auth issue, etc.) — log explicitly
      const status = err instanceof ApiError ? err.status : 'unknown'
      console.warn('[KEK Backup] Backfill check failed for workspace:', workspaceId, 'status:', status, err)
    }
  }
}

/**
 * Fetch or create KEK for a workspace (module-level, deduplicated).
 * Only one fetch/create will run per workspace at a time.
 *
 * Flow:
 * 1. Try device ECDH key → success: backfill UMK backup if needed
 * 2. 404 → Try UMK backup → success: re-wrap for device via ECDH
 * 3. 404 → Generate new KEK + save device key + save UMK backup
 */
async function fetchOrCreateKek(
  workspaceId: string,
  userId: string,
  deviceId: string,
  deviceKeys: DeviceKeyPair,
  umk: Uint8Array | null | undefined
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
      // Try to get existing KEK from server (device ECDH wrapped)
      const response = await encryptionApi.getWorkspaceKey(workspaceId, deviceId)
      const encryptedKek = base64UrlDecode(response.encrypted_kek)
      const nonce = base64UrlDecode(response.nonce)
      const senderEcdhPublicKey = response.sender_ecdh_public_key
        ? base64UrlDecode(response.sender_ecdh_public_key)
        : deviceKeys.ecdhPublicKey
      const senderDeviceId = response.sender_device_id || deviceId

      // TOFU verification: verify sender device before using its public key (fail-close)
      if (senderDeviceId !== deviceId) {
        if (!response.sender_signing_public_key) {
          throw new Error(
            'KEK sender signing public key missing. Cannot verify sender identity. Decryption aborted.'
          )
        }
        const senderSigningPublicKey = base64UrlDecode(response.sender_signing_public_key)
        const tofuResult = await verifyTofu(
          userId,
          senderDeviceId,
          senderSigningPublicKey,
          senderEcdhPublicKey
        )

        if (tofuResult.status === 'ecdh_key_mismatch') {
          throw new Error('KEK sender ECDH key mismatch. Decryption aborted for security.')
        }
        if (tofuResult.status === 'identity_key_changed') {
          throw new Error(
            'KEK sender identity key changed unexpectedly. ' +
            'Please verify your devices from a trusted device before continuing.'
          )
        }
        await handleTofuResult(tofuResult)
      }

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

      // Anti-rollback: check KEK version
      const kekRollback = await checkKeyVersionRollback('kek', workspaceId, response.key_version)
      if (kekRollback.rolledBack) {
        throw new Error(
          `KEK rollback detected for workspace ${workspaceId}: ` +
          `server returned v${response.key_version}, pinned v${kekRollback.pinnedVersion}`
        )
      }
      await pinKeyVersion({
        type: 'kek',
        id: workspaceId,
        highestVersion: response.key_version,
        observedAt: Date.now(),
      })

      kekCache.set(workspaceId, decryptedKek)

      // Fire-and-forget: backfill UMK backup for existing workspaces
      if (umk) {
        backfillKekBackup(workspaceId, userId, decryptedKek, umk, response.key_version)
      }

      return decryptedKek
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // No device key exists — try UMK backup first
        if (umk) {
          try {
            const backupResponse = await encryptionApi.getWorkspaceKekBackup(workspaceId)
            const encryptedKek = base64UrlDecode(backupResponse.encrypted_kek)
            const backupNonce = base64UrlDecode(backupResponse.nonce)

            // Decrypt KEK from UMK backup
            const restoredKek = unwrapKekWithUmk(
              encryptedKek,
              backupNonce,
              umk,
              workspaceId,
              userId,
              backupResponse.key_version
            )

            // Anti-rollback: check KEK version BEFORE any side effects
            const backupRollback = await checkKeyVersionRollback('kek', workspaceId, backupResponse.key_version)
            if (backupRollback.rolledBack) {
              throw new Error(
                `KEK rollback detected for workspace ${workspaceId}: ` +
                `backup returned v${backupResponse.key_version}, pinned v${backupRollback.pinnedVersion}`
              )
            }

            // Re-wrap for this device via ECDH and save
            const { encryptedKek: deviceEncKek, nonce: deviceNonce } = encryptKekForDevice(
              restoredKek,
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
              key_version: backupResponse.key_version,
              encrypted_kek: base64UrlEncode(deviceEncKek),
              nonce: base64UrlEncode(deviceNonce),
              is_active: true,
            })

            await pinKeyVersion({
              type: 'kek',
              id: workspaceId,
              highestVersion: backupResponse.key_version,
              observedAt: Date.now(),
            })

            kekCache.set(workspaceId, restoredKek)
            return restoredKek
          } catch (backupErr) {
            if (backupErr instanceof ApiError && backupErr.status === 404) {
              // No backup exists either — fall through to create new KEK
            } else if (backupErr instanceof ApiError) {
              // API error (auth, network, server) — do NOT fall through to create new KEK
              throw new Error(
                `Failed to fetch KEK backup for workspace ${workspaceId} (HTTP ${backupErr.status}). ` +
                `Cannot determine if KEK exists. Retry later.`
              )
            } else {
              // Crypto error (decryption failed) — backup exists but UMK mismatch
              throw new Error(
                `Failed to decrypt KEK backup for workspace ${workspaceId}. ` +
                `This may indicate a UMK mismatch. Do not create a new KEK.`
              )
            }
          }
        }

        // No KEK exists anywhere — try to create one (workspace creator case)
        // Server rejects with 409 if keys already exist (prevents key fork)

        // Anti-rollback: if we previously observed a version, 404 means server rollback
        const existingKekPin = await getKeyVersionPin('kek', workspaceId)
        if (existingKekPin) {
          throw new Error(
            `KEK rollback detected for workspace ${workspaceId}: ` +
            `server returned 404 but v${existingKekPin.highestVersion} was previously observed`
          )
        }

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

        try {
          const saveResponse = await encryptionApi.saveWorkspaceKey(workspaceId, {
            device_id: deviceId,
            sender_device_id: deviceId,
            encrypted_kek: base64UrlEncode(encryptedKek),
            nonce: base64UrlEncode(nonce),
            is_active: true,
          })

          // Anti-rollback: check + pin BEFORE any further side effects
          const newKekRollback = await checkKeyVersionRollback('kek', workspaceId, saveResponse.key_version)
          if (newKekRollback.rolledBack) {
            throw new Error(
              `KEK rollback detected for workspace ${workspaceId}: ` +
              `new KEK v${saveResponse.key_version}, pinned v${newKekRollback.pinnedVersion}`
            )
          }
          await pinKeyVersion({
            type: 'kek',
            id: workspaceId,
            highestVersion: saveResponse.key_version,
            observedAt: Date.now(),
          })

          // Save UMK backup for the new KEK
          if (umk) {
            const keyVersion = saveResponse.key_version
            const { encryptedKek: bkpKek, nonce: bkpNonce } = wrapKekWithUmk(
              newKek, umk, workspaceId, userId, keyVersion
            )
            await encryptionApi.saveWorkspaceKekBackup(workspaceId, {
              key_version: keyVersion,
              encrypted_kek: base64UrlEncode(bkpKek),
              nonce: base64UrlEncode(bkpNonce),
            })
          }

          kekCache.set(workspaceId, newKek)
          return newKek
        } catch (saveErr) {
          if (saveErr instanceof ApiError && saveErr.status === 409) {
            // KEK already exists but wasn't available via device key or backup.
            // This device needs KEK distributed from an existing device.
            throw new Error(
              `Workspace ${workspaceId} already has encryption keys. ` +
              `Please access from an existing device to distribute keys to this device.`
            )
          }
          throw saveErr
        }
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
 * @param umk User Master Key (for UMK backup restore/save)
 */
export function useWorkspaceKek(
  workspaceId: string | null | undefined,
  userId: string | null | undefined,
  deviceId: string | null | undefined,
  deviceKeys: DeviceKeyPair | null | undefined,
  umk: Uint8Array | null | undefined
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
      const result = await fetchOrCreateKek(workspaceId, userId, deviceId, deviceKeys, umk)
      setKek(result)
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to fetch workspace key'))
    } finally {
      setIsLoading(false)
    }
  }, [workspaceId, userId, deviceId, deviceKeys, umk])

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
