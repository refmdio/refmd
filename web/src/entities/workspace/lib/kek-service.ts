/**
 * KEK Service
 *
 * KEK (Key Encryption Key) lifecycle orchestration: fetch, decrypt, restore, create.
 * Stateless reusable operations are in kek-ops.ts. Cache and deduplication are in kek-cache.ts.
 *
 * Flow:
 * 1. Try device ECDH key -> success: backfill UMK backup if needed
 * 2. 404 -> Try UMK backup -> success: re-wrap for device via ECDH
 * 3. 404 -> Generate new KEK + save device key + save UMK backup
 */

import { encryptionApi, ApiError } from '@/shared/api'
import {
  base64UrlDecode,
  base64UrlEncode,
  generateKek,
  encryptKekForDevice,
  unwrapKekWithUmk,
} from '@/shared/lib/crypto'
import type { DeviceKeyPair } from '@/shared/lib/crypto'
import { assertAndPinKeyVersion, assertNoRollbackOn404 } from '@/shared/lib/anti-rollback'
import { kekCache } from './kek-cache'
import { encryptAndSaveKekForDevice, fetchAndDecryptKek, wrapAndSaveKekBackup } from './kek-ops'

export { clearKekCache } from './kek-cache'
export { encryptAndSaveKekForDevice, fetchAndDecryptKek, wrapAndSaveKekBackup, type DecryptedWorkspaceKek } from './kek-ops'

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
        await wrapAndSaveKekBackup(kek, umk, workspaceId, userId, keyVersion)
      } catch {
        // Backfill is fire-and-forget
      }
    } else {
      // Non-404 error — skip backfill
    }
  }
}

/**
 * Decrypt KEK from device ECDH key, with TOFU verification and anti-rollback.
 * Caches result and backfills UMK backup if one doesn't exist yet.
 */
async function decryptKekViaDevice(
  workspaceId: string,
  userId: string,
  deviceId: string,
  deviceKeys: DeviceKeyPair,
  umk: Uint8Array | null | undefined
): Promise<Uint8Array> {
  const { kek, keyVersion } = await fetchAndDecryptKek(workspaceId, userId, deviceId, deviceKeys)

  kekCache.setValue(workspaceId, kek)

  // Fire-and-forget: backfill UMK backup for existing workspaces
  if (umk) {
    backfillKekBackup(workspaceId, userId, kek, umk, keyVersion)
  }

  return kek
}

/**
 * Restore KEK from UMK backup, re-wrap for this device via ECDH, and save.
 */
async function restoreKekFromUmkBackup(
  workspaceId: string,
  userId: string,
  deviceId: string,
  deviceKeys: DeviceKeyPair,
  umk: Uint8Array
): Promise<Uint8Array> {
  const backupResponse = await encryptionApi.getWorkspaceKekBackup(workspaceId)
  const encryptedKek = base64UrlDecode(backupResponse.encrypted_kek)
  const backupNonce = base64UrlDecode(backupResponse.nonce)

  const restoredKek = unwrapKekWithUmk(
    encryptedKek,
    backupNonce,
    umk,
    workspaceId,
    userId,
    backupResponse.key_version
  )

  // Anti-rollback: check KEK version BEFORE any side effects
  await assertAndPinKeyVersion('kek', workspaceId, backupResponse.key_version)

  // Re-wrap for this device via ECDH and save
  await encryptAndSaveKekForDevice(
    restoredKek,
    deviceKeys.ecdhPrivateKey,
    deviceKeys.ecdhPublicKey,
    deviceId,
    workspaceId,
    userId,
    deviceId,
    backupResponse.key_version
  )

  kekCache.setValue(workspaceId, restoredKek)
  return restoredKek
}

/**
 * Generate a new KEK, save device key + UMK backup.
 * Server rejects with 409 if keys already exist (prevents key fork).
 */
async function createNewKek(
  workspaceId: string,
  userId: string,
  deviceId: string,
  deviceKeys: DeviceKeyPair,
  umk: Uint8Array | null | undefined
): Promise<Uint8Array> {
  // Anti-rollback: if we previously observed a version, 404 means server rollback
  await assertNoRollbackOn404('kek', workspaceId)

  const newKek = generateKek()

  // createNewKek uses inline encrypt+save because the server assigns key_version
  // (unlike restoreKekFromUmkBackup which knows the version and uses encryptAndSaveKekForDevice)
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
    await assertAndPinKeyVersion('kek', workspaceId, saveResponse.key_version)

    // Save UMK backup for the new KEK
    if (umk) {
      await wrapAndSaveKekBackup(newKek, umk, workspaceId, userId, saveResponse.key_version)
    }

    kekCache.setValue(workspaceId, newKek)
    return newKek
  } catch (saveErr) {
    if (saveErr instanceof ApiError && saveErr.status === 409) {
      throw new Error(
        `Workspace ${workspaceId} already has encryption keys. ` +
        `Please access from an existing device to distribute keys to this device.`
      )
    }
    throw saveErr
  }
}

/** Try an async operation, returning null on 404. Rethrows all other errors. */
async function tryOr404Null<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn()
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null
    throw err
  }
}

/**
 * Try restoring KEK from UMK backup. Returns null on 404.
 * Wraps restoreKekFromUmkBackup with clearer error messages for non-404 failures.
 */
async function tryRestoreFromBackup(
  workspaceId: string,
  userId: string,
  deviceId: string,
  deviceKeys: DeviceKeyPair,
  umk: Uint8Array
): Promise<Uint8Array | null> {
  try {
    return await restoreKekFromUmkBackup(workspaceId, userId, deviceId, deviceKeys, umk)
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null
    if (err instanceof ApiError) {
      throw new Error(
        `Failed to fetch KEK backup for workspace ${workspaceId} (HTTP ${err.status}). ` +
        `Cannot determine if KEK exists. Retry later.`
      )
    }
    throw new Error(
      `Failed to decrypt KEK backup for workspace ${workspaceId}. ` +
      `This may indicate a UMK mismatch. Do not create a new KEK.`
    )
  }
}

/**
 * Fetch or create KEK for a workspace (module-level, deduplicated).
 * Only one fetch/create will run per workspace at a time.
 *
 * Flow:
 * 1. Try device ECDH key -> success: backfill UMK backup if needed
 * 2. 404 -> Try UMK backup -> success: re-wrap for device via ECDH
 * 3. 404 -> Generate new KEK + save device key + save UMK backup
 */
export async function fetchOrCreateKek(
  workspaceId: string,
  userId: string,
  deviceId: string,
  deviceKeys: DeviceKeyPair,
  umk: Uint8Array | null | undefined
): Promise<Uint8Array> {
  const cached = kekCache.getValue(workspaceId)
  if (cached) return cached

  const existing = kekCache.getPromise(workspaceId)
  if (existing) return existing

  const promise = (async () => {
    try {
      // Strategy 1: Decrypt via device ECDH key
      const deviceResult = await tryOr404Null(() =>
        decryptKekViaDevice(workspaceId, userId, deviceId, deviceKeys, umk)
      )
      if (deviceResult) return deviceResult

      // Strategy 2: Restore from UMK backup
      if (umk) {
        const backupResult = await tryRestoreFromBackup(workspaceId, userId, deviceId, deviceKeys, umk)
        if (backupResult) return backupResult
      }

      // Strategy 3: Create new KEK (workspace creator case)
      return await createNewKek(workspaceId, userId, deviceId, deviceKeys, umk)
    } finally {
      kekCache.removePromise(workspaceId)
    }
  })()

  kekCache.setPromise(workspaceId, promise)
  return promise
}
