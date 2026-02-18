/**
 * Shared Key Persistence Helpers
 *
 * Consolidates DSK persistence and PDK re-wrap patterns
 * shared between login and session restoration flows.
 */

import {
  ensureDsk,
  loadDsk,
  wrapAndStoreDeviceKeys,
  loadAndUnwrapDeviceKeys,
  wrapAndStoreUmk,
  updatePdkWraps,
  unwrapPdkDeviceKeys,
  deriveEcdhPublicKey,
  deriveSigningPublicKey,
  type DeviceKeyPair,
} from '@/shared/lib/crypto'

export { ensureDsk, updatePdkWraps }

/**
 * Ensure device keys are persisted to DSK storage.
 * Reuses an existing DSK if available, otherwise creates a new one.
 * Optionally also wraps UMK with the DSK.
 */
export async function persistDeviceKeysToDsk(
  deviceKeys: DeviceKeyPair,
  userId: string,
  umk?: Uint8Array
): Promise<void> {
  const dsk = await ensureDsk()
  if (dsk) {
    await wrapAndStoreDeviceKeys(deviceKeys, dsk, userId)
    if (umk) {
      await wrapAndStoreUmk(umk, dsk, userId)
    }
  }
}

/**
 * Load device keys from DSK storage and verify userId.
 * Common pattern shared by login and session restoration.
 */
export async function loadDeviceKeysFromDsk(userId: string): Promise<DeviceKeyPair | null> {
  const dsk = await loadDsk()
  if (!dsk) return null

  const data = await loadAndUnwrapDeviceKeys(dsk)
  if (!data || data.userId !== userId) return null

  return {
    ecdhPrivateKey: data.ecdhPrivateKey,
    ecdhPublicKey: data.ecdhPublicKey,
    signingPrivateKey: data.signingPrivateKey,
    signingPublicKey: data.signingPublicKey,
  }
}

/**
 * Reconstruct a full DeviceKeyPair from PDK-wrapped private keys.
 * Derives public keys from private keys to build the complete key pair.
 */
export function buildDeviceKeyPairFromPdk(pdkKeys: {
  ecdhPrivateKey: Uint8Array
  signingPrivateKey: Uint8Array
}): DeviceKeyPair {
  return {
    ecdhPrivateKey: pdkKeys.ecdhPrivateKey,
    ecdhPublicKey: deriveEcdhPublicKey(pdkKeys.ecdhPrivateKey),
    signingPrivateKey: pdkKeys.signingPrivateKey,
    signingPublicKey: deriveSigningPublicKey(pdkKeys.signingPrivateKey),
  }
}

/**
 * Resolve device keys using DSK-first, PDK-fallback strategy.
 *
 * Shared between login and session restoration flows:
 * 1. Try loading from DSK (IndexedDB)
 * 2. Fall back to PDK-wrapped keys with userId/deviceId validation
 * 3. If PDK succeeds, migrate keys to DSK for future use
 *
 * Returns null if no device keys are available from either source.
 */
export async function resolveDeviceKeysWithPdkFallback(params: {
  pdk: Uint8Array
  userId: string
  deviceId: string
}): Promise<DeviceKeyPair | null> {
  const fromDsk = await loadDeviceKeysFromDsk(params.userId)
  if (fromDsk) return fromDsk

  const pdkKeys = unwrapPdkDeviceKeys(params.pdk)
  if (!pdkKeys || pdkKeys.userId !== params.userId || pdkKeys.deviceId !== params.deviceId) {
    return null
  }

  const deviceKeys = buildDeviceKeyPairFromPdk(pdkKeys)
  await persistDeviceKeysToDsk(deviceKeys, params.userId)
  return deviceKeys
}
