/**
 * DSK UMK — UMK wrap/unwrap with DSK and session cache management
 *
 * Handles wrapping/unwrapping the User Master Key (UMK) with the
 * Device Storage Key (DSK) for local KMSI (Keep Me Signed In).
 */

import { buildAad, AAD_PURPOSE } from './aad'
import { SIGNATURE_PROTOCOL } from './signature'
import {
  dbGet, dbSet, dbDelete,
  DSK_KEY, WRAPPED_UMK_KEY, DEVICE_KEYS_KEY, DEVICE_ID_KEY,
} from './dsk-store'

/**
 * Wrapped UMK structure stored in IndexedDB
 */
interface WrappedUmkData {
  ciphertext: ArrayBuffer
  nonce: Uint8Array
  userId: string
}

/**
 * Build AAD for DSK UMK cache
 */
function buildDskUmkCacheAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DSK_UMK_CACHE,
    user_id: userId,
  })
}

/**
 * Wrap UMK with DSK and store in IndexedDB
 *
 * @param umk User Master Key (32 bytes)
 * @param dsk Device Storage Key
 * @param userId User ID for AAD binding
 */
export async function wrapAndStoreUmk(
  umk: Uint8Array,
  dsk: CryptoKey,
  userId: string
): Promise<void> {
  const nonce = crypto.getRandomValues(new Uint8Array(12)) // AES-GCM uses 12-byte nonce
  const aad = buildDskUmkCacheAad(userId)

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce as Uint8Array<ArrayBuffer>,
      additionalData: aad as Uint8Array<ArrayBuffer>,
    },
    dsk,
    umk as Uint8Array<ArrayBuffer>
  )

  const wrappedData: WrappedUmkData = {
    ciphertext,
    nonce,
    userId,
  }

  await dbSet(WRAPPED_UMK_KEY, wrappedData)
}

/**
 * Load and unwrap UMK from IndexedDB
 *
 * @param dsk Device Storage Key
 * @returns Unwrapped UMK and userId, or null if not found
 */
export async function loadAndUnwrapUmk(
  dsk: CryptoKey
): Promise<{ umk: Uint8Array; userId: string } | null> {
  const wrappedData = await dbGet<WrappedUmkData>(WRAPPED_UMK_KEY)
  if (!wrappedData) {
    return null
  }

  const aad = buildDskUmkCacheAad(wrappedData.userId)

  try {
    const umkBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: wrappedData.nonce as Uint8Array<ArrayBuffer>,
        additionalData: aad as Uint8Array<ArrayBuffer>,
      },
      dsk,
      wrappedData.ciphertext
    )

    return {
      umk: new Uint8Array(umkBuffer),
      userId: wrappedData.userId,
    }
  } catch {
    // Decryption failed (corrupted or tampered)
    return null
  }
}

/**
 * Clear UMK cache from IndexedDB
 *
 * Use this when rememberMe is disabled. DSK, device keys, and device_id
 * are preserved to maintain device identity and allow device key operations.
 *
 * Note: DSK is required to decrypt device keys, so it must be preserved
 * even when UMK cache is cleared.
 */
export async function clearSessionCache(): Promise<void> {
  await dbDelete(WRAPPED_UMK_KEY)
}

/**
 * Clear all DSK-related data from IndexedDB (call on secure logout)
 *
 * This removes all local cryptographic material including device keys.
 * Use clearSessionCache() for normal logout to preserve device identity.
 */
export async function clearDskData(): Promise<void> {
  await Promise.all([
    dbDelete(DSK_KEY),
    dbDelete(WRAPPED_UMK_KEY),
    dbDelete(DEVICE_KEYS_KEY),
    dbDelete(DEVICE_ID_KEY),
  ])
}

/**
 * Check if DSK and wrapped UMK exist in IndexedDB
 */
export async function hasCachedSession(): Promise<boolean> {
  const [dsk, wrappedUmk] = await Promise.all([
    dbGet<CryptoKey>(DSK_KEY),
    dbGet<WrappedUmkData>(WRAPPED_UMK_KEY),
  ])
  return dsk !== undefined && wrappedUmk !== undefined
}
