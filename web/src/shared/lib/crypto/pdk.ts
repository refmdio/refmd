/**
 * PDK (Password Derived Key) Storage Module
 *
 * Fallback for environments where IndexedDB non-exportable keys (DSK) are not available.
 * Uses XChaCha20-Poly1305 to wrap device keys and UMK with PDK.
 *
 * Storage: localStorage (since IndexedDB non-exportable keys are the problem)
 *
 * Security note:
 * - PDK is derived from password via HKDF, so password re-entry is required to unwrap
 * - XSS can read localStorage, but XSS is considered a fatal breach (CSP is primary defense)
 * - This is strictly a fallback; DSK (non-exportable) is always preferred when available
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { buildAad, SIGNATURE_PROTOCOL, AAD_PURPOSE } from './aad'
import { base64UrlEncode, base64UrlDecode } from './encoding'

// localStorage keys
const LS_PREFIX = 'refmd-pdk-'
const LS_DEVICE_ECDH_KEY = `${LS_PREFIX}device-ecdh`
const LS_DEVICE_SIGNING_KEY = `${LS_PREFIX}device-signing`
const LS_UMK_KEY = `${LS_PREFIX}umk`

interface PdkWrappedBase {
  /** Base64url-encoded ciphertext */
  ct: string
  /** Base64url-encoded 24-byte nonce */
  n: string
  /** User ID used for AAD binding */
  uid: string
}

/** Device-key wrapped data includes device ID binding */
interface PdkWrappedDeviceData extends PdkWrappedBase {
  /** Device ID for cross-device mismatch detection */
  did: string
}

// =============================================================================
// AAD builders
// =============================================================================

function buildPdkDeviceEcdhAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.PDK_DEVICE_ECDH_PRIVATE,
    user_id: userId,
  })
}

function buildPdkDeviceSigningAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.PDK_DEVICE_SIGNING_PRIVATE,
    user_id: userId,
  })
}

function buildPdkUmkAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.PDK_UMK_WRAP,
    user_id: userId,
  })
}

// =============================================================================
// Core encrypt/decrypt
// =============================================================================

function pdkEncrypt(
  plaintext: Uint8Array,
  pdk: Uint8Array,
  aad: Uint8Array
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(24)
  const cipher = xchacha20poly1305(pdk, nonce, aad)
  const ciphertext = cipher.encrypt(plaintext)
  return { ciphertext, nonce }
}

function pdkDecrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  pdk: Uint8Array,
  aad: Uint8Array
): Uint8Array {
  const cipher = xchacha20poly1305(pdk, nonce, aad)
  return cipher.decrypt(ciphertext)
}

// =============================================================================
// localStorage helpers
// =============================================================================

function storeWrapped(key: string, data: PdkWrappedBase | PdkWrappedDeviceData): void {
  localStorage.setItem(key, JSON.stringify(data))
}

function loadWrapped<T extends PdkWrappedBase = PdkWrappedBase>(key: string): T | null {
  const raw = localStorage.getItem(key)
  if (!raw) return null
  try {
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

// =============================================================================
// Device key wrap/unwrap
// =============================================================================

/**
 * Wrap device keys with PDK and store in localStorage
 */
export function wrapAndStorePdkDeviceKeys(
  deviceKeys: {
    ecdhPrivateKey: Uint8Array
    signingPrivateKey: Uint8Array
  },
  pdk: Uint8Array,
  userId: string,
  deviceId: string
): void {
  // Wrap ECDH private key
  const ecdhAad = buildPdkDeviceEcdhAad(userId)
  const ecdhWrapped = pdkEncrypt(deviceKeys.ecdhPrivateKey, pdk, ecdhAad)
  storeWrapped(LS_DEVICE_ECDH_KEY, {
    ct: base64UrlEncode(ecdhWrapped.ciphertext),
    n: base64UrlEncode(ecdhWrapped.nonce),
    uid: userId,
    did: deviceId,
  })

  // Wrap signing private key
  const signingAad = buildPdkDeviceSigningAad(userId)
  const signingWrapped = pdkEncrypt(deviceKeys.signingPrivateKey, pdk, signingAad)
  storeWrapped(LS_DEVICE_SIGNING_KEY, {
    ct: base64UrlEncode(signingWrapped.ciphertext),
    n: base64UrlEncode(signingWrapped.nonce),
    uid: userId,
    did: deviceId,
  })
}

/**
 * Unwrap device keys from localStorage using PDK
 *
 * @returns Device private keys with userId and deviceId, or null if not found or decryption fails
 */
export function unwrapPdkDeviceKeys(
  pdk: Uint8Array
): {
  ecdhPrivateKey: Uint8Array
  signingPrivateKey: Uint8Array
  userId: string
  deviceId: string
} | null {
  const ecdhData = loadWrapped<PdkWrappedDeviceData>(LS_DEVICE_ECDH_KEY)
  const signingData = loadWrapped<PdkWrappedDeviceData>(LS_DEVICE_SIGNING_KEY)
  if (!ecdhData || !signingData) return null

  // Verify user and device consistency across both stored keys
  if (ecdhData.uid !== signingData.uid) return null
  if (!ecdhData.did || ecdhData.did !== signingData.did) return null

  try {
    const ecdhAad = buildPdkDeviceEcdhAad(ecdhData.uid)
    const ecdhPrivateKey = pdkDecrypt(
      base64UrlDecode(ecdhData.ct),
      base64UrlDecode(ecdhData.n),
      pdk,
      ecdhAad
    )

    const signingAad = buildPdkDeviceSigningAad(signingData.uid)
    const signingPrivateKey = pdkDecrypt(
      base64UrlDecode(signingData.ct),
      base64UrlDecode(signingData.n),
      pdk,
      signingAad
    )

    return { ecdhPrivateKey, signingPrivateKey, userId: ecdhData.uid, deviceId: ecdhData.did }
  } catch {
    return null
  }
}

/**
 * Check if PDK-wrapped device keys exist in localStorage
 */
export function hasPdkWrappedDeviceKeys(): boolean {
  return (
    localStorage.getItem(LS_DEVICE_ECDH_KEY) !== null &&
    localStorage.getItem(LS_DEVICE_SIGNING_KEY) !== null
  )
}

/**
 * Clear PDK-wrapped device keys from localStorage
 */
export function clearPdkWrappedDeviceKeys(): void {
  localStorage.removeItem(LS_DEVICE_ECDH_KEY)
  localStorage.removeItem(LS_DEVICE_SIGNING_KEY)
}

// =============================================================================
// UMK wrap/unwrap
// =============================================================================

/**
 * Wrap UMK with PDK and store in localStorage
 */
export function wrapAndStorePdkUmk(
  umk: Uint8Array,
  pdk: Uint8Array,
  userId: string
): void {
  const aad = buildPdkUmkAad(userId)
  const wrapped = pdkEncrypt(umk, pdk, aad)
  storeWrapped(LS_UMK_KEY, {
    ct: base64UrlEncode(wrapped.ciphertext),
    n: base64UrlEncode(wrapped.nonce),
    uid: userId,
  })
}

/**
 * Unwrap UMK from localStorage using PDK
 *
 * @returns UMK and userId, or null if not found or decryption fails
 */
export function unwrapPdkUmk(
  pdk: Uint8Array
): { umk: Uint8Array; userId: string } | null {
  const data = loadWrapped(LS_UMK_KEY)
  if (!data) return null

  try {
    const aad = buildPdkUmkAad(data.uid)
    const umk = pdkDecrypt(
      base64UrlDecode(data.ct),
      base64UrlDecode(data.n),
      pdk,
      aad
    )
    return { umk, userId: data.uid }
  } catch {
    return null
  }
}

/**
 * Check if PDK-wrapped UMK exists in localStorage
 */
export function hasPdkWrappedUmk(): boolean {
  return localStorage.getItem(LS_UMK_KEY) !== null
}

/**
 * Clear PDK-wrapped UMK from localStorage
 */
export function clearPdkWrappedUmk(): void {
  localStorage.removeItem(LS_UMK_KEY)
}

// =============================================================================
// Ephemeral PDK storage (memory-only)
//
// Used to pass PDK from login to device-register when device is pending.
// PDK is ephemeral (memory-only) — never persisted to any browser storage.
// Module-level variable is sufficient since SPA navigation does not trigger
// page reloads.
// =============================================================================

let ephemeralPdk: Uint8Array | null = null

/**
 * Store PDK temporarily in memory for device registration flow.
 * Called during login when device_required is returned.
 */
export function storePdkForDeviceRegistration(pdk: Uint8Array): void {
  ephemeralPdk = pdk
}

/**
 * Load and clear ephemeral PDK from memory.
 * Returns null if not found.
 */
export function loadAndClearPdkForDeviceRegistration(): Uint8Array | null {
  const pdk = ephemeralPdk
  ephemeralPdk = null
  return pdk
}

/**
 * Clear ephemeral PDK from memory (e.g., on logout).
 */
export function clearPdkEphemeral(): void {
  ephemeralPdk = null
}
