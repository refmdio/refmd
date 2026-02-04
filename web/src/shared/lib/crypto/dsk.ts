/**
 * DSK (Device Storage Key) Module
 *
 * DSK is a non-exportable AES-256-GCM key stored in IndexedDB.
 * Used to wrap UMK for local caching (KMSI - Keep Me Signed In).
 *
 * Security properties:
 * - Non-exportable: Key cannot be extracted via API (protects against disk theft)
 * - XSS is considered a fatal breach; CSP is the primary defense
 *
 * Storage structure in IndexedDB:
 * - DSK: CryptoKey (non-exportable AES-GCM)
 * - Wrapped UMK: { ciphertext, nonce, userId }
 */

import { buildAad, SIGNATURE_PROTOCOL, AAD_PURPOSE } from './aad'

const DB_NAME = 'refmd-crypto'
const DB_VERSION = 1
const STORE_NAME = 'keys'
const DSK_KEY = 'dsk'
const WRAPPED_UMK_KEY = 'wrapped-umk'
const DEVICE_KEYS_KEY = 'device-keys'
const DEVICE_ID_KEY = 'device-id'

/**
 * Wrapped UMK structure stored in IndexedDB
 */
interface WrappedUmkData {
  ciphertext: ArrayBuffer
  nonce: Uint8Array
  userId: string
}

/**
 * Wrapped device keys structure stored in IndexedDB
 */
interface WrappedDeviceKeysData {
  /** Encrypted ECDH private key */
  encryptedEcdhPrivate: ArrayBuffer
  ecdhNonce: Uint8Array
  /** Encrypted signing private key */
  encryptedSigningPrivate: ArrayBuffer
  signingNonce: Uint8Array
  /** Public keys (not encrypted) */
  ecdhPublicKey: Uint8Array
  signingPublicKey: Uint8Array
  /** User ID for AAD binding */
  userId: string
}

/**
 * Open IndexedDB connection
 */
function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result)

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME)
      }
    }
  })
}

/**
 * Get value from IndexedDB
 */
async function dbGet<T>(key: string): Promise<T | undefined> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly')
    const store = tx.objectStore(STORE_NAME)
    const request = store.get(key)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result as T | undefined)

    tx.oncomplete = () => db.close()
  })
}

/**
 * Set value in IndexedDB
 */
async function dbSet(key: string, value: unknown): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    const store = tx.objectStore(STORE_NAME)
    const request = store.put(value, key)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()

    tx.oncomplete = () => db.close()
  })
}

/**
 * Delete value from IndexedDB
 */
async function dbDelete(key: string): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    const store = tx.objectStore(STORE_NAME)
    const request = store.delete(key)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()

    tx.oncomplete = () => db.close()
  })
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
 * Generate a new DSK (non-exportable AES-256-GCM key)
 */
export async function generateDsk(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    false, // Non-exportable
    ['encrypt', 'decrypt']
  )
}

/**
 * Store DSK in IndexedDB
 */
export async function storeDsk(dsk: CryptoKey): Promise<void> {
  await dbSet(DSK_KEY, dsk)
}

/**
 * Load DSK from IndexedDB
 */
export async function loadDsk(): Promise<CryptoKey | null> {
  const dsk = await dbGet<CryptoKey>(DSK_KEY)
  return dsk ?? null
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

/**
 * Build AAD for device ECDH private key encryption
 */
function buildDskDeviceEcdhAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DSK_DEVICE_ECDH_PRIVATE,
    user_id: userId,
  })
}

/**
 * Build AAD for device signing private key encryption
 */
function buildDskDeviceSigningAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DSK_DEVICE_SIGNING_PRIVATE,
    user_id: userId,
  })
}

/**
 * Store device ID in IndexedDB
 */
export async function storeDeviceId(deviceId: string): Promise<void> {
  await dbSet(DEVICE_ID_KEY, deviceId)
}

/**
 * Load device ID from IndexedDB
 */
export async function loadDeviceId(): Promise<string | null> {
  const deviceId = await dbGet<string>(DEVICE_ID_KEY)
  return deviceId ?? null
}

/**
 * Wrap device keys with DSK and store in IndexedDB
 *
 * @param deviceKeys Device key pair (ECDH + signing)
 * @param dsk Device Storage Key
 * @param userId User ID for AAD binding
 */
export async function wrapAndStoreDeviceKeys(
  deviceKeys: {
    ecdhPrivateKey: Uint8Array
    ecdhPublicKey: Uint8Array
    signingPrivateKey: Uint8Array
    signingPublicKey: Uint8Array
  },
  dsk: CryptoKey,
  userId: string
): Promise<void> {
  // Encrypt ECDH private key
  const ecdhNonce = crypto.getRandomValues(new Uint8Array(12))
  const ecdhAad = buildDskDeviceEcdhAad(userId)
  const encryptedEcdhPrivate = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: ecdhNonce as Uint8Array<ArrayBuffer>,
      additionalData: ecdhAad as Uint8Array<ArrayBuffer>,
    },
    dsk,
    deviceKeys.ecdhPrivateKey as Uint8Array<ArrayBuffer>
  )

  // Encrypt signing private key
  const signingNonce = crypto.getRandomValues(new Uint8Array(12))
  const signingAad = buildDskDeviceSigningAad(userId)
  const encryptedSigningPrivate = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: signingNonce as Uint8Array<ArrayBuffer>,
      additionalData: signingAad as Uint8Array<ArrayBuffer>,
    },
    dsk,
    deviceKeys.signingPrivateKey as Uint8Array<ArrayBuffer>
  )

  const wrappedData: WrappedDeviceKeysData = {
    encryptedEcdhPrivate,
    ecdhNonce,
    encryptedSigningPrivate,
    signingNonce,
    ecdhPublicKey: deviceKeys.ecdhPublicKey,
    signingPublicKey: deviceKeys.signingPublicKey,
    userId,
  }

  await dbSet(DEVICE_KEYS_KEY, wrappedData)
}

/**
 * Load and unwrap device keys from IndexedDB
 *
 * @param dsk Device Storage Key
 * @returns Unwrapped device keys, or null if not found
 */
export async function loadAndUnwrapDeviceKeys(
  dsk: CryptoKey
): Promise<{
  ecdhPrivateKey: Uint8Array
  ecdhPublicKey: Uint8Array
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
  userId: string
} | null> {
  const wrappedData = await dbGet<WrappedDeviceKeysData>(DEVICE_KEYS_KEY)
  if (!wrappedData) {
    return null
  }

  try {
    // Decrypt ECDH private key
    const ecdhAad = buildDskDeviceEcdhAad(wrappedData.userId)
    const ecdhPrivateBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: wrappedData.ecdhNonce as Uint8Array<ArrayBuffer>,
        additionalData: ecdhAad as Uint8Array<ArrayBuffer>,
      },
      dsk,
      wrappedData.encryptedEcdhPrivate
    )

    // Decrypt signing private key
    const signingAad = buildDskDeviceSigningAad(wrappedData.userId)
    const signingPrivateBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: wrappedData.signingNonce as Uint8Array<ArrayBuffer>,
        additionalData: signingAad as Uint8Array<ArrayBuffer>,
      },
      dsk,
      wrappedData.encryptedSigningPrivate
    )

    return {
      ecdhPrivateKey: new Uint8Array(ecdhPrivateBuffer),
      ecdhPublicKey: wrappedData.ecdhPublicKey,
      signingPrivateKey: new Uint8Array(signingPrivateBuffer),
      signingPublicKey: wrappedData.signingPublicKey,
      userId: wrappedData.userId,
    }
  } catch {
    // Decryption failed
    return null
  }
}

/**
 * Check if device keys exist in IndexedDB
 */
export async function hasDeviceKeys(): Promise<boolean> {
  const deviceKeys = await dbGet<WrappedDeviceKeysData>(DEVICE_KEYS_KEY)
  return deviceKeys !== undefined
}

/**
 * Check if device keys exist in IndexedDB for a specific user
 *
 * This is more secure than hasDeviceKeys() as it verifies that the stored
 * keys belong to the currently logged-in user, preventing key mismatch
 * when switching between accounts.
 */
export async function hasDeviceKeysForUser(userId: string): Promise<boolean> {
  const deviceKeys = await dbGet<WrappedDeviceKeysData>(DEVICE_KEYS_KEY)
  return deviceKeys !== undefined && deviceKeys.userId === userId
}

// =============================================================================
// Session Storage (for rememberMe=false, persists until tab close)
// =============================================================================

const SESSION_UMK_KEY = 'refmd-session-umk'

interface SessionUmkData {
  umk: string // base64url encoded
  userId: string
}

/**
 * Store UMK in sessionStorage (for rememberMe=false)
 *
 * This is used when the user doesn't want to persist their session across
 * browser restarts, but still wants to maintain the session during page
 * reloads within the same tab.
 *
 * Security note: sessionStorage is isolated per tab and origin.
 * XSS is considered a fatal breach per design docs, so CSP is the primary defense.
 */
export function storeSessionUmk(umk: Uint8Array, userId: string): void {
  const data: SessionUmkData = {
    umk: bytesToBase64Url(umk),
    userId,
  }
  sessionStorage.setItem(SESSION_UMK_KEY, JSON.stringify(data))
}

/**
 * Load UMK from sessionStorage
 *
 * @returns UMK and userId if found and valid, null otherwise
 */
export function loadSessionUmk(): { umk: Uint8Array; userId: string } | null {
  const raw = sessionStorage.getItem(SESSION_UMK_KEY)
  if (!raw) {
    return null
  }

  try {
    const data: SessionUmkData = JSON.parse(raw)
    if (!data.umk || !data.userId) {
      return null
    }
    return {
      umk: base64UrlToBytes(data.umk),
      userId: data.userId,
    }
  } catch {
    return null
  }
}

/**
 * Clear UMK from sessionStorage
 */
export function clearSessionUmk(): void {
  sessionStorage.removeItem(SESSION_UMK_KEY)
}

/**
 * Check if UMK exists in sessionStorage
 */
export function hasSessionUmk(): boolean {
  return sessionStorage.getItem(SESSION_UMK_KEY) !== null
}

// Helper functions for base64url encoding/decoding
function bytesToBase64Url(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (byte) => String.fromCodePoint(byte)).join('')
  return btoa(binString).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64UrlToBytes(base64url: string): Uint8Array {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const binString = atob(base64)
  return Uint8Array.from(binString, (c) => c.codePointAt(0)!)
}
