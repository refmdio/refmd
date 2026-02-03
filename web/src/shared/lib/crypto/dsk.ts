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

/**
 * Wrapped UMK structure stored in IndexedDB
 */
interface WrappedUmkData {
  ciphertext: ArrayBuffer
  nonce: Uint8Array
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
 * Clear all DSK-related data from IndexedDB (call on logout)
 */
export async function clearDskData(): Promise<void> {
  await Promise.all([dbDelete(DSK_KEY), dbDelete(WRAPPED_UMK_KEY)])
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
