/**
 * TOFU (Trust On First Use) Trust Store Module
 *
 * IndexedDB-based storage for trusted device public keys.
 * Used to implement TOFU security model for device identity verification.
 *
 * Security properties:
 * - Stores signing and ECDH public keys for each trusted device
 * - Tracks first-seen and last-seen timestamps for audit
 * - Used to detect key changes (potential MITM attacks)
 */

import { openIdb, idbGet, idbPut, idbClear, toArrayBuffer } from '@/shared/lib/idb'

const DB_NAME = 'refmd-trust'
const DB_VERSION = 1
const STORE_NAME = 'tofu-entries'

/**
 * TOFU entry representing a trusted device's public keys
 */
export interface TofuEntry {
  /** User ID that owns this device */
  userId: string
  /** Device ID (UUID) */
  deviceId: string
  /** Ed25519 signing public key (32 bytes) */
  signingPublicKey: Uint8Array
  /** X25519 ECDH public key (32 bytes) */
  ecdhPublicKey: Uint8Array
  /** Unix timestamp when this device was first seen */
  firstSeenAt: number
  /** Unix timestamp when this device was last seen */
  lastSeenAt: number
}

/**
 * Serialized TOFU entry for IndexedDB storage
 * (Uint8Array is stored as ArrayBuffer in IndexedDB)
 */
interface SerializedTofuEntry {
  userId: string
  deviceId: string
  signingPublicKey: ArrayBuffer
  ecdhPublicKey: ArrayBuffer
  firstSeenAt: number
  lastSeenAt: number
}

function openDb(): Promise<IDBDatabase> {
  return openIdb(DB_NAME, DB_VERSION, (db) => {
    if (!db.objectStoreNames.contains(STORE_NAME)) {
      const store = db.createObjectStore(STORE_NAME, {
        keyPath: ['userId', 'deviceId'],
      })
      store.createIndex('by-user', 'userId', { unique: false })
    }
  })
}

/**
 * Generate composite key for IndexedDB
 */
function compositeKey(userId: string, deviceId: string): [string, string] {
  return [userId, deviceId]
}

/**
 * Convert TofuEntry to serialized form for storage
 */
function serialize(entry: TofuEntry): SerializedTofuEntry {
  return {
    userId: entry.userId,
    deviceId: entry.deviceId,
    signingPublicKey: toArrayBuffer(entry.signingPublicKey),
    ecdhPublicKey: toArrayBuffer(entry.ecdhPublicKey),
    firstSeenAt: entry.firstSeenAt,
    lastSeenAt: entry.lastSeenAt,
  }
}

/**
 * Convert serialized form back to TofuEntry
 */
function deserialize(serialized: SerializedTofuEntry): TofuEntry {
  return {
    userId: serialized.userId,
    deviceId: serialized.deviceId,
    signingPublicKey: new Uint8Array(serialized.signingPublicKey),
    ecdhPublicKey: new Uint8Array(serialized.ecdhPublicKey),
    firstSeenAt: serialized.firstSeenAt,
    lastSeenAt: serialized.lastSeenAt,
  }
}

/**
 * Save a TOFU entry to the trust store
 *
 * If an entry already exists for this userId+deviceId, it will be overwritten.
 * Use verifyTofu() to check for key changes before calling this.
 */
export async function saveTofuEntry(entry: TofuEntry): Promise<void> {
  const db = await openDb()
  await idbPut(db, STORE_NAME, serialize(entry))
}

/**
 * Get a TOFU entry from the trust store
 *
 * @returns The entry if found, null otherwise
 */
export async function getTofuEntry(
  userId: string,
  deviceId: string
): Promise<TofuEntry | null> {
  const db = await openDb()
  const result = await idbGet<SerializedTofuEntry>(db, STORE_NAME, compositeKey(userId, deviceId))
  return result ? deserialize(result) : null
}

/**
 * Update the lastSeenAt timestamp for a TOFU entry
 *
 * @returns true if the entry was updated, false if not found
 */
export async function updateLastSeen(
  userId: string,
  deviceId: string
): Promise<boolean> {
  // Uses raw transaction for atomic get-then-put within single tx
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    const store = tx.objectStore(STORE_NAME)
    const getRequest = store.get(compositeKey(userId, deviceId))

    getRequest.onerror = () => reject(getRequest.error)
    getRequest.onsuccess = () => {
      const result = getRequest.result as SerializedTofuEntry | undefined
      if (!result) {
        resolve(false)
        return
      }

      result.lastSeenAt = Date.now()
      const putRequest = store.put(result)
      putRequest.onerror = () => reject(putRequest.error)
      putRequest.onsuccess = () => resolve(true)
    }

    tx.oncomplete = () => db.close()
  })
}

/**
 * Get all TOFU entries for a specific user
 *
 * Useful for trust state transfer and displaying trusted devices.
 */
export async function getAllTofuEntriesForUser(
  userId: string
): Promise<TofuEntry[]> {
  // Uses raw transaction for index-based query
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly')
    const store = tx.objectStore(STORE_NAME)
    const index = store.index('by-user')
    const request = index.getAll(userId)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      const results = request.result as SerializedTofuEntry[]
      resolve(results.map(deserialize))
    }

    tx.oncomplete = () => db.close()
  })
}

/**
 * Clear all TOFU entries from the trust store
 *
 * Use when performing a complete reset (e.g., secure logout).
 */
export async function clearAllTofuEntries(): Promise<void> {
  const db = await openDb()
  await idbClear(db, STORE_NAME)
}

/**
 * Import multiple TOFU entries (used for trust state transfer)
 *
 * Performs a bulk insert/update operation within a single transaction.
 */
export async function importTofuEntries(entries: TofuEntry[]): Promise<void> {
  if (entries.length === 0) {
    return
  }

  // Uses raw transaction for batch operation within single tx
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    const store = tx.objectStore(STORE_NAME)

    let completed = 0
    const total = entries.length

    for (const entry of entries) {
      const request = store.put(serialize(entry))
      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        completed++
        if (completed === total) {
          resolve()
        }
      }
    }

    tx.oncomplete = () => db.close()
  })
}
