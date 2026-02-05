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
        // Composite key: [userId, deviceId]
        const store = db.createObjectStore(STORE_NAME, {
          keyPath: ['userId', 'deviceId'],
        })
        // Index for querying all entries for a user
        store.createIndex('by-user', 'userId', { unique: false })
      }
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
    signingPublicKey: entry.signingPublicKey.buffer.slice(
      entry.signingPublicKey.byteOffset,
      entry.signingPublicKey.byteOffset + entry.signingPublicKey.byteLength
    ) as ArrayBuffer,
    ecdhPublicKey: entry.ecdhPublicKey.buffer.slice(
      entry.ecdhPublicKey.byteOffset,
      entry.ecdhPublicKey.byteOffset + entry.ecdhPublicKey.byteLength
    ) as ArrayBuffer,
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
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    const store = tx.objectStore(STORE_NAME)
    const request = store.put(serialize(entry))

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()

    tx.oncomplete = () => db.close()
  })
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
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly')
    const store = tx.objectStore(STORE_NAME)
    const request = store.get(compositeKey(userId, deviceId))

    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      const result = request.result as SerializedTofuEntry | undefined
      resolve(result ? deserialize(result) : null)
    }

    tx.oncomplete = () => db.close()
  })
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
 * Get all TOFU entries from the trust store
 *
 * Useful for trust state transfer to a new device.
 */
export async function getAllTofuEntries(): Promise<TofuEntry[]> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly')
    const store = tx.objectStore(STORE_NAME)
    const request = store.getAll()

    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      const results = request.result as SerializedTofuEntry[]
      resolve(results.map(deserialize))
    }

    tx.oncomplete = () => db.close()
  })
}

/**
 * Delete a TOFU entry from the trust store
 *
 * Use when a device is revoked or explicitly untrusted.
 */
export async function deleteTofuEntry(
  userId: string,
  deviceId: string
): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    const store = tx.objectStore(STORE_NAME)
    const request = store.delete(compositeKey(userId, deviceId))

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()

    tx.oncomplete = () => db.close()
  })
}

/**
 * Delete all TOFU entries for a user
 *
 * Use when the user logs out or wants to reset trust state.
 */
export async function deleteAllTofuEntriesForUser(userId: string): Promise<void> {
  const entries = await getAllTofuEntriesForUser(userId)
  const db = await openDb()

  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    const store = tx.objectStore(STORE_NAME)

    let completed = 0
    const total = entries.length

    if (total === 0) {
      resolve()
      db.close()
      return
    }

    for (const entry of entries) {
      const request = store.delete(compositeKey(entry.userId, entry.deviceId))
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

/**
 * Clear all TOFU entries from the trust store
 *
 * Use when performing a complete reset (e.g., secure logout).
 */
export async function clearAllTofuEntries(): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    const store = tx.objectStore(STORE_NAME)
    const request = store.clear()

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()

    tx.oncomplete = () => db.close()
  })
}

/**
 * Import multiple TOFU entries (used for trust state transfer)
 *
 * Performs a bulk insert/update operation.
 */
export async function importTofuEntries(entries: TofuEntry[]): Promise<void> {
  if (entries.length === 0) {
    return
  }

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
