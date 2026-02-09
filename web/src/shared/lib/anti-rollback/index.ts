/**
 * Anti-Rollback Stores Module
 *
 * IndexedDB-based storage for anti-rollback security data.
 * Prevents server from rolling back revocations, key versions,
 * membership changes, or document state.
 *
 * Database: refmd-security
 * Stores:
 * 1. revocation-pins - Tracks device revocation events
 * 2. key-version-pins - Tracks highest observed key versions
 * 3. membership-logs - Audit log of workspace membership changes
 * 4. document-state-pins - Tracks latest document sequence numbers
 */

const DB_NAME = 'refmd-security'
const DB_VERSION = 1

const STORES = {
  REVOCATION_PINS: 'revocation-pins',
  KEY_VERSION_PINS: 'key-version-pins',
  MEMBERSHIP_LOGS: 'membership-logs',
  DOCUMENT_STATE_PINS: 'document-state-pins',
} as const

// =============================================================================
// Types
// =============================================================================

export interface RevocationPin {
  userId: string
  deviceId: string
  revokedAt: number
  signature: Uint8Array
}

export interface KeyVersionPin {
  type: 'kek' | 'dek'
  id: string
  highestVersion: number
  observedAt: number
}

export interface MembershipLogEntry {
  workspaceId: string
  userId: string
  action: string
  signature: Uint8Array
  timestamp: number
}

export interface DocumentStatePin {
  documentId: string
  latestSeq: number
  latestUpdateHash: string
  observedAt: number
}

// Serialized forms for IndexedDB (Uint8Array → ArrayBuffer)
interface SerializedRevocationPin {
  userId: string
  deviceId: string
  revokedAt: number
  signature: ArrayBuffer
}

interface SerializedMembershipLogEntry {
  workspaceId: string
  userId: string
  action: string
  signature: ArrayBuffer
  timestamp: number
}

// =============================================================================
// Database
// =============================================================================

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result)

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result

      // revocation-pins: composite key [userId, deviceId]
      if (!db.objectStoreNames.contains(STORES.REVOCATION_PINS)) {
        db.createObjectStore(STORES.REVOCATION_PINS, {
          keyPath: ['userId', 'deviceId'],
        })
      }

      // key-version-pins: composite key [type, id]
      if (!db.objectStoreNames.contains(STORES.KEY_VERSION_PINS)) {
        db.createObjectStore(STORES.KEY_VERSION_PINS, {
          keyPath: ['type', 'id'],
        })
      }

      // membership-logs: autoIncrement with workspaceId index
      if (!db.objectStoreNames.contains(STORES.MEMBERSHIP_LOGS)) {
        const store = db.createObjectStore(STORES.MEMBERSHIP_LOGS, {
          autoIncrement: true,
        })
        store.createIndex('by-workspace', 'workspaceId', { unique: false })
      }

      // document-state-pins: keyPath documentId
      if (!db.objectStoreNames.contains(STORES.DOCUMENT_STATE_PINS)) {
        db.createObjectStore(STORES.DOCUMENT_STATE_PINS, {
          keyPath: 'documentId',
        })
      }
    }
  })
}

// =============================================================================
// Serialization helpers
// =============================================================================

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer
}

// =============================================================================
// Revocation Pins
// =============================================================================

export async function pinRevocation(pin: RevocationPin): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.REVOCATION_PINS, 'readwrite')
    const store = tx.objectStore(STORES.REVOCATION_PINS)
    const serialized: SerializedRevocationPin = {
      userId: pin.userId,
      deviceId: pin.deviceId,
      revokedAt: pin.revokedAt,
      signature: toArrayBuffer(pin.signature),
    }
    const request = store.put(serialized)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()

    tx.oncomplete = () => db.close()
  })
}

export async function getRevocationPin(
  userId: string,
  deviceId: string
): Promise<RevocationPin | null> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.REVOCATION_PINS, 'readonly')
    const store = tx.objectStore(STORES.REVOCATION_PINS)
    const request = store.get([userId, deviceId])

    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      const result = request.result as SerializedRevocationPin | undefined
      if (!result) {
        resolve(null)
        return
      }
      resolve({
        userId: result.userId,
        deviceId: result.deviceId,
        revokedAt: result.revokedAt,
        signature: new Uint8Array(result.signature),
      })
    }

    tx.oncomplete = () => db.close()
  })
}

/**
 * Check if a device revocation is being rolled back.
 * Returns true if the device was previously pinned as revoked.
 */
export async function isRevocationRolledBack(
  userId: string,
  deviceId: string
): Promise<boolean> {
  const pin = await getRevocationPin(userId, deviceId)
  return pin !== null
}

export async function clearAllRevocationPins(): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.REVOCATION_PINS, 'readwrite')
    const store = tx.objectStore(STORES.REVOCATION_PINS)
    const request = store.clear()

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()

    tx.oncomplete = () => db.close()
  })
}

// =============================================================================
// Key Version Pins
// =============================================================================

export async function pinKeyVersion(pin: KeyVersionPin): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.KEY_VERSION_PINS, 'readwrite')
    const store = tx.objectStore(STORES.KEY_VERSION_PINS)

    // Only update if new version is >= existing highest version
    const getRequest = store.get([pin.type, pin.id])
    getRequest.onerror = () => reject(getRequest.error)
    getRequest.onsuccess = () => {
      const existing = getRequest.result as KeyVersionPin | undefined
      if (existing && existing.highestVersion > pin.highestVersion) {
        // Don't downgrade
        resolve()
        return
      }
      const putRequest = store.put(pin)
      putRequest.onerror = () => reject(putRequest.error)
      putRequest.onsuccess = () => resolve()
    }

    tx.oncomplete = () => db.close()
  })
}

export async function getKeyVersionPin(
  type: 'kek' | 'dek',
  id: string
): Promise<KeyVersionPin | null> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.KEY_VERSION_PINS, 'readonly')
    const store = tx.objectStore(STORES.KEY_VERSION_PINS)
    const request = store.get([type, id])

    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      resolve((request.result as KeyVersionPin | undefined) ?? null)
    }

    tx.oncomplete = () => db.close()
  })
}

/**
 * Check if a key version is being rolled back.
 * Returns the pinned version if the provided version is lower than the pinned one, null otherwise.
 */
export async function checkKeyVersionRollback(
  type: 'kek' | 'dek',
  id: string,
  version: number
): Promise<{ rolledBack: true; pinnedVersion: number } | { rolledBack: false }> {
  const pin = await getKeyVersionPin(type, id)
  if (pin && version < pin.highestVersion) {
    return { rolledBack: true, pinnedVersion: pin.highestVersion }
  }
  return { rolledBack: false }
}

export async function clearAllKeyVersionPins(): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.KEY_VERSION_PINS, 'readwrite')
    const store = tx.objectStore(STORES.KEY_VERSION_PINS)
    const request = store.clear()

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()

    tx.oncomplete = () => db.close()
  })
}

// =============================================================================
// Membership Logs
// =============================================================================

export async function appendMembershipLog(entry: MembershipLogEntry): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.MEMBERSHIP_LOGS, 'readwrite')
    const store = tx.objectStore(STORES.MEMBERSHIP_LOGS)
    const serialized: SerializedMembershipLogEntry = {
      workspaceId: entry.workspaceId,
      userId: entry.userId,
      action: entry.action,
      signature: toArrayBuffer(entry.signature),
      timestamp: entry.timestamp,
    }
    const request = store.add(serialized)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()

    tx.oncomplete = () => db.close()
  })
}

export async function getMembershipLogsForWorkspace(
  workspaceId: string
): Promise<MembershipLogEntry[]> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.MEMBERSHIP_LOGS, 'readonly')
    const store = tx.objectStore(STORES.MEMBERSHIP_LOGS)
    const index = store.index('by-workspace')
    const request = index.getAll(workspaceId)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      const results = request.result as SerializedMembershipLogEntry[]
      resolve(
        results.map((r) => ({
          workspaceId: r.workspaceId,
          userId: r.userId,
          action: r.action,
          signature: new Uint8Array(r.signature),
          timestamp: r.timestamp,
        }))
      )
    }

    tx.oncomplete = () => db.close()
  })
}

export async function clearAllMembershipLogs(): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.MEMBERSHIP_LOGS, 'readwrite')
    const store = tx.objectStore(STORES.MEMBERSHIP_LOGS)
    const request = store.clear()

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()

    tx.oncomplete = () => db.close()
  })
}

// =============================================================================
// Document State Pins
// =============================================================================

export async function pinDocumentState(pin: DocumentStatePin): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.DOCUMENT_STATE_PINS, 'readwrite')
    const store = tx.objectStore(STORES.DOCUMENT_STATE_PINS)

    // Only update if new seq is >= existing
    const getRequest = store.get(pin.documentId)
    getRequest.onerror = () => reject(getRequest.error)
    getRequest.onsuccess = () => {
      const existing = getRequest.result as DocumentStatePin | undefined
      if (existing && existing.latestSeq > pin.latestSeq) {
        // Don't downgrade
        resolve()
        return
      }
      const putRequest = store.put(pin)
      putRequest.onerror = () => reject(putRequest.error)
      putRequest.onsuccess = () => resolve()
    }

    tx.oncomplete = () => db.close()
  })
}

export async function getDocumentStatePin(
  documentId: string
): Promise<DocumentStatePin | null> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.DOCUMENT_STATE_PINS, 'readonly')
    const store = tx.objectStore(STORES.DOCUMENT_STATE_PINS)
    const request = store.get(documentId)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      resolve((request.result as DocumentStatePin | undefined) ?? null)
    }

    tx.oncomplete = () => db.close()
  })
}

/**
 * Check if a document state is being rolled back.
 * Returns the pinned state if the provided seq is lower than the pinned one, null otherwise.
 */
export async function checkDocumentStateRollback(
  documentId: string,
  seq: number
): Promise<{ rolledBack: true; pinnedSeq: number } | { rolledBack: false }> {
  const pin = await getDocumentStatePin(documentId)
  if (pin && seq < pin.latestSeq) {
    return { rolledBack: true, pinnedSeq: pin.latestSeq }
  }
  return { rolledBack: false }
}

export async function clearAllDocumentStatePins(): Promise<void> {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.DOCUMENT_STATE_PINS, 'readwrite')
    const store = tx.objectStore(STORES.DOCUMENT_STATE_PINS)
    const request = store.clear()

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()

    tx.oncomplete = () => db.close()
  })
}
