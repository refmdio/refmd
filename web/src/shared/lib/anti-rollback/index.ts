/**
 * Anti-Rollback Stores Module
 *
 * IndexedDB-based storage for anti-rollback security data.
 * Prevents server from rolling back revocations, key versions,
 * or document state.
 *
 * Database: refmd-security
 * Stores:
 * 1. revocation-pins - Tracks device revocation events
 * 2. key-version-pins - Tracks highest observed key versions
 * 3. document-state-pins - Tracks latest document sequence numbers
 */

import { openIdb, idbGet, idbPut, idbClear, idbConditionalPut, toArrayBuffer } from '@/shared/lib/idb'

const DB_NAME = 'refmd-security'
const DB_VERSION = 4

const STORES = {
  REVOCATION_PINS: 'revocation-pins',
  KEY_VERSION_PINS: 'key-version-pins',
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

// =============================================================================
// Database
// =============================================================================

function openDb(): Promise<IDBDatabase> {
  return openIdb(DB_NAME, DB_VERSION, (db) => {
    if (!db.objectStoreNames.contains(STORES.REVOCATION_PINS)) {
      db.createObjectStore(STORES.REVOCATION_PINS, {
        keyPath: ['userId', 'deviceId'],
      })
    }

    if (!db.objectStoreNames.contains(STORES.KEY_VERSION_PINS)) {
      db.createObjectStore(STORES.KEY_VERSION_PINS, {
        keyPath: ['type', 'id'],
      })
    }

    if (!db.objectStoreNames.contains(STORES.DOCUMENT_STATE_PINS)) {
      db.createObjectStore(STORES.DOCUMENT_STATE_PINS, {
        keyPath: 'documentId',
      })
    }

    // v4: remove unused membership-logs scaffold (was Phase 3 pre-implementation)
    if (db.objectStoreNames.contains('membership-logs')) {
      db.deleteObjectStore('membership-logs')
    }
  })
}

// =============================================================================
// Revocation Pins
// =============================================================================

export async function pinRevocation(pin: RevocationPin): Promise<void> {
  const db = await openDb()
  const serialized: SerializedRevocationPin = {
    userId: pin.userId,
    deviceId: pin.deviceId,
    revokedAt: pin.revokedAt,
    signature: toArrayBuffer(pin.signature),
  }
  await idbPut(db, STORES.REVOCATION_PINS, serialized)
}

export async function getRevocationPin(
  userId: string,
  deviceId: string
): Promise<RevocationPin | null> {
  const db = await openDb()
  const result = await idbGet<SerializedRevocationPin>(db, STORES.REVOCATION_PINS, [userId, deviceId])
  if (!result) return null
  return {
    userId: result.userId,
    deviceId: result.deviceId,
    revokedAt: result.revokedAt,
    signature: new Uint8Array(result.signature),
  }
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
  await idbClear(db, STORES.REVOCATION_PINS)
}

// =============================================================================
// Key Version Pins
// =============================================================================

export async function pinKeyVersion(pin: KeyVersionPin): Promise<void> {
  const db = await openDb()
  return idbConditionalPut<KeyVersionPin>(
    db,
    STORES.KEY_VERSION_PINS,
    [pin.type, pin.id],
    pin,
    (existing) => !existing || existing.highestVersion <= pin.highestVersion
  )
}

export async function getKeyVersionPin(
  type: 'kek' | 'dek',
  id: string
): Promise<KeyVersionPin | null> {
  const db = await openDb()
  const result = await idbGet<KeyVersionPin>(db, STORES.KEY_VERSION_PINS, [type, id])
  return result ?? null
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

/**
 * Assert that a 404 from the server is genuine (no prior version observed).
 * Throws if we previously pinned a version for this key — a 404 after a known
 * version means the server deleted a key it shouldn't have (rollback attack).
 *
 * Use in create-new-key paths where the server returned 404 for an existing key.
 */
export async function assertNoRollbackOn404(
  type: 'kek' | 'dek',
  id: string
): Promise<void> {
  const pin = await getKeyVersionPin(type, id)
  if (pin) {
    throw new Error(
      `${type.toUpperCase()} rollback detected for ${id}: ` +
      `server returned 404 but v${pin.highestVersion} was previously observed`
    )
  }
}

/**
 * Assert no rollback, then pin the key version atomically.
 * Throws on rollback detection. Use in fail-close paths (KEK/DEK fetch, create).
 */
export async function assertAndPinKeyVersion(
  type: 'kek' | 'dek',
  id: string,
  version: number
): Promise<void> {
  const rollback = await checkKeyVersionRollback(type, id, version)
  if (rollback.rolledBack) {
    throw new Error(
      `${type.toUpperCase()} rollback detected for ${id}: ` +
      `server returned v${version}, pinned v${rollback.pinnedVersion}`
    )
  }
  await pinKeyVersion({
    type,
    id,
    highestVersion: version,
    observedAt: Date.now(),
  })
}

/**
 * Check for rollback and pin if safe. Returns false on rollback (no throw).
 * Use in best-effort paths (KEK rotation loop) where rollback means "skip".
 */
export async function checkAndPinKeyVersion(
  type: 'kek' | 'dek',
  id: string,
  version: number
): Promise<boolean> {
  const rollback = await checkKeyVersionRollback(type, id, version)
  if (rollback.rolledBack) {
    return false
  }
  await pinKeyVersion({
    type,
    id,
    highestVersion: version,
    observedAt: Date.now(),
  })
  return true
}

export async function clearAllKeyVersionPins(): Promise<void> {
  const db = await openDb()
  await idbClear(db, STORES.KEY_VERSION_PINS)
}

// =============================================================================
// Document State Pins
// =============================================================================

export async function pinDocumentState(pin: DocumentStatePin): Promise<void> {
  const db = await openDb()
  return idbConditionalPut<DocumentStatePin>(
    db,
    STORES.DOCUMENT_STATE_PINS,
    pin.documentId,
    pin,
    (existing) => !existing || existing.latestSeq <= pin.latestSeq
  )
}

export async function getDocumentStatePin(
  documentId: string
): Promise<DocumentStatePin | null> {
  const db = await openDb()
  const result = await idbGet<DocumentStatePin>(db, STORES.DOCUMENT_STATE_PINS, documentId)
  return result ?? null
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
  await idbClear(db, STORES.DOCUMENT_STATE_PINS)
}


