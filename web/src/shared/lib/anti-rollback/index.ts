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
 * 3. document-state-pins - Tracks latest document snapshot/version state
 */

import { openIdb, idbGet, idbPut, idbClear, idbConditionalPut, toArrayBuffer } from '@/shared/lib/idb'
import { computeParentSnapshotProof } from '@/shared/lib/crypto'

const DB_NAME = 'refmd-security'
const DB_VERSION = 8

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
  /** Active collab snapshot ID (null = no snapshot yet, new document) */
  latestSnapshotId: string | null
  /** BLAKE3 proof hash of the snapshot chain head (prevents snapshot substitution) */
  latestSnapshotProofHash: string
  /** BLAKE3(ciphertext) of the pinned snapshot (needed for cross-snapshot proof verification) */
  latestSnapshotCiphertextHash: string
  /** Global version (monotonically increasing across all devices) */
  latestGlobalVersion: number
  /** Per-device max clocks { deviceSigningPubKey: maxClock } */
  perDeviceMaxClocks: Record<string, number>
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
  return openIdb(DB_NAME, DB_VERSION, (db, oldVersion) => {
    // v1: create stores
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
    if (oldVersion < 4 && db.objectStoreNames.contains('membership-logs')) {
      db.deleteObjectStore('membership-logs')
    }

    // v8: latestSnapshotCiphertextHash field added to document-state-pins
    // No store migration needed — IndexedDB is schemaless, new field is simply
    // undefined on old records. checkDocumentStateRollback is fail-closed:
    // pins without latestSnapshotCiphertextHash reject cross-snapshot transitions
    // (forces reconnect to re-pin with the new field).
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
// Document State Pins (snapshot + clock based)
// =============================================================================

export async function pinDocumentState(pin: DocumentStatePin): Promise<void> {
  const db = await openDb()
  return idbConditionalPut<DocumentStatePin>(
    db,
    STORES.DOCUMENT_STATE_PINS,
    pin.documentId,
    pin,
    (existing) =>
      !existing ||
      // Snapshot transition: always accept new snapshot
      existing.latestSnapshotId !== pin.latestSnapshotId ||
      // Within same snapshot: accept only if per-device clocks are monotonically
      // non-decreasing. This uses signed clock data (not unsigned version) to
      // prevent both pin-freeze (malicious server freezing unsigned version) and
      // pin-downgrade (malicious server sending stale clocks) attacks.
      clocksMonotonicallyAdvanced(existing.perDeviceMaxClocks, pin.perDeviceMaxClocks)
  )
}

/**
 * Check that new clocks are >= existing clocks for all known devices.
 * Existing devices missing from incoming are treated as clock=0 (downgrade).
 * New devices (not in existing) are always accepted.
 */
function clocksMonotonicallyAdvanced(
  existing: Record<string, number>,
  incoming: Record<string, number>,
): boolean {
  for (const [device, existingClock] of Object.entries(existing)) {
    const incomingClock = incoming[device] ?? -1
    if (incomingClock < existingClock) {
      return false
    }
  }
  return true
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
 * Uses per-device clocks (monotonically increasing across snapshots) as the
 * primary integrity check. Global version is only compared within the same
 * snapshot (version resets when a new snapshot is created).
 */
export async function checkDocumentStateRollback(
  documentId: string,
  snapshotId: string | null,
  globalVersion: number,
  perDeviceClocks?: Record<string, number>,
  snapshotProofHash?: string,
  snapshotProofChain?: Array<{ snapshotId: string; ciphertextHash: string; parentSnapshotProof: string }>,
  snapshotCiphertextHash?: string,
): Promise<{ rolledBack: true; pinnedVersion: number; detail?: string } | { rolledBack: false }> {
  const pin = await getDocumentStatePin(documentId)
  if (!pin) return { rolledBack: false }

  // Fail-closed: if server returns null snapshot but we have a pinned snapshot,
  // this is a rollback attack (server deleted a known snapshot).
  if (!snapshotId && pin.latestSnapshotId) {
    return {
      rolledBack: true,
      pinnedVersion: pin.latestGlobalVersion,
      detail: `Snapshot disappeared: server returned null but pinned snapshot ${pin.latestSnapshotId} exists`,
    }
  }

  // Same-snapshot integrity: detect content substitution when snapshotId matches pinned.
  // Compare both parentSnapshotProof (chain integrity) and ciphertextHash (content integrity).
  // A malicious server could replay a valid signed snapshot with a relabeled snapshotId;
  // ciphertextHash comparison prevents substitution of snapshot content.
  if (snapshotId && pin.latestSnapshotId === snapshotId) {
    if (snapshotProofHash && pin.latestSnapshotProofHash && pin.latestSnapshotProofHash !== snapshotProofHash) {
      return {
        rolledBack: true,
        pinnedVersion: pin.latestGlobalVersion,
        detail: 'Snapshot proof hash mismatch',
      }
    }
    if (snapshotCiphertextHash && pin.latestSnapshotCiphertextHash && pin.latestSnapshotCiphertextHash !== snapshotCiphertextHash) {
      return {
        rolledBack: true,
        pinnedVersion: pin.latestGlobalVersion,
        detail: 'Snapshot ciphertext hash mismatch (content substitution detected)',
      }
    }
  }

  // Cross-snapshot rollback detection via proof chain (fail-closed)
  // When the snapshot has changed, proof chain is REQUIRED to verify ancestry.
  // Missing chain → reject as rollback attack.
  if (snapshotId && pin.latestSnapshotId && snapshotId !== pin.latestSnapshotId) {
    if (!snapshotProofChain || snapshotProofChain.length === 0) {
      return {
        rolledBack: true,
        pinnedVersion: pin.latestGlobalVersion,
        detail: `Cross-snapshot rollback: proof chain missing for snapshot transition ${pin.latestSnapshotId} → ${snapshotId}`,
      }
    }
    // Find the chain entry whose snapshotId matches the pinned snapshot
    const pinnedEntry = snapshotProofChain.find((e) => e.snapshotId === pin.latestSnapshotId)
    if (pinnedEntry) {
      // Verify parentSnapshotProof links to the pinned proof hash.
      // Use locally pinned ciphertextHash (not server-provided pinnedEntry.ciphertextHash)
      // to prevent server from substituting the ciphertext of a pinned snapshot.
      // Fail-closed: if latestSnapshotCiphertextHash is missing (pre-v8 pin),
      // we cannot verify proof chain integrity — reject as rollback.
      if (!pin.latestSnapshotCiphertextHash) {
        return {
          rolledBack: true,
          pinnedVersion: pin.latestGlobalVersion,
          detail: `Cross-snapshot rollback: cannot verify proof for pinned snapshot ${pin.latestSnapshotId} (missing ciphertextHash)`,
        }
      }
      const expectedProof = computeParentSnapshotProof(
        pin.latestSnapshotProofHash,
        pin.latestSnapshotId,
        pin.latestSnapshotCiphertextHash,
      )
      if (pinnedEntry.parentSnapshotProof !== expectedProof) {
        return {
          rolledBack: true,
          pinnedVersion: pin.latestGlobalVersion,
          detail: `Cross-snapshot rollback: proof chain mismatch for pinned snapshot ${pin.latestSnapshotId}`,
        }
      }
    } else if (pin.latestSnapshotCiphertextHash) {
      // Pinned snapshot is the BASE of the chain (from_snapshot_id):
      // find_proof_chain walks parent_snapshot_id chain (recursive CTE) which excludes it.
      // Verify the first chain entry's parentSnapshotProof links to the pinned snapshot.
      const firstEntry = snapshotProofChain[0]
      const expectedProof = computeParentSnapshotProof(
        pin.latestSnapshotProofHash,
        pin.latestSnapshotId,
        pin.latestSnapshotCiphertextHash,
      )
      if (firstEntry.parentSnapshotProof !== expectedProof) {
        return {
          rolledBack: true,
          pinnedVersion: pin.latestGlobalVersion,
          detail: `Cross-snapshot rollback: pinned snapshot ${pin.latestSnapshotId} not found in proof chain`,
        }
      }
    } else {
      // No ciphertext hash to verify — cannot confirm chain integrity
      return {
        rolledBack: true,
        pinnedVersion: pin.latestGlobalVersion,
        detail: `Cross-snapshot rollback: pinned snapshot ${pin.latestSnapshotId} not found in proof chain`,
      }
    }
  }

  // Global version is NOT compared for rollback detection.
  // Version is unsigned (server-assigned) and can be inflated by a malicious server
  // to poison the pin (DoS via false positive rollback). Per-device signed clocks
  // provide stronger same-snapshot rollback detection (see below).
  void globalVersion

  // Per-device clocks: only valid within the same snapshot (ADR-015: clocks reset per snapshot).
  // Each device's clock must be >= pinned value.
  // A device disappearing from the clocks map is also a rollback indicator
  // (server dropped updates from a known device).
  if (snapshotId && snapshotId === pin.latestSnapshotId && perDeviceClocks && pin.perDeviceMaxClocks) {
    for (const [deviceKey, pinnedClock] of Object.entries(pin.perDeviceMaxClocks)) {
      const currentClock = perDeviceClocks[deviceKey]
      if (currentClock === undefined) {
        return {
          rolledBack: true,
          pinnedVersion: pin.latestGlobalVersion,
          detail: `Device ${deviceKey} disappeared: pinned clock=${pinnedClock} but device absent from server clocks`,
        }
      }
      if (currentClock < pinnedClock) {
        return {
          rolledBack: true,
          pinnedVersion: pin.latestGlobalVersion,
          detail: `Device ${deviceKey} clock rolled back: server=${currentClock}, pinned=${pinnedClock}`,
        }
      }
    }
  }

  return { rolledBack: false }
}

export async function clearAllDocumentStatePins(): Promise<void> {
  const db = await openDb()
  await idbClear(db, STORES.DOCUMENT_STATE_PINS)
}
