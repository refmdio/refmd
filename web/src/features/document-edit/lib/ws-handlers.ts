/**
 * WebSocket Message Handlers
 *
 * Extracted from useDocumentEdit.ts for maintainability.
 * Handles the three largest WS message callbacks:
 * - onDocument: initial document load / delta reconnect
 * - onSnapshot: remote snapshot broadcast
 * - onSnapshotSaveFailed: snapshot save rejection with server state recovery
 *
 * All snapshot signature verifications use a shared fail-closed helper:
 * missing signing key → reject (no silent skip).
 */

import * as Y from 'yjs'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  base64UrlDecode,
  base64UrlEncode,
  decryptSnapshot,
  computeSnapshotCiphertextHash,
  computeParentSnapshotProof,
  buildWsEnvelopeMessage,
  WS_SIGNATURE_PREFIX,
} from '@/shared/lib/crypto'
import type { DeviceState } from '@/shared/model/auth-types'
import { VerificationError } from './ws'
import type { DocumentWebSocket } from './ws'
import type {
  WsConnectionMode,
  WsDocumentMessage,
  WsSnapshotMessage,
  WsSnapshotSaveFailedMessage,
  WsSnapshotData,
} from './ws'
import { checkDocumentStateRollback, pinDocumentState, getDocumentStatePin } from '@/shared/lib/anti-rollback'
import { verifySnapshotProofChain } from './document-verification-service'
import { verifyAndApplyWsUpdates } from './auto-sync'
import type { DocumentState } from './types'

// =============================================================================
// Types
// =============================================================================

export interface HandlerDeps {
  documentId: string
  deviceRef: { current: DeviceState | null }
  ws: DocumentWebSocket
}

// =============================================================================
// Shared signature verification (fail-closed)
// =============================================================================

/**
 * Verify a snapshot's envelope signature.
 *
 * Fail-closed: returns false if the signing key is not found in the local
 * key cache (unknown device) OR if the signature doesn't match. Callers
 * must reject the snapshot when this returns false.
 */
function verifySnapshotSignature(
  snapshot: { data: string; nonce: string; signature: string; publicData?: Record<string, unknown>; createdByDevice: string },
  signingKeys: Map<string, Uint8Array>,
  context: string,
): boolean {
  if (!snapshot.publicData) {
    console.error(`[ws] ${context}: missing publicData, rejecting`)
    return false
  }

  // Use signed publicData.signingPubKey as the source of truth (not unsigned createdByDevice)
  const signedPubKey = snapshot.publicData.signingPubKey as string | undefined
  if (!signedPubKey) {
    console.error(`[ws] ${context}: missing signingPubKey in publicData, rejecting`)
    return false
  }
  const signingKey = signingKeys.get(signedPubKey)
  if (!signingKey) {
    console.error(`[ws] ${context}: unknown signing key ${signedPubKey}, rejecting (fail-closed)`)
    return false
  }

  const envMsg = buildWsEnvelopeMessage(
    WS_SIGNATURE_PREFIX.SNAPSHOT,
    snapshot.data,
    snapshot.nonce,
    snapshot.publicData,
    base64UrlEncode,
  )
  const sig = base64UrlDecode(snapshot.signature)
  if (!ed25519.verify(sig, envMsg, signingKey)) {
    console.error(`[ws] ${context}: signature verification failed`)
    return false
  }

  return true
}

/**
 * Verify ciphertext hash and decrypt a snapshot.
 * Returns decrypted Y.js state and the recomputed ciphertext hash, or null on failure.
 */
function verifyAndDecryptSnapshot(
  snapshot: WsSnapshotData,
  dek: Uint8Array,
  documentId: string,
  keyVersion: number,
): { decrypted: Uint8Array; ciphertextHash: string } | null {
  const ciphertextBytes = base64UrlDecode(snapshot.data)

  const recomputedHash = computeSnapshotCiphertextHash(ciphertextBytes)
  if (recomputedHash !== snapshot.ciphertextHash) {
    console.error('[ws] Snapshot ciphertext hash mismatch')
    return null
  }

  const nonceBytes = base64UrlDecode(snapshot.nonce)
  const decrypted = decryptSnapshot(ciphertextBytes, nonceBytes, dek, documentId, keyVersion)
  return { decrypted, ciphertextHash: recomputedHash }
}

// =============================================================================
// onDocument handler
// =============================================================================

/**
 * Handle the initial `document` message (complete or delta reconnect).
 *
 * Performs: snapshot signature verification (fail-closed), ciphertext hash check,
 * decryption, proof chain verification, anti-rollback check, Y.Doc application,
 * and anti-rollback pinning.
 *
 * The `mode` parameter is used to disambiguate `snapshot: null`:
 * - delta mode + state.initialized + state.activeSnapshotId != null → "snapshot unchanged"
 * - otherwise → "no snapshot exists" (new document)
 * See collaboration.md: delta response snapshot:null disambiguation rule
 */
export async function handleDocumentMessage(
  msg: WsDocumentMessage,
  mode: WsConnectionMode,
  state: DocumentState,
  deps: HandlerDeps,
): Promise<void> {
  const { documentId, deviceRef, ws } = deps

  try {
    // Disambiguate snapshot: null based on connection mode and client state
    const isDeltaUnchanged = msg.snapshot === null
      && mode === 'delta'
      && state.initialized
      && state.activeSnapshotId !== null

    const isSnapshotTransition = msg.snapshot !== null && msg.snapshot.id !== state.activeSnapshotId

    // Complete mode with the same snapshotId must still re-verify (authoritative mode).
    // Only delta mode with unchanged snapshot may skip verification.
    const needsSnapshotVerification = msg.snapshot !== null && (isSnapshotTransition || mode === 'complete')

    // Decrypted snapshot Y.js state — deferred until after anti-rollback check
    let pendingSnapshotUpdate: Uint8Array | null = null
    // Track whether this is a new-document (no snapshot) case for post-check commit
    const isNewDocument = msg.snapshot === null && !isDeltaUnchanged

    if (isNewDocument) {
      // New document (or complete mode with no snapshot): state reset deferred
      // until after anti-rollback check (verify-then-commit).
    } else if (isDeltaUnchanged) {
      // Delta reconnect with same snapshot: skip signature/decrypt,
      // just apply delta updates below.
    } else if (needsSnapshotVerification && msg.snapshot !== null) {
      // Full signature + ciphertext verification required.
      // Triggered for: snapshot ID change (any mode) OR complete mode (even same ID).
      if (!verifySnapshotSignature(msg.snapshot, state.signingKeys, 'Document snapshot')) {
        throw new VerificationError('Document snapshot signature verification failed')
      }

      // Cross-validate: unsigned top-level fields must match signed publicData.
      // Prevents a compromised server from altering snapshotId, parentSnapshotProof,
      // or keyVersion while keeping the signature valid over the original publicData.
      // snapshotId is REQUIRED in signed publicData (fail-closed).
      const spd = msg.snapshot.publicData as Record<string, unknown> | undefined
      if (!spd?.snapshotId) {
        throw new VerificationError('Snapshot missing snapshotId in signed publicData (fail-closed)')
      }
      if (spd.snapshotId !== msg.snapshot.id) {
        throw new VerificationError('Snapshot id mismatch with signed publicData.snapshotId')
      }
      if (spd.parentSnapshotProof !== undefined && spd.parentSnapshotProof !== msg.snapshot.parentSnapshotProof) {
        throw new VerificationError('Snapshot parentSnapshotProof mismatch with signed publicData')
      }
      if (spd.keyVersion !== undefined && spd.keyVersion !== msg.snapshot.keyVersion) {
        throw new VerificationError('Snapshot keyVersion mismatch with signed publicData')
      }
      if (spd.docId !== undefined && spd.docId !== msg.snapshot.documentId) {
        throw new VerificationError('Snapshot documentId mismatch with signed publicData')
      }
      if (spd.signingPubKey !== undefined && spd.signingPubKey !== msg.snapshot.createdByDevice) {
        throw new VerificationError('Snapshot createdByDevice mismatch with signed publicData.signingPubKey')
      }

      const result = verifyAndDecryptSnapshot(msg.snapshot, state.dek, documentId, msg.snapshot.keyVersion)
      if (!result) throw new VerificationError('Document snapshot ciphertext hash mismatch or decrypt failed')
      pendingSnapshotUpdate = result.decrypted

      // Validate decrypted Yjs bytes before any state transition.
      // A malicious collaborator could sign garbage encrypted with the DEK.
      if (pendingSnapshotUpdate) {
        const validationDoc = new Y.Doc()
        Y.applyUpdate(validationDoc, pendingSnapshotUpdate, 'remote')
        validationDoc.destroy()
      }

      // Verify proof chain (delta reconnections include chain entries)
      if (msg.snapshotProofChain && msg.snapshotProofChain.length > 0) {
        verifySnapshotProofChain(
          {
            id: msg.snapshot.id,
            ciphertext_hash: msg.snapshot.ciphertextHash,
            parent_snapshot_proof: msg.snapshot.parentSnapshotProof,
          },
          msg.snapshotProofChain.map((e) => ({
            snapshot_id: e.snapshotId,
            ciphertext_hash: e.ciphertextHash,
            parent_snapshot_proof: e.parentSnapshotProof,
          })),
          state.snapshotProofHash,
          state.activeSnapshotId ?? undefined,
          state.snapshotCiphertextHash,
        )
      }
    }

    // Compute projected clocks and version BEFORE applying updates (fail-closed anti-rollback)
    // Complete mode always resets clocks (authoritative); delta with same snapshot keeps
    // confirmed (server-acked) clocks only — using knownClocks would include optimistic
    // local clocks that mask server-side rollbacks of unconfirmed updates.
    const baseClocks = needsSnapshotVerification ? {} : { ...state.confirmedClocks }
    const projectedClocks: Record<string, number> = { ...baseClocks }
    for (const update of msg.updates) {
      const lastClock = projectedClocks[update.deviceSigningPubKey]
      if (lastClock === undefined || update.clock > lastClock) {
        projectedClocks[update.deviceSigningPubKey] = update.clock
      }
    }

    // Anti-rollback check
    // For delta unchanged: use the existing activeSnapshotId (server omitted snapshot data).
    // For new document (null, not delta unchanged): pass null so checkDocumentStateRollback
    // can detect if a previously-pinned snapshot was deleted (rollback attack).
    const checkSnapshotId = isDeltaUnchanged
      ? state.activeSnapshotId
      : (msg.snapshot?.id ?? null)

    let latestVersion: number
    if (msg.updates.length > 0) {
      latestVersion = msg.updates[msg.updates.length - 1].version
    } else if (needsSnapshotVerification) {
      latestVersion = 0
    } else {
      const existingPin = await getDocumentStatePin(documentId)
      latestVersion = (existingPin?.latestSnapshotId === checkSnapshotId)
        ? existingPin.latestGlobalVersion
        : 0
    }

    const checkProofHash = needsSnapshotVerification
      ? msg.snapshot!.parentSnapshotProof
      : state.snapshotProofHash

    const checkCiphertextHash = needsSnapshotVerification
      ? msg.snapshot!.ciphertextHash
      : state.snapshotCiphertextHash

    try {
      const rollback = await checkDocumentStateRollback(
        documentId,
        checkSnapshotId,
        latestVersion,
        projectedClocks,
        checkProofHash,
        msg.snapshotProofChain?.map((e) => ({
          snapshotId: e.snapshotId,
          ciphertextHash: e.ciphertextHash,
          parentSnapshotProof: e.parentSnapshotProof,
        })),
        checkCiphertextHash,
      )
      if (rollback.rolledBack) {
        const detail = rollback.detail ? ` (${rollback.detail})` : ''
        throw new VerificationError(`Document rollback detected: pinned=${rollback.pinnedVersion}${detail}`)
      }
    } catch (err) {
      if (err instanceof VerificationError) throw err
      throw new VerificationError(`Anti-rollback check failed: ${err}`)
    }

    // Anti-rollback passed — now commit state changes.

    // New document (no snapshot): reset all state to ensure clean start.
    if (isNewDocument) {
      ws.drainAllQueues()
      state.activeSnapshotId = null
      state.snapshotProofHash = ''
      state.snapshotCiphertextHash = ''
      state.knownClocks = {}
      state.confirmedClocks = {}
      state.localClock = 0
      state.snapshotUpdatesCount = 0
      state.pendingSnapshot = null
      state.lastSavedState = Y.encodeStateAsUpdate(state.yDoc)
    }

    // Complete mode always resets state (authoritative reconnect, even with same snapshotId).
    if (needsSnapshotVerification && msg.snapshot) {
      ws.drainAllQueues()
      state.activeSnapshotId = msg.snapshot.id
      state.snapshotCiphertextHash = msg.snapshot.ciphertextHash
      state.snapshotProofHash = msg.snapshot.parentSnapshotProof
      state.keyVersion = msg.snapshot.keyVersion
      state.knownClocks = {}
      state.confirmedClocks = {}
      state.localClock = 0
      state.snapshotUpdatesCount = 0
      state.pendingSnapshot = null
    }

    // For snapshot verification (complete mode or snapshot transition), track server-only
    // state in a separate Y.Doc so lastSavedState excludes local unsent changes.
    // For delta unchanged with updates, also track separately for the same reason.
    const needsServerDoc = needsSnapshotVerification || (isDeltaUnchanged && msg.updates.length > 0)
    const serverDoc = needsServerDoc ? new Y.Doc() : undefined

    // Apply snapshot + updates atomically
    state.yDoc.transact(() => {
      if (pendingSnapshotUpdate) {
        Y.applyUpdate(state.yDoc, pendingSnapshotUpdate, 'remote')
        if (serverDoc) Y.applyUpdate(serverDoc, pendingSnapshotUpdate, 'remote')
      }
      if (msg.updates.length > 0) {
        // For delta unchanged serverDoc: seed with current server state first
        if (isDeltaUnchanged && serverDoc && state.lastSavedState) {
          Y.applyUpdate(serverDoc, state.lastSavedState, 'remote')
        }
        // Reset knownClocks to confirmedClocks before processing delta updates
        // so verifyAndApplyWsUpdates uses server-confirmed base clocks (not
        // optimistic values from pre-disconnect in-flight sends).
        if (isDeltaUnchanged) {
          state.knownClocks = { ...state.confirmedClocks }
        }
        state.knownClocks = verifyAndApplyWsUpdates(msg.updates, state, documentId, serverDoc)
        // Server-returned updates are confirmed — sync confirmedClocks
        state.confirmedClocks = { ...state.knownClocks }
      }
    }, 'remote')

    if (serverDoc) {
      state.lastSavedState = Y.encodeStateAsUpdate(serverDoc)
      serverDoc.destroy()
    } else {
      state.lastSavedState = Y.encodeStateAsUpdate(state.yDoc)
    }

    // Initialize snapshot updates counter from server metadata.
    // For delta unchanged, the server omits snapshot data, so we can't read latestVersion.
    // Use existing count + delta updates received.
    if (isDeltaUnchanged) {
      state.snapshotUpdatesCount += msg.updates.length
    } else {
      state.snapshotUpdatesCount = msg.snapshot?.latestVersion ?? msg.updates.length
    }

    // Determine local clock for this device
    const dev = deviceRef.current
    if (dev) {
      const myKey = base64UrlEncode(dev.deviceKeys.signingPublicKey)
      state.localClock = myKey in state.knownClocks
        ? state.knownClocks[myKey] + 1
        : 0
    }

    // Mark as initialized (first onDocument after connect)
    state.initialized = true

    // If snapshot was re-verified (transition or complete reconnect), trigger auto-sync
    // to resend local changes under the (possibly reset) snapshot state.
    if (needsSnapshotVerification) {
      state.autoSync?.notifyPendingChanges()
    }

    // Update knownState for delta reconnection (use confirmed clocks only)
    ws.updateKnownState(state.activeSnapshotId, state.confirmedClocks)

    // Pin anti-rollback state (use confirmed clocks for persistent state)
    await pinDocumentState({
      documentId,
      latestSnapshotId: state.activeSnapshotId,
      latestSnapshotProofHash: state.snapshotProofHash,
      latestSnapshotCiphertextHash: state.snapshotCiphertextHash,
      latestGlobalVersion: latestVersion,
      perDeviceMaxClocks: state.confirmedClocks,
      observedAt: Date.now(),
    })
  } catch (err) {
    if (err instanceof VerificationError) throw err
    console.error('[ws] Failed to apply document message:', err)
    throw err
  }
}

// =============================================================================
// onSnapshot handler
// =============================================================================

/**
 * Handle a remote snapshot broadcast from another client.
 *
 * Performs: envelope signature verification (fail-closed), ciphertext hash check,
 * parent proof verification, decryption, Y.Doc application,
 * state transition, and anti-rollback pinning.
 *
 * Note: cross-snapshot proof chain validation (checkDocumentStateRollback) is NOT
 * applied here per design (collaboration.md L526: only 'document' and
 * 'snapshot-save-failed' messages). Direct parentSnapshotProof verification is
 * sufficient for real-time 1-generation snapshot broadcasts.
 */
export async function handleSnapshotMessage(
  msg: WsSnapshotMessage,
  state: DocumentState,
  deps: HandlerDeps,
): Promise<void> {
  const { documentId, ws } = deps

  try {
    const pd = msg.snapshot.publicData
    if (!pd) {
      throw new VerificationError('Remote snapshot missing publicData')
    }
    const signingPubKeyB64 = pd.signingPubKey as string
    const signingKey = state.signingKeys.get(signingPubKeyB64)
    if (!signingKey) {
      throw new VerificationError(`Remote snapshot: unknown signing key ${signingPubKeyB64} (fail-closed)`)
    }

    // 1. Verify envelope signature
    const envelopeMessage = buildWsEnvelopeMessage(
      WS_SIGNATURE_PREFIX.SNAPSHOT,
      msg.snapshot.ciphertext,
      msg.snapshot.nonce,
      pd,
      base64UrlEncode,
    )
    const sigBytes = base64UrlDecode(msg.snapshot.signature)
    if (!ed25519.verify(sigBytes, envelopeMessage, signingKey)) {
      throw new VerificationError('Remote snapshot: signature verification failed')
    }

    // 2. Compute ciphertext hash (pre-decrypt)
    const ciphertextBytes = base64UrlDecode(msg.snapshot.ciphertext)
    const ciphertextHash = computeSnapshotCiphertextHash(ciphertextBytes)

    // 3. Verify proof chain (parentSnapshotProof must match expected)
    const parentSnapshotProof = pd.parentSnapshotProof as string ?? ''
    if (state.activeSnapshotId !== null) {
      const expectedProof = computeParentSnapshotProof(
        state.snapshotProofHash,
        state.activeSnapshotId,
        state.snapshotCiphertextHash,
      )
      if (parentSnapshotProof !== expectedProof) {
        throw new VerificationError('Snapshot proof chain verification failed')
      }
    }

    // 4. Decrypt BEFORE state transition (fail-closed: decrypt error must not
    //    leave state half-transitioned with activeSnapshotId pointing to an
    //    unapplied snapshot)
    const nonceBytes = base64UrlDecode(msg.snapshot.nonce)
    const keyVersion = (pd.keyVersion as number) ?? state.keyVersion
    const yjsState = decryptSnapshot(ciphertextBytes, nonceBytes, state.dek, documentId, keyVersion)

    // 5. Validate Yjs payload BEFORE destructive state changes.
    //    Apply to a temporary Y.Doc first — if the bytes are invalid Yjs encoding
    //    (malicious collaborator signed garbage), this throws before any state mutation.
    const serverDoc = new Y.Doc()
    Y.applyUpdate(serverDoc, yjsState, 'remote')
    const lastSavedState = Y.encodeStateAsUpdate(serverDoc)
    serverDoc.destroy()

    // 6. Cross-validate signed docId against current document
    const signedDocId = pd.docId as string | undefined
    if (signedDocId !== undefined && signedDocId !== documentId) {
      throw new VerificationError('Remote snapshot: docId mismatch with signed publicData')
    }

    // 7. Use the signed snapshotId from publicData (not the unsigned msg.snapshotId)
    //    to prevent server forgery of snapshot IDs in anti-rollback pins.
    const signedSnapshotId = pd.snapshotId as string
    if (!signedSnapshotId) {
      throw new VerificationError('Remote snapshot: missing snapshotId in signed publicData')
    }
    // Cross-validate unsigned top-level snapshotId against signed publicData
    if (msg.snapshotId !== signedSnapshotId) {
      throw new VerificationError('Remote snapshot: snapshotId mismatch with signed publicData')
    }

    // 8. Drain all queues (pending messages reference old snapshot and will be rejected)
    ws.drainAllQueues()

    // 9. Transition to the new snapshot
    state.activeSnapshotId = signedSnapshotId
    state.snapshotProofHash = parentSnapshotProof
    state.snapshotCiphertextHash = ciphertextHash
    state.keyVersion = keyVersion
    state.knownClocks = {}
    state.confirmedClocks = {}
    state.localClock = 0
    state.snapshotUpdatesCount = 0
    state.pendingSnapshot = null

    // 10. Apply to live Y.Doc (already validated above)
    Y.applyUpdate(state.yDoc, yjsState, 'remote')
    state.lastSavedState = lastSavedState
    ws.updateKnownState(signedSnapshotId, {})

    // Trigger auto-sync to resend any local unsent changes under new snapshot
    state.autoSync?.notifyPendingChanges()

    // Advance anti-rollback pin after remote snapshot transition
    await pinDocumentState({
      documentId,
      latestSnapshotId: signedSnapshotId,
      latestSnapshotProofHash: parentSnapshotProof,
      latestSnapshotCiphertextHash: ciphertextHash,
      latestGlobalVersion: 0,
      perDeviceMaxClocks: {},
      observedAt: Date.now(),
    })
  } catch (err) {
    if (err instanceof VerificationError) throw err
    console.error('[ws] Failed to apply remote snapshot:', err)
    throw err
  }
}

// =============================================================================
// onSnapshotSaveFailed handler
// =============================================================================

/**
 * Handle snapshot-save-failed message from server.
 *
 * Server returns its current state (snapshot + updates) when our snapshot save
 * was rejected. Performs: signature verification (fail-closed), ciphertext hash
 * check, decryption (deferred), proof chain verification, anti-rollback check,
 * Y.Doc atomic application, state transition, and anti-rollback pinning.
 */
export async function handleSnapshotSaveFailedMessage(
  msg: WsSnapshotSaveFailedMessage,
  state: DocumentState,
  deps: HandlerDeps,
): Promise<void> {
  const { documentId, deviceRef, ws } = deps

  ws.resolvePendingSnapshot()
  state.pendingSnapshot = null

  if (!msg.snapshot) {
    // Fail-closed: if we have a pinned snapshot but server returns null,
    // this is a rollback attack (server deleted a known snapshot).
    const pin = await getDocumentStatePin(documentId)
    if (pin?.latestSnapshotId) {
      throw new VerificationError('Snapshot-save-failed: server returned null snapshot but pin exists (rollback)')
    }
    return
  }

  try {
    // 1. Fail-closed signature verification
    if (!verifySnapshotSignature(msg.snapshot, state.signingKeys, 'Snapshot-save-failed')) {
      throw new VerificationError('Snapshot-save-failed signature verification failed')
    }

    // Cross-validate: unsigned top-level fields must match signed publicData.
    // snapshotId is REQUIRED in signed publicData (fail-closed).
    const spd = msg.snapshot.publicData as Record<string, unknown> | undefined
    if (!spd?.snapshotId) {
      throw new VerificationError('Snapshot-save-failed missing snapshotId in signed publicData (fail-closed)')
    }
    if (spd.snapshotId !== msg.snapshot.id) {
      throw new VerificationError('Snapshot-save-failed id mismatch with signed publicData.snapshotId')
    }
    if (spd.parentSnapshotProof !== undefined && spd.parentSnapshotProof !== msg.snapshot.parentSnapshotProof) {
      throw new VerificationError('Snapshot-save-failed parentSnapshotProof mismatch with signed publicData')
    }
    if (spd.keyVersion !== undefined && spd.keyVersion !== msg.snapshot.keyVersion) {
      throw new VerificationError('Snapshot-save-failed keyVersion mismatch with signed publicData')
    }
    if (spd.docId !== undefined && spd.docId !== msg.snapshot.documentId) {
      throw new VerificationError('Snapshot-save-failed documentId mismatch with signed publicData')
    }
    if (spd.signingPubKey !== undefined && spd.signingPubKey !== msg.snapshot.createdByDevice) {
      throw new VerificationError('Snapshot-save-failed createdByDevice mismatch with signed publicData.signingPubKey')
    }

    // 2. Decrypt snapshot but DON'T apply yet (deferred until after anti-rollback)
    // Fail-closed: always reject if hash/decrypt fails, regardless of ciphertext length.
    // Empty ciphertext must still pass ciphertextHash verification.
    const decryptResult = verifyAndDecryptSnapshot(msg.snapshot, state.dek, documentId, msg.snapshot.keyVersion)
    if (!decryptResult) {
      throw new VerificationError('Snapshot-save-failed ciphertext hash mismatch or decrypt failed')
    }
    const pendingSnapshotUpdate = decryptResult.decrypted

    // 2b. Validate decrypted Yjs bytes before any state transition.
    //     A malicious collaborator could sign garbage encrypted with the DEK.
    //     Validating on a temporary Y.Doc ensures the bytes are valid Yjs encoding.
    if (pendingSnapshotUpdate) {
      const validationDoc = new Y.Doc()
      Y.applyUpdate(validationDoc, pendingSnapshotUpdate, 'remote')
      validationDoc.destroy()
    }

    // 3. Verify proof chain (if provided)
    if (msg.snapshotProofChain && msg.snapshotProofChain.length > 0) {
      verifySnapshotProofChain(
        {
          id: msg.snapshot.id,
          ciphertext_hash: msg.snapshot.ciphertextHash,
          parent_snapshot_proof: msg.snapshot.parentSnapshotProof,
        },
        msg.snapshotProofChain.map((e) => ({
          snapshot_id: e.snapshotId,
          ciphertext_hash: e.ciphertextHash,
          parent_snapshot_proof: e.parentSnapshotProof,
        })),
        state.snapshotProofHash,
        state.activeSnapshotId ?? undefined,
        state.snapshotCiphertextHash,
      )
    }

    // 4. Compute projected clocks WITHOUT applying updates (for anti-rollback)
    // Use empty base clocks: snapshot-save-failed returns ALL updates (complete mode,
    // starting from clock=0), so projectedClocks should be derived entirely from the
    // verified updates. msg.snapshot.clocks is unsigned (server-cached) and could be
    // inflated to mask dropped updates.
    const projectedClocks: Record<string, number> = {}
    for (const update of msg.updates) {
      const lastClock = projectedClocks[update.deviceSigningPubKey]
      if (lastClock === undefined || update.clock > lastClock) {
        projectedClocks[update.deviceSigningPubKey] = update.clock
      }
    }
    const latestVersion = msg.updates.length > 0
      ? msg.updates[msg.updates.length - 1].version
      : 0

    // 5. Anti-rollback check (fail-closed: BEFORE any Y.Doc mutation)
    const rollback = await checkDocumentStateRollback(
      documentId,
      msg.snapshot.id,
      latestVersion,
      projectedClocks,
      msg.snapshot.parentSnapshotProof,
      msg.snapshotProofChain?.map((e) => ({
        snapshotId: e.snapshotId,
        ciphertextHash: e.ciphertextHash,
        parentSnapshotProof: e.parentSnapshotProof,
      })),
      msg.snapshot.ciphertextHash,
    )
    if (rollback.rolledBack) {
      const detail = rollback.detail ? ` (${rollback.detail})` : ''
      throw new VerificationError(`Snapshot-save-failed: rollback detected: pinned=${rollback.pinnedVersion}${detail}`)
    }

    // 6. Anti-rollback passed — apply everything atomically
    ws.drainAllQueues()
    state.activeSnapshotId = msg.snapshot.id
    state.snapshotCiphertextHash = msg.snapshot.ciphertextHash
    state.snapshotProofHash = msg.snapshot.parentSnapshotProof
    state.keyVersion = msg.snapshot.keyVersion
    // Reset knownClocks to empty before processing updates: snapshot-save-failed
    // returns ALL updates (complete mode), so updates start from clock=0.
    // snapshot.clocks is a live cache of max clocks, not a base for post-snapshot updates.
    state.knownClocks = {}

    const serverDoc = new Y.Doc()
    state.yDoc.transact(() => {
      if (pendingSnapshotUpdate) {
        Y.applyUpdate(state.yDoc, pendingSnapshotUpdate, 'remote')
        Y.applyUpdate(serverDoc, pendingSnapshotUpdate, 'remote')
      }
      if (msg.updates.length > 0) {
        state.knownClocks = verifyAndApplyWsUpdates(msg.updates, state, documentId, serverDoc)
      }
    }, 'remote')

    // Server-returned state is confirmed — sync confirmedClocks
    state.confirmedClocks = { ...state.knownClocks }

    state.snapshotUpdatesCount = msg.updates?.length ?? 0
    state.lastSavedState = Y.encodeStateAsUpdate(serverDoc)
    serverDoc.destroy()
    ws.updateKnownState(msg.snapshot.id, state.confirmedClocks)

    // Recompute localClock from server state
    const dev = deviceRef.current
    if (dev) {
      const myKey = base64UrlEncode(dev.deviceKeys.signingPublicKey)
      state.localClock = myKey in state.knownClocks
        ? state.knownClocks[myKey] + 1
        : 0
    }

    // Pin anti-rollback state after all checks pass (use confirmed clocks)
    await pinDocumentState({
      documentId,
      latestSnapshotId: state.activeSnapshotId,
      latestSnapshotProofHash: state.snapshotProofHash,
      latestSnapshotCiphertextHash: state.snapshotCiphertextHash,
      latestGlobalVersion: latestVersion,
      perDeviceMaxClocks: state.confirmedClocks,
      observedAt: Date.now(),
    })

    // Trigger auto-sync to resend any local unsent changes
    state.autoSync?.notifyPendingChanges()
  } catch (err) {
    if (err instanceof VerificationError) throw err
    console.error('[ws] Failed to apply snapshot-save-failed state:', err)
    throw err
  }
}
