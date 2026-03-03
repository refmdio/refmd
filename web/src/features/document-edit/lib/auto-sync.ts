/**
 * Auto-Sync Service
 *
 * Watches for local document changes and automatically syncs them via WebSocket:
 * - Local changes: throttle → encrypt → sign → WS send
 * - Remote updates: decrypt → verify → Y.Doc apply
 * - Confirmations: resolve pending, snapshot threshold check
 * - Snapshots: create and send via WS when threshold reached
 *
 * Two edit detection paths:
 * - PM edits: Y.Text observer catches ORIGIN_PM_TO_TEXT (bridgeSyncPlugin)
 * - CM edits: CodeMirrorEditor calls notifyLocalEdit() from a CM ViewPlugin
 *   when CodeMirror emits doc-changing user-event transactions
 *
 * yCollab (y-codemirror.next) writes to Y.Text with a YSyncConfig object
 * as origin. These are ALWAYS filtered because yCollab echoes remote content
 * back through CM with normalization artifacts that cause oscillating sends.
 */

import * as Y from 'yjs'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  base64UrlEncode,
  base64UrlDecode,
  encryptContent,
  decryptContent,
  encryptSnapshot,
  computeSnapshotCiphertextHash,
  computeParentSnapshotProof,
  computeUpdateHash,
  buildWsEnvelopeMessage,
  WS_SIGNATURE_PREFIX,
} from '@/shared/lib/crypto'
import type { DeviceState } from '@/shared/model/auth-types'
import { VerificationError, TofuKeyChangeError } from './ws'
import type { DocumentWebSocket } from './ws'
import type {
  WsUpdateMessage,
  WsUpdateSavedMessage,
  WsUpdateSaveFailedMessage,
  WsUpdateData,
  QueuedMessage,
} from './ws'
import { ORIGIN_PM_TO_TEXT } from '@pm-cm/yjs'
import { pinDocumentState } from '@/shared/lib/anti-rollback'
import type { DocumentState } from './types'
import { resolveSigningKey } from './document-verification-service'

/** Throttle interval for auto-sync (ms) — sends at most once per interval */
const THROTTLE_MS = 25

/** Threshold for creating a new snapshot (number of updates per snapshot) */
const SNAPSHOT_UPDATE_THRESHOLD = 100

// =============================================================================
// Auto-Sync: Local changes → WS send
// =============================================================================

export interface AutoSyncDeps {
  documentId: string
  device: { current: DeviceState | null }
  getState: () => DocumentState | undefined
  getWs: () => DocumentWebSocket | null
}

export interface AutoSyncHandle {
  dispose: () => void
  /** Notify that there are pending changes to resend (e.g. after a non-snapshot save failure) */
  notifyPendingChanges: () => void
  /** Called by the CM ViewPlugin when a genuine local edit is detected */
  notifyLocalEdit: () => void
}

/**
 * Start auto-syncing local document changes to the server via WebSocket.
 *
 * Two edit detection paths:
 *
 * 1. **PM edits**: Y.Text observer catches ORIGIN_PM_TO_TEXT — this is the
 *    only Y.Text origin that represents a genuine ProseMirror user edit
 *    flowing through bridgeSyncPlugin → replaceSharedText.
 *
 * 2. **CM edits**: The CodeMirrorEditor component has a CM ViewPlugin that
 *    detects doc-changing user-event transactions and calls
 *    `notifyLocalEdit()`.
 *
 * All other Y.Text origins are filtered:
 * - 'remote': applied by us from WS
 * - ORIGIN_TEXT_TO_PM / ORIGIN_INIT: bridge internal reconciliation
 * - YSyncConfig object: yCollab echo — CM processes remote content and
 *   writes back a normalized version, causing oscillating sends
 */
export function startAutoSync(deps: AutoSyncDeps): AutoSyncHandle {
  let disposed = false
  let sending = false
  let dirty = false
  let trailingTimer: ReturnType<typeof setTimeout> | null = null
  let lastSendTime = 0

  const doSend = () => {
    if (disposed || sending) {
      dirty = true
      return
    }
    const state = deps.getState()
    if (!state?.initialized) {
      dirty = true
      return
    }
    dirty = false
    sending = true
    lastSendTime = Date.now()
    sendPendingChanges(deps)
      .catch((err) => {
        console.error('[auto-sync] send failed:', err)
      })
      .finally(() => {
        sending = false
        if (dirty && !disposed) {
          scheduleSend()
        }
      })
  }

  const scheduleSend = () => {
    if (disposed) return
    const elapsed = Date.now() - lastSendTime
    if (elapsed >= THROTTLE_MS) {
      if (trailingTimer) { clearTimeout(trailingTimer); trailingTimer = null }
      doSend()
    } else if (!trailingTimer) {
      trailingTimer = setTimeout(() => {
        trailingTimer = null
        doSend()
      }, THROTTLE_MS - elapsed)
    }
  }

  // Y.Text observer — only fires for ORIGIN_PM_TO_TEXT (PM user edits via bridge).
  // All other origins are filtered to prevent the yCollab echo loop.
  const onTextChange = (_event: Y.YTextEvent, transaction: Y.Transaction) => {
    if (disposed) return
    if (transaction.origin !== ORIGIN_PM_TO_TEXT) return
    dirty = true
    scheduleSend()
  }

  const state = deps.getState()
  if (state) {
    state.yDoc.getText('content').observe(onTextChange)
  }

  return {
    dispose: () => {
      // Flush any pending changes before tearing down
      if (trailingTimer) { clearTimeout(trailingTimer); trailingTimer = null }
      if (dirty && !sending) {
        doSend()
      }
      disposed = true
      const s = deps.getState()
      if (s) s.yDoc.getText('content').unobserve(onTextChange)
    },
    notifyPendingChanges: () => {
      dirty = true
      scheduleSend()
    },
    notifyLocalEdit: () => {
      if (disposed) return
      dirty = true
      scheduleSend()
    },
  }
}

/**
 * Compute Y.js diff from last saved state and send via WebSocket.
 * If no snapshot exists yet (genesis), creates and sends the first snapshot.
 */
async function sendPendingChanges(deps: AutoSyncDeps): Promise<void> {
  const { documentId } = deps
  const device = deps.device.current
  const state = deps.getState()
  const ws = deps.getWs()
  if (!state || !ws || !device) return

  // No active snapshot yet — create and send genesis snapshot
  if (state.activeSnapshotId === null) {
    if (state.pendingSnapshot) return  // Already sending a genesis snapshot
    createAndSendGenesisSnapshot(state, ws, documentId, device)
    return
  }

  // Compute diff from last saved state
  let updateToSend: Uint8Array
  const savedState = state.lastSavedState

  if (savedState) {
    const tempDoc = new Y.Doc()
    Y.applyUpdate(tempDoc, savedState)
    const savedVector = Y.encodeStateVector(tempDoc)
    updateToSend = Y.encodeStateAsUpdate(state.yDoc, savedVector)
    tempDoc.destroy()

    // Nothing to send (Y.js minimal header is typically 2 bytes for empty diff)
    if (updateToSend.length <= 2) return
  } else {
    updateToSend = Y.encodeStateAsUpdate(state.yDoc)
  }

  // Encrypt
  const { encrypted, nonce } = encryptContent(updateToSend, state.dek, documentId, state.keyVersion)
  const ciphertextB64 = base64UrlEncode(encrypted)
  const nonceB64 = base64UrlEncode(nonce)

  const deviceSigningPubKey = base64UrlEncode(device.deviceKeys.signingPublicKey)
  const clock = state.localClock
  const timestamp = Date.now()

  // Compute update_hash per update-hash.md spec (client-side, sent to server for verification)
  const updateHash = computeUpdateHash({
    clock,
    deviceSigningPubKey,
    documentId,
    encryptedContent: ciphertextB64,
    keyVersion: state.keyVersion,
    nonce: nonceB64,
    refSnapshotId: state.activeSnapshotId,
    timestamp,
  })

  // Build WS envelope publicData
  const publicData: Record<string, unknown> = {
    docId: documentId,
    deviceId: device.deviceId,
    signingPubKey: deviceSigningPubKey,
    keyVersion: state.keyVersion,
    refSnapshotId: state.activeSnapshotId,
    clock,
    timestamp,
    updateHash,
  }

  // WS envelope signature
  const envelopeMessage = buildWsEnvelopeMessage(
    WS_SIGNATURE_PREFIX.UPDATE,
    ciphertextB64,
    nonceB64,
    publicData,
    base64UrlEncode,
  )
  const envelopeSignature = ed25519.sign(envelopeMessage, device.deviceKeys.signingPrivateKey)

  // Save pre-send state for rollback on failure
  const preSendState = state.lastSavedState ?? undefined
  const preSendLocalClock = state.localClock

  // Advance lastSavedState optimistically (will be rolled back on failure)
  state.lastSavedState = Y.encodeStateAsUpdate(state.yDoc)

  // Send via WebSocket
  ws.send({
    envelope: {
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      signature: base64UrlEncode(envelopeSignature),
      publicData,
    },
    type: 'update',
    clock,
    refSnapshotId: state.activeSnapshotId,
    preSendState,
    preSendLocalClock,
    deviceSigningPubKey,
  })

  // Update local state.
  // knownClocks is advanced optimistically before server confirmation because
  // TCP guarantees ordered delivery: the server processes messages in send order,
  // so clock N is always processed before clock N+1. This means the optimistic
  // value is correct as long as the connection remains open — if the connection
  // drops, knownClocks is reset from confirmedClocks on reconnect.
  state.knownClocks[deviceSigningPubKey] = clock
  state.localClock++
}

/**
 * Create and send the genesis snapshot (first snapshot for a new document).
 * Uses empty parent fields per the collaboration protocol spec.
 */
function createAndSendGenesisSnapshot(
  state: DocumentState,
  ws: DocumentWebSocket,
  documentId: string,
  device: DeviceState,
): void {
  const deviceSigningPubKey = base64UrlEncode(device.deviceKeys.signingPublicKey)

  // 1. Encode full Y.js state
  const yjsState = Y.encodeStateAsUpdate(state.yDoc)

  // 2. Encrypt
  const { ciphertext, nonce } = encryptSnapshot(yjsState, state.dek, documentId, state.keyVersion)
  const ciphertextB64 = base64UrlEncode(ciphertext)
  const nonceB64 = base64UrlEncode(nonce)

  // 3. Hash (genesis has no parent proof chain)
  const ciphertextHash = computeSnapshotCiphertextHash(ciphertext)

  // 4. Build WS envelope publicData (genesis: empty parent fields)
  const snapshotId = crypto.randomUUID()
  const publicData: Record<string, unknown> = {
    docId: documentId,
    snapshotId,
    deviceId: device.deviceId,
    signingPubKey: deviceSigningPubKey,
    keyVersion: state.keyVersion,
    parentSnapshotId: '',
    parentSnapshotProof: '',
    parentSnapshotUpdateClocks: {},
  }

  // 5. WS envelope signature
  const envelopeMessage = buildWsEnvelopeMessage(
    WS_SIGNATURE_PREFIX.SNAPSHOT,
    ciphertextB64,
    nonceB64,
    publicData,
    base64UrlEncode,
  )
  const envelopeSignature = ed25519.sign(envelopeMessage, device.deviceKeys.signingPrivateKey)

  // 6. Store pending snapshot metadata (consumed on snapshot-saved)
  state.pendingSnapshot = {
    snapshotId,
    ciphertextHash,
    parentSnapshotProof: '',
    snapshotYjsState: yjsState,
  }

  // 7. Send
  ws.send({
    envelope: {
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      signature: base64UrlEncode(envelopeSignature),
      publicData,
    },
    type: 'snapshot',
  })
}

// =============================================================================
// Remote Update: WS receive → decrypt → verify → Y.Doc apply
// =============================================================================

/**
 * Apply a remote update received via WebSocket.
 *
 * Verifies the WS envelope signature, decrypts the ciphertext,
 * and applies the Y.js update to the local Y.Doc.
 */
export async function applyRemoteUpdate(
  msg: WsUpdateMessage,
  state: DocumentState,
  documentId: string,
  localDeviceSigningPubKey?: string,
): Promise<boolean> {
  const devicePubKey = msg.publicData.signingPubKey

  // 1. Verify refSnapshotId matches our active snapshot
  if (msg.publicData.refSnapshotId !== state.activeSnapshotId) {
    console.warn(`[ws] Remote update dropped: refSnapshotId mismatch (got=${msg.publicData.refSnapshotId}, active=${state.activeSnapshotId})`)
    return false
  }

  // 2. Find signing key (re-fetch member devices on cache miss)
  const resolveResult = await resolveSigningKey(devicePubKey, state)
  if (resolveResult.status === 'key_changed') {
    throw new TofuKeyChangeError(resolveResult.warning)
  }
  if (resolveResult.status === 'not_found') {
    throw new VerificationError(`Remote update: unknown signing key ${devicePubKey}`)
  }
  const signingPubKey = resolveResult.key

  // 3. Verify WS envelope signature
  const publicDataObj: Record<string, unknown> = { ...msg.publicData }
  const envelopeMessage = buildWsEnvelopeMessage(
    WS_SIGNATURE_PREFIX.UPDATE,
    msg.ciphertext,
    msg.nonce,
    publicDataObj,
    base64UrlEncode,
  )
  const signatureBytes = base64UrlDecode(msg.signature)
  const valid = ed25519.verify(signatureBytes, envelopeMessage, signingPubKey)
  if (!valid) {
    throw new VerificationError(`Remote update signature verification failed for device ${devicePubKey}`)
  }

  // 4. Cross-validate signed docId against current document
  const signedDocId = msg.publicData.docId
  if (signedDocId !== undefined && signedDocId !== documentId) {
    throw new VerificationError(`Remote update: docId mismatch with signed publicData`)
  }

  // 5. Clock contiguity check (fail-closed: reject gaps to prevent silent update omission)
  // Server enforces clock === serverClock + 1, so broadcast must be contiguous.
  // A gap means the server (potentially malicious) skipped an intermediate update.
  const lastClock = state.knownClocks[devicePubKey]
  if (lastClock !== undefined) {
    if (msg.publicData.clock <= lastClock) {
      console.warn(`[ws] Remote update dropped: stale clock (got=${msg.publicData.clock}, known=${lastClock})`)
      return false
    }
    if (msg.publicData.clock !== lastClock + 1) {
      throw new VerificationError(
        `Clock gap detected for device ${devicePubKey}: expected=${lastClock + 1}, got=${msg.publicData.clock}`,
      )
    }
  } else if (msg.publicData.clock !== 0) {
    // First update for this device in the current snapshot must start at clock=0.
    // A non-zero first clock means intermediate updates were omitted.
    throw new VerificationError(
      `Clock gap for first-seen device ${devicePubKey}: expected=0, got=${msg.publicData.clock}`,
    )
  }

  // 6. Decrypt (use the sender's keyVersion, not local state keyVersion)
  const ciphertext = base64UrlDecode(msg.ciphertext)
  const nonce = base64UrlDecode(msg.nonce)
  const decrypted = decryptContent(ciphertext, nonce, state.dek, documentId, msg.publicData.keyVersion)

  // 7. Apply to Y.Doc (mark as 'remote' so auto-sync skips it)
  Y.applyUpdate(state.yDoc, decrypted, 'remote')

  // 8. Update state
  state.knownClocks[devicePubKey] = msg.publicData.clock
  state.confirmedClocks[devicePubKey] = msg.publicData.clock

  // Update lastSavedState by applying the remote update to the server-known baseline.
  // Using state.yDoc directly would include local unsent changes, causing
  // sendPendingChanges() to compute an empty diff and lose those edits.
  const serverDoc = new Y.Doc()
  if (state.lastSavedState) Y.applyUpdate(serverDoc, state.lastSavedState, 'remote')
  Y.applyUpdate(serverDoc, decrypted, 'remote')
  state.lastSavedState = Y.encodeStateAsUpdate(serverDoc)
  serverDoc.destroy()

  state.snapshotUpdatesCount++

  // 9. If this update is from our own device (e.g. another browser with same device keys),
  //    advance localClock to avoid clock collision on next send
  if (localDeviceSigningPubKey && devicePubKey === localDeviceSigningPubKey) {
    if (msg.publicData.clock >= state.localClock) {
      state.localClock = msg.publicData.clock + 1
    }
  }

  return true
}

// =============================================================================
// Verified update application (for reconnect delta + snapshot-save-failed)
// =============================================================================

/**
 * Verify and apply server-returned updates (from document or snapshot-save-failed messages).
 * Performs signature verification and clock ordering checks using existing signing keys.
 * Returns updated known clocks.
 */
/**
 * Pre-resolve all signing keys for a batch of updates.
 * Must be called before verifyAndApplyWsUpdates when updates may contain
 * unknown signing keys (e.g., after reconnect with new members).
 */
export async function preResolveSigningKeys(
  updates: WsUpdateData[],
  state: DocumentState,
): Promise<void> {
  for (const update of updates) {
    if (!update.publicData) continue
    const pd = update.publicData as Record<string, unknown>
    const signedPubKey = pd.signingPubKey as string | undefined
    if (signedPubKey && !state.signingKeys.has(signedPubKey)) {
      const result = await resolveSigningKey(signedPubKey, state)
      if (result.status === 'key_changed') {
        throw new TofuKeyChangeError(result.warning)
      }
      if (result.status === 'not_found') {
        throw new VerificationError(`Unknown signing key ${signedPubKey}`)
      }
    }
  }
}

export function verifyAndApplyWsUpdates(
  updates: WsUpdateData[],
  state: DocumentState,
  documentId: string,
  serverTrackingDoc?: Y.Doc,
): Record<string, number> {
  const clocks: Record<string, number> = { ...state.knownClocks }

  for (const update of updates) {
    // Reject updates without publicData (fail-closed)
    if (!update.publicData) {
      throw new VerificationError(`Update missing publicData`)
    }

    // Use signed publicData.signingPubKey as the source of truth (not unsigned deviceSigningPubKey)
    const pd = update.publicData as Record<string, unknown>
    const signedPubKey = pd.signingPubKey as string | undefined
    if (!signedPubKey) {
      throw new VerificationError(`Update missing signingPubKey in publicData`)
    }

    // Look up signing key (pre-resolved via preResolveSigningKeys)
    const signingKey = state.signingKeys.get(signedPubKey)
    if (!signingKey) {
      throw new VerificationError(`Unknown signing key ${signedPubKey}`)
    }

    // Verify envelope signature (fail-closed: signature failure may indicate tampering)
    const msg = buildWsEnvelopeMessage(
      WS_SIGNATURE_PREFIX.UPDATE,
      update.updateData,
      update.nonce,
      update.publicData,
      base64UrlEncode,
    )
    const sig = base64UrlDecode(update.signature)
    if (!ed25519.verify(sig, msg, signingKey)) {
      throw new VerificationError(`Signature verification failed for key ${signedPubKey}`)
    }

    // Cross-validate: signed docId must match the current document
    const signedDocId = pd.docId as string | undefined
    if (signedDocId !== undefined && signedDocId !== documentId) {
      throw new VerificationError(`Update docId mismatch with signed publicData`)
    }

    // Cross-validate: unsigned top-level fields must match signed publicData.
    // Prevents a compromised server from altering clock/snapshotId/keyVersion/signingKey
    // while keeping the signature valid over the original publicData.
    if (signedPubKey !== update.deviceSigningPubKey) {
      throw new VerificationError(`Update deviceSigningPubKey mismatch with signed publicData`)
    }
    if (pd.refSnapshotId !== undefined && pd.refSnapshotId !== update.snapshotId) {
      throw new VerificationError(`Update snapshotId mismatch with signed publicData`)
    }
    if (pd.clock !== undefined && pd.clock !== update.clock) {
      throw new VerificationError(`Update clock mismatch with signed publicData`)
    }
    if (pd.keyVersion !== undefined && pd.keyVersion !== update.keyVersion) {
      throw new VerificationError(`Update keyVersion mismatch with signed publicData`)
    }
    if (pd.timestamp !== undefined && pd.timestamp !== update.timestamp) {
      throw new VerificationError(`Update timestamp mismatch with signed publicData`)
    }
    if (pd.updateHash !== undefined && pd.updateHash !== update.updateHash) {
      throw new VerificationError(`Update updateHash mismatch with signed publicData`)
    }

    // Verify snapshotId matches our active snapshot (fail-closed)
    if (update.snapshotId !== state.activeSnapshotId) {
      throw new VerificationError(`Update snapshotId mismatch: got=${update.snapshotId}, active=${state.activeSnapshotId}`)
    }

    // Clock contiguity check (fail-closed: reject gaps to prevent silent update omission)
    // Server enforces clock === serverClock + 1, so returned updates must be contiguous.
    const lastClock = clocks[signedPubKey]
    if (lastClock !== undefined) {
      if (update.clock <= lastClock) continue
      if (update.clock !== lastClock + 1) {
        throw new VerificationError(
          `Clock gap in initial load for device ${signedPubKey}: expected=${lastClock + 1}, got=${update.clock}`,
        )
      }
    } else if (update.clock !== 0) {
      // First update for this device within the current update set must start at 0.
      // (Base clocks from snapshot are pre-loaded into the clocks map by the caller.)
      throw new VerificationError(
        `Clock gap in initial load for device ${signedPubKey}: expected=0, got=${update.clock}`,
      )
    }

    // Decrypt and apply
    const ciphertext = base64UrlDecode(update.updateData)
    const nonce = base64UrlDecode(update.nonce)
    const decrypted = decryptContent(ciphertext, nonce, state.dek, documentId, update.keyVersion)
    Y.applyUpdate(state.yDoc, decrypted, 'remote')
    if (serverTrackingDoc) {
      Y.applyUpdate(serverTrackingDoc, decrypted, 'remote')
    }

    clocks[signedPubKey] = update.clock
  }

  return clocks
}

// =============================================================================
// Confirmation handlers
// =============================================================================

/**
 * Handle update-saved confirmation from server.
 */
export function handleUpdateSaved(
  msg: WsUpdateSavedMessage,
  state: DocumentState,
  ws: DocumentWebSocket,
  documentId: string,
  device: DeviceState,
  onPinFailed?: (error: Error) => void,
): void {
  const resolved = ws.resolvePending(msg.clock, msg.snapshotId)

  // Ignore unsolicited update-saved (no matching pending update to confirm).
  // Accepting it would advance confirmedClocks and pin with server-provided clock,
  // enabling pin inflation → false positive rollback on next reconnect.
  if (!resolved) {
    console.warn('[auto-sync] Ignoring unsolicited update-saved:', msg.clock, msg.snapshotId)
    return
  }

  state.snapshotUpdatesCount++

  // Track server-confirmed clocks for delta reconnect (avoids using optimistic clocks)
  const deviceSigningPubKey = base64UrlEncode(device.deviceKeys.signingPublicKey)
  state.confirmedClocks[deviceSigningPubKey] = msg.clock

  // Use confirmed clocks for delta reconnect state
  ws.updateKnownState(msg.snapshotId, state.confirmedClocks)

  // Pin anti-rollback state (fail-closed: IDB failure degrades rollback detection)
  pinDocumentState({
    documentId,
    latestSnapshotId: state.activeSnapshotId,
    latestSnapshotProofHash: state.snapshotProofHash,
    latestSnapshotCiphertextHash: state.snapshotCiphertextHash,
    latestGlobalVersion: msg.version,
    perDeviceMaxClocks: state.confirmedClocks,
    observedAt: Date.now(),
  }).catch((err) => {
    console.error('[auto-sync] pinDocumentState failed:', err)
    onPinFailed?.(new Error('Anti-rollback pin write failed'))
  })

  // Check snapshot threshold
  if (state.snapshotUpdatesCount >= SNAPSHOT_UPDATE_THRESHOLD) {
    if (state.pendingSnapshot) return  // Already sending a snapshot
    createAndSendSnapshot(state, ws, documentId, device)
  }
}

/**
 * Handle update-save-failed from server.
 * Rolls back lastSavedState so the diff will be recomputed on next send.
 * If requiresNewSnapshot is true, triggers immediate snapshot creation
 * (the active snapshot has changed and our refSnapshotId is stale).
 */
export function handleUpdateSaveFailed(
  msg: WsUpdateSaveFailedMessage,
  state: DocumentState,
  ws: DocumentWebSocket,
  _documentId: string,
  _device: DeviceState,
): void {
  const allPending = drainAndRollback(ws, state)

  if (msg.requiresNewSnapshot) {
    // Active snapshot has changed — all in-flight and queued messages reference the
    // old snapshot and will fail. Reconnect in complete mode.
    ws.disconnect()
    ws.connect('complete')
    return
  }

  // Clock mismatch: roll back knownClocks for this device to just before the
  // earliest failed send, then let auto-sync re-diff and resend.
  if (state.localClock !== undefined && allPending.length > 0) {
    const deviceKey = allPending[0].deviceSigningPubKey
    if (deviceKey) {
      if (state.localClock === 0) {
        delete state.knownClocks[deviceKey]
      } else {
        state.knownClocks[deviceKey] = state.localClock - 1
      }
    }
  }
}

/**
 * Drain all queued/pending messages and roll back state to the earliest
 * pre-send checkpoint. Used by both requiresNewSnapshot and clock-mismatch paths.
 */
function drainAndRollback(ws: DocumentWebSocket, state: DocumentState): QueuedMessage[] {
  const allPending = ws.drainAllQueues()

  let earliestState: Uint8Array | undefined
  let earliestClock: number | undefined
  for (const p of allPending) {
    if (p.preSendState && earliestState === undefined) {
      earliestState = p.preSendState
    }
    if (p.preSendLocalClock !== undefined) {
      if (earliestClock === undefined || p.preSendLocalClock < earliestClock) {
        earliestClock = p.preSendLocalClock
      }
    }
  }

  if (earliestState) {
    state.lastSavedState = earliestState
  }
  if (earliestClock !== undefined) {
    state.localClock = earliestClock
  }

  return allPending
}

// =============================================================================
// Snapshot: create and send via WS
// =============================================================================

/**
 * Create a snapshot of the current Y.Doc state and send via WebSocket.
 */
export function createAndSendSnapshot(
  state: DocumentState,
  ws: DocumentWebSocket,
  documentId: string,
  device: DeviceState,
): void {
  // Only called from handleUpdateSaved threshold — activeSnapshotId is guaranteed non-null
  if (state.activeSnapshotId === null) return

  const deviceSigningPubKey = base64UrlEncode(device.deviceKeys.signingPublicKey)

  // 1. Encode full Y.js state
  const yjsState = Y.encodeStateAsUpdate(state.yDoc)

  // 2. Encrypt
  const { ciphertext, nonce } = encryptSnapshot(yjsState, state.dek, documentId, state.keyVersion)
  const ciphertextB64 = base64UrlEncode(ciphertext)
  const nonceB64 = base64UrlEncode(nonce)

  // 3. Hash + proof chain
  const ciphertextHash = computeSnapshotCiphertextHash(ciphertext)
  const parentSnapshotProof = computeParentSnapshotProof(
    state.snapshotProofHash,
    state.activeSnapshotId,
    state.snapshotCiphertextHash,
  )

  // 4. Build WS envelope publicData
  const snapshotId = crypto.randomUUID()
  const publicData: Record<string, unknown> = {
    docId: documentId,
    snapshotId,
    deviceId: device.deviceId,
    signingPubKey: deviceSigningPubKey,
    keyVersion: state.keyVersion,
    parentSnapshotId: state.activeSnapshotId,
    parentSnapshotProof,
    // knownClocks is used here (not confirmedClocks) because TCP ordering
    // guarantees all updates sent before this snapshot have been processed by
    // the server. The server's active snapshot already includes these updates,
    // so parentSnapshotUpdateClocks correctly captures the full clock state at
    // the moment of snapshot creation.
    parentSnapshotUpdateClocks: { ...state.knownClocks },
  }

  // 5. WS envelope signature
  const envelopeMessage = buildWsEnvelopeMessage(
    WS_SIGNATURE_PREFIX.SNAPSHOT,
    ciphertextB64,
    nonceB64,
    publicData,
    base64UrlEncode,
  )
  const envelopeSignature = ed25519.sign(envelopeMessage, device.deviceKeys.signingPrivateKey)

  // 6. Store pending snapshot metadata (consumed on snapshot-saved)
  state.pendingSnapshot = {
    snapshotId,
    ciphertextHash,
    parentSnapshotProof,
    snapshotYjsState: yjsState,
  }

  // 7. Send
  ws.send({
    envelope: {
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      signature: base64UrlEncode(envelopeSignature),
      publicData,
    },
    type: 'snapshot',
  })
}
