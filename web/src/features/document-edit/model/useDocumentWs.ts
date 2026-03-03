/**
 * Document WebSocket Hook
 *
 * Manages the WebSocket connection lifecycle and auto-sync for a document:
 * - WS creation, reuse across panels (via shared DocumentState), and cleanup
 * - Anti-rollback pin loading before initial connect
 * - All WS message handlers (update, snapshot, ephemeral, confirmations)
 * - Auto-sync (local Y.Doc changes → throttle → encrypt → WS send)
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import { ed25519 } from '@noble/curves/ed25519.js'
import type { DeviceState } from '@/shared/model/auth-types'
import {
  base64UrlEncode,
  base64UrlDecode,
  decryptContent,
  buildWsEnvelopeMessage,
  WS_SIGNATURE_PREFIX,
} from '@/shared/lib/crypto'
import { DocumentWebSocket, TofuKeyChangeError, VerificationError, type WsConnectionState } from '../lib/ws'
import { pinDocumentState, getDocumentStatePin } from '@/shared/lib/anti-rollback'
import { documentCache } from '../lib/document-cache'
import {
  startAutoSync,
  applyRemoteUpdate,
  handleUpdateSaved,
  handleUpdateSaveFailed,
} from '../lib/auto-sync'
import { handleDocumentMessage, handleSnapshotMessage, handleSnapshotSaveFailedMessage } from '../lib/ws-handlers'
import { buildDeviceKeyCaches, resolveSigningKey } from '../lib/document-verification-service'
import {
  createEphemeralSession,
  decodeEphemeralPayload,
  encodeEphemeralPayload,
  handleIncomingEphemeral,
  MSG_INITIALIZE,
} from '../lib/ephemeral-session'
import { sendEphemeralEnvelope } from '../lib/ephemeral-send'
import { encodeAwarenessUpdate, applyAwarenessUpdate, removeAwarenessStates } from 'y-protocols/awareness'
import { MSG_MESSAGE } from '../lib/ephemeral-session'
import { assignUserColor } from '../lib/user-colors'
import type { DocumentState, TofuKeyChangeWarning } from '../lib/types'

/**
 * Set up the Awareness relay listener on shared state.
 * The listener is stored in `state.awarenessRelayCleanup` so it survives
 * beyond the hook instance that created the WS — any panel can hold the WS
 * alive and Awareness relay will keep working.
 *
 * Idempotent: re-calling replaces the previous listener (e.g. on reconnect).
 */
function setupAwarenessRelay(
  state: DocumentState,
  deviceRef: React.RefObject<DeviceState | null>,
  documentId: string,
): void {
  // Clean up any existing listener (reconnect or re-call)
  state.awarenessRelayCleanup?.()

  let awarenessThrottleTimer: ReturnType<typeof setTimeout> | null = null
  let pendingAwarenessClients: number[] | null = null

  const flushAwareness = () => {
    awarenessThrottleTimer = null
    const clients = pendingAwarenessClients
    pendingAwarenessClients = null
    if (!clients || clients.length === 0) return
    const dev = deviceRef.current
    const session = state.ephemeralSession
    if (!dev || !session || !state.ws) return
    const encoded = encodeAwarenessUpdate(state.awareness, clients)
    const payload = encodeEphemeralPayload(session, MSG_MESSAGE, encoded)
    sendEphemeralEnvelope(payload, state, state.ws, dev, documentId)
  }

  const onAwarenessUpdate = ({ added, updated, removed }: {
    added: number[]; updated: number[]; removed: number[]
  }, origin: unknown) => {
    if (origin === 'remote') return
    const localClientId = state.awareness.clientID
    const changedClients = [...added, ...updated, ...removed].filter(
      (id) => id === localClientId,
    )
    if (changedClients.length === 0) return

    if (!pendingAwarenessClients) {
      pendingAwarenessClients = changedClients
    } else {
      for (const c of changedClients) {
        if (!pendingAwarenessClients.includes(c)) {
          pendingAwarenessClients.push(c)
        }
      }
    }
    if (!awarenessThrottleTimer) {
      awarenessThrottleTimer = setTimeout(flushAwareness, 100)
    }
  }

  state.awareness.on('update', onAwarenessUpdate)
  state.awarenessRelayCleanup = () => {
    // Flush any pending awareness update immediately (e.g. removal on teardown)
    // before removing the listener, so the final state reaches peers.
    if (awarenessThrottleTimer) {
      clearTimeout(awarenessThrottleTimer)
      awarenessThrottleTimer = null
    }
    flushAwareness()
    state.awareness.off('update', onAwarenessUpdate)
  }
}

export interface UseDocumentWsResult {
  wsState: WsConnectionState
  /** Notify auto-sync of a local CM edit */
  onLocalEdit: () => void
}

/**
 * Hook to manage WebSocket connection and auto-sync for a document.
 *
 * Requires a valid Y.Doc (non-null) and document state in the cache.
 * Handles shared WS lifecycle across multiple panels viewing the same document.
 */
export function useDocumentWs(
  documentId: string,
  yDoc: unknown | null,
  device: DeviceState | null,
  userId: string,
  onFatalError: (error: Error) => void,
  onTofuKeyChange?: (warning: TofuKeyChangeWarning) => void,
): UseDocumentWsResult {
  const [wsState, setWsState] = useState<WsConnectionState>('idle')

  // Keep device in ref so WS callbacks always see the latest value
  const deviceRef = useRef(device)
  deviceRef.current = device

  // Update shared TOFU callback on every render so whichever panel is
  // still mounted can surface the warning dialog. This runs outside
  // useEffect to stay current across re-renders without cleanup races.
  const state = documentCache.getValue(documentId)
  if (state && onTofuKeyChange) {
    state.onTofuKeyChange = onTofuKeyChange
  }

  useEffect(() => {
    if (!yDoc || !documentId) return

    const state = documentCache.getValue(documentId)
    if (!state) return

    // Shared subscribe handlers factory — used for both reuse and first-instance paths
    const subscribeWs = (wsInstance: DocumentWebSocket) =>
      wsInstance.subscribe({
        onStateChange: (s) => setWsState(s),
        onError: (wsError) => {
          console.error('WebSocket error:', wsError)
          if (
            wsError === 'verification-failed' ||
            wsError === 'unauthorized' ||
            wsError === 'document-not-found' ||
            wsError === 'unrecoverable-error'
          ) {
            if (state.ws === wsInstance) {
              removeAwarenessStates(state.awareness, [state.awareness.clientID], 'local')
              state.awarenessRelayCleanup?.()
              state.awarenessRelayCleanup = null
              const syncToDispose = state.autoSync
              state.ws = null
              state.autoSync = null
              state.ephemeralSession = null
              state.wsRefCount = 0
              syncToDispose?.dispose()
            }
            onFatalError(new Error(`Document connection failed: ${wsError}`))
          }
        },
      })

    // If WS already exists on the shared state, reuse it and bump ref count
    if (state.ws) {
      const reusedWs = state.ws
      state.wsRefCount++
      // Subscribe this hook instance's UI callbacks (broadcast to all panels)
      const unsubscribe = subscribeWs(reusedWs)
      setWsState(reusedWs.getState())
      return () => {
        unsubscribe()
        // Skip if WS was already replaced (fatal error teardown)
        if (state.ws !== reusedWs) return
        state.wsRefCount--
        if (state.wsRefCount <= 0) {
          // Remove local Awareness first (while relay listener is still active)
          // so the removal is broadcast to peers before we tear down
          removeAwarenessStates(state.awareness, [state.awareness.clientID], 'local')
          state.awarenessRelayCleanup?.()
          state.awarenessRelayCleanup = null
          state.autoSync?.dispose()
          reusedWs.disconnect()
          state.ws = null
          state.autoSync = null
          state.ephemeralSession = null
        }
      }
    }

    // First instance: create WS + auto-sync, attach to shared state

    // Immediate teardown helper: disconnect WS + dispose autoSync before reporting
    // fatal error. Prevents message processing in the micro-window before React
    // re-renders and runs useEffect cleanup.
    const teardownAndFatal = (wsInstance: DocumentWebSocket, error: Error) => {
      if (state.ws === wsInstance) {
        // Remove local Awareness first (while relay listener + WS are still active)
        // so the removal is broadcast to peers before we tear down
        removeAwarenessStates(state.awareness, [state.awareness.clientID], 'local')
        state.awarenessRelayCleanup?.()
        state.awarenessRelayCleanup = null
        const syncToDispose = state.autoSync
        state.ws = null
        state.autoSync = null
        state.ephemeralSession = null
        state.wsRefCount = 0
        syncToDispose?.dispose()
      }
      wsInstance.disconnect()
      onFatalError(error)
    }

    const handlerDeps = { documentId, deviceRef, ws: null! as DocumentWebSocket }
    const ws = new DocumentWebSocket(documentId, {
      onDocument: async (msg, mode) => {
        // Refresh device key cache on every WS (re)connect per design spec
        // (collaboration.md: fetch workspace member devices on WS connection)
        const cacheResult = await buildDeviceKeyCaches(state.workspaceId)
        if (cacheResult.status === 'key_changed') {
          state.onTofuKeyChange?.(cacheResult.warning)
          throw new VerificationError(`TOFU key change on reconnect: device ${cacheResult.warning.deviceId}`)
        }
        // Replace cache with fresh keys (prunes revoked devices)
        state.signingKeys.clear()
        for (const [key, value] of cacheResult.signingKeys) {
          state.signingKeys.set(key, value)
        }
        state.signingKeyOwners.clear()
        for (const [key, value] of cacheResult.signingKeyOwners) {
          state.signingKeyOwners.set(key, value)
        }

        try {
          await handleDocumentMessage(msg, mode, state, handlerDeps)
        } catch (err) {
          if (err instanceof TofuKeyChangeError) {
            state.onTofuKeyChange?.(err.warning)
            // Re-throw as VerificationError to trigger disconnect (fail-closed).
            // User can retry after trusting the new key via the dialog.
            throw new VerificationError(err.message)
          }
          throw err
        }
        // Set local Awareness state with user info for cursor rendering
        // Use member name from device key cache (fetched from workspace members API)
        const localMemberName = cacheResult.memberNames.get(userId) ?? userId
        state.awareness.setLocalStateField('user', {
          userId,
          name: localMemberName,
          color: assignUserColor(userId),
        })
        // After each document message (initial or reconnect): create a fresh
        // ephemeral session and broadcast initialize. Old sessions are invalidated
        // on reconnect because peers' counter state is stale.
        // Drain any stale ephemeral messages queued during disconnect (delta mode
        // doesn't call drainAllQueues, so old-session ephemerals may linger).
        handlerDeps.ws.drainEphemeralQueue()
        const dev = deviceRef.current
        if (dev) {
          const session = createEphemeralSession()
          state.ephemeralSession = session
          const initPayload = encodeEphemeralPayload(session, MSG_INITIALIZE, new Uint8Array(0))
          sendEphemeralEnvelope(initPayload, state, handlerDeps.ws, dev, documentId)
          session.initializeSent = true
        }
      },
      onUpdate: async (msg) => {
        const dev = deviceRef.current
        const localKey = dev ? base64UrlEncode(dev.deviceKeys.signingPublicKey) : undefined
        let applied: boolean
        try {
          applied = await applyRemoteUpdate(msg, state, documentId, localKey)
        } catch (err) {
          if (err instanceof TofuKeyChangeError) {
            state.onTofuKeyChange?.(err.warning)
            throw new VerificationError(err.message)
          }
          throw err
        }
        if (!applied) return
        // Update WS known state so delta reconnect uses confirmed clocks only
        handlerDeps.ws.updateKnownState(state.activeSnapshotId, state.confirmedClocks)
        // Advance anti-rollback pin on remote updates (fail-closed: IDB failure
        // degrades rollback detection, so treat as fatal to prevent stale pin window)
        const latestVersion = msg.version
        pinDocumentState({
          documentId,
          latestSnapshotId: state.activeSnapshotId,
          latestSnapshotProofHash: state.snapshotProofHash,
          latestSnapshotCiphertextHash: state.snapshotCiphertextHash,
          latestGlobalVersion: latestVersion,
          perDeviceMaxClocks: state.confirmedClocks,
          observedAt: Date.now(),
        }).catch((err) => {
          console.error('[ws] pinDocumentState failed:', err)
          teardownAndFatal(handlerDeps.ws, new Error('Anti-rollback pin write failed'))
        })
      },
      onSnapshot: async (msg) => {
        try {
          await handleSnapshotMessage(msg, state, handlerDeps)
        } catch (err) {
          if (err instanceof TofuKeyChangeError) {
            state.onTofuKeyChange?.(err.warning)
            throw new VerificationError(err.message)
          }
          throw err
        }
      },
      onSnapshotSaved: (msg) => {
        const resolvedSnapshot = handlerDeps.ws.resolvePendingSnapshot()
        // Ignore unsolicited snapshot-saved: requires BOTH a matching pending queue
        // entry AND local pendingSnapshot metadata. This dual check prevents:
        // 1. Completely unsolicited messages (no pending → no resolvedSnapshot)
        // 2. Stale pendingSnapshot surviving reconnect with no matching queue entry
        //    (pendingQueue moved to sendQueue, but snapshot not yet re-sent)
        if (!resolvedSnapshot || !state.pendingSnapshot) {
          console.warn('[ws] Ignoring unsolicited snapshot-saved:', msg.snapshotId)
          return
        }
        // Use the client-generated snapshotId from pendingSnapshot (included in signed
        // publicData) instead of server-provided msg.snapshotId to prevent server forgery.
        const savedSnapshotId = state.pendingSnapshot.snapshotId

        // Update proof chain and reset lastSavedState to the snapshot's Y.js state.
        // This ensures local edits made after snapshot creation are preserved in the
        // next diff computation (they exist in yDoc but not in lastSavedState).
        state.snapshotProofHash = state.pendingSnapshot.parentSnapshotProof
        state.snapshotCiphertextHash = state.pendingSnapshot.ciphertextHash
        state.lastSavedState = state.pendingSnapshot.snapshotYjsState
        state.pendingSnapshot = null
        // Drain stale queued updates that reference the old snapshotId —
        // they will be rejected by the server after the snapshot transition.
        handlerDeps.ws.drainAllQueues()
        state.localClock = 0
        state.knownClocks = {}
        state.confirmedClocks = {}
        state.activeSnapshotId = savedSnapshotId
        state.snapshotUpdatesCount = 0
        handlerDeps.ws.updateKnownState(savedSnapshotId, {})

        // Pin anti-rollback state after snapshot save (fail-closed)
        pinDocumentState({
          documentId,
          latestSnapshotId: savedSnapshotId,
          latestSnapshotProofHash: state.snapshotProofHash,
          latestSnapshotCiphertextHash: state.snapshotCiphertextHash,
          latestGlobalVersion: 0,
          perDeviceMaxClocks: state.knownClocks,
          observedAt: Date.now(),
        }).catch((err) => {
          console.error('[ws] pinDocumentState failed:', err)
          teardownAndFatal(handlerDeps.ws, new Error('Anti-rollback pin write failed'))
        })

        // Trigger auto-sync to resend any local unsent changes under the new snapshot
        state.autoSync?.notifyPendingChanges()
      },
      onSnapshotSaveFailed: async (msg) => {
        try {
          await handleSnapshotSaveFailedMessage(msg, state, handlerDeps)
        } catch (err) {
          if (err instanceof TofuKeyChangeError) {
            state.onTofuKeyChange?.(err.warning)
            throw new VerificationError(err.message)
          }
          throw err
        }
      },
      onUpdateSaved: (msg) => {
        const dev = deviceRef.current
        if (dev) handleUpdateSaved(msg, state, handlerDeps.ws, documentId, dev, (err) => {
          teardownAndFatal(handlerDeps.ws, err)
        })
      },
      onUpdateSaveFailed: (msg) => {
        const dev = deviceRef.current
        if (dev) handleUpdateSaveFailed(msg, state, handlerDeps.ws, documentId, dev)
        // Retry sending for non-snapshot failures (update was rejected but snapshot is still current)
        if (!msg.requiresNewSnapshot) {
          state.autoSync?.notifyPendingChanges()
        }
      },
      onEphemeral: async (msg) => {
        const dev = deviceRef.current
        if (!dev || !state.ephemeralSession) return

        const pd = msg.publicData as Record<string, unknown>
        const senderPubKeyB64 = pd?.signingPubKey as string | undefined
        if (!senderPubKeyB64) return

        // Validate docId matches current document (prevent cross-document injection)
        const msgDocId = pd?.docId as string | undefined
        if (!msgDocId || msgDocId !== documentId) {
          console.warn('[ws] Ephemeral: docId missing or mismatch, ignoring')
          return
        }

        // Skip own messages (defense-in-depth: server uses broadcast_except,
        // but client-side filter guards against future transport changes)
        const localPubKeyB64 = base64UrlEncode(dev.deviceKeys.signingPublicKey)
        if (senderPubKeyB64 === localPubKeyB64) return

        // 1. Resolve sender's signing key via shared resolver (dedup + TOFU + cache refresh)
        const resolveResult = await resolveSigningKey(senderPubKeyB64, state)
        if (resolveResult.status === 'key_changed') {
          state.onTofuKeyChange?.(resolveResult.warning)
          throw new VerificationError(`TOFU key change on ephemeral resolve: device ${resolveResult.warning.deviceId}`)
        }
        if (resolveResult.status === 'not_found') {
          console.warn('[ws] Ephemeral: unknown signing key, ignoring')
          return
        }
        const senderPubKeyBytes = resolveResult.key

        // 2. Verify envelope signature
        const envelopeMessage = buildWsEnvelopeMessage(
          WS_SIGNATURE_PREFIX.EPHEMERAL,
          msg.ciphertext,
          msg.nonce,
          pd,
          base64UrlEncode,
        )
        const sigBytes = base64UrlDecode(msg.signature)
        if (!ed25519.verify(sigBytes, envelopeMessage, senderPubKeyBytes)) {
          console.warn('[ws] Ephemeral: envelope signature verification failed')
          return
        }

        // 3. Decrypt ciphertext
        let decrypted: Uint8Array
        try {
          const ciphertextBytes = base64UrlDecode(msg.ciphertext)
          const nonceBytes = base64UrlDecode(msg.nonce)
          decrypted = decryptContent(ciphertextBytes, nonceBytes, state.dek, documentId, state.keyVersion)
        } catch (err) {
          console.warn('[ws] Ephemeral: decryption failed:', err)
          return
        }

        // 4. Decode ephemeral payload
        const decoded = decodeEphemeralPayload(decrypted)
        if (!decoded) {
          console.warn('[ws] Ephemeral: payload decode failed')
          return
        }

        // 5. Handle handshake / awareness
        const result = handleIncomingEphemeral(
          state.ephemeralSession,
          decoded,
          senderPubKeyB64,
          senderPubKeyBytes,
          dev.deviceKeys.signingPrivateKey,
        )

        const remoteSessionIdB64 = base64UrlEncode(decoded.sessionId)

        // Helper: resend current Awareness state so peer sees our presence immediately
        const resendAwareness = () => {
          const session = state.ephemeralSession
          if (!session) return
          const localState = state.awareness.getLocalState()
          if (!localState) return
          const encoded = encodeAwarenessUpdate(state.awareness, [state.awareness.clientID])
          const payload = encodeEphemeralPayload(session, MSG_MESSAGE, encoded)
          sendEphemeralEnvelope(payload, state, handlerDeps.ws, dev, documentId)
        }

        switch (result.action) {
          case 'respond':
            sendEphemeralEnvelope(result.responsePayload, state, handlerDeps.ws, dev, documentId)
            // After respond to proofAndRequest, we've added the peer as trusted.
            // Resend Awareness so they see our presence immediately.
            if (state.ephemeralSession?.trustedPeers.has(remoteSessionIdB64)) {
              resendAwareness()
            }
            break
          case 'trusted':
            // Peer is now trusted — resend current Awareness so they see our presence
            // immediately (any earlier MSG_MESSAGE was rejected while untrusted).
            resendAwareness()
            break
          case 'awareness': {
            // Same-user different-device: apply then immediately remove
            // (collaboration.md: applyAwarenessUpdate → removeAwarenessStates)
            const resolvedUserId = state.signingKeyOwners.get(senderPubKeyB64)
            if (resolvedUserId && resolvedUserId === userId) {
              let changedClients: number[] = []
              const captureHandler = ({ added, updated }: { added: number[]; updated: number[] }) => {
                changedClients = [...added, ...updated]
              }
              state.awareness.on('update', captureHandler)
              applyAwarenessUpdate(state.awareness, result.awarenessData, 'remote')
              state.awareness.off('update', captureHandler)
              if (changedClients.length > 0) {
                removeAwarenessStates(state.awareness, changedClients, 'same-user')
              }
            } else {
              applyAwarenessUpdate(state.awareness, result.awarenessData, 'remote')
            }
            break
          }
          case 'reject':
            console.warn('[ws] Ephemeral rejected:', result.reason)
            break
        }
      },
    })
    // Bind the ws instance to handlerDeps after creation (circular ref resolved)
    handlerDeps.ws = ws

    // Subscribe this hook instance's UI callbacks
    const unsubscribe = subscribeWs(ws)

    state.ws = ws
    state.wsRefCount = 1

    // Load anti-rollback pin before connecting so knownSnapshotId is sent
    // even in complete mode (required for proof chain / fail-closed verification).
    // Retry once on IDB failure to handle transient errors; the design spec
    // requires knownSnapshotId to be sent whenever a pin exists (mandatory).
    let cancelled = false
    const loadPin = async (): Promise<void> => {
      try {
        const pin = await getDocumentStatePin(documentId)
        if (pin) {
          ws.updateKnownState(pin.latestSnapshotId, {})
        }
      } catch (firstErr) {
        console.warn('[ws] Anti-rollback pin load failed, retrying:', firstErr)
        try {
          const pin = await getDocumentStatePin(documentId)
          if (pin) {
            ws.updateKnownState(pin.latestSnapshotId, {})
          }
        } catch (retryErr) {
          // Permanent IDB failure. Log and proceed — checkDocumentStateRollback
          // will re-attempt pin read and enforce fail-closed if a pin exists.
          console.error('[ws] Anti-rollback pin load failed after retry:', retryErr)
        }
      }
    }
    loadPin().then(() => {
      if (!cancelled) ws.connect('complete')
    })

    // Start auto-sync: Y.Doc changes → debounce → encrypt → WS send
    const sync = startAutoSync({
      documentId,
      device: deviceRef,
      getState: () => documentCache.getValue(documentId),
      getWs: () => state.ws,
    })
    state.autoSync = sync

    // Subscribe to Awareness updates for outbound ephemeral relay (throttled ~100ms).
    // This is stored on shared state so it survives beyond the creator hook instance.
    // If the creator panel unmounts, the listener stays alive while other panels exist.
    setupAwarenessRelay(state, deviceRef, documentId)

    return () => {
      cancelled = true
      unsubscribe()
      // Skip if WS was already replaced (fatal error teardown)
      if (state.ws !== ws) return
      state.wsRefCount--
      if (state.wsRefCount <= 0) {
        // Remove local Awareness first (while relay listener is still active)
        // so the removal is broadcast to peers before we tear down
        removeAwarenessStates(state.awareness, [state.awareness.clientID], 'local')
        state.awarenessRelayCleanup?.()
        state.awarenessRelayCleanup = null
        sync.dispose()
        ws.disconnect()
        state.ws = null
        state.autoSync = null
        state.ephemeralSession = null
      }
    }
  }, [yDoc, documentId, userId])

  // Stable callback that reads autoSync from cache at call time
  const onLocalEdit = useCallback(() => {
    if (!documentId) return
    documentCache.getValue(documentId)?.autoSync?.notifyLocalEdit()
  }, [documentId])

  return { wsState, onLocalEdit }
}
