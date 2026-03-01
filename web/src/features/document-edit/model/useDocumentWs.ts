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
import type { DeviceState } from '@/shared/model/auth-types'
import { base64UrlEncode } from '@/shared/lib/crypto'
import { DocumentWebSocket, type WsConnectionState } from '../lib/ws'
import { pinDocumentState, getDocumentStatePin } from '@/shared/lib/anti-rollback'
import { documentCache } from '../lib/document-cache'
import {
  startAutoSync,
  applyRemoteUpdate,
  handleUpdateSaved,
  handleUpdateSaveFailed,
} from '../lib/auto-sync'
import { handleDocumentMessage, handleSnapshotMessage, handleSnapshotSaveFailedMessage } from '../lib/ws-handlers'

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
  onFatalError: (error: Error) => void,
): UseDocumentWsResult {
  const [wsState, setWsState] = useState<WsConnectionState>('idle')

  // Keep device in a ref so WS callbacks always see the latest value
  const deviceRef = useRef(device)
  deviceRef.current = device

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
              const syncToDispose = state.autoSync
              state.ws = null
              state.autoSync = null
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
          state.autoSync?.dispose()
          reusedWs.disconnect()
          state.ws = null
          state.autoSync = null
        }
      }
    }

    // First instance: create WS + auto-sync, attach to shared state

    // Immediate teardown helper: disconnect WS + dispose autoSync before reporting
    // fatal error. Prevents message processing in the micro-window before React
    // re-renders and runs useEffect cleanup.
    const teardownAndFatal = (wsInstance: DocumentWebSocket, error: Error) => {
      if (state.ws === wsInstance) {
        const syncToDispose = state.autoSync
        state.ws = null
        state.autoSync = null
        state.wsRefCount = 0
        syncToDispose?.dispose()
      }
      wsInstance.disconnect()
      onFatalError(error)
    }

    const handlerDeps = { documentId, deviceRef, ws: null! as DocumentWebSocket }
    const ws = new DocumentWebSocket(documentId, {
      onDocument: async (msg, mode) => {
        await handleDocumentMessage(msg, mode, state, handlerDeps)
      },
      onUpdate: (msg) => {
        const dev = deviceRef.current
        const localKey = dev ? base64UrlEncode(dev.deviceKeys.signingPublicKey) : undefined
        const applied = applyRemoteUpdate(msg, state, documentId, localKey)
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
        await handleSnapshotMessage(msg, state, handlerDeps)
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
        await handleSnapshotSaveFailedMessage(msg, state, handlerDeps)
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
      onEphemeral: () => {},
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

    return () => {
      cancelled = true
      unsubscribe()
      // Skip if WS was already replaced (fatal error teardown)
      if (state.ws !== ws) return
      state.wsRefCount--
      if (state.wsRefCount <= 0) {
        sync.dispose()
        ws.disconnect()
        state.ws = null
        state.autoSync = null
      }
    }
  }, [yDoc, documentId])

  // Stable callback that reads autoSync from cache at call time
  const onLocalEdit = useCallback(() => {
    if (!documentId) return
    documentCache.getValue(documentId)?.autoSync?.notifyLocalEdit()
  }, [documentId])

  return { wsState, onLocalEdit }
}
