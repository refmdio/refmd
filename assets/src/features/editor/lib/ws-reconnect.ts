import { getPopHeaders } from "@/shared/lib/pop";
import {
  rejoinDocument,
  pushUpdate,
  pushSnapshot,
  type DocumentChannelCallbacks,
} from "@/shared/lib/ws/phoenix-channel";
import {
  handleDocumentMessage,
  handleRemoteUpdate,
  handleRemoteSnapshot,
  handleUpdateSaved,
  handleUpdateSaveFailed,
  handleSnapshotSaved,
  handleSnapshotSaveFailed,
  type DocumentPayload,
  type UpdateSavedPayload,
  type UpdateSaveFailedPayload,
  type SnapshotSavedPayload,
  type SnapshotSaveFailedPayload,
} from "./ws-handlers";
import { authState, deviceState } from "@/shared/lib/auth-state";
import { removeAwarenessStates } from "y-protocols/awareness";
import {
  getDocumentState,
  notifyAwarenessReady,
  requestReauth,
  type DocumentState,
} from "./document-state-cache";
import { setWsConnected, notifyOfflineListeners } from "@/shared/lib/offline/offline-state";
import { buildDeviceKeyCaches } from "./document-verification";
import { createEphemeralSession } from "./ephemeral-session";
import { assignUserColor } from "./user-colors";
import { handleEphemeralMessage, handlePeerLeft } from "./ws-ephemeral-handler";
import { setupAwarenessRelay } from "./ws-awareness-relay";
import { sendInitialize } from "./document-sync";
import { cacheDocumentState, cacheDek } from "@/shared/lib/offline/cache-manager";

const MAX_RECONNECT_ATTEMPTS = 13;
const RECONNECT_BASE_MS = 100;
const RECONNECT_MAX_MS = 30_000;

export function triggerReconnect(
  state: DocumentState,
  documentId: string,
  workspaceId: string,
  localDeviceSigningPubKey: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): void {
  if (!getDocumentState(documentId)) return;
  if (state.error) return;
  if (state._reconnecting) return;

  state.channel = null;
  state.sending = false;
  state.awarenessRelayCleanup?.();
  state.awarenessRelayCleanup = null;
  state.ephemeralSession = null;
  state._reconnecting = true;

  attemptReconnect(documentId, workspaceId, state, localDeviceSigningPubKey, failClosed).finally(
    () => {
      state._reconnecting = false;
      if (!state.error && !state.channel && getDocumentState(documentId)) {
        triggerReconnect(state, documentId, workspaceId, localDeviceSigningPubKey, failClosed);
      }
    },
  );
}

async function attemptReconnect(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  localDeviceSigningPubKey: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): Promise<void> {
  let useDelta = !!state.activeSnapshotId;

  for (let attempt = 0; attempt < MAX_RECONNECT_ATTEMPTS; attempt++) {
    if (state.error || !getDocumentState(documentId)) return;

    const delay = Math.min(RECONNECT_BASE_MS * Math.pow(1.8, attempt), RECONNECT_MAX_MS);
    await new Promise((r) => setTimeout(r, delay));

    if (state.error || !getDocumentState(documentId)) return;

    try {
      const popHeaders = await getPopHeaders();
      const joinParams: Record<string, unknown> = {
        pop_challenge: popHeaders["X-PoP-Challenge"],
        pop_signature: popHeaders["X-PoP-Signature"],
        mode: useDelta ? "delta" : "complete",
      };
      state._lastJoinMode = useDelta ? "delta" : "complete";
      if (state.activeSnapshotId) {
        joinParams.knownSnapshotId = state.activeSnapshotId;
      }
      if (useDelta && state.activeSnapshotId) {
        joinParams.knownSnapshotUpdateClocks = { ...state.confirmedClocks };
      }

      let documentHandled: Promise<void> | null = null;
      let earlyCloseReject: ((err: Error) => void) | null = null;

      const callbacks: DocumentChannelCallbacks = {
        onDocument: (payload) => {
          documentHandled = handleReconnectDocument(
            payload as unknown as DocumentPayload,
            state,
            documentId,
            localDeviceSigningPubKey,
            failClosed,
          );
        },
        onUpdate: (payload) => {
          handleRemoteUpdate(payload as any, state, documentId, localDeviceSigningPubKey).catch(
            (err) => {
              failClosed("verification_failed", err);
            },
          );
        },
        onSnapshot: (payload) => {
          handleRemoteSnapshot(payload as any, state, documentId).catch((err) => {
            failClosed("verification_failed", err);
          });
        },
        onUpdateSaved: (payload) => {
          handleUpdateSaved(payload as unknown as UpdateSavedPayload, state, documentId);
        },
        onUpdateSaveFailed: (payload) => {
          handleUpdateSaveFailed(payload as unknown as UpdateSaveFailedPayload, state);
          const p = payload as unknown as UpdateSaveFailedPayload;
          if (p.requiresNewSnapshot) {
            failClosed("snapshot_mismatch");
          }
        },
        onSnapshotSaved: (payload) => {
          handleSnapshotSaved(payload as unknown as SnapshotSavedPayload, state, documentId);
        },
        onSnapshotSaveFailed: (payload) => {
          handleSnapshotSaveFailed(
            payload as unknown as SnapshotSaveFailedPayload,
            state,
            documentId,
          ).catch((err) => {
            failClosed("verification_failed", err);
          });
        },
        onEphemeralMessage: (payload) => {
          handleEphemeralMessage(
            payload as Record<string, unknown>,
            state,
            documentId,
            localDeviceSigningPubKey,
            failClosed,
          );
        },
        onPeerLeft: (payload) => {
          handlePeerLeft(payload, state);
        },
        onUnauthorized: () => {
          // Session expired mid-connection: trigger reconnect which handles re-auth
          triggerReconnect(state, documentId, workspaceId, localDeviceSigningPubKey, failClosed);
        },
        onError: (reason) => {
          if (
            reason === "document_not_found" ||
            reason === "document_error" ||
            reason === "connection_cap_evict"
          ) {
            failClosed(String(reason));
          } else {
            triggerReconnect(state, documentId, workspaceId, localDeviceSigningPubKey, failClosed);
          }
        },
        onClose: () => {
          if (earlyCloseReject) {
            earlyCloseReject(new Error("Disconnected before document received"));
          } else {
            triggerReconnect(state, documentId, workspaceId, localDeviceSigningPubKey, failClosed);
          }
        },
      };

      state.channel = null;
      state.initialized = false;
      state._pendingRemoteEvents = [];
      const channel = await rejoinDocument(documentId, joinParams, callbacks);
      state.channel = channel;

      await new Promise<void>((resolve, reject) => {
        const cleanup = () => {
          clearTimeout(timer);
          clearInterval(check);
          earlyCloseReject = null;
        };
        earlyCloseReject = (err: Error) => {
          cleanup();
          reject(err);
        };
        const timer = setTimeout(() => {
          if (!documentHandled) {
            cleanup();
            reject(new Error("Reconnect document message timeout"));
          }
        }, 30_000);
        const check = setInterval(() => {
          if (documentHandled) {
            cleanup();
            documentHandled.then(resolve, reject);
          }
        }, 100);
      });
      return;
    } catch (err) {
      const resp = (err as any)?.joinErrorResp;
      const reason = resp?.reason;
      if (reason === "not_a_member" || reason === "permission_denied") {
        // Access revoked: switch to read-only cached mode, purge KEK
        state.readOnly = true;
        if (state.autoSync) {
          state.autoSync.dispose();
          state.autoSync = null;
        }
        import("@/shared/lib/offline/offline-store").then(({ deleteOfflineKek }) =>
          deleteOfflineKek(workspaceId).catch(() => {}),
        );
        import("@/shared/lib/notice")
          .then(({ Notice }) => new Notice("Workspace access revoked. Document is now read-only."))
          .catch(() => {});
        return;
      }
      if (reason === "document_not_found" || reason === "pop_verification_failed") {
        failClosed(reason);
        return;
      }
      if (reason === "unauthorized") {
        // Session expired: request re-authentication and retry
        await requestReauth(documentId);
        // After re-auth completes, reset attempt counter and retry
        attempt = -1; // Will be incremented to 0 by the loop
        useDelta = !!state.activeSnapshotId;
        continue;
      }
      if (useDelta) useDelta = false;
    }
  }

  failClosed("reconnect_exhausted");
}

async function handleReconnectDocument(
  payload: DocumentPayload,
  state: DocumentState,
  documentId: string,
  localDeviceSigningPubKey: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): Promise<void> {
  try {
    // Channel successfully rejoined — ensure offlineMode() returns false
    // so auto-sync sends local diffs to the server instead of caching them.
    // Socket.onOpen may not have fired yet due to event loop ordering.
    setWsConnected(true);
    notifyOfflineListeners();

    const localClientId = state.awareness.clientID;
    const staleClients: number[] = [];
    state.awareness.getStates().forEach((_, clientId) => {
      if (clientId !== localClientId) staleClients.push(clientId);
    });
    if (staleClients.length > 0) {
      removeAwarenessStates(state.awareness, staleClients, "reconnect");
      for (const clientId of staleClients) {
        state.awarenessClientOwners.delete(clientId);
      }
    }

    const cacheResult = await buildDeviceKeyCaches(state.workspaceId);
    if (cacheResult.status === "key_changed") {
      failClosed("verification_failed");
      return;
    }
    state.signingKeys = cacheResult.signingKeys;
    state.signingKeyOwners = cacheResult.signingKeyOwners;
    state.memberNames = cacheResult.memberNames;
    state.revokedSigningKeys = cacheResult.revokedSigningKeys;
    state.rejectedSigningKeys = cacheResult.rejectedSigningKeys;

    // Save in-flight envelopes before clearing (for queue replay on same-snapshot)
    const savedUpdateEnvelope = state.pendingUpdateEnvelope;
    const savedUpdateBytes = state.pendingUpdateBytes;
    const savedPendingSnapshot = state.pendingSnapshot;
    const savedSnapshotEnvelope = state.pendingSnapshotEnvelope;

    state.pendingSnapshot = null;
    state.pendingSnapshotEnvelope = null;
    state.sending = false;
    state.pendingUpdateBytes = null;
    state.pendingUpdateEnvelope = null;

    const prevSnapshotId = state.activeSnapshotId;

    await handleDocumentMessage(payload, state, documentId);

    // Drain events queued during async document processing
    const queued = state._pendingRemoteEvents.splice(0);
    for (const event of queued) {
      if (event.type === "update") {
        await handleRemoteUpdate(event.payload as any, state, documentId, localDeviceSigningPubKey);
      } else {
        await handleRemoteSnapshot(event.payload as any, state, documentId);
      }
    }

    // Compare actual snapshot IDs — not payload.snapshot presence.
    // Complete-mode fallback can return the same snapshot, which is not a "change".
    const snapshotChanged = state.activeSnapshotId !== prevSnapshotId;

    if (localDeviceSigningPubKey) {
      let maxClock = -1;
      if (payload.updates) {
        for (const update of payload.updates) {
          if (
            update.publicData.signingPubKey === localDeviceSigningPubKey &&
            update.publicData.clock > maxClock
          ) {
            maxClock = update.publicData.clock;
          }
        }
      }
      if (snapshotChanged) {
        state.localClock = maxClock + 1;
      } else {
        if (maxClock >= 0) {
          state.localClock = maxClock + 1;
        } else if (state.preSendLocalClock < state.localClock) {
          state.localClock = state.preSendLocalClock;
        }
      }
    }

    // Queue replay: same snapshot → replay in-flight envelope (update_hash UNIQUE idempotency)
    // Different snapshot → discard (refSnapshotId is stale, content remains in local Y.Doc)
    if (!snapshotChanged) {
      if (savedUpdateEnvelope && savedUpdateBytes) {
        state.sending = true;
        state.pendingUpdateBytes = savedUpdateBytes;
        state.pendingUpdateEnvelope = savedUpdateEnvelope;
        pushUpdate(documentId, savedUpdateEnvelope, (resp: unknown) => {
          if (resp !== "timeout" && state.pendingUpdateBytes) {
            state.sending = false;
            state.pendingUpdateBytes = null;
            state.pendingUpdateEnvelope = null;
            state.localClock = state.preSendLocalClock;
            if (state.autoSync) state.autoSync.notifyLocalEdit();
          }
        });
      } else if (savedSnapshotEnvelope && savedPendingSnapshot) {
        state.sending = true;
        state.pendingSnapshot = savedPendingSnapshot;
        state.pendingSnapshotEnvelope = savedSnapshotEnvelope;
        pushSnapshot(documentId, savedSnapshotEnvelope, (resp: unknown) => {
          if (resp === "timeout") return;
          state.pendingSnapshot = null;
          state.pendingSnapshotEnvelope = null;
          state.sending = false;
        });
      }
    }

    const auth = authState();
    const currentDevice = deviceState();
    if (auth && currentDevice && localDeviceSigningPubKey) {
      state.awareness.setLocalStateField("user", {
        userId: auth.user.id,
        name: auth.user.name,
        color: assignUserColor(auth.user.id, state.awareness),
        signingPubKey: localDeviceSigningPubKey,
      });

      const session = createEphemeralSession();
      state.ephemeralSession = session;
      sendInitialize(session, state, documentId, currentDevice.deviceId, localDeviceSigningPubKey);

      setupAwarenessRelay(state, documentId, currentDevice.deviceId, localDeviceSigningPubKey);
      notifyAwarenessReady(documentId);
    }

    // Remaining local changes: only trigger if queue replay didn't take the sending lock
    if (!state.sending && state.autoSync) state.autoSync.notifyLocalEdit();

    // Update offline cache after successful reconnect.
    // Do NOT delete pending-changes here — they must persist until
    // the auto-sync successfully sends the diff and update-saved confirms it.
    // handleUpdateSaved already calls deletePendingChanges on confirmation.
    state.loadedFromOfflineCache = false;
    cacheDocumentState(documentId, state.workspaceId, state).catch(() => {});
    cacheDek(documentId, state.keyVersion).catch(() => {});
  } catch (err) {
    failClosed("reconnect_failed", err);
  }
}
