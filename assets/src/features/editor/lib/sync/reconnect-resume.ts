import { authState, deviceState } from "@/entities/session";
import { cacheDek } from "@/shared/lib/offline/cache/manager/keys";
import { cacheDocumentState } from "@/shared/lib/offline/cache/manager/write";
import { setWsConnected } from "@/shared/lib/offline/offline-state";
import { documentClockKey } from "@/shared/lib/anti-rollback/clock-observations";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import { getChannelState, pushSnapshot, pushUpdate } from "@/shared/lib/ws/phoenix-channel";
import {
  encodeCanonicalDiffAsUpdate,
  encodeCanonicalStateAsUpdate,
} from "@/shared/lib/yjs/canonical-document";
import { removeAwarenessStates } from "y-protocols/awareness";
import * as Y from "yjs";
import { notifyAwarenessReady } from "../../model/document-state/signals";
import type { DocumentState } from "../../model/document-state/types";
import { assignUserColor } from "../presence/user-colors";
import { runPostReconnectSession } from "./reconnect-session";
import { isRecoverableSyncGapError } from "./error";
import {
  handleDocumentMessage,
  handleRemoteSnapshot,
  handleRemoteUpdate,
  handleRemoteWriteSession,
} from "./inbound-document";
import { applyDeviceKeyCache, buildDocumentSigningKeyCaches } from "./inbound-signing-keys";
import { getLocalDeviceId, getLocalIdentity } from "./share-identity";
import { armSaveAckWatchdog, clearSaveAckWatchdog } from "./outbound-save-watchdog";
import { getDocumentCryptoWorker } from "./crypto-worker";
import { getDocumentDekCacheKey } from "./share-access";
import { localDocumentClockKey, nextLocalClockForDevice } from "./local-clock";

function isChannelJoined(state: DocumentState): boolean {
  return !!state.channel && getChannelState(state.channel) === "joined";
}

function buildUnsavedLocalUpdate(state: DocumentState): Uint8Array | null {
  if (!state.lastSavedState) {
    const fullState = encodeCanonicalStateAsUpdate(state.yDoc);
    return fullState.length > 2 ? fullState : null;
  }

  const update = encodeCanonicalDiffAsUpdate(state.yDoc, state.lastSavedState);
  return update.length > 2 ? update : null;
}

export async function resumeReconnectDocument(
  payload: DocumentPayload,
  state: DocumentState,
  documentId: string,
  localDeviceSigningKeyId: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): Promise<void> {
  try {
    // Channel successfully rejoined — ensure offlineMode() returns false
    // so auto-sync sends local diffs to the server instead of caching them.
    // Socket.onOpen may not have fired yet due to event loop ordering.
    setWsConnected(true);

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

    const cacheResult = await buildDocumentSigningKeyCaches(state);
    if (cacheResult.status === "key_changed") {
      failClosed("verification_failed");
      return;
    }
    applyDeviceKeyCache(state, cacheResult);

    const savedUpdateEnvelope = state.pendingUpdateEnvelope;
    const savedUpdateBytes = state.pendingUpdateBytes;
    const savedPendingSnapshot = state.pendingSnapshot;
    const savedSnapshotEnvelope = state.pendingSnapshotEnvelope;
    const unsavedLocalUpdate = buildUnsavedLocalUpdate(state);

    clearSaveAckWatchdog(state);
    state.pendingSnapshot = null;
    state.pendingSnapshotEnvelope = null;
    state.sending = false;
    state.pendingUpdateBytes = null;
    state.pendingUpdateEnvelope = null;

    const prevSnapshotId = state.activeSnapshotId;

    await handleDocumentMessage(payload, state, documentId);
    if (payload.archived) {
      state.readOnly = true;
    }

    const queued = state._pendingRemoteEvents.splice(0);
    for (const event of queued) {
      if (event.type === "update") {
        await handleRemoteUpdate(event.payload, state, documentId, localDeviceSigningKeyId);
      } else if (event.type === "snapshot") {
        await handleRemoteSnapshot(event.payload, state, documentId);
      } else {
        await handleRemoteWriteSession(event.payload, state, documentId);
      }
    }

    if (unsavedLocalUpdate) {
      Y.applyUpdate(state.yDoc, unsavedLocalUpdate, "local-reconnect");
    }

    const snapshotChanged = state.activeSnapshotId !== prevSnapshotId;

    if (localDeviceSigningKeyId) {
      const localClockKey = localDocumentClockKey(state, localDeviceSigningKeyId);
      let maxClock =
        nextLocalClockForDevice(state.confirmedClocks, state, localDeviceSigningKeyId) - 1;
      if (payload.updates) {
        for (const update of payload.updates) {
          if (
            documentClockKey(update.publicData) === localClockKey &&
            update.publicData.clock > maxClock
          ) {
            maxClock = update.publicData.clock;
          }
        }
      }
      if (snapshotChanged) {
        state.localClock = maxClock + 1;
      } else if (maxClock >= 0) {
        state.localClock = maxClock + 1;
      } else if (state.preSendLocalClock < state.localClock) {
        state.localClock = state.preSendLocalClock;
      }
    }

    if (!snapshotChanged) {
      if (savedUpdateEnvelope && savedUpdateBytes) {
        state.sending = true;
        state.pendingUpdateBytes = savedUpdateBytes;
        state.pendingUpdateEnvelope = savedUpdateEnvelope;
        const pushed = isChannelJoined(state)
          ? pushUpdate(
              documentId,
              savedUpdateEnvelope,
              (resp: unknown) => {
                if (resp !== "timeout" && state.pendingUpdateBytes) {
                  state.sending = false;
                  state.pendingUpdateBytes = null;
                  state.pendingUpdateEnvelope = null;
                  state.localClock = state.preSendLocalClock;
                  if (state.autoSync) state.autoSync.notifyLocalEdit();
                }
              },
              state.stateKey,
            )
          : false;
        if (pushed) {
          armSaveAckWatchdog(state, () => failClosed("reconnect_failed"), "update");
        } else {
          state.sending = false;
          state.pendingUpdateBytes = null;
          state.pendingUpdateEnvelope = null;
          if (state.autoSync) state.autoSync.notifyLocalEdit();
        }
      } else if (savedSnapshotEnvelope && savedPendingSnapshot) {
        state.sending = true;
        state.pendingSnapshot = savedPendingSnapshot;
        state.pendingSnapshotEnvelope = savedSnapshotEnvelope;
        const pushed = isChannelJoined(state)
          ? pushSnapshot(
              documentId,
              savedSnapshotEnvelope,
              (resp: unknown) => {
                if (resp === "timeout") return;
                state.pendingSnapshot = null;
                state.pendingSnapshotEnvelope = null;
                state.sending = false;
              },
              state.stateKey,
            )
          : false;
        if (pushed) {
          armSaveAckWatchdog(state, () => failClosed("reconnect_failed"), "snapshot");
        } else {
          state.pendingSnapshot = null;
          state.pendingSnapshotEnvelope = null;
          state.sending = false;
          if (state.autoSync) state.autoSync.notifyLocalEdit();
        }
      }
    }

    const auth = state.access.kind === "share" ? null : authState();
    const currentDevice = state.access.kind === "share" ? null : deviceState();
    const shareIdentity = getLocalIdentity(state);
    const shareDeviceId = getLocalDeviceId(state);
    if ((shareIdentity || (auth && currentDevice)) && localDeviceSigningKeyId) {
      state.awareness.setLocalStateField("user", {
        userId: shareIdentity?.id ?? auth!.user.id,
        name: shareIdentity?.name ?? auth!.user.name,
        color: assignUserColor(shareIdentity?.colorSeed ?? auth!.user.id, state.awareness),
        signingKeyId: localDeviceSigningKeyId,
      });

      runPostReconnectSession(
        state,
        documentId,
        shareDeviceId ?? currentDevice!.deviceId,
        localDeviceSigningKeyId,
      );
      notifyAwarenessReady(state.stateKey);
    }

    if (!state.sending && state.autoSync) state.autoSync.notifyLocalEdit();

    state.loadedFromOfflineCache = false;
    if (state.access.kind === "share") {
      cacheDocumentState(documentId, state.workspaceId, state, {
        worker: getDocumentCryptoWorker(state),
        cacheKey: getDocumentDekCacheKey(state, documentId),
      }).catch(() => {});
    } else {
      cacheDocumentState(documentId, state.workspaceId, state).catch(() => {});
      cacheDek(documentId, state.keyVersion).catch(() => {});
    }
  } catch (err) {
    if (isRecoverableSyncGapError(err)) {
      throw err;
    }
    failClosed("reconnect_failed", err);
  }
}
