import { authState, deviceState } from "@/entities/session";
import { cacheDek } from "@/shared/lib/offline/cache/manager/keys";
import { cacheDocumentState } from "@/shared/lib/offline/cache/manager/write";
import { setWsConnected } from "@/shared/lib/offline/offline-state";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import { pushSnapshot, pushUpdate } from "@/shared/lib/ws/phoenix-channel";
import { removeAwarenessStates } from "y-protocols/awareness";
import { notifyAwarenessReady } from "../../../model/document-state/signals";
import type { DocumentState } from "../../../model/document-state/types";
import { assignUserColor } from "../../user-colors";
import { runPostReconnectSession } from "./session";
import {
  handleDocumentMessage,
  handleRemoteSnapshot,
  handleRemoteUpdate,
} from "../inbound/document";
import { applyDeviceKeyCache, buildDeviceKeyCaches } from "../inbound/signing-keys";

export async function resumeReconnectDocument(
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
    applyDeviceKeyCache(state, cacheResult);

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

    const queued = state._pendingRemoteEvents.splice(0);
    for (const event of queued) {
      if (event.type === "update") {
        await handleRemoteUpdate(event.payload, state, documentId, localDeviceSigningPubKey);
      } else {
        await handleRemoteSnapshot(event.payload, state, documentId);
      }
    }

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

      runPostReconnectSession(state, documentId, currentDevice.deviceId, localDeviceSigningPubKey);
      notifyAwarenessReady(documentId);
    }

    if (!state.sending && state.autoSync) state.autoSync.notifyLocalEdit();

    state.loadedFromOfflineCache = false;
    cacheDocumentState(documentId, state.workspaceId, state).catch(() => {});
    cacheDek(documentId, state.keyVersion).catch(() => {});
  } catch (err) {
    failClosed("reconnect_failed", err);
  }
}
