import { authState, deviceState } from "@/entities/session";
import { cacheDek } from "@/shared/lib/offline/cache/manager/keys";
import { cacheDocumentState } from "@/shared/lib/offline/cache/manager/write";
import { setWsConnected } from "@/shared/lib/offline/offline-state";
import { documentClockKey } from "@/shared/lib/anti-rollback/clock-observations";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import { getChannelState, pushSnapshot, pushUpdate } from "@/shared/lib/ws/phoenix-channel";
import {
  canonicalMarkdownText,
  encodeCanonicalDiffAsUpdate,
  replaceDocWithCanonicalText,
} from "@/shared/lib/yjs/canonical-document";
import { removeAwarenessStates } from "y-protocols/awareness";
import * as Y from "yjs";
import { notifyAwarenessReady } from "../../model/document-state/signals";
import type { DocumentState } from "../../model/document-state/types";
import { assignUserColor } from "../presence/user-colors";
import { runPostReconnectSession } from "./reconnect-session";
import { isRecoverableSyncGapError } from "./error";
import { createSyncGapError } from "./inbound-verify-decrypt";
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
import {
  shouldRecomputeUnsavedLocalUpdate,
  shouldFailNoBaselineLocalTextReconnect,
} from "./reconnect-decisions";
import { getDocumentDekCacheKey } from "./share-access";
import { localDocumentClockKey, nextLocalClockForDevice } from "./local-clock";

function isChannelJoined(state: DocumentState): boolean {
  return !!state.channel && getChannelState(state.channel) === "joined";
}

function canonicalTextFromSnapshotState(snapshotState: Uint8Array): string | null {
  const doc = new Y.Doc();
  try {
    Y.applyUpdateV2(doc, snapshotState, "reconnect-replay-guard");
    return canonicalMarkdownText(doc);
  } catch {
    return null;
  } finally {
    doc.destroy();
  }
}

function canReplayPendingNoBaselineGenesisSnapshot(params: {
  prevSnapshotId: string | null;
  currentSnapshotId: string | null;
  pendingSnapshot: DocumentState["pendingSnapshot"];
  pendingSnapshotEnvelope: DocumentState["pendingSnapshotEnvelope"];
  localText: string | null;
}): boolean {
  if (!params.pendingSnapshot || !params.pendingSnapshotEnvelope || params.localText === null) {
    return false;
  }
  if (params.prevSnapshotId !== null || params.currentSnapshotId !== null) return false;
  if (params.pendingSnapshot.parentSnapshotId !== "GENESIS") return false;

  return (
    canonicalTextFromSnapshotState(params.pendingSnapshot.snapshotYjsState) === params.localText
  );
}

function buildUnsavedLocalUpdate(state: DocumentState): Uint8Array | null {
  if (!state.lastSavedState) {
    return null;
  }

  const update = encodeCanonicalDiffAsUpdate(state.yDoc, state.lastSavedState);
  return update && update.length > 2 ? update : null;
}

function unsavedLocalTextWithoutBaseline(state: DocumentState): string | null {
  if (state.lastSavedState) return null;
  const text = canonicalMarkdownText(state.yDoc);
  return text.length > 0 ? text : null;
}

interface NoBaselineReconnectRollback {
  text: string;
  activeSnapshotId: string | null;
  localClock: number;
  knownClocks: Record<string, number>;
  confirmedClocks: Record<string, number>;
  writeSessionCounters: Record<string, number>;
  snapshotBaseClocks: Record<string, number>;
  lastSavedState: Uint8Array | null;
  snapshotUpdatesCount: number;
  snapshotProofHash: string;
  snapshotCiphertextHash: string;
  latestVersion: number;
  keyVersion: number;
  pendingRemoteEvents: DocumentState["_pendingRemoteEvents"];
  pendingOutOfOrderUpdates: DocumentState["_pendingOutOfOrderUpdates"];
}

function cloneBytes(bytes: Uint8Array | null): Uint8Array | null {
  return bytes ? new Uint8Array(bytes) : null;
}

export function captureNoBaselineReconnectRollback(
  state: DocumentState,
  text: string,
): NoBaselineReconnectRollback {
  return {
    text,
    activeSnapshotId: state.activeSnapshotId,
    localClock: state.localClock,
    knownClocks: { ...state.knownClocks },
    confirmedClocks: { ...state.confirmedClocks },
    writeSessionCounters: { ...state.writeSessionCounters },
    snapshotBaseClocks: { ...state.snapshotBaseClocks },
    lastSavedState: cloneBytes(state.lastSavedState),
    snapshotUpdatesCount: state.snapshotUpdatesCount,
    snapshotProofHash: state.snapshotProofHash,
    snapshotCiphertextHash: state.snapshotCiphertextHash,
    latestVersion: state.latestVersion,
    keyVersion: state.keyVersion,
    pendingRemoteEvents: [...state._pendingRemoteEvents],
    pendingOutOfOrderUpdates: [...state._pendingOutOfOrderUpdates],
  };
}

export function rollbackNoBaselineReconnectState(
  state: DocumentState,
  snapshot: NoBaselineReconnectRollback,
): void {
  replaceDocWithCanonicalText(state.yDoc, snapshot.text, "reconnect-rollback");
  state.activeSnapshotId = snapshot.activeSnapshotId;
  state.localClock = snapshot.localClock;
  state.knownClocks = { ...snapshot.knownClocks };
  state.confirmedClocks = { ...snapshot.confirmedClocks };
  state.writeSessionCounters = { ...snapshot.writeSessionCounters };
  state.snapshotBaseClocks = { ...snapshot.snapshotBaseClocks };
  state.lastSavedState = cloneBytes(snapshot.lastSavedState);
  state.snapshotUpdatesCount = snapshot.snapshotUpdatesCount;
  state.snapshotProofHash = snapshot.snapshotProofHash;
  state.snapshotCiphertextHash = snapshot.snapshotCiphertextHash;
  state.latestVersion = snapshot.latestVersion;
  state.keyVersion = snapshot.keyVersion;
  state._pendingRemoteEvents = [...snapshot.pendingRemoteEvents];
  state._pendingOutOfOrderUpdates = [...snapshot.pendingOutOfOrderUpdates];
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
      failClosed(
        "verification_failed",
        new Error(`TOFU key change detected: device ${cacheResult.warning.deviceId ?? "unknown"}`),
      );
      return;
    }
    applyDeviceKeyCache(state, cacheResult);

    const savedUpdateEnvelope = state.pendingUpdateEnvelope;
    const savedUpdateBytes = state.pendingUpdateBytes;
    const savedPendingSnapshot = state.pendingSnapshot;
    const savedSnapshotEnvelope = state.pendingSnapshotEnvelope;
    const unsavedLocalUpdate = shouldRecomputeUnsavedLocalUpdate(savedUpdateBytes !== null)
      ? buildUnsavedLocalUpdate(state)
      : null;
    const unsavedNoBaselineText = unsavedLocalTextWithoutBaseline(state);
    const noBaselineRollback =
      unsavedNoBaselineText !== null
        ? captureNoBaselineReconnectRollback(state, unsavedNoBaselineText)
        : null;

    clearSaveAckWatchdog(state);
    state.pendingSnapshot = null;
    state.pendingSnapshotEnvelope = null;
    state.sending = false;
    state.pendingUpdateBytes = null;
    state.pendingUpdateEnvelope = null;

    const prevSnapshotId = state.activeSnapshotId;
    const canReplayPendingSnapshot = () =>
      canReplayPendingNoBaselineGenesisSnapshot({
        prevSnapshotId,
        currentSnapshotId: state.activeSnapshotId,
        pendingSnapshot: savedPendingSnapshot,
        pendingSnapshotEnvelope: savedSnapshotEnvelope,
        localText: unsavedNoBaselineText,
      });

    try {
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
    } catch (err) {
      if (noBaselineRollback && isRecoverableSyncGapError(err)) {
        if (canReplayPendingSnapshot()) {
          rollbackNoBaselineReconnectState(state, noBaselineRollback);
          state.initialized = true;
        } else {
          rollbackNoBaselineReconnectState(state, noBaselineRollback);
          failClosed("reconnect_failed", err);
          return;
        }
      } else {
        throw err;
      }
    }

    const snapshotChanged = state.activeSnapshotId !== prevSnapshotId;

    if (unsavedLocalUpdate) {
      Y.applyUpdate(state.yDoc, unsavedLocalUpdate, "local-reconnect");
    } else if (unsavedNoBaselineText !== null) {
      const currentText = canonicalMarkdownText(state.yDoc);
      if (shouldFailNoBaselineLocalTextReconnect(currentText, unsavedNoBaselineText)) {
        if (canReplayPendingSnapshot() && noBaselineRollback) {
          rollbackNoBaselineReconnectState(state, noBaselineRollback);
        } else {
          const err = createSyncGapError("no_baseline_local_text_reconnect_conflict");
          if (noBaselineRollback) rollbackNoBaselineReconnectState(state, noBaselineRollback);
          failClosed("reconnect_failed", err);
          return;
        }
      }
    }

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
