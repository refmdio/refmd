import * as Y from "yjs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getNextClockForDevice } from "@/shared/lib/anti-rollback/clock-observations";
import { cacheDocumentState } from "@/shared/lib/offline/cache/manager/write";
import { deletePendingChanges } from "@/shared/lib/offline/storage/store";
import { deviceState } from "@/entities/session";
import {
  buildDocumentStatePinKey,
  getDocumentStatePin,
  putDocumentStatePin,
  updatePinFromState,
} from "@/shared/lib/anti-rollback/document-state-pins";
import type {
  SnapshotSaveFailedPayload,
  SnapshotSavedPayload,
  UpdateSaveFailedPayload,
  UpdateSavedPayload,
} from "@/shared/lib/ws/document-payloads";
import { DocumentSyncError, isRecoverableSyncGapError } from "../error";
import { getDocumentState } from "../../../model/document-state/store";
import type { DocumentState } from "../../../model/document-state/types";
import { handleDocumentMessage } from "../inbound/document";
import { getLocalSigningPubKeyB64, getLocalSigningPublicKeyBytes } from "../share-identity";
import { hasUnsavedCanonicalText, refreshSavedBaselineToCurrent } from "./canonical";
import { queuePublicationSaveSync } from "./publication";
import { clearSaveAckWatchdog } from "./save-watchdog";

function getPinKey(state: DocumentState, documentId: string): string {
  return state.access.kind === "share"
    ? buildDocumentStatePinKey(documentId, state.access.shareId)
    : buildDocumentStatePinKey(documentId);
}

function hasUnsavedLocalChanges(state: DocumentState): boolean {
  return hasUnsavedCanonicalText(state);
}

function pendingUpdatePublicData(
  state: DocumentState,
): { refSnapshotId: string; clock: number; updateHash: string } | null {
  const publicData = state.pendingUpdateEnvelope?.publicData;
  if (!publicData || typeof publicData !== "object") return null;
  const typed = publicData as Record<string, unknown>;
  if (
    typeof typed.refSnapshotId !== "string" ||
    typeof typed.clock !== "number" ||
    typeof typed.updateHash !== "string"
  ) {
    return null;
  }
  return {
    refSnapshotId: typed.refSnapshotId,
    clock: typed.clock,
    updateHash: typed.updateHash,
  };
}

function rejectInvalidAck(state: DocumentState): void {
  if (state.pendingUpdateEnvelope) {
    state.localClock = state.preSendLocalClock;
  }
  state.pendingUpdateBytes = null;
  state.pendingUpdateEnvelope = null;
  state.pendingSnapshot = null;
  state.pendingSnapshotEnvelope = null;
  state.sending = false;
  state._forceCompleteReconnect = true;
  if (state.autoSync) state.autoSync.notifyLocalEdit();
}

export function handleUpdateSaved(
  payload: UpdateSavedPayload,
  state: DocumentState,
  documentId?: string,
): void {
  clearSaveAckWatchdog(state);
  const pending = pendingUpdatePublicData(state);
  if (
    !pending ||
    payload.snapshotId !== pending.refSnapshotId ||
    payload.clock !== pending.clock ||
    payload.updateHash !== pending.updateHash
  ) {
    rejectInvalidAck(state);
    return;
  }

  if (state.activeSnapshotId && payload.snapshotId !== state.activeSnapshotId) {
    state.pendingUpdateBytes = null;
    state.pendingUpdateEnvelope = null;
    state.sending = false;
    if (state.autoSync && hasUnsavedLocalChanges(state)) {
      state.autoSync.notifyLocalEdit();
    }
    return;
  }

  const deviceKey = getLocalSigningPublicKeyBytes(state) ?? deviceState()?.deviceSigningPublic;
  if (deviceKey) {
    const key = base64UrlEncode(deviceKey);
    state.knownClocks[key] = payload.clock;
    state.confirmedClocks[key] = payload.clock;
    if (payload.clock >= state.localClock) {
      state.localClock = payload.clock + 1;
    }
  }

  if (state.pendingUpdateBytes && state.lastSavedState) {
    const serverDoc = new Y.Doc();
    Y.applyUpdate(serverDoc, state.lastSavedState, "remote");
    Y.applyUpdate(serverDoc, state.pendingUpdateBytes, "remote");
    state.lastSavedState = Y.encodeStateAsUpdate(serverDoc);
    serverDoc.destroy();
  }
  state.pendingUpdateBytes = null;
  state.pendingUpdateEnvelope = null;
  state.sending = false;

  if (payload.version > state.latestVersion) {
    state.latestVersion = payload.version;
  }
  state.snapshotUpdatesCount++;

  if (documentId) {
    const pinKey = getPinKey(state, documentId);
    getDocumentStatePin(pinKey).then((existing) => {
      const pin = updatePinFromState(
        existing,
        pinKey,
        state.activeSnapshotId,
        state.snapshotProofHash,
        state.snapshotCiphertextHash,
        state.confirmedClocks,
        state.latestVersion,
        documentId,
      );
      putDocumentStatePin(pin).catch(() => {});
    });
  }

  if (documentId && state.workspaceId && state.keyVersion > 0 && state.access.kind !== "share") {
    cacheDocumentState(documentId, state.workspaceId, state).catch(() => {});
    deletePendingChanges(documentId).catch(() => {});
  }

  if (documentId) {
    queuePublicationSaveSync(documentId, state);
  }

  const hasUnsavedChanges = hasUnsavedLocalChanges(state);
  if (state.autoSync && hasUnsavedChanges) {
    state.autoSync.notifyLocalEdit();
  } else if (!hasUnsavedChanges) {
    refreshSavedBaselineToCurrent(state);
  }
}

export function handleUpdateSaveFailed(
  payload: UpdateSaveFailedPayload,
  state: DocumentState,
): void {
  clearSaveAckWatchdog(state);
  const sentClock = state.preSendLocalClock;
  if (state.localClock === sentClock + 1) {
    state.localClock = sentClock;
  }
  state.pendingUpdateBytes = null;
  state.pendingUpdateEnvelope = null;
  state.sending = false;

  if (payload.requiresNewSnapshot) {
    state.error = "snapshot_mismatch";
    return;
  }
}

export async function handleSnapshotSaved(
  payload: SnapshotSavedPayload,
  state: DocumentState,
  documentId?: string,
): Promise<void> {
  clearSaveAckWatchdog(state);
  const pendingSnapshot = state.pendingSnapshot;
  if (!pendingSnapshot) return;
  if (payload.snapshotId !== pendingSnapshot.snapshotId) {
    rejectInvalidAck(state);
    return;
  }

  state.activeSnapshotId = pendingSnapshot.snapshotId;
  state.snapshotCiphertextHash = pendingSnapshot.ciphertextHash;
  state.snapshotProofHash = await getCryptoWorker().computeSnapshotProof({
    ciphertextHash: pendingSnapshot.ciphertextHash,
    parentProof: pendingSnapshot.parentSnapshotProof,
    snapshotId: pendingSnapshot.snapshotId,
  });

  const serverDoc = new Y.Doc();
  Y.applyUpdateV2(serverDoc, pendingSnapshot.snapshotYjsState, "remote");
  state.lastSavedState = Y.encodeStateAsUpdate(serverDoc);
  serverDoc.destroy();
  state.snapshotUpdatesCount = 0;
  state.snapshotBaseClocks = { ...pendingSnapshot.knownClocksAtSend };
  if (typeof payload.latestVersion === "number") {
    state.latestVersion = payload.latestVersion;
  }

  state.pendingSnapshot = null;
  state.pendingSnapshotEnvelope = null;
  state.sending = false;
  if (state.pendingRotationKeyVersion !== null) {
    state.keyVersion = state.pendingRotationKeyVersion;
    state.pendingRotationKeyVersion = null;
  }
  state.pendingRotationSnapshot = false;
  const localDeviceSigningPublic =
    getLocalSigningPublicKeyBytes(state) ?? deviceState()?.deviceSigningPublic;
  state.knownClocks = {};
  state.confirmedClocks = {};
  state.localClock = getNextClockForDevice(
    state.knownClocks,
    getLocalSigningPubKeyB64(state) ??
      (localDeviceSigningPublic ? base64UrlEncode(localDeviceSigningPublic) : undefined),
  );

  if (documentId && state.workspaceId && state.keyVersion > 0 && state.access.kind !== "share") {
    cacheDocumentState(documentId, state.workspaceId, state).catch(() => {});
    deletePendingChanges(documentId).catch(() => {});
  }

  if (documentId) {
    const pinKey = getPinKey(state, documentId);
    getDocumentStatePin(pinKey).then((existing) => {
      const pin = updatePinFromState(
        existing,
        pinKey,
        state.activeSnapshotId,
        state.snapshotProofHash,
        state.snapshotCiphertextHash,
        state.confirmedClocks,
        state.latestVersion,
        documentId,
      );
      putDocumentStatePin(pin, {
        expectedPreviousSnapshotId: pendingSnapshot.parentSnapshotId,
        allowSnapshotChangeAtSameVersion: true,
      }).catch(() => {});
    });

    queuePublicationSaveSync(documentId, state);
  }

  const hasUnsavedChanges = hasUnsavedLocalChanges(state);
  if (state.autoSync && hasUnsavedChanges) {
    state.autoSync.notifyLocalEdit();
  } else if (!hasUnsavedChanges) {
    refreshSavedBaselineToCurrent(state);
  }
}

export async function handleSnapshotSaveFailed(
  payload: SnapshotSaveFailedPayload,
  state: DocumentState,
  documentId: string,
): Promise<void> {
  clearSaveAckWatchdog(state);
  if (getDocumentState(state.stateKey) !== state || state.refCount <= 0) {
    state.snapshotUpdatesCount = 0;
    return;
  }

  state.pendingSnapshot = null;
  state.pendingSnapshotEnvelope = null;
  state.sending = false;

  if (payload.snapshot || payload.updates.length > 0) {
    let recoveryVersion = state.latestVersion;
    for (const update of payload.updates) {
      if (update.version > recoveryVersion) recoveryVersion = update.version;
    }
    try {
      await handleDocumentMessage(
        {
          snapshot: payload.snapshot,
          updates: payload.updates,
          snapshotProofChain: payload.snapshotProofChain,
          latestVersion: recoveryVersion,
        },
        state,
        documentId,
      );
      state.snapshotUpdatesCount = Infinity;
      if (state.autoSync) state.autoSync.notifyLocalEdit();
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        state.snapshotUpdatesCount = 0;
        return;
      }
      if (err instanceof Error && err.message === "Worker terminated") {
        state.snapshotUpdatesCount = 0;
        return;
      }
      if (
        isRecoverableSyncGapError(err) ||
        (err instanceof DocumentSyncError && err.code === "rollback_attack")
      ) {
        state.snapshotUpdatesCount = Infinity;
        if (state.autoSync) state.autoSync.notifyLocalEdit();
        return;
      }
      console.error("[ws] snapshot recovery failed (non-fatal):", err);
      state.snapshotUpdatesCount = 0;
    }
  } else {
    state.snapshotUpdatesCount = Infinity;
    if (state.autoSync) state.autoSync.notifyLocalEdit();
  }
}
