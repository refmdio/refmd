import * as Y from "yjs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getNextClockForDevice } from "@/shared/lib/anti-rollback/clock-observations";
import { cacheDocumentState } from "@/shared/lib/offline/cache-manager";
import { deletePendingChanges } from "@/shared/lib/offline/offline-store";
import { deviceState } from "@/entities/session";
import {
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
import type { DocumentState } from "./document-state-cache";
import { handleDocumentMessage } from "./ws-handlers";

export function handleUpdateSaved(
  payload: UpdateSavedPayload,
  state: DocumentState,
  documentId?: string,
): void {
  const deviceKey = deviceState()?.deviceSigningPublic;
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
    getDocumentStatePin(documentId).then((existing) => {
      const pin = updatePinFromState(
        existing,
        documentId,
        state.activeSnapshotId,
        state.snapshotProofHash,
        state.snapshotCiphertextHash,
        state.confirmedClocks,
        state.latestVersion,
      );
      putDocumentStatePin(pin).catch(() => {});
    });
  }

  if (documentId && state.workspaceId && state.keyVersion > 0) {
    cacheDocumentState(documentId, state.workspaceId, state).catch(() => {});
    deletePendingChanges(documentId).catch(() => {});
  }

  if (state.autoSync) state.autoSync.notifyLocalEdit();
}

export function handleUpdateSaveFailed(
  payload: UpdateSaveFailedPayload,
  state: DocumentState,
): void {
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

  if (state.autoSync) state.autoSync.notifyLocalEdit();
}

export async function handleSnapshotSaved(
  payload: SnapshotSavedPayload,
  state: DocumentState,
  documentId?: string,
): Promise<void> {
  const pendingSnapshot = state.pendingSnapshot;
  if (!pendingSnapshot) return;

  state.activeSnapshotId = payload.snapshotId;
  state.snapshotCiphertextHash = pendingSnapshot.ciphertextHash;
  state.snapshotProofHash = await getCryptoWorker().computeSnapshotProof({
    ciphertextHash: pendingSnapshot.ciphertextHash,
    parentProof: pendingSnapshot.parentSnapshotProof,
    snapshotId: payload.snapshotId,
  });

  const serverDoc = new Y.Doc();
  Y.applyUpdateV2(serverDoc, pendingSnapshot.snapshotYjsState, "remote");
  state.lastSavedState = Y.encodeStateAsUpdate(serverDoc);
  serverDoc.destroy();
  state.snapshotUpdatesCount = 0;

  state.pendingSnapshot = null;
  state.pendingSnapshotEnvelope = null;
  state.sending = false;
  if (state.pendingRotationKeyVersion !== null) {
    state.keyVersion = state.pendingRotationKeyVersion;
    state.pendingRotationKeyVersion = null;
  }
  state.pendingRotationSnapshot = false;
  const localDeviceSigningPublic = deviceState()?.deviceSigningPublic;
  state.knownClocks = { ...pendingSnapshot.knownClocksAtSend };
  state.confirmedClocks = { ...pendingSnapshot.knownClocksAtSend };
  state.localClock = getNextClockForDevice(
    state.knownClocks,
    localDeviceSigningPublic ? base64UrlEncode(localDeviceSigningPublic) : undefined,
  );

  if (documentId && state.workspaceId && state.keyVersion > 0) {
    cacheDocumentState(documentId, state.workspaceId, state).catch(() => {});
    deletePendingChanges(documentId).catch(() => {});
  }

  if (documentId) {
    getDocumentStatePin(documentId).then((existing) => {
      const pin = updatePinFromState(
        existing,
        documentId,
        state.activeSnapshotId,
        state.snapshotProofHash,
        state.snapshotCiphertextHash,
        state.confirmedClocks,
        state.latestVersion,
      );
      putDocumentStatePin(pin).catch(() => {});
    });
  }

  if (state.autoSync) state.autoSync.notifyLocalEdit();
}

export async function handleSnapshotSaveFailed(
  payload: SnapshotSaveFailedPayload,
  state: DocumentState,
  documentId: string,
): Promise<void> {
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
      console.error("[ws] snapshot recovery failed (non-fatal):", err);
      state.snapshotUpdatesCount = 0;
    }
  } else {
    state.snapshotUpdatesCount = Infinity;
    if (state.autoSync) state.autoSync.notifyLocalEdit();
  }
}
