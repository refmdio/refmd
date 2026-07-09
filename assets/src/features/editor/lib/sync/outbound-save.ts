import * as Y from "yjs";
import {
  clearProseMirrorXml,
  encodeCanonicalSyncedStateAsUpdate,
} from "@/shared/lib/yjs/canonical-document";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { cacheDocumentState } from "@/shared/lib/offline/cache/manager/write";
import { deletePendingChanges } from "@/shared/lib/offline/storage/store";
import { deviceState } from "@/entities/session";
import {
  buildDocumentStatePinKey,
  getDocumentStatePin,
  putDocumentStatePin,
  updatePinFromState,
} from "@/shared/lib/anti-rollback/document-state-pins";
import { clientError } from "@/shared/lib/logger";
import type {
  SnapshotSaveFailedPayload,
  SnapshotSavedPayload,
  UpdateSaveFailedPayload,
  UpdateSavedPayload,
} from "@/shared/lib/ws/document-payloads";
import { DocumentSyncError, isRecoverableSyncGapError } from "./error";
import { getDocumentState } from "../../model/document-state/store";
import type { DocumentState } from "../../model/document-state/types";
import { handleDocumentMessage } from "./inbound-document";
import { resetWriteSessionCountersForSnapshotBaseline } from "./inbound-verify-decrypt";
import { getLocalDeviceId, getLocalSigningKeyId } from "./share-identity";
import { getDocumentDekCacheKey } from "./share-access";
import { getDocumentCryptoWorker } from "./crypto-worker";
import {
  keyDirectoryAdvanceSymbol,
  rememberDocumentAdmissionCheckpoint,
  type KeyDirectoryAdvance,
} from "./outbound-admission";
import { hasUnsavedCanonicalText } from "./outbound-canonical";
import { queuePublicationSaveSync } from "./outbound-publication";
import { clearSaveAckWatchdog } from "./outbound-save-watchdog";
import { recordSyncPerf } from "./perf";
import { nextLocalClockForDevice } from "./local-clock";

function getPinKey(state: DocumentState, documentId: string): string {
  return state.access.kind === "share"
    ? buildDocumentStatePinKey(documentId, state.access.shareId)
    : buildDocumentStatePinKey(documentId);
}

function rebaseLiveDocOntoAcceptedSnapshot(state: DocumentState, snapshotState: Uint8Array): void {
  Y.applyUpdateV2(state.yDoc, snapshotState, "snapshot-ack");
  clearProseMirrorXml(state.yDoc, "snapshot-ack");
}

function getOfflineCacheOptions(state: DocumentState, documentId: string) {
  return state.access.kind === "share"
    ? {
        worker: getDocumentCryptoWorker(state),
        cacheKey: getDocumentDekCacheKey(state, documentId),
      }
    : undefined;
}

function hasUnsavedLocalChanges(state: DocumentState): boolean {
  return hasUnsavedCanonicalText(state);
}

function pendingUpdatePublicData(state: DocumentState): {
  refSnapshotId: string;
  clock: number;
  updateHash: string;
  authorityContextKey?: string;
} | null {
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
    authorityContextKey:
      typeof typed.authorityContextKey === "string" ? typed.authorityContextKey : undefined,
  };
}

function recordSaveEvent(
  state: DocumentState,
  event: string,
  details: Omit<DocumentState["_recentSaveEvents"][number], "event" | "at"> = {},
): void {
  state._recentSaveEvents.push({
    event,
    at: Date.now(),
    ...details,
  });
  if (state._recentSaveEvents.length > 12) {
    state._recentSaveEvents.splice(0, state._recentSaveEvents.length - 12);
  }
}

function rejectInvalidAck(state: DocumentState): void {
  recordSaveEvent(state, "update_ack_rejected", {
    activeSnapshotId: state.activeSnapshotId,
    hasPendingUpdateBytes: state.pendingUpdateBytes !== null,
    hasPendingUpdateEnvelope: state.pendingUpdateEnvelope !== null,
  });
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

export type UpdateSaveFailureRecovery = "none" | "complete_reconnect" | "snapshot_mismatch";

const RECONNECT_AFTER_UPDATE_SAVE_FAILURE = new Set([
  "clock_mismatch",
  "key_version_too_old",
  "key_rotation_required",
  "rotation_snapshot_required",
  "serialization_conflict",
]);

const FORCE_SNAPSHOT_AFTER_UPDATE_SAVE_FAILURE = new Set(["document_update_payload_too_large"]);

function clearPreparedWriteSession(state: DocumentState): void {
  state.writeSession = null;
  state.writeSessionPromise = null;
  state.writeSessionReadyAt = null;
  state.writeSessionError = null;
}

function isAdmissionAdvanceRace(err: unknown): boolean {
  return (
    err instanceof Error &&
    (err.message === "key_directory_checkpoint_rollback" ||
      err.message === "key_directory_pin_conflict")
  );
}

function isAdmissionCheckpointAlreadyAdvanced(err: unknown): boolean {
  return err instanceof Error && err.message === "key_directory_checkpoint_rollback";
}

async function recoverAdmissionAdvanceRace(
  advance: KeyDirectoryAdvance,
  state: DocumentState,
  documentId?: string,
): Promise<boolean> {
  const deviceId = getLocalDeviceId(state) ?? deviceState()?.deviceId;
  if (advance.scopeKind !== "workspace" || !deviceId) return false;

  try {
    const directory = await fetchVerifiedKeyDirectory({
      scopeKind: advance.scopeKind,
      scopeId: advance.scopeId,
      rrpDeviceId: deviceId,
      popScope: state.access.kind === "share" ? "share" : "user",
      popWorker: state.access.kind === "share" ? getDocumentCryptoWorker(state) : undefined,
    });
    rememberDocumentAdmissionCheckpoint(state, {
      admission: { workspaceKeyDirectoryCheckpoint: directory.checkpoint },
    });
    recordSyncPerf("update_ack_admission_advance_race_recovered", {
      documentId,
      accessKind: state.access.kind,
    });
    return true;
  } catch (recoveryError) {
    recordSyncPerf("update_ack_admission_advance_race_recovery_failed", {
      documentId,
      accessKind: state.access.kind,
      error: recoveryError instanceof Error ? recoveryError.message : String(recoveryError),
    });
    return false;
  }
}

async function rememberAcceptedAdmissionCheckpoint(
  envelope: { admission?: unknown } | null | undefined,
  state: DocumentState,
  documentId?: string,
): Promise<void> {
  const advance = (envelope as { [keyDirectoryAdvanceSymbol]?: KeyDirectoryAdvance } | null)?.[
    keyDirectoryAdvanceSymbol
  ];
  recordSyncPerf("update_ack_admission_checkpoint_start", {
    documentId,
    hasAdvance: Boolean(advance),
    accessKind: state.access.kind,
  });
  if (advance) {
    try {
      await advanceKeyDirectoryPinWithProof(advance);
      recordSyncPerf("update_ack_admission_advance_ready", {
        documentId,
      });
    } catch (err) {
      recordSyncPerf("update_ack_admission_advance_failed", {
        documentId,
        error: err instanceof Error ? err.message : String(err),
      });
      if (isAdmissionCheckpointAlreadyAdvanced(err)) {
        recordSyncPerf("update_ack_admission_advance_already_covered", {
          documentId,
          accessKind: state.access.kind,
        });
      } else if (
        !isAdmissionAdvanceRace(err) ||
        !(await recoverAdmissionAdvanceRace(advance, state, documentId))
      ) {
        throw err;
      }
      // Another socket event may already have advanced the local key-directory pin
      // past this locally-sent operation. The accepted operation remains covered
      // by its signed admission; do not fail-closed for this benign ACK race.
    }
  }
  rememberDocumentAdmissionCheckpoint(state, envelope);
  recordSyncPerf("update_ack_admission_checkpoint_ready", {
    documentId,
  });
  state._admissionDirectoryRefreshRequired = false;
}

export async function handleUpdateSaved(
  payload: UpdateSavedPayload,
  state: DocumentState,
  documentId?: string,
): Promise<void> {
  clearSaveAckWatchdog(state);
  const pending = pendingUpdatePublicData(state);
  const acceptedEnvelope = state.pendingUpdateEnvelope;
  recordSaveEvent(state, "update_saved_received", {
    payload,
    pending,
    activeSnapshotId: state.activeSnapshotId,
    hasPendingUpdateBytes: state.pendingUpdateBytes !== null,
    hasPendingUpdateEnvelope: state.pendingUpdateEnvelope !== null,
  });
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
    recordSaveEvent(state, "update_saved_snapshot_mismatch", {
      payload,
      pending,
      activeSnapshotId: state.activeSnapshotId,
      hasPendingUpdateBytes: state.pendingUpdateBytes !== null,
      hasPendingUpdateEnvelope: state.pendingUpdateEnvelope !== null,
    });
    state.pendingUpdateBytes = null;
    state.pendingUpdateEnvelope = null;
    state.sending = false;
    if (state.autoSync && hasUnsavedLocalChanges(state)) {
      state.autoSync.notifyLocalEdit();
    }
    return;
  }

  await rememberAcceptedAdmissionCheckpoint(acceptedEnvelope, state, documentId);
  recordSyncPerf("update_saved_ack", {
    documentId,
    updateHash: pending.updateHash,
  });

  const signingKeyId = getLocalSigningKeyId(state) ?? deviceState()?.deviceSigningKeyId;
  if (signingKeyId) {
    const clockKey = pending.authorityContextKey
      ? `${pending.authorityContextKey}:${signingKeyId}`
      : signingKeyId;
    state.knownClocks[clockKey] = payload.clock;
    state.confirmedClocks[clockKey] = payload.clock;
    if (payload.clock >= state.localClock) {
      state.localClock = payload.clock + 1;
    }
  }

  if (state.pendingUpdateBytes && state.lastSavedState) {
    const serverDoc = new Y.Doc();
    Y.applyUpdate(serverDoc, state.lastSavedState, "remote");
    Y.applyUpdate(serverDoc, state.pendingUpdateBytes, "remote");
    state.lastSavedState = encodeCanonicalSyncedStateAsUpdate(serverDoc);
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
    void getDocumentStatePin(pinKey).then((existing) => {
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

  if (documentId && state.workspaceId && state.keyVersion > 0) {
    cacheDocumentState(
      documentId,
      state.workspaceId,
      state,
      getOfflineCacheOptions(state, documentId),
    ).catch(() => {});
    deletePendingChanges(documentId).catch(() => {});
  }

  if (documentId) {
    queuePublicationSaveSync(documentId, state);
  }

  const hasUnsavedChanges = hasUnsavedLocalChanges(state);
  if (state.autoSync && hasUnsavedChanges) {
    state.autoSync.flushNow().catch((err) => {
      clientError("auto_sync_flush_after_update_ack_failed", { documentId, error: err });
    });
  } else if (!hasUnsavedChanges) {
    void state.autoSync?.prepareWriteSession();
  }
}

export function handleUpdateSaveFailed(
  payload: UpdateSaveFailedPayload,
  state: DocumentState,
): UpdateSaveFailureRecovery {
  clearSaveAckWatchdog(state);
  recordSaveEvent(state, "update_save_failed", {
    payload,
    activeSnapshotId: state.activeSnapshotId,
    hasPendingUpdateBytes: state.pendingUpdateBytes !== null,
    hasPendingUpdateEnvelope: state.pendingUpdateEnvelope !== null,
  });
  const sentClock = state.preSendLocalClock;
  if (state.localClock === sentClock + 1) {
    state.localClock = sentClock;
  }
  state.pendingUpdateBytes = null;
  state.pendingUpdateEnvelope = null;
  state.sending = false;
  clearPreparedWriteSession(state);

  if (payload.requiresNewSnapshot) {
    state.error = "snapshot_mismatch";
    return "snapshot_mismatch";
  }

  const reason = typeof payload.reason === "string" ? payload.reason : null;
  if (reason && FORCE_SNAPSHOT_AFTER_UPDATE_SAVE_FAILURE.has(reason)) {
    state.snapshotUpdatesCount = Infinity;
    state._admissionDirectoryRefreshRequired = true;
    return "none";
  }

  if (!reason || RECONNECT_AFTER_UPDATE_SAVE_FAILURE.has(reason)) {
    state._forceCompleteReconnect = true;
    if (reason !== "clock_mismatch") {
      state._admissionDirectoryRefreshRequired = true;
    }
    return "complete_reconnect";
  }

  state._forceCompleteReconnect = true;
  state._admissionDirectoryRefreshRequired = true;
  return "complete_reconnect";
}

export async function handleSnapshotSaved(
  payload: SnapshotSavedPayload,
  state: DocumentState,
  documentId?: string,
): Promise<void> {
  clearSaveAckWatchdog(state);
  const pendingSnapshot = state.pendingSnapshot;
  const acceptedEnvelope = state.pendingSnapshotEnvelope;
  if (!pendingSnapshot) return;
  if (payload.snapshotId !== pendingSnapshot.snapshotId) {
    rejectInvalidAck(state);
    return;
  }

  state.activeSnapshotId = pendingSnapshot.snapshotId;
  if (payload.ciphertextHash !== pendingSnapshot.ciphertextHash) {
    rejectInvalidAck(state);
    return;
  }
  state.snapshotCiphertextHash = payload.ciphertextHash;
  state.snapshotProofHash = payload.proofChainHash;

  const serverDoc = new Y.Doc();
  Y.applyUpdateV2(serverDoc, pendingSnapshot.snapshotYjsState, "remote");
  state.lastSavedState = encodeCanonicalSyncedStateAsUpdate(serverDoc);
  serverDoc.destroy();
  rebaseLiveDocOntoAcceptedSnapshot(state, pendingSnapshot.snapshotYjsState);
  state.snapshotUpdatesCount = 0;
  state.snapshotBaseClocks = { ...pendingSnapshot.knownClocksAtSend };
  if (typeof payload.latestVersion === "number") {
    state.latestVersion = payload.latestVersion;
  }

  await rememberAcceptedAdmissionCheckpoint(acceptedEnvelope, state);

  state.pendingSnapshot = null;
  state.pendingSnapshotEnvelope = null;
  state.sending = false;
  if (state.pendingRotationKeyVersion !== null) {
    state.keyVersion = state.pendingRotationKeyVersion;
    state.pendingRotationKeyVersion = null;
  }
  state.pendingRotationSnapshot = false;
  const signingKeyId = getLocalSigningKeyId(state) ?? deviceState()?.deviceSigningKeyId;
  state.knownClocks = {};
  state.confirmedClocks = {};
  resetWriteSessionCountersForSnapshotBaseline(state);
  state.localClock = nextLocalClockForDevice(state.confirmedClocks, state, signingKeyId);

  if (documentId && state.workspaceId && state.keyVersion > 0) {
    cacheDocumentState(
      documentId,
      state.workspaceId,
      state,
      getOfflineCacheOptions(state, documentId),
    ).catch(() => {});
    deletePendingChanges(documentId).catch(() => {});
  }

  if (documentId) {
    const pinKey = getPinKey(state, documentId);
    void getDocumentStatePin(pinKey).then((existing) => {
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
    void state.autoSync?.prepareWriteSession();
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
      clientError("snapshot_recovery_failed", { documentId: state.documentId, error: err });
      state.snapshotUpdatesCount = 0;
    }
  } else {
    state.snapshotUpdatesCount = Infinity;
    if (state.autoSync) state.autoSync.notifyLocalEdit();
  }
}
