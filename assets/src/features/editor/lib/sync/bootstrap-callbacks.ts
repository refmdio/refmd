import type { DocumentChannelCallbacks } from "@/shared/lib/ws/phoenix-channel";
import type { DocumentState } from "../../model/document-state/types";
import { isRecoverableSyncGapError } from "./error";
import { handleEphemeralMessage, handlePeerLeft } from "./ephemeral-receive";
import {
  handleRemoteSnapshot,
  handleRemoteUpdate,
  handleRemoteWriteSession,
} from "./inbound-document";
import { applyPublicationStatusChanged } from "./outbound-publication";
import {
  handleSnapshotSaveFailed,
  handleSnapshotSaved,
  handleUpdateSaveFailed,
  handleUpdateSaved,
} from "./outbound-save";
import { recordSyncPerf } from "./perf";

interface DocumentChannelLifecycleHandlers {
  onDocument: DocumentChannelCallbacks["onDocument"];
  onUnauthorized: DocumentChannelCallbacks["onUnauthorized"];
  onError: DocumentChannelCallbacks["onError"];
  onClose: DocumentChannelCallbacks["onClose"];
  onUpdateSaveFailed?: (
    payload: Parameters<DocumentChannelCallbacks["onUpdateSaveFailed"]>[0],
  ) => void;
  onSyncGap?: (err: unknown) => void;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function buildDocumentChannelCallbacks(
  state: DocumentState,
  documentId: string,
  localDeviceSigningKeyId: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
  handlers: DocumentChannelLifecycleHandlers,
): DocumentChannelCallbacks {
  state._onRecoverableSyncGap = handlers.onSyncGap ?? null;
  let orderedDocumentEventQueue: Promise<void> = Promise.resolve();

  const enqueueOrderedDocumentEvent = (run: () => void | Promise<void>): Promise<void> => {
    const task = orderedDocumentEventQueue.catch(() => {}).then(run);
    orderedDocumentEventQueue = task.catch(() => {});
    return task;
  };

  return {
    onDocument: handlers.onDocument,
    onUpdate: (payload) => {
      enqueueOrderedDocumentEvent(() =>
        handleRemoteUpdate(payload, state, documentId, localDeviceSigningKeyId, (err) =>
          failClosed("verification_failed", err),
        ),
      ).catch((err) => {
        if (isRecoverableSyncGapError(err) && handlers.onSyncGap) {
          handlers.onSyncGap(err);
          return;
        }
        recordSyncPerf("remote_update_failed", {
          documentId,
          signingKeyId: payload.publicData.signingKeyId,
          updateHash: payload.publicData.updateHash,
          error: errorMessage(err),
        });
        failClosed("verification_failed", err);
      });
    },
    onSnapshot: (payload) => {
      enqueueOrderedDocumentEvent(() => handleRemoteSnapshot(payload, state, documentId)).catch(
        (err) => {
          if (isRecoverableSyncGapError(err) && handlers.onSyncGap) {
            handlers.onSyncGap(err);
            return;
          }
          recordSyncPerf("remote_snapshot_failed", {
            documentId,
            snapshotId: payload.snapshotId,
            error: errorMessage(err),
          });
          failClosed("verification_failed", err);
        },
      );
    },
    onWriteSession: (payload) => {
      enqueueOrderedDocumentEvent(() => handleRemoteWriteSession(payload, state, documentId)).catch(
        (err) => {
          recordSyncPerf("write_session_broadcast_failed", {
            documentId,
            signingKeyId: payload.publicData.signingKeyId,
            writeSessionEventHash: payload.publicData.writeSessionEventHash,
            error: errorMessage(err),
          });
        },
      );
    },
    onUpdateSaved: (payload) => {
      enqueueOrderedDocumentEvent(() => handleUpdateSaved(payload, state, documentId)).catch(
        (err) => {
          recordSyncPerf("update_saved_ack_failed", {
            documentId,
            error: errorMessage(err),
          });
          failClosed("verification_failed", err);
        },
      );
    },
    onUpdateSaveFailed: (payload) => {
      enqueueOrderedDocumentEvent(() => {
        const recovery = handleUpdateSaveFailed(payload, state);
        if (recovery === "snapshot_mismatch") {
          failClosed("snapshot_mismatch");
          return;
        }
        if (recovery === "complete_reconnect" && handlers.onSyncGap) {
          handlers.onSyncGap(new Error(payload.reason ?? "update_save_failed"));
          return;
        }
        handlers.onUpdateSaveFailed?.(payload);
      }).catch((err) => {
        recordSyncPerf("update_save_failed_ack_failed", {
          documentId,
          error: errorMessage(err),
        });
        failClosed("verification_failed", err);
      });
    },
    onSnapshotSaved: (payload) => {
      enqueueOrderedDocumentEvent(() => handleSnapshotSaved(payload, state, documentId)).catch(
        (err) => {
          recordSyncPerf("snapshot_saved_ack_failed", {
            documentId,
            error: errorMessage(err),
          });
          failClosed("verification_failed", err);
        },
      );
    },
    onSnapshotSaveFailed: (payload) => {
      enqueueOrderedDocumentEvent(() => handleSnapshotSaveFailed(payload, state, documentId)).catch(
        (err) => {
          recordSyncPerf("snapshot_save_failed_ack_failed", {
            documentId,
            error: errorMessage(err),
          });
          failClosed("verification_failed", err);
        },
      );
    },
    onEphemeralMessage: (payload) => {
      handleEphemeralMessage(payload, state, documentId, localDeviceSigningKeyId);
    },
    onPeerLeft: (payload) => {
      handlePeerLeft(payload, state);
    },
    onPublicStatusChanged: (payload) => {
      applyPublicationStatusChanged(documentId, state, payload);
    },
    onUnauthorized: handlers.onUnauthorized,
    onError: handlers.onError,
    onClose: handlers.onClose,
  };
}
