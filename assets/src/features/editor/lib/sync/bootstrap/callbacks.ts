import type { DocumentChannelCallbacks } from "@/shared/lib/ws/phoenix-channel";
import type { DocumentState } from "../../../model/document-state/types";
import { isRecoverableSyncGapError } from "../error";
import { handleEphemeralMessage, handlePeerLeft } from "../ephemeral/receive";
import { handleRemoteSnapshot, handleRemoteUpdate } from "../inbound/document";
import { applyPublicationStatusChanged } from "../outbound/publication";
import {
  handleSnapshotSaveFailed,
  handleSnapshotSaved,
  handleUpdateSaveFailed,
  handleUpdateSaved,
} from "../outbound/save";

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

export function buildDocumentChannelCallbacks(
  state: DocumentState,
  documentId: string,
  localDeviceSigningPubKey: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
  handlers: DocumentChannelLifecycleHandlers,
): DocumentChannelCallbacks {
  state._onRecoverableSyncGap = handlers.onSyncGap ?? null;

  return {
    onDocument: handlers.onDocument,
    onUpdate: (payload) => {
      handleRemoteUpdate(payload, state, documentId, localDeviceSigningPubKey).catch((err) => {
        if (isRecoverableSyncGapError(err) && handlers.onSyncGap) {
          handlers.onSyncGap(err);
          return;
        }
        failClosed("verification_failed", err);
      });
    },
    onSnapshot: (payload) => {
      handleRemoteSnapshot(payload, state, documentId).catch((err) => {
        if (isRecoverableSyncGapError(err) && handlers.onSyncGap) {
          handlers.onSyncGap(err);
          return;
        }
        failClosed("verification_failed", err);
      });
    },
    onUpdateSaved: (payload) => {
      handleUpdateSaved(payload, state, documentId);
    },
    onUpdateSaveFailed: (payload) => {
      handleUpdateSaveFailed(payload, state);
      if (payload.requiresNewSnapshot) {
        failClosed("snapshot_mismatch");
      }
      handlers.onUpdateSaveFailed?.(payload);
    },
    onSnapshotSaved: (payload) => {
      handleSnapshotSaved(payload, state, documentId);
    },
    onSnapshotSaveFailed: (payload) => {
      handleSnapshotSaveFailed(payload, state, documentId).catch((err) => {
        failClosed("verification_failed", err);
      });
    },
    onEphemeralMessage: (payload) => {
      handleEphemeralMessage(payload, state, documentId, localDeviceSigningPubKey);
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
